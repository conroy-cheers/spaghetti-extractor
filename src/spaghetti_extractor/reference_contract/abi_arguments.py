"""Machine-level ABI evidence and candidate ABI comparison."""

from __future__ import annotations

import copy
import json
import os
import platform
import re
import shutil
import sys
from bisect import bisect_left
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Iterable

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import pefile

from ..pe32.stage_binary import (
    BlockSide,
    StageABinary,
    StageAImport,
    StageAInputError,
    StageASection,
    _artifact_name,
    _executable_section_for_rva,
    _parse_linker_map_functions,
    _parse_linker_map_symbol_line,
    _parse_stage_a_pe,
    _section_for_rva,
)
from ..extraction.cutpoints import semantic_cutpoint_spans_for_side
from ..util import sha256_bytes, sha256_file, utc_now, write_json

from .common import (
    ABI_FIXED_STDCALL_IMPORT_STACK_ARG_COUNTS,
    BlockMapping,
    STAGE_A_ABI_PROFILE_FUNCTION_MISMATCH_CATEGORIES,
    _is_conditional_jump,
    _mapping_source,
    _range_report,
)

from .map_analysis import (
    _capstone_mode,
    _linker_function_match_key,
    _recover_basic_blocks,
)
from .map_analysis import (
    _absolute_mem_operand_rva,
    _direct_branch_target,
    _direct_cfg_edges,
    _import_for_absolute_memory_operand,
    _import_for_thunk_rva,
    _instruction_report,
    _resolved_branch_target,
)

from .abi_instruction import (
    _abi_absolute_addressing_rva,
    _abi_import_report,
    _abi_mem_operand_report,
    _abi_memory_role,
    _abi_section_report,
    _abi_string_literal_at_rva,
    _abi_value_to_rva,
    _instruction_register_access,
)

from .abi_support import (
    _safe_int,
)

def _abi_argument_source(binary: StageABinary, insn: Any, register_definitions: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    if not insn.operands:
        return {"kind": "unknown", "instruction": _instruction_report(binary, insn)}
    return _abi_attach_register_definition(
        _abi_operand_argument_source(binary, insn, insn.operands[0], register_definitions),
        register_definitions,
    )

def _abi_stack_argument_write_source(
    binary: StageABinary,
    insn: Any,
    offset: int,
    register_definitions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if len(insn.operands) < 2:
        source = {"kind": "unknown", "instruction": _instruction_report(binary, insn)}
    else:
        source = _abi_attach_register_definition(
            _abi_operand_argument_source(binary, insn, insn.operands[1], register_definitions),
            register_definitions,
        )
    source["stack_offset"] = offset
    source["stack_write"] = _instruction_report(binary, insn)
    return source

def _abi_operand_argument_source(
    binary: StageABinary,
    insn: Any,
    operand: Any,
    register_definitions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if str(insn.mnemonic) == "lea" and operand.type == X86_OP_MEM:
        addressing = _abi_mem_operand_report(insn, operand)
        return {
            "kind": "address",
            "addressing": addressing,
            "address_class": _abi_address_class(addressing),
            "instruction": _instruction_report(binary, insn),
        }
    if operand.type == X86_OP_IMM:
        source = {"kind": "immediate", "value": int(operand.imm), "instruction": _instruction_report(binary, insn)}
        _abi_attach_immediate_literal(binary, source)
        return source
    if operand.type == X86_OP_REG:
        return {"kind": "register", "register": insn.reg_name(operand.reg), "instruction": _instruction_report(binary, insn)}
    if operand.type == X86_OP_MEM:
        addressing = _abi_mem_operand_report(insn, operand)
        source: dict[str, Any] = {"kind": "memory", "addressing": addressing, "instruction": _instruction_report(binary, insn)}
        memory_rva = _abi_absolute_addressing_rva(binary, addressing)
        if memory_rva is not None:
            source["memory_rva"] = memory_rva
            section = _section_for_rva(binary, memory_rva)
            if section is not None:
                source["memory_section"] = _abi_section_report(section)
            string_literal = _abi_string_literal_at_rva(binary, memory_rva)
            if string_literal is not None:
                source["string_literal"] = string_literal
            imported = _import_for_thunk_rva(binary, memory_rva)
            if imported is not None:
                source["import"] = _abi_import_report(imported)
        base = addressing.get("base")
        if isinstance(base, str) and isinstance(register_definitions, dict):
            base_definition = register_definitions.get(base)
            if isinstance(base_definition, dict):
                source["base_register_definition"] = base_definition
        source["memory_role"] = _abi_memory_role(source)
        return source
    return {"kind": "unknown", "instruction": _instruction_report(binary, insn)}

def _abi_attach_immediate_literal(binary: StageABinary, source: dict[str, Any]) -> None:
    value = _safe_int(source.get("value"))
    if value is None:
        return
    rva = _abi_value_to_rva(binary, value)
    if rva is None:
        return
    source["memory_rva"] = rva
    section = _section_for_rva(binary, rva)
    if section is not None:
        source["memory_section"] = _abi_section_report(section)
    string_literal = _abi_string_literal_at_rva(binary, rva)
    if string_literal is not None:
        source["string_literal"] = string_literal

def _abi_attach_register_definition(source: dict[str, Any], register_definitions: dict[str, dict[str, Any]] | None) -> dict[str, Any]:
    if source.get("kind") != "register" or not isinstance(register_definitions, dict):
        return source
    register = source.get("register")
    definition = register_definitions.get(str(register))
    if isinstance(definition, dict):
        source = dict(source)
        source["register_definition"] = definition
    return source

def _abi_update_register_definitions(
    binary: StageABinary,
    insn: Any,
    register_definitions: dict[str, dict[str, Any]],
    written_registers: set[str],
) -> str | None:
    definition = _abi_register_definition(binary, insn, register_definitions)
    defined_register = definition[0] if definition is not None else None
    for register in written_registers:
        if register != defined_register:
            register_definitions.pop(register, None)
    if definition is not None:
        register_definitions[definition[0]] = definition[1]
    return defined_register

def _abi_register_definition(
    binary: StageABinary,
    insn: Any,
    register_definitions: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, Any]] | None:
    if len(insn.operands) < 2:
        return None
    dst = insn.operands[0]
    if dst.type != X86_OP_REG:
        return None
    register = insn.reg_name(dst.reg)
    if not register:
        return None
    mnemonic = str(insn.mnemonic)
    if mnemonic == "lea":
        source = _abi_operand_argument_source(binary, insn, insn.operands[1], register_definitions)
    elif mnemonic == "mov":
        source = _abi_operand_argument_source(binary, insn, insn.operands[1], register_definitions)
        if source.get("kind") == "register":
            copied = register_definitions.get(str(source.get("register")))
            if isinstance(copied, dict):
                source = dict(copied)
                source["copied_from_register"] = insn.reg_name(insn.operands[1].reg)
                source["copied_by"] = _instruction_report(binary, insn)
    else:
        return None
    return str(register), source

def _abi_address_class(addressing: dict[str, Any]) -> str:
    base = str(addressing.get("base") or "")
    if base in {"esp", "ebp", "rsp", "rbp"}:
        return "stack_address"
    return "computed_address"

def _abi_pending_argument_sources(
    pushes: list[dict[str, Any]],
    stack_argument_writes: dict[int, dict[str, Any]],
    *,
    word_size: int,
) -> list[dict[str, Any]]:
    contiguous_offsets: list[int] = []
    expected_offset = 0
    for offset in sorted(offset for offset in stack_argument_writes if offset >= 0):
        if offset < expected_offset:
            continue
        if offset != expected_offset:
            break
        contiguous_offsets.append(offset)
        expected_offset += word_size
    stack_sources = [stack_argument_writes[offset] for offset in reversed(contiguous_offsets)]
    return list(pushes[-8:]) + stack_sources

def _abi_resets_pending_arguments(insn: Any) -> bool:
    mnemonic = str(insn.mnemonic)
    if mnemonic in {"leave", "enter"}:
        return True
    if mnemonic == "mov" and len(insn.operands) == 2:
        dst, src = insn.operands
        if dst.type == X86_OP_REG and src.type == X86_OP_REG:
            dst_name = insn.reg_name(dst.reg)
            src_name = insn.reg_name(src.reg)
            if (dst_name, src_name) in {("ebp", "esp"), ("rbp", "rsp")}:
                return True
    if mnemonic in {"sub", "add", "and", "lea"} and insn.operands:
        dst = insn.operands[0]
        if dst.type == X86_OP_REG and insn.reg_name(dst.reg) in {"esp", "rsp"}:
            return True
    return False

def _abi_stack_argument_write_offset(insn: Any) -> int | None:
    if not insn.operands:
        return None
    mnemonic = str(insn.mnemonic)
    if mnemonic != "mov":
        return None
    dst = insn.operands[0]
    if dst.type != X86_OP_MEM:
        return None
    mem = dst.mem
    base = insn.reg_name(mem.base) if mem.base else None
    index = insn.reg_name(mem.index) if mem.index else None
    if base not in {"esp", "rsp"} or index not in {None, ""}:
        return None
    offset = int(mem.disp)
    if offset < 0:
        return None
    return offset

def _abi_callsite_evidence(
    binary: StageABinary,
    insn: Any,
    block_id: str,
    argument_sources: list[dict[str, Any]],
    register_definitions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    target = _abi_call_target(binary, insn, register_definitions)
    symbol = str(target.get("symbol") or "")
    inventory = _abi_call_argument_inventory(binary, argument_sources, register_definitions, target=target)
    varargs = _abi_varargs_evidence(symbol, inventory)
    return {
        "id": f"callsite:{block_id}:{int(insn.address - binary.image_base):x}",
        "block_id": block_id,
        "instruction": _instruction_report(binary, insn),
        "target": target,
        "argument_sources": argument_sources,
        "argument_inventory": inventory,
        "stack_delta": {"status": "unknown"},
        "hidden_sret_or_out_param_evidence": _abi_hidden_sret_evidence(argument_sources),
        "varargs_evidence": varargs,
        "function_pointer_targets": _abi_function_pointer_targets(target),
    }

def _abi_call_target(
    binary: StageABinary,
    insn: Any,
    register_definitions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    target_rva = _resolved_branch_target(binary, insn)
    imported = _import_for_call_instruction(binary, insn)
    if imported is not None:
        return {
            "kind": "import",
            "dll": imported.dll,
            "symbol": imported.symbol,
            "ordinal": imported.ordinal,
            "thunk_rva": imported.thunk_rva,
        }
    if target_rva is not None:
        return {"kind": "direct", "target_rva": target_rva}
    if len(insn.operands) == 1 and insn.operands[0].type in {X86_OP_REG, X86_OP_MEM}:
        operand = insn.operands[0]
        if operand.type == X86_OP_REG:
            register_name = insn.reg_name(insn.operands[0].reg)
            resolved = _abi_register_call_target(binary, register_name, register_definitions)
            if resolved is not None:
                return resolved
        if operand.type == X86_OP_MEM:
            source = _abi_operand_argument_source(binary, insn, operand, register_definitions)
            return _abi_function_pointer_target_from_source(binary, insn.op_str, source)
        return _abi_function_pointer_target_from_source(binary, insn.op_str, None)
    return {"kind": "unknown", "status": "unresolved"}

def _abi_register_call_target(
    binary: StageABinary,
    register_name: str | None,
    register_definitions: dict[str, dict[str, Any]] | None,
) -> dict[str, Any] | None:
    if not register_name or not isinstance(register_definitions, dict):
        return None
    definition = register_definitions.get(register_name)
    if not isinstance(definition, dict):
        return None
    imported = definition.get("import") if isinstance(definition.get("import"), dict) else None
    if imported is not None:
        return {
            "kind": "import",
            "dll": imported.get("dll"),
            "symbol": imported.get("symbol"),
            "ordinal": imported.get("ordinal"),
            "thunk_rva": imported.get("thunk_rva"),
            "via_register": register_name,
            "source": definition,
        }
    memory_rva = _safe_int(definition.get("memory_rva"))
    if memory_rva is not None:
        return _abi_function_pointer_target_from_source(binary, register_name, definition)
    if definition.get("kind") == "memory":
        return _abi_function_pointer_target_from_source(binary, register_name, definition)
    return None

def _abi_function_pointer_target_from_source(
    binary: StageABinary,
    operand: str,
    source: dict[str, Any] | None,
) -> dict[str, Any]:
    recoverable_targets = _abi_static_function_pointer_targets(binary, source)
    target: dict[str, Any] = {
        "kind": "function_pointer",
        "operand": operand,
        "recoverable_targets": recoverable_targets,
        "status": "resolved_static_pointer_slot" if recoverable_targets else "unresolved",
    }
    if isinstance(source, dict):
        target["source"] = source
        if source.get("memory_role") not in {None, ""}:
            target["memory_role"] = source.get("memory_role")
        if source.get("memory_rva") not in {None, ""}:
            target["memory_rva"] = source.get("memory_rva")
    return target

def _abi_static_function_pointer_targets(binary: StageABinary, source: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(source, dict):
        return []
    memory_rva = _safe_int(source.get("memory_rva"))
    if memory_rva is None:
        return []
    pointer_size = 8 if binary.bitness == 64 else 4
    raw = binary.pe.get_data(memory_rva, pointer_size)
    if len(raw) != pointer_size:
        return []
    pointer_value = int.from_bytes(raw, "little")
    target_rva = _abi_value_to_rva(binary, pointer_value)
    if target_rva is None:
        return []
    section = _executable_section_for_rva(binary, target_rva)
    if section is None:
        return []
    return [
        {
            "status": "resolved",
            "kind": "direct",
            "target_rva": target_rva,
            "target_va": pointer_value,
            "source": "static_pointer_slot_value",
            "memory_rva": memory_rva,
            "memory_role": source.get("memory_role"),
            "section": _abi_section_report(section),
        }
    ]

def _import_for_call_instruction(binary: StageABinary, insn: Any) -> StageAImport | None:
    if len(insn.operands) != 1 or insn.operands[0].type != X86_OP_MEM:
        return None
    return _import_for_absolute_memory_operand(binary, insn.operands[0])

def _abi_hidden_sret_evidence(argument_sources: list[dict[str, Any]]) -> dict[str, Any]:
    if not argument_sources:
        return {"status": "unknown", "reason": "no_static_arguments"}
    first = argument_sources[-1]
    address_source = _abi_address_like_argument_source(first)
    if address_source is not None:
        return {
            "status": "candidate",
            "source": first,
            "address_source": address_source,
            "address_role": _abi_address_argument_role(address_source),
            "reason": "first_stack_argument_has_address_provenance",
        }
    if first.get("kind") == "register":
        return {"status": "unknown", "reason": "first_stack_argument_register_without_address_provenance"}
    return {"status": "unknown", "reason": "first_stack_argument_not_address_like"}

def _abi_address_like_argument_source(source: dict[str, Any]) -> dict[str, Any] | None:
    if source.get("kind") == "address":
        return source
    definition = source.get("register_definition") if isinstance(source.get("register_definition"), dict) else None
    if definition is not None and definition.get("kind") == "address":
        return definition
    return None

def _abi_address_argument_role(address_source: dict[str, Any]) -> str:
    if address_source.get("address_class") == "stack_address":
        return "stack_out_param_or_scratch_buffer"
    return "computed_out_param_or_hidden_sret"

def _abi_call_argument_inventory(
    binary: StageABinary,
    argument_sources: list[dict[str, Any]],
    register_definitions: dict[str, dict[str, Any]] | None,
    *,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ordered_stack_args = list(reversed(argument_sources))
    fixed_stack_arg_count = _abi_fixed_stack_arg_count_for_target(target, binary)
    if fixed_stack_arg_count is not None:
        ordered_stack_args = ordered_stack_args[:fixed_stack_arg_count]
    stack_args = [
        {
            "index": index,
            "source": source,
            "role": _abi_argument_role(source),
        }
        for index, source in enumerate(ordered_stack_args)
        if isinstance(source, dict)
    ]
    register_args = []
    for register in _abi_call_register_argument_order(binary, target):
        definition = register_definitions.get(register) if isinstance(register_definitions, dict) else None
        if isinstance(definition, dict):
            register_args.append({"register": register, "source": definition, "role": _abi_argument_role(definition)})
    calling_convention = "cdecl_or_stdcall_stack" if binary.bitness == 32 else "x86_64_mixed"
    register_argument_evidence = _abi_register_argument_evidence(binary, target, register_args)
    if binary.bitness == 32 and register_args:
        calling_convention = "x86_register_carried_internal"
    return {
        "evidence_status": "derived",
        "stack_args": stack_args,
        "register_args": register_args,
        "argument_count": len(stack_args) + len(register_args),
        "calling_convention": calling_convention,
        "register_argument_evidence": register_argument_evidence,
    }

def _abi_fixed_stack_arg_count_for_target(target: dict[str, Any] | None, binary: StageABinary) -> int | None:
    if binary.bitness != 32 or not isinstance(target, dict) or target.get("kind") != "import":
        return None
    symbol = target.get("symbol")
    if not isinstance(symbol, str) or not symbol:
        return None
    decorated = re.search(r"@([0-9]+)$", symbol)
    if decorated is not None:
        byte_count = _safe_int(decorated.group(1))
        return byte_count // 4 if byte_count is not None and byte_count >= 0 else None
    return ABI_FIXED_STDCALL_IMPORT_STACK_ARG_COUNTS.get(symbol.lower().lstrip("_"))

def _abi_call_register_argument_order(binary: StageABinary, target: dict[str, Any] | None = None) -> tuple[str, ...]:
    if binary.bitness == 64:
        return ("rcx", "rdx", "r8", "r9")
    if binary.bitness == 32:
        return _abi_x86_direct_target_register_argument_order(binary, target)
    return ()

def _abi_x86_direct_target_register_argument_order(
    binary: StageABinary,
    target: dict[str, Any] | None,
) -> tuple[str, ...]:
    if not isinstance(target, dict) or target.get("kind") != "direct":
        return ()
    target_rva = _safe_int(target.get("target_rva"))
    if target_rva is None:
        return ()
    read_registers = _abi_x86_entry_read_before_write_registers(binary, target_rva)
    order = ("eax", "edx", "ecx")
    return tuple(register for register in order if register in read_registers)

def _abi_x86_entry_read_before_write_registers(binary: StageABinary, target_rva: int) -> set[str]:
    section = _section_for_rva(binary, target_rva)
    if section is None or not section.executable:
        return set()
    size = min(128, max(0, section.rva_end - target_rva))
    if size <= 0:
        return set()
    data = binary.pe.get_data(target_rva, size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    read_before_write: set[str] = set()
    written: set[str] = set()
    candidates = {"eax", "edx", "ecx"}
    for insn in dis.disasm(data, binary.image_base + target_rva):
        mnemonic = str(insn.mnemonic)
        if mnemonic == "call" or mnemonic in {"jmp", "ljmp", "ret"} or _is_conditional_jump(mnemonic):
            break
        reads, writes = _instruction_register_access(insn)
        zeroed = _abi_x86_zero_idiom_register(insn)
        if zeroed is not None:
            reads.discard(zeroed)
        for register in sorted(candidates & reads):
            if register not in written:
                read_before_write.add(register)
        written.update(candidates & writes)
    return read_before_write

def _abi_x86_zero_idiom_register(insn: Any) -> str | None:
    if str(insn.mnemonic) != "xor" or len(getattr(insn, "operands", []) or []) != 2:
        return None
    left, right = insn.operands[:2]
    if left.type != X86_OP_REG or right.type != X86_OP_REG or left.reg != right.reg:
        return None
    register = insn.reg_name(left.reg)
    return str(register) if register in {"eax", "edx", "ecx"} else None

def _abi_register_argument_evidence(
    binary: StageABinary,
    target: dict[str, Any] | None,
    register_args: list[dict[str, Any]],
) -> dict[str, Any]:
    if not register_args:
        return {"status": "not_observed"}
    evidence: dict[str, Any] = {
        "status": "derived",
        "registers": [arg.get("register") for arg in register_args if isinstance(arg, dict)],
    }
    if binary.bitness == 32 and isinstance(target, dict) and target.get("kind") == "direct":
        evidence["source"] = "direct_target_entry_read_before_write"
        evidence["target_rva"] = target.get("target_rva")
    elif binary.bitness == 64:
        evidence["source"] = "platform_abi_register_order"
    return evidence

def _abi_argument_role(source: dict[str, Any]) -> str:
    if source.get("string_literal") is not None:
        return "string_literal"
    if source.get("kind") == "address":
        return _abi_address_argument_role(source)
    if source.get("kind") == "memory":
        return str(source.get("memory_role") or "memory")
    definition = source.get("register_definition") if isinstance(source.get("register_definition"), dict) else None
    if definition is not None:
        return _abi_argument_role(definition)
    return str(source.get("kind") or "unknown")

def _abi_varargs_evidence(symbol: str, inventory: dict[str, Any] | None = None) -> dict[str, Any]:
    lower = symbol.lower()
    if any(token in lower for token in ("printf", "fprintf", "sprintf", "scanf", "execl")):
        evidence: dict[str, Any] = {
            "status": "candidate",
            "evidence_status": "candidate",
            "reason": "known_variadic_symbol",
        }
        if isinstance(inventory, dict):
            evidence["format_string"] = _abi_format_string_evidence(lower, inventory)
        return evidence
    return {"status": "not_observed"}

def _abi_format_string_evidence(symbol: str, inventory: dict[str, Any]) -> dict[str, Any]:
    stack_args = inventory.get("stack_args") if isinstance(inventory.get("stack_args"), list) else []
    fixed_count = _abi_variadic_fixed_arg_count(symbol)
    format_arg = stack_args[fixed_count - 1] if fixed_count > 0 and len(stack_args) >= fixed_count else None
    if not isinstance(format_arg, dict):
        return {
            "status": "incomplete",
            "fixed_arg_count": fixed_count,
            "reason": "format_argument_not_recovered",
        }
    source = format_arg.get("source") if isinstance(format_arg.get("source"), dict) else {}
    literal = source.get("string_literal") if isinstance(source.get("string_literal"), dict) else None
    if literal is None:
        return {
            "status": "incomplete",
            "fixed_arg_count": fixed_count,
            "format_arg_index": fixed_count - 1,
            "source": source,
            "reason": "format_argument_is_not_a_static_string_literal",
        }
    text = str(literal.get("text") or "")
    conversions = _abi_printf_conversions(text)
    return {
        "status": "derived",
        "fixed_arg_count": fixed_count,
        "format_arg_index": fixed_count - 1,
        "literal": literal,
        "conversions": conversions,
        "required_varargs": len(conversions),
        "observed_varargs": max(0, len(stack_args) - fixed_count),
        "missing_varargs": max(0, len(conversions) - max(0, len(stack_args) - fixed_count)),
    }

def _abi_variadic_fixed_arg_count(symbol: str) -> int:
    lower = symbol.lower()
    if "fprintf" in lower or "sprintf" in lower or "snprintf" in lower:
        return 2
    return 1

def _abi_printf_conversions(format_text: str) -> list[dict[str, Any]]:
    conversions: list[dict[str, Any]] = []
    index = 0
    length = len(format_text)
    while index < length:
        if format_text[index] != "%":
            index += 1
            continue
        start = index
        index += 1
        if index < length and format_text[index] == "%":
            index += 1
            continue
        while index < length and format_text[index] in "-+ #0'":
            index += 1
        while index < length and (format_text[index].isdigit() or format_text[index] == "*"):
            if format_text[index] == "*":
                conversions.append({"offset": start, "specifier": "*", "kind": "dynamic_width"})
            index += 1
        if index < length and format_text[index] == ".":
            index += 1
            while index < length and (format_text[index].isdigit() or format_text[index] == "*"):
                if format_text[index] == "*":
                    conversions.append({"offset": start, "specifier": "*", "kind": "dynamic_precision"})
                index += 1
        while index < length and format_text[index] in "hljztL":
            index += 1
        if index < length:
            specifier = format_text[index]
            if specifier not in "n":
                conversions.append({"offset": start, "specifier": specifier, "kind": "value"})
            index += 1
    return conversions

def _abi_function_pointer_targets(target: dict[str, Any]) -> list[dict[str, Any]]:
    if target.get("kind") != "function_pointer":
        return []
    item: dict[str, Any] = {"status": target.get("status") or "unresolved", "operand": target.get("operand")}
    for key in ("memory_rva", "memory_role", "source", "recoverable_targets"):
        if key in target:
            item[key] = target[key]
    return [item]

def _abi_import_prototypes(binary: StageABinary) -> list[dict[str, Any]]:
    return [
        {
            "dll": item.dll,
            "symbol": item.symbol,
            "ordinal": item.ordinal,
            "thunk_rva": item.thunk_rva,
            "calling_convention": "stdcall" if item.symbol and "@" in item.symbol else "unknown",
            "varargs_evidence": _abi_varargs_evidence(item.symbol or "", None),
        }
        for item in binary.imports
    ]

__all__ = [
    '_abi_address_argument_role',
    '_abi_address_class',
    '_abi_address_like_argument_source',
    '_abi_argument_role',
    '_abi_argument_source',
    '_abi_attach_immediate_literal',
    '_abi_attach_register_definition',
    '_abi_call_argument_inventory',
    '_abi_call_register_argument_order',
    '_abi_call_target',
    '_abi_callsite_evidence',
    '_abi_fixed_stack_arg_count_for_target',
    '_abi_format_string_evidence',
    '_abi_function_pointer_target_from_source',
    '_abi_function_pointer_targets',
    '_abi_hidden_sret_evidence',
    '_abi_import_prototypes',
    '_abi_operand_argument_source',
    '_abi_pending_argument_sources',
    '_abi_printf_conversions',
    '_abi_register_argument_evidence',
    '_abi_register_call_target',
    '_abi_register_definition',
    '_abi_resets_pending_arguments',
    '_abi_stack_argument_write_offset',
    '_abi_stack_argument_write_source',
    '_abi_static_function_pointer_targets',
    '_abi_update_register_definitions',
    '_abi_varargs_evidence',
    '_abi_variadic_fixed_arg_count',
    '_abi_x86_direct_target_register_argument_order',
    '_abi_x86_entry_read_before_write_registers',
    '_abi_x86_zero_idiom_register',
    '_import_for_call_instruction',
]
