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

from ..stage_binary import (
    BlockSide,
    StageABinary,
    StageAImport,
    StageAInputError,
    StageASection,
    _artifact_name,
    _coff_symbol_aliases_by_rva,
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

from .abi_support import (
    _count_by,
    _safe_int,
)

def _abi_instruction_is_semantic_noop(insn: Any) -> bool:
    mnemonic = str(insn.mnemonic)
    if mnemonic == "nop":
        return True
    if mnemonic == "xchg" and len(insn.operands) == 2:
        left = _abi_operand_register_name(insn, insn.operands[0])
        right = _abi_operand_register_name(insn, insn.operands[1])
        return bool(left and right and left == right)
    if mnemonic != "lea" or len(insn.operands) != 2:
        return False
    destination = _abi_operand_register_name(insn, insn.operands[0])
    source = insn.operands[1]
    if not destination or source.type != X86_OP_MEM:
        return False
    base = _abi_x86_register_family(insn.reg_name(source.mem.base) if source.mem.base else None)
    index = _abi_x86_register_family(insn.reg_name(source.mem.index) if source.mem.index else None)
    destination = _abi_x86_register_family(destination)
    return base == destination and not index and int(source.mem.disp) == 0

def _abi_operand_register_name(insn: Any, operand: Any) -> str | None:
    if operand.type != X86_OP_REG:
        return None
    return _abi_x86_register_family(insn.reg_name(operand.reg))

def _instruction_register_access(insn: Any) -> tuple[set[str], set[str]]:
    reads: set[str] = set()
    writes: set[str] = set()
    try:
        read_ids, write_ids = insn.regs_access()
    except Exception:
        read_ids, write_ids = (), ()
    for reg in read_ids:
        name = insn.reg_name(reg)
        if name:
            reads.add(str(name))
    for reg in write_ids:
        name = insn.reg_name(reg)
        if name:
            writes.add(str(name))
    return reads, writes

def _abi_instruction_memory_accesses(
    binary: StageABinary,
    insn: Any,
    register_definitions: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    reads: list[dict[str, Any]] = []
    writes: list[dict[str, Any]] = []
    field_accesses: list[dict[str, Any]] = []
    mnemonic = str(insn.mnemonic)
    for index, operand in enumerate(getattr(insn, "operands", []) or []):
        if operand.type != X86_OP_MEM:
            continue
        if mnemonic == "lea":
            continue
        access_kind = _abi_operand_memory_access_kind(insn, index)
        if access_kind is None:
            continue
        access = _abi_memory_access_report(binary, insn, operand, access_kind, register_definitions)
        if access_kind == "read":
            reads.append(access)
        elif access_kind == "write":
            writes.append(access)
        else:
            reads.append({**access, "access": "read"})
            writes.append({**access, "access": "write"})
        field = _abi_field_access_report(access)
        if field is not None:
            field_accesses.append(field)
    return {"reads": reads, "writes": writes, "field_accesses": field_accesses}

def _abi_operand_memory_access_kind(insn: Any, operand_index: int) -> str | None:
    mnemonic = str(insn.mnemonic)
    if mnemonic in {"jmp", "ljmp", "call"}:
        return "read"
    if mnemonic in {"cmp", "test"}:
        return "read"
    if mnemonic == "push":
        return "read"
    if mnemonic == "pop":
        return "write"
    if mnemonic in {"inc", "dec", "neg", "not"}:
        return "read_write"
    if mnemonic in {"mov", "movzx", "movsx", "lea"}:
        return "write" if operand_index == 0 and mnemonic == "mov" else "read"
    if operand_index == 0 and mnemonic in {"add", "sub", "and", "or", "xor", "shl", "shr", "sar", "rol", "ror"}:
        return "read_write"
    return "read"

def _abi_memory_access_report(
    binary: StageABinary,
    insn: Any,
    operand: Any,
    access_kind: str,
    register_definitions: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    addressing = _abi_mem_operand_report(insn, operand)
    access: dict[str, Any] = {
        "evidence_status": "derived",
        "access": access_kind,
        "width": int(getattr(operand, "size", 0) or 0),
        "addressing": addressing,
        "instruction": _instruction_report(binary, insn),
    }
    memory_rva = _abi_absolute_addressing_rva(binary, addressing)
    if memory_rva is not None:
        access["memory_rva"] = memory_rva
        imported = _import_for_thunk_rva(binary, memory_rva)
        if imported is not None:
            access["import"] = _abi_import_report(imported)
        section = _section_for_rva(binary, memory_rva)
        if section is not None:
            access["memory_section"] = _abi_section_report(section)
        string_literal = _abi_string_literal_at_rva(binary, memory_rva)
        if string_literal is not None:
            access["string_literal"] = string_literal
    base = addressing.get("base")
    if isinstance(base, str):
        base_definition = register_definitions.get(base)
        if isinstance(base_definition, dict):
            access["base_register_definition"] = base_definition
        elif base not in {"esp", "ebp", "rsp", "rbp"}:
            access["entry_register_pointer"] = {
                "register": base,
                "evidence_status": "candidate",
                "reason": "memory access uses an entry register as a base before a local definition was observed",
            }
    access["memory_role"] = _abi_memory_role(access)
    return access

def _abi_field_access_report(access: dict[str, Any]) -> dict[str, Any] | None:
    addressing = access.get("addressing") if isinstance(access.get("addressing"), dict) else {}
    base = addressing.get("base")
    disp = _safe_int(addressing.get("disp"))
    if not isinstance(base, str) or disp is None:
        return None
    if base in {"esp", "ebp", "rsp", "rbp"} and disp == 0:
        return None
    return {
        "evidence_status": "derived",
        "base": base,
        "offset": disp,
        "width": access.get("width"),
        "access": access.get("access"),
        "memory_role": access.get("memory_role"),
        "instruction": access.get("instruction"),
        "base_register_definition": access.get("base_register_definition") if isinstance(access.get("base_register_definition"), dict) else None,
    }

def _abi_register_out_param_candidates(memory_writes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for write in memory_writes:
        if not isinstance(write, dict):
            continue
        entry_pointer = write.get("entry_register_pointer") if isinstance(write.get("entry_register_pointer"), dict) else None
        if entry_pointer is None:
            continue
        result.append(
            {
                "evidence_status": "candidate",
                "register": entry_pointer.get("register"),
                "kind": "register_carried_out_param",
                "reason": "function writes through an entry register pointer before defining that register",
                "write": write,
            }
        )
    return result

def _abi_memory_effect_summary(reads: list[dict[str, Any]], writes: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "evidence_status": "derived",
        "reads": len([item for item in reads if isinstance(item, dict)]),
        "writes": len([item for item in writes if isinstance(item, dict)]),
        "read_roles": _count_by([item for item in reads if isinstance(item, dict)], "memory_role"),
        "write_roles": _count_by([item for item in writes if isinstance(item, dict)], "memory_role"),
    }

def _abi_x86_register_family(register: str | None) -> str:
    name = str(register or "").lower()
    families = {
        "eax": {"eax", "ax", "al", "ah"},
        "ebx": {"ebx", "bx", "bl", "bh"},
        "ecx": {"ecx", "cx", "cl", "ch"},
        "edx": {"edx", "dx", "dl", "dh"},
        "esi": {"esi", "si", "sil"},
        "edi": {"edi", "di", "dil"},
        "ebp": {"ebp", "bp", "bpl"},
        "esp": {"esp", "sp", "spl"},
    }
    for full, names in families.items():
        if name in names:
            return full
    return name

def _abi_loop_hints(binary: StageABinary, block: BlockSide, instructions: list[Any]) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    for insn in instructions:
        target = _resolved_branch_target(binary, insn)
        if target is None or target >= block.rva_end:
            continue
        mnemonic = str(insn.mnemonic)
        if mnemonic not in {"jmp", "ljmp"} and not _is_conditional_jump(mnemonic):
            continue
        hints.append(
            {
                "evidence_status": "derived",
                "kind": "backedge_candidate",
                "block": _range_report(block),
                "instruction": _instruction_report(binary, insn),
                "target_rva": target,
                "next_action": "derive loop-carried variables and exit conditions before treating this as a full loop contract",
            }
        )
    return hints

def _abi_ret_imm(insn: Any) -> int:
    if len(insn.operands) != 1 or insn.operands[0].type != X86_OP_IMM:
        return 0
    return int(insn.operands[0].imm)

def _abi_stack_pointer_adjustment(binary: StageABinary, insn: Any) -> int | None:
    if len(insn.operands) < 2:
        return None
    mnemonic = str(insn.mnemonic)
    if mnemonic not in {"add", "sub"}:
        return None
    dst, src = insn.operands[:2]
    if dst.type != X86_OP_REG or src.type != X86_OP_IMM:
        return None
    stack_register = "esp" if binary.bitness == 32 else "rsp"
    if insn.reg_name(dst.reg) != stack_register:
        return None
    value = int(src.imm)
    return value if mnemonic == "add" else -value

def _abi_value_to_rva(binary: StageABinary, value: int) -> int | None:
    if binary.image_base <= value < binary.image_base + binary.size_of_image:
        return value - binary.image_base
    if 0 <= value < binary.size_of_image and _section_for_rva(binary, value) is not None:
        return value
    return None

def _abi_string_literal_at_rva(binary: StageABinary, rva: int) -> dict[str, Any] | None:
    section = _section_for_rva(binary, rva)
    if section is None or not section.readable or section.executable:
        return None
    data = binary.pe.get_data(rva, 256)
    if not data:
        return None
    end = data.find(b"\0")
    if end < 0:
        return None
    raw = data[:end]
    if not raw:
        return None
    if any(byte < 0x09 or (0x0E <= byte < 0x20) for byte in raw):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")
    return {
        "evidence_status": "derived",
        "rva": rva,
        "size": len(raw) + 1,
        "text": text,
        "sha256": sha256_bytes(raw),
    }

def _abi_mem_operand_report(insn: Any, operand: Any) -> dict[str, Any]:
    mem = operand.mem
    return {
        "base": insn.reg_name(mem.base) if mem.base else None,
        "index": insn.reg_name(mem.index) if mem.index else None,
        "scale": int(mem.scale),
        "disp": int(mem.disp),
    }

def _abi_section_report(section: StageASection) -> dict[str, Any]:
    return {
        "name": section.name,
        "rva_start": section.rva_start,
        "rva_end": section.rva_end,
        "readable": section.readable,
        "writable": section.writable,
        "executable": section.executable,
    }

def _abi_memory_role(source: dict[str, Any]) -> str:
    if isinstance(source.get("import"), dict):
        return "import_address_table"
    section = source.get("memory_section") if isinstance(source.get("memory_section"), dict) else {}
    if source.get("memory_rva") is not None:
        if section.get("writable") is True:
            return "global_writable_pointer_slot"
        if section:
            return "global_readonly_pointer_slot"
        return "absolute_memory_slot"
    addressing = source.get("addressing") if isinstance(source.get("addressing"), dict) else {}
    base = str(addressing.get("base") or "")
    if base in {"ebp", "rbp"}:
        disp = _safe_int(addressing.get("disp")) or 0
        return "stack_argument_slot" if disp >= 0 else "stack_local_slot"
    if base in {"esp", "rsp"}:
        return "stack_pointer_slot"
    base_definition = source.get("base_register_definition") if isinstance(source.get("base_register_definition"), dict) else None
    if base_definition is not None:
        base_role = str(base_definition.get("memory_role") or "")
        if base_role == "stack_argument_slot":
            return "argument_pointer_deref"
        if base_definition.get("memory_rva") is not None:
            return "global_pointer_deref"
        return "computed_pointer_deref"
    return "computed_memory"

def _abi_import_report(item: StageAImport) -> dict[str, Any]:
    return {
        "dll": item.dll,
        "symbol": item.symbol,
        "ordinal": item.ordinal,
        "thunk_rva": item.thunk_rva,
    }

def _abi_absolute_addressing_rva(binary: StageABinary, addressing: dict[str, Any]) -> int | None:
    if addressing.get("base") or addressing.get("index"):
        return None
    address = _safe_int(addressing.get("disp"))
    if address is None:
        return None
    if binary.image_base <= address < binary.image_base + binary.size_of_image:
        return address - binary.image_base
    if 0 <= address < binary.size_of_image:
        return address
    return None

__all__ = [
    '_abi_absolute_addressing_rva',
    '_abi_field_access_report',
    '_abi_import_report',
    '_abi_instruction_is_semantic_noop',
    '_abi_instruction_memory_accesses',
    '_abi_loop_hints',
    '_abi_mem_operand_report',
    '_abi_memory_access_report',
    '_abi_memory_effect_summary',
    '_abi_memory_role',
    '_abi_operand_memory_access_kind',
    '_abi_operand_register_name',
    '_abi_register_out_param_candidates',
    '_abi_ret_imm',
    '_abi_section_report',
    '_abi_stack_pointer_adjustment',
    '_abi_string_literal_at_rva',
    '_abi_value_to_rva',
    '_abi_x86_register_family',
    '_instruction_register_access',
]
