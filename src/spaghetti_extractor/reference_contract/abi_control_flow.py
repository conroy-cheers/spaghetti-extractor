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
    _abi_mem_operand_report,
    _abi_section_report,
    _abi_value_to_rva,
    _abi_x86_register_family,
)

def _abi_switch_contracts(binary: StageABinary, block: BlockSide, instructions: list[Any]) -> list[dict[str, Any]]:
    contracts: list[dict[str, Any]] = []
    for insn in instructions:
        mnemonic = str(insn.mnemonic)
        if mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1 or insn.operands[0].type != X86_OP_MEM:
            continue
        target = _resolved_branch_target(binary, insn)
        addressing = _abi_mem_operand_report(insn, insn.operands[0])
        if _abi_refptr_direct_transfer(binary, block, insn, addressing, target) is not None:
            continue
        table_contract = _abi_indexed_jump_table_contract(binary, block, instructions, insn, addressing)
        if table_contract is not None:
            contracts.append(table_contract)
            continue
        contracts.append(
            {
                "evidence_status": "derived" if target is not None else "incomplete",
                "kind": "indirect_jump_table_candidate",
                "block": _range_report(block),
                "instruction": _instruction_report(binary, insn),
                "index_expression": addressing,
                "resolved_target_rva": target,
                "next_action": "recover table bounds, default edge, and case target mapping before treating this as a source-level switch",
            }
        )
    return contracts

def _abi_direct_refptr_transfers(binary: StageABinary, block: BlockSide, instructions: list[Any]) -> list[dict[str, Any]]:
    transfers: list[dict[str, Any]] = []
    for insn in instructions:
        mnemonic = str(insn.mnemonic)
        if mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1 or insn.operands[0].type != X86_OP_MEM:
            continue
        addressing = _abi_mem_operand_report(insn, insn.operands[0])
        transfer = _abi_refptr_direct_transfer(binary, block, insn, addressing, _resolved_branch_target(binary, insn))
        if transfer is not None:
            transfers.append(transfer)
    return transfers

def _abi_refptr_direct_transfer(
    binary: StageABinary,
    block: BlockSide,
    insn: Any,
    addressing: dict[str, Any],
    target: int | None,
) -> dict[str, Any] | None:
    if target is None:
        return None
    if addressing.get("base") is not None or addressing.get("index") is not None:
        return None
    pointer_rva = _absolute_mem_operand_rva(binary, insn.operands[0])
    if pointer_rva is None:
        return None
    return {
        "evidence_status": "derived",
        "kind": "resolved_refptr_direct_transfer",
        "block": _range_report(block),
        "instruction": _instruction_report(binary, insn),
        "pointer_rva": pointer_rva,
        "pointer_section": _abi_section_report(section) if (section := _section_for_rva(binary, pointer_rva)) is not None else None,
        "target_rva": target,
        "target_section": _abi_section_report(section) if (section := _section_for_rva(binary, target)) is not None else None,
        "normalization": "candidate may cover this with an equivalent direct branch when the refptr target is resolved by Stage A",
    }

def _abi_direct_control_transfers(binary: StageABinary, block: BlockSide, instructions: list[Any]) -> list[dict[str, Any]]:
    transfers: list[dict[str, Any]] = []
    for insn in instructions:
        mnemonic = str(insn.mnemonic)
        if mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1:
            continue
        target = _direct_branch_target(insn, binary.image_base)
        if target is None:
            continue
        transfers.append(
            {
                "evidence_status": "derived",
                "kind": "direct_control_transfer",
                "block": _range_report(block),
                "instruction": _instruction_report(binary, insn),
                "target_rva": target,
                "target_section": _abi_section_report(section) if (section := _section_for_rva(binary, target)) is not None else None,
            }
        )
    return transfers

def _abi_indexed_jump_table_contract(
    binary: StageABinary,
    block: BlockSide,
    instructions: list[Any],
    insn: Any,
    addressing: dict[str, Any],
    *,
    bounds_override: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if binary.bitness != 32:
        return None
    operand = insn.operands[0]
    mem = operand.mem
    pointer_width = 4
    index_register = insn.reg_name(mem.index) if mem.index else None
    if not index_register or mem.base or int(mem.scale) != pointer_width:
        return None
    table_rva = _abi_value_to_rva(binary, int(mem.disp))
    if table_rva is None:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table displacement is not an in-image table address",
        )
    table_section = _section_for_rva(binary, table_rva)
    if table_section is None or not table_section.readable:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table address does not resolve to readable PE section bytes",
            table_rva=table_rva,
        )
    bounds = bounds_override if bounds_override is not None else _abi_jump_table_index_bounds(binary, instructions, insn, index_register)
    if bounds is None:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table index bounds are not statically recovered",
            table_rva=table_rva,
        )
    lower = int(bounds["lower"])
    upper = int(bounds["upper"])
    if lower < 0 or upper < lower or upper - lower + 1 > 4096:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table index bounds are invalid or exceed the conservative resolver cap",
            table_rva=table_rva,
        )

    case_targets: list[dict[str, Any]] = []
    table_bytes = bytearray()
    for index in range(lower, upper + 1):
        entry_rva = table_rva + index * pointer_width
        raw = binary.pe.get_data(entry_rva, pointer_width)
        if len(raw) != pointer_width:
            return _abi_incomplete_indexed_jump_table_contract(
                binary,
                block,
                insn,
                addressing,
                f"jump-table entry {index} could not be read",
                table_rva=table_rva,
                table_bounds=bounds,
            )
        table_bytes.extend(raw)
        target_va = int.from_bytes(raw, "little")
        target_rva = _abi_value_to_rva(binary, target_va)
        target_section = _executable_section_for_rva(binary, target_rva) if target_rva is not None else None
        if target_rva is None or target_section is None:
            return _abi_incomplete_indexed_jump_table_contract(
                binary,
                block,
                insn,
                addressing,
                f"jump-table entry {index} does not resolve to executable code",
                table_rva=table_rva,
                table_bounds=bounds,
            )
        case_targets.append(
            {
                "index": index,
                "entry_rva": entry_rva,
                "entry_va": binary.image_base + entry_rva,
                "target_va": target_va,
                "target_rva": target_rva,
                "target_section": _abi_section_report(target_section),
            }
        )
    if not case_targets:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table bounds produced no case entries",
            table_rva=table_rva,
            table_bounds=bounds,
        )
    unique_targets = sorted({int(item["target_rva"]) for item in case_targets})
    return {
        "evidence_status": "derived",
        "kind": "indirect_jump_table_candidate",
        "block": _range_report(block),
        "instruction": _instruction_report(binary, insn),
        "index_expression": addressing,
        "index_bounds": bounds,
        "table": {
            "rva_start": table_rva,
            "rva_end": table_rva + len(table_bytes),
            "va_start": binary.image_base + table_rva,
            "entry_width": pointer_width,
            "entries": len(case_targets),
            "bytes_sha256": sha256_bytes(bytes(table_bytes)),
            "section": _abi_section_report(table_section),
        },
        "table_bounds": {
            "lower": lower,
            "upper": upper,
            "entries": len(case_targets),
            "source": bounds.get("source"),
        },
        "case_targets": case_targets,
        "unique_target_rvas": unique_targets,
        "resolved_target_rva": unique_targets[0] if len(unique_targets) == 1 else None,
        "default_target_rva": None,
        "next_action": "represent this dispatch with the recovered selector, bounded case table, and explicit jump targets",
    }

def _abi_incomplete_indexed_jump_table_contract(
    binary: StageABinary,
    block: BlockSide,
    insn: Any,
    addressing: dict[str, Any],
    blocker: str,
    *,
    table_rva: int | None = None,
    table_bounds: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "evidence_status": "incomplete",
        "kind": "indirect_jump_table_candidate",
        "block": _range_report(block),
        "instruction": _instruction_report(binary, insn),
        "index_expression": addressing,
        "resolved_target_rva": None,
        "blocker": blocker,
        "next_action": "recover table bounds, default edge, and case target mapping before treating this as a source-level switch",
    }
    if table_rva is not None:
        result["table"] = {
            "rva_start": table_rva,
            "va_start": binary.image_base + table_rva,
            "entry_width": 4 if binary.bitness == 32 else 8,
        }
    if table_bounds is not None:
        result["table_bounds"] = table_bounds
    return result

def _abi_jump_table_index_bounds(
    binary: StageABinary,
    instructions: list[Any],
    insn: Any,
    index_register: str,
) -> dict[str, Any] | None:
    index_rva = int(insn.address - binary.image_base)
    full_index = _abi_x86_register_family(index_register)
    for previous in reversed([item for item in instructions if int(item.address - binary.image_base) < index_rva]):
        mnemonic = str(previous.mnemonic)
        operands = getattr(previous, "operands", []) or []
        if mnemonic == "movzx" and len(operands) == 2 and operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
            dst = _abi_x86_register_family(previous.reg_name(operands[0].reg))
            src = previous.reg_name(operands[1].reg)
            if dst == full_index and _abi_x86_register_family(src) == full_index:
                width = int(getattr(operands[1], "size", 0) or 0)
                if width > 0:
                    return {
                        "status": "derived",
                        "lower": 0,
                        "upper": (1 << (width * 8)) - 1,
                        "register": full_index,
                        "source": "movzx_register_width",
                        "source_instruction": _instruction_report(binary, previous),
                    }
        if mnemonic == "and" and len(operands) == 2 and operands[0].type == X86_OP_REG and operands[1].type == X86_OP_IMM:
            dst = _abi_x86_register_family(previous.reg_name(operands[0].reg))
            mask = int(operands[1].imm)
            if dst == full_index and 0 <= mask <= 4095:
                return {
                    "status": "derived",
                    "lower": 0,
                    "upper": mask,
                    "register": full_index,
                    "source": "and_immediate_mask",
                    "source_instruction": _instruction_report(binary, previous),
                }
        if mnemonic in {"call", "ret", "jmp", "ljmp"} or _is_conditional_jump(mnemonic):
            break
    return None

__all__ = [
    '_abi_direct_control_transfers',
    '_abi_direct_refptr_transfers',
    '_abi_incomplete_indexed_jump_table_contract',
    '_abi_indexed_jump_table_contract',
    '_abi_jump_table_index_bounds',
    '_abi_refptr_direct_transfer',
    '_abi_switch_contracts',
]
