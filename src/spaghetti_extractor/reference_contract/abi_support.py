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

def _nested_dict(value: dict[str, Any], *path: str) -> dict[str, Any]:
    current: Any = value
    for key in path:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}

def _block_id_for_instruction(function: dict[str, Any], instruction: dict[str, Any]) -> str | None:
    rva = _safe_int(instruction.get("rva")) if isinstance(instruction, dict) else None
    if rva is None:
        return None
    for block in function.get("blocks", []) if isinstance(function.get("blocks"), list) else []:
        if not isinstance(block, dict):
            continue
        start = _safe_int(block.get("rva_start"))
        end = _safe_int(block.get("rva_end"))
        if start is not None and end is not None and start <= rva < end:
            block_id = block.get("block_id")
            return str(block_id) if block_id not in {None, ""} else None
    return None

def _contract_constraint(contract: dict[str, Any], key: str) -> dict[str, Any]:
    constraints = contract.get("constraints") if isinstance(contract.get("constraints"), dict) else {}
    value = constraints.get(key)
    return value if isinstance(value, dict) else {}

def _safe_gap_part(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.:@+-]+", "-", value.strip())
    return text.strip("-") or "unknown"

def _safe_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None

def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))

def _empty_contract_candidate_alias_evidence(*, status: str = "not_applicable") -> dict[str, Any]:
    return {
        "format": "stage-a-contract-candidate-alias-evidence-v1",
        "status": status,
        "matches_by_reference": {},
        "ambiguities_by_reference": {},
        "unmatched_by_reference": {},
        "alias_matches": [],
        "ambiguities": [],
        "unmatched_aliases": [],
        "counts": {"alias_matches": 0, "ambiguities": 0, "unmatched_aliases": 0},
    }

def _contract_candidate_function_symbol_names(function: dict[str, Any]) -> list[str]:
    names: list[str] = []
    name = function.get("name")
    if isinstance(name, str) and name:
        names.append(name)
    aliases = function.get("aliases") if isinstance(function.get("aliases"), list) else []
    names.extend(alias for alias in aliases if isinstance(alias, str) and alias)
    return _dedupe_strings(names)

def _contract_candidate_symbol_keys(name: str) -> set[str]:
    variants = {name}
    if name.startswith("@"):
        stripped = name[1:]
        variants.add(stripped)
        if "@" in stripped:
            left, right = stripped.rsplit("@", 1)
            if right.isdigit():
                variants.add(left)
    if "@" in name:
        left, right = name.rsplit("@", 1)
        if right.isdigit():
            variants.add(left)
    keys = set()
    for variant in variants:
        keys.add(variant)
        keys.add(_linker_function_match_key(variant))
    return {key for key in keys if key}

def _dedupe_strings(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result

def _optional_contract_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None

def _abi_function_local_loop_hint_count(function: dict[str, Any]) -> int:
    return len(_abi_function_local_loop_hints(function))

def _abi_function_local_loop_hints(function: dict[str, Any]) -> list[dict[str, Any]]:
    hints = function.get("loop_hints") if isinstance(function.get("loop_hints"), list) else []
    return [hint for hint in hints if isinstance(hint, dict) and _abi_loop_hint_is_function_local(function, hint)]

def _abi_loop_hint_is_function_local(function: dict[str, Any], hint: dict[str, Any]) -> bool:
    target = _safe_int(hint.get("target_rva"))
    if target is None:
        return False
    for block in function.get("blocks", []) if isinstance(function.get("blocks"), list) else []:
        if not isinstance(block, dict):
            continue
        start = _safe_int(block.get("rva_start"))
        end = _safe_int(block.get("rva_end"))
        if start is not None and end is not None and start <= target < end:
            return True
    return False

def _abi_loop_hint_key(hint: dict[str, Any]) -> tuple[int, int]:
    instruction = hint.get("instruction") if isinstance(hint.get("instruction"), dict) else {}
    return (_safe_int(instruction.get("rva")) or -1, _safe_int(hint.get("target_rva")) or -1)

__all__ = [
    '_abi_function_local_loop_hint_count',
    '_abi_function_local_loop_hints',
    '_abi_loop_hint_is_function_local',
    '_abi_loop_hint_key',
    '_block_id_for_instruction',
    '_contract_candidate_function_symbol_names',
    '_contract_candidate_symbol_keys',
    '_contract_constraint',
    '_count_by',
    '_dedupe_strings',
    '_empty_contract_candidate_alias_evidence',
    '_nested_dict',
    '_optional_contract_int',
    '_safe_gap_part',
    '_safe_int',
]
