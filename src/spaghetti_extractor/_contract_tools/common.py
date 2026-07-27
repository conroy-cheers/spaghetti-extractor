"""Shared models and small utilities for contract tooling."""

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
from ..relational.semantic_cutpoints import semantic_cutpoint_spans_for_side
from ..util import sha256_bytes, sha256_file, utc_now, write_json


CHECKED_GENERATED_MAPPING_PROOF_RULES = {
    "same_source_layout_preserving_build_v1",
    "stage_b_skeleton_reimplementation_contract_v1",
}

REFERENCE_CONTRACT_MODEL_ID = "x86-pe32-relational-v3"

NORETURN_IMPORT_SYMBOLS = {
    "abort",
    "amsg_exit",
    "exit",
    "exitprocess",
    "terminateprocess",
}

ABI_FIXED_STDCALL_IMPORT_STACK_ARG_COUNTS = {
    "arefileapisansi": 0,
    "deletecriticalsection": 1,
    "entercriticalsection": 1,
    "getconsolemode": 2,
    "getlasterror": 0,
    "gettickcount": 0,
    "getmodulehandlea": 1,
    "getprocaddress": 2,
    "getstdhandle": 1,
    "gettimezoneinformation": 1,
    "initializecriticalsection": 1,
    "isdbcsleadbyteex": 2,
    "leavecriticalsection": 1,
    "multibytetowidechar": 6,
    "pathisrelativea": 1,
    "setconsolemode": 2,
    "setunhandledexceptionfilter": 1,
    "sleep": 1,
    "tlsgetvalue": 1,
    "virtualprotect": 4,
    "virtualquery": 3,
    "widechartomultibyte": 8,
    "writeconsolew": 5,
    "writefile": 5,
}

STAGE_A_ABI_PROFILE_FUNCTION_MISMATCH_CATEGORIES = {
    "stack_delta_mismatch",
    "preserved_register_mismatch",
    "clobbered_register_mismatch",
}

@dataclass(frozen=True)
class BlockMapping:
    id: str
    original: BlockSide
    candidate: BlockSide
    kind: str
    reachable: bool
    invariant_checked: bool
    source: dict[str, Any]

@dataclass(frozen=True)
class NonCodeWaiver:
    id: str
    binary: str
    rva_start: int
    rva_end: int
    reason: str

def _range_report(side: BlockSide) -> dict[str, int]:
    return {"rva_start": side.rva_start, "rva_end": side.rva_end, "size": side.size}

def _mapping_source(mapped: BlockMapping) -> dict[str, Any]:
    source = mapped.source.get("source")
    return source if isinstance(source, dict) else {}

def _parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise StageAInputError(f"expected integer or integer string, got {value!r}")

def _is_conditional_jump(mnemonic: str) -> bool:
    return mnemonic in {
        "ja",
        "jae",
        "jb",
        "jbe",
        "jc",
        "je",
        "jg",
        "jge",
        "jl",
        "jle",
        "jna",
        "jnae",
        "jnb",
        "jnbe",
        "jnc",
        "jne",
        "jng",
        "jnge",
        "jnl",
        "jnle",
        "jno",
        "jnp",
        "jns",
        "jnz",
        "jo",
        "jp",
        "jpe",
        "jpo",
        "js",
        "jz",
    }

def _incomplete_record(
    *,
    category: str,
    obligation_id: str,
    blocker: str,
    next_action: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "severity": "incomplete",
        "status": "incomplete",
        "category": category,
        "obligation_id": obligation_id,
        "blocker": blocker,
        "next_action": next_action,
        "details": details or {},
    }

def _failure_record(
    *,
    category: str,
    obligation_id: str,
    blocker: str,
    original: Any,
    candidate: Any,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "severity": "fail",
        "status": "failed",
        "category": category,
        "obligation_id": obligation_id,
        "blocker": blocker,
        "original": original,
        "candidate": candidate,
        "details": details or {},
    }

__all__ = [
    'ABI_FIXED_STDCALL_IMPORT_STACK_ARG_COUNTS',
    'BlockMapping',
    'CHECKED_GENERATED_MAPPING_PROOF_RULES',
    'NORETURN_IMPORT_SYMBOLS',
    'NonCodeWaiver',
    'REFERENCE_CONTRACT_MODEL_ID',
    'STAGE_A_ABI_PROFILE_FUNCTION_MISMATCH_CATEGORIES',
    '_failure_record',
    '_incomplete_record',
    '_is_conditional_jump',
    '_mapping_source',
    '_parse_int',
    '_range_report',
]
