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

def _stage_a_abi_profile_comparison_gaps(comparison_gaps: dict[str, Any]) -> dict[str, Any]:
    function_mismatches = [
        item
        for item in comparison_gaps.get("function_mismatches", [])
        if isinstance(item, dict) and _stage_a_abi_profile_function_mismatch_is_hard(item)
    ]
    callsite_mismatches = [
        item for item in comparison_gaps.get("callsite_mismatches", []) if isinstance(item, dict)
    ]
    incomplete_callsites = [
        item for item in comparison_gaps.get("incomplete_callsites", []) if isinstance(item, dict)
    ]
    missing_functions = [
        item for item in comparison_gaps.get("missing_functions", []) if isinstance(item, dict)
    ]
    ambiguous_functions = [
        item for item in comparison_gaps.get("ambiguous_functions", []) if isinstance(item, dict)
    ]
    return {
        "missing_functions": missing_functions,
        "ambiguous_functions": ambiguous_functions,
        "incomplete_callsites": incomplete_callsites,
        "function_mismatches": function_mismatches,
        "callsite_mismatches": callsite_mismatches,
        "counts": {
            "missing_functions": len(missing_functions),
            "ambiguous_functions": len(ambiguous_functions),
            "incomplete_callsite_functions": len(incomplete_callsites),
            "missing_callsites": sum(int(item.get("missing_callsites") or 0) for item in incomplete_callsites),
            "function_mismatches": len(function_mismatches),
            "callsite_mismatches": len(callsite_mismatches),
        },
    }

def _stage_a_abi_profile_function_mismatch_is_hard(mismatch: dict[str, Any]) -> bool:
    issues = mismatch.get("issues") if isinstance(mismatch.get("issues"), list) else []
    categories = {str(item.get("category") or "") for item in issues if isinstance(item, dict)}
    return bool(categories & STAGE_A_ABI_PROFILE_FUNCTION_MISMATCH_CATEGORIES)

__all__ = [
    '_stage_a_abi_profile_comparison_gaps',
    '_stage_a_abi_profile_function_mismatch_is_hard',
]
