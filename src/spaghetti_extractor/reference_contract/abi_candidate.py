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

from .abi import (
    _abi_function_evidence,
)

from .abi_arguments import (
    _abi_import_prototypes,
)

from .abi_support import (
    _optional_contract_int,
)

def _candidate_abi_constraint_from_functions(
    candidate: StageABinary,
    candidate_functions: list[dict[str, Any]],
    *,
    reference_abi: dict[str, Any] | None = None,
    alias_evidence: dict[str, Any] | None = None,
    candidate_rva_anchors: dict[int, int] | None = None,
) -> dict[str, Any]:
    mappings = _candidate_abi_block_mappings_from_functions(candidate, candidate_functions)
    reference_section_gap_mappings = _candidate_reference_section_gap_abi_mappings(
        candidate,
        reference_abi,
        alias_evidence=alias_evidence,
        candidate_rva_anchors=candidate_rva_anchors,
    )
    mappings.extend(reference_section_gap_mappings)
    functions = _abi_function_evidence(candidate, mappings, side="candidate", compose_direct_callee_import_memory=True)
    return {
        "status": "satisfied" if functions else "incomplete",
        "evidence_kind": "capstone-static-abi-callsites",
        "candidate": {
            "functions": functions,
            "import_prototypes": _abi_import_prototypes(candidate),
            "reference_section_gap_probes": {
                "kind": "candidate_section_gap_probe",
                "count": len(reference_section_gap_mappings),
                "contract_rva_anchors": len(candidate_rva_anchors or {}),
            },
        },
        "counts": {
            "functions": len(functions),
            "callsites": sum(len(item.get("callsites", [])) for item in functions),
            "import_prototypes": len(candidate.imports),
            "reference_section_gap_probes": len(reference_section_gap_mappings),
        },
    }

def _candidate_abi_block_mappings_from_functions(
    candidate: StageABinary,
    candidate_functions: list[dict[str, Any]],
) -> list[BlockMapping]:
    mappings: list[BlockMapping] = []
    for function_index, function in enumerate(candidate_functions):
        rva_start = _optional_contract_int(function.get("rva_start"))
        rva_end = _optional_contract_int(function.get("rva_end"))
        if rva_start is None or rva_end is None or rva_end <= rva_start:
            continue
        name = str(function.get("name") or f"function_{function_index:04d}")
        blocks = _recover_basic_blocks(candidate, rva_start, rva_end)
        for block_index, block in enumerate(blocks):
            block_start = _optional_contract_int(block.get("rva_start"))
            block_end = _optional_contract_int(block.get("rva_end"))
            if block_start is None or block_end is None or block_end <= block_start:
                continue
            mappings.append(
                BlockMapping(
                    id=_artifact_name(f"{name}-{block_index:04d}"),
                    kind="code",
                    original=BlockSide(block_start, block_end),
                    candidate=BlockSide(block_start, block_end),
                    reachable=True,
                    invariant_checked=True,
                    source={"source": {"function": name, "kind": "candidate_capstone_basic_block"}},
                )
            )
    return mappings

def _candidate_reference_section_gap_abi_mappings(
    candidate: StageABinary,
    reference_abi: dict[str, Any] | None,
    *,
    alias_evidence: dict[str, Any] | None = None,
    candidate_rva_anchors: dict[int, int] | None = None,
) -> list[BlockMapping]:
    if not isinstance(reference_abi, dict):
        return []
    reference = reference_abi.get("original") if isinstance(reference_abi.get("original"), dict) else {}
    functions = reference.get("functions") if isinstance(reference.get("functions"), list) else []
    owner_ranges = _candidate_reference_section_gap_owner_ranges(functions)
    alias_matches = (
        alias_evidence.get("matches_by_reference")
        if isinstance(alias_evidence, dict) and isinstance(alias_evidence.get("matches_by_reference"), dict)
        else {}
    )
    mappings: list[BlockMapping] = []
    for function in functions:
        if not isinstance(function, dict):
            continue
        name = function.get("name")
        if not isinstance(name, str) or not name.startswith("section-gap-"):
            continue
        blocks = function.get("blocks") if isinstance(function.get("blocks"), list) else []
        for index, block in enumerate(blocks):
            if not isinstance(block, dict):
                continue
            start = _optional_contract_int(block.get("rva_start"))
            end = _optional_contract_int(block.get("rva_end"))
            if start is None or end is None or end <= start:
                continue
            block_id = block.get("block_id") if isinstance(block.get("block_id"), str) and block.get("block_id") else f"{name}-{index:04d}"
            anchor_mapping = _candidate_reference_section_gap_anchor_mapping(
                candidate,
                name=name,
                block_id=block_id,
                reference_start=start,
                reference_end=end,
                owner_ranges=owner_ranges,
                alias_matches=alias_matches,
                candidate_rva_anchors=candidate_rva_anchors or {},
            )
            if anchor_mapping is not None:
                mappings.append(anchor_mapping)
                continue
            owner_mapping = _candidate_reference_section_gap_owner_offset_mapping(
                candidate,
                name=name,
                block_id=block_id,
                reference_start=start,
                reference_end=end,
                owner_ranges=owner_ranges,
                alias_matches=alias_matches,
            )
            if owner_mapping is not None:
                mappings.append(owner_mapping)
                continue
            section = _section_for_rva(candidate, start)
            if section is None or not section.executable or end > section.rva_end:
                continue
            mappings.append(
                BlockMapping(
                    id=_artifact_name(block_id),
                    kind="code",
                    original=BlockSide(start, end),
                    candidate=BlockSide(start, end),
                    reachable=True,
                    invariant_checked=False,
                    source={
                        "source": {
                            "function": name,
                            "kind": "candidate_same_rva_section_gap_probe",
                            "reference_block_id": block_id,
                        }
                    },
                )
            )
    return mappings

def _candidate_reference_section_gap_owner_ranges(functions: list[Any]) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    for function in functions:
        if not isinstance(function, dict):
            continue
        name = function.get("name")
        if not isinstance(name, str) or not name or name.startswith("section-gap-"):
            continue
        blocks = function.get("blocks") if isinstance(function.get("blocks"), list) else []
        starts: list[int] = []
        ends: list[int] = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            start = _optional_contract_int(block.get("rva_start"))
            end = _optional_contract_int(block.get("rva_end"))
            if start is None or end is None or end <= start:
                continue
            starts.append(start)
            ends.append(end)
        if not starts:
            continue
        ranges.append({"name": name, "rva_start": min(starts), "rva_end": max(ends)})
    ranges.sort(key=lambda item: (int(item["rva_end"]) - int(item["rva_start"]), str(item["name"])))
    return ranges

def _candidate_reference_section_gap_anchor_mapping(
    candidate: StageABinary,
    *,
    name: str,
    block_id: str,
    reference_start: int,
    reference_end: int,
    owner_ranges: list[dict[str, Any]],
    alias_matches: dict[str, Any],
    candidate_rva_anchors: dict[int, int],
) -> BlockMapping | None:
    if not candidate_rva_anchors:
        return None
    owner_context = _candidate_reference_section_gap_owner_context(
        reference_start=reference_start,
        reference_end=reference_end,
        owner_ranges=owner_ranges,
        alias_matches=alias_matches,
    )
    if owner_context is None:
        return None
    previous_reference = max((rva for rva in candidate_rva_anchors if rva <= reference_start), default=None)
    if previous_reference is None:
        return None
    next_reference = min((rva for rva in candidate_rva_anchors if rva > previous_reference), default=None)
    if next_reference is not None and reference_end > next_reference:
        return None
    candidate_anchor = candidate_rva_anchors[previous_reference]
    candidate_start = candidate_anchor + (reference_start - previous_reference)
    candidate_end = candidate_start + (reference_end - reference_start)
    candidate_owner_start = int(owner_context["candidate_start"])
    candidate_owner_end = int(owner_context["candidate_end"])
    if candidate_start < candidate_owner_start or candidate_end > candidate_owner_end:
        return None
    if next_reference is not None:
        next_candidate = candidate_rva_anchors[next_reference]
        if candidate_end > next_candidate:
            return None
    section = _section_for_rva(candidate, candidate_start)
    if section is None or not section.executable or candidate_end > section.rva_end:
        return None
    return BlockMapping(
        id=_artifact_name(block_id),
        kind="code",
        original=BlockSide(reference_start, reference_end),
        candidate=BlockSide(candidate_start, candidate_end),
        reachable=True,
        invariant_checked=False,
        source={
            "source": {
                "function": name,
                "kind": "candidate_contract_rva_anchor_section_gap_probe",
                "reference_block_id": block_id,
                "owner_function": owner_context["owner_name"],
                "anchor_reference_rva": previous_reference,
                "anchor_candidate_rva": candidate_anchor,
                "anchor_delta": reference_start - previous_reference,
            }
        },
    )

def _candidate_reference_section_gap_owner_offset_mapping(
    candidate: StageABinary,
    *,
    name: str,
    block_id: str,
    reference_start: int,
    reference_end: int,
    owner_ranges: list[dict[str, Any]],
    alias_matches: dict[str, Any],
) -> BlockMapping | None:
    owner_context = _candidate_reference_section_gap_owner_context(
        reference_start=reference_start,
        reference_end=reference_end,
        owner_ranges=owner_ranges,
        alias_matches=alias_matches,
    )
    if owner_context is None:
        return None
    owner_name = str(owner_context["owner_name"])
    owner_start = int(owner_context["reference_start"])
    candidate_owner_start = int(owner_context["candidate_start"])
    candidate_owner_end = int(owner_context["candidate_end"])
    candidate_start = candidate_owner_start + (reference_start - owner_start)
    candidate_end = candidate_start + (reference_end - reference_start)
    if candidate_start < candidate_owner_start or candidate_end > candidate_owner_end:
        return None
    section = _section_for_rva(candidate, candidate_start)
    if section is None or not section.executable or candidate_end > section.rva_end:
        return None
    return BlockMapping(
        id=_artifact_name(block_id),
        kind="code",
        original=BlockSide(reference_start, reference_end),
        candidate=BlockSide(candidate_start, candidate_end),
        reachable=True,
        invariant_checked=False,
        source={
            "source": {
                "function": name,
                "kind": "candidate_owner_offset_section_gap_probe",
                "reference_block_id": block_id,
                "owner_function": owner_name,
                "owner_reference_rva_start": owner_start,
                "owner_candidate_rva_start": candidate_owner_start,
                "owner_offset": reference_start - owner_start,
            }
        },
    )

def _candidate_reference_section_gap_owner_context(
    *,
    reference_start: int,
    reference_end: int,
    owner_ranges: list[dict[str, Any]],
    alias_matches: dict[str, Any],
) -> dict[str, Any] | None:
    owner = next(
        (
            item
            for item in owner_ranges
            if int(item.get("rva_start") or 0) <= reference_start and reference_end <= int(item.get("rva_end") or 0)
        ),
        None,
    )
    if owner is None:
        return None
    owner_name = str(owner.get("name") or "")
    alias_match = alias_matches.get(owner_name) if isinstance(alias_matches.get(owner_name), dict) else {}
    if str(alias_match.get("source_kind") or "") not in {
        "generated_contract_guided_flow",
        "generated_checked_semantic_region",
    }:
        return None
    candidate_owner = alias_match.get("candidate") if isinstance(alias_match.get("candidate"), dict) else {}
    candidate_owner_start = _optional_contract_int(candidate_owner.get("rva_start"))
    candidate_owner_end = _optional_contract_int(candidate_owner.get("rva_end"))
    owner_start = _optional_contract_int(owner.get("rva_start"))
    owner_end = _optional_contract_int(owner.get("rva_end"))
    if candidate_owner_start is None or candidate_owner_end is None or owner_start is None or owner_end is None:
        return None
    return {
        "owner_name": owner_name,
        "reference_start": owner_start,
        "reference_end": owner_end,
        "candidate_start": candidate_owner_start,
        "candidate_end": candidate_owner_end,
    }

__all__ = [
    '_candidate_abi_block_mappings_from_functions',
    '_candidate_abi_constraint_from_functions',
    '_candidate_reference_section_gap_abi_mappings',
    '_candidate_reference_section_gap_anchor_mapping',
    '_candidate_reference_section_gap_owner_context',
    '_candidate_reference_section_gap_owner_offset_mapping',
    '_candidate_reference_section_gap_owner_ranges',
]
