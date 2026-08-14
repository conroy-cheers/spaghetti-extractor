"""Static map and executable-byte classification proposals."""

from __future__ import annotations

import copy
import json
import os
import platform
import re
import shutil
import sys
from bisect import bisect_left
from collections import Counter
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
    BlockMapping,
    CHECKED_GENERATED_MAPPING_PROOF_RULES,
    NORETURN_IMPORT_SYMBOLS,
    NonCodeWaiver,
    _failure_record,
    _incomplete_record,
    _is_conditional_jump,
    _parse_int,
    _range_report,
)

def _layout_issues(
    original: StageABinary,
    candidate: StageABinary,
    layout_contract: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if original.machine != candidate.machine or original.bitness != candidate.bitness:
        issues.append(
            _failure_record(
                category="layout_mismatch",
                obligation_id="layout:architecture",
                blocker="original and candidate architecture/bitness differ",
                original={"machine": original.machine, "bitness": original.bitness},
                candidate={"machine": candidate.machine, "bitness": candidate.bitness},
            )
        )
    section_signature_matches = _section_permission_signature(original) == _section_permission_signature(candidate)
    section_contract_allows_span_delta = (
        isinstance(layout_contract, dict)
        and layout_contract.get("allow_different_section_spans") is True
        and layout_contract.get("facts", {}).get("matching_normalized_executable_section_spans") is True
        and _section_compatibility_signature(original) == _section_compatibility_signature(candidate)
        and _section_rva_start_signature(original) == _section_rva_start_signature(candidate)
    )
    if not section_signature_matches and not section_contract_allows_span_delta:
        issues.append(
            _failure_record(
                category="layout_mismatch",
                obligation_id="layout:sections",
                blocker="PE section permissions or mapped executable ranges differ",
                original=_section_permission_signature(original),
                candidate=_section_permission_signature(candidate),
            )
        )
    if _import_signature(original) != _import_signature(candidate):
        issues.append(
            _failure_record(
                category="layout_mismatch",
                obligation_id="layout:imports",
                blocker="import boundary model differs",
                original=_import_signature(original),
                candidate=_import_signature(candidate),
            )
        )
    if layout_contract is not None:
        if layout_contract.get("require_same_image_base") is True and original.image_base != candidate.image_base:
            issues.append(
                _failure_record(
                    category="layout_mismatch",
                    obligation_id="layout:image_base",
                    blocker="strict layout contract requires equal image bases",
                    original={"image_base": original.image_base},
                    candidate={"image_base": candidate.image_base},
                )
            )
        for fact in layout_contract.get("required_facts", []):
            if fact not in layout_contract.get("facts", {}):
                issues.append(
                    _incomplete_record(
                        category="missing_layout_fact",
                        obligation_id=f"layout:fact:{fact}",
                        blocker=f"strict layout contract requires missing fact {fact!r}",
                        next_action="add the required layout fact or remove it from required_facts",
                    )
                )
            elif layout_contract.get("facts", {}).get(fact) is not True:
                issues.append(
                    _incomplete_record(
                        category="unsatisfied_layout_fact",
                        obligation_id=f"layout:fact:{fact}",
                        blocker=f"strict layout contract requires fact {fact!r} to be true",
                        next_action="regenerate the layout contract from a closed Stage A map or rebuild the fixtures with compatible PE layout",
                        details={"fact": fact, "value": layout_contract.get("facts", {}).get(fact)},
                    )
                )
    return issues

def _section_permission_signature(binary: StageABinary) -> list[dict[str, Any]]:
    return [
        {
            "name": section.name,
            "rva_start": section.rva_start,
            "rva_end": section.rva_end,
            "executable": section.executable,
            "readable": section.readable,
            "writable": section.writable,
            "contains_code": section.contains_code,
        }
        for section in binary.sections
    ]

def _section_compatibility_signature(binary: StageABinary) -> list[dict[str, Any]]:
    return [
        {
            "name": section.name,
            "executable": section.executable,
            "readable": section.readable,
            "writable": section.writable,
            "contains_code": section.contains_code,
        }
        for section in binary.sections
    ]

def _section_rva_start_signature(binary: StageABinary) -> list[dict[str, Any]]:
    return [
        {
            "name": section.name,
            "rva_start": section.rva_start,
            "executable": section.executable,
            "readable": section.readable,
            "writable": section.writable,
            "contains_code": section.contains_code,
        }
        for section in binary.sections
    ]

def _import_signature(binary: StageABinary) -> list[tuple[str, str | None, int | None]]:
    return sorted((item.dll, item.symbol, item.ordinal) for item in binary.imports)

def _generated_map_issues(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    issues = payload.get("issues", [])
    if payload.get("generator") == "stage-a-generate-map" and payload.get("status") != "pass":
        return [
            _incomplete_record(
                category="generated_map_incomplete",
                obligation_id="mapping:generated-map",
                blocker="stage-a-generate-map did not produce a closed block map",
                next_action="inspect mapping issues and extend the generic map generator or Stage A model",
                details={"issues": issues},
            )
        ]
    return []

def _generic_map_layout_issues(original: StageABinary, candidate: StageABinary) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if original.machine != candidate.machine or original.bitness != candidate.bitness:
        issues.append(
            _incomplete_record(
                category="layout_mismatch",
                obligation_id="map:layout:architecture",
                blocker="generated map creation requires both inputs to use the same supported PE architecture",
                next_action="rebuild the fixtures for a single supported Windows target",
            )
        )
    if _section_compatibility_signature(original) != _section_compatibility_signature(candidate):
        issues.append(
            _incomplete_record(
                category="layout_mismatch",
                obligation_id="map:layout:sections",
                blocker="map generation requires matching PE section names and permissions",
                next_action="make the fixture builds use the same linker script and section policy",
                details={
                    "original": _section_compatibility_signature(original),
                    "candidate": _section_compatibility_signature(candidate),
                },
            )
        )
    if _section_rva_start_signature(original) != _section_rva_start_signature(candidate):
        issues.append(
            _incomplete_record(
                category="layout_mismatch",
                obligation_id="map:layout:section-rvas",
                blocker="map generation requires matching PE section RVAs before span normalization",
                next_action="make the fixture builds use the same linker script and section placement policy",
                details={
                    "original": _section_rva_start_signature(original),
                    "candidate": _section_rva_start_signature(candidate),
                },
            )
        )
    if _import_signature(original) != _import_signature(candidate):
        issues.append(
            _incomplete_record(
                category="layout_mismatch",
                obligation_id="map:layout:imports",
                blocker="map generation requires matching PE imports",
                next_action="make the fixture builds use the same linkage and dependency policy",
                details={"original": _import_signature(original), "candidate": _import_signature(candidate)},
            )
        )
    return issues

def _capstone_mode(binary: StageABinary) -> int:
    return capstone.CS_MODE_64 if binary.bitness == 64 else capstone.CS_MODE_32

def _linker_function_issues(binary_name: str, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if not functions:
        issues.append(
            _incomplete_record(
                category="missing_linker_map_entries",
                obligation_id=f"map:{binary_name}:functions",
                blocker=f"{binary_name} linker map did not expose executable symbols",
                next_action="rebuild with linker map emission and unstripped symbols",
            )
        )
    by_name: dict[str, list[dict[str, Any]]] = {}
    for function in functions:
        by_name.setdefault(str(function["name"]), []).append(function)
    duplicates = {
        name: [
            {"rva_start": item["rva_start"], "rva_end": item["rva_end"], "aliases": item.get("aliases", [])}
            for item in entries
        ]
        for name, entries in by_name.items()
        if len(entries) > 1
    }
    if duplicates:
        issues.append(
            _incomplete_record(
                category="ambiguous_linker_map",
                obligation_id=f"map:{binary_name}:duplicate-function-names",
                blocker=f"{binary_name} linker map contains duplicate primary function names",
                next_action="disambiguate duplicate linker-map symbols before accepting generated mappings",
                details={"functions": duplicates},
            )
        )
    seen_ranges: list[tuple[str, BlockSide]] = [
        (str(item["name"]), BlockSide(int(item["rva_start"]), int(item["rva_end"]))) for item in functions
    ]
    for overlap in _range_overlap_issues(binary_name, seen_ranges):
        issues.append(
            _incomplete_record(
                category="ambiguous_linker_map",
                obligation_id=overlap["obligation_id"],
                blocker=overlap["blocker"],
                next_action="fix linker-map function range recovery before generating a Stage A map",
                details=overlap,
            )
        )
    return issues

def _unique_functions_by_name(functions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in functions:
        grouped.setdefault(str(item["name"]), []).append(item)
    return {name: entries[0] for name, entries in grouped.items() if len(entries) == 1}

def _match_linker_functions_by_name_or_unique_alias(
    original_functions: list[dict[str, Any]],
    candidate_functions: list[dict[str, Any]],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any], str]], list[str], list[str], list[dict[str, Any]]]:
    original_by_name = _unique_functions_by_name(original_functions)
    candidate_by_name = _unique_functions_by_name(candidate_functions)
    matched: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    unmatched_original = set(original_by_name)
    unmatched_candidate = set(candidate_by_name)
    for name in sorted(set(original_by_name) & set(candidate_by_name)):
        matched.append((original_by_name[name], candidate_by_name[name], _linker_function_match_key(name)))
        unmatched_original.discard(name)
        unmatched_candidate.discard(name)

    original_by_key: dict[str, list[str]] = {}
    candidate_by_key: dict[str, list[str]] = {}
    for name in unmatched_original:
        original_by_key.setdefault(_linker_function_match_key(name), []).append(name)
    for name in unmatched_candidate:
        candidate_by_key.setdefault(_linker_function_match_key(name), []).append(name)

    issues: list[dict[str, Any]] = []
    for key in sorted(set(original_by_key) & set(candidate_by_key)):
        original_names = sorted(original_by_key[key])
        candidate_names = sorted(candidate_by_key[key])
        if len(original_names) == 1 and len(candidate_names) == 1:
            original_name = original_names[0]
            candidate_name = candidate_names[0]
            matched.append((original_by_name[original_name], candidate_by_name[candidate_name], key))
            unmatched_original.discard(original_name)
            unmatched_candidate.discard(candidate_name)
            continue
        issues.append(
            _incomplete_record(
                category="ambiguous_linker_map",
                obligation_id=f"map:alias:{_artifact_name(key)}",
                blocker="decorated linker-map names produce an ambiguous canonical alias match",
                next_action="preserve exact function names or add a more specific linker-map alias rule",
                details={"match_key": key, "original": original_names, "candidate": candidate_names},
            )
        )
    return matched, sorted(unmatched_original), sorted(unmatched_candidate), issues

def _match_import_thunk_functions_by_signature(
    original: StageABinary,
    candidate: StageABinary,
    original_functions: list[dict[str, Any]],
    candidate_functions: list[dict[str, Any]],
    unmatched_original: list[str],
    unmatched_candidate: list[str],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[str], list[str], list[dict[str, Any]]]:
    original_by_name = _unique_functions_by_name(original_functions)
    candidate_by_name = _unique_functions_by_name(candidate_functions)
    original_unmatched = set(unmatched_original)
    candidate_unmatched = set(unmatched_candidate)
    original_thunks = [
        thunk
        for name in sorted(original_unmatched)
        for thunk in [_linker_function_import_thunk_evidence(original, original_by_name[name])]
        if name in original_by_name and thunk is not None
    ]
    candidate_thunks = [
        thunk
        for name in sorted(candidate_unmatched)
        for thunk in [_linker_function_import_thunk_evidence(candidate, candidate_by_name[name])]
        if name in candidate_by_name and thunk is not None
    ]
    original_by_signature = _group_import_thunks_by_signature(original_thunks)
    candidate_by_signature = _group_import_thunks_by_signature(candidate_thunks)

    matched: list[tuple[dict[str, Any], dict[str, Any]]] = []
    issues: list[dict[str, Any]] = []
    for signature in sorted(set(original_by_signature) & set(candidate_by_signature)):
        left = original_by_signature[signature]
        right = candidate_by_signature[signature]
        if len(left) == 1 and len(right) == 1:
            matched.append((left[0], right[0]))
            original_unmatched.discard(str(left[0]["function"]["name"]))
            candidate_unmatched.discard(str(right[0]["function"]["name"]))
            continue
        issues.append(
            _incomplete_record(
                category="ambiguous_import_thunk_match",
                obligation_id=f"map:import-thunk:{_artifact_name(signature)}",
                blocker="PE import-thunk linker-map functions do not have a unique import-signature match",
                next_action="preserve unique import thunk symbols or add disambiguating checked thunk metadata",
                details={
                    "import_signature": _import_signature_report(left[0]["import"] if left else right[0]["import"]),
                    "original": [_import_thunk_match_report(item) for item in left],
                    "candidate": [_import_thunk_match_report(item) for item in right],
                },
            )
        )
    return matched, sorted(original_unmatched), sorted(candidate_unmatched), issues

def _group_import_thunks_by_signature(thunks: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for thunk in thunks:
        grouped.setdefault(str(thunk["signature_key"]), []).append(thunk)
    return grouped

def _linker_function_import_thunk_evidence(binary: StageABinary, function: dict[str, Any]) -> dict[str, Any] | None:
    start = int(function["rva_start"])
    end = int(function["rva_end"])
    if end <= start:
        return None
    data = binary.pe.get_data(start, min(16, end - start))
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + start))
    if not instructions:
        return None
    first = instructions[0]
    if int(first.address - binary.image_base) != start:
        return None
    imported = _direct_import_jump_instruction(binary, first)
    if imported is None:
        return None
    thunk_end = start + int(first.size)
    if thunk_end > end:
        return None
    padding = binary.pe.get_data(thunk_end, end - thunk_end)
    if len(padding) != end - thunk_end or not _is_padding_bytes(binary, thunk_end, padding):
        return None
    return {
        "function": function,
        "block": BlockSide(start, thunk_end),
        "function_range": BlockSide(start, end),
        "import": imported,
        "signature_key": _import_thunk_match_key(imported),
        "instruction": _instruction_report(binary, first),
        "padding_sha256": sha256_bytes(padding),
    }

def _import_thunk_block_entry(
    original: dict[str, Any],
    candidate: dict[str, Any],
    *,
    match_key: str,
) -> dict[str, Any]:
    original_function = original["function"]
    candidate_function = candidate["function"]
    original_block: BlockSide = original["block"]
    candidate_block: BlockSide = candidate["block"]
    name = str(original_function["name"])
    return {
        "id": _artifact_name(f"{name}-import-thunk"),
        "kind": "code",
        "reachable": True,
        "original": {"rva": original_block.rva_start, "size": original_block.size},
        "candidate": {"rva": candidate_block.rva_start, "size": candidate_block.size},
        "root": {"kind": "linker_map_function", "checked": True, "symbol": name},
        "source": {
            "kind": "import_thunk",
            "function": name,
            "candidate_function": str(candidate_function["name"]),
            "function_block_index": 0,
            "function_match_key": match_key,
            "import_signature": _import_signature_report(original["import"]),
            "original_instruction": original["instruction"],
            "candidate_instruction": candidate["instruction"],
            "original_function_range": _range_report(original["function_range"]),
            "candidate_function_range": _range_report(candidate["function_range"]),
            "padding_classification": "verified_linker_function_suffix_padding",
        },
    }

def _import_thunk_match_report(thunk: dict[str, Any] | None) -> dict[str, Any] | None:
    if thunk is None:
        return None
    return {
        "function": str(thunk["function"]["name"]),
        "aliases": list(thunk["function"].get("aliases", [])),
        "block": _range_report(thunk["block"]),
        "function_range": _range_report(thunk["function_range"]),
        "import_signature": _import_signature_report(thunk["import"]),
        "instruction": thunk["instruction"],
    }

def _import_thunk_match_key(imported: StageAImport) -> str:
    symbol = imported.symbol if imported.symbol is not None else f"ordinal-{imported.ordinal}"
    return f"{imported.dll}!{symbol}"

def _import_signature_report(imported: StageAImport) -> dict[str, Any]:
    return {"dll": imported.dll, "symbol": imported.symbol, "ordinal": imported.ordinal}

def _linker_function_match_key(name: str) -> str:
    value = name
    if "@" in value:
        left, right = value.rsplit("@", 1)
        if right.isdigit():
            value = left
    return value.lstrip("_")

def _match_function_blocks(
    name: str,
    original: StageABinary,
    candidate: StageABinary,
    original_blocks: list[dict[str, Any]],
    candidate_blocks: list[dict[str, Any]],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[dict[str, Any]]]:
    if len(original_blocks) != len(candidate_blocks):
        original_cluster = _contiguous_function_path_cluster(
            original, original_blocks
        )
        candidate_cluster = _contiguous_function_path_cluster(
            candidate, candidate_blocks
        )
        if original_cluster is not None and candidate_cluster is not None:
            original_cluster["match_key"] = {
                "kind": "paired_function_path_cluster_v1",
                "original_basic_block_count": len(original_blocks),
                "candidate_basic_block_count": len(candidate_blocks),
                "side": "original",
            }
            candidate_cluster["match_key"] = {
                "kind": "paired_function_path_cluster_v1",
                "original_basic_block_count": len(original_blocks),
                "candidate_basic_block_count": len(candidate_blocks),
                "side": "candidate",
            }
            return [(original_cluster, candidate_cluster)], []
        return [], [
            _incomplete_record(
                category="ambiguous_block_match",
                obligation_id=f"map:function:{_artifact_name(name)}",
                blocker="function map recovered different basic-block counts for matching linker-map symbols",
                next_action="extend the generic map generator to match split basic blocks for this function by CFG shape",
                details=_ambiguous_block_match_details(
                    name=name,
                    original=original,
                    candidate=candidate,
                    original_blocks=original_blocks,
                    candidate_blocks=candidate_blocks,
                ),
            )
        ]
    return list(zip(original_blocks, candidate_blocks)), []

def _contiguous_function_path_cluster(
    binary: StageABinary,
    blocks: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Collapse a recovered N-block path to one untrusted segment proposal.

    The relation contract and Lean proof remain responsible for showing that
    the paired paths are semantically related.  This helper establishes only
    that each proposed side is a non-empty, exactly decodable, contiguous byte
    range, so a compiler-introduced direct bridge may change block count
    without being rejected by the mapping heuristic first.
    """

    if not blocks:
        return None
    ordered = sorted(blocks, key=lambda item: int(item["rva_start"]))
    if any(
        int(left["rva_end"]) != int(right["rva_start"])
        for left, right in zip(ordered, ordered[1:])
    ):
        return None
    start = int(ordered[0]["rva_start"])
    end = int(ordered[-1]["rva_end"])
    data = binary.pe.get_data(start, end - start)
    if len(data) != end - start:
        return None
    decoded = _disassemble_block(binary, start, data)
    if sum(int(instruction.size) for instruction in decoded) != len(data):
        return None
    return {
        "rva_start": start,
        "rva_end": end,
        "bytes_sha256": sha256_bytes(data),
        "match_key": {},
    }

def _ambiguous_block_match_details(
    *,
    name: str,
    original: StageABinary,
    candidate: StageABinary,
    original_blocks: list[dict[str, Any]],
    candidate_blocks: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "function": name,
        "original_blocks": len(original_blocks),
        "candidate_blocks": len(candidate_blocks),
        "block_count_delta": len(candidate_blocks) - len(original_blocks),
        "original_block_shapes": _block_shape_summaries(original, original_blocks),
        "candidate_block_shapes": _block_shape_summaries(candidate, candidate_blocks),
    }

def _block_shape_summaries(binary: StageABinary, blocks: list[dict[str, Any]], *, limit: int = 64) -> dict[str, Any]:
    summaries = [
        _block_shape_summary(binary, index, block)
        for index, block in enumerate(blocks[:limit])
    ]
    return {
        "count": len(blocks),
        "items": summaries,
        "truncated": max(0, len(blocks) - limit),
    }

def _block_shape_summary(binary: StageABinary, index: int, block: dict[str, Any]) -> dict[str, Any]:
    rva_start = int(block["rva_start"])
    rva_end = int(block["rva_end"])
    data = binary.pe.get_data(rva_start, rva_end - rva_start)
    instructions = _disassemble_block(binary, rva_start, data)
    terminal = instructions[-1] if instructions else None
    first = instructions[0] if instructions else None
    edges = _direct_cfg_edges(binary, BlockSide(rva_start, rva_end))
    return {
        "index": index,
        "rva_start": rva_start,
        "rva_end": rva_end,
        "size": rva_end - rva_start,
        "instruction_count": len(instructions),
        "first_instruction": _instruction_shape(binary, first),
        "terminal_instruction": _instruction_shape(binary, terminal),
        "direct_edge_counts": _edge_kind_counts(edges),
        "direct_edges": edges[:8],
        "direct_edges_truncated": max(0, len(edges) - 8),
        "bytes_sha256": block.get("bytes_sha256"),
        "match_key": block.get("match_key"),
    }

def _disassemble_block(binary: StageABinary, rva_start: int, data: bytes) -> list[Any]:
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    return list(dis.disasm(data, binary.image_base + rva_start))

def _instruction_shape(binary: StageABinary, insn: Any | None) -> dict[str, Any] | None:
    if insn is None:
        return None
    return {
        "rva": int(insn.address - binary.image_base),
        "mnemonic": str(insn.mnemonic),
        "op_str": str(insn.op_str),
        "size": int(insn.size),
    }

def _edge_kind_counts(edges: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for edge in edges:
        kind = str(edge.get("kind") or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
    return counts

def _recover_basic_blocks(binary: StageABinary, rva_start: int, rva_end: int) -> list[dict[str, Any]]:
    data = binary.pe.get_data(rva_start, rva_end - rva_start)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + rva_start))
    decoded = sum(int(insn.size) for insn in instructions)
    if not instructions or decoded != len(data):
        return [_function_range_block(binary, rva_start, rva_end, data, len(instructions), decoded)]

    insn_by_rva = {int(insn.address - binary.image_base): insn for insn in instructions}
    starts: set[int] = {rva_start}
    declared_roots = {binary.entrypoint_rva}
    if binary.tls_callback_rvas is not None:
        declared_roots.update(binary.tls_callback_rvas)
    if binary.exports is not None:
        declared_roots.update(
            exported.rva
            for exported in binary.exports
            if exported.kind == "code"
        )
    starts.update(
        root for root in declared_roots if rva_start <= root < rva_end
    )
    for insn in instructions:
        rva = int(insn.address - binary.image_base)
        next_rva = rva + int(insn.size)
        mnemonic = insn.mnemonic
        if _is_conditional_jump(mnemonic):
            target = _resolved_branch_target(binary, insn)
            if target is not None and rva_start <= target < rva_end:
                starts.add(target)
            if next_rva < rva_end:
                starts.add(next_rva)
        elif mnemonic in {"jmp", "ljmp"}:
            target = _resolved_branch_target(binary, insn)
            if target is not None and rva_start <= target < rva_end:
                starts.add(target)
        elif mnemonic == "call":
            target = _resolved_branch_target(binary, insn)
            if target is not None and rva_start <= target < rva_end:
                starts.add(target)
            if next_rva < rva_end:
                starts.add(next_rva)

    ordered_starts = [start for start in sorted(starts) if start in insn_by_rva]
    if not ordered_starts:
        return [_function_range_block(binary, rva_start, rva_end, data, len(instructions), decoded)]

    blocks: list[dict[str, Any]] = []
    instruction_rvas = sorted(insn_by_rva)
    for index, start in enumerate(ordered_starts):
        next_start = ordered_starts[index + 1] if index + 1 < len(ordered_starts) else rva_end
        block_end = next_start
        instruction_start = bisect_left(instruction_rvas, start)
        instruction_stop = bisect_left(
            instruction_rvas, next_start, lo=instruction_start
        )
        for insn_rva in instruction_rvas[instruction_start:instruction_stop]:
            insn = insn_by_rva[insn_rva]
            insn_end = insn_rva + int(insn.size)
            if _instruction_ends_basic_block(insn) or _is_noreturn_import_call(binary, insn):
                block_end = insn_end
                instruction_stop = bisect_left(
                    instruction_rvas, block_end, lo=instruction_start
                )
                break
        if block_end <= start:
            continue
        block_data = binary.pe.get_data(start, block_end - start)
        if _is_padding_bytes(binary, start, block_data):
            continue
        blocks.append(
            {
                "rva_start": start,
                "rva_end": block_end,
                "bytes_sha256": sha256_bytes(block_data),
                "match_key": {
                    "kind": "recovered_basic_block",
                    "function_rva_start": rva_start,
                    "function_rva_end": rva_end,
                    "block_index": len(blocks),
                    "instruction_count": instruction_stop - instruction_start,
                    "range_size": len(block_data),
                },
            }
        )
    return blocks or [_function_range_block(binary, rva_start, rva_end, data, len(instructions), decoded)]

def _function_range_block(
    binary: StageABinary,
    rva_start: int,
    rva_end: int,
    data: bytes,
    instruction_count: int,
    decoded: int,
) -> dict[str, Any]:
    del binary
    return {
        "rva_start": rva_start,
        "rva_end": rva_end,
        "bytes_sha256": sha256_bytes(data),
        "match_key": {
            "kind": "linker_map_function_range",
            "instruction_count": instruction_count,
            "decoded_bytes": decoded,
            "range_size": len(data),
        },
    }

def _paired_section_gap_classification(
    original: StageABinary,
    candidate: StageABinary,
    blocks: list[dict[str, Any]],
    *,
    original_flags: str,
    candidate_flags: str,
    proof_rule: str,
    proof_metadata: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    original_ranges = [
        BlockSide(_parse_int(block["original"]["rva"]), _parse_int(block["original"]["rva"]) + _parse_int(block["original"]["size"]))
        for block in blocks
    ]
    candidate_ranges = [
        BlockSide(_parse_int(block["candidate"]["rva"]), _parse_int(block["candidate"]["rva"]) + _parse_int(block["candidate"]["size"]))
        for block in blocks
    ]
    original_gaps = _section_gaps(original, original_ranges)
    candidate_gaps = _section_gaps(candidate, candidate_ranges)
    gap_blocks: list[dict[str, Any]] = []
    waivers: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for section in sorted(set(original_gaps) | set(candidate_gaps)):
        left_gaps = original_gaps.get(section, [])
        right_gaps = candidate_gaps.get(section, [])
        left_code_blocks, left_waivers = _section_gap_code_blocks("original", original, left_gaps)
        right_code_blocks, right_waivers = _section_gap_code_blocks("candidate", candidate, right_gaps)
        waivers.extend(left_waivers)
        waivers.extend(right_waivers)
        if len(left_code_blocks) != len(right_code_blocks):
            issues.append(
                _incomplete_record(
                    category="ambiguous_section_gap_match",
                    obligation_id=f"map:section-gap:{_artifact_name(section)}",
                    blocker="original and candidate executable section gap basic blocks do not have the same count after padding normalization",
                    next_action="extend the generic map generator to match split section-gap blocks by CFG shape",
                    details={
                        "section": section,
                        "original_code_blocks": len(left_code_blocks),
                        "candidate_code_blocks": len(right_code_blocks),
                        "original_gaps": len(left_gaps),
                        "candidate_gaps": len(right_gaps),
                        "original_unmatched_sample": _gap_block_sample(left_code_blocks, limit=8),
                        "candidate_unmatched_sample": _gap_block_sample(right_code_blocks, limit=8),
                    },
                )
            )
            continue
        for index, (left_unit, right_unit) in enumerate(zip(left_code_blocks, right_code_blocks)):
            left = left_unit["block"]
            right = right_unit["block"]
            left_bytes = left_unit["bytes"]
            right_bytes = right_unit["bytes"]
            name = f"section-gap-{section}-{index:04d}"
            gap_blocks.append(
                {
                    "id": _artifact_name(name),
                    "kind": "code",
                    "reachable": True,
                    "root": {"kind": "linker_map_section_gap", "checked": True, "section": section, "index": index},
                    "original": {"rva": left.rva_start, "size": left.size},
                    "candidate": {"rva": right.rva_start, "size": right.size},
                    "source": {
                        "kind": "paired_executable_section_gap_v1",
                        "section": section,
                        "gap_index": index,
                        "original_gap_index": left_unit["gap_index"],
                        "candidate_gap_index": right_unit["gap_index"],
                        "original_gap_block_index": left_unit["gap_block_index"],
                        "candidate_gap_block_index": right_unit["gap_block_index"],
                        "original_match": left_unit["match_key"],
                        "candidate_match": right_unit["match_key"],
                        "original_sha256": sha256_bytes(left_bytes),
                        "candidate_sha256": sha256_bytes(right_bytes),
                    },
                    "proof": _generated_mapping_proof(
                        proof_rule=proof_rule,
                        function=name,
                        original_flags=original_flags,
                        candidate_flags=candidate_flags,
                        proof_metadata=proof_metadata,
                    ),
                }
            )
    return gap_blocks, waivers, issues

def _section_gap_code_blocks(
    binary_name: str,
    binary: StageABinary,
    gaps: list[BlockSide],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    code_blocks: list[dict[str, Any]] = []
    waivers: list[dict[str, Any]] = []
    for gap_index, gap in enumerate(gaps):
        queue = [gap]
        seen: set[tuple[int, int]] = set()
        gap_block_index = 0
        while queue:
            span = queue.pop(0)
            span_key = (span.rva_start, span.rva_end)
            if span_key in seen or span.size <= 0:
                continue
            seen.add(span_key)
            data = binary.pe.get_data(span.rva_start, span.size)
            if len(data) != span.size:
                code_blocks.append(
                    {
                        "gap_index": gap_index,
                        "gap_block_index": gap_block_index,
                        "block": span,
                        "bytes": data,
                        "match_key": {"kind": "unreadable_section_gap_fragment", "range_size": span.size, "read_bytes": len(data)},
                    }
                )
                gap_block_index += 1
                continue
            if _is_padding_bytes(binary, span.rva_start, data):
                waivers.append(_padding_waiver(binary_name, span))
                continue

            recovery_span = _decodable_prefix_before_padding_suffix(
                binary, span, data
            )
            recovered = [
                item
                for item in _recover_basic_blocks(
                    binary, recovery_span.rva_start, recovery_span.rva_end
                )
                if span.rva_start <= int(item["rva_start"]) < int(item["rva_end"]) <= span.rva_end
            ]
            recovered_ranges: list[BlockSide] = []
            for item in recovered:
                block = BlockSide(int(item["rva_start"]), int(item["rva_end"]))
                block_bytes = binary.pe.get_data(block.rva_start, block.size)
                recovered_ranges.append(block)
                if len(block_bytes) != block.size:
                    code_blocks.append(
                        {
                            "gap_index": gap_index,
                            "gap_block_index": gap_block_index,
                            "block": block,
                            "bytes": block_bytes,
                            "match_key": {
                                "kind": "unreadable_section_gap_fragment",
                                "range_size": block.size,
                                "read_bytes": len(block_bytes),
                            },
                        }
                    )
                    gap_block_index += 1
                    continue
                if _is_padding_bytes(binary, block.rva_start, block_bytes):
                    waivers.append(_padding_waiver(binary_name, block))
                    continue

                edge_padding, code_span, code_bytes = _trim_padding_edges(binary, block, block_bytes)
                for padding in edge_padding:
                    waivers.append(_padding_waiver(binary_name, padding))
                if code_span is None:
                    continue
                if _is_padding_bytes(binary, code_span.rva_start, code_bytes):
                    waivers.append(_padding_waiver(binary_name, code_span))
                    continue
                code_blocks.append(
                    {
                        "gap_index": gap_index,
                        "gap_block_index": gap_block_index,
                        "block": code_span,
                        "bytes": code_bytes,
                        "match_key": {
                            **item["match_key"],
                            "trimmed_padding_prefix": code_span.rva_start - block.rva_start,
                            "trimmed_padding_suffix": block.rva_end - code_span.rva_end,
                        },
                    }
                )
                gap_block_index += 1

            if not recovered_ranges:
                code_blocks.append(
                    {
                        "gap_index": gap_index,
                        "gap_block_index": gap_block_index,
                        "block": span,
                        "bytes": data,
                        "match_key": {"kind": "unrecovered_section_gap_fragment", "range_size": span.size},
                    }
                )
                gap_block_index += 1
                continue

            for residue in _gaps(span.rva_start, span.rva_end, recovered_ranges):
                if residue.size > 0:
                    queue.append(residue)
    code_blocks.sort(key=lambda item: (item["block"].rva_start, item["block"].rva_end))
    return code_blocks, waivers

def _decodable_prefix_before_padding_suffix(
    binary: StageABinary,
    span: BlockSide,
    data: bytes,
) -> BlockSide:
    """Keep an exact decode prefix when only verified tail padding is invalid."""

    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    instructions = list(dis.disasm(data, binary.image_base + span.rva_start))
    decoded = sum(int(instruction.size) for instruction in instructions)
    if decoded == len(data) or decoded <= 0:
        return span
    suffix = data[decoded:]
    suffix_start = span.rva_start + decoded
    if not _is_padding_bytes(binary, suffix_start, suffix):
        return span
    return BlockSide(span.rva_start, suffix_start)

def _trim_padding_edges(binary: StageABinary, block: BlockSide, data: bytes) -> tuple[list[BlockSide], BlockSide | None, bytes]:
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + block.rva_start))
    if sum(int(insn.size) for insn in instructions) != len(data):
        return [], block, data

    first_code_index = 0
    while first_code_index < len(instructions) and _is_padding_instruction(instructions[first_code_index]):
        first_code_index += 1
    if first_code_index == len(instructions):
        return [block], None, b""

    last_code_index = len(instructions) - 1
    while last_code_index > first_code_index and _is_padding_instruction(instructions[last_code_index]):
        last_code_index -= 1

    code_start = int(instructions[first_code_index].address - binary.image_base)
    last_code = instructions[last_code_index]
    code_end = int(last_code.address - binary.image_base) + int(last_code.size)
    padding: list[BlockSide] = []
    if block.rva_start < code_start:
        padding.append(BlockSide(block.rva_start, code_start))
    if code_end < block.rva_end:
        padding.append(BlockSide(code_end, block.rva_end))
    code_span = BlockSide(code_start, code_end)
    return padding, code_span, binary.pe.get_data(code_span.rva_start, code_span.size)

def _padding_waiver(binary_name: str, span: BlockSide) -> dict[str, Any]:
    return {
        "id": f"{binary_name}-padding-{span.rva_start:x}-{span.rva_end:x}",
        "binary": binary_name,
        "rva": span.rva_start,
        "size": span.size,
        "reason": "verified executable section gap is zero-fill or padding instructions",
    }

def _gap_block_sample(items: list[dict[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    return [
        {
            "rva_start": item["block"].rva_start,
            "rva_end": item["block"].rva_end,
            "gap_index": item["gap_index"],
            "gap_block_index": item["gap_block_index"],
            "match_key": item["match_key"],
            "bytes_sha256": sha256_bytes(item["bytes"]) if isinstance(item.get("bytes"), bytes) else None,
        }
        for item in items[:limit]
    ]

def _section_gaps(binary: StageABinary, ranges: list[BlockSide]) -> dict[str, list[BlockSide]]:
    result: dict[str, list[BlockSide]] = {}
    executable_name_counts = Counter(
        section.name for section in binary.sections if section.executable
    )
    for section in binary.sections:
        if not section.executable:
            continue
        identity = (
            section.name
            if executable_name_counts[section.name] == 1
            else f"{section.name}@{section.rva_start:08x}"
        )
        result[identity] = _gaps(section.rva_start, section.rva_end, ranges)
    return result

def _is_padding_bytes(binary: StageABinary, rva_start: int, data: bytes) -> bool:
    if not data:
        return True
    if all(byte == 0 for byte in data):
        return True
    if all(byte in {0x00, 0x90, 0xCC} for byte in data):
        return True
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + rva_start))
    if sum(int(insn.size) for insn in instructions) != len(data):
        return False
    return all(_is_padding_instruction(insn) for insn in instructions)

def _is_padding_instruction(insn: Any) -> bool:
    if insn.mnemonic in {"nop", "int3"}:
        return True
    if insn.mnemonic != "lea" or len(insn.operands) != 2:
        return False
    destination, source = insn.operands
    if destination.type != X86_OP_REG or source.type != X86_OP_MEM:
        return False
    mem = source.mem
    return destination.reg == mem.base and not mem.index and mem.disp == 0

def _range_overlap_issues(binary_name: str, ranges: list[tuple[str, BlockSide]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    ordered = sorted(ranges, key=lambda item: (item[1].rva_start, item[1].rva_end, item[0]))
    for left, right in zip(ordered, ordered[1:]):
        left_id, left_range = left
        right_id, right_range = right
        if left_range.rva_end > right_range.rva_start:
            issues.append(
                _failure_record(
                    category="invalid_mapping",
                    obligation_id=f"mapping:{binary_name}:overlap:{left_id}:{right_id}",
                    blocker=f"{binary_name} block mappings overlap",
                    original={"id": left_id, "rva_start": left_range.rva_start, "rva_end": left_range.rva_end},
                    candidate={"id": right_id, "rva_start": right_range.rva_start, "rva_end": right_range.rva_end},
                )
            )
    return issues

def _gaps(start: int, end: int, ranges: list[BlockSide]) -> list[BlockSide]:
    cursor = start
    gaps: list[BlockSide] = []
    for item in sorted(ranges, key=lambda entry: (entry.rva_start, entry.rva_end)):
        if item.rva_end <= start or item.rva_start >= end:
            continue
        clipped_start = max(start, item.rva_start)
        clipped_end = min(end, item.rva_end)
        if clipped_start > cursor:
            gaps.append(BlockSide(cursor, clipped_start))
        cursor = max(cursor, clipped_end)
    if cursor < end:
        gaps.append(BlockSide(cursor, end))
    return gaps

def _instruction_report(binary: StageABinary, insn: Any) -> dict[str, Any]:
    return {
        "rva": int(insn.address - binary.image_base),
        "size": int(insn.size),
        "mnemonic": insn.mnemonic,
        "op_str": insn.op_str,
        "bytes": bytes(insn.bytes).hex(),
    }

def _instruction_ends_basic_block(insn: Any) -> bool:
    mnemonic = insn.mnemonic
    return mnemonic in {"call", "ret", "jmp", "ljmp"} or _is_conditional_jump(mnemonic)

def _direct_cfg_edges(binary: StageABinary, side: BlockSide) -> list[dict[str, Any]]:
    data = binary.pe.get_data(side.rva_start, side.size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + side.rva_start))
    if not instructions or sum(insn.size for insn in instructions) != len(data):
        return []
    last = instructions[-1]
    last_rva = int(last.address - binary.image_base)
    fallthrough_rva = last_rva + int(last.size)
    mnemonic = last.mnemonic
    if _is_conditional_jump(mnemonic):
        target = _resolved_branch_target(binary, last)
        if target is None:
            return []
        return [
            {"kind": "taken", "target_rva": target, "instruction_rva": last_rva, "mnemonic": mnemonic},
            {"kind": "fallthrough", "target_rva": fallthrough_rva, "instruction_rva": last_rva, "mnemonic": mnemonic},
        ]
    if mnemonic in {"jmp", "ljmp"}:
        target = _resolved_branch_target(binary, last)
        return [] if target is None else [{"kind": "jump", "target_rva": target, "instruction_rva": last_rva, "mnemonic": mnemonic}]
    if mnemonic == "call":
        if _external_import_call(binary, last) is not None:
            return [] if _is_noreturn_import_call(binary, last) else [
                {"kind": "fallthrough", "target_rva": fallthrough_rva, "instruction_rva": last_rva, "mnemonic": mnemonic}
            ]
        target = _resolved_branch_target(binary, last)
        edges = [{"kind": "fallthrough", "target_rva": fallthrough_rva, "instruction_rva": last_rva, "mnemonic": mnemonic}]
        if target is not None:
            edges.insert(0, {"kind": "call", "target_rva": target, "instruction_rva": last_rva, "mnemonic": mnemonic})
        return edges
    if mnemonic == "ret":
        return []
    return [{"kind": "fallthrough", "target_rva": side.rva_end, "instruction_rva": last_rva, "mnemonic": mnemonic}]

def _direct_branch_target(insn: Any, image_base: int) -> int | None:
    if len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_IMM:
        return None
    return int(operand.imm - image_base)

def _resolved_branch_target(binary: StageABinary, insn: Any) -> int | None:
    target = _direct_branch_target(insn, binary.image_base)
    if target is not None:
        return target
    if len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_MEM:
        return None
    pointer_rva = _absolute_mem_operand_rva(binary, operand)
    if pointer_rva is None:
        return None
    pointer_section = _section_for_rva(binary, pointer_rva)
    if (
        pointer_section is None
        or not pointer_section.readable
        or pointer_section.writable
    ):
        # A mapped image word is a runtime control value, not a direct edge,
        # when execution can replace it.  Import/IAT transfers are classified
        # separately before this resolver is used.
        return None
    width = 8 if binary.bitness == 64 else 4
    data = binary.pe.get_data(pointer_rva, width)
    if len(data) != width:
        return None
    value = int.from_bytes(data, "little")
    if binary.image_base <= value < binary.image_base + binary.size_of_image:
        target_rva = value - binary.image_base
    elif 0 <= value < binary.size_of_image:
        target_rva = value
    else:
        return None
    if _executable_section_for_rva(binary, target_rva) is None:
        return None
    return target_rva

def _external_import_call(binary: StageABinary, insn: Any) -> StageAImport | None:
    if insn.mnemonic != "call" or len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type == X86_OP_MEM:
        return _import_for_absolute_memory_operand(binary, operand)
    if operand.type == X86_OP_IMM:
        target_rva = int(operand.imm - binary.image_base)
        return _direct_import_thunk(binary, target_rva)
    return None

def _direct_import_jump_instruction(binary: StageABinary, insn: Any) -> StageAImport | None:
    if insn.mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_MEM:
        return None
    return _import_for_absolute_memory_operand(binary, operand)

def _import_for_absolute_memory_operand(binary: StageABinary, operand: Any) -> StageAImport | None:
    thunk_rva = _absolute_mem_operand_rva(binary, operand)
    if thunk_rva is None:
        return None
    return _import_for_thunk_rva(binary, thunk_rva)

def _import_for_thunk_rva(binary: StageABinary, thunk_rva: int) -> StageAImport | None:
    for item in binary.imports:
        if item.thunk_rva == thunk_rva:
            return item
    return None

def _direct_import_thunk(binary: StageABinary, target_rva: int) -> StageAImport | None:
    if _executable_section_for_rva(binary, target_rva) is None:
        return None
    data = binary.pe.get_data(target_rva, 16)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + target_rva))
    if not instructions:
        return None
    first = instructions[0]
    if first.mnemonic not in {"jmp", "ljmp"} or len(first.operands) != 1:
        return None
    operand = first.operands[0]
    if operand.type != X86_OP_MEM:
        return None
    return _import_for_absolute_memory_operand(binary, operand)

def _is_noreturn_import_call(binary: StageABinary, insn: Any) -> bool:
    imported = _external_import_call(binary, insn)
    if imported is None:
        return False
    symbol = _normalized_import_symbol(imported.symbol)
    return symbol in NORETURN_IMPORT_SYMBOLS

def _normalized_import_symbol(symbol: str | None) -> str:
    if not symbol:
        return ""
    name = symbol.split("@", 1)[0]
    return name.lstrip("_").lower()

def _absolute_mem_operand_rva(binary: StageABinary, operand: Any) -> int | None:
    mem = operand.mem
    if mem.base or mem.index:
        return None
    address = int(mem.disp)
    if binary.image_base <= address < binary.image_base + binary.size_of_image:
        return address - binary.image_base
    if 0 <= address < binary.size_of_image:
        return address
    return None

def _generated_mapping_proof(
    *,
    proof_rule: str,
    function: str,
    original_flags: str,
    candidate_flags: str,
    proof_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    proof = {
        "rule": proof_rule,
        "checked": True,
        "function": function,
        "original_flags": original_flags,
        "candidate_flags": candidate_flags,
    }
    if proof_metadata:
        proof.update(proof_metadata)
    return proof

__all__ = [
    '_ambiguous_block_match_details',
    '_block_shape_summaries',
    '_block_shape_summary',
    '_capstone_mode',
    '_contiguous_function_path_cluster',
    '_disassemble_block',
    '_edge_kind_counts',
    '_function_range_block',
    '_gap_block_sample',
    '_generated_map_issues',
    '_generic_map_layout_issues',
    '_group_import_thunks_by_signature',
    '_import_signature',
    '_import_signature_report',
    '_import_thunk_block_entry',
    '_import_thunk_match_key',
    '_import_thunk_match_report',
    '_instruction_shape',
    '_is_padding_bytes',
    '_is_padding_instruction',
    '_layout_issues',
    '_linker_function_import_thunk_evidence',
    '_linker_function_issues',
    '_linker_function_match_key',
    '_match_function_blocks',
    '_match_import_thunk_functions_by_signature',
    '_match_linker_functions_by_name_or_unique_alias',
    '_padding_waiver',
    '_paired_section_gap_classification',
    '_recover_basic_blocks',
    '_section_compatibility_signature',
    '_section_gap_code_blocks',
    '_section_gaps',
    '_section_permission_signature',
    '_section_rva_start_signature',
    '_trim_padding_edges',
    '_unique_functions_by_name',
    '_absolute_mem_operand_rva',
    '_direct_branch_target',
    '_direct_cfg_edges',
    '_direct_import_jump_instruction',
    '_direct_import_thunk',
    '_external_import_call',
    '_gaps',
    '_generated_mapping_proof',
    '_import_for_absolute_memory_operand',
    '_import_for_thunk_rva',
    '_instruction_ends_basic_block',
    '_instruction_report',
    '_is_noreturn_import_call',
    '_normalized_import_symbol',
    '_range_overlap_issues',
    '_resolved_branch_target',
]
