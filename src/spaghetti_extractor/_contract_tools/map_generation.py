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

def stage_a_generate_map(
    *,
    original: Path,
    candidate: Path,
    linker_map_original: Path,
    linker_map_candidate: Path,
    out: Path,
    layout_contract_out: Path | None = None,
    original_flags: str = "",
    candidate_flags: str = "",
    proof_rule: str = "same_source_layout_preserving_build_v1",
    proof_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if proof_rule not in CHECKED_GENERATED_MAPPING_PROOF_RULES:
        raise StageAInputError(f"unsupported generated mapping proof rule {proof_rule!r}")
    original_bin = _parse_stage_a_pe(original)
    candidate_bin = _parse_stage_a_pe(candidate)
    original_functions = _parse_linker_map_functions(linker_map_original, original_bin)
    candidate_functions = _parse_linker_map_functions(linker_map_candidate, candidate_bin)
    issues = _generic_map_layout_issues(original_bin, candidate_bin)
    issues.extend(_linker_function_issues("original", original_functions))
    issues.extend(_linker_function_issues("candidate", candidate_functions))

    matched_functions, unmatched_original, unmatched_candidate, match_issues = _match_linker_functions_by_name_or_unique_alias(
        original_functions,
        candidate_functions,
    )
    issues.extend(match_issues)
    import_thunk_matches, _, _, import_thunk_issues = _match_import_thunk_functions_by_signature(
        original_bin,
        candidate_bin,
        original_functions,
        candidate_functions,
        sorted(_unique_functions_by_name(original_functions)),
        sorted(_unique_functions_by_name(candidate_functions)),
    )
    issues.extend(import_thunk_issues)
    import_matched_original = {str(original_thunk["function"]["name"]) for original_thunk, _ in import_thunk_matches}
    import_matched_candidate = {str(candidate_thunk["function"]["name"]) for _, candidate_thunk in import_thunk_matches}
    filtered_matched_functions: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    released_original: set[str] = set()
    released_candidate: set[str] = set()
    for original_fn, candidate_fn, match_key in matched_functions:
        original_name = str(original_fn["name"])
        candidate_name = str(candidate_fn["name"])
        if original_name in import_matched_original or candidate_name in import_matched_candidate:
            if original_name not in import_matched_original:
                released_original.add(original_name)
            if candidate_name not in import_matched_candidate:
                released_candidate.add(candidate_name)
            continue
        filtered_matched_functions.append((original_fn, candidate_fn, match_key))
    matched_functions = filtered_matched_functions
    unmatched_original = sorted((set(unmatched_original) | released_original) - import_matched_original)
    unmatched_candidate = sorted((set(unmatched_candidate) | released_candidate) - import_matched_candidate)
    blocks: list[dict[str, Any]] = []

    for original_thunk, candidate_thunk in import_thunk_matches:
        blocks.append(
            _import_thunk_block_entry(
                original_thunk,
                candidate_thunk,
                match_key=_import_thunk_match_key(original_thunk["import"]),
            )
        )

    for original_fn, candidate_fn, match_key in sorted(matched_functions, key=lambda item: str(item[0]["name"])):
        name = str(original_fn["name"])
        candidate_name = str(candidate_fn["name"])
        original_thunk = _linker_function_import_thunk_evidence(original_bin, original_fn)
        candidate_thunk = _linker_function_import_thunk_evidence(candidate_bin, candidate_fn)
        if original_thunk is not None or candidate_thunk is not None:
            if original_thunk is not None and candidate_thunk is not None and original_thunk["signature_key"] == candidate_thunk["signature_key"]:
                blocks.append(
                    _import_thunk_block_entry(
                        original_thunk,
                        candidate_thunk,
                        match_key=match_key,
                    )
                )
                continue
            issues.append(
                _incomplete_record(
                    category="ambiguous_import_thunk_match",
                    obligation_id=f"map:import-thunk:{_artifact_name(name)}",
                    blocker="matched linker-map functions do not decode as the same PE import thunk",
                    next_action="preserve import thunk boundaries or add a more specific import-thunk matching rule",
                    details={
                        "function": name,
                        "candidate_function": candidate_name,
                        "original": _import_thunk_match_report(original_thunk),
                        "candidate": _import_thunk_match_report(candidate_thunk),
                    },
                )
            )
            continue
        original_blocks = _recover_basic_blocks(original_bin, original_fn["rva_start"], original_fn["rva_end"])
        candidate_blocks = _recover_basic_blocks(candidate_bin, candidate_fn["rva_start"], candidate_fn["rva_end"])
        matched, block_issues = _match_function_blocks(name, original_bin, candidate_bin, original_blocks, candidate_blocks)
        issues.extend(block_issues)
        for index, (original_block, candidate_block) in enumerate(matched):
            block_id = _artifact_name(f"{name}-{index:04d}")
            entry: dict[str, Any] = {
                "id": block_id,
                "kind": "code",
                "reachable": True,
                "original": {"rva": original_block["rva_start"], "size": original_block["rva_end"] - original_block["rva_start"]},
                "candidate": {"rva": candidate_block["rva_start"], "size": candidate_block["rva_end"] - candidate_block["rva_start"]},
                "source": {
                    "kind": "linker_map_capstone_block_match_v1",
                    "function": name,
                    "candidate_function": candidate_name,
                    "function_match_key": match_key,
                    "function_block_index": index,
                    "match": original_block["match_key"],
                },
                "proof": _generated_mapping_proof(
                    proof_rule=proof_rule,
                    function=name,
                    original_flags=original_flags,
                    candidate_flags=candidate_flags,
                    proof_metadata=proof_metadata,
                ),
            }
            if index == 0:
                entry["root"] = {"kind": "linker_map_function", "checked": True, "symbol": name}
            if original_block["bytes_sha256"] == candidate_block["bytes_sha256"]:
                entry["source"]["byte_identical"] = True
            blocks.append(entry)

    if unmatched_original:
        issues.append(
            _incomplete_record(
                category="missing_linker_map_entry",
                obligation_id="map:unmatched-original-functions",
                blocker="original linker-map functions have no candidate function with the same canonical name",
                next_action="add a stronger linker-map function matcher or verify the build flags preserve these functions",
                details={"functions": unmatched_original[:200], "count": len(unmatched_original)},
            )
        )
    if unmatched_candidate:
        issues.append(
            _incomplete_record(
                category="missing_linker_map_entry",
                obligation_id="map:unmatched-candidate-functions",
                blocker="candidate linker-map functions have no original function with the same canonical name",
                next_action="add a stronger linker-map function matcher or verify the build flags preserve these functions",
                details={
                    "functions": sorted(unmatched_candidate)[:200],
                    "count": len(unmatched_candidate),
                },
            )
        )

    gap_blocks, waivers, gap_issues = _paired_section_gap_classification(
        original_bin,
        candidate_bin,
        blocks,
        original_flags=original_flags,
        candidate_flags=candidate_flags,
        proof_rule=proof_rule,
        proof_metadata=proof_metadata,
    )
    blocks.extend(gap_blocks)
    issues.extend(gap_issues)

    map_payload = {
        "format": "stage-a-block-map-v1",
        "generator": "stage-a-generate-map",
        "status": "pass" if not issues else "incomplete",
        "original": {"path": str(original), "sha256": original_bin.sha256},
        "candidate": {"path": str(candidate), "sha256": candidate_bin.sha256},
        "linker_maps": {
            "original": str(linker_map_original),
            "candidate": str(linker_map_candidate),
        },
        "blocks": blocks,
        "waivers": waivers,
        "issues": issues,
        "counts": {
            "blocks": len(blocks),
            "waivers": len(waivers),
            "issues": len(issues),
            "original_functions": len(original_functions),
            "candidate_functions": len(candidate_functions),
        },
    }
    write_json(out, map_payload)

    layout_contract = _generated_layout_contract(original_bin, candidate_bin, map_payload)
    if layout_contract_out is not None:
        write_json(layout_contract_out, layout_contract)
    map_payload["layout_contract"] = layout_contract if layout_contract_out is None else str(layout_contract_out)
    return map_payload

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

def _generated_layout_contract(original: StageABinary, candidate: StageABinary, map_payload: dict[str, Any]) -> dict[str, Any]:
    facts = {
        "matching_architecture": original.machine == candidate.machine and original.bitness == candidate.bitness,
        "matching_section_rvas": _section_rva_start_signature(original) == _section_rva_start_signature(candidate),
        "matching_section_permissions": _section_compatibility_signature(original) == _section_compatibility_signature(candidate),
        "matching_imports": _import_signature(original) == _import_signature(candidate),
        "all_executable_bytes_classified": map_payload.get("status") == "pass",
    }
    facts["matching_normalized_executable_section_spans"] = (
        facts["matching_architecture"]
        and facts["matching_section_rvas"]
        and facts["matching_section_permissions"]
        and facts["all_executable_bytes_classified"]
    )
    return {
        "format": "stage-a-layout-contract-v1",
        "generator": "stage-a-generate-map",
        "require_same_image_base": original.image_base == candidate.image_base,
        "allow_different_section_spans": facts["matching_normalized_executable_section_spans"],
        "required_facts": [
            "matching_architecture",
            "matching_section_rvas",
            "matching_section_permissions",
            "matching_imports",
            "all_executable_bytes_classified",
            "matching_normalized_executable_section_spans",
        ],
        "facts": facts,
        "normalized_sections": _normalized_section_reports(original, candidate),
    }

def _normalized_section_reports(original: StageABinary, candidate: StageABinary) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    by_name = {section.name: section for section in candidate.sections}
    for section in original.sections:
        other = by_name.get(section.name)
        normalized_rva_end = max(section.rva_end, other.rva_end) if other is not None and section.executable else section.rva_end
        reports.append(
            {
                "name": section.name,
                "executable": section.executable,
                "rva_start": section.rva_start,
                "normalized_rva_end": normalized_rva_end,
                "original_rva_end": section.rva_end,
                "candidate_rva_end": other.rva_end if other is not None else None,
            }
        )
    return reports

def _parse_block_map(payload: Any, original: StageABinary) -> tuple[list[BlockMapping], list[NonCodeWaiver], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    if isinstance(payload, list):
        block_entries = payload
        waiver_entries: list[Any] = []
    elif isinstance(payload, dict):
        block_entries = payload.get("blocks", payload.get("mappings"))
        waiver_entries = payload.get("waivers", [])
    else:
        block_entries = None
        waiver_entries = []

    if not isinstance(block_entries, list):
        return [], [], [
            _incomplete_record(
                category="invalid_mapping",
                obligation_id="mapping:blocks",
                blocker="block-map.json must be a list or contain a blocks/mappings list",
                next_action="add explicit original-to-candidate block mappings",
            )
        ]

    mappings: list[BlockMapping] = []
    seen_ids: set[str] = set()
    for index, entry in enumerate(block_entries):
        try:
            mapped = _parse_block_mapping(entry, index, original)
        except StageAInputError as exc:
            issues.append(
                _incomplete_record(
                    category="invalid_mapping",
                    obligation_id=f"mapping:block:{index}",
                    blocker=str(exc),
                    next_action="fix the malformed block mapping entry",
                )
            )
            continue
        if mapped.id in seen_ids:
            issues.append(
                _failure_record(
                    category="invalid_mapping",
                    obligation_id=f"mapping:block:{mapped.id}",
                    blocker=f"duplicate block mapping id {mapped.id!r}",
                    original={"id": mapped.id},
                    candidate={"id": mapped.id},
                )
            )
            continue
        seen_ids.add(mapped.id)
        mappings.append(mapped)

    issues.extend(_range_overlap_issues("original", [(mapped.id, mapped.original) for mapped in mappings]))
    issues.extend(_range_overlap_issues("candidate", [(mapped.id, mapped.candidate) for mapped in mappings]))

    waivers: list[NonCodeWaiver] = []
    for index, entry in enumerate(waiver_entries if isinstance(waiver_entries, list) else []):
        try:
            waivers.append(_parse_waiver(entry, index))
        except StageAInputError as exc:
            issues.append(
                _incomplete_record(
                    category="invalid_waiver",
                    obligation_id=f"mapping:waiver:{index}",
                    blocker=str(exc),
                    next_action="fix the malformed non-code waiver entry",
                )
            )

    return mappings, waivers, issues

def _parse_block_mapping(entry: Any, index: int, original: StageABinary) -> BlockMapping:
    if not isinstance(entry, dict):
        raise StageAInputError("block mapping entry must be an object")
    block_id = str(entry.get("id") or f"block_{index:04d}")
    original_side = _parse_side(entry.get("original"), "original")
    candidate_side = _parse_side(entry.get("candidate"), "candidate")
    if original_side.size <= 0 or candidate_side.size <= 0:
        raise StageAInputError(f"block {block_id!r} has an empty or inverted range")
    invariant = entry.get("invariant", {})
    invariant_checked = bool(invariant.get("checked", True)) if isinstance(invariant, dict) else False
    reachable = bool(entry.get("reachable", original_side.rva_start == original.entrypoint_rva))
    return BlockMapping(
        id=block_id,
        original=original_side,
        candidate=candidate_side,
        kind=str(entry.get("kind") or "code"),
        reachable=reachable,
        invariant_checked=invariant_checked,
        source=entry,
    )

def _parse_side(value: Any, name: str) -> BlockSide:
    if not isinstance(value, dict):
        raise StageAInputError(f"{name} block side must be an object")
    if "rva_start" in value and "rva_end" in value:
        return BlockSide(_parse_int(value["rva_start"]), _parse_int(value["rva_end"]))
    if "rva" in value and "size" in value:
        start = _parse_int(value["rva"])
        return BlockSide(start, start + _parse_int(value["size"]))
    raise StageAInputError(f"{name} block side must contain rva_start/rva_end or rva/size")

def _parse_waiver(entry: Any, index: int) -> NonCodeWaiver:
    if not isinstance(entry, dict):
        raise StageAInputError("waiver entry must be an object")
    side = _parse_side(entry, "waiver")
    binary = str(entry.get("binary") or "both")
    if binary not in {"original", "candidate", "both"}:
        raise StageAInputError(f"waiver binary must be original, candidate, or both, got {binary!r}")
    return NonCodeWaiver(
        id=str(entry.get("id") or f"waiver_{index:04d}"),
        binary=binary,
        rva_start=side.rva_start,
        rva_end=side.rva_end,
        reason=str(entry.get("reason") or "non-code waiver"),
    )

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

def _waiver_obligations(
    original: StageABinary,
    candidate: StageABinary,
    waivers: Iterable[NonCodeWaiver],
) -> tuple[list[NonCodeWaiver], list[dict[str, Any]]]:
    verified: list[NonCodeWaiver] = []
    obligations: list[dict[str, Any]] = []
    for waiver in waivers:
        checks = _verify_waiver(original, candidate, waiver)
        obligation_id = f"waiver:{waiver.id}:{waiver.binary}:{waiver.rva_start:x}-{waiver.rva_end:x}"
        failed = [check for check in checks if check["status"] != "verified"]
        if failed:
            blocker = _incomplete_record(
                category="unverified_noncode_waiver",
                obligation_id=obligation_id,
                blocker="non-code waiver bytes are not independently verified as executable-section padding",
                next_action="narrow the waiver to verified padding bytes or map the range as code",
                details={
                    "waiver": {
                        "id": waiver.id,
                        "binary": waiver.binary,
                        "rva_start": waiver.rva_start,
                        "rva_end": waiver.rva_end,
                        "reason": waiver.reason,
                    },
                    "checks": checks,
                },
            )
            obligations.append(
                {
                    "id": obligation_id,
                    "kind": "executable_byte_class",
                    "status": "incomplete",
                    "binary": waiver.binary,
                    "rva_start": waiver.rva_start,
                    "rva_end": waiver.rva_end,
                    "reason": waiver.reason,
                    "incomplete": blocker,
                }
            )
            continue
        verified.append(waiver)
        obligations.append(
            {
                "id": obligation_id,
                "kind": "executable_byte_class",
                "status": "waived_noncode",
                "proof_rule": "verified_padding_bytes_v1",
                "binary": waiver.binary,
                "rva_start": waiver.rva_start,
                "rva_end": waiver.rva_end,
                "reason": waiver.reason,
                "checks": checks,
            }
        )
    return verified, obligations

def _verify_waiver(original: StageABinary, candidate: StageABinary, waiver: NonCodeWaiver) -> list[dict[str, Any]]:
    sides = []
    if waiver.binary in {"original", "both"}:
        sides.append(("original", original))
    if waiver.binary in {"candidate", "both"}:
        sides.append(("candidate", candidate))
    return [_verify_waiver_side(side, binary, waiver) for side, binary in sides]

def _verify_waiver_side(side: str, binary: StageABinary, waiver: NonCodeWaiver) -> dict[str, Any]:
    section = _executable_section_covering_range(binary, waiver.rva_start, waiver.rva_end)
    if section is None:
        return {
            "binary": side,
            "status": "not_executable_section_padding",
            "rva_start": waiver.rva_start,
            "rva_end": waiver.rva_end,
            "reason": "waiver range is not fully contained in one executable section",
        }
    data = binary.pe.get_data(waiver.rva_start, waiver.rva_end - waiver.rva_start)
    if len(data) != waiver.rva_end - waiver.rva_start:
        return {
            "binary": side,
            "status": "unreadable",
            "rva_start": waiver.rva_start,
            "rva_end": waiver.rva_end,
            "section": section.name,
            "read_bytes": len(data),
        }
    if not _is_padding_bytes(binary, waiver.rva_start, data):
        return {
            "binary": side,
            "status": "not_padding",
            "rva_start": waiver.rva_start,
            "rva_end": waiver.rva_end,
            "section": section.name,
            "bytes_sha256": sha256_bytes(data),
        }
    return {
        "binary": side,
        "status": "verified",
        "rva_start": waiver.rva_start,
        "rva_end": waiver.rva_end,
        "section": section.name,
        "bytes_sha256": sha256_bytes(data),
        "bytes_hex": data.hex(),
    }

def _executable_section_covering_range(binary: StageABinary, rva_start: int, rva_end: int) -> StageASection | None:
    if rva_end <= rva_start:
        return None
    for section in binary.sections:
        if section.executable and section.rva_start <= rva_start and rva_end <= section.rva_end:
            return section
    return None

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

def _external_import_jump(binary: StageABinary, insn: Any) -> StageAImport | None:
    if insn.mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1:
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
    '_absolute_mem_operand_rva',
    '_ambiguous_block_match_details',
    '_block_shape_summaries',
    '_block_shape_summary',
    '_capstone_mode',
    '_contiguous_function_path_cluster',
    '_direct_branch_target',
    '_direct_cfg_edges',
    '_direct_import_jump_instruction',
    '_direct_import_thunk',
    '_disassemble_block',
    '_edge_kind_counts',
    '_executable_section_covering_range',
    '_external_import_call',
    '_external_import_jump',
    '_function_range_block',
    '_gap_block_sample',
    '_gaps',
    '_generated_layout_contract',
    '_generated_map_issues',
    '_generated_mapping_proof',
    '_generic_map_layout_issues',
    '_group_import_thunks_by_signature',
    '_import_for_absolute_memory_operand',
    '_import_for_thunk_rva',
    '_import_signature',
    '_import_signature_report',
    '_import_thunk_block_entry',
    '_import_thunk_match_key',
    '_import_thunk_match_report',
    '_instruction_ends_basic_block',
    '_instruction_report',
    '_instruction_shape',
    '_is_noreturn_import_call',
    '_is_padding_bytes',
    '_is_padding_instruction',
    '_layout_issues',
    '_linker_function_import_thunk_evidence',
    '_linker_function_issues',
    '_linker_function_match_key',
    '_match_function_blocks',
    '_match_import_thunk_functions_by_signature',
    '_match_linker_functions_by_name_or_unique_alias',
    '_normalized_import_symbol',
    '_normalized_section_reports',
    '_padding_waiver',
    '_paired_section_gap_classification',
    '_parse_block_map',
    '_parse_block_mapping',
    '_parse_side',
    '_parse_waiver',
    '_range_overlap_issues',
    '_recover_basic_blocks',
    '_resolved_branch_target',
    '_section_compatibility_signature',
    '_section_gap_code_blocks',
    '_section_gaps',
    '_section_permission_signature',
    '_section_rva_start_signature',
    '_trim_padding_edges',
    '_unique_functions_by_name',
    '_verify_waiver',
    '_verify_waiver_side',
    '_waiver_obligations',
    'stage_a_generate_map',
]
