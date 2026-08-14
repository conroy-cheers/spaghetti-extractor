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
from .map_analysis import (
    _generic_map_layout_issues,
    _import_thunk_block_entry,
    _import_thunk_match_key,
    _import_thunk_match_report,
    _linker_function_import_thunk_evidence,
    _linker_function_issues,
    _match_function_blocks,
    _match_import_thunk_functions_by_signature,
    _match_linker_functions_by_name_or_unique_alias,
    _paired_section_gap_classification,
    _recover_basic_blocks,
    _unique_functions_by_name,
)

from .map_analysis import (
    _generated_mapping_proof,
)
from .map_verification import (
    _generated_layout_contract,
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

__all__ = [
    'stage_a_generate_map',
]
