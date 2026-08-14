"""Reference-contract generation, sidecars, and obligation diagnostics."""

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
    BlockMapping,
    NonCodeWaiver,
    REFERENCE_CONTRACT_MODEL_ID,
    _incomplete_record,
    _mapping_source,
    _range_report,
)

from .map_analysis import (
    _capstone_mode,
    _generated_map_issues,
    _import_signature,
    _layout_issues,
    _section_compatibility_signature,
    _section_permission_signature,
    _section_rva_start_signature,
)
from .map_analysis import (
    _direct_cfg_edges,
    _gaps,
    _instruction_report,
)
from .map_verification import (
    _parse_block_map,
    _verify_waiver_side,
    _waiver_obligations,
)

from .abi import (
    _abi_function_evidence,
)
from .abi_arguments import (
    _abi_import_prototypes,
)
from .abi_clusters import (
    _abi_cluster_contracts,
    _abi_evidence_by_block,
    _abi_evidence_by_function,
    _abi_functions,
    _cluster_contract,
)
from .abi_comparison import (
    _contract_candidate_abi_coverage_gaps,
)
from .abi_profile import (
    _stage_a_abi_profile_comparison_gaps,
)
from .abi_support import (
    _block_id_for_instruction,
    _contract_constraint,
    _count_by,
    _safe_gap_part,
    _safe_int,
)

from .symbolic_execution import (
    _import_z3,
    _symbolic_execute,
    _symbolic_incomplete,
)
from .symbolic_expressions import (
    _expr_json,
)

from .reference_utils import (
    _binary_relocation_summary,
    _load_json,
)

def _layout_contract_from_mapping_payload(payload: Any, mapping: Path | None) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    embedded = payload.get("layout_contract")
    if isinstance(embedded, dict):
        return embedded
    if not isinstance(embedded, str) or not embedded:
        return None
    path = Path(embedded)
    if not path.is_absolute() and mapping is not None:
        path = mapping.parent / path
    try:
        return _load_json(path)
    except StageAInputError:
        return None

def _reference_pe_layout_constraint(
    *,
    original: StageABinary,
    candidate: StageABinary | None,
    layout_contract: dict[str, Any] | None,
) -> dict[str, Any]:
    if candidate is None:
        return {
            "status": "derived",
            "evidence_kind": "pefile",
            "scope": "original",
            "sections": _section_permission_signature(original),
            "imports": _import_signature(original),
            "relocations": _binary_relocation_summary(original),
            "image_base": original.image_base,
        }
    issues = _layout_issues(original, candidate, layout_contract)
    return {
        "status": "satisfied" if not issues else ("failed" if any(issue.get("severity") == "fail" for issue in issues) else "incomplete"),
        "evidence_kind": "stage-a-layout-model",
        "scope": "original-candidate-pair",
        "facts": {
            "matching_machine": original.machine == candidate.machine,
            "matching_bitness": original.bitness == candidate.bitness,
            "matching_section_rvas": _section_rva_start_signature(original) == _section_rva_start_signature(candidate),
            "matching_section_permissions": _section_compatibility_signature(original) == _section_compatibility_signature(candidate),
            "matching_imports": _import_signature(original) == _import_signature(candidate),
            "matching_image_base": original.image_base == candidate.image_base,
        },
        "original": {
            "sections": _section_permission_signature(original),
            "imports": _import_signature(original),
            "relocations": _binary_relocation_summary(original),
            "image_base": original.image_base,
        },
        "candidate": {
            "sections": _section_permission_signature(candidate),
            "imports": _import_signature(candidate),
            "relocations": _binary_relocation_summary(candidate),
            "image_base": candidate.image_base,
        },
        "issues": issues,
    }

def _reference_map_constraints(
    *,
    original: StageABinary,
    candidate: StageABinary | None,
    mapping_payload: Any,
) -> dict[str, Any]:
    if mapping_payload is None:
        missing = _reference_missing_map_constraint()
        return {
            "issues": [],
            "mappings": [],
            "verified_waivers": [],
            "executable_byte_coverage": missing,
            "function_ranges": missing,
            "basic_blocks_and_cfg": missing,
            "roots_and_jump_tables": missing,
            "padding_alignment": missing,
        }

    mappings, waivers, map_issues = _parse_block_map(mapping_payload, original)
    map_issues.extend(_generated_map_issues(mapping_payload))
    verified_waivers: list[NonCodeWaiver] = []
    waiver_obligations: list[dict[str, Any]] = []
    if candidate is not None:
        verified_waivers, waiver_obligations = _waiver_obligations(original, candidate, waivers)
    elif waivers:
        for waiver in waivers:
            check = _verify_waiver_side("original", original, waiver)
            obligation_id = (
                f"waiver:{waiver.id}:original:"
                f"{waiver.rva_start:x}-{waiver.rva_end:x}"
            )
            if check["status"] == "verified":
                verified_waivers.append(waiver)
                waiver_obligations.append({
                    "id": obligation_id,
                    "kind": "executable_byte_class",
                    "status": "classified_padding",
                    "classification_rule": "verified_original_padding_bytes_v1",
                    "binary": "original",
                    "rva_start": waiver.rva_start,
                    "rva_end": waiver.rva_end,
                    "reason": waiver.reason,
                    "checks": [check],
                })
            else:
                incomplete = _incomplete_record(
                    category="unverified_noncode_waiver",
                    obligation_id=obligation_id,
                    blocker="non-code bytes are not verified as executable-section padding",
                    next_action="narrow the range to verified padding or classify it as code",
                    details={"check": check},
                )
                map_issues.append(incomplete)
                waiver_obligations.append({
                    "id": obligation_id,
                    "kind": "executable_byte_class",
                    "status": "incomplete",
                    "binary": "original",
                    "rva_start": waiver.rva_start,
                    "rva_end": waiver.rva_end,
                    "reason": waiver.reason,
                    "incomplete": incomplete,
                })
    for obligation in waiver_obligations:
        if obligation.get("status") == "incomplete" and isinstance(obligation.get("incomplete"), dict):
            map_issues.append(obligation["incomplete"])

    map_status = _reference_map_status(mapping_payload, map_issues)
    return {
        "issues": map_issues,
        "mappings": mappings,
        "verified_waivers": verified_waivers,
        "executable_byte_coverage": {
            "status": "satisfied"
            if map_status == "satisfied"
            and not _reference_coverage_side("original", original, mappings, verified_waivers)["gaps"]
            and (candidate is None or not _reference_coverage_side("candidate", candidate, mappings, verified_waivers)["gaps"])
            else "incomplete",
            "evidence_kind": "stage-a-block-map",
            "original": _reference_coverage_side("original", original, mappings, verified_waivers),
            "candidate": _reference_coverage_side("candidate", candidate, mappings, verified_waivers) if candidate is not None else None,
        },
        "function_ranges": _reference_function_ranges(mappings, map_status),
        "basic_blocks_and_cfg": _reference_basic_blocks_and_cfg(original, candidate, mappings, map_status),
        "roots_and_jump_tables": _reference_roots_and_jump_tables(mappings, map_status),
        "padding_alignment": _reference_padding_alignment(waivers, verified_waivers, waiver_obligations, map_status),
    }

def _reference_missing_map_constraint() -> dict[str, Any]:
    return {
        "status": "not_provided",
        "evidence_kind": "none",
        "blocker": "no Stage A block map was provided",
        "next_action": "generate a Stage A block map and re-export the reference contract",
    }

def _reference_map_status(mapping_payload: Any, issues: list[dict[str, Any]]) -> str:
    if any(issue.get("status") == "failed" or issue.get("severity") == "fail" for issue in issues):
        return "failed"
    if issues:
        return "incomplete"
    if isinstance(mapping_payload, dict) and mapping_payload.get("status") not in {None, "pass"}:
        return "incomplete"
    return "satisfied"

def _reference_coverage_side(
    side: str,
    binary: StageABinary,
    mappings: list[BlockMapping],
    waivers: list[NonCodeWaiver],
) -> dict[str, Any]:
    mapped_ranges = [
        mapped.original if side == "original" else mapped.candidate
        for mapped in mappings
        if mapped.kind == "code"
    ]
    waiver_ranges = [
        BlockSide(waiver.rva_start, waiver.rva_end)
        for waiver in waivers
        if waiver.binary in {side, "both"}
    ]
    classified = mapped_ranges + waiver_ranges
    executable_sections = [section for section in binary.sections if section.executable]
    gaps = [
        gap
        for section in executable_sections
        for gap in _gaps(section.rva_start, section.rva_end, classified)
    ]
    executable_bytes = sum(section.rva_end - section.rva_start for section in executable_sections)
    classified_bytes = sum(item.rva_end - item.rva_start for item in _merged_ranges(classified))
    return {
        "status": "satisfied" if not gaps else "incomplete",
        "binary": side,
        "executable_bytes": executable_bytes,
        "classified_bytes": min(classified_bytes, executable_bytes),
        "mapped_code_ranges": [_range_report(item) for item in mapped_ranges],
        "waived_noncode_ranges": [_range_report(item) for item in waiver_ranges],
        "gaps": [_range_report(item) for item in gaps],
    }

def _merged_ranges(ranges: list[BlockSide]) -> list[BlockSide]:
    merged: list[BlockSide] = []
    for item in sorted(ranges, key=lambda value: (value.rva_start, value.rva_end)):
        if not merged or item.rva_start > merged[-1].rva_end:
            merged.append(item)
            continue
        merged[-1] = BlockSide(merged[-1].rva_start, max(merged[-1].rva_end, item.rva_end))
    return merged

def _reference_function_ranges(mappings: list[BlockMapping], map_status: str) -> dict[str, Any]:
    functions: dict[str, dict[str, Any]] = {}
    for mapped in mappings:
        source = _mapping_source(mapped)
        name = source.get("function") if isinstance(source.get("function"), str) else ""
        if not name:
            continue
        entry = functions.setdefault(
            name,
            {
                "name": name,
                "original": {"rva_start": mapped.original.rva_start, "rva_end": mapped.original.rva_end},
                "candidate": {"rva_start": mapped.candidate.rva_start, "rva_end": mapped.candidate.rva_end},
                "block_ids": [],
            },
        )
        entry["original"]["rva_start"] = min(entry["original"]["rva_start"], mapped.original.rva_start)
        entry["original"]["rva_end"] = max(entry["original"]["rva_end"], mapped.original.rva_end)
        entry["candidate"]["rva_start"] = min(entry["candidate"]["rva_start"], mapped.candidate.rva_start)
        entry["candidate"]["rva_end"] = max(entry["candidate"]["rva_end"], mapped.candidate.rva_end)
        entry["block_ids"].append(mapped.id)
    return {
        "status": map_status if functions else "incomplete",
        "evidence_kind": "linker-map-capstone-block-map",
        "functions": sorted(functions.values(), key=lambda item: item["name"]),
    }

def _reference_basic_blocks_and_cfg(
    original: StageABinary,
    candidate: StageABinary | None,
    mappings: list[BlockMapping],
    map_status: str,
) -> dict[str, Any]:
    blocks = []
    cfg_edges = []
    original_symbol_aliases = _coff_symbol_aliases_by_rva(original)
    candidate_symbol_aliases = _coff_symbol_aliases_by_rva(candidate) if candidate is not None else {}
    for mapped in mappings:
        source = _mapping_source(mapped)
        proof = mapped.source.get("proof") if isinstance(mapped.source.get("proof"), dict) else {}
        block = {
            "id": mapped.id,
            "kind": mapped.kind,
            "reachable": mapped.reachable,
            "function": source.get("function"),
            "original": _range_report(mapped.original),
            "candidate": _range_report(mapped.candidate),
            "source_kind": source.get("kind"),
            "proof_rule": proof.get("rule"),
            "byte_identical": source.get("byte_identical"),
        }
        symbol_aliases = {
            "original": _symbol_aliases_for_range(original_symbol_aliases, mapped.original),
            "candidate": _symbol_aliases_for_range(candidate_symbol_aliases, mapped.candidate) if candidate is not None else [],
        }
        if symbol_aliases["original"] or symbol_aliases["candidate"]:
            block["symbol_aliases"] = symbol_aliases
        blocks.append(block)
        if mapped.kind != "code":
            continue
        edge_report = {
            "block_id": mapped.id,
            "original": _direct_cfg_edges(original, mapped.original),
            "candidate": _direct_cfg_edges(candidate, mapped.candidate) if candidate is not None else None,
        }
        cfg_edges.append(edge_report)
    return {
        "status": map_status if blocks else "incomplete",
        "evidence_kind": "capstone-direct-cfg",
        "basic_blocks": blocks,
        "cfg_edges": cfg_edges,
    }

def _symbol_aliases_for_range(symbols_by_rva: dict[int, list[str]], span: BlockSide) -> list[str]:
    aliases: list[str] = []
    for rva in sorted(rva for rva in symbols_by_rva if span.rva_start <= rva < span.rva_end):
        for alias in symbols_by_rva[rva]:
            if alias and alias not in aliases:
                aliases.append(alias)
    return aliases

def _reference_roots_and_jump_tables(mappings: list[BlockMapping], map_status: str) -> dict[str, Any]:
    roots = []
    jump_table_targets = []
    for mapped in mappings:
        for key in ("root", "reachability"):
            value = mapped.source.get(key)
            if isinstance(value, dict):
                roots.append({"block_id": mapped.id, **value})
        for key in ("jump_table_targets", "checked_jump_table_targets"):
            targets = mapped.source.get(key)
            if isinstance(targets, list):
                for target in targets:
                    if isinstance(target, dict):
                        jump_table_targets.append({"block_id": mapped.id, **target})
    return {
        "status": map_status if roots or jump_table_targets else ("not_applicable" if not mappings else "derived"),
        "evidence_kind": "stage-a-reachability-markers",
        "roots": roots,
        "jump_table_targets": jump_table_targets,
    }

def _reference_roots_and_jump_tables_with_abi_targets(
    roots: dict[str, Any],
    abi_callsites: dict[str, Any],
) -> dict[str, Any]:
    updated = dict(roots)
    existing = [
        item
        for item in roots.get("jump_table_targets", [])
        if isinstance(item, dict)
    ]
    targets: dict[tuple[str, int, int], dict[str, Any]] = {}
    for item in existing:
        key = (
            str(item.get("function") or ""),
            _safe_int(item.get("instruction_rva")) or -1,
            _safe_int(item.get("target_rva", item.get("rva"))) or -1,
        )
        targets.setdefault(key, dict(item))
    original = abi_callsites.get("original") if isinstance(abi_callsites.get("original"), dict) else {}
    functions = original.get("functions") if isinstance(original.get("functions"), list) else []
    for function in functions:
        if not isinstance(function, dict):
            continue
        function_name = str(function.get("name") or "")
        switches = function.get("switch_contracts") if isinstance(function.get("switch_contracts"), list) else []
        for switch in switches:
            if not isinstance(switch, dict) or switch.get("evidence_status") != "derived":
                continue
            instruction = switch.get("instruction") if isinstance(switch.get("instruction"), dict) else {}
            instruction_rva = _safe_int(instruction.get("rva"))
            case_targets = switch.get("case_targets") if isinstance(switch.get("case_targets"), list) else []
            by_target: dict[int, list[int]] = {}
            for case in case_targets:
                if not isinstance(case, dict):
                    continue
                target_rva = _safe_int(case.get("target_rva"))
                index = _safe_int(case.get("index"))
                if target_rva is None:
                    continue
                by_target.setdefault(target_rva, [])
                if index is not None:
                    by_target[target_rva].append(index)
            for target_rva, case_indices in sorted(by_target.items()):
                key = (function_name, instruction_rva or -1, target_rva)
                if key in targets:
                    continue
                targets[key] = {
                    "evidence_status": "derived",
                    "kind": "resolved_static_jump_table_target",
                    "function": function_name,
                    "block_id": _block_id_for_instruction(function, instruction),
                    "instruction_rva": instruction_rva,
                    "target_rva": target_rva,
                    "rva": target_rva,
                    "case_indices": sorted(set(case_indices)),
                    "table": switch.get("table"),
                    "source": "capstone-indexed-memory-jump-table",
                }
    updated["jump_table_targets"] = sorted(
        targets.values(),
        key=lambda item: (
            str(item.get("function") or ""),
            _safe_int(item.get("instruction_rva")) or -1,
            _safe_int(item.get("target_rva", item.get("rva"))) or -1,
        ),
    )
    if updated["jump_table_targets"] and updated.get("status") == "not_applicable":
        updated["status"] = "derived"
    return updated

def _reference_import_thunk_constraint(
    original: StageABinary,
    candidate: StageABinary | None,
    map_contract: dict[str, Any],
) -> dict[str, Any]:
    mappings = map_contract.get("mappings", [])
    mapped_thunks = []
    for mapped in mappings:
        source = _mapping_source(mapped)
        if mapped.kind == "import_thunk" or source.get("kind") == "import_thunk":
            mapped_thunks.append(
                {
                    "block_id": mapped.id,
                    "original": _range_report(mapped.original),
                    "candidate": _range_report(mapped.candidate),
                    "source": source,
                }
            )
    return {
        "status": "derived" if original.imports or (candidate is not None and candidate.imports) or mapped_thunks else "not_applicable",
        "evidence_kind": "pe-import-directory-and-block-map",
        "original_imports": [
            {"dll": item.dll, "symbol": item.symbol, "ordinal": item.ordinal, "thunk_rva": item.thunk_rva}
            for item in original.imports
        ],
        "candidate_imports": [
            {"dll": item.dll, "symbol": item.symbol, "ordinal": item.ordinal, "thunk_rva": item.thunk_rva}
            for item in candidate.imports
        ]
        if candidate is not None
        else None,
        "mapped_import_thunks": mapped_thunks,
    }

def _reference_abi_callsites_constraint(
    original: StageABinary,
    candidate: StageABinary | None,
    map_contract: dict[str, Any],
) -> dict[str, Any]:
    mappings = [mapped for mapped in map_contract.get("mappings", []) if isinstance(mapped, BlockMapping) and mapped.kind == "code"]
    map_status = str(map_contract.get("function_ranges", {}).get("status") or "incomplete")
    original_functions = _abi_function_evidence(original, mappings, side="original")
    candidate_functions = _abi_function_evidence(candidate, mappings, side="candidate") if candidate is not None else None
    original_callsites = sum(len(item.get("callsites", [])) for item in original_functions)
    candidate_callsites = (
        sum(len(item.get("callsites", [])) for item in candidate_functions)
        if isinstance(candidate_functions, list)
        else None
    )
    payload = {
        "status": map_status if mappings else "incomplete",
        "evidence_kind": "capstone-static-abi-callsites",
        "scope": "original-candidate-pair" if candidate is not None else "original",
        "original": {
            "functions": original_functions,
            "import_prototypes": _abi_import_prototypes(original),
        },
        "candidate": {
            "functions": candidate_functions,
            "import_prototypes": _abi_import_prototypes(candidate),
        }
        if candidate is not None
        else None,
        "counts": {
            "functions": len(original_functions),
            "callsites": original_callsites,
            "candidate_callsites": candidate_callsites,
            "import_prototypes": len(original.imports),
        },
    }
    if candidate is not None:
        comparison_gaps = _contract_candidate_abi_coverage_gaps(payload, payload)
        payload["comparison_gaps"] = comparison_gaps
        payload["profile_comparison_gaps"] = _stage_a_abi_profile_comparison_gaps(comparison_gaps)
    return payload

def _reference_padding_alignment(
    waivers: list[NonCodeWaiver],
    verified_waivers: list[NonCodeWaiver],
    waiver_obligations: list[dict[str, Any]],
    map_status: str,
) -> dict[str, Any]:
    if not waivers:
        return {"status": "not_applicable", "evidence_kind": "stage-a-waivers", "waivers": [], "obligations": []}
    status = map_status if len(waivers) == len(verified_waivers) and all(item.get("status") != "incomplete" for item in waiver_obligations) else "incomplete"
    return {
        "status": status,
        "evidence_kind": "verified-padding-bytes",
        "waivers": [
            {
                "id": waiver.id,
                "binary": waiver.binary,
                "rva_start": waiver.rva_start,
                "rva_end": waiver.rva_end,
                "reason": waiver.reason,
                "verified": waiver in verified_waivers,
            }
            for waiver in waivers
        ],
        "obligations": waiver_obligations,
    }

def _reference_layout_normalization_constraint(payload: dict[str, Any] | None) -> dict[str, Any]:
    if payload is None:
        return {
            "status": "not_provided",
            "evidence_kind": "none",
            "blocker": "no Stage A layout contract was provided",
            "next_action": "export a layout contract from stage-a-generate-map or pass --layout-contract",
        }
    required = payload.get("required_facts", []) if isinstance(payload.get("required_facts"), list) else []
    facts = payload.get("facts", {}) if isinstance(payload.get("facts"), dict) else {}
    missing = [fact for fact in required if fact not in facts]
    unsatisfied = [fact for fact in required if facts.get(fact) is not True]
    status = "satisfied" if not missing and not unsatisfied else "incomplete"
    return {
        "status": status,
        "evidence_kind": "stage-a-layout-contract",
        "contract": payload,
        "missing_required_facts": missing,
        "unsatisfied_required_facts": unsatisfied,
    }

def _reference_constraint_issues(constraints: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for name, constraint in constraints.items():
        if not isinstance(constraint, dict):
            continue
        if constraint.get("status") in {"satisfied", "derived", "not_applicable"}:
            continue
        issues.append(
            _incomplete_record(
                category="reference_contract_constraint_incomplete",
                obligation_id=f"reference-contract:{name}",
                blocker=f"Stage A reference contract constraint {name!r} is not closed",
                next_action="provide the missing Stage A evidence or inspect the constraint details",
                details={"status": constraint.get("status")},
            )
        )
    return issues

def _reference_contract_status(constraints: dict[str, Any], issues: list[dict[str, Any]]) -> str:
    if any(issue.get("status") == "failed" or issue.get("severity") == "fail" for issue in issues):
        return "violated"
    if issues:
        return "incomplete"
    return "qualified"

__all__ = [
    '_layout_contract_from_mapping_payload',
    '_merged_ranges',
    '_reference_abi_callsites_constraint',
    '_reference_basic_blocks_and_cfg',
    '_reference_constraint_issues',
    '_reference_contract_status',
    '_reference_coverage_side',
    '_reference_function_ranges',
    '_reference_import_thunk_constraint',
    '_reference_layout_normalization_constraint',
    '_reference_map_constraints',
    '_reference_map_status',
    '_reference_missing_map_constraint',
    '_reference_padding_alignment',
    '_reference_pe_layout_constraint',
    '_reference_roots_and_jump_tables',
    '_reference_roots_and_jump_tables_with_abi_targets',
    '_symbol_aliases_for_range',
]
