"""Candidate-only contract validation, audit, and repair feedback."""

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
    REFERENCE_CONTRACT_MODEL_ID,
    _incomplete_record,
)

from .map_analysis import (
    _linker_function_match_key,
)

from .abi_candidate import (
    _candidate_abi_constraint_from_functions,
)
from .abi_comparison import (
    _contract_candidate_abi_coverage_gaps,
    _contract_candidate_abi_status,
)
from .abi_support import (
    _contract_candidate_function_symbol_names,
    _contract_candidate_symbol_keys,
    _contract_constraint,
    _count_by,
    _dedupe_strings,
    _empty_contract_candidate_alias_evidence,
    _safe_gap_part,
    _safe_int,
)

from .reference_contract import (
    _contract_candidate_validation_artifact,
    _contract_candidate_validation_summary,
    _load_contract_candidate_validation,
    stage_a_smoke_contract,
)
from .reference_diagnostics import (
    _load_reference_contract_sidecars,
)
from .reference_semantics import (
    _semantic_disassemble_block,
)
from .reference_sidecars import (
    _reference_sidecar_contract_ref,
)
from .reference_units import (
    _load_reference_unit_contract_sidecars,
    _matching_unit_contracts,
    _reference_unit_contract_artifact,
    _semantic_coverage_blockers,
    _semantic_coverage_counts,
    _semantic_coverage_families,
    _semantic_coverage_next_work,
)
from .reference_utils import (
    _binary_reference_layout,
    _gap_severity_rank,
    _load_json,
    _matches_focus,
    _reference_input_artifact,
)

from .candidate_audit import (
    _contract_candidate_shortfall_family,
    _stage_a_contract_shortfall_audit,
)

from .candidate_comparison import (
    _contract_candidate_families,
    _contract_candidate_skeleton_alias_evidence,
    _parse_stage_b_contract_rva_anchors,
)

def stage_b_check_contract(
    *,
    reference_contract: Path,
    candidate: Path,
    linker_map_candidate: Path,
    out: Path,
    model: str = REFERENCE_CONTRACT_MODEL_ID,
    skeleton_manifest: Path | None = None,
) -> dict[str, Any]:
    reference_contract = Path(reference_contract)
    candidate = Path(candidate)
    linker_map_candidate = Path(linker_map_candidate)
    skeleton_manifest = Path(skeleton_manifest) if skeleton_manifest is not None else None
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    contract = _load_json(reference_contract)
    candidate_bin = _parse_stage_a_pe(candidate)
    smoke = stage_a_smoke_contract(reference_contract=reference_contract)
    issues = list(smoke.get("issues", [])) if isinstance(smoke.get("issues"), list) else []
    if not isinstance(contract, dict) or contract.get("format") != "stage-a-reference-contract-v1":
        raise StageAInputError("reference contract must have format stage-a-reference-contract-v1")
    if contract.get("model") != model:
        issues.append(
            _incomplete_record(
                category="contract_model_mismatch",
                obligation_id="stage-a-contract-candidate:model",
                blocker="reference contract model does not match requested model",
                next_action="rerun with the contract model or regenerate the contract",
                details={"expected": model, "actual": contract.get("model")},
            )
        )
    candidate_functions = _parse_linker_map_functions(linker_map_candidate, candidate_bin)
    candidate_rva_anchors = _parse_stage_b_contract_rva_anchors(linker_map_candidate, candidate_bin)
    alias_evidence = _empty_contract_candidate_alias_evidence()
    skeleton_payload: dict[str, Any] | None = None
    if skeleton_manifest is not None:
        try:
            skeleton_payload = _load_json(skeleton_manifest)
            alias_evidence = _contract_candidate_skeleton_alias_evidence(skeleton_payload, candidate_functions)
        except StageAInputError as exc:
            alias_evidence = _empty_contract_candidate_alias_evidence(status="incomplete")
            issues.append(
                _incomplete_record(
                    category="contract_candidate_alias_evidence",
                    obligation_id="stage-a-contract-candidate:alias-evidence",
                    blocker=str(exc),
                    next_action="provide a readable stage-b-skeleton-v1 manifest or omit skeleton alias evidence",
                    details={"skeleton_manifest": str(skeleton_manifest)},
                )
            )
    families = _contract_candidate_families(
        contract,
        candidate_bin,
        candidate_functions,
        alias_evidence=alias_evidence,
        candidate_rva_anchors=candidate_rva_anchors,
    )
    shortfall_audit = _stage_a_contract_shortfall_audit(
        contract=contract,
        contract_path=reference_contract,
        model=model,
        candidate_bin=candidate_bin,
        candidate_functions=candidate_functions,
        alias_evidence=alias_evidence,
        skeleton_payload=skeleton_payload,
        linker_map_candidate=linker_map_candidate,
    )
    if shortfall_audit["status"] != "qualified":
        families.append(_contract_candidate_shortfall_family(shortfall_audit))
    for family in families:
        if family["status"] in {"incomplete", "violated"}:
            issues.append(
                _incomplete_record(
                    category=f"contract_candidate_{family['family']}",
                    obligation_id=f"stage-a-contract-candidate:{family['family']}",
                    blocker=family.get("blocker", "candidate does not satisfy this reference contract family"),
                    next_action=family.get("next_action", "repair the candidate or regenerate the contract package"),
                    details=family.get("evidence", {}),
                )
            )
    if any(item["status"] == "violated" for item in families):
        status = "violated"
    elif issues or not all(item["status"] in {"satisfied", "not_applicable"} for item in families):
        status = "incomplete"
    else:
        status = "qualified"
    result = {
        "format": "stage-b-candidate-contract-check-v2",
        "status": status,
        "model": model,
        "reference_contract": _reference_input_artifact(reference_contract),
        "candidate": _reference_input_artifact(candidate),
        "linker_map_candidate": _reference_input_artifact(linker_map_candidate),
        "skeleton_manifest": _reference_input_artifact(skeleton_manifest) if skeleton_manifest is not None else None,
        "shortfall_audit": shortfall_audit,
        "families": families,
        "issues": issues,
        "counts": {
            "families": len(families),
            "issues": len(issues),
            "candidate_functions": len(candidate_functions),
            "alias_matches": alias_evidence["counts"]["alias_matches"],
            "alias_ambiguities": alias_evidence["counts"]["ambiguities"],
            "unmatched_aliases": alias_evidence["counts"].get("unmatched_aliases", 0),
            "shortfall_findings": shortfall_audit.get("counts", {}).get("findings", 0)
            if isinstance(shortfall_audit.get("counts"), dict)
            else 0,
        },
    }
    write_json(out / "verdict.json", result)
    write_json(out / "contract-candidate.json", result)
    return result

def stage_b_audit_contract(
    *,
    reference_contract: Path,
    out: Path,
    contract_candidate_validation: Path | None = None,
    candidate: Path | None = None,
    linker_map_candidate: Path | None = None,
    skeleton_manifest: Path | None = None,
    candidate_crash_report: Path | None = None,
    unit_contract_dir: Path | None = None,
    target_name: str | None = None,
    model: str = REFERENCE_CONTRACT_MODEL_ID,
) -> dict[str, Any]:
    reference_contract = Path(reference_contract)
    contract = _load_json(reference_contract)
    if not isinstance(contract, dict) or contract.get("format") != "stage-a-reference-contract-v1":
        raise StageAInputError("reference contract must have format stage-a-reference-contract-v1")
    candidate_bin: StageABinary | None = None
    candidate_functions: list[dict[str, Any]] = []
    if candidate is not None:
        candidate_bin = _parse_stage_a_pe(Path(candidate))
    if linker_map_candidate is not None:
        if candidate_bin is None:
            raise StageAInputError("--linker-map-candidate requires --candidate")
        candidate_functions = _parse_linker_map_functions(Path(linker_map_candidate), candidate_bin)
    skeleton_payload = _load_json(Path(skeleton_manifest)) if skeleton_manifest is not None else None
    if skeleton_payload is not None and (not isinstance(skeleton_payload, dict) or skeleton_payload.get("format") != "stage-b-skeleton-v1"):
        raise StageAInputError("skeleton manifest must have format stage-b-skeleton-v1")
    alias_evidence = (
        _contract_candidate_skeleton_alias_evidence(skeleton_payload, candidate_functions)
        if isinstance(skeleton_payload, dict) and candidate_functions
        else _empty_contract_candidate_alias_evidence()
    )
    validation_payload = _load_json(Path(contract_candidate_validation)) if contract_candidate_validation is not None else None
    crash_payload = _load_json(Path(candidate_crash_report)) if candidate_crash_report is not None else None
    result = _stage_a_contract_shortfall_audit(
        contract=contract,
        contract_path=reference_contract,
        model=model,
        candidate_bin=candidate_bin,
        candidate_functions=candidate_functions,
        alias_evidence=alias_evidence,
        skeleton_payload=skeleton_payload if isinstance(skeleton_payload, dict) else None,
        contract_candidate_validation=validation_payload if isinstance(validation_payload, dict) else None,
        candidate_crash=crash_payload if isinstance(crash_payload, dict) else None,
        unit_contract_dir=Path(unit_contract_dir) if unit_contract_dir is not None else None,
        target_name=target_name,
        linker_map_candidate=Path(linker_map_candidate) if linker_map_candidate is not None else None,
    )
    out = Path(out)
    if out.suffix.lower() == ".json":
        out.parent.mkdir(parents=True, exist_ok=True)
        write_json(out, result)
    else:
        out.mkdir(parents=True, exist_ok=True)
        write_json(out / "stage-a-shortfalls.json", result)
    return result

def stage_b_extract_work_items(
    *,
    reference_contract: Path,
    out: Path,
    unit_contract_dir: Path | None = None,
) -> dict[str, Any]:
    reference_contract = Path(reference_contract)
    contract = _load_json(reference_contract)
    contract_ref = _reference_sidecar_contract_ref(reference_contract)
    unit_contracts = _load_reference_unit_contract_sidecars(
        contract,
        reference_contract,
        unit_contract_dir=Path(unit_contract_dir) if unit_contract_dir is not None else None,
        contract_ref=contract_ref,
    )
    repair_units = unit_contracts.get("repair_units") if isinstance(unit_contracts.get("repair_units"), dict) else {}
    work_items = repair_units.get("work_items") if isinstance(repair_units.get("work_items"), list) else []
    result = {
        "format": "stage-b-work-items-v2",
        "status": "qualified",
        "reference_contract": _reference_input_artifact(reference_contract),
        "unit_contracts": _reference_unit_contract_artifact(unit_contracts),
        "work_items": work_items,
        "counts": {
            "work_items": len(work_items),
            "by_family": _count_by([item for item in work_items if isinstance(item, dict)], "family"),
            "by_repair_class": _count_by([item for item in work_items if isinstance(item, dict)], "repair_class"),
        },
    }
    write_json(Path(out), result)
    return result

def stage_b_contract_coverage(
    *,
    reference_contract: Path,
    out: Path,
    unit_contract_dir: Path | None = None,
) -> dict[str, Any]:
    reference_contract = Path(reference_contract)
    contract = _load_json(reference_contract)
    contract_ref = _reference_sidecar_contract_ref(reference_contract)
    unit_contracts = _load_reference_unit_contract_sidecars(
        contract,
        reference_contract,
        unit_contract_dir=Path(unit_contract_dir) if unit_contract_dir is not None else None,
        contract_ref=contract_ref,
    )
    blockers = _semantic_coverage_blockers(unit_contracts)
    status = "qualified" if not blockers else "incomplete"
    result = {
        "format": "stage-b-semantic-coverage-v2",
        "status": status,
        "reference_contract": _reference_input_artifact(reference_contract),
        "unit_contracts": _reference_unit_contract_artifact(unit_contracts),
        "families": _semantic_coverage_families(unit_contracts, blockers),
        "counts": _semantic_coverage_counts(unit_contracts, blockers),
        "blockers": blockers[:250],
        "next_work": _semantic_coverage_next_work(blockers),
        "qualification": {
            "full_reimplementation_ready": status == "qualified",
            "requirement": "all executable regions must have implementable transfer/cluster contracts or explicit external-boundary contracts",
            "final_assurance": "compiled candidates still require candidate-only static and behavioral assurance; this ledger only gates analysis coverage",
        },
    }
    write_json(Path(out), result)
    return result

def stage_b_check_unit(
    *,
    reference_contract: Path,
    candidate: Path,
    linker_map_candidate: Path,
    skeleton_manifest: Path | None,
    focus: str,
    out: Path,
    unit_contract_dir: Path | None = None,
    model: str = REFERENCE_CONTRACT_MODEL_ID,
    contract_candidate_validation: dict[str, Any] | Path | None = None,
    embed_contract_candidate_validation: bool = True,
) -> dict[str, Any]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    validation = _load_contract_candidate_validation(contract_candidate_validation)
    validation_source = "provided"
    if validation is None:
        validation_source = "computed"
        validation = stage_b_check_contract(
            reference_contract=reference_contract,
            candidate=candidate,
            linker_map_candidate=linker_map_candidate,
            skeleton_manifest=skeleton_manifest,
            model=model,
            out=out / "contract-candidate",
        )
    reference_contract = Path(reference_contract)
    contract = _load_json(reference_contract)
    unit_contracts = _load_reference_unit_contract_sidecars(
        contract,
        reference_contract,
        unit_contract_dir=Path(unit_contract_dir) if unit_contract_dir is not None else None,
        contract_ref=_reference_sidecar_contract_ref(reference_contract),
    )
    focus_lower = focus.lower()
    focused_families = [
        item
        for item in validation.get("families", [])
        if isinstance(item, dict) and _matches_focus(item, focus_lower)
    ]
    focused_issues = [
        item
        for item in validation.get("issues", [])
        if isinstance(item, dict) and _matches_focus(item, focus_lower)
    ]
    focused_units = _matching_unit_contracts(unit_contracts, focus_lower)
    matched = bool(focused_families or focused_issues or focused_units)
    blocking_families = [
        item for item in focused_families
        if item.get("status") not in {"satisfied", "not_applicable", "qualified"}
    ]
    focused_status = "qualified" if matched and not blocking_families and not focused_issues else "incomplete"
    status = "qualified" if validation.get("status") == "qualified" and focused_status == "qualified" else "incomplete"
    result = {
        "format": "stage-b-unit-contract-check-v2",
        "status": status,
        "focused_status": focused_status,
        "scope": "focused_unit_filter",
        "focus": focus,
        "reference_contract": _reference_input_artifact(reference_contract),
        "candidate": _reference_input_artifact(Path(candidate)),
        "candidate_contract_status": validation.get("status") or validation.get("verdict"),
        "contract_candidate_validation_source": validation_source,
        "contract_candidate_validation_embedded": embed_contract_candidate_validation,
        "contract_candidate_validation_artifact": _contract_candidate_validation_artifact(contract_candidate_validation),
        "contract_candidate_validation": validation
        if embed_contract_candidate_validation
        else _contract_candidate_validation_summary(validation),
        "families": focused_families,
        "issues": focused_issues,
        "unit_contracts": focused_units,
        "counts": {
            "families": len(focused_families),
            "issues": len(focused_issues),
            "unit_contracts": len(focused_units),
        },
    }
    if not matched:
        result["blocker"] = "no contract unit or validation evidence matched the requested focus"
        result["next_action"] = "pick a function name, block id, family, obligation id, or work-item id from the reference contract sidecars"
    write_json(out / "unit-validation.json", result)
    return result

__all__ = [
    'stage_b_audit_contract',
    'stage_b_check_contract',
    'stage_b_check_unit',
    'stage_b_contract_coverage',
    'stage_b_extract_work_items',
]
