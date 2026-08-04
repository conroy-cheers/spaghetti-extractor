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
from ..analysis.cutpoints import semantic_cutpoint_spans_for_side
from ..util import sha256_bytes, sha256_file, utc_now, write_json

from .common import (
    REFERENCE_CONTRACT_MODEL_ID,
    _incomplete_record,
)

from .map_generation import (
    _linker_function_match_key,
)

from .abi import (
    _candidate_abi_constraint_from_functions,
    _contract_candidate_abi_coverage_gaps,
    _contract_candidate_abi_status,
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
    _binary_reference_layout,
    _contract_candidate_validation_artifact,
    _contract_candidate_validation_summary,
    _gap_severity_rank,
    _load_contract_candidate_validation,
    _load_json,
    _load_reference_contract_sidecars,
    _load_reference_unit_contract_sidecars,
    _matches_focus,
    _matching_unit_contracts,
    _reference_input_artifact,
    _reference_sidecar_contract_ref,
    _reference_unit_contract_artifact,
    _semantic_coverage_blockers,
    _semantic_coverage_counts,
    _semantic_coverage_families,
    _semantic_coverage_next_work,
    _semantic_disassemble_block,
    stage_a_smoke_contract,
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

def _stage_a_contract_shortfall_audit(
    *,
    contract: dict[str, Any],
    contract_path: Path,
    model: str,
    candidate_bin: StageABinary | None = None,
    candidate_functions: list[dict[str, Any]] | None = None,
    alias_evidence: dict[str, Any] | None = None,
    skeleton_payload: dict[str, Any] | None = None,
    contract_candidate_validation: dict[str, Any] | None = None,
    candidate_crash: dict[str, Any] | None = None,
    unit_contract_dir: Path | None = None,
    target_name: str | None = None,
    linker_map_candidate: Path | None = None,
) -> dict[str, Any]:
    candidate_functions = candidate_functions or []
    alias_evidence = alias_evidence or _empty_contract_candidate_alias_evidence()
    contract_ref = _reference_sidecar_contract_ref(contract_path)
    unit_contracts = _load_reference_unit_contract_sidecars(
        contract,
        contract_path,
        unit_contract_dir=unit_contract_dir,
        contract_ref=contract_ref,
    )
    sidecars = _load_reference_contract_sidecars(contract, contract_path)
    source_entries = _audit_source_map_entries(skeleton_payload)
    findings: list[dict[str, Any]] = []

    if contract.get("model") != model:
        findings.append(
            _audit_finding(
                family="candidate_semantics_unresolved",
                category="contract_model_mismatch",
                severity="incomplete",
                location={"reference_contract": str(contract_path)},
                expected=f"reference contract model {model}",
                observed=contract.get("model"),
                cause_hint="candidate audit was run against a different machine model",
                next_action="rerun with the reference contract model or regenerate the contract",
                evidence={},
            )
        )

    crash_finding = _audit_candidate_crash_finding(candidate_crash, candidate_bin, candidate_functions, source_entries)
    if crash_finding is not None:
        findings.append(crash_finding)

    findings.extend(_audit_alias_shortfall_findings(alias_evidence))
    findings.extend(_audit_target_owned_import_findings(contract, candidate_bin, target_name=target_name))
    findings.extend(_audit_raw_section_gap_findings(candidate_bin, candidate_functions, source_entries))
    findings.extend(_audit_unit_contract_shortfall_findings(contract, unit_contracts, source_entries))
    findings.extend(_audit_coverage_gap_mask_findings(sidecars, unit_contracts, alias_evidence, source_entries))
    findings.extend(_audit_validation_shortfall_findings(contract_candidate_validation))

    findings = _rank_audit_findings(_dedupe_audit_findings(findings))
    families = _audit_families(findings)
    return {
        "format": "stage-b-candidate-shortfall-audit-v2",
        "status": "qualified" if not findings else "incomplete",
        "model": model,
        "reference_contract": _reference_input_artifact(contract_path),
        "candidate": _reference_input_artifact(candidate_bin.path) if candidate_bin is not None else None,
        "linker_map_candidate": _reference_input_artifact(linker_map_candidate) if linker_map_candidate is not None else None,
        "contract_candidate_validation": contract_candidate_validation
        if isinstance(contract_candidate_validation, dict)
        else None,
        "families": families,
        "findings": findings,
        "next_work": [
            {
                "id": item["id"],
                "family": item["family"],
                "category": item["category"],
                "severity": item["severity"],
                "next_action": item["next_action"],
                "location": item["location"],
            }
            for item in findings[:10]
        ],
        "counts": {
            "findings": len(findings),
            "by_family": _count_by(findings, "family"),
            "by_category": _count_by(findings, "category"),
            "by_severity": _count_by(findings, "severity"),
            "source_map_entries": len(source_entries),
            "candidate_functions": len(candidate_functions),
        },
    }

def _contract_candidate_shortfall_family(shortfall_audit: dict[str, Any]) -> dict[str, Any]:
    findings = shortfall_audit.get("findings") if isinstance(shortfall_audit.get("findings"), list) else []
    return _contract_candidate_family(
        "contract_shortfalls",
        "satisfied" if not findings else "incomplete",
        "Stage A generated-candidate audit found underconstrained contract evidence",
        "fix the ranked Stage A shortfalls before treating this generated candidate as accepted",
        None,
        evidence={
            "audit_format": shortfall_audit.get("format"),
            "audit_status": shortfall_audit.get("status"),
            "counts": shortfall_audit.get("counts"),
            "families": shortfall_audit.get("families"),
            "findings": findings[:25],
            "next_work": shortfall_audit.get("next_work"),
        },
    )

def _audit_finding(
    *,
    family: str,
    category: str,
    severity: str,
    location: dict[str, Any],
    expected: Any,
    observed: Any,
    cause_hint: str,
    next_action: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    finding_id = f"shortfall:{family}:{category}:{_safe_gap_part(json.dumps(location, sort_keys=True, default=str))}"
    return {
        "id": finding_id[:240],
        "family": family,
        "category": category,
        "severity": severity,
        "location": location,
        "expected": expected,
        "observed": observed,
        "cause_hint": cause_hint,
        "next_action": next_action,
        "evidence": evidence,
    }

def _audit_alias_shortfall_findings(alias_evidence: dict[str, Any]) -> list[dict[str, Any]]:
    counts = alias_evidence.get("counts") if isinstance(alias_evidence.get("counts"), dict) else {}
    findings: list[dict[str, Any]] = []
    unmatched_count = int(counts.get("unmatched_aliases") or 0)
    if unmatched_count:
        findings.append(
            _audit_finding(
                family="candidate_semantics_unresolved",
                category="unmatched_skeleton_aliases",
                severity="incomplete",
                location={"alias_evidence": "skeleton_manifest", "unmatched_aliases": unmatched_count},
                expected="every source-map alias that claims reference coverage maps to a candidate linker symbol",
                observed=f"{unmatched_count} unmatched aliases",
                cause_hint="candidate source-map coverage is not fully bound to candidate code",
                next_action="root or remove unmatched source-map aliases, then rerun Stage A candidate validation",
                evidence=_contract_candidate_alias_evidence_summary(alias_evidence),
            )
        )
    ambiguity_count = int(counts.get("ambiguities") or 0)
    if ambiguity_count:
        findings.append(
            _audit_finding(
                family="candidate_semantics_unresolved",
                category="ambiguous_skeleton_aliases",
                severity="incomplete",
                location={"alias_evidence": "skeleton_manifest", "ambiguities": ambiguity_count},
                expected="each reference source-map alias resolves to one candidate linker symbol",
                observed=f"{ambiguity_count} ambiguous aliases",
                cause_hint="Stage A cannot identify which candidate code satisfies a claimed source alias",
                next_action="make source-map aliases deterministic and unique",
                evidence=_contract_candidate_alias_evidence_summary(alias_evidence),
            )
        )
    return findings

def _audit_target_owned_import_findings(
    contract: dict[str, Any],
    candidate_bin: StageABinary | None,
    *,
    target_name: str | None,
) -> list[dict[str, Any]]:
    target = target_name or _audit_infer_target_name(contract)
    if not target or candidate_bin is None:
        return []
    imports = _contract_import_signature(_binary_reference_layout(candidate_bin))
    owned_by_dll: dict[str, list[dict[str, Any]]] = {}
    for imported in imports:
        dll = str(imported.get("dll") or "")
        if _audit_dll_is_target_owned(dll, target):
            owned_by_dll.setdefault(dll.lower(), []).append(imported)
    if not owned_by_dll:
        return []
    samples = [
        {"dll": dll, "symbols": [str(item.get("symbol") or item.get("ordinal") or "") for item in rows[:12]], "imports": len(rows)}
        for dll, rows in sorted(owned_by_dll.items())
    ]
    return [
        _audit_finding(
            family="target_owned_import_borrowed",
            category="candidate_imports_target_owned_library",
            severity="incomplete",
            location={"target_name": target, "dlls": sorted(owned_by_dll)},
            expected="generated candidate reimplements target-owned libraries or includes them in an explicit checked closure contract",
            observed="candidate imports target-owned DLL symbols",
            cause_hint="matching PE imports alone does not prove that borrowed target-owned library behavior is faithfully reimplemented",
            next_action="reimplement the target-owned DLL closure or add a Stage A closure contract that validates it as part of the candidate",
            evidence={"imports_by_dll": samples},
        )
    ]

def _audit_raw_section_gap_findings(
    candidate_bin: StageABinary | None,
    candidate_functions: list[dict[str, Any]],
    source_entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    raw_entries = [entry for entry in source_entries if _audit_source_entry_is_raw_section_gap(entry)]
    if not raw_entries:
        return []
    risky: list[dict[str, Any]] = []
    missing_ranges = 0
    for entry in raw_entries:
        function = _audit_candidate_function_for_source_entry(candidate_functions, entry)
        if function is None:
            missing_ranges += 1
            continue
        instructions = _audit_function_instruction_sample(candidate_bin, function)
        risk_instructions = [item for item in instructions if _audit_raw_instruction_needs_checked_contract(item)]
        if risk_instructions:
            risky.append(
                {
                    "source_entry": _audit_source_entry_sample(entry),
                    "candidate_function": _contract_candidate_function_sample(function),
                    "risk_instructions": risk_instructions[:8],
                    "instruction_count": len(instructions),
                }
            )
    findings: list[dict[str, Any]] = [
        _audit_finding(
            family="raw_section_gap_accepted",
            category="raw_section_gap_source_without_checked_semantics",
            severity="incomplete",
            location={"source_map": "stage-b-skeleton", "raw_section_gap_entries": len(raw_entries)},
            expected="section-gap generated code is represented by checked semantic contracts before candidate qualification",
            observed=f"{len(raw_entries)} raw section-gap source-map entries",
            cause_hint="layout/byte coverage does not prove generated source faithfully implements section-gap control flow",
            next_action="replace raw section-gap helpers with checked semantic-region/source contracts or keep the candidate incomplete",
            evidence={"samples": [_audit_source_entry_sample(entry) for entry in raw_entries[:20]], "missing_candidate_ranges": missing_ranges},
        )
    ]
    if risky:
        findings.append(
            _audit_finding(
                family="raw_section_gap_accepted",
                category="effectful_raw_section_gap_code",
                severity="incomplete",
                location={"source_map": "stage-b-skeleton", "effectful_raw_section_gap_entries": len(risky)},
                expected="raw section-gap code with calls, returns, or indirect control flow has a checked compositional contract",
                observed=f"{len(risky)} raw section-gap entries contain effectful control-flow instructions",
                cause_hint="effectful raw-flow helpers can crash or diverge even when layout validation passes",
                next_action="emit checked per-block/cluster contracts for these helpers before accepting the candidate",
                evidence={"samples": risky[:20]},
            )
        )
    return findings

def _audit_unit_contract_shortfall_findings(
    contract: dict[str, Any],
    unit_contracts: dict[str, Any],
    source_entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not _audit_explicit_unit_sidecar_exists(unit_contracts, "repair_units"):
        return []
    repair_units = unit_contracts.get("repair_units") if isinstance(unit_contracts.get("repair_units"), dict) else {}
    work_items = repair_units.get("work_items") if isinstance(repair_units.get("work_items"), list) else []
    unresolved = [item for item in work_items if isinstance(item, dict)]
    findings: list[dict[str, Any]] = []
    if unresolved and source_entries:
        findings.append(
            _audit_finding(
                family="candidate_semantics_unresolved",
                category="unresolved_repair_units",
                severity="incomplete",
                location={"repair_units": "stage-a-unit-contract-sidecar", "work_items": len(unresolved)},
                expected="all Stage A repair units are represented by checked generated-candidate contracts",
                observed=f"{len(unresolved)} repair units still require a checked representation",
                cause_hint="the reference contract contains actionable work items that are not yet tied to candidate evidence",
                next_action="close or explicitly bind repair units to checked generated-candidate contracts",
                evidence={"counts": repair_units.get("counts"), "samples": unresolved[:20]},
            )
        )
    abi_items = [
        item
        for item in unresolved
        if str(item.get("repair_class") or "")
        in {"hidden_sret_or_out_param", "import_prototype_mismatch", "function_pointer_target", "switch_or_jump_table_dispatch", "tls_callback_abi"}
        or str(item.get("family") or "") == "abi_callsites"
    ]
    if abi_items:
        findings.append(
            _audit_finding(
                family="abi_underconstrained",
                category="abi_repair_units_not_blocking_verified",
                severity="incomplete",
                location={"repair_units": "stage-a-unit-contract-sidecar", "abi_items": len(abi_items)},
                expected="ABI/callsite evidence used for qualification is blocking-verified, not only derived guidance",
                observed=f"{len(abi_items)} ABI-related repair units remain",
                cause_hint="static ABI hints do not establish source-level prototypes, sret/out-param handling, varargs, or preserved state",
                next_action="promote ABI repair units to checked obligations or keep generated-candidate validation incomplete",
                evidence={"samples": abi_items[:20], "contract_abi_counts": _contract_constraint(contract, "abi_callsites").get("counts", {})},
            )
        )
    external_items = [item for item in abi_items if str(item.get("repair_class") or "") in {"import_prototype_mismatch", "function_pointer_target"}]
    if external_items:
        findings.append(
            _audit_finding(
                family="external_environment_underspecified",
                category="external_call_boundary_underconstrained",
                severity="incomplete",
                location={"repair_units": "stage-a-unit-contract-sidecar", "external_boundary_items": len(external_items)},
                expected="external/import/function-pointer boundaries have checked prototypes, argument roles, and environment effects",
                observed=f"{len(external_items)} external-boundary repair units remain",
                cause_hint="uninterpreted external calls are insufficient for generated source behavior claims",
                next_action="add checked import/function-pointer boundary contracts before accepting generated behavior",
                evidence={"samples": external_items[:20]},
            )
        )
    return findings

def _audit_coverage_gap_mask_findings(
    sidecars: dict[str, Any],
    unit_contracts: dict[str, Any],
    alias_evidence: dict[str, Any],
    source_entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    coverage = sidecars.get("coverage_gaps") if isinstance(sidecars.get("coverage_gaps"), dict) else {}
    gap_count = int((coverage.get("counts") if isinstance(coverage.get("counts"), dict) else {}).get("gaps") or 0)
    repair_units = unit_contracts.get("repair_units") if isinstance(unit_contracts.get("repair_units"), dict) else {}
    work_items = (
        repair_units.get("work_items")
        if _audit_explicit_unit_sidecar_exists(unit_contracts, "repair_units") and isinstance(repair_units.get("work_items"), list)
        else []
    )
    alias_counts = alias_evidence.get("counts") if isinstance(alias_evidence.get("counts"), dict) else {}
    unmatched_aliases = int(alias_counts.get("unmatched_aliases") or 0)
    raw_entries = [entry for entry in source_entries if _audit_source_entry_is_raw_section_gap(entry)]
    masked_count = len(work_items) + unmatched_aliases + len(raw_entries)
    if gap_count or not masked_count:
        return []
    return [
        _audit_finding(
            family="coverage_gap_masked",
            category="coverage_gaps_omit_assurance_shortfalls",
            severity="incomplete",
            location={"coverage_gaps": "coverage_gaps.json"},
            expected="coverage_gaps reflects generated-candidate assurance blockers as well as static reconstruction gaps",
            observed="coverage_gaps reports zero gaps while other assurance shortfalls exist",
            cause_hint="the current sidecar can suggest there is no work even when generated-candidate coverage remains incomplete",
            next_action="include repair units, unmatched aliases, raw section-gap helpers, and closure/import blockers in generated-candidate audit output",
            evidence={
                "coverage_counts": coverage.get("counts"),
                "repair_unit_count": len(work_items),
                "unmatched_aliases": unmatched_aliases,
                "raw_section_gap_entries": len(raw_entries),
            },
        )
    ]

def _audit_explicit_unit_sidecar_exists(unit_contracts: dict[str, Any], name: str) -> bool:
    paths = unit_contracts.get("paths") if isinstance(unit_contracts.get("paths"), dict) else {}
    path_text = paths.get(name)
    return isinstance(path_text, str) and Path(path_text).is_file()

def _audit_validation_shortfall_findings(validation: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(validation, dict) or validation.get("status") != "qualified":
        return []
    counts = validation.get("counts") if isinstance(validation.get("counts"), dict) else {}
    unmatched = int(counts.get("unmatched_aliases") or 0)
    if not unmatched:
        return []
    return [
        _audit_finding(
            family="candidate_semantics_unresolved",
            category="qualified_validation_with_unmatched_aliases",
            severity="incomplete",
            location={"contract_candidate_validation": validation.get("format")},
            expected="candidate validation cannot qualify with unmatched source-map aliases",
            observed=f"validation qualified with {unmatched} unmatched aliases",
            cause_hint="candidate validation treated unbound source coverage as non-blocking",
            next_action="make unmatched aliases blocking for generated-candidate qualification",
            evidence={"counts": counts},
        )
    ]

def _audit_candidate_crash_finding(
    crash: dict[str, Any] | None,
    candidate_bin: StageABinary | None,
    candidate_functions: list[dict[str, Any]],
    source_entries: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not isinstance(crash, dict) or crash.get("status") not in {"detected", "crash_detected"}:
        return None
    address = _audit_hex_int(crash.get("instruction_address") or crash.get("address") or crash.get("eip"))
    location: dict[str, Any] = {"crash_kind": crash.get("crash_kind")}
    function = None
    source_entry = None
    if candidate_bin is not None and address is not None:
        rva = _audit_va_to_rva(candidate_bin, address)
        location["instruction_address"] = f"0x{address:08X}"
        location["rva"] = rva
        function = _audit_candidate_function_for_rva(candidate_functions, rva)
        source_entry = _audit_source_entry_for_rva(source_entries, rva)
        if function is not None:
            location["candidate_function"] = function.get("name")
        if source_entry is not None:
            location["source_function"] = source_entry.get("function")
    return _audit_finding(
        family="candidate_runtime_witness",
        category="candidate_only_crash_static_location",
        severity="violated",
        location=location,
        expected="a candidate accepted by Stage A does not crash on public candidate-only behavior tests",
        observed=crash.get("crash_kind") or "candidate crash",
        cause_hint="runtime crash falsifies the current generated-candidate assurance result",
        next_action="use the mapped source/function location to add a blocking Stage A contract or reject this candidate statically",
        evidence={
            "crash": crash,
            "candidate_function": _contract_candidate_function_sample(function) if isinstance(function, dict) else None,
            "source_entry": _audit_source_entry_sample(source_entry) if isinstance(source_entry, dict) else None,
        },
    )

def _audit_source_map_entries(skeleton: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(skeleton, dict):
        return []
    source_map = skeleton.get("source_map") if isinstance(skeleton.get("source_map"), dict) else {}
    entries = source_map.get("functions") if isinstance(source_map.get("functions"), list) else []
    return [entry for entry in entries if isinstance(entry, dict)]

def _audit_source_entry_is_raw_section_gap(entry: dict[str, Any]) -> bool:
    name = str(entry.get("function") or "")
    source_kind = str(entry.get("source_kind") or "")
    aliases = entry.get("aliases") if isinstance(entry.get("aliases"), list) else []
    text = " ".join([name, source_kind, *[str(alias) for alias in aliases]])
    return (
        name.startswith("stage_b_contract_section_gap__")
        or "section-gap" in text
        or source_kind in {"generated_contract_guided_raw_flow", "generated_contract_placeholder_from_section_gap"}
    )

def _audit_source_entry_sample(entry: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        return None
    return {
        "function": entry.get("function"),
        "aliases": entry.get("aliases") if isinstance(entry.get("aliases"), list) else [],
        "source_kind": entry.get("source_kind"),
        "file": entry.get("file"),
        "line_start": entry.get("line_start"),
        "line_end": entry.get("line_end"),
        "rva_start": entry.get("rva_start"),
        "rva_end": entry.get("rva_end"),
    }

def _audit_candidate_function_for_source_entry(
    candidate_functions: list[dict[str, Any]],
    entry: dict[str, Any],
) -> dict[str, Any] | None:
    lookup = _contract_candidate_function_lookup(candidate_functions)
    names = [str(entry.get("function") or "")]
    aliases = entry.get("aliases") if isinstance(entry.get("aliases"), list) else []
    names.extend(str(alias) for alias in aliases if isinstance(alias, str))
    matches = _contract_candidate_lookup_matches(lookup, *names)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        exact = _contract_candidate_disambiguate_exact_source_match(matches, str(entry.get("function") or ""))
        return exact or matches[0]
    start = _safe_int(entry.get("rva_start"))
    if start is not None:
        return _audit_candidate_function_for_rva(candidate_functions, start)
    return None

def _audit_candidate_function_for_rva(candidate_functions: list[dict[str, Any]], rva: int) -> dict[str, Any] | None:
    containing = [
        function
        for function in candidate_functions
        if (_safe_int(function.get("rva_start")) is not None and _safe_int(function.get("rva_end")) is not None)
        and _safe_int(function.get("rva_start")) <= rva < _safe_int(function.get("rva_end"))
    ]
    if not containing:
        return None
    return sorted(containing, key=lambda item: (_safe_int(item.get("rva_end")) or 0) - (_safe_int(item.get("rva_start")) or 0))[0]

def _audit_source_entry_for_rva(source_entries: list[dict[str, Any]], rva: int) -> dict[str, Any] | None:
    containing = [
        entry
        for entry in source_entries
        if _safe_int(entry.get("rva_start")) is not None
        and _safe_int(entry.get("rva_end")) is not None
        and _safe_int(entry.get("rva_start")) <= rva < _safe_int(entry.get("rva_end"))
    ]
    if not containing:
        return None
    return sorted(containing, key=lambda item: (_safe_int(item.get("rva_end")) or 0) - (_safe_int(item.get("rva_start")) or 0))[0]

def _audit_function_instruction_sample(candidate_bin: StageABinary | None, function: dict[str, Any]) -> list[dict[str, Any]]:
    if candidate_bin is None:
        return []
    start = _safe_int(function.get("rva_start"))
    end = _safe_int(function.get("rva_end"))
    if start is None or end is None or end <= start:
        return []
    size = min(end - start, 256)
    data = candidate_bin.pe.get_data(start, size)
    if len(data) <= 0:
        return []
    return _semantic_disassemble_block(candidate_bin, BlockSide(start, start + len(data)), data)[:32]

def _audit_raw_instruction_needs_checked_contract(instruction: dict[str, Any]) -> bool:
    mnemonic = str(instruction.get("mnemonic") or "").lower()
    op_str = str(instruction.get("op_str") or "").lower()
    if mnemonic.startswith("call") or mnemonic.startswith("ret"):
        return True
    if mnemonic.startswith("jmp") and not re.match(r"^(0x[0-9a-f]+|[0-9]+)$", op_str.strip()):
        return True
    if mnemonic.startswith("j") and not re.match(r"^(0x[0-9a-f]+|[0-9]+)$", op_str.strip()):
        return True
    return False

def _audit_hex_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value:
        try:
            return int(value, 0)
        except ValueError:
            try:
                return int(value, 16)
            except ValueError:
                return None
    return None

def _audit_va_to_rva(binary: StageABinary, address: int) -> int:
    if binary.image_base <= address < binary.image_base + binary.size_of_image:
        return address - binary.image_base
    return address

def _audit_infer_target_name(contract: dict[str, Any]) -> str:
    for key in ("target_name", "target"):
        value = contract.get(key)
        if isinstance(value, str) and value:
            return value
    inputs = contract.get("inputs") if isinstance(contract.get("inputs"), dict) else {}
    original = inputs.get("original") if isinstance(inputs.get("original"), dict) else {}
    path_text = original.get("path")
    if isinstance(path_text, str) and path_text:
        stem = Path(path_text).stem.lower()
        for suffix in ("-original", "_original", ".original", "-reference", "_reference"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
        if stem and stem not in {"original", "candidate", "reference"}:
            return stem
    return ""

def _audit_dll_is_target_owned(dll: str, target_name: str) -> bool:
    aliases = _audit_target_library_aliases(target_name)
    name = Path(str(dll)).name.lower()
    for suffix in (".dll", ".drv", ".ocx"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    token = _audit_library_alias_token(name)
    for alias in aliases:
        if token in {alias, f"lib{alias}"}:
            return True
        if token.startswith(f"lib{alias}") or token.startswith(alias):
            return True
    return False

def _audit_target_library_aliases(target_name: str) -> set[str]:
    normalized = _audit_library_alias_token(target_name)
    aliases = {normalized, _audit_library_alias_token(target_name.replace("-", "")), _audit_library_alias_token(target_name.replace("_", ""))}
    if normalized in {"ripgrep", "rg"}:
        aliases.update({"ripgrep", "rg"})
    return {alias for alias in aliases if alias}

def _audit_library_alias_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).lower())

def _dedupe_audit_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        key = str(finding.get("id") or json.dumps(finding, sort_keys=True, default=str))
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result

def _rank_audit_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = sorted(
        findings,
        key=lambda item: (
            _audit_family_rank(str(item.get("family") or "")),
            -_gap_severity_rank(item.get("severity")),
            str(item.get("id") or ""),
        ),
    )
    for index, item in enumerate(ranked, start=1):
        item["rank"] = index
    return ranked

def _audit_families(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    by_family: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        by_family.setdefault(str(finding.get("family") or "unknown"), []).append(finding)
    for family, items in sorted(by_family.items(), key=lambda pair: _audit_family_rank(pair[0])):
        severity = "violated" if any(item.get("severity") == "violated" for item in items) else "incomplete"
        rows.append(
            {
                "family": family,
                "status": severity,
                "blocking": True,
                "counts": {"findings": len(items), "by_category": _count_by(items, "category")},
                "top_finding": items[0].get("id") if items else None,
            }
        )
    return rows

def _audit_family_rank(family: str) -> int:
    order = {
        "candidate_runtime_witness": 0,
        "raw_section_gap_accepted": 1,
        "target_owned_import_borrowed": 2,
        "abi_underconstrained": 3,
        "coverage_gap_masked": 4,
        "candidate_semantics_unresolved": 5,
        "external_environment_underspecified": 6,
    }
    return order.get(family, 99)

def _contract_candidate_families(
    contract: dict[str, Any],
    candidate: StageABinary,
    candidate_functions: list[dict[str, Any]],
    *,
    alias_evidence: dict[str, Any] | None = None,
    candidate_rva_anchors: dict[int, int] | None = None,
) -> list[dict[str, Any]]:
    alias_evidence = alias_evidence or _empty_contract_candidate_alias_evidence()
    original = contract.get("original") if isinstance(contract.get("original"), dict) else {}
    constraints = contract.get("constraints") if isinstance(contract.get("constraints"), dict) else {}
    contract_families = {str(item.get("family")): item for item in contract.get("families", []) if isinstance(item, dict)}
    candidate_function_names = _contract_candidate_function_names(candidate_functions)
    function_contract = constraints.get("function_ranges") if isinstance(constraints.get("function_ranges"), dict) else {}
    expected_functions = [
        item for item in function_contract.get("functions", []) if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]
    alias_matches = alias_evidence.get("matches_by_reference") if isinstance(alias_evidence.get("matches_by_reference"), dict) else {}
    alias_ambiguities = alias_evidence.get("ambiguities_by_reference") if isinstance(alias_evidence.get("ambiguities_by_reference"), dict) else {}
    missing_functions = sorted(
        str(item["name"])
        for item in expected_functions
        if str(item["name"]) not in candidate_function_names and str(item["name"]) not in alias_matches
        and str(item["name"]) not in alias_ambiguities
    )
    ambiguous_functions = sorted(str(item["name"]) for item in expected_functions if str(item["name"]) in alias_ambiguities)
    abi_contract = constraints.get("abi_callsites") if isinstance(constraints.get("abi_callsites"), dict) else {}
    candidate_abi = _candidate_abi_constraint_from_functions(
        candidate,
        candidate_functions,
        reference_abi=abi_contract,
        alias_evidence=alias_evidence,
        candidate_rva_anchors=candidate_rva_anchors,
    )
    abi_coverage_gaps = _contract_candidate_abi_coverage_gaps(abi_contract, candidate_abi, alias_evidence=alias_evidence)
    original_imports = _contract_import_signature(original)
    candidate_imports = _contract_import_signature(_binary_reference_layout(candidate))
    missing_function_details = _contract_candidate_missing_function_details(
        missing_functions,
        constraints=constraints,
        candidate_imports=candidate_imports,
        alias_evidence=alias_evidence,
    )
    alias_ambiguity_count = len(ambiguous_functions)
    function_ranges_status = "satisfied" if not missing_functions and not ambiguous_functions and expected_functions else "incomplete"
    abi_status = _contract_candidate_abi_status(abi_contract, candidate_abi)
    expected_binary_signature = _contract_binary_signature(original)
    candidate_binary_signature = _contract_binary_signature(_binary_reference_layout(candidate))
    if alias_ambiguity_count or int(abi_coverage_gaps["counts"].get("missing_functions") or 0) or int(
        abi_coverage_gaps["counts"].get("ambiguous_functions") or 0
    ) or int(
        abi_coverage_gaps["counts"].get("incomplete_callsite_functions") or 0
    ) or int(
        abi_coverage_gaps["counts"].get("function_mismatches") or 0
    ) or int(
        abi_coverage_gaps["counts"].get("callsite_mismatches") or 0
    ):
        abi_status = "incomplete"
    families = [
        _contract_candidate_family(
            "binary_faithfulness",
            "satisfied" if expected_binary_signature == candidate_binary_signature else "violated",
            "candidate PE layout/import/image-base target does not match the Stage A reference contract",
            "rebuild the candidate with matching PE target layout, imports, subsystem, and image base",
            contract_families.get("binary_faithfulness"),
            evidence={
                "expected": expected_binary_signature,
                "candidate": candidate_binary_signature,
                "layout_delta": _contract_binary_signature_delta(expected_binary_signature, candidate_binary_signature),
            },
        ),
        _contract_candidate_family(
            "function_ranges",
            function_ranges_status,
            "candidate linker map is missing or ambiguously maps reference-contract functions",
            "add/generate candidate functions, fix source-map aliases, or remove ambiguous linker roots",
            contract_families.get("function_ranges"),
            evidence={
                "expected_count": len(expected_functions),
                "candidate_count": len(candidate_functions),
                "missing_count": len(missing_functions),
                "ambiguous_count": alias_ambiguity_count,
                "missing_functions": missing_functions[:100],
                "missing_function_details": missing_function_details[:100],
                "missing_by_category": _count_by(missing_function_details, "category"),
                "ambiguous_aliases": [_contract_alias_ambiguity_sample(alias_ambiguities[name]) for name in ambiguous_functions[:100]],
                "alias_matches": _contract_alias_match_samples(alias_matches, expected_functions),
                "alias_evidence_status": alias_evidence.get("status"),
                "alias_evidence_counts": alias_evidence.get("counts"),
            },
        ),
        _contract_candidate_family(
            "abi_callsites",
            abi_status,
            "candidate ABI/callsite evidence does not yet cover the reference contract",
            "repair prototypes, sret/out-params, varargs bridges, stack deltas, or register preservation",
            contract_families.get("abi_callsites"),
            evidence={
                "reference_counts": abi_contract.get("counts") if isinstance(abi_contract.get("counts"), dict) else {},
                "candidate_counts": candidate_abi.get("counts"),
                "candidate_abi": candidate_abi,
                "coverage_gaps": abi_coverage_gaps,
                "alias_evidence": _contract_candidate_alias_evidence_summary(alias_evidence),
            },
        ),
        _contract_candidate_family(
            "import_thunks",
            "satisfied" if original_imports == candidate_imports else "incomplete",
            "candidate imports differ from the reference contract",
            "rebuild/link the candidate with matching import thunk/prototype surface",
            contract_families.get("import_thunks"),
            evidence={"expected_imports": original_imports, "candidate_imports": candidate_imports},
        ),
    ]
    return families

def _contract_candidate_family(
    family: str,
    status: str,
    blocker: str,
    next_action: str,
    contract_family: dict[str, Any] | None,
    *,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    contract_status = contract_family.get("status") if isinstance(contract_family, dict) else None
    if contract_status == "violated":
        status = "violated"
    elif contract_status == "incomplete" and status == "satisfied":
        status = "incomplete"
    return {
        "family": family,
        "status": status,
        "contract_status": contract_status,
        "blocker": "" if status in {"satisfied", "not_applicable"} else blocker,
        "next_action": "" if status in {"satisfied", "not_applicable"} else next_action,
        "evidence": evidence,
    }

def _contract_candidate_skeleton_alias_evidence(skeleton: dict[str, Any], candidate_functions: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(skeleton, dict) or skeleton.get("format") != "stage-b-skeleton-v1":
        raise StageAInputError("skeleton manifest must have format stage-b-skeleton-v1")
    source_map = skeleton.get("source_map") if isinstance(skeleton.get("source_map"), dict) else {}
    entries = source_map.get("functions") if isinstance(source_map.get("functions"), list) else []
    candidate_lookup = _contract_candidate_function_lookup(candidate_functions)
    unresolved: dict[str, list[dict[str, Any]]] = {}
    unmatched: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("function"), str):
            continue
        source_function = str(entry["function"])
        source_aliases = [
            alias
            for alias in entry.get("aliases", [])
            if isinstance(alias, str) and _contract_candidate_source_alias_is_function_name(alias)
        ]
        reference_names = _dedupe_strings(
            [
                name
                for name in [source_function, *source_aliases]
                if _contract_candidate_source_alias_is_function_name(name)
            ]
        )
        if not reference_names:
            continue
        candidate_matches = _contract_candidate_lookup_matches(candidate_lookup, *reference_names)
        if not candidate_matches:
            for name in reference_names:
                unmatched.setdefault(name, []).append(
                    _contract_candidate_source_alias_sample(entry, reference_name=name, source_aliases=source_aliases)
                )
            continue
        if len(candidate_matches) > 1:
            resolved = _contract_candidate_disambiguate_exact_source_match(candidate_matches, source_function)
            if resolved is not None:
                for name in reference_names:
                    unresolved.setdefault(name, []).append(
                        {
                            "reference_name": name,
                            "source_function": source_function,
                            "source_kind": entry.get("source_kind"),
                            "candidate": _contract_candidate_function_sample(resolved),
                            "source_aliases": source_aliases,
                            "resolution": "unique_exact_source_function",
                        }
                    )
                continue
            ambiguity = {
                "reference_names": reference_names,
                "source_function": source_function,
                "reason": "source function resolves to multiple candidate linker-map functions",
                "candidate_matches": [_contract_candidate_function_sample(item) for item in candidate_matches],
            }
            for name in reference_names:
                unresolved.setdefault(name, []).append(ambiguity)
            continue
        candidate_match = candidate_matches[0]
        for name in reference_names:
            unresolved.setdefault(name, []).append(
                {
                    "reference_name": name,
                    "source_function": source_function,
                    "source_kind": entry.get("source_kind"),
                    "candidate": _contract_candidate_function_sample(candidate_match),
                    "source_aliases": source_aliases,
                }
            )

    matches_by_reference: dict[str, dict[str, Any]] = {}
    ambiguities_by_reference: dict[str, list[dict[str, Any]]] = {}
    alias_matches: list[dict[str, Any]] = []
    ambiguities: list[dict[str, Any]] = []
    unmatched_by_reference: dict[str, list[dict[str, Any]]] = {}
    unmatched_aliases: list[dict[str, Any]] = []
    for reference_name, matches in sorted(unresolved.items()):
        unique = _unique_alias_matches(matches)
        if len(unique) == 1 and "candidate" in unique[0]:
            matches_by_reference[reference_name] = unique[0]
            alias_matches.append(unique[0])
        else:
            ambiguities_by_reference[reference_name] = unique
            ambiguities.append({"reference_name": reference_name, "matches": unique[:5], "matches_total": len(unique)})
    for reference_name, matches in sorted(unmatched.items()):
        if reference_name in matches_by_reference or reference_name in ambiguities_by_reference:
            continue
        unique = _unique_alias_matches(matches)
        unmatched_by_reference[reference_name] = unique
        unmatched_aliases.append({"reference_name": reference_name, "matches": unique[:5], "matches_total": len(unique)})

    return {
        "format": "stage-a-contract-candidate-alias-evidence-v1",
        "status": "incomplete" if ambiguities else "satisfied",
        "matches_by_reference": matches_by_reference,
        "ambiguities_by_reference": ambiguities_by_reference,
        "unmatched_by_reference": unmatched_by_reference,
        "alias_matches": alias_matches[:100],
        "ambiguities": ambiguities[:100],
        "unmatched_aliases": unmatched_aliases[:100],
        "counts": {"alias_matches": len(alias_matches), "ambiguities": len(ambiguities), "unmatched_aliases": len(unmatched_aliases)},
    }

def _contract_candidate_function_lookup(candidate_functions: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    lookup: dict[str, list[dict[str, Any]]] = {}
    for function in candidate_functions:
        if not isinstance(function, dict):
            continue
        for name in _contract_candidate_function_symbol_names(function):
            for key in _contract_candidate_symbol_keys(name):
                bucket = lookup.setdefault(key, [])
                if function not in bucket:
                    bucket.append(function)
    return lookup

def _contract_candidate_lookup_matches(lookup: dict[str, list[dict[str, Any]]], *source_names: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for source_name in source_names:
        for key in _contract_candidate_symbol_keys(source_name):
            for function in lookup.get(key, []):
                if function not in matches:
                    matches.append(function)
    return matches

def _contract_candidate_disambiguate_exact_source_match(
    candidate_matches: list[dict[str, Any]],
    source_function: str,
) -> dict[str, Any] | None:
    exact = [
        function
        for function in candidate_matches
        if source_function in _contract_candidate_function_symbol_names(function)
    ]
    return exact[0] if len(exact) == 1 else None

def _contract_candidate_function_names(candidate_functions: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for function in candidate_functions:
        for name in _contract_candidate_function_symbol_names(function):
            names.add(name)
    return names

def _contract_candidate_source_alias_is_function_name(name: str) -> bool:
    if not name:
        return False
    # COFF section symbols such as ".text" can appear in linker/source-map
    # alias lists for section-gap ranges. They are layout evidence, not
    # callable function names, and treating them as aliases creates false
    # ambiguities across every range in the section.
    return not name.startswith(".")

def _unique_alias_matches(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in matches:
        candidate = match.get("candidate") if isinstance(match.get("candidate"), dict) else {}
        key = json.dumps(
            {
                "reference_name": match.get("reference_name"),
                "source_function": match.get("source_function"),
                "candidate_name": candidate.get("name"),
                "candidate_rva_start": candidate.get("rva_start"),
                "candidate_rva_end": candidate.get("rva_end"),
                "reason": match.get("reason"),
                "source_kind": match.get("source_kind"),
                "source_aliases": match.get("source_aliases"),
                "rva_start": match.get("rva_start"),
                "rva_end": match.get("rva_end"),
                "file": match.get("file"),
                "line_start": match.get("line_start"),
            },
            sort_keys=True,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(match)
    return result

def _contract_candidate_source_alias_sample(
    entry: dict[str, Any],
    *,
    reference_name: str,
    source_aliases: list[str],
) -> dict[str, Any]:
    return {
        "reference_name": reference_name,
        "source_function": entry.get("function"),
        "source_kind": entry.get("source_kind"),
        "source_aliases": source_aliases,
        "rva_start": entry.get("rva_start"),
        "rva_end": entry.get("rva_end"),
        "file": entry.get("file"),
        "line_start": entry.get("line_start"),
        "line_end": entry.get("line_end"),
    }

def _contract_candidate_function_sample(function: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": function.get("name"),
        "aliases": [alias for alias in function.get("aliases", []) if isinstance(alias, str)] if isinstance(function.get("aliases"), list) else [],
        "rva_start": function.get("rva_start"),
        "rva_end": function.get("rva_end"),
        "section": function.get("section"),
    }

def _contract_alias_match_samples(alias_matches: dict[str, Any], expected_functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    expected_names = {str(item["name"]) for item in expected_functions if isinstance(item.get("name"), str)}
    result = []
    for reference_name in sorted(expected_names & set(alias_matches)):
        match = alias_matches[reference_name]
        if isinstance(match, dict):
            result.append(
                {
                    "reference_name": reference_name,
                    "source_function": match.get("source_function"),
                    "source_kind": match.get("source_kind"),
                    "candidate": match.get("candidate"),
                }
            )
    return result[:100]

def _contract_alias_ambiguity_sample(ambiguities: list[dict[str, Any]]) -> dict[str, Any]:
    return {"matches": ambiguities[:5], "matches_total": len(ambiguities)}

def _contract_candidate_alias_evidence_summary(alias_evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": alias_evidence.get("status"),
        "counts": alias_evidence.get("counts"),
        "alias_matches": alias_evidence.get("alias_matches", [])[:20] if isinstance(alias_evidence.get("alias_matches"), list) else [],
        "ambiguities": alias_evidence.get("ambiguities", [])[:20] if isinstance(alias_evidence.get("ambiguities"), list) else [],
        "unmatched_aliases": alias_evidence.get("unmatched_aliases", [])[:20]
        if isinstance(alias_evidence.get("unmatched_aliases"), list)
        else [],
    }

def _contract_candidate_missing_function_details(
    missing_functions: list[str],
    *,
    constraints: dict[str, Any],
    candidate_imports: list[dict[str, Any]],
    alias_evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    unmatched = alias_evidence.get("unmatched_by_reference") if isinstance(alias_evidence.get("unmatched_by_reference"), dict) else {}
    reference_import_thunks = _contract_reference_import_thunks_by_function(constraints)
    details: list[dict[str, Any]] = []
    for function_name in missing_functions:
        source_entries = unmatched.get(function_name) if isinstance(unmatched.get(function_name), list) else []
        source_evidence = source_entries[0] if source_entries and isinstance(source_entries[0], dict) else None
        import_thunk = reference_import_thunks.get(function_name)
        candidate_import_match = _contract_candidate_matching_import(import_thunk, candidate_imports)
        category = _contract_candidate_missing_function_category(
            function_name,
            source_evidence=source_evidence,
            reference_import_thunk=import_thunk,
            candidate_import_match=candidate_import_match,
        )
        item: dict[str, Any] = {
            "function": function_name,
            "category": category,
            "severity": "blocking",
            "next_action": _contract_candidate_missing_function_next_action(function_name, category),
        }
        if source_evidence is not None:
            item["source_evidence"] = source_evidence
        if import_thunk is not None:
            item["reference_import_thunk"] = import_thunk
        if candidate_import_match is not None:
            item["candidate_import_match"] = candidate_import_match
        details.append(item)
    return details

def _contract_reference_import_thunks_by_function(constraints: dict[str, Any]) -> dict[str, dict[str, Any]]:
    import_contract = constraints.get("import_thunks") if isinstance(constraints.get("import_thunks"), dict) else {}
    mapped = import_contract.get("mapped_import_thunks") if isinstance(import_contract.get("mapped_import_thunks"), list) else []
    result: dict[str, dict[str, Any]] = {}
    for item in mapped:
        if not isinstance(item, dict):
            continue
        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        function_name = source.get("function")
        if not isinstance(function_name, str) or not function_name:
            continue
        result.setdefault(
            function_name,
            {
                "id": item.get("id"),
                "function": function_name,
                "function_match_key": _linker_function_match_key(function_name),
                "source_kind": source.get("kind"),
                "import_signature": source.get("import_signature") if isinstance(source.get("import_signature"), dict) else None,
                "original": item.get("original") if isinstance(item.get("original"), dict) else None,
                "candidate": item.get("candidate") if isinstance(item.get("candidate"), dict) else None,
            },
        )
    return result

def _contract_candidate_matching_import(
    reference_import_thunk: dict[str, Any] | None,
    candidate_imports: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not isinstance(reference_import_thunk, dict):
        return None
    signature = reference_import_thunk.get("import_signature")
    if not isinstance(signature, dict):
        return None
    for imported in candidate_imports:
        if not isinstance(imported, dict):
            continue
        if _contract_import_signature_dict_key(imported) == _contract_import_signature_dict_key(signature):
            return imported
    return None

def _contract_import_signature_dict_key(imported: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(imported.get("dll") or "").lower(),
        str(imported.get("symbol") or ""),
        str(imported.get("ordinal") or ""),
    )

def _contract_candidate_missing_function_category(
    function_name: str,
    *,
    source_evidence: dict[str, Any] | None,
    reference_import_thunk: dict[str, Any] | None,
    candidate_import_match: dict[str, Any] | None,
) -> str:
    source_kind = source_evidence.get("source_kind") if isinstance(source_evidence, dict) else None
    if source_kind == "omitted_import_thunk" or reference_import_thunk is not None:
        if candidate_import_match is not None:
            return "import_thunk_symbol_missing_with_matching_import"
        return "import_thunk_symbol_missing"
    if source_kind == "omitted_runtime_entry":
        return "runtime_entry_replaced_by_generated_bridge"
    if source_kind == "generated_contract_placeholder":
        return "generated_contract_placeholder_missing"
    if function_name.startswith("section-gap-"):
        return "section_gap_or_padding_missing"
    if source_evidence is not None:
        return "source_map_alias_unresolved"
    return "function_missing"

def _contract_candidate_missing_function_next_action(function_name: str, category: str) -> str:
    if category == "import_thunk_symbol_missing_with_matching_import":
        return (
            f"preserve the original import thunk symbol for {function_name} or add a strict Stage A import-thunk "
            "representation mapping that proves the matching candidate import is equivalent"
        )
    if category == "import_thunk_symbol_missing":
        return f"restore or map the import thunk for {function_name} and ensure the candidate imports the same target"
    if category == "runtime_entry_replaced_by_generated_bridge":
        return f"emit or retain the runtime/CRT entry/support function {function_name}, or prove the generated bridge is equivalent"
    if category == "generated_contract_placeholder_missing":
        return f"replace or root the generated contract placeholder for {function_name} before rerunning Stage A"
    if category == "section_gap_or_padding_missing":
        return f"classify and preserve the executable section span represented by {function_name}"
    if category == "source_map_alias_unresolved":
        return f"root the generated source-map alias for {function_name} so the candidate linker map exposes it"
    return f"generate or retain candidate implementation and linker root for {function_name}"

def _contract_binary_signature(layout: dict[str, Any]) -> dict[str, Any]:
    return {
        "machine": layout.get("machine"),
        "bitness": layout.get("bitness"),
        "subsystem": layout.get("subsystem"),
        "image_base": layout.get("image_base"),
        "entrypoint_rva": layout.get("entrypoint_rva"),
        "sections": _contract_section_signature(layout),
        "imports": _contract_import_signature(layout),
    }

def _contract_binary_signature_delta(expected: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    header: dict[str, dict[str, Any]] = {}
    for key in ("machine", "bitness", "subsystem", "image_base", "entrypoint_rva"):
        if expected.get(key) != candidate.get(key):
            header[key] = {"expected": expected.get(key), "observed": candidate.get(key)}
    return {
        "header": header,
        "sections": _contract_section_signature_delta(
            expected.get("sections") if isinstance(expected.get("sections"), list) else [],
            candidate.get("sections") if isinstance(candidate.get("sections"), list) else [],
        ),
        "imports": _contract_import_signature_delta(
            expected.get("imports") if isinstance(expected.get("imports"), list) else [],
            candidate.get("imports") if isinstance(candidate.get("imports"), list) else [],
        ),
    }

def _contract_section_signature_delta(expected: list[dict[str, Any]], candidate: list[dict[str, Any]]) -> list[dict[str, Any]]:
    expected_by_name = {str(item.get("name") or ""): item for item in expected if isinstance(item, dict)}
    candidate_by_name = {str(item.get("name") or ""): item for item in candidate if isinstance(item, dict)}
    deltas: list[dict[str, Any]] = []
    for name in sorted(set(expected_by_name) | set(candidate_by_name)):
        expected_section = expected_by_name.get(name)
        candidate_section = candidate_by_name.get(name)
        if expected_section is None:
            deltas.append({"name": name, "status": "extra", "candidate": candidate_section})
            continue
        if candidate_section is None:
            deltas.append({"name": name, "status": "missing", "expected": expected_section})
            continue
        fields: dict[str, dict[str, Any]] = {}
        for key in ("rva_start", "rva_end", "executable", "readable", "writable"):
            if expected_section.get(key) != candidate_section.get(key):
                fields[key] = {"expected": expected_section.get(key), "observed": candidate_section.get(key)}
        expected_size = (_safe_int(expected_section.get("rva_end")) or 0) - (_safe_int(expected_section.get("rva_start")) or 0)
        candidate_size = (_safe_int(candidate_section.get("rva_end")) or 0) - (_safe_int(candidate_section.get("rva_start")) or 0)
        if expected_size != candidate_size:
            fields["size"] = {"expected": expected_size, "observed": candidate_size, "delta": candidate_size - expected_size}
        if fields:
            deltas.append({"name": name, "status": "changed", "delta": fields})
    return deltas

def _contract_import_signature_delta(expected: list[dict[str, Any]], candidate: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    expected_keys = {_contract_import_delta_key(item): item for item in expected if isinstance(item, dict)}
    candidate_keys = {_contract_import_delta_key(item): item for item in candidate if isinstance(item, dict)}
    return {
        "missing": [expected_keys[key] for key in sorted(set(expected_keys) - set(candidate_keys))],
        "extra": [candidate_keys[key] for key in sorted(set(candidate_keys) - set(expected_keys))],
    }

def _contract_import_delta_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (str(item.get("dll") or ""), str(item.get("symbol") or ""), str(item.get("ordinal") or ""))

def _contract_section_signature(layout: dict[str, Any]) -> list[dict[str, Any]]:
    sections = layout.get("sections") if isinstance(layout.get("sections"), list) else []
    result = []
    for item in sections:
        if not isinstance(item, dict):
            continue
        permissions = item.get("permissions") if isinstance(item.get("permissions"), dict) else {}
        result.append(
            {
                "name": item.get("name"),
                "rva_start": item.get("rva_start"),
                "rva_end": item.get("rva_end"),
                "executable": item.get("executable", permissions.get("execute")),
                "readable": item.get("readable", permissions.get("read")),
                "writable": item.get("writable", permissions.get("write")),
            }
        )
    return result

def _contract_import_signature(layout: dict[str, Any]) -> list[dict[str, Any]]:
    imports = layout.get("imports") if isinstance(layout.get("imports"), list) else []
    result = []
    for item in imports:
        if isinstance(item, dict):
            result.append({"dll": item.get("dll"), "symbol": item.get("symbol"), "ordinal": item.get("ordinal")})
        elif isinstance(item, (list, tuple)) and len(item) >= 3:
            result.append({"dll": item[0], "symbol": item[1], "ordinal": item[2]})
    return sorted(result, key=lambda value: (str(value.get("dll")), str(value.get("symbol")), str(value.get("ordinal"))))

def _parse_stage_b_contract_rva_anchors(path: Path, binary: StageABinary) -> dict[int, int]:
    anchors: dict[int, int] = {}
    ambiguous: set[int] = set()
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        parsed = _parse_linker_map_symbol_line(line, binary)
        if parsed is None:
            continue
        candidate_rva, name = parsed
        reference_rva = _stage_b_contract_rva_anchor_reference(name)
        if reference_rva is None:
            continue
        section = _section_for_rva(binary, candidate_rva)
        if section is None or not section.executable:
            continue
        previous = anchors.get(reference_rva)
        if previous is not None and previous != candidate_rva:
            ambiguous.add(reference_rva)
            continue
        anchors[reference_rva] = candidate_rva
    for reference_rva in ambiguous:
        anchors.pop(reference_rva, None)
    return anchors

def _stage_b_contract_rva_anchor_reference(name: str) -> int | None:
    stripped = name.lstrip("_")
    match = re.fullmatch(r"stage_b_contract_rva_([0-9a-fA-F]{8})", stripped)
    if match is None:
        return None
    return int(match.group(1), 16)

__all__ = [
    '_audit_alias_shortfall_findings',
    '_audit_candidate_crash_finding',
    '_audit_candidate_function_for_rva',
    '_audit_candidate_function_for_source_entry',
    '_audit_coverage_gap_mask_findings',
    '_audit_dll_is_target_owned',
    '_audit_explicit_unit_sidecar_exists',
    '_audit_families',
    '_audit_family_rank',
    '_audit_finding',
    '_audit_function_instruction_sample',
    '_audit_hex_int',
    '_audit_infer_target_name',
    '_audit_library_alias_token',
    '_audit_raw_instruction_needs_checked_contract',
    '_audit_raw_section_gap_findings',
    '_audit_source_entry_for_rva',
    '_audit_source_entry_is_raw_section_gap',
    '_audit_source_entry_sample',
    '_audit_source_map_entries',
    '_audit_target_library_aliases',
    '_audit_target_owned_import_findings',
    '_audit_unit_contract_shortfall_findings',
    '_audit_va_to_rva',
    '_audit_validation_shortfall_findings',
    '_contract_alias_ambiguity_sample',
    '_contract_alias_match_samples',
    '_contract_binary_signature',
    '_contract_binary_signature_delta',
    '_contract_candidate_alias_evidence_summary',
    '_contract_candidate_disambiguate_exact_source_match',
    '_contract_candidate_families',
    '_contract_candidate_family',
    '_contract_candidate_function_lookup',
    '_contract_candidate_function_names',
    '_contract_candidate_function_sample',
    '_contract_candidate_lookup_matches',
    '_contract_candidate_matching_import',
    '_contract_candidate_missing_function_category',
    '_contract_candidate_missing_function_details',
    '_contract_candidate_missing_function_next_action',
    '_contract_candidate_shortfall_family',
    '_contract_candidate_skeleton_alias_evidence',
    '_contract_candidate_source_alias_is_function_name',
    '_contract_candidate_source_alias_sample',
    '_contract_import_delta_key',
    '_contract_import_signature',
    '_contract_import_signature_delta',
    '_contract_import_signature_dict_key',
    '_contract_reference_import_thunks_by_function',
    '_contract_section_signature',
    '_contract_section_signature_delta',
    '_dedupe_audit_findings',
    '_parse_stage_b_contract_rva_anchors',
    '_rank_audit_findings',
    '_stage_a_contract_shortfall_audit',
    '_stage_b_contract_rva_anchor_reference',
    '_unique_alias_matches',
    'stage_b_audit_contract',
    'stage_b_check_contract',
    'stage_b_check_unit',
    'stage_b_contract_coverage',
    'stage_b_extract_work_items',
]
