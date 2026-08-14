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

from .candidate_comparison import (
    _contract_candidate_alias_evidence_summary,
    _contract_candidate_disambiguate_exact_source_match,
    _contract_candidate_family,
    _contract_candidate_function_lookup,
    _contract_candidate_function_sample,
    _contract_candidate_lookup_matches,
    _contract_import_signature,
)

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
    '_contract_candidate_shortfall_family',
    '_dedupe_audit_findings',
    '_rank_audit_findings',
    '_stage_a_contract_shortfall_audit',
]
