"""Resolve physical ABI constraints at exact target/library match boundaries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..artifacts.formats import ABI_MATCH_RESOLUTION_FORMAT
from ..libraries.v4_release_set import read_library_release_set_v4
from ..libraries.signature_graph import TARGET_SIGNATURE_GRAPH_CODEC_V3
from .catalog import PhysicalAbiCatalogV1
from .compatibility import compare_physical_abis
from .extraction import AbiExtractionResultV1
from .legacy import physical_profile_from_library_v3
from .model import AbiEvidenceV1, AbiFactV1, canonical_json_bytes, canonical_sha256
from .solver import (
    PHYSICAL_PROFILE_FIELDS,
    AbiEqualityConstraintV1,
    facts_from_profile,
    solve_abi_constraints,
)


def _match_evidence(
    *, match_id: str, target_unit_ids: Iterable[str], catalog_function_id: str
) -> AbiEvidenceV1:
    return AbiEvidenceV1.create(
        kind="exact_library_function_match",
        producer="libraries.release_hypotheses_v4",
        subject_kind="library_member",
        subject_id=catalog_function_id,
        dependencies=(match_id,),
        payload={
            "match_id": match_id,
            "target_unit_ids": sorted(set(target_unit_ids)),
            "catalog_function_id": catalog_function_id,
        },
    )


_REGION_SAFE_FIELDS = frozenset(
    {
        "calling_convention",
        "stack_alignment_bytes",
        "stack_cleanup",
        "stack_coordinate",
        "target",
    }
)


def _region_machine_facts(
    extraction: AbiExtractionResultV1,
    *,
    region_id: str,
    unit_ids: set[str],
) -> tuple[AbiFactV1, ...]:
    """Project only whole-boundary-safe unit observations onto a function span.

    Library matches commonly contain several basic machine units.  Unit-local
    register preservation and stack accesses are not whole-function facts and
    must not be promoted merely because a unit lies inside the matched span.
    Return cleanup and target/stack-coordinate facts are safe constraints and
    are intersected across all observed returns.
    """

    return tuple(
        AbiFactV1.create(
            subject_id=region_id,
            field=row.field,
            status=row.status,
            values=row.values,
            evidence_ids=row.evidence_ids,
            dependency_ids=row.dependency_ids,
        )
        for row in extraction.facts
        if row.subject_id in unit_ids and row.field in _REGION_SAFE_FIELDS
    )


def _callsite_constraints_for_region(
    extraction: AbiExtractionResultV1,
    *,
    region_id: str,
    unit_ids: set[str],
) -> tuple[dict[str, str], tuple[AbiFactV1, ...], tuple[AbiEqualityConstraintV1, ...]]:
    subjects: dict[str, str] = {}
    facts: list[AbiFactV1] = []
    equalities: list[AbiEqualityConstraintV1] = []
    for equality in extraction.equalities:
        callsite_id = None
        if equality.right_subject_id in unit_ids:
            callsite_id = equality.left_subject_id
            callsite_field = equality.left_field
            region_field = equality.right_field
        elif equality.left_subject_id in unit_ids:
            callsite_id = equality.right_subject_id
            callsite_field = equality.right_field
            region_field = equality.left_field
        if callsite_id is None or extraction.subjects.get(callsite_id) != "callsite":
            continue
        equalities.append(
            AbiEqualityConstraintV1(
                callsite_id,
                callsite_field,
                region_id,
                region_field,
                equality.evidence_ids,
            )
        )
    candidate_ids = {
        equality.left_subject_id
        for equality in equalities
        if extraction.subjects.get(equality.left_subject_id) == "callsite"
    }
    for row in extraction.facts:
        if row.subject_id in candidate_ids:
            subjects[row.subject_id] = "callsite"
            facts.append(row)
    selected_equalities = tuple(
        equality
        for equality in sorted(set(equalities))
        if equality.left_subject_id in subjects
    )
    return subjects, tuple(facts), selected_equalities


def _binding_issue(
    issue: Mapping[str, Any],
    *,
    match_id: str,
    target_function_id: str,
    catalog_function_id: str,
    symbols: Sequence[str],
    undecorated_symbol: object,
) -> dict[str, Any]:
    """Attach the human-facing match context without replacing exact IDs."""

    return {
        **issue,
        "match_id": match_id,
        "target_function_id": target_function_id,
        "catalog_function_id": catalog_function_id,
        "catalog_symbols": list(symbols),
        "catalog_undecorated_symbol": undecorated_symbol,
    }


def resolve_library_match_abis(
    *,
    target_abi_evidence: Path | str,
    physical_abi_catalogs: Sequence[Path | str],
    release_hypotheses: Path | str,
    out: Path | str,
    target_signature_graph: Path | str | None = None,
) -> dict[str, Any]:
    extraction = AbiExtractionResultV1.read(target_abi_evidence)
    catalogs = tuple(PhysicalAbiCatalogV1.read(path) for path in physical_abi_catalogs)
    target_graph = (
        None
        if target_signature_graph is None
        else TARGET_SIGNATURE_GRAPH_CODEC_V3.read(target_signature_graph)
    )
    target_functions = (
        {}
        if target_graph is None
        else {row.function_id: row for row in target_graph.functions}
    )
    target_functions_by_units = (
        {}
        if target_graph is None
        else {
            tuple(sorted(row.unit_ids)): row
            for row in target_graph.functions
        }
    )
    catalog_facts: dict[str, tuple[AbiFactV1, ...]] = {}
    function_catalog: dict[str, str] = {}
    function_metadata: dict[str, Mapping[str, Any]] = {}
    for catalog in catalogs:
        for function in catalog.function_subjects:
            function_id = str(function.get("function_id", ""))
            if not function_id:
                raise ValueError("physical ABI catalog function lacks an identity")
            previous = function_catalog.get(function_id)
            if previous is not None and previous != catalog.catalog_id:
                raise ValueError("physical ABI function identity appears in two catalogs")
            function_catalog[function_id] = catalog.catalog_id
            function_metadata[function_id] = function
        grouped: dict[str, list[AbiFactV1]] = {}
        for fact in catalog.facts:
            grouped.setdefault(fact.subject_id, []).append(fact)
        for function_id, rows in grouped.items():
            if function_id in catalog_facts:
                raise ValueError("physical ABI facts duplicate a function identity")
            catalog_facts[function_id] = tuple(rows)

    bindings: list[dict[str, Any]] = []
    issues: list[Mapping[str, Any]] = []
    seen_matches: set[str] = set()
    for release in read_library_release_set_v4(release_hypotheses):
        for island in release.islands:
            for match in island.matches:
                if match.match_id in seen_matches:
                    continue
                seen_matches.add(match.match_id)
                unit_ids = set(match.target_unit_ids)
                region_id = match.target_function_id
                catalog_function_id = match.catalog_function_id
                catalog_id = function_catalog.get(catalog_function_id)
                metadata = function_metadata.get(catalog_function_id, {})
                symbols = tuple(
                    str(symbol) for symbol in metadata.get("symbols", ())
                )
                undecorated_symbol = metadata.get("undecorated_symbol")
                evidence = _match_evidence(
                    match_id=match.match_id,
                    target_unit_ids=unit_ids,
                    catalog_function_id=catalog_function_id,
                )
                if catalog_id is None:
                    issue = {
                        "status": "incomplete",
                        "code": "physical_abi_catalog_function_missing",
                        "match_id": match.match_id,
                        "catalog_function_id": catalog_function_id,
                    }
                    issues.append(issue)
                    bindings.append(
                        {
                            "match_id": match.match_id,
                            "target_function_id": region_id,
                            "target_unit_ids": sorted(unit_ids),
                            "catalog_function_id": catalog_function_id,
                            "catalog_symbols": list(symbols),
                            "catalog_undecorated_symbol": undecorated_symbol,
                            "status": "incomplete",
                            "profile": None,
                            "compatibility": None,
                            "certificate_ids": [],
                            "issues": [issue],
                        }
                    )
                    continue
                callsite_subjects, callsite_facts, callsite_equalities = (
                    _callsite_constraints_for_region(
                        extraction,
                        region_id=region_id,
                        unit_ids=unit_ids,
                    )
                )
                subjects = {region_id: "function", **callsite_subjects}
                subjects[catalog_function_id] = "library_member"
                equalities = list(callsite_equalities)
                for field in PHYSICAL_PROFILE_FIELDS:
                    equalities.append(
                        AbiEqualityConstraintV1(
                            region_id,
                            field,
                            catalog_function_id,
                            field,
                            (evidence.evidence_id,),
                        )
                    )
                target_function = target_functions.get(region_id)
                if target_function is None:
                    target_function = target_functions_by_units.get(
                        tuple(sorted(unit_ids))
                    )
                target_profile_facts: tuple[AbiFactV1, ...] = ()
                if target_function is not None and target_function.abi_profile is not None:
                    target_profile = physical_profile_from_library_v3(
                        target_function.abi_profile
                    )
                    target_profile_evidence = AbiEvidenceV1.create(
                        kind="machine_ir_function_abi_envelope",
                        producer="libraries.target_signature_graph_v3",
                        subject_kind="function",
                        subject_id=region_id,
                        binary_sha256=(
                            None if target_graph is None else target_graph.binary_sha256
                        ),
                        dependencies=(
                            evidence.evidence_id,
                            *(
                                ()
                                if target_graph is None
                                else (
                                    target_graph.graph_sha256,
                                    target_graph.machine_ir_sha256,
                                )
                            ),
                        ),
                        payload={
                            "target_function_id": region_id,
                            "profile_id": target_profile.profile_id,
                            "unit_ids": sorted(unit_ids),
                        },
                    )
                    target_profile_facts = facts_from_profile(
                        subject_id=region_id,
                        profile=target_profile,
                        evidence_ids=(target_profile_evidence.evidence_id,),
                        dependency_ids=(
                            target_graph.graph_sha256,
                            target_graph.machine_ir_sha256,
                        ),
                    )
                facts = (
                    *_region_machine_facts(
                        extraction,
                        region_id=region_id,
                        unit_ids=unit_ids,
                    ),
                    *target_profile_facts,
                    *callsite_facts,
                    *catalog_facts.get(catalog_function_id, ()),
                )
                solved = solve_abi_constraints(
                    subjects=subjects,
                    facts=facts,
                    equalities=equalities,
                )
                complete_profiles = {
                    row.profile.profile_id: row.profile
                    for row in solved.certificates
                    if row.profile is not None
                }
                profile = (
                    next(iter(complete_profiles.values()))
                    if solved.status == "complete" and len(complete_profiles) == 1
                    else None
                )
                certificate_by_subject = {
                    row.subject_id: row for row in solved.certificates
                }
                target_certificate = certificate_by_subject.get(region_id)
                catalog_certificate = certificate_by_subject.get(
                    catalog_function_id
                )
                compatibility = (
                    compare_physical_abis(
                        target_certificate.profile,
                        catalog_certificate.profile,
                    )
                    if target_certificate is not None
                    and target_certificate.profile is not None
                    and catalog_certificate is not None
                    and catalog_certificate.profile is not None
                    else None
                )
                binding_issues = [
                    _binding_issue(
                        row,
                        match_id=match.match_id,
                        target_function_id=region_id,
                        catalog_function_id=catalog_function_id,
                        symbols=symbols,
                        undecorated_symbol=undecorated_symbol,
                    )
                    for row in solved.issues
                ]
                binding_issues.extend(
                    _binding_issue(
                        row,
                        match_id=match.match_id,
                        target_function_id=region_id,
                        catalog_function_id=catalog_function_id,
                        symbols=symbols,
                        undecorated_symbol=undecorated_symbol,
                    )
                    for row in extraction.issues
                    if row.get("subject_id") in unit_ids
                )
                if solved.status == "complete" and profile is None:
                    binding_issues.append(
                        {
                            "status": "violated",
                            "code": "abi_match_profiles_disagree",
                            "match_id": match.match_id,
                        }
                    )
                if compatibility is not None and compatibility.status != "complete":
                    binding_issues.extend(
                        _binding_issue(
                            row.to_payload(),
                            match_id=match.match_id,
                            target_function_id=region_id,
                            catalog_function_id=catalog_function_id,
                            symbols=symbols,
                            undecorated_symbol=undecorated_symbol,
                        )
                        for row in compatibility.issues
                    )
                binding_status = (
                    "violated"
                    if solved.status == "violated" or any(
                        row.get("status") == "violated" for row in binding_issues
                    )
                    else "complete"
                    if profile is not None
                    and not any(
                        row.get("status") == "incomplete"
                        for row in binding_issues
                    )
                    else "incomplete"
                )
                issues.extend(binding_issues)
                bindings.append(
                    {
                        "match_id": match.match_id,
                        "target_function_id": region_id,
                        "target_unit_ids": sorted(unit_ids),
                        "catalog_id": catalog_id,
                        "catalog_function_id": catalog_function_id,
                        "catalog_symbols": list(symbols),
                        "catalog_undecorated_symbol": undecorated_symbol,
                        "status": binding_status,
                        "profile": None if profile is None else profile.to_payload(),
                        "compatibility": (
                            None
                            if compatibility is None
                            else compatibility.to_payload()
                        ),
                        "portable_prototype": function_metadata[
                            catalog_function_id
                        ].get("portable_prototype"),
                        "boundary_effects": function_metadata[
                            catalog_function_id
                        ].get("boundary_effects"),
                        "certificate_ids": sorted(
                            row.certificate_id for row in solved.certificates
                        ),
                        "facts_sha256": solved.facts_sha256,
                        "constraint_sha256": solved.constraint_sha256,
                        "issues": binding_issues,
                    }
                )
    status = (
        "violated"
        if any(row["status"] == "violated" for row in bindings)
        else "incomplete"
        if any(row["status"] == "incomplete" for row in bindings)
        else "complete"
    )
    core = {
        "format": ABI_MATCH_RESOLUTION_FORMAT,
        "status": status,
        "target_abi_evidence_sha256": canonical_sha256(
            extraction.to_payload()
        ),
        "target_signature_graph_sha256": (
            None if target_graph is None else target_graph.graph_sha256
        ),
        "catalog_bindings": [
            {
                "catalog_id": catalog.catalog_id,
                "catalog_sha256": catalog.catalog_sha256,
                "source_index_sha256": catalog.source_index_sha256,
                "decoration_model": catalog.decoration_model,
                "declaration_set_sha256": catalog.declaration_set_sha256,
            }
            for catalog in sorted(catalogs, key=lambda row: row.catalog_id)
        ],
        "bindings": sorted(bindings, key=lambda row: str(row["match_id"])),
        "issues": sorted(
            issues,
            key=lambda row: (
                str(row.get("status")),
                str(row.get("subject_id", row.get("match_id", ""))),
                str(row.get("field", row.get("code", ""))),
            ),
        ),
    }
    result = {**core, "resolution_sha256": canonical_sha256(core)}
    destination = Path(out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(canonical_json_bytes(result) + b"\n")
    return result


def read_abi_match_resolution(path: Path | str) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("ABI match resolution must be an object")
    core = dict(payload)
    observed = core.pop("resolution_sha256", None)
    if core.get("format") != ABI_MATCH_RESOLUTION_FORMAT:
        raise ValueError("ABI match resolution format is unsupported")
    if observed != canonical_sha256(core):
        raise ValueError("ABI match resolution hash is stale")
    if not isinstance(core.get("bindings"), list):
        raise ValueError("ABI match resolution bindings must be an array")
    return payload


def complete_profiles_by_catalog_function(
    resolution: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for row in resolution.get("bindings", []):
        if not isinstance(row, Mapping) or row.get("status") != "complete":
            continue
        function_id = row.get("catalog_function_id")
        profile = row.get("profile")
        if not isinstance(function_id, str) or not isinstance(profile, Mapping):
            raise ValueError("complete ABI match binding is malformed")
        previous = result.get(function_id)
        if previous is not None and previous != profile:
            raise ValueError("catalog function has contradictory complete ABI profiles")
        result[function_id] = profile
    return result


__all__ = [
    "complete_profiles_by_catalog_function",
    "read_abi_match_resolution",
    "resolve_library_match_abis",
]
