"""Fail-closed activation of one recognized library island.

Identity matching is proposal evidence.  This checker is the authority boundary:
it rebinds an operator intent to the exact island, checks every structural
crossing, consumes canonical external-site and indirect-target authority, and
requires one qualified reusable implementation covering every operation.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..artifacts.formats import (
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
)
from ..artifacts.io import open_artifact_reader_v3
from ..authority.target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
    INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
    IndirectTargetCertificateV3,
)
from ..external.site_authority import read_canonical_external_sites
from ..abi.matching import read_abi_match_resolution
from .abi_catalog import CATALOG_SEARCH_INDEX_CODEC_V3, CatalogSearchIndexV3
from .matching_support import load_machine_package
from .v4_adoption_records import (
    CHECKED_LIBRARY_ISLAND_CODEC_V1,
    LIBRARY_ADOPTION_INTENT_CODEC_V1,
    REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1,
    CheckedLibraryIslandV1,
    LibraryAdoptionIntentV1,
    ReusableLibraryImplementationV1,
)
from .v4_behavior_manifest import read_library_behavior_pack_declaration
from .v4_identity_records import (
    LibraryIslandIssueV4,
)
from .v4_record_support import stable_id
from .v4_release_set import select_library_island_v1


_CHECKER_ID = "checked-library-island-v1"


def _issue(
    family: str,
    status: str,
    code: str,
    message: str,
    location: str,
) -> LibraryIslandIssueV4:
    return LibraryIslandIssueV4.create(
        family=family,
        status=status,
        code=code,
        message=message,
        location=location,
    )


def _abi_id(payload: Mapping[str, Any]) -> str | None:
    direct = payload.get("abi_profile_id")
    if isinstance(direct, str) and direct:
        return direct
    contract = payload.get("machine_contract")
    if isinstance(contract, Mapping):
        template = contract.get("abi_template")
        if isinstance(template, str) and template:
            return template
    envelope = payload.get("abi_envelope")
    if isinstance(envelope, Mapping):
        identity = envelope.get("id")
        if isinstance(identity, str) and identity:
            return identity
    return None


def _edge_id(
    *, kind: str, direction: str, source: str, target: str, abi_id: str | None
) -> str:
    return stable_id(
        "library-boundary-edge-v4",
        {
            "kind": kind,
            "direction": direction,
            "source": source,
            "target": target,
            "abi_profile_id": abi_id,
        },
    )


def _direct_crossings(
    machine: Any, island_ids: set[str]
) -> tuple[tuple[str, str, str, str, str, str | None], ...]:
    starts = {unit.start: unit for unit in machine.units}
    edges: dict[str, tuple[str, str, str, str | None]] = {}
    for unit in machine.units:
        control = unit.payload.get("control")
        if not isinstance(control, Mapping):
            continue
        targets = control.get("direct_targets")
        if not isinstance(targets, list):
            continue
        source_inside = unit.identity in island_ids
        kind_value = control.get("kind")
        kind = "call" if isinstance(kind_value, str) and "call" in kind_value else "control"
        abi_id = _abi_id(control) if kind == "call" else None
        for target in targets:
            if isinstance(target, bool) or not isinstance(target, int):
                continue
            destination = starts.get(target)
            destination_inside = destination is not None and destination.identity in island_ids
            if source_inside == destination_inside:
                continue
            direction = "outbound" if source_inside else "inbound"
            destination_id = (
                destination.identity if destination is not None else f"rva:{target:08x}"
            )
            edge = _edge_id(
                kind=kind,
                direction=direction,
                source=unit.identity,
                target=destination_id,
                abi_id=abi_id,
            )
            edges[edge] = (kind, direction, unit.identity, destination_id, abi_id)
    return tuple(
        (edge_id, kind, direction, source, target, abi_id)
        for edge_id, (kind, direction, source, target, abi_id) in sorted(edges.items())
    )


def _external_sites(
    root: Path | str,
) -> tuple[dict[str, tuple[Any, ...]], str]:
    reader = open_artifact_reader_v3(root)
    if reader.manifest.artifact_kind != CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3:
        raise ValueError("library boundary requires canonical-external-sites-v3")
    by_unit: dict[str, list[Any]] = defaultdict(list)
    for site in read_canonical_external_sites(root).values():
        by_unit[site.unit_id].append(site)
    return (
        {
            unit_id: tuple(sorted(rows, key=lambda item: item.site_id))
            for unit_id, rows in by_unit.items()
        },
        reader.manifest_sha256,
    )


def _target_certificates(
    root: Path | str,
) -> tuple[dict[str, tuple[IndirectTargetCertificateV3, ...]], str]:
    reader = open_artifact_reader_v3(root)
    if reader.manifest.artifact_kind != INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3:
        raise ValueError("library boundary requires indirect-target-certificates-v3")
    result = {}
    for record in reader.iter_records():
        unit = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(record).value
        result[unit.source_unit_id] = unit.certificates
    return result, reader.manifest_sha256


def _external_event_count(unit: Any) -> int:
    semantics = unit.payload.get("semantics")
    events = semantics.get("external_events") if isinstance(semantics, Mapping) else None
    return len(events) if isinstance(events, list) else 0


def check_library_island_v1(
    *,
    target_id: str,
    machine_ir: Path | str,
    release_hypotheses: Path | str,
    island_id: str,
    adoption_intent: LibraryAdoptionIntentV1 | Path | str,
    implementation: ReusableLibraryImplementationV1 | Path | str,
    catalog_search_index: CatalogSearchIndexV3 | Path | str,
    canonical_external_sites: Path | str,
    target_certificates: Path | str,
    out: Path | str,
    abi_match_resolution: Path | str | None = None,
) -> CheckedLibraryIslandV1:
    """Check one adoption without executing either the target or candidate."""

    release, island = select_library_island_v1(release_hypotheses, island_id)
    intent = (
        adoption_intent
        if isinstance(adoption_intent, LibraryAdoptionIntentV1)
        else LIBRARY_ADOPTION_INTENT_CODEC_V1.read(adoption_intent)
    )
    implementation_pack_sha256: str | None = None
    if isinstance(implementation, ReusableLibraryImplementationV1):
        checked_implementation = implementation
    elif Path(implementation).is_dir():
        behavior_pack = read_library_behavior_pack_declaration(implementation)
        checked_implementation = behavior_pack.implementation
        implementation_pack_sha256 = behavior_pack.pack_sha256
    else:
        checked_implementation = REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.read(
            implementation
        )
    catalog = (
        catalog_search_index
        if isinstance(catalog_search_index, CatalogSearchIndexV3)
        else CATALOG_SEARCH_INDEX_CODEC_V3.read(catalog_search_index)
    )
    abi_resolution = (
        None
        if abi_match_resolution is None
        else read_abi_match_resolution(abi_match_resolution)
    )
    abi_bindings = {
        str(row.get("match_id")): row
        for row in (() if abi_resolution is None else abi_resolution["bindings"])
        if isinstance(row, Mapping)
    }
    machine = load_machine_package(Path(machine_ir))
    sites_by_unit, external_manifest_sha256 = _external_sites(canonical_external_sites)
    certificates_by_unit, target_manifest_sha256 = _target_certificates(target_certificates)
    issues = [issue for issue in island.issues if issue.family == "identity"]

    if intent.target_id != target_id or island.target_id != target_id:
        issues.append(
            _issue(
                "identity",
                "violated",
                "adoption_target_mismatch",
                "adoption, island, and checked target must have one target identity",
                f"intent:{intent.intent_id}",
            )
        )
    if intent.island_id != island.island_id:
        issues.append(
            _issue(
                "identity",
                "violated",
                "adoption_island_mismatch",
                "adoption selects a different recognized island",
                f"intent:{intent.intent_id}",
            )
        )
    if intent.hypotheses_sha256 != release.hypotheses_sha256:
        issues.append(
            _issue(
                "identity",
                "violated",
                "adoption_hypotheses_stale",
                "adoption was authored against different release hypotheses",
                f"intent:{intent.intent_id}",
            )
        )
    if intent.mode != "adopt" or intent.implementation_id != checked_implementation.implementation_id:
        issues.append(
            _issue(
                "implementation",
                "violated",
                "adoption_implementation_mismatch",
                "checked adoption must select this exact reusable implementation",
                f"intent:{intent.intent_id}",
            )
        )

    missing_units = sorted(set(island.target_unit_ids) - set(machine.by_id))
    if missing_units:
        issues.append(
            _issue(
                "boundary",
                "violated",
                "island_unit_missing",
                f"machine IR lacks selected units {missing_units!r}",
                f"island:{island.island_id}",
            )
        )
    island_ids = set(island.target_unit_ids)
    direct_crossings = () if missing_units else _direct_crossings(machine, island_ids)
    boundary_ids = {
        edge_id for edge_id, _kind, _direction, _source, _target, _abi in direct_crossings
    }
    catalog_functions = {row.function_id: row for row in catalog.functions}
    catalog_abi_by_unit = {
        unit_id: (
            (
                binding.get("profile", {}).get("id")
                if isinstance(binding.get("profile"), Mapping)
                else None
            )
            if (binding := abi_bindings.get(match.match_id)) is not None
            and binding.get("status") == "complete"
            else catalog_functions[match.catalog_function_id].abi_profile_id
            if abi_resolution is None
            else None
        )
        for release_island in release.islands
        for match in release_island.matches
        if match.catalog_function_id in catalog_functions
        for unit_id in match.target_unit_ids
    }
    for edge_id, kind, _direction, _source, target, abi_id in direct_crossings:
        inferred_abi = abi_id or catalog_abi_by_unit.get(target)
        if kind == "call" and inferred_abi is None:
            issues.append(
                _issue(
                    "boundary",
                    "incomplete",
                    "direct_boundary_abi_missing",
                    "direct call crossing lacks a checked machine ABI contract",
                    f"boundary-edge:{edge_id}",
                )
            )

    for unit_id in sorted(island_ids - set(missing_units)):
        unit = machine.by_id[unit_id]
        expected_events = _external_event_count(unit)
        sites = sites_by_unit.get(unit_id, ())
        event_indexes = {site.event_index for site in sites}
        for event_index in range(expected_events):
            if event_index not in event_indexes:
                issues.append(
                    _issue(
                        "boundary",
                        "incomplete",
                        "canonical_external_site_missing",
                        "an exact external event has no canonical site authority",
                        f"unit:{unit_id}/event:{event_index}",
                    )
                )
        for site in sites:
            boundary_ids.add(site.site_id)
            if not site.authorizing or site.status != "complete" or site.contract is None:
                issues.append(
                    _issue(
                        "boundary",
                        "violated" if site.status == "violated" else "incomplete",
                        "canonical_external_site_not_complete",
                        "external crossing requires a complete canonical machine contract",
                        f"external-site:{site.site_id}",
                    )
                )

        control = unit.payload.get("control")
        has_indirect = isinstance(control, Mapping) and control.get("has_indirect_target") is True
        certificates = certificates_by_unit.get(unit_id, ())
        if has_indirect and not certificates:
            issues.append(
                _issue(
                    "boundary",
                    "incomplete",
                    "indirect_target_certificate_missing",
                    "indirect island exit lacks a checked finite target certificate",
                    f"unit:{unit_id}",
                )
            )
        for certificate in certificates:
            boundary_ids.add(certificate.certificate_id)
            if not certificate.authorizing or certificate.status != "complete":
                issues.append(
                    _issue(
                        "boundary",
                        "violated" if certificate.status == "violated" else "incomplete",
                        "indirect_target_certificate_not_complete",
                        "indirect island exit does not have complete target authority",
                        f"indirect-exit:{certificate.exit_id}",
                    )
                )

    for source_unit_id, certificates in sorted(certificates_by_unit.items()):
        if source_unit_id in island_ids:
            continue
        for certificate in certificates:
            if not set(certificate.target_unit_ids).intersection(island_ids):
                continue
            boundary_ids.add(certificate.certificate_id)
            if not certificate.authorizing or certificate.status != "complete":
                issues.append(
                    _issue(
                        "boundary",
                        "violated" if certificate.status == "violated" else "incomplete",
                        "inbound_indirect_target_not_complete",
                        "an inbound indirect transfer to the island is not fully checked",
                        f"indirect-exit:{certificate.exit_id}",
                    )
                )

    implementation_operations = {
        mapping.operation_id
        for mapping in checked_implementation.operation_source_mappings
    }
    missing_operations = sorted(set(island.operation_ids) - implementation_operations)
    if checked_implementation.family_id != island.family_id:
        issues.append(
            _issue(
                "implementation",
                "violated",
                "implementation_family_mismatch",
                "implementation belongs to another library family",
                f"implementation:{checked_implementation.implementation_id}",
            )
        )
    if island.release_id not in checked_implementation.compatible_release_ids:
        issues.append(
            _issue(
                "implementation",
                "violated",
                "implementation_release_mismatch",
                "implementation does not cover the recognized release",
                f"implementation:{checked_implementation.implementation_id}",
            )
        )
    if missing_operations:
        issues.append(
            _issue(
                "implementation",
                "incomplete",
                "implementation_operations_missing",
                f"implementation omits island operations {missing_operations!r}",
                f"implementation:{checked_implementation.implementation_id}",
            )
        )
    if checked_implementation.status != "complete":
        issues.extend(checked_implementation.issues)
        if not checked_implementation.issues:
            issues.append(
                _issue(
                    "implementation",
                    "incomplete",
                    "implementation_qualification_incomplete",
                    "implementation has no complete compile/refinement qualification",
                    f"implementation:{checked_implementation.implementation_id}",
                )
            )

    for function_id in island.catalog_function_ids:
        function = catalog_functions.get(function_id)
        if function is None:
            issues.append(
                _issue(
                    "identity",
                    "violated",
                    "catalog_function_missing",
                    "selected function is absent from the bound catalog index",
                    f"catalog-function:{function_id}",
                )
            )
        elif abi_resolution is not None:
            matching_bindings = [
                abi_bindings.get(match.match_id)
                for match in island.matches
                if match.catalog_function_id == function_id
            ]
            complete = [
                row
                for row in matching_bindings
                if isinstance(row, Mapping)
                and row.get("status") == "complete"
                and isinstance(row.get("profile"), Mapping)
            ]
            if len(complete) != 1:
                statuses = sorted(
                    str(row.get("status"))
                    for row in matching_bindings
                    if isinstance(row, Mapping)
                )
                issues.append(
                    _issue(
                        "boundary",
                        "violated" if "violated" in statuses else "incomplete",
                        "catalog_operation_physical_abi_unresolved",
                        "recognized operation lacks one complete canonical physical ABI binding",
                        f"catalog-function:{function_id}",
                    )
                )
        elif function.abi_profile_id is None:
            issues.append(
                _issue(
                    "boundary",
                    "incomplete",
                    "catalog_operation_abi_missing",
                    "recognized operation lacks a machine-level ABI profile",
                    f"catalog-function:{function_id}",
                )
            )

    receipt = CheckedLibraryIslandV1.create(
        target_id=target_id,
        target_binary_sha256=release.target_binary_sha256,
        machine_ir_sha256=machine.ir_sha256,
        island_id=island.island_id,
        hypotheses_sha256=release.hypotheses_sha256,
        implementation_id=checked_implementation.implementation_id,
        implementation_sha256=checked_implementation.implementation_sha256,
        checker_id=_CHECKER_ID,
        checked_unit_ids=island.target_unit_ids,
        checked_operation_ids=island.operation_ids,
        checked_boundary_edge_ids=boundary_ids,
        dependency_sha256s=(
            machine.ir_sha256,
            catalog.index_sha256,
            checked_implementation.implementation_sha256,
            implementation_pack_sha256
            or checked_implementation.implementation_sha256,
            intent.intent_sha256,
            external_manifest_sha256,
            target_manifest_sha256,
            *(
                ()
                if abi_resolution is None
                else (str(abi_resolution["resolution_sha256"]),)
            ),
        ),
        issues=issues,
    )
    CHECKED_LIBRARY_ISLAND_CODEC_V1.write(out, receipt)
    return receipt


__all__ = ["check_library_island_v1"]
