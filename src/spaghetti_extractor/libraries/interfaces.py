"""Linked-library interfaces."""

from __future__ import annotations

import copy
import json
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..artifacts.formats import (
    COMPONENT_QUALIFICATION_FORMAT,
    LIBRARY_ARTIFACT_INDEX_FORMAT,
    LIBRARY_ARTIFACT_INDEX_V2_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_V2_FORMAT,
    LIBRARY_CATALOG_LOCK_FORMAT,
    LIBRARY_HYPOTHESIS_SET_FORMAT,
    LIBRARY_INTERFACE_CATALOG_FORMAT,
    LIBRARY_MATCH_EVIDENCE_FORMAT,
    LIBRARY_REPLACEMENT_PLAN_FORMAT,
    DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
    LINKED_INTERFACE_ASSIGNMENTS_FORMAT,
    LINKED_INTERFACE_QUALIFICATION_FORMAT,
    LINKED_ISLAND_MANIFEST_FORMAT,
    LINKED_ISLAND_MANIFEST_V2_FORMAT,
    LINKED_ISLAND_REVIEW_FORMAT,
    MACHINE_IR_FORMAT,
)
from ..errors import ToolkitInputError
from ..pe32.image import parse_pe_image
from .contracts import (
    validate_linked_island_manifest as _validate_linked_island_contract,
)
from ..util import sha256_file, write_json


from .matching_support import (
    _array,
    _canonical_sha256,
    _copy_object,
    _issue,
    _issue_sort_key,
    _nonempty,
    _object,
    _qualification_contract_descriptor,
    _qualification_unit_ids,
    _read_object,
    _sha256,
    _validate_linked_island_manifest,
    _validate_self_hash,
)
from .model import (
    LinkedLibraryError,
    _REPLACEMENT_KINDS,
)

def bind_interface_contract_catalog(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and self-bind reusable interface contracts and replacements."""

    core = copy.deepcopy(dict(payload))
    core.pop("catalog_sha256", None)
    if core.get("format") != LIBRARY_INTERFACE_CATALOG_FORMAT:
        raise LinkedLibraryError("unsupported interface contract catalog format")
    _nonempty(core.get("catalog_id"), "interface contract catalog ID")
    contract_ids: set[str] = set()
    for raw in _array(core.get("contracts", []), "interface contracts"):
        contract = _object(raw, "interface contract")
        identity = _nonempty(contract.get("id"), "interface contract ID")
        if identity in contract_ids:
            raise LinkedLibraryError(f"duplicate interface contract ID: {identity}")
        contract_ids.add(identity)
        descriptor = _object(contract.get("component_contract"), "component contract")
        _nonempty(descriptor.get("format"), "component contract format")
        _sha256(descriptor.get("contract_sha256"), "component contract SHA-256")
        domain = _object(contract.get("domain"), "interface contract domain")
        if domain.get("kind") not in {"total", "caller_proven", "guarded"}:
            raise LinkedLibraryError(f"interface contract {identity} has invalid domain")
    replacement_ids: set[str] = set()
    for raw in _array(core.get("replacements", []), "interface replacements"):
        replacement = _object(raw, "interface replacement")
        identity = _nonempty(replacement.get("id"), "interface replacement ID")
        if identity in replacement_ids:
            raise LinkedLibraryError(f"duplicate interface replacement ID: {identity}")
        replacement_ids.add(identity)
        if replacement.get("contract_id") not in contract_ids:
            raise LinkedLibraryError(
                f"replacement {identity} references unknown interface contract"
            )
        if replacement.get("kind") not in _REPLACEMENT_KINDS - {
            "portable_machine_ir_fallback",
            "lift_locally",
        }:
            raise LinkedLibraryError(f"replacement {identity} has invalid kind")
        qualification = _object(
            replacement.get("qualification"), "replacement qualification"
        )
        if qualification.get("status") not in {"qualified", "guarded", "incomplete"}:
            raise LinkedLibraryError(
                f"replacement {identity} has invalid qualification status"
            )
        implementation = _object(
            replacement.get("implementation"), "replacement implementation"
        )
        _sha256(
            implementation.get("portable_source_sha256"),
            "replacement portable source SHA-256",
        )
        _nonempty(
            implementation.get("portable_symbol"),
            "replacement portable symbol",
        )
    return {**core, "catalog_sha256": _canonical_sha256(core)}


def bind_linked_interface_assignments(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return self-bound operator assignments for linked interfaces."""

    core = copy.deepcopy(dict(payload))
    core.pop("assignments_sha256", None)
    if core.get("format") != LINKED_INTERFACE_ASSIGNMENTS_FORMAT:
        raise LinkedLibraryError("unsupported linked interface assignments format")
    _sha256(
        core.get("linked_island_manifest_sha256"),
        "linked-island manifest SHA-256",
    )
    seen: set[str] = set()
    for raw in _array(core.get("assignments", []), "linked interface assignments"):
        assignment = _object(raw, "linked interface assignment")
        island_id = _nonempty(assignment.get("island_id"), "assigned island ID")
        if island_id in seen:
            raise LinkedLibraryError(f"duplicate linked interface assignment: {island_id}")
        seen.add(island_id)
        _nonempty(assignment.get("contract_id"), "assigned contract ID")
        _object(assignment.get("evidence"), "linked interface assignment evidence")
    return {**core, "assignments_sha256": _canonical_sha256(core)}


def qualify_linked_interfaces(
    *,
    linked_islands: Path | str,
    interface_catalog: Path | str | Mapping[str, Any],
    assignments: Path | str | Mapping[str, Any],
    out: Path | str,
) -> dict[str, Any]:
    """Bind checked component evidence to proposed library interfaces."""

    manifest_path = Path(linked_islands)
    manifest = _read_object(manifest_path, "linked-island manifest")
    _validate_linked_island_manifest(manifest)
    catalog = (
        _copy_object(interface_catalog, "interface contract catalog")
        if isinstance(interface_catalog, Mapping)
        else _read_object(Path(interface_catalog), "interface contract catalog")
    )
    expected_catalog = catalog.get("catalog_sha256")
    checked_catalog = bind_interface_contract_catalog(catalog)
    if expected_catalog != checked_catalog["catalog_sha256"]:
        raise LinkedLibraryError("interface contract catalog self-hash is stale")
    assignment_payload = (
        _copy_object(assignments, "linked interface assignments")
        if isinstance(assignments, Mapping)
        else _read_object(Path(assignments), "linked interface assignments")
    )
    if assignment_payload.get("format") != LINKED_INTERFACE_ASSIGNMENTS_FORMAT:
        raise LinkedLibraryError("unsupported linked interface assignments format")
    assignment_core = copy.deepcopy(assignment_payload)
    observed_assignment_hash = assignment_core.pop("assignments_sha256", None)
    if observed_assignment_hash != _canonical_sha256(assignment_core):
        raise LinkedLibraryError("linked interface assignments self-hash is stale")
    if assignment_payload.get("linked_island_manifest_sha256") != manifest["manifest_sha256"]:
        raise LinkedLibraryError("linked interface assignments are stale")

    islands = {str(item["id"]): item for item in manifest["islands"]}
    contracts = {str(item["id"]): item for item in catalog.get("contracts", [])}
    results: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    seen_islands: set[str] = set()
    for raw in _array(assignment_payload.get("assignments", []), "interface assignments"):
        assignment = _object(raw, "linked interface assignment")
        island_id = _nonempty(assignment.get("island_id"), "assigned island ID")
        contract_id = _nonempty(assignment.get("contract_id"), "assigned contract ID")
        if island_id in seen_islands:
            raise LinkedLibraryError(f"duplicate interface assignment: {island_id}")
        seen_islands.add(island_id)
        island = islands.get(island_id)
        contract = contracts.get(contract_id)
        row_issues: list[dict[str, Any]] = []
        if island is None:
            row_issues.append(
                _issue("violated", "unknown_assigned_island", "assignment names an unknown island", island_id=island_id)
            )
        if contract is None:
            row_issues.append(
                _issue("violated", "unknown_assigned_contract", "assignment names an unknown contract", island_id=island_id, contract_id=contract_id)
            )
        evidence = _object(assignment.get("evidence"), "interface assignment evidence")
        evidence_kind = evidence.get("kind")
        evidence_binding: dict[str, Any] = {"kind": evidence_kind}
        if evidence_kind == "component_qualification":
            path = Path(_nonempty(evidence.get("path"), "component qualification path"))
            qualification = _read_object(path, "component qualification")
            expected_file = evidence.get("file_sha256")
            if expected_file != sha256_file(path):
                row_issues.append(
                    _issue("violated", "stale_component_qualification", "component qualification file hash differs", island_id=island_id)
                )
            try:
                _validate_self_hash(
                    qualification,
                    COMPONENT_QUALIFICATION_FORMAT,
                    "qualification_sha256",
                    "component qualification",
                )
            except LinkedLibraryError as error:
                row_issues.append(
                    _issue(
                        "violated",
                        "malformed_component_qualification",
                        str(error),
                        island_id=island_id,
                    )
                )
            if (
                qualification.get("status") != "qualified"
                or qualification.get("executes_original_binary") is not False
                or qualification.get("activation", {}).get("authorized") is not True
            ):
                row_issues.append(
                    _issue("incomplete", "component_not_qualified", "component evidence is not qualified", island_id=island_id)
                )
            descriptor = _qualification_contract_descriptor(qualification)
            expected_descriptor = contract.get("component_contract") if contract else None
            if descriptor != expected_descriptor:
                row_issues.append(
                    _issue("violated", "component_contract_mismatch", "component qualification proves a different contract", island_id=island_id, contract_id=contract_id, expected=expected_descriptor, observed=descriptor)
                )
            if island is not None:
                qualified_units = set(_qualification_unit_ids(qualification))
                island_units = set(island["unit_ids"])
                if qualified_units != island_units:
                    row_issues.append(
                        _issue("violated", "qualification_membership_mismatch", "component qualification does not cover the exact island", island_id=island_id, expected=sorted(island_units), observed=sorted(qualified_units))
                    )
            implementation = qualification.get("implementation")
            if not isinstance(implementation, Mapping):
                row_issues.append(
                    _issue(
                        "violated",
                        "qualification_implementation_missing",
                        "component qualification omits its portable implementation identity",
                        island_id=island_id,
                    )
                )
            else:
                try:
                    portable_source_sha256 = _sha256(
                        implementation.get("portable_source_sha256"),
                        "qualified portable source SHA-256",
                    )
                    portable_symbol = _nonempty(
                        implementation.get("portable_symbol"),
                        "qualified portable symbol",
                    )
                    evidence_binding["implementation"] = {
                        "portable_source_sha256": portable_source_sha256,
                        "portable_symbol": portable_symbol,
                    }
                except LinkedLibraryError as error:
                    row_issues.append(
                        _issue(
                            "violated",
                            "qualification_implementation_malformed",
                            str(error),
                            island_id=island_id,
                        )
                    )
            evidence_binding.update(
                {
                    "path": str(path.resolve()),
                    "file_sha256": sha256_file(path),
                    "qualification_sha256": qualification.get(
                        "qualification_sha256"
                    ),
                }
            )
        elif evidence_kind == "checked_contract_certificate":
            row_issues.append(
                _issue(
                    "incomplete",
                    "certificate_checker_unavailable",
                    "a certificate hash cannot authorize replacement without a checked certificate format",
                    island_id=island_id,
                    contract_id=contract_id,
                )
            )
        elif evidence_kind in {"identity_only", "operator_proposal"}:
            row_issues.append(
                _issue("incomplete", "semantic_qualification_missing", "artifact identity does not establish interface behavior", island_id=island_id, contract_id=contract_id)
            )
        else:
            row_issues.append(
                _issue("violated", "unsupported_qualification_evidence", "assignment uses unsupported evidence", island_id=island_id, contract_id=contract_id)
            )
        status = (
            "violated" if any(item["status"] == "violated" for item in row_issues)
            else "incomplete" if row_issues
            else "qualified"
        )
        issues.extend(row_issues)
        results.append(
            {
                "island_id": island_id,
                "contract_id": contract_id,
                "status": status,
                "domain": copy.deepcopy(contract.get("domain")) if contract else None,
                "evidence": evidence_binding,
                "issues": sorted(row_issues, key=_issue_sort_key),
            }
        )
    qualified = sum(row["status"] == "qualified" for row in results)
    overall = (
        "violated" if any(item["status"] == "violated" for item in issues)
        else "incomplete" if issues or qualified < len(islands)
        else "qualified"
    )
    core = {
        "format": LINKED_INTERFACE_QUALIFICATION_FORMAT,
        "status": overall,
        "executes_original_binary": False,
        "bindings": {
            "linked_island_manifest_sha256": manifest["manifest_sha256"],
            "interface_catalog_sha256": expected_catalog,
            "assignments_sha256": observed_assignment_hash,
        },
        "qualifications": sorted(results, key=lambda item: item["island_id"]),
        "counts": {
            "islands": len(islands),
            "assignments": len(results),
            "qualified": qualified,
            "incomplete": sum(row["status"] == "incomplete" for row in results),
            "violated": sum(row["status"] == "violated" for row in results),
            "unassigned": len(islands) - len(results),
        },
        "issues": sorted(issues, key=_issue_sort_key),
        "authority": {
            "artifact_identity_is_semantic_proof": False,
            "component_contract_authority_reused": True,
        },
    }
    payload = {**core, "qualification_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload
