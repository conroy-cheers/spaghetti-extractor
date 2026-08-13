"""Fail-closed binding from machine call frontiers to source calls.

The artifacts in this module are diagnostic and source-generation authority.
They never turn artifact names into semantic evidence and never execute the
original binary.
"""

from __future__ import annotations

import copy
import json
from collections import Counter
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping

from .artifact_formats import (
    ALLOWED_RUNTIME_IMPORTS_FORMAT,
    CALLABLE_INTERFACE_CATALOG_FORMAT,
    CALL_FRONTIER_FORMAT,
    CALL_SUBSTITUTION_ASSIGNMENTS_FORMAT,
    CALL_SUBSTITUTION_PLAN_FORMAT,
    CANDIDATE_DEPENDENCY_AUDIT_FORMAT,
    DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
    INDIRECT_CALL_TARGETS_FORMAT,
    MACHINE_IR_FORMAT,
    SOURCE_CALL_BINDING_REPORT_FORMAT,
    SOURCE_CALL_BINDINGS_FORMAT,
    SOURCE_CALL_INVENTORY_FORMAT,
    SOURCE_SUBSTITUTION_CATALOG_FORMAT,
)
from .linked_library_contracts import (
    LinkedLibraryContractError,
    validate_linked_island_manifest,
)
from .source_project import SOURCE_PROJECT_BINDING_FORMAT
from .source_graph import source_function_closure
from .stage_binary import _parse_stage_a_pe
from .util import sha256_file, write_json


class SourceCallSubstitutionError(ValueError):
    """A call-frontier or source-call artifact is malformed or stale."""


def derive_static_indirect_call_targets(
    *,
    original: Path | str,
    machine_ir: Path | str,
    source_binding: Path | str,
    out: Path | str,
) -> dict[str, Any]:
    """Resolve relocation-backed internal code pointers without execution."""

    original_path = Path(original)
    binary = _parse_stage_a_pe(original_path)
    binding = _read_hashed(
        Path(source_binding),
        SOURCE_PROJECT_BINDING_FORMAT,
        "binding_sha256",
        "source-project binding",
    )
    if binding["bindings"].get("original_binary_sha256") != binary.sha256:
        raise SourceCallSubstitutionError(
            "indirect-target source binding/original binary are stale"
        )
    manifest_path = Path(machine_ir)
    if manifest_path.is_dir():
        manifest_path = manifest_path / "machine-ir-manifest.json"
    manifest = _read_object(manifest_path, "machine IR manifest")
    if manifest.get("format") != MACHINE_IR_FORMAT:
        raise SourceCallSubstitutionError("unsupported machine IR format")
    artifact = _object(
        _object(manifest.get("artifacts"), "machine IR artifacts").get("machine_ir"),
        "machine IR artifact",
    )
    ir_path = (manifest_path.parent / str(artifact.get("path"))).resolve()
    try:
        ir_path.relative_to(manifest_path.parent.resolve())
    except ValueError as error:
        raise SourceCallSubstitutionError("machine IR path escapes package") from error
    ir_sha256 = sha256_file(ir_path)
    if (
        artifact.get("sha256") != ir_sha256
        or binding["bindings"].get("machine_ir_sha256") != ir_sha256
    ):
        raise SourceCallSubstitutionError(
            "indirect-target source binding/machine IR are stale"
        )
    unit_starts = _machine_unit_starts(ir_path)
    relocation_types = _pe32_relocation_types(binary)
    rows: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for island in binding["islands"]:
        boundary = _object(island.get("boundary"), "source-island boundary")
        for boundary_index, raw_event in enumerate(
            _array(boundary.get("external_events"), "source-island external events")
        ):
            event = _object(raw_event, "source-island external event")
            if event.get("kind") != "indirect_call":
                continue
            source_unit_id = _nonempty(
                event.get("source_unit_id"), "indirect-call source unit"
            )
            row, row_issues = _static_indirect_target_row(
                binary=binary,
                event=event,
                source_unit_id=source_unit_id,
                boundary_index=boundary_index,
                relocation_types=relocation_types,
                unit_starts=unit_starts,
            )
            rows.append(row)
            issues.extend(row_issues)
    core = {
        "format": INDIRECT_CALL_TARGETS_FORMAT,
        "status": "qualified" if not issues else "incomplete",
        "executes_original_binary": False,
        "source_project_binding_sha256": binding["binding_sha256"],
        "bindings": {
            "original_binary_sha256": binary.sha256,
            "machine_ir_sha256": ir_sha256,
        },
        "targets": sorted(
            rows, key=lambda item: (item["source_unit_id"], item["event_index"])
        ),
        "issues": sorted(issues, key=_issue_sort_key),
        "counts": {
            "indirect_calls": len(rows),
            "qualified": sum(item["status"] == "qualified" for item in rows),
            "incomplete": sum(item["status"] != "qualified" for item in rows),
        },
        "authority": {
            "static_pe_evidence_only": True,
            "authorizes_semantic_substitution": False,
            "final_candidate_validation_required": True,
        },
    }
    payload = {**core, "inventory_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def generate_call_frontier(
    *,
    source_binding: Path | str,
    linked_islands: Path | str,
    dynamic_requirements: Path | str,
    indirect_targets: Path | str | Mapping[str, Any] | None = None,
    out: Path | str,
) -> dict[str, Any]:
    """Classify every outgoing call from every source-bound application island."""

    binding = _read_hashed(
        Path(source_binding),
        SOURCE_PROJECT_BINDING_FORMAT,
        "binding_sha256",
        "source-project binding",
    )
    manifest = _read_object(Path(linked_islands), "linked-island manifest")
    try:
        validate_linked_island_manifest(manifest)
    except LinkedLibraryContractError as error:
        raise SourceCallSubstitutionError(
            f"invalid linked-island manifest: {error}"
        ) from error
    dynamic = _read_hashed(
        Path(dynamic_requirements),
        DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
        "requirements_sha256",
        "dynamic-library requirements",
    )
    _check_frontier_bindings(binding, manifest, dynamic)
    indirect = _load_indirect_targets(indirect_targets, binding)

    owners = _owner_index(manifest)
    source_owner = {
        unit_id: str(island["id"])
        for island in binding["islands"]
        for unit_id in island["unit_ids"]
    }
    dynamic_by_unit: dict[str, list[Mapping[str, Any]]] = {}
    for callsite in _array(dynamic.get("callsites"), "dynamic callsites"):
        row = _object(callsite, "dynamic callsite")
        unit_id = row.get("unit_id")
        if isinstance(unit_id, str):
            dynamic_by_unit.setdefault(unit_id, []).append(row)

    rows: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for source_island in sorted(binding["islands"], key=lambda item: item["id"]):
        boundary = _object(source_island.get("boundary"), "source-island boundary")
        for index, raw_call in enumerate(
            _array(boundary.get("internal_calls"), "source-island internal calls")
        ):
            call = _object(raw_call, "source-island internal call")
            row = _direct_call_row(
                source_island=source_island,
                call=call,
                index=index,
                owners=owners,
                source_owner=source_owner,
            )
            _append_unique(rows, seen_ids, row)
            if row["resolution_status"] != "resolved":
                issues.append(_frontier_issue(row))
        for index, raw_event in enumerate(
            _array(boundary.get("external_events"), "source-island external events")
        ):
            event = _object(raw_event, "source-island external event")
            if event.get("kind") == "external_call":
                row = _external_call_row(
                    source_island=source_island,
                    event=event,
                    index=index,
                    dynamic_by_unit=dynamic_by_unit,
                )
            elif event.get("kind") == "indirect_call":
                row = _indirect_call_row(
                    source_island=source_island,
                    event=event,
                    index=index,
                    indirect=indirect,
                    owners=owners,
                )
            else:
                row = _unsupported_event_row(source_island, event, index)
            _append_unique(rows, seen_ids, row)
            if row["resolution_status"] != "resolved":
                issues.append(_frontier_issue(row))

    rows.sort(key=_frontier_sort_key)
    kind_counts = Counter(row["target"]["kind"] for row in rows)
    resolved = sum(row["resolution_status"] == "resolved" for row in rows)
    core = {
        "format": CALL_FRONTIER_FORMAT,
        "status": "complete" if resolved == len(rows) else "incomplete",
        "executes_original_binary": False,
        "bindings": {
            "source_project_binding_sha256": binding["binding_sha256"],
            "linked_island_manifest_sha256": manifest["manifest_sha256"],
            "dynamic_requirements_sha256": dynamic["requirements_sha256"],
            "indirect_targets_sha256": indirect.get("inventory_sha256"),
            "original_binary_sha256": binding["bindings"]["original_binary_sha256"],
            "machine_ir_sha256": binding["bindings"]["machine_ir_sha256"],
        },
        "calls": rows,
        "issues": sorted(issues, key=_issue_sort_key),
        "counts": {
            "calls": len(rows),
            "resolved": resolved,
            "incomplete": len(rows) - resolved,
            "by_target_kind": dict(sorted(kind_counts.items())),
        },
        "authority": {
            "artifact_identity_is_semantic_proof": False,
            "every_source_boundary_call_must_be_present": True,
            "can_authorize_source_substitution": False,
        },
    }
    payload = {**core, "frontier_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def bind_callable_interface_catalog(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate reusable callable endpoint contracts."""

    core = copy.deepcopy(dict(payload))
    core.pop("catalog_sha256", None)
    if core.get("format") != CALLABLE_INTERFACE_CATALOG_FORMAT:
        raise SourceCallSubstitutionError("unsupported callable interface catalog")
    _nonempty(core.get("catalog_id"), "callable interface catalog ID")
    seen: set[str] = set()
    for raw in _array(core.get("interfaces"), "callable interfaces"):
        interface = _object(raw, "callable interface")
        identity = _nonempty(interface.get("id"), "callable interface ID")
        if identity in seen:
            raise SourceCallSubstitutionError(
                f"duplicate callable interface ID: {identity}"
            )
        seen.add(identity)
        selector = _object(interface.get("selector"), "callable selector")
        if selector.get("kind") not in {
            "dynamic_import",
            "static_library_symbol",
            "exact_endpoint",
            "exact_cluster",
            "project_internal",
        }:
            raise SourceCallSubstitutionError(
                f"callable interface {identity} has invalid selector"
            )
        if selector.get("kind") == "exact_cluster":
            endpoint_ids = [
                _nonempty(value, "cluster endpoint ID")
                for value in _array(
                    selector.get("endpoint_ids"), "cluster endpoint IDs"
                )
            ]
            if not endpoint_ids or len(endpoint_ids) != len(set(endpoint_ids)):
                raise SourceCallSubstitutionError(
                    f"callable interface {identity} has invalid cluster endpoints"
                )
        logical = _object(interface.get("logical_contract"), "logical contract")
        _nonempty(logical.get("format"), "logical contract format")
        contract_sha256 = _sha256(
            logical.get("contract_sha256"), "logical contract SHA-256"
        )
        specification = logical.get("specification")
        if specification is not None:
            checked_specification = _object(
                specification, "logical contract specification"
            )
            if _canonical_sha256(checked_specification) != contract_sha256:
                raise SourceCallSubstitutionError(
                    f"callable interface {identity} has stale logical contract"
                )
        qualification = _object(
            interface.get("qualification"), "callable qualification"
        )
        if qualification.get("status") not in {"qualified", "incomplete"}:
            raise SourceCallSubstitutionError(
                f"callable interface {identity} has invalid qualification status"
            )
        if qualification.get("kind") not in {
            "checked_machine_import_contract",
            "component_qualification",
            "pinned_source_dependency",
            "operator_proposal",
        }:
            raise SourceCallSubstitutionError(
                f"callable interface {identity} has invalid qualification kind"
            )
    return {**core, "catalog_sha256": _canonical_sha256(core)}


def bind_source_substitution_catalog(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate C implementations of callable logical contracts."""

    core = copy.deepcopy(dict(payload))
    core.pop("catalog_sha256", None)
    if core.get("format") != SOURCE_SUBSTITUTION_CATALOG_FORMAT:
        raise SourceCallSubstitutionError("unsupported source substitution catalog")
    _nonempty(core.get("catalog_id"), "source substitution catalog ID")
    seen: set[str] = set()
    for raw in _array(core.get("substitutions"), "source substitutions"):
        substitution = _object(raw, "source substitution")
        identity = _nonempty(substitution.get("id"), "source substitution ID")
        if identity in seen:
            raise SourceCallSubstitutionError(
                f"duplicate source substitution ID: {identity}"
            )
        seen.add(identity)
        _nonempty(substitution.get("interface_id"), "source interface ID")
        if substitution.get("assurance_class") not in {
            "machine_exact",
            "contract_equivalent",
            "behavioral_only",
        }:
            raise SourceCallSubstitutionError(
                f"source substitution {identity} has invalid assurance class"
            )
        implementation = _object(
            substitution.get("implementation"), "source implementation"
        )
        implementation_kind = implementation.get("kind", "call_expression")
        if implementation_kind == "call_expression":
            _nonempty(implementation.get("symbol"), "source implementation symbol")
            prototype = _object(implementation.get("prototype"), "source prototype")
            _nonempty(prototype.get("return_type"), "source return type")
            _array(prototype.get("parameters", []), "source prototype parameters")
            _array(implementation.get("headers", []), "source implementation headers")
            _array(implementation.get("link_inputs", []), "source link inputs")
        elif implementation_kind == "source_component":
            _nonempty(implementation.get("symbol"), "source component symbol")
            paths = _array(implementation.get("source_paths"), "source component paths")
            if not paths or any(not isinstance(path, str) or not path for path in paths):
                raise SourceCallSubstitutionError(
                    f"source substitution {identity} has invalid component paths"
                )
        else:
            raise SourceCallSubstitutionError(
                f"source substitution {identity} has invalid implementation kind"
            )
        expected_imports = implementation.get("expected_imports", [])
        if not isinstance(expected_imports, list):
            raise SourceCallSubstitutionError(
                f"source substitution {identity} has invalid expected imports"
            )
        for expected_import in expected_imports:
            _import_key(_object(expected_import, "expected source import"))
        expected_import = implementation.get("expected_import")
        if expected_import is not None:
            _import_key(_object(expected_import, "expected source import"))
    return {**core, "catalog_sha256": _canonical_sha256(core)}


def bind_allowed_runtime_imports(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and self-bind a candidate dependency envelope."""

    core = copy.deepcopy(dict(payload))
    core.pop("envelope_sha256", None)
    if core.get("format") != ALLOWED_RUNTIME_IMPORTS_FORMAT:
        raise SourceCallSubstitutionError("unsupported allowed runtime imports")
    _nonempty(core.get("profile_id"), "runtime import profile ID")
    imports = [
        _import_key(_object(value, "allowed runtime import"))
        for value in _array(core.get("imports"), "allowed runtime imports")
    ]
    if len(imports) != len(set(imports)):
        raise SourceCallSubstitutionError("allowed runtime imports contain duplicates")
    core["imports"] = [_import_dict(value) for value in sorted(imports, key=repr)]
    return {**core, "envelope_sha256": _canonical_sha256(core)}


def bind_call_substitution_assignments(payload: Mapping[str, Any]) -> dict[str, Any]:
    core = copy.deepcopy(dict(payload))
    core.pop("assignments_sha256", None)
    if core.get("format") != CALL_SUBSTITUTION_ASSIGNMENTS_FORMAT:
        raise SourceCallSubstitutionError("unsupported call substitution assignments")
    _sha256(core.get("frontier_sha256"), "call frontier SHA-256")
    seen_calls: set[str] = set()
    for raw in _array(core.get("assignments", []), "call assignments"):
        assignment = _object(raw, "call assignment")
        call_ids = [
            _nonempty(value, "assigned call ID")
            for value in _array(assignment.get("call_ids"), "assigned call IDs")
        ]
        if not call_ids:
            raise SourceCallSubstitutionError("call assignment has no call IDs")
        overlap = seen_calls.intersection(call_ids)
        if overlap:
            raise SourceCallSubstitutionError(
                f"call assignments overlap: {sorted(overlap)}"
            )
        seen_calls.update(call_ids)
        _nonempty(assignment.get("interface_id"), "assigned interface ID")
        _nonempty(assignment.get("substitution_id"), "assigned substitution ID")
    return {**core, "assignments_sha256": _canonical_sha256(core)}


def plan_call_substitutions(
    *,
    frontier: Path | str,
    interface_catalog: Path | str | Mapping[str, Any],
    substitution_catalog: Path | str | Mapping[str, Any],
    assignments: Path | str | Mapping[str, Any],
    out: Path | str,
) -> dict[str, Any]:
    """Check that every frontier call has one qualified source disposition."""

    frontier_payload = _read_hashed(
        Path(frontier), CALL_FRONTIER_FORMAT, "frontier_sha256", "call frontier"
    )
    interfaces = _load_bound_catalog(
        interface_catalog,
        "callable interface catalog",
        bind_callable_interface_catalog,
    )
    substitutions = _load_bound_catalog(
        substitution_catalog,
        "source substitution catalog",
        bind_source_substitution_catalog,
    )
    assignment_payload = _load_bound_catalog(
        assignments,
        "call substitution assignments",
        bind_call_substitution_assignments,
        hash_key="assignments_sha256",
    )
    if assignment_payload.get("frontier_sha256") != frontier_payload["frontier_sha256"]:
        raise SourceCallSubstitutionError("call assignments/frontier are stale")

    calls = {str(item["id"]): item for item in frontier_payload["calls"]}
    interface_by_id = {str(item["id"]): item for item in interfaces["interfaces"]}
    substitution_by_id = {
        str(item["id"]): item for item in substitutions["substitutions"]
    }
    planned: list[dict[str, Any]] = []
    consumed: set[str] = set()
    issues: list[dict[str, Any]] = []
    for raw in assignment_payload["assignments"]:
        assignment = _object(raw, "call assignment")
        interface = interface_by_id.get(str(assignment["interface_id"]))
        substitution = substitution_by_id.get(str(assignment["substitution_id"]))
        call_ids = [str(value) for value in assignment["call_ids"]]
        row_issues: list[dict[str, Any]] = []
        selected_calls = [calls.get(call_id) for call_id in call_ids]
        if any(call is None for call in selected_calls):
            row_issues.append(_issue("violated", "unknown_frontier_call"))
        if interface is None:
            row_issues.append(_issue("violated", "unknown_callable_interface"))
        if substitution is None:
            row_issues.append(_issue("violated", "unknown_source_substitution"))
        if (
            interface is not None
            and substitution is not None
            and substitution.get("interface_id") != interface.get("id")
        ):
            row_issues.append(_issue("violated", "substitution_interface_mismatch"))
        if interface is not None and any(
            call is not None and not _interface_matches_call(interface, call)
            for call in selected_calls
        ):
            row_issues.append(_issue("violated", "callable_selector_mismatch"))
        if (
            interface is not None
            and interface.get("selector", {}).get("kind") == "exact_cluster"
            and set(call_ids)
            != set(interface.get("selector", {}).get("endpoint_ids", []))
        ):
            row_issues.append(_issue("violated", "cluster_endpoint_set_mismatch"))
        if len(call_ids) > 1 and assignment.get("composition") != "qualified_cluster":
            row_issues.append(_issue("incomplete", "call_cluster_contract_missing"))
        qualification = interface.get("qualification", {}) if interface else {}
        if qualification.get("status") != "qualified":
            row_issues.append(_issue("incomplete", "callable_interface_unqualified"))
        if substitution is not None and substitution.get("assurance_class") == "behavioral_only":
            row_issues.append(_issue("incomplete", "behavioral_only_substitution"))
        if any(
            call is not None and call.get("resolution_status") != "resolved"
            for call in selected_calls
        ):
            row_issues.append(_issue("incomplete", "frontier_call_unresolved"))
        status = _status_from_issues(row_issues, success="ready")
        consumed.update(call_id for call_id in call_ids if call_id in calls)
        issues.extend(row_issues)
        planned.append(
            {
                "id": _nonempty(assignment.get("id"), "call assignment ID"),
                "call_ids": call_ids,
                "interface_id": assignment["interface_id"],
                "substitution_id": assignment["substitution_id"],
                "composition": assignment.get("composition", "one_to_one"),
                "status": status,
                "source_implementation": copy.deepcopy(
                    substitution.get("implementation") if substitution else None
                ),
                "issues": row_issues,
            }
        )
    for call_id in sorted(set(calls) - consumed):
        issue = _issue("incomplete", "frontier_call_unassigned", call_id=call_id)
        issues.append(issue)
        planned.append(
            {
                "id": f"unassigned:{call_id}",
                "call_ids": [call_id],
                "interface_id": None,
                "substitution_id": None,
                "composition": "one_to_one",
                "status": "incomplete",
                "source_implementation": None,
                "issues": [issue],
            }
        )
    counts = Counter(item["status"] for item in planned)
    core = {
        "format": CALL_SUBSTITUTION_PLAN_FORMAT,
        "status": (
            "violated"
            if counts["violated"]
            else "complete"
            if counts["ready"] == len(planned) and len(consumed) == len(calls)
            else "incomplete"
        ),
        "executes_original_binary": False,
        "bindings": {
            "frontier_sha256": frontier_payload["frontier_sha256"],
            "interface_catalog_sha256": interfaces["catalog_sha256"],
            "substitution_catalog_sha256": substitutions["catalog_sha256"],
            "assignments_sha256": assignment_payload["assignments_sha256"],
        },
        "assignments": sorted(planned, key=lambda item: item["id"]),
        "issues": sorted(issues, key=_issue_sort_key),
        "counts": {
            "frontier_calls": len(calls),
            "assigned_frontier_calls": len(consumed),
            "plans": len(planned),
            "ready": counts["ready"],
            "incomplete": counts["incomplete"],
            "violated": counts["violated"],
        },
        "authority": {
            "library_identity_alone_authorizes_substitution": False,
            "complete_plan_can_authorize_source_binding": True,
        },
    }
    payload = {**core, "plan_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def propose_source_component_artifacts(
    *,
    frontier: Path | str,
    source_binding: Path | str,
    interfaces_out: Path | str,
    substitutions_out: Path | str,
    assignments_out: Path | str,
) -> dict[str, dict[str, Any]]:
    """Propose one fail-closed source component for each application island."""

    frontier_payload = _read_hashed(
        Path(frontier), CALL_FRONTIER_FORMAT, "frontier_sha256", "call frontier"
    )
    binding = _read_hashed(
        Path(source_binding),
        SOURCE_PROJECT_BINDING_FORMAT,
        "binding_sha256",
        "source-project binding",
    )
    if (
        frontier_payload.get("bindings", {}).get("source_project_binding_sha256")
        != binding["binding_sha256"]
    ):
        raise SourceCallSubstitutionError(
            "source-component proposal/frontier source binding are stale"
        )
    calls_by_island: dict[str, list[Mapping[str, Any]]] = {}
    for raw_call in frontier_payload["calls"]:
        call = _object(raw_call, "frontier call")
        source = _object(call.get("source"), "frontier call source")
        calls_by_island.setdefault(
            _nonempty(source.get("island_id"), "frontier source island"), []
        ).append(call)
    source_paths = sorted(
        _nonempty(source.get("path"), "source path")
        for source in _array(binding.get("sources"), "bound sources")
    )
    interfaces: list[dict[str, Any]] = []
    substitutions: list[dict[str, Any]] = []
    assignments: list[dict[str, Any]] = []
    known_islands: set[str] = set()
    for raw_island in sorted(binding["islands"], key=lambda item: item["id"]):
        island = _object(raw_island, "source island")
        island_id = _nonempty(island.get("id"), "source island ID")
        known_islands.add(island_id)
        calls = sorted(calls_by_island.get(island_id, []), key=lambda item: item["id"])
        if not calls:
            continue
        symbol = _nonempty(island.get("source_symbol"), "source island symbol")
        interface_id = f"source-component-interface:{island_id}"
        substitution_id = f"source-component-substitution:{island_id}"
        assignment_id = f"source-component-assignment:{island_id}"
        endpoint_ids = [str(call["id"]) for call in calls]
        contract = {
            "format": "stage-b-source-component-boundary-contract-v1",
            "source_project_binding_sha256": binding["binding_sha256"],
            "source_island_id": island_id,
            "source_symbol": symbol,
            "machine_unit_ids": sorted(str(value) for value in island["unit_ids"]),
            "endpoint_ids": endpoint_ids,
            "boundary": copy.deepcopy(island.get("boundary")),
        }
        interfaces.append(
            {
                "id": interface_id,
                "selector": {"kind": "exact_cluster", "endpoint_ids": endpoint_ids},
                "logical_contract": {
                    "format": contract["format"],
                    "contract_sha256": _canonical_sha256(contract),
                    "specification": contract,
                },
                "qualification": {
                    "kind": "operator_proposal",
                    "status": "incomplete",
                    "blockers": [
                        {
                            "code": "source_component_semantics_not_qualified",
                            "source_island_id": island_id,
                            "source_symbol": symbol,
                            "machine_unit_ids": contract["machine_unit_ids"],
                            "endpoint_ids": endpoint_ids,
                            "next_action": (
                                "qualify the source component against the exact "
                                "machine island boundary contract"
                            ),
                        }
                    ],
                },
            }
        )
        substitutions.append(
            {
                "id": substitution_id,
                "interface_id": interface_id,
                "assurance_class": "contract_equivalent",
                "implementation": {
                    "kind": "source_component",
                    "symbol": symbol,
                    "source_paths": source_paths,
                    "expected_imports": [],
                },
            }
        )
        assignments.append(
            {
                "id": assignment_id,
                "call_ids": endpoint_ids,
                "interface_id": interface_id,
                "substitution_id": substitution_id,
                "composition": "qualified_cluster",
            }
        )
    unknown_islands = sorted(set(calls_by_island) - known_islands)
    if unknown_islands:
        raise SourceCallSubstitutionError(
            f"frontier references unknown source islands: {unknown_islands}"
        )
    interface_catalog = bind_callable_interface_catalog(
        {
            "format": CALLABLE_INTERFACE_CATALOG_FORMAT,
            "catalog_id": "proposed-source-components-v1",
            "interfaces": interfaces,
        }
    )
    substitution_catalog = bind_source_substitution_catalog(
        {
            "format": SOURCE_SUBSTITUTION_CATALOG_FORMAT,
            "catalog_id": "proposed-source-component-substitutions-v1",
            "substitutions": substitutions,
        }
    )
    assignment_catalog = bind_call_substitution_assignments(
        {
            "format": CALL_SUBSTITUTION_ASSIGNMENTS_FORMAT,
            "frontier_sha256": frontier_payload["frontier_sha256"],
            "assignments": assignments,
        }
    )
    write_json(Path(interfaces_out), interface_catalog)
    write_json(Path(substitutions_out), substitution_catalog)
    write_json(Path(assignments_out), assignment_catalog)
    return {
        "interfaces": interface_catalog,
        "substitutions": substitution_catalog,
        "assignments": assignment_catalog,
    }


def propose_source_component_bindings(
    *,
    call_plan: Path | str,
    source_inventory: Path | str,
    out: Path | str,
) -> dict[str, Any]:
    """Bind proposed component plans to matching source definitions."""

    plan = _read_hashed(
        Path(call_plan), CALL_SUBSTITUTION_PLAN_FORMAT, "plan_sha256", "call plan"
    )
    inventory = _read_hashed(
        Path(source_inventory),
        SOURCE_CALL_INVENTORY_FORMAT,
        "inventory_sha256",
        "source call inventory",
    )
    rows: list[dict[str, Any]] = []
    for assignment in plan["assignments"]:
        implementation = assignment.get("source_implementation")
        if not isinstance(implementation, Mapping):
            continue
        if implementation.get("kind", "call_expression") != "source_component":
            continue
        rows.append(
            {
                "plan_id": _nonempty(assignment.get("id"), "call plan ID"),
                "source_component_symbol": _nonempty(
                    implementation.get("symbol"), "source component symbol"
                ),
            }
        )
    payload = bind_source_call_bindings(
        {
            "format": SOURCE_CALL_BINDINGS_FORMAT,
            "call_plan_sha256": plan["plan_sha256"],
            "source_inventory_sha256": inventory["inventory_sha256"],
            "bindings": rows,
        }
    )
    write_json(Path(out), payload)
    return payload


def inventory_clang_source_calls(
    *, ast_json: Path | str,
    source_root: Path | str,
    source_hashes: Iterable[Mapping[str, Any]],
    project_symbols: Iterable[str] = (),
    out: Path | str,
) -> dict[str, Any]:
    """Extract direct and indirect C calls from one or more Clang JSON ASTs."""

    ast_payload = _read_object(Path(ast_json), "Clang AST")
    root = Path(source_root).resolve()
    expected = {
        str(item["path"]): str(item["sha256"]) for item in source_hashes
    }
    for relative, digest in expected.items():
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise SourceCallSubstitutionError("source inventory path escapes root") from error
        if not path.is_file() or sha256_file(path) != digest:
            raise SourceCallSubstitutionError(f"source inventory is stale: {relative}")
    translation_units = sorted(
        relative
        for relative in expected
        if Path(relative).suffix.lower() in {".c", ".cc", ".cpp", ".cxx"}
    )
    asts = _clang_ast_translation_units(
        ast_payload,
        expected=expected,
        translation_units=translation_units,
    )
    definitions: dict[str, Mapping[str, Any]] = {}
    for relative, ast in asts:
        for symbol, source in _clang_source_definitions(
            ast, root, expected, fallback_source=relative
        ).items():
            if symbol in definitions:
                raise SourceCallSubstitutionError(
                    f"duplicate source function definition: {symbol}"
                )
            definitions[symbol] = source
    project_symbol_set = {str(value) for value in project_symbols}
    calls: list[dict[str, Any]] = []
    function_references: list[dict[str, Any]] = []
    for translation_unit_index, (relative, ast) in enumerate(asts):
        _walk_clang_ast(
            ast,
            calls,
            function_references,
            root,
            expected,
            ast_path=(translation_unit_index,),
            current_function=None,
            fallback_source=relative,
            definitions=definitions,
            project_symbols=project_symbol_set,
        )
    _disambiguate_source_artifact_ids(calls, prefix="source-call:")
    _disambiguate_source_artifact_ids(
        function_references, prefix="source-function-reference:"
    )
    calls.sort(key=lambda item: (item["source"]["path"], item["source"]["offset"], item["id"]))
    function_references.sort(
        key=lambda item: (
            item["source"]["path"],
            item["source"]["offset"],
            item["id"],
        )
    )
    core = {
        "format": SOURCE_CALL_INVENTORY_FORMAT,
        "status": "inventoried",
        "executes_original_binary": False,
        "bindings": {"sources": sorted(source_hashes, key=lambda item: item["path"])},
        "definitions": [
            {"symbol": symbol, "source": definitions[symbol]}
            for symbol in sorted(definitions)
        ],
        "calls": calls,
        "function_references": function_references,
        "counts": {
            "calls": len(calls),
            "direct": sum(item["kind"] == "direct" for item in calls),
            "indirect": sum(item["kind"] == "indirect" for item in calls),
            "function_references": len(function_references),
        },
    }
    payload = {**core, "inventory_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def _clang_ast_translation_units(
    payload: Mapping[str, Any],
    *,
    expected: Mapping[str, str],
    translation_units: list[str],
) -> tuple[tuple[str, Mapping[str, Any]], ...]:
    if payload.get("format") != "spaghetti-extractor-clang-ast-bundle-v1":
        if len(translation_units) != 1:
            raise SourceCallSubstitutionError(
                "multiple source translation units require a Clang AST bundle"
            )
        return ((translation_units[0], payload),)
    rows = _array(payload.get("translation_units"), "Clang AST translation units")
    result: list[tuple[str, Mapping[str, Any]]] = []
    seen: set[str] = set()
    for raw in rows:
        row = _object(raw, "Clang AST translation unit")
        relative = _nonempty(row.get("path"), "Clang AST source path")
        if relative in seen or relative not in translation_units:
            raise SourceCallSubstitutionError(
                "Clang AST bundle has duplicate or unknown translation units"
            )
        if row.get("source_sha256") != expected.get(relative):
            raise SourceCallSubstitutionError(
                f"Clang AST bundle is stale for {relative}"
            )
        ast = _object(row.get("ast"), "Clang AST translation-unit root")
        seen.add(relative)
        result.append((relative, ast))
    if seen != set(translation_units):
        raise SourceCallSubstitutionError(
            "Clang AST bundle does not cover every source translation unit"
        )
    return tuple(sorted(result, key=lambda row: row[0]))


def bind_source_call_bindings(payload: Mapping[str, Any]) -> dict[str, Any]:
    core = copy.deepcopy(dict(payload))
    core.pop("bindings_sha256", None)
    if core.get("format") != SOURCE_CALL_BINDINGS_FORMAT:
        raise SourceCallSubstitutionError("unsupported source call bindings")
    _sha256(core.get("call_plan_sha256"), "call plan SHA-256")
    _sha256(core.get("source_inventory_sha256"), "source inventory SHA-256")
    seen_plans: set[str] = set()
    seen_calls: set[str] = set()
    seen_components: set[str] = set()
    for raw in _array(core.get("bindings"), "source call bindings"):
        row = _object(raw, "source call binding")
        plan_id = _nonempty(row.get("plan_id"), "source call plan ID")
        source_call_id = row.get("source_call_id")
        source_component = row.get("source_component_symbol")
        if (source_call_id is None) == (source_component is None):
            raise SourceCallSubstitutionError(
                "source call binding must select one call or one source component"
            )
        if source_call_id is not None:
            source_call_id = _nonempty(source_call_id, "source call ID")
        if source_component is not None:
            source_component = _nonempty(
                source_component, "source component symbol"
            )
        if (
            plan_id in seen_plans
            or source_call_id in seen_calls
            or source_component in seen_components
        ):
            raise SourceCallSubstitutionError("source call bindings are not one-to-one")
        seen_plans.add(plan_id)
        if source_call_id is not None:
            seen_calls.add(source_call_id)
        if source_component is not None:
            seen_components.add(source_component)
    return {**core, "bindings_sha256": _canonical_sha256(core)}


def check_source_call_bindings(
    *,
    call_plan: Path | str,
    source_inventory: Path | str,
    bindings: Path | str | Mapping[str, Any],
    out: Path | str,
) -> dict[str, Any]:
    """Reject missing, extra, mismatched, or duplicated source calls."""

    plan = _read_hashed(
        Path(call_plan), CALL_SUBSTITUTION_PLAN_FORMAT, "plan_sha256", "call plan"
    )
    inventory = _read_hashed(
        Path(source_inventory),
        SOURCE_CALL_INVENTORY_FORMAT,
        "inventory_sha256",
        "source call inventory",
    )
    bound = _load_bound_catalog(
        bindings,
        "source call bindings",
        bind_source_call_bindings,
        hash_key="bindings_sha256",
    )
    if bound["call_plan_sha256"] != plan["plan_sha256"]:
        raise SourceCallSubstitutionError("source call bindings/call plan are stale")
    if bound["source_inventory_sha256"] != inventory["inventory_sha256"]:
        raise SourceCallSubstitutionError("source call bindings/inventory are stale")
    plans = {str(item["id"]): item for item in plan["assignments"]}
    calls = {str(item["id"]): item for item in inventory["calls"]}
    definitions = {
        str(item["symbol"]): item for item in inventory.get("definitions", [])
    }
    results: list[dict[str, Any]] = []
    used_plans: set[str] = set()
    used_calls: set[str] = set()
    component_roots: set[str] = set()
    issues: list[dict[str, Any]] = []
    for raw in bound["bindings"]:
        row = _object(raw, "source call binding")
        plan_row = plans.get(str(row["plan_id"]))
        source_call_id = row.get("source_call_id")
        source_call = calls.get(str(source_call_id)) if source_call_id else None
        source_component = row.get("source_component_symbol")
        row_issues: list[dict[str, Any]] = []
        if plan_row is None:
            row_issues.append(_issue("violated", "unknown_call_plan"))
        if source_call_id is not None and source_call is None:
            row_issues.append(_issue("violated", "unknown_source_call"))
        if source_component is not None and source_component not in definitions:
            row_issues.append(_issue("violated", "unknown_source_component"))
        expected_symbol = (
            plan_row.get("source_implementation", {}).get("symbol")
            if plan_row is not None
            and isinstance(plan_row.get("source_implementation"), Mapping)
            else None
        )
        expected_kind = (
            plan_row.get("source_implementation", {}).get(
                "kind", "call_expression"
            )
            if plan_row is not None
            and isinstance(plan_row.get("source_implementation"), Mapping)
            else None
        )
        if source_call_id is not None and expected_kind != "call_expression":
            row_issues.append(_issue("violated", "source_placement_kind_mismatch"))
        if source_component is not None and expected_kind != "source_component":
            row_issues.append(_issue("violated", "source_placement_kind_mismatch"))
        if (
            source_call is not None
            and expected_symbol is not None
            and source_call.get("callee") != expected_symbol
        ):
            row_issues.append(
                _issue(
                    "violated",
                    "source_callee_mismatch",
                    expected=expected_symbol,
                    observed=source_call.get("callee"),
                )
            )
        if (
            source_component is not None
            and expected_symbol is not None
            and source_component != expected_symbol
        ):
            row_issues.append(
                _issue(
                    "violated",
                    "source_component_mismatch",
                    expected=expected_symbol,
                    observed=source_component,
                )
            )
        if plan_row is not None and plan_row.get("status") != "ready":
            row_issues.append(_issue("incomplete", "call_plan_not_ready"))
        status = _status_from_issues(row_issues, success="satisfied")
        used_plans.add(str(row["plan_id"]))
        if source_call_id is not None:
            used_calls.add(str(source_call_id))
        if source_component is not None:
            component_roots.add(str(source_component))
        issues.extend(row_issues)
        results.append({**copy.deepcopy(dict(row)), "status": status, "issues": row_issues})
    for plan_id in sorted(set(plans) - used_plans):
        issue = _issue("incomplete", "call_plan_has_no_source_call", plan_id=plan_id)
        issues.append(issue)
    function_references = [
        _object(row, "source function reference")
        for row in inventory.get("function_references", [])
    ]
    covered_functions = source_function_closure(
        component_roots, calls.values(), function_references
    )
    unbound_source_local = 0
    covered_by_source_component = 0
    for call_id in sorted(set(calls) - used_calls):
        if calls[call_id].get("enclosing_function") in covered_functions:
            covered_by_source_component += 1
            continue
        if calls[call_id].get("callee_scope") == "source_local":
            unbound_source_local += 1
            continue
        issue = _issue("violated", "unexpected_source_call", source_call_id=call_id)
        issues.append(issue)
    status = _status_from_issues(issues, success="complete")
    core = {
        "format": SOURCE_CALL_BINDING_REPORT_FORMAT,
        "status": status,
        "executes_original_binary": False,
        "bindings": {
            "call_plan_sha256": plan["plan_sha256"],
            "source_inventory_sha256": inventory["inventory_sha256"],
            "source_call_bindings_sha256": bound["bindings_sha256"],
        },
        "results": sorted(results, key=lambda item: item["plan_id"]),
        "issues": sorted(issues, key=_issue_sort_key),
        "counts": {
            "plans": len(plans),
            "source_calls": len(calls),
            "bindings": len(results),
            "satisfied": sum(item["status"] == "satisfied" for item in results),
            "incomplete_or_violated": len(issues),
            "unbound_source_local": unbound_source_local,
            "covered_by_source_component": covered_by_source_component,
            "source_function_references": len(function_references),
        },
    }
    payload = {**core, "report_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def audit_candidate_dependencies(
    *,
    candidate: Path | str,
    call_plan: Path | str,
    allowed_runtime_imports: Iterable[Mapping[str, Any]],
    allowed_runtime_imports_sha256: str | None = None,
    out: Path | str,
) -> dict[str, Any]:
    """Statically reject candidate imports absent from the checked source envelope."""

    candidate_path = Path(candidate)
    pe = _parse_stage_a_pe(candidate_path)
    plan = _read_hashed(
        Path(call_plan), CALL_SUBSTITUTION_PLAN_FORMAT, "plan_sha256", "call plan"
    )
    expected = {
        _import_key(item)
        for item in allowed_runtime_imports
    }
    if allowed_runtime_imports_sha256 is not None:
        _sha256(
            allowed_runtime_imports_sha256,
            "allowed runtime imports SHA-256",
        )
    for assignment in plan["assignments"]:
        implementation = assignment.get("source_implementation")
        if not isinstance(implementation, Mapping):
            continue
        imported = implementation.get("expected_import")
        if isinstance(imported, Mapping):
            expected.add(_import_key(imported))
        for imported in implementation.get("expected_imports", []) or []:
            expected.add(_import_key(_object(imported, "expected source import")))
    observed = {
        (
            str(item.dll).lower(),
            str(item.symbol) if item.symbol is not None else None,
            int(item.ordinal) if item.ordinal is not None else None,
        )
        for item in pe.imports
    }
    unexpected = sorted(observed - expected, key=repr)
    core = {
        "format": CANDIDATE_DEPENDENCY_AUDIT_FORMAT,
        "status": "pass" if not unexpected else "violated",
        "executes_original_binary": False,
        "bindings": {
            "candidate_sha256": sha256_file(candidate_path),
            "call_plan_sha256": plan["plan_sha256"],
            "allowed_runtime_imports_sha256": allowed_runtime_imports_sha256,
        },
        "expected_imports": [_import_dict(value) for value in sorted(expected, key=repr)],
        "observed_imports": [_import_dict(value) for value in sorted(observed, key=repr)],
        "unexpected_imports": [_import_dict(value) for value in unexpected],
        "counts": {
            "expected": len(expected),
            "observed": len(observed),
            "unexpected": len(unexpected),
        },
        "authority": {
            "static_import_audit_proves_source_semantics": False,
            "candidate_runtime_validation_required": True,
        },
    }
    payload = {**core, "audit_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def _check_frontier_bindings(
    binding: Mapping[str, Any],
    manifest: Mapping[str, Any],
    dynamic: Mapping[str, Any],
) -> None:
    binding_ids = binding["bindings"]
    manifest_ids = manifest["bindings"]
    dynamic_ids = dynamic["bindings"]
    checks = (
        (binding_ids.get("original_binary_sha256"), manifest_ids.get("original_binary_sha256")),
        (binding_ids.get("machine_ir_sha256"), manifest_ids.get("machine_ir_sha256")),
        (binding_ids.get("machine_ir_sha256"), dynamic_ids.get("machine_ir_sha256")),
    )
    if any(left != right for left, right in checks):
        raise SourceCallSubstitutionError("call-frontier inputs are stale")


def _load_indirect_targets(
    value: Path | str | Mapping[str, Any] | None,
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    if value is None:
        return {"format": INDIRECT_CALL_TARGETS_FORMAT, "targets": []}
    payload = (
        copy.deepcopy(dict(value))
        if isinstance(value, Mapping)
        else _read_object(Path(value), "indirect call targets")
    )
    core = copy.deepcopy(payload)
    observed = core.pop("inventory_sha256", None)
    if payload.get("format") != INDIRECT_CALL_TARGETS_FORMAT:
        raise SourceCallSubstitutionError("unsupported indirect-call target inventory")
    if observed != _canonical_sha256(core):
        raise SourceCallSubstitutionError("indirect-call target inventory is stale")
    if payload.get("source_project_binding_sha256") != binding["binding_sha256"]:
        raise SourceCallSubstitutionError("indirect-call targets/source binding are stale")
    return payload


def _owner_index(manifest: Mapping[str, Any]) -> dict[str, Any]:
    by_unit: dict[str, Mapping[str, Any]] = {}
    spans: list[tuple[int, int, Mapping[str, Any]]] = []
    for raw in manifest["islands"]:
        island = _object(raw, "linked island")
        for unit_id in island["unit_ids"]:
            if unit_id in by_unit:
                raise SourceCallSubstitutionError("linked-island unit ownership overlaps")
            by_unit[str(unit_id)] = island
        for span in island["rva_spans"]:
            spans.append((int(span["rva_start"]), int(span["rva_end"]), island))
    return {"by_unit": by_unit, "spans": spans, "manifest": manifest}


def _machine_unit_starts(path: Path) -> set[int]:
    starts: set[int] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise SourceCallSubstitutionError(f"cannot read machine IR: {error}") from error
    for line_number, line in enumerate(lines, 1):
        if not line:
            continue
        try:
            unit = json.loads(line)
        except json.JSONDecodeError as error:
            raise SourceCallSubstitutionError(
                f"invalid machine IR row {line_number}: {error}"
            ) from error
        source = _object(
            _object(unit, "machine IR unit").get("source"), "machine IR source"
        )
        original = _object(source.get("original"), "machine IR original span")
        start = original.get("rva_start")
        if not isinstance(start, int) or start < 0 or start in starts:
            raise SourceCallSubstitutionError(
                "machine IR has invalid or duplicate unit start"
            )
        starts.add(start)
    return starts


def _pe32_relocation_types(binary: Any) -> dict[int, set[int]]:
    result: dict[int, set[int]] = {}
    for block in getattr(binary.pe, "DIRECTORY_ENTRY_BASERELOC", []):
        for entry in getattr(block, "entries", []):
            rva = getattr(entry, "rva", None)
            relocation_type = getattr(entry, "type", None)
            if isinstance(rva, int) and isinstance(relocation_type, int):
                result.setdefault(rva, set()).add(relocation_type)
    return result


def _static_indirect_target_row(
    *,
    binary: Any,
    event: Mapping[str, Any],
    source_unit_id: str,
    boundary_index: int,
    relocation_types: Mapping[int, set[int]],
    unit_starts: set[int],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    target_expression = event.get("target")
    issues: list[dict[str, Any]] = []
    slot_rva: int | None = None
    target_rva: int | None = None
    slot_bytes = b""
    if not isinstance(target_expression, Mapping):
        issues.append(_issue("incomplete", "indirect_target_expression_missing"))
    else:
        address = target_expression.get("address")
        if (
            target_expression.get("op") != "load"
            or target_expression.get("width") != 4
            or not isinstance(address, Mapping)
            or address.get("op") != "const"
            or not isinstance(address.get("value"), int)
        ):
            issues.append(
                _issue("incomplete", "indirect_target_expression_not_static_slot")
            )
        else:
            slot_rva = int(address["value"]) - int(binary.image_base)
            slot_section = _section_containing(binary, slot_rva, 4)
            if slot_section is None or not slot_section.readable:
                issues.append(
                    _issue("incomplete", "indirect_target_slot_not_readable")
                )
            else:
                slot_bytes = bytes(binary.pe.get_data(slot_rva, 4))
                if len(slot_bytes) != 4:
                    issues.append(
                        _issue("incomplete", "indirect_target_slot_not_file_backed")
                    )
                elif 3 not in relocation_types.get(slot_rva, set()):
                    issues.append(
                        _issue("incomplete", "indirect_target_slot_not_highlow_relocated")
                    )
                else:
                    target_va = int.from_bytes(slot_bytes, "little")
                    target_rva = target_va - int(binary.image_base)
                    target_section = _section_containing(binary, target_rva, 1)
                    if target_section is None or not target_section.executable:
                        issues.append(
                            _issue("incomplete", "indirect_target_not_executable")
                        )
                    elif target_rva not in unit_starts:
                        issues.append(
                            _issue("incomplete", "indirect_target_not_machine_cutpoint")
                        )
    status = _status_from_issues(issues, success="qualified")
    evidence = {
        "target_expression_sha256": _canonical_sha256(target_expression),
        "slot_rva": slot_rva,
        "slot_bytes": slot_bytes.hex(),
        "relocation_type": "IMAGE_REL_BASED_HIGHLOW" if slot_rva is not None and 3 in relocation_types.get(slot_rva, set()) else None,
        "target_rva": target_rva,
    }
    certificate_id = "static-indirect:" + _canonical_sha256(
        {
            "source_unit_id": source_unit_id,
            "event_index": boundary_index,
            "evidence": evidence,
        }
    )[:24]
    return (
        {
            "source_unit_id": source_unit_id,
            "event_index": boundary_index,
            "status": status,
            "certificate_id": certificate_id,
            "target_rvas": [target_rva] if status == "qualified" else [],
            "evidence": evidence,
            "issues": issues,
        },
        [
            {**issue, "source_unit_id": source_unit_id, "event_index": boundary_index}
            for issue in issues
        ],
    )


def _section_containing(binary: Any, rva: int | None, size: int) -> Any | None:
    if not isinstance(rva, int) or rva < 0 or size <= 0:
        return None
    matches = [
        section
        for section in binary.sections
        if section.rva_start <= rva and rva + size <= section.rva_end
    ]
    return matches[0] if len(matches) == 1 else None


def _direct_call_row(
    *,
    source_island: Mapping[str, Any],
    call: Mapping[str, Any],
    index: int,
    owners: Mapping[str, Any],
    source_owner: Mapping[str, str],
) -> dict[str, Any]:
    source_unit = _nonempty(call.get("source_unit_id"), "call source unit")
    target_rva = call.get("target_rva")
    owner = _owner_at_rva(owners, target_rva) if isinstance(target_rva, int) else None
    call_id = _call_id(source_island["id"], source_unit, "direct", index)
    if owner is None:
        target = {"kind": "unresolved_static", "rva": target_rva}
        resolution = "incomplete"
    elif owner.get("kind") == "application":
        target_island = source_owner.get(_entry_unit_id(owner, target_rva))
        if target_island is None:
            target = {
                "kind": "unresolved_application",
                "rva": target_rva,
                "ownership_island_id": owner["id"],
            }
            resolution = "incomplete"
        else:
            target = {
                "kind": "project_internal",
                "rva": target_rva,
                "source_island_id": target_island,
                "ownership_island_id": owner["id"],
            }
            resolution = "resolved"
    elif owner.get("kind") == "import_thunk":
        target = {
            "kind": "dynamic_import",
            "rva": target_rva,
            "ownership_island_id": owner["id"],
            "import": copy.deepcopy(owner.get("match", {}).get("import")),
            "machine_contract_id": None,
        }
        resolution = "resolved"
    elif owner.get("kind") in {"linked_dependency", "compiler_linker_support"}:
        target = _static_target(owner, target_rva)
        resolution = "resolved"
    elif owner.get("kind") == "unknown":
        target_unit_id = _entry_unit_id(owner, target_rva)
        target = {
            "kind": "static_internal",
            "rva": target_rva,
            "target_unit_id": target_unit_id or None,
            "ownership_island_id": owner.get("id"),
            "identity_status": "unidentified",
        }
        resolution = "resolved" if target_unit_id else "incomplete"
    else:
        target = {
            "kind": "unresolved_static",
            "rva": target_rva,
            "ownership_island_id": owner.get("id"),
            "ownership_kind": owner.get("kind"),
        }
        resolution = "incomplete"
    return _frontier_row(call_id, source_island, source_unit, "direct_call", target, resolution)


def _external_call_row(
    *,
    source_island: Mapping[str, Any],
    event: Mapping[str, Any],
    index: int,
    dynamic_by_unit: Mapping[str, list[Mapping[str, Any]]],
) -> dict[str, Any]:
    source_unit = _nonempty(event.get("source_unit_id"), "external call source unit")
    call_id = _call_id(source_island["id"], source_unit, "external", index)
    expected_key = _import_key(event)
    candidates = [
        value
        for value in dynamic_by_unit.get(source_unit, [])
        if _import_key(_object(value.get("import"), "dynamic import")) == expected_key
    ]
    if len(candidates) != 1:
        target = {
            "kind": "dynamic_import",
            "import": copy.deepcopy(
                {"dll": event.get("dll"), "symbol": event.get("symbol"), "ordinal": event.get("ordinal")}
            ),
            "machine_contract_id": None,
            "candidate_callsite_ids": sorted(str(value["id"]) for value in candidates),
        }
        resolution = "incomplete"
    else:
        candidate = candidates[0]
        contract = candidate.get("abi_contract")
        target = {
            "kind": "dynamic_import",
            "import": copy.deepcopy(candidate["import"]),
            "machine_contract_id": (
                contract.get("contract_id") if isinstance(contract, Mapping) else None
            ),
            "dynamic_callsite_id": candidate["id"],
            "dynamic_contract_status": candidate.get("status"),
            "argument_words": candidate.get("argument_words"),
        }
        resolution = "resolved"
    return _frontier_row(call_id, source_island, source_unit, "external_call", target, resolution)


def _indirect_call_row(
    *,
    source_island: Mapping[str, Any],
    event: Mapping[str, Any],
    index: int,
    indirect: Mapping[str, Any],
    owners: Mapping[str, Any],
) -> dict[str, Any]:
    source_unit = _nonempty(event.get("source_unit_id"), "indirect call source unit")
    call_id = _call_id(source_island["id"], source_unit, "indirect", index)
    matches = [
        _object(value, "indirect target declaration")
        for value in indirect.get("targets", [])
        if value.get("source_unit_id") == source_unit
        and value.get("event_index", index) == index
    ]
    if len(matches) != 1 or not matches[0].get("target_rvas"):
        target = {"kind": "indirect", "target_rvas": [], "certificate_id": None}
        resolution = "incomplete"
    else:
        match = matches[0]
        targets = []
        for rva in match["target_rvas"]:
            owner = _owner_at_rva(owners, rva) if isinstance(rva, int) else None
            targets.append(
                {
                    "rva": rva,
                    "ownership_island_id": owner.get("id") if owner else None,
                    "ownership_kind": owner.get("kind") if owner else "unresolved",
                }
            )
        target = {
            "kind": "indirect",
            "target_rvas": targets,
            "certificate_id": match.get("certificate_id"),
        }
        resolution = (
            "resolved"
            if match.get("status") == "qualified"
            and all(value["ownership_island_id"] is not None for value in targets)
            else "incomplete"
        )
    return _frontier_row(call_id, source_island, source_unit, "indirect_call", target, resolution)


def _unsupported_event_row(
    source_island: Mapping[str, Any], event: Mapping[str, Any], index: int
) -> dict[str, Any]:
    source_unit = _nonempty(event.get("source_unit_id"), "event source unit")
    return _frontier_row(
        _call_id(source_island["id"], source_unit, "unsupported", index),
        source_island,
        source_unit,
        str(event.get("kind", "unsupported")),
        {"kind": "unsupported_event"},
        "incomplete",
    )


def _frontier_row(
    call_id: str,
    source_island: Mapping[str, Any],
    source_unit: str,
    boundary_kind: str,
    target: Mapping[str, Any],
    resolution: str,
) -> dict[str, Any]:
    return {
        "id": call_id,
        "source": {
            "island_id": source_island["id"],
            "source_symbol": source_island["source_symbol"],
            "unit_id": source_unit,
        },
        "boundary_kind": boundary_kind,
        "target": copy.deepcopy(dict(target)),
        "resolution_status": resolution,
    }


def _static_target(owner: Mapping[str, Any], target_rva: int) -> dict[str, Any]:
    match = _object(owner.get("match"), "static target match")
    symbols = sorted(
        {
            str(symbol)
            for candidate in match.get("candidates", [])
            if isinstance(candidate, Mapping)
            for symbol in candidate.get("symbols", [])
        }
    )
    return {
        "kind": "static_library",
        "rva": target_rva,
        "ownership_island_id": owner["id"],
        "identity_status": match.get("identity_status"),
        "library_identities": copy.deepcopy(match.get("library_identities", [])),
        "symbols": symbols,
        "candidate_fingerprints": sorted(
            str(candidate.get("fingerprint_id"))
            for candidate in match.get("candidates", [])
            if isinstance(candidate, Mapping) and candidate.get("fingerprint_id")
        ),
    }


def _interface_matches_call(interface: Mapping[str, Any], call: Mapping[str, Any]) -> bool:
    selector = interface["selector"]
    target = call["target"]
    kind = selector["kind"]
    if kind == "dynamic_import":
        return target.get("kind") == "dynamic_import" and _import_key(
            selector
        ) == _import_key(_object(target.get("import"), "call import"))
    if kind == "static_library_symbol":
        return (
            target.get("kind") == "static_library"
            and selector.get("symbol") in target.get("symbols", [])
        )
    if kind == "exact_endpoint":
        return selector.get("endpoint_id") == call.get("id")
    if kind == "exact_cluster":
        return call.get("id") in selector.get("endpoint_ids", [])
    if kind == "project_internal":
        return (
            target.get("kind") == "project_internal"
            and selector.get("source_island_id") == target.get("source_island_id")
        )
    return False


def _walk_clang_ast(
    node: Mapping[str, Any],
    calls: list[dict[str, Any]],
    function_references: list[dict[str, Any]],
    root: Path,
    expected: Mapping[str, str],
    *,
    ast_path: tuple[int, ...],
    current_function: str | None,
    fallback_source: str | None,
    definitions: Mapping[str, Mapping[str, Any]],
    project_symbols: set[str],
) -> None:
    kind = node.get("kind")
    if kind == "FunctionDecl" and isinstance(node.get("name"), str):
        current_function = str(node["name"])
    if kind == "CallExpr":
        source = _clang_source_location(
            node, root, expected, fallback_source=fallback_source
        )
        if source is not None:
            callee = _clang_callee(node)
            call_id = "source-call:" + sha256(
                f"{source['path']}:{source['offset']}:{callee or 'indirect'}".encode("utf-8")
            ).hexdigest()[:24]
            calls.append(
                {
                    "id": call_id,
                    "kind": "direct" if callee is not None else "indirect",
                    "callee": callee,
                    "callee_scope": (
                        "project_boundary"
                        if callee in project_symbols
                        else "source_local"
                        if callee in definitions
                        else "external"
                    ),
                    "enclosing_function": current_function,
                    "source": source,
                    "type": copy.deepcopy(node.get("type")),
                    "argument_count": max(0, len(node.get("inner", [])) - 1),
                    "_ast_path": ast_path,
                }
            )
    if kind == "DeclRefExpr" and current_function is not None:
        referenced = node.get("referencedDecl")
        if isinstance(referenced, Mapping):
            target = referenced.get("name")
            if (
                referenced.get("kind") == "FunctionDecl"
                and isinstance(target, str)
                and target in definitions
            ):
                source = _clang_source_location(
                    node, root, expected, fallback_source=fallback_source
                )
                if source is not None:
                    reference_id = "source-function-reference:" + sha256(
                        (
                            f"{source['path']}:{source['offset']}:"
                            f"{current_function}:{target}"
                        ).encode("utf-8")
                    ).hexdigest()[:24]
                    function_references.append(
                        {
                            "id": reference_id,
                            "kind": "function_value",
                            "enclosing_function": current_function,
                            "target_symbol": target,
                            "target_scope": "source_local",
                            "source": source,
                            "_ast_path": ast_path,
                        }
                    )
    for child_index, child in enumerate(node.get("inner", []) or []):
        if isinstance(child, Mapping):
            _walk_clang_ast(
                child,
                calls,
                function_references,
                root,
                expected,
                ast_path=ast_path + (child_index,),
                current_function=current_function,
                fallback_source=fallback_source,
                definitions=definitions,
                project_symbols=project_symbols,
            )


def _disambiguate_source_artifact_ids(
    rows: list[dict[str, Any]], *, prefix: str
) -> None:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(str(row["id"]), []).append(row)
    for base_id, group in groups.items():
        ordered = sorted(group, key=lambda row: tuple(row["_ast_path"]))
        for occurrence, row in enumerate(ordered):
            ast_path = tuple(row.pop("_ast_path"))
            if len(ordered) == 1:
                continue
            path_text = ".".join(str(value) for value in ast_path)
            row["id"] = prefix + sha256(
                f"{base_id}:{path_text}".encode("ascii")
            ).hexdigest()[:24]
            row["source_occurrence"] = {
                "ordinal": occurrence,
                "count": len(ordered),
            }


def _clang_source_definitions(
    ast: Mapping[str, Any],
    root: Path,
    expected: Mapping[str, str],
    *,
    fallback_source: str | None,
) -> dict[str, Mapping[str, Any]]:
    definitions: dict[str, Mapping[str, Any]] = {}
    stack = [ast]
    while stack:
        node = stack.pop()
        if (
            node.get("kind") == "FunctionDecl"
            and isinstance(node.get("name"), str)
            and any(
                isinstance(child, Mapping) and child.get("kind") == "CompoundStmt"
                for child in node.get("inner", []) or []
            )
        ):
            source = _clang_source_location(
                node, root, expected, fallback_source=fallback_source
            )
            if source is not None:
                name = str(node["name"])
                if name in definitions:
                    raise SourceCallSubstitutionError(
                        f"duplicate source function definition: {name}"
                    )
                definitions[name] = source
        stack.extend(
            child
            for child in node.get("inner", []) or []
            if isinstance(child, Mapping)
        )
    return definitions


def _clang_source_location(
    node: Mapping[str, Any],
    root: Path,
    expected: Mapping[str, str],
    *,
    fallback_source: str | None,
) -> dict[str, Any] | None:
    begin = node.get("range", {}).get("begin", {})
    location = begin.get("expansionLoc", begin.get("spellingLoc", begin))
    file_name = location.get("file")
    offset = location.get("offset")
    if not isinstance(offset, int):
        return None
    if isinstance(file_name, str):
        relative = _match_inventory_source(file_name, root, expected)
        if relative is None:
            return None
    elif fallback_source is not None and "includedFrom" not in location:
        relative = fallback_source
    else:
        return None
    if relative not in expected:
        return None
    source_path = root / relative
    line = location.get("line")
    column = location.get("col")
    if not isinstance(line, int):
        prefix = source_path.read_bytes()[:offset]
        line = prefix.count(b"\n") + 1
    if not isinstance(column, int):
        prefix = source_path.read_bytes()[:offset]
        column = len(prefix.rsplit(b"\n", 1)[-1]) + 1
    return {
        "path": relative,
        "offset": offset,
        "line": line,
        "column": column,
    }


def _match_inventory_source(
    file_name: str, root: Path, expected: Mapping[str, str]
) -> str | None:
    path = Path(file_name)
    local = path if path.is_absolute() else root / path
    try:
        relative = local.resolve().relative_to(root).as_posix()
    except ValueError:
        relative = None
    if relative in expected:
        return relative

    # Nix may materialize the AST input and the source-root input from separate
    # store snapshots. Match only a unique relative suffix with the exact
    # checked source hash; a basename alone is never sufficient authority.
    if not local.is_file():
        return None
    digest = sha256_file(local)
    normalized = local.as_posix()
    matches = [
        candidate
        for candidate, expected_digest in expected.items()
        if expected_digest == digest
        and (normalized == candidate or normalized.endswith("/" + candidate))
    ]
    return matches[0] if len(matches) == 1 else None


def _clang_callee(node: Mapping[str, Any]) -> str | None:
    inner = node.get("inner", []) or []
    if not inner or not isinstance(inner[0], Mapping):
        return None
    stack = [inner[0]]
    while stack:
        current = stack.pop()
        if current.get("kind") == "DeclRefExpr":
            referenced = current.get("referencedDecl")
            if isinstance(referenced, Mapping) and referenced.get("kind") == "FunctionDecl":
                name = referenced.get("name")
                return str(name) if isinstance(name, str) else None
        stack.extend(
            child for child in current.get("inner", []) or [] if isinstance(child, Mapping)
        )
    return None


def _owner_at_rva(owners: Mapping[str, Any], rva: int) -> Mapping[str, Any] | None:
    matches = [
        island
        for start, end, island in owners["spans"]
        if start <= rva < end
    ]
    if len(matches) > 1:
        raise SourceCallSubstitutionError(f"multiple islands own RVA 0x{rva:x}")
    return matches[0] if matches else None


def _entry_unit_id(owner: Mapping[str, Any], target_rva: int) -> str:
    # Machine unit identities include the exact cutpoint RVA; select the one
    # whose normalized identifier starts at the target when possible.
    marker = f"-{target_rva:08x}-"
    for unit_id in owner.get("unit_ids", []):
        if marker in str(unit_id):
            return str(unit_id)
    return ""


def _call_id(island: Any, unit: str, kind: str, index: int) -> str:
    return "call:" + sha256(
        f"{island}:{unit}:{kind}:{index}".encode("utf-8")
    ).hexdigest()[:24]


def _append_unique(
    rows: list[dict[str, Any]], seen: set[str], row: dict[str, Any]
) -> None:
    if row["id"] in seen:
        raise SourceCallSubstitutionError(f"duplicate call frontier ID: {row['id']}")
    seen.add(row["id"])
    rows.append(row)


def _frontier_issue(row: Mapping[str, Any]) -> dict[str, Any]:
    return _issue(
        "incomplete",
        "call_target_unresolved",
        call_id=row["id"],
        source_island_id=row["source"]["island_id"],
        source_unit_id=row["source"]["unit_id"],
        target_kind=row["target"]["kind"],
        target_rva=row["target"].get("rva"),
    )


def _frontier_sort_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (row["source"]["island_id"], row["source"]["unit_id"], row["id"])


def _issue(status: str, code: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "code": code, **details}


def _issue_sort_key(issue: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(issue.get("status", "")),
        str(issue.get("code", "")),
        json.dumps(issue, sort_keys=True, separators=(",", ":")),
    )


def _status_from_issues(issues: Iterable[Mapping[str, Any]], *, success: str) -> str:
    rows = list(issues)
    if any(item.get("status") == "violated" for item in rows):
        return "violated"
    return "incomplete" if rows else success


def _load_bound_catalog(
    value: Path | str | Mapping[str, Any],
    label: str,
    binder: Any,
    *,
    hash_key: str = "catalog_sha256",
) -> dict[str, Any]:
    payload = (
        copy.deepcopy(dict(value))
        if isinstance(value, Mapping)
        else _read_object(Path(value), label)
    )
    expected = payload.get(hash_key)
    checked = binder(payload)
    if expected != checked[hash_key]:
        raise SourceCallSubstitutionError(f"{label} self-hash is stale")
    return payload


def _read_hashed(path: Path, format_name: str, hash_key: str, label: str) -> dict[str, Any]:
    payload = _read_object(path, label)
    if payload.get("format") != format_name:
        raise SourceCallSubstitutionError(f"unsupported {label} format")
    core = copy.deepcopy(payload)
    observed = core.pop(hash_key, None)
    if observed != _canonical_sha256(core):
        raise SourceCallSubstitutionError(f"{label} self-hash is stale")
    return payload


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SourceCallSubstitutionError(f"cannot read {label}: {error}") from error
    return dict(_object(value, label))


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SourceCallSubstitutionError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SourceCallSubstitutionError(f"{label} must be an array")
    return value


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SourceCallSubstitutionError(f"{label} must be a non-empty string")
    return value


def _sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SourceCallSubstitutionError(f"{label} must be a lowercase SHA-256")
    return value


def _canonical_sha256(value: Any) -> str:
    return sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()


def _import_key(value: Mapping[str, Any]) -> tuple[str, str | None, int | None]:
    imported = value.get("import") if isinstance(value.get("import"), Mapping) else value
    assert isinstance(imported, Mapping)
    dll = _nonempty(imported.get("dll"), "import DLL").lower()
    symbol = imported.get("symbol")
    ordinal = imported.get("ordinal")
    if (isinstance(symbol, str) and bool(symbol)) == isinstance(ordinal, int):
        raise SourceCallSubstitutionError(
            "import must select exactly one nonempty symbol or integer ordinal"
        )
    return (
        dll,
        symbol if isinstance(symbol, str) else None,
        int(ordinal) if isinstance(ordinal, int) else None,
    )


def _import_dict(value: tuple[str, str | None, int | None]) -> dict[str, Any]:
    return {"dll": value[0], "symbol": value[1], "ordinal": value[2]}


__all__ = [
    "SourceCallSubstitutionError",
    "audit_candidate_dependencies",
    "bind_allowed_runtime_imports",
    "bind_call_substitution_assignments",
    "bind_callable_interface_catalog",
    "bind_source_call_bindings",
    "bind_source_substitution_catalog",
    "check_source_call_bindings",
    "derive_static_indirect_call_targets",
    "generate_call_frontier",
    "inventory_clang_source_calls",
    "plan_call_substitutions",
    "propose_source_component_artifacts",
    "propose_source_component_bindings",
]
