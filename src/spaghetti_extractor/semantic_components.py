"""Validate hierarchical semantic components against reconstruction machine IR.

Components are operator-authored validation and source-organization units.  A
component may contain one block, a non-contiguous procedure, a subsystem, or
other components.  This module validates those declarations and derives their
machine boundaries from the canonical static IR.  It does not infer logical
interfaces, generate implementations, execute the original binary, or confer
Stage A proof authority.
"""

from __future__ import annotations

import copy
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .artifact_formats import (
    RECONSTRUCTION_PLAN_FORMAT,
    SEMANTIC_COMPONENT_CATALOG_FORMAT,
    SEMANTIC_COMPONENT_DECLARATIONS_FORMAT,
)
from .linked_library_contracts import (
    LinkedLibraryContractError,
    validate_linked_island_manifest,
)
from .util import sha256_file, write_json


MACHINE_IR_FORMAT = "stage-a-machine-ir-v2"
MACHINE_IR_FILENAME = "machine-ir.jsonl"
MACHINE_IR_MANIFEST_FILENAME = "machine-ir-manifest.json"

_COMPONENT_ID_RE = re.compile(r"^[a-z][a-z0-9._-]*$")
_KINDS = {"inline", "procedure", "subsystem", "aggregate"}
_SHARING = {"exclusive", "shared"}
_REACHABILITY = {"exact", "potential", "mixed", "any"}
_LOGICAL_STATUSES = {"proposed", "reviewed", "not_applicable"}
_REFINEMENT_STATUSES = {"not_started", "in_progress", "validated", "not_applicable"}
_EMISSION_POLICIES = {"inline", "function", "subsystem", "none"}
_EVIDENCE_CLASSES = {
    "formal",
    "exhaustive",
    "solver",
    "differential",
    "fuzzed",
    "integration",
    "assumed",
    "unsupported",
}


class SemanticComponentError(ValueError):
    """Semantic component inputs are structurally malformed."""


@dataclass(frozen=True)
class LogicalInterface:
    status: str
    parameters: tuple[dict[str, Any], ...]
    results: tuple[dict[str, Any], ...]
    objects: tuple[dict[str, Any], ...]
    persistent_state: tuple[dict[str, Any], ...]
    services: tuple[dict[str, Any], ...]
    preconditions: tuple[dict[str, Any], ...]
    postconditions: tuple[dict[str, Any], ...]
    observations: tuple[dict[str, Any], ...]

    def payload(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "authority": "operator_proposal_not_machine_truth",
            "parameters": copy.deepcopy(list(self.parameters)),
            "results": copy.deepcopy(list(self.results)),
            "objects": copy.deepcopy(list(self.objects)),
            "persistent_state": copy.deepcopy(list(self.persistent_state)),
            "services": copy.deepcopy(list(self.services)),
            "preconditions": copy.deepcopy(list(self.preconditions)),
            "postconditions": copy.deepcopy(list(self.postconditions)),
            "observations": copy.deepcopy(list(self.observations)),
        }


@dataclass(frozen=True)
class ComponentDeclaration:
    identity: str
    label: str
    purpose: str
    kind: str
    sharing: str
    expected_reachability: str
    unit_ids: tuple[str, ...]
    cluster_ids: tuple[str, ...]
    child_ids: tuple[str, ...]
    component_calls: tuple[dict[str, Any], ...]
    logical_interface: LogicalInterface
    refinement_status: str
    refinement_stages: tuple[dict[str, Any], ...]
    emission_policy: str
    emission_symbol: str | None
    evidence: tuple[dict[str, Any], ...]
    assumptions: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class _MachineInputs:
    manifest_path: Path
    ir_path: Path
    manifest: dict[str, Any]
    units: tuple[dict[str, Any], ...]
    units_by_id: dict[str, dict[str, Any]]
    units_by_rva: dict[int, dict[str, Any]]


def build_semantic_component_catalog(
    *,
    machine_ir: Path | str,
    reconstruction_plan: Path | str,
    declarations: Path | str | Mapping[str, Any],
    linked_islands: Path | str | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Check component declarations and derive their exact static boundaries."""

    machine = _load_machine_inputs(Path(machine_ir))
    plan_path, plan = _load_plan(Path(reconstruction_plan))
    declaration_payload, declaration_sha256 = _load_declarations(declarations)
    parsed = _parse_declarations(declaration_payload)
    linked_scope = _load_linked_island_scope(linked_islands, machine=machine)

    issues: list[dict[str, Any]] = []
    _check_bindings(
        declaration_payload,
        machine=machine,
        plan=plan,
        plan_path=plan_path,
        issues=issues,
    )
    _check_source_consistency(machine=machine, plan=plan, issues=issues)

    plan_clusters = {
        str(item.get("id")): item
        for item in _array(plan.get("clusters"), "reconstruction plan clusters")
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    declarations_by_id = {item.identity: item for item in parsed}
    direct_members: dict[str, set[str]] = {}
    for declaration in parsed:
        resolved = set(declaration.unit_ids)
        for unit_id in declaration.unit_ids:
            if unit_id not in machine.units_by_id:
                _issue(
                    issues,
                    "violated",
                    "unknown_component_unit",
                    f"component references unknown machine unit {unit_id!r}",
                    component_id=declaration.identity,
                    unit_id=unit_id,
                )
        for cluster_id in declaration.cluster_ids:
            cluster = plan_clusters.get(cluster_id)
            if cluster is None:
                _issue(
                    issues,
                    "violated",
                    "unknown_component_cluster",
                    f"component references unknown reconstruction cluster {cluster_id!r}",
                    component_id=declaration.identity,
                )
                continue
            resolved.update(
                str(value)
                for value in _array(
                    cluster.get("unit_ids"), f"cluster {cluster_id} unit ids"
                )
            )
            for unit_id in cluster.get("unit_ids", []):
                if str(unit_id) not in machine.units_by_id:
                    _issue(
                        issues,
                        "violated",
                        "unknown_cluster_member",
                        "reconstruction cluster references an unknown machine unit",
                        component_id=declaration.identity,
                        cluster_id=cluster_id,
                        unit_id=str(unit_id),
                    )
        direct_members[declaration.identity] = {
            unit_id for unit_id in resolved if unit_id in machine.units_by_id
        }
        for child_id in declaration.child_ids:
            if child_id not in declarations_by_id:
                _issue(
                    issues,
                    "violated",
                    "unknown_component_child",
                    f"component references unknown child {child_id!r}",
                    component_id=declaration.identity,
                )

    ancestors, hierarchy_valid = _check_hierarchy(parsed, issues)
    resolved_members = _resolve_members(parsed, direct_members, hierarchy_valid)
    _check_component_overlaps(parsed, resolved_members, ancestors, issues)
    _check_component_call_dependencies(
        machine=machine,
        declarations=parsed,
        resolved_members=resolved_members,
        issues=issues,
    )

    graph = _machine_graph(machine)
    _check_machine_control_inventory(machine, issues)
    component_payloads: list[dict[str, Any]] = []
    for declaration in parsed:
        members = resolved_members.get(declaration.identity, set())
        component_issues = [
            issue for issue in issues if issue.get("component_id") == declaration.identity
        ]
        boundary = _derive_boundary(machine, graph, members)
        reachability = _component_reachability(machine, members)
        if not members:
            _issue(
                issues,
                "violated",
                "empty_component",
                "component resolves to no machine units",
                component_id=declaration.identity,
            )
        if (
            members
            and declaration.expected_reachability != "any"
            and reachability["classification"] != declaration.expected_reachability
        ):
            _issue(
                issues,
                "violated",
                "component_reachability_mismatch",
                "derived reachability does not match the declaration",
                component_id=declaration.identity,
                expected=declaration.expected_reachability,
                observed=reachability["classification"],
            )
        component_issues = [
            issue for issue in issues if issue.get("component_id") == declaration.identity
        ]
        definition_status = (
            "violated"
            if any(issue["status"] == "violated" for issue in component_issues)
            else "valid"
        )
        membership_spans = _membership_spans(machine, members)
        effective_refinement_status = (
            "not_applicable"
            if declaration.refinement_status == "not_applicable"
            else "not_started"
        )
        component_core = {
            "id": declaration.identity,
            "label": declaration.label,
            "purpose": declaration.purpose,
            "kind": declaration.kind,
            "sharing": declaration.sharing,
            "definition_status": definition_status,
            "refinement_status": effective_refinement_status,
            "implementation_status": (
                "not_required"
                if effective_refinement_status == "not_applicable"
                else "not_implemented"
            ),
            "membership": {
                "direct_unit_ids": sorted(direct_members.get(declaration.identity, set())),
                "resolved_unit_ids": sorted(members),
                "cluster_ids": list(declaration.cluster_ids),
                "child_ids": list(declaration.child_ids),
                "rva_spans": membership_spans,
                "noncontiguous": len(membership_spans) > 1,
            },
            "reachability": reachability,
            "machine_boundary": boundary,
            "component_calls": copy.deepcopy(list(declaration.component_calls)),
            "logical_interface": declaration.logical_interface.payload(),
            "refinement": {
                "status": effective_refinement_status,
                "declared_status": declaration.refinement_status,
                "stages": copy.deepcopy(list(declaration.refinement_stages)),
                "machine_to_logical_projection_validated": False,
            },
            "emission": {
                "policy": declaration.emission_policy,
                **(
                    {"symbol": declaration.emission_symbol}
                    if declaration.emission_symbol is not None
                    else {}
                ),
            },
            "evidence": copy.deepcopy(list(declaration.evidence)),
            "assumptions": copy.deepcopy(list(declaration.assumptions)),
            "issues": component_issues,
        }
        if linked_scope is not None:
            component_core["linked_island_membership"] = (
                _component_linked_island_membership(linked_scope, members)
            )
        component_payloads.append(
            {
                **component_core,
                "component_sha256": _canonical_sha256(component_core),
            }
        )

    component_payloads.sort(key=lambda item: item["id"])
    coverage = _coverage_ledger(machine, parsed, direct_members, resolved_members)
    if linked_scope is not None:
        coverage["linked_islands"] = _component_catalog_linked_coverage(
            linked_scope,
            declared_units=set().union(*resolved_members.values()),
        )
    status = "violated" if any(item["status"] == "violated" for item in issues) else "incomplete"
    result = {
        "format": SEMANTIC_COMPONENT_CATALOG_FORMAT,
        "status": status,
        "definition_status": "violated" if status == "violated" else "valid",
        "assurance_status": "incomplete",
        "proof_authority": "none",
        "executes_original_binary": False,
        "generates_component_implementations": False,
        "program_id": declaration_payload["program_id"],
        "bindings": {
            "declarations_sha256": declaration_sha256,
            "machine_ir_sha256": machine.manifest["artifacts"]["machine_ir"]["sha256"],
            "machine_ir_manifest_sha256": sha256_file(machine.manifest_path),
            "reconstruction_plan_sha256": plan["plan_sha256"],
            "original_binary_sha256": machine.manifest["binary"]["sha256"],
            **(
                {
                    "linked_island_manifest_sha256": linked_scope[
                        "manifest_sha256"
                    ]
                }
                if linked_scope is not None
                else {}
            ),
        },
        "policy": {
            "machine_boundary_authority": "canonical_full_machine_state_v1",
            "logical_interface_authority": "operator_proposal_until_refined",
            "logical_interface_activation_gate": (
                "checked_stage_b_component_interface_refinement_v1_required"
            ),
            "declaration_refinement_status_authority": "none",
            "membership_authority": "exact_machine_unit_ids_checked_against_machine_ir",
            "overlap_policy": "nested_or_explicit_shared_component_only",
            "acceptance_authority": "none",
            "linked_island_identity_authorizes_replacement": False,
        },
        "components": component_payloads,
        "coverage": coverage,
        "issues": sorted(issues, key=_issue_sort_key),
        "counts": {
            "components": len(component_payloads),
            "leaf_components": sum(not item["membership"]["child_ids"] for item in component_payloads),
            "aggregate_components": sum(item["kind"] == "aggregate" for item in component_payloads),
            "valid_definitions": sum(item["definition_status"] == "valid" for item in component_payloads),
            "validated_refinements": 0,
            "declared_units": coverage["counts"]["declared_units"],
            "unassigned_exact_reachable_units": coverage["counts"]["unassigned_exact_reachable_units"],
            "issues": len(issues),
        },
    }
    result["catalog_sha256"] = _canonical_sha256(result)
    return result


def write_semantic_component_catalog(
    *,
    machine_ir: Path | str,
    reconstruction_plan: Path | str,
    declarations: Path | str | Mapping[str, Any],
    linked_islands: Path | str | Mapping[str, Any] | None = None,
    out: Path | str,
) -> dict[str, Any]:
    payload = build_semantic_component_catalog(
        machine_ir=machine_ir,
        reconstruction_plan=reconstruction_plan,
        declarations=declarations,
        linked_islands=linked_islands,
    )
    write_json(Path(out), payload)
    return payload


def _load_linked_island_scope(
    linked_islands: Path | str | Mapping[str, Any] | None,
    *,
    machine: _MachineInputs,
) -> dict[str, Any] | None:
    if linked_islands is None:
        return None
    manifest = (
        copy.deepcopy(dict(linked_islands))
        if isinstance(linked_islands, Mapping)
        else _json_object(Path(linked_islands), "linked-island manifest")
    )
    try:
        validate_linked_island_manifest(manifest)
    except LinkedLibraryContractError as error:
        raise SemanticComponentError(
            f"invalid linked-island manifest: {error}"
        ) from error
    bindings = _object(manifest.get("bindings"), "linked-island bindings")
    expected = {
        "original_binary_sha256": machine.manifest["binary"]["sha256"],
        "machine_ir_sha256": machine.manifest["artifacts"]["machine_ir"][
            "sha256"
        ],
        "machine_ir_manifest_sha256": sha256_file(machine.manifest_path),
    }
    stale = {
        key: {"expected": value, "observed": bindings.get(key)}
        for key, value in expected.items()
        if bindings.get(key) != value
    }
    if stale:
        raise SemanticComponentError(
            f"semantic components/linked-island binding is stale: {stale}"
        )
    owner_by_unit: dict[str, Mapping[str, Any]] = {}
    for raw_island in _array(manifest.get("islands"), "linked islands"):
        island = _object(raw_island, "linked island")
        for unit_id in _array(island.get("unit_ids"), "linked island units"):
            owner_by_unit[str(unit_id)] = island
    if set(owner_by_unit) != set(machine.units_by_id):
        raise SemanticComponentError(
            "linked-island manifest does not classify the exact machine-IR unit set"
        )
    return {
        "manifest_sha256": manifest["manifest_sha256"],
        "status": manifest.get("status"),
        "islands": manifest["islands"],
        "owner_by_unit": owner_by_unit,
    }


def _component_linked_island_membership(
    linked_scope: Mapping[str, Any],
    members: set[str],
) -> dict[str, Any]:
    owner_by_unit = _object(
        linked_scope.get("owner_by_unit"), "linked-island unit ownership"
    )
    grouped: dict[str, dict[str, Any]] = {}
    for unit_id in sorted(members):
        island = _object(owner_by_unit[unit_id], "linked island")
        island_id = str(island["id"])
        grouped.setdefault(
            island_id,
            {"island_id": island_id, "kind": island["kind"], "unit_ids": []},
        )["unit_ids"].append(unit_id)
    rows = []
    for row in sorted(grouped.values(), key=lambda item: item["island_id"]):
        rows.append({**row, "unit_count": len(row["unit_ids"])})
    kinds = sorted({str(row["kind"]) for row in rows})
    return {
        "manifest_sha256": linked_scope["manifest_sha256"],
        "islands": rows,
        "kinds": kinds,
        "crosses_island_boundaries": len(rows) > 1,
        "crosses_ownership_kinds": len(kinds) > 1,
        "identity_authorizes_replacement": False,
    }


def _component_catalog_linked_coverage(
    linked_scope: Mapping[str, Any],
    *,
    declared_units: set[str],
) -> dict[str, Any]:
    owner_by_unit = _object(
        linked_scope.get("owner_by_unit"), "linked-island unit ownership"
    )
    totals: dict[str, int] = defaultdict(int)
    declared: dict[str, int] = defaultdict(int)
    for unit_id, raw_island in owner_by_unit.items():
        island = _object(raw_island, "linked island")
        kind = str(island["kind"])
        totals[kind] += 1
        if unit_id in declared_units:
            declared[kind] += 1
    return {
        "manifest_sha256": linked_scope["manifest_sha256"],
        "classification_status": linked_scope["status"],
        "machine_units_by_kind": dict(sorted(totals.items())),
        "component_declared_units_by_kind": dict(sorted(declared.items())),
        "remaining_units_by_kind": {
            kind: count - declared.get(kind, 0)
            for kind, count in sorted(totals.items())
        },
        "identity_authorizes_replacement": False,
    }


def _load_machine_inputs(path: Path) -> _MachineInputs:
    manifest_path = path / MACHINE_IR_MANIFEST_FILENAME if path.is_dir() else path
    if not manifest_path.is_file():
        raise SemanticComponentError(f"machine IR manifest does not exist: {manifest_path}")
    manifest = _json_object(manifest_path, "machine IR manifest")
    if manifest.get("format") != MACHINE_IR_FORMAT:
        raise SemanticComponentError("machine IR manifest has an unsupported format")
    artifact = _object(_object(manifest.get("artifacts"), "machine IR artifacts").get("machine_ir"), "machine IR artifact")
    ir_path = manifest_path.parent / str(artifact.get("path", MACHINE_IR_FILENAME))
    if not ir_path.is_file():
        raise SemanticComponentError(f"machine IR JSONL does not exist: {ir_path}")
    if sha256_file(ir_path) != artifact.get("sha256"):
        raise SemanticComponentError("machine IR JSONL hash does not match its manifest")
    units = tuple(_read_jsonl(ir_path))
    units_by_id: dict[str, dict[str, Any]] = {}
    units_by_rva: dict[int, dict[str, Any]] = {}
    for unit in units:
        identity = unit.get("id")
        if not isinstance(identity, str) or not identity:
            raise SemanticComponentError("machine IR unit has no stable id")
        if identity in units_by_id:
            raise SemanticComponentError(f"duplicate machine IR unit id {identity!r}")
        rva = _unit_start(unit)
        if rva in units_by_rva:
            raise SemanticComponentError(f"duplicate machine IR unit RVA 0x{rva:x}")
        units_by_id[identity] = unit
        units_by_rva[rva] = unit
    return _MachineInputs(manifest_path, ir_path, manifest, units, units_by_id, units_by_rva)


def _load_plan(path: Path) -> tuple[Path, dict[str, Any]]:
    plan_path = path / "reconstruction-plan.json" if path.is_dir() else path
    plan = _json_object(plan_path, "reconstruction plan")
    if plan.get("format") != RECONSTRUCTION_PLAN_FORMAT:
        raise SemanticComponentError("reconstruction plan has an unsupported format")
    return plan_path, plan


def _load_declarations(value: Path | str | Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    if isinstance(value, Mapping):
        payload = _json_copy(value, "semantic component declarations")
        return payload, _canonical_sha256(payload)
    path = Path(value)
    payload = _json_object(path, "semantic component declarations")
    return payload, sha256_file(path)


def _parse_declarations(payload: Mapping[str, Any]) -> tuple[ComponentDeclaration, ...]:
    if payload.get("format") != SEMANTIC_COMPONENT_DECLARATIONS_FORMAT:
        raise SemanticComponentError("semantic component declarations have an unsupported format")
    if not isinstance(payload.get("program_id"), str) or not payload["program_id"]:
        raise SemanticComponentError("semantic component declarations require program_id")
    raw_components = _array(payload.get("components"), "semantic components")
    result: list[ComponentDeclaration] = []
    identities: set[str] = set()
    for index, raw in enumerate(raw_components):
        item = _object(raw, f"component {index}")
        identity = _nonempty_string(item.get("id"), f"component {index} id")
        if not _COMPONENT_ID_RE.fullmatch(identity):
            raise SemanticComponentError(f"component id {identity!r} is not canonical")
        if identity in identities:
            raise SemanticComponentError(f"duplicate component id {identity!r}")
        identities.add(identity)
        kind = _enum(item.get("kind"), _KINDS, f"component {identity} kind")
        sharing = _enum(item.get("sharing", "exclusive"), _SHARING, f"component {identity} sharing")
        expected = _enum(item.get("expected_reachability", "any"), _REACHABILITY, f"component {identity} reachability")
        membership = _object(item.get("membership"), f"component {identity} membership")
        logical = _parse_logical_interface(item.get("logical_interface"), identity)
        refinement = _object(item.get("refinement"), f"component {identity} refinement")
        refinement_status = _enum(refinement.get("status"), _REFINEMENT_STATUSES, f"component {identity} refinement status")
        emission = _object(item.get("emission"), f"component {identity} emission")
        emission_policy = _enum(emission.get("policy"), _EMISSION_POLICIES, f"component {identity} emission policy")
        symbol = emission.get("symbol")
        if symbol is not None and (not isinstance(symbol, str) or not symbol):
            raise SemanticComponentError(f"component {identity} emission symbol must be a non-empty string")
        evidence = tuple(_object_sequence(item.get("evidence", []), f"component {identity} evidence"))
        for entry in evidence:
            _enum(entry.get("class"), _EVIDENCE_CLASSES, f"component {identity} evidence class")
        result.append(
            ComponentDeclaration(
                identity=identity,
                label=_nonempty_string(item.get("label"), f"component {identity} label"),
                purpose=_nonempty_string(item.get("purpose"), f"component {identity} purpose"),
                kind=kind,
                sharing=sharing,
                expected_reachability=expected,
                unit_ids=_string_sequence(membership.get("unit_ids", []), f"component {identity} unit ids"),
                cluster_ids=_string_sequence(membership.get("cluster_ids", []), f"component {identity} cluster ids"),
                child_ids=_string_sequence(item.get("children", []), f"component {identity} children"),
                component_calls=tuple(
                    _object_sequence(
                        item.get("component_calls", []),
                        f"component {identity} component calls",
                    )
                ),
                logical_interface=logical,
                refinement_status=refinement_status,
                refinement_stages=tuple(_object_sequence(refinement.get("stages", []), f"component {identity} refinement stages")),
                emission_policy=emission_policy,
                emission_symbol=symbol,
                evidence=evidence,
                assumptions=tuple(_object_sequence(item.get("assumptions", []), f"component {identity} assumptions")),
            )
        )
    if not result:
        raise SemanticComponentError("semantic component declarations contain no components")
    return tuple(result)


def _parse_logical_interface(value: Any, component_id: str) -> LogicalInterface:
    item = _object(value, f"component {component_id} logical interface")
    status = _enum(item.get("status"), _LOGICAL_STATUSES, f"component {component_id} logical interface status")
    fields = {}
    for name in (
        "parameters",
        "results",
        "objects",
        "persistent_state",
        "services",
        "preconditions",
        "postconditions",
        "observations",
    ):
        fields[name] = tuple(_object_sequence(item.get(name, []), f"component {component_id} logical {name}"))
    return LogicalInterface(status=status, **fields)


def _check_bindings(
    declarations: Mapping[str, Any], *, machine: _MachineInputs, plan: Mapping[str, Any], plan_path: Path, issues: list[dict[str, Any]]
) -> None:
    bindings = _object(declarations.get("bindings"), "semantic component bindings")
    expected = {
        "machine_ir_sha256": machine.manifest["artifacts"]["machine_ir"]["sha256"],
        "machine_ir_manifest_sha256": sha256_file(machine.manifest_path),
        "reconstruction_plan_sha256": plan.get("plan_sha256"),
        "original_binary_sha256": machine.manifest["binary"]["sha256"],
    }
    for field, observed in expected.items():
        if bindings.get(field) != observed:
            _issue(
                issues,
                "violated",
                "component_binding_mismatch",
                f"component declaration binding {field} is stale",
                expected=observed,
                observed=bindings.get(field),
                artifact=str(plan_path if field == "reconstruction_plan_sha256" else machine.manifest_path),
            )


def _check_source_consistency(
    *, machine: _MachineInputs, plan: Mapping[str, Any], issues: list[dict[str, Any]]
) -> None:
    plan_core = {key: copy.deepcopy(value) for key, value in plan.items() if key != "plan_sha256"}
    observed_plan_sha256 = plan.get("plan_sha256")
    expected_plan_sha256 = _canonical_sha256(plan_core)
    if observed_plan_sha256 != expected_plan_sha256:
        _issue(
            issues,
            "violated",
            "reconstruction_plan_digest_mismatch",
            "reconstruction plan content does not match plan_sha256",
            expected=expected_plan_sha256,
            observed=observed_plan_sha256,
        )
    inputs = plan.get("inputs")
    machine_binding = inputs.get("machine_ir") if isinstance(inputs, Mapping) else None
    expected_binding = {
        "format": machine.manifest.get("format"),
        "sha256": machine.manifest["artifacts"]["machine_ir"]["sha256"],
        "manifest_sha256": sha256_file(machine.manifest_path),
    }
    if not isinstance(machine_binding, Mapping):
        _issue(
            issues,
            "violated",
            "missing_plan_machine_ir_binding",
            "reconstruction plan has no machine IR binding",
            expected=expected_binding,
            observed=machine_binding,
        )
        return
    for field, expected in expected_binding.items():
        if machine_binding.get(field) != expected:
            _issue(
                issues,
                "violated",
                "plan_machine_ir_binding_mismatch",
                f"reconstruction plan machine IR {field} is stale",
                field=field,
                expected=expected,
                observed=machine_binding.get(field),
            )


def _check_machine_control_inventory(
    machine: _MachineInputs, issues: list[dict[str, Any]]
) -> None:
    control = machine.manifest.get("control")
    if not isinstance(control, Mapping):
        _issue(
            issues,
            "violated",
            "missing_machine_control_inventory",
            "machine IR manifest has no control inventory",
        )
        return
    for root in control.get("roots", []):
        if not isinstance(root, Mapping) or not isinstance(root.get("rva"), int):
            _issue(
                issues,
                "violated",
                "malformed_machine_root",
                "machine control root has no exact RVA",
                observed=root,
            )
            continue
        if int(root["rva"]) not in machine.units_by_rva:
            _issue(
                issues,
                "violated",
                "unknown_machine_root",
                "machine control root does not name a machine unit",
                rva=int(root["rva"]),
            )
    for certificate in control.get("recovered_indirect_targets", []):
        if not isinstance(certificate, Mapping):
            _issue(
                issues,
                "violated",
                "malformed_indirect_certificate",
                "indirect-control certificate is not an object",
            )
            continue
        source_id = certificate.get("source_unit_id")
        if not isinstance(source_id, str) or source_id not in machine.units_by_id:
            _issue(
                issues,
                "violated",
                "unknown_indirect_source",
                "indirect-control certificate names an unknown source unit",
                certificate_id=certificate.get("id"),
                unit_id=source_id,
            )
        for target_id in certificate.get("target_unit_ids", []):
            if not isinstance(target_id, str) or target_id not in machine.units_by_id:
                _issue(
                    issues,
                    "violated",
                    "unknown_indirect_target",
                    "indirect-control certificate names an unknown target unit",
                    certificate_id=certificate.get("id"),
                    unit_id=target_id,
                )


def _check_hierarchy(
    declarations: Sequence[ComponentDeclaration], issues: list[dict[str, Any]]
) -> tuple[dict[str, set[str]], bool]:
    by_id = {item.identity: item for item in declarations}
    parents: dict[str, list[str]] = defaultdict(list)
    for item in declarations:
        for child in item.child_ids:
            if child in by_id:
                parents[child].append(item.identity)
    for child, owner_ids in parents.items():
        if len(owner_ids) > 1 and by_id[child].sharing != "shared":
            _issue(
                issues,
                "violated",
                "component_multiple_parents",
                "an exclusive component has multiple parents",
                component_id=child,
                parent_ids=sorted(owner_ids),
            )

    state: dict[str, int] = {}
    ancestors: dict[str, set[str]] = {item.identity: set() for item in declarations}
    valid = True

    def visit(identity: str, path: tuple[str, ...]) -> None:
        nonlocal valid
        marker = state.get(identity, 0)
        if marker == 1:
            valid = False
            _issue(
                issues,
                "violated",
                "component_hierarchy_cycle",
                "component hierarchy contains a cycle",
                component_id=identity,
                cycle=list(path + (identity,)),
            )
            return
        if marker == 2:
            return
        state[identity] = 1
        for child in by_id[identity].child_ids:
            if child not in by_id:
                continue
            ancestors[child].add(identity)
            ancestors[child].update(ancestors[identity])
            visit(child, path + (identity,))
        state[identity] = 2

    for identity in sorted(by_id):
        visit(identity, ())
    # Propagate transitive parents after every path has been explored.
    changed = True
    while changed:
        changed = False
        for child, direct_parents in parents.items():
            expanded = set(direct_parents)
            for parent in direct_parents:
                expanded.update(ancestors[parent])
            if not expanded.issubset(ancestors[child]):
                ancestors[child].update(expanded)
                changed = True
    return ancestors, valid


def _resolve_members(
    declarations: Sequence[ComponentDeclaration], direct: Mapping[str, set[str]], hierarchy_valid: bool
) -> dict[str, set[str]]:
    if not hierarchy_valid:
        return {key: set(value) for key, value in direct.items()}
    by_id = {item.identity: item for item in declarations}
    cache: dict[str, set[str]] = {}

    def resolve(identity: str) -> set[str]:
        if identity in cache:
            return cache[identity]
        result = set(direct.get(identity, set()))
        for child in by_id[identity].child_ids:
            if child in by_id:
                result.update(resolve(child))
        cache[identity] = result
        return result

    for identity in by_id:
        resolve(identity)
    return cache


def _check_component_overlaps(
    declarations: Sequence[ComponentDeclaration], resolved: Mapping[str, set[str]], ancestors: Mapping[str, set[str]], issues: list[dict[str, Any]]
) -> None:
    shared_components = [item for item in declarations if item.sharing == "shared"]
    ordered = sorted(item.identity for item in declarations)
    for index, left in enumerate(ordered):
        for right in ordered[index + 1 :]:
            overlap = resolved.get(left, set()) & resolved.get(right, set())
            if not overlap:
                continue
            if left in ancestors.get(right, set()) or right in ancestors.get(left, set()):
                continue
            shared_cover: set[str] = set()
            for shared in shared_components:
                shared_ancestors = ancestors.get(shared.identity, set())
                if left in shared_ancestors and right in shared_ancestors:
                    shared_cover.update(resolved.get(shared.identity, set()))
            if overlap.issubset(shared_cover):
                continue
            _issue(
                issues,
                "violated",
                "incomparable_component_overlap",
                "overlapping membership is only valid through component nesting",
                component_id=left,
                other_component_id=right,
                unit_ids=sorted(overlap),
            )


def _check_component_call_dependencies(
    *,
    machine: _MachineInputs,
    declarations: Sequence[ComponentDeclaration],
    resolved_members: Mapping[str, set[str]],
    issues: list[dict[str, Any]],
) -> None:
    by_id = {item.identity: item for item in declarations}
    for declaration in declarations:
        members = resolved_members.get(declaration.identity, set())
        declared_calls: set[tuple[str, int]] = set()
        for dependency in declaration.component_calls:
            core = copy.deepcopy(dict(dependency))
            observed_hash = core.pop("dependency_sha256", None)
            target_component_id = dependency.get("target_component_id")
            target_rva = dependency.get("target_rva")
            target_unit_id = dependency.get("target_unit_id")
            target = by_id.get(str(target_component_id))
            target_members = resolved_members.get(str(target_component_id), set())
            valid = (
                observed_hash == _canonical_sha256(core)
                and target is not None
                and target_component_id != declaration.identity
                and isinstance(target_rva, int)
                and isinstance(target_unit_id, str)
                and target_unit_id in target_members
                and target_unit_id in machine.units_by_id
                and _unit_start(machine.units_by_id[target_unit_id]) == target_rva
            )
            callsites = dependency.get("callsites")
            if not isinstance(callsites, list) or not callsites:
                valid = False
                callsites = []
            for callsite in callsites:
                if not isinstance(callsite, Mapping):
                    valid = False
                    continue
                source_id = callsite.get("source_unit_id")
                source = machine.units_by_id.get(str(source_id))
                if source_id not in members or source is None:
                    valid = False
                    continue
                events = _mapping(
                    source.get("semantics"), f"unit {source_id} semantics"
                ).get("external_events", [])
                matches = [
                    event
                    for event in events
                    if isinstance(event, Mapping)
                    and event.get("kind") == "internal_call"
                    and event.get("target_rva") == target_rva
                ]
                if len(matches) != 1:
                    valid = False
                declared_calls.add((str(source_id), int(target_rva or 0)))
            if not valid:
                _issue(
                    issues,
                    "violated",
                    "invalid_component_call_dependency",
                    "component-call dependency does not bind exact machine callsites to a selected callee",
                    component_id=declaration.identity,
                    target_component_id=target_component_id,
                    target_rva=target_rva,
                )
        external_internal_calls = {
            (unit_id, int(event["target_rva"]))
            for unit_id in members
            for event in _mapping(
                machine.units_by_id[unit_id].get("semantics"),
                f"unit {unit_id} semantics",
            ).get("external_events", [])
            if isinstance(event, Mapping)
            and event.get("kind") == "internal_call"
            and isinstance(event.get("target_rva"), int)
            and (
                machine.units_by_rva.get(int(event["target_rva"])) is None
                or machine.units_by_rva[int(event["target_rva"])]["id"] not in members
            )
        }
        if declared_calls != external_internal_calls:
            _issue(
                issues,
                "violated",
                "incomplete_component_call_inventory",
                "component-call dependencies do not exactly cover external internal calls",
                component_id=declaration.identity,
                expected=sorted(external_internal_calls),
                observed=sorted(declared_calls),
            )


def _machine_graph(machine: _MachineInputs) -> dict[str, Any]:
    incoming: dict[str, list[dict[str, Any]]] = defaultdict(list)
    outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for unit in machine.units:
        source_id = str(unit["id"])
        semantics = _mapping(unit.get("semantics"), f"unit {source_id} semantics")
        outcome = semantics.get("outcome")
        if isinstance(outcome, Mapping):
            for target_rva in _outcome_targets(outcome):
                target = machine.units_by_rva.get(target_rva)
                edge = {
                    "kind": "direct_control",
                    "source_unit_id": source_id,
                    "target_rva": target_rva,
                    **({"target_unit_id": target["id"]} if target is not None else {}),
                }
                outgoing[source_id].append(edge)
                if target is not None:
                    incoming[str(target["id"])].append(edge)
        for event_index, event in enumerate(semantics.get("external_events", [])):
            if not isinstance(event, Mapping) or event.get("kind") != "internal_call":
                continue
            target_rva = event.get("target_rva")
            if not isinstance(target_rva, int):
                continue
            target = machine.units_by_rva.get(target_rva)
            edge = {
                "kind": "internal_call",
                "source_unit_id": source_id,
                "event_index": event_index,
                "target_rva": target_rva,
                **(
                    {"return_rva": event["return_rva"]}
                    if isinstance(event.get("return_rva"), int)
                    else {}
                ),
                **({"target_unit_id": target["id"]} if target is not None else {}),
            }
            outgoing[source_id].append(edge)
            if target is not None:
                incoming[str(target["id"])].append(edge)
    indirect_by_unit: dict[str, dict[str, Any]] = {}
    recovered = machine.manifest.get("control", {}).get(
        "recovered_indirect_targets", []
    )
    for item in recovered:
        if not isinstance(item, Mapping):
            continue
        source_id = item.get("source_unit_id")
        if not isinstance(source_id, str) or source_id not in machine.units_by_id:
            continue
        certificate = copy.deepcopy(dict(item))
        indirect_by_unit[source_id] = certificate
        for target_id in item.get("target_unit_ids", []):
            if not isinstance(target_id, str) or target_id not in machine.units_by_id:
                continue
            edge = {
                "kind": "checked_indirect_control",
                "source_unit_id": source_id,
                "target_unit_id": target_id,
                "target_rva": _unit_start(machine.units_by_id[target_id]),
                "certificate_id": item.get("id"),
            }
            outgoing[source_id].append(edge)
            incoming[target_id].append(edge)
    roots_by_rva = {
        int(item["rva"]): copy.deepcopy(dict(item))
        for item in machine.manifest.get("control", {}).get("roots", [])
        if isinstance(item, Mapping) and isinstance(item.get("rva"), int)
    }
    return {
        "incoming": incoming,
        "outgoing": outgoing,
        "roots_by_rva": roots_by_rva,
        "indirect_by_unit": indirect_by_unit,
    }


def _derive_boundary(machine: _MachineInputs, graph: Mapping[str, Any], members: set[str]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    exits: list[dict[str, Any]] = []
    external_events: list[dict[str, Any]] = []
    faults: list[dict[str, Any]] = []
    memory_events: list[dict[str, Any]] = []
    registers_written: set[str] = set()
    flags_written: set[str] = set()
    internal_indirect_controls: list[dict[str, Any]] = []
    call_closure = _derive_internal_call_closure(machine, graph, members)
    consumed_returns = set(call_closure["consumed_return_unit_ids"])

    for unit_id in sorted(members, key=lambda value: (_unit_start(machine.units_by_id[value]), value)):
        unit = machine.units_by_id[unit_id]
        rva = _unit_start(unit)
        incoming = [edge for edge in graph["incoming"].get(unit_id, []) if edge["source_unit_id"] not in members]
        root = graph["roots_by_rva"].get(rva)
        if incoming or root is not None:
            entries.append(
                {
                    "unit_id": unit_id,
                    "rva": rva,
                    "incoming": copy.deepcopy(incoming),
                    **({"root": copy.deepcopy(root)} if root is not None else {}),
                }
            )
        for edge in graph["outgoing"].get(unit_id, []):
            if edge["kind"] == "checked_indirect_control":
                continue
            target_id = edge.get("target_unit_id")
            if target_id not in members:
                exits.append(copy.deepcopy(edge))
        semantics = _mapping(unit.get("semantics"), f"unit {unit_id} semantics")
        outcome = semantics.get("outcome")
        if isinstance(outcome, Mapping):
            outcome_kind = str(outcome.get("kind", ""))
            if outcome_kind == "return" and unit_id in consumed_returns:
                pass
            elif outcome_kind in {"return", "fault", "termination"}:
                exits.append(
                    {
                        "kind": outcome_kind,
                        "source_unit_id": unit_id,
                        "outcome": copy.deepcopy(dict(outcome)),
                    }
                )
            elif outcome_kind.startswith("indirect"):
                certificate = graph["indirect_by_unit"].get(unit_id)
                inventory = (
                    copy.deepcopy(certificate)
                    if certificate is not None
                    else {
                        "status": "incomplete",
                        "closure": "unresolved",
                        "target_unit_ids": [],
                        "target_rvas": [],
                    }
                )
                target_ids = {
                    str(target_id)
                    for target_id in inventory.get("target_unit_ids", [])
                    if isinstance(target_id, str)
                }
                inventory_complete = (
                    inventory.get("status") == "recovered"
                    and inventory.get("closure")
                    == "checked_finite_target_inventory"
                    and bool(target_ids)
                    and inventory.get("failure") is None
                )
                internal_targets = sorted(target_ids & members)
                external_targets = sorted(target_ids - members)
                record = {
                    "kind": outcome_kind,
                    "source_unit_id": unit_id,
                    "target_expression": copy.deepcopy(outcome.get("target")),
                    "target_inventory": inventory,
                    "internal_target_unit_ids": internal_targets,
                    "external_target_unit_ids": external_targets,
                }
                if inventory_complete and not external_targets:
                    internal_indirect_controls.append(record)
                else:
                    exits.append(record)
        for index, event in enumerate(semantics.get("external_events", [])):
            if not isinstance(event, Mapping):
                continue
            target = event.get("target_rva")
            if event.get("kind") == "internal_call" and isinstance(target, int):
                target_unit = machine.units_by_rva.get(target)
                if target_unit is not None and str(target_unit["id"]) in members:
                    continue
            external_events.append({"unit_id": unit_id, "event_index": index, "event": _event_summary(event)})
        for index, fault in enumerate(semantics.get("faults", [])):
            if isinstance(fault, Mapping):
                faults.append({"unit_id": unit_id, "fault_index": index, "fault": copy.deepcopy(dict(fault))})
        for index, event in enumerate(semantics.get("memory_events", [])):
            if isinstance(event, Mapping):
                memory_events.append({"unit_id": unit_id, "event_index": index, "event": copy.deepcopy(dict(event))})
        for write in semantics.get("register_writes", []):
            if isinstance(write, Mapping) and isinstance(write.get("register"), str):
                registers_written.add(str(write["register"]))
        for write in semantics.get("flag_writes", []):
            if isinstance(write, Mapping) and isinstance(write.get("flag"), str):
                flags_written.add(str(write["flag"]))

    if members and not entries:
        first = min(members, key=lambda value: (_unit_start(machine.units_by_id[value]), value))
        entries.append({"unit_id": first, "rva": _unit_start(machine.units_by_id[first]), "incoming": [], "reason": "no_checked_predecessor_in_static_inventory"})
    exits.sort(key=lambda item: (str(item.get("source_unit_id", "")), str(item.get("kind", "")), int(item.get("target_rva", -1))))
    return {
        "state_relation": "canonical_full_machine_state_v1",
        "boundary_minimization_status": "not_attempted",
        "entries": entries,
        "exits": exits,
        "effects": {
            "registers_written": sorted(registers_written),
            "flags_written": sorted(flags_written),
            "memory_events": memory_events,
            "external_events": external_events,
            "faults": faults,
            "internal_call_frames": copy.deepcopy(call_closure["frame_effects"]),
        },
        "internal_calls": copy.deepcopy(call_closure["calls"]),
        "internal_returns": copy.deepcopy(call_closure["returns"]),
        "internal_indirect_controls": internal_indirect_controls,
        "call_closure": {
            "status": call_closure["status"],
            "issues": copy.deepcopy(call_closure["issues"]),
        },
        "counts": {
            "entries": len(entries),
            "exits": len(exits),
            "memory_events": len(memory_events),
            "external_events": len(external_events),
            "faults": len(faults),
            "internal_calls": len(call_closure["calls"]),
            "internal_returns": len(call_closure["returns"]),
            "internal_frame_effects": len(call_closure["frame_effects"]),
            "internal_indirect_controls": len(internal_indirect_controls),
        },
    }


def _derive_internal_call_closure(
    machine: _MachineInputs,
    graph: Mapping[str, Any],
    members: set[str],
) -> dict[str, Any]:
    """Derive checked member-to-member call/return ownership.

    The machine IR represents an internal call as a call event on the caller
    and a normal return outcome on the callee.  Component boundaries must not
    expose that callee return as a second external exit when the callee is
    entered exclusively through a member call.  This routine deliberately
    handles only finite direct call closure; ambiguous, recursive, or externally
    entered callees remain visible and make activation incomplete.
    """

    calls: list[dict[str, Any]] = []
    returns: list[dict[str, Any]] = []
    frame_effects: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    consumed: set[str] = set()
    member_calls = [
        copy.deepcopy(edge)
        for source_id in sorted(members)
        for edge in graph["outgoing"].get(source_id, [])
        if edge.get("kind") == "internal_call"
        and edge.get("target_unit_id") in members
    ]

    call_targets = {str(edge["target_unit_id"]) for edge in member_calls}
    call_adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in member_calls:
        call_adjacency[str(edge["source_unit_id"])].add(
            str(edge["target_unit_id"])
        )
    if _directed_cycle(call_adjacency):
        issues.append(
            {
                "code": "recursive_internal_call_closure",
                "message": "component internal-call closure contains a cycle",
            }
        )

    for edge in sorted(
        member_calls,
        key=lambda item: (
            _unit_start(machine.units_by_id[str(item["source_unit_id"])]),
            int(item.get("event_index", 0)),
        ),
    ):
        source_id = str(edge["source_unit_id"])
        target_id = str(edge["target_unit_id"])
        return_rva = edge.get("return_rva")
        outside_incoming = [
            incoming
            for incoming in graph["incoming"].get(target_id, [])
            if incoming.get("source_unit_id") not in members
        ]
        terminal_returns = _reachable_internal_returns(
            machine, graph, members, target_id
        )
        call_issues: list[str] = []
        if not isinstance(return_rva, int):
            call_issues.append("missing_return_rva")
        if outside_incoming:
            call_issues.append("callee_has_external_entry")
        if not terminal_returns:
            call_issues.append("callee_has_no_finite_return")
        if source_id == target_id:
            call_issues.append("direct_recursion")
        status = "complete" if not call_issues else "incomplete"
        call_id = "component-call:" + _canonical_sha256(
            {
                "source_unit_id": source_id,
                "event_index": edge.get("event_index"),
                "target_unit_id": target_id,
                "return_rva": return_rva,
            }
        )[:20]
        call = {
            "id": call_id,
            "status": status,
            "source_unit_id": source_id,
            "event_index": int(edge.get("event_index", 0)),
            "target_unit_id": target_id,
            "target_rva": int(edge["target_rva"]),
            "return_rva": return_rva,
            "return_unit_ids": terminal_returns,
            "outside_incoming": outside_incoming,
            "issues": call_issues,
            "frame": {
                "model": "x86-pe32-direct-call-frame-v1",
                "caller_esp": {"op": "reg", "name": "esp", "width": 32},
                "callee_esp": {
                    "op": "sub32",
                    "args": [
                        {"op": "reg", "name": "esp", "width": 32},
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
                "return_address": return_rva,
                "net_stack_bytes": 0,
            },
        }
        calls.append(call)
        if status == "complete":
            consumed.update(terminal_returns)
            for return_id in terminal_returns:
                returns.append(
                    {
                        "call_id": call_id,
                        "unit_id": return_id,
                        "return_rva": return_rva,
                        "status": "consumed_internal_return",
                    }
                )
            frame_effects.extend(
                [
                    {
                        "call_id": call_id,
                        "phase": "call_push",
                        "kind": "write",
                        "address": copy.deepcopy(call["frame"]["callee_esp"]),
                        "width": 4,
                        "value": {
                            "op": "const",
                            "value": return_rva,
                            "width": 32,
                        },
                    },
                    {
                        "call_id": call_id,
                        "phase": "return_target_read",
                        "kind": "read",
                        "address": copy.deepcopy(call["frame"]["callee_esp"]),
                        "width": 4,
                    },
                ]
            )
        else:
            issues.append(
                {
                    "code": "incomplete_internal_call_closure",
                    "call_id": call_id,
                    "reasons": call_issues,
                }
            )

    # A member callee that is named by more than one internal call is valid,
    # but only if every call carries the same checked continuation contract.
    for target_id in sorted(call_targets):
        target_calls = [item for item in calls if item["target_unit_id"] == target_id]
        continuations = {item.get("return_rva") for item in target_calls}
        if len(continuations) > 1:
            issues.append(
                {
                    "code": "ambiguous_internal_return_continuation",
                    "target_unit_id": target_id,
                    "return_rvas": sorted(
                        value for value in continuations if isinstance(value, int)
                    ),
                }
            )
            consumed.difference_update(
                return_id
                for item in target_calls
                for return_id in item["return_unit_ids"]
            )

    return {
        "status": "complete" if not issues else "incomplete",
        "calls": calls,
        "returns": sorted(
            returns, key=lambda item: (item["unit_id"], item["call_id"])
        ),
        "frame_effects": frame_effects,
        "consumed_return_unit_ids": sorted(consumed),
        "issues": issues,
    }


def _reachable_internal_returns(
    machine: _MachineInputs,
    graph: Mapping[str, Any],
    members: set[str],
    start_id: str,
) -> list[str]:
    pending = [start_id]
    visited: set[str] = set()
    result: set[str] = set()
    while pending:
        unit_id = pending.pop()
        if unit_id in visited:
            continue
        visited.add(unit_id)
        outcome = _mapping(
            machine.units_by_id[unit_id].get("semantics"),
            f"unit {unit_id} semantics",
        ).get("outcome")
        if isinstance(outcome, Mapping) and outcome.get("kind") == "return":
            result.add(unit_id)
            continue
        for edge in graph["outgoing"].get(unit_id, []):
            if edge.get("kind") not in {
                "direct_control",
                "checked_indirect_control",
            }:
                continue
            target_id = edge.get("target_unit_id")
            if isinstance(target_id, str) and target_id in members:
                pending.append(target_id)
    return sorted(result)


def _directed_cycle(adjacency: Mapping[str, set[str]]) -> bool:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for target in adjacency.get(node, set()):
            if visit(target):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in adjacency)


def _component_reachability(machine: _MachineInputs, members: set[str]) -> dict[str, Any]:
    exact = sorted(unit_id for unit_id in members if machine.units_by_id[unit_id].get("reachability") == "reachable")
    potential = sorted(unit_id for unit_id in members if machine.units_by_id[unit_id].get("reachability") == "potential")
    other = sorted(members - set(exact) - set(potential))
    classes = sum(bool(values) for values in (exact, potential, other))
    classification = "mixed" if classes > 1 else ("exact" if exact else "potential" if potential else "any")
    return {
        "classification": classification,
        "exact_unit_ids": exact,
        "potential_unit_ids": potential,
        "other_unit_ids": other,
        "counts": {"exact": len(exact), "potential": len(potential), "other": len(other)},
    }


def _coverage_ledger(
    machine: _MachineInputs,
    declarations: Sequence[ComponentDeclaration],
    direct: Mapping[str, set[str]],
    resolved: Mapping[str, set[str]],
) -> dict[str, Any]:
    child_ids = {child for item in declarations for child in item.child_ids}
    roots = [item for item in declarations if item.identity not in child_ids]
    declared = set().union(*(resolved.get(item.identity, set()) for item in roots)) if roots else set()
    exact_all = {str(unit["id"]) for unit in machine.units if unit.get("reachability") == "reachable"}
    potential_all = {str(unit["id"]) for unit in machine.units if unit.get("reachability") == "potential"}
    owners: dict[str, list[str]] = defaultdict(list)
    for item in declarations:
        for unit_id in direct.get(item.identity, set()):
            owners[unit_id].append(item.identity)
    return {
        "authority": "rooted_static_machine_ir_reachability",
        "scope": "declared_components_with_global_residual",
        "declared_unit_ids": sorted(declared),
        "unit_owners": {key: sorted(value) for key, value in sorted(owners.items())},
        "unassigned_exact_reachable_unit_ids": sorted(exact_all - declared),
        "unassigned_potential_unit_ids": sorted(potential_all - declared),
        "counts": {
            "machine_units": len(machine.units),
            "exact_reachable_units": len(exact_all),
            "potential_units": len(potential_all),
            "declared_units": len(declared),
            "declared_exact_reachable_units": len(exact_all & declared),
            "declared_potential_units": len(potential_all & declared),
            "unassigned_exact_reachable_units": len(exact_all - declared),
            "unassigned_potential_units": len(potential_all - declared),
        },
        "exact_reachable_complete": exact_all.issubset(declared),
        "potential_residual_empty": not (potential_all - declared),
        "complete": exact_all.issubset(declared) and potential_all.issubset(declared),
    }


def _membership_spans(machine: _MachineInputs, members: Iterable[str]) -> list[dict[str, int]]:
    ranges = sorted((_unit_start(machine.units_by_id[item]), _unit_end(machine.units_by_id[item])) for item in members)
    spans: list[dict[str, int]] = []
    for start, end in ranges:
        if spans and start == spans[-1]["rva_end"]:
            spans[-1]["rva_end"] = end
        else:
            spans.append({"rva_start": start, "rva_end": end})
    return spans


def _event_summary(event: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(event[key])
        for key in (
            "kind",
            "dll",
            "symbol",
            "ordinal",
            "target_rva",
            "return_rva",
            "effect_model",
            "stack_inputs",
            "register_inputs",
            "flag_inputs",
            "abi_contract",
        )
        if key in event
    }


def _outcome_targets(outcome: Mapping[str, Any]) -> tuple[int, ...]:
    values = []
    for field in ("target_rva", "true_target_rva", "false_target_rva"):
        value = outcome.get(field)
        if isinstance(value, int) and not isinstance(value, bool):
            values.append(value)
    return tuple(sorted(set(values)))


def _unit_start(unit: Mapping[str, Any]) -> int:
    source = _mapping(unit.get("source"), "unit source")
    original = _mapping(source.get("original"), "original source")
    return int(original["rva_start"])


def _unit_end(unit: Mapping[str, Any]) -> int:
    source = _mapping(unit.get("source"), "unit source")
    original = _mapping(source.get("original"), "original source")
    return int(original["rva_end"])


def _issue(issues: list[dict[str, Any]], status: str, code: str, message: str, **details: Any) -> None:
    core = {"status": status, "code": code, "message": message, **copy.deepcopy(details)}
    issues.append({"id": "semantic-component-issue:" + _canonical_sha256(core)[:20], **core})


def _issue_sort_key(issue: Mapping[str, Any]) -> tuple[Any, ...]:
    return (0 if issue.get("status") == "violated" else 1, str(issue.get("component_id", "")), str(issue.get("code", "")), str(issue.get("id", "")))


def _read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SemanticComponentError(f"invalid machine IR JSONL at line {line_number}: {exc}") from exc
            yield _object(value, f"machine IR line {line_number}")


def _json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SemanticComponentError(f"cannot read {label} {path}: {exc}") from exc
    return _object(value, label)


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SemanticComponentError(f"{label} must be an object")
    return _json_copy(value, label)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SemanticComponentError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SemanticComponentError(f"{label} must be an array")
    return value


def _object_sequence(value: Any, label: str) -> list[dict[str, Any]]:
    return [_object(item, f"{label} item") for item in _array(value, label)]


def _string_sequence(value: Any, label: str) -> tuple[str, ...]:
    items = _array(value, label)
    result = tuple(_nonempty_string(item, f"{label} item") for item in items)
    if len(set(result)) != len(result):
        raise SemanticComponentError(f"{label} contains duplicates")
    return result


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SemanticComponentError(f"{label} must be a non-empty string")
    return value


def _enum(value: Any, choices: set[str], label: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise SemanticComponentError(f"{label} must be one of {sorted(choices)}")
    return value


def _json_copy(value: Any, label: str) -> Any:
    try:
        return json.loads(json.dumps(value))
    except (TypeError, ValueError) as exc:
        raise SemanticComponentError(f"{label} must contain JSON values") from exc


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()


__all__ = [
    "ComponentDeclaration",
    "LogicalInterface",
    "SemanticComponentError",
    "build_semantic_component_catalog",
    "write_semantic_component_catalog",
]
