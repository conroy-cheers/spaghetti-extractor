"""Materialize operator-selected discovery proposals as component declarations."""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .artifact_formats import (
    COMPONENT_PROPOSAL_SET_FORMAT,
    COMPONENT_SELECTION_FORMAT,
    SEMANTIC_COMPONENT_DECLARATIONS_FORMAT,
)
from .util import sha256_file, write_json


class ComponentSelectionError(ValueError):
    """A proposal selection is malformed, stale, or internally inconsistent."""


def materialize_component_declarations(
    *,
    proposals: Path | str,
    selection: Path | str | Mapping[str, Any],
    out: Path | str,
) -> dict[str, Any]:
    """Apply reviewed names and interfaces without permitting membership edits."""

    proposal_path = Path(proposals)
    proposal_set = _read_object(proposal_path, "component proposal set")
    _require_self_hash(
        proposal_set,
        expected_format=COMPONENT_PROPOSAL_SET_FORMAT,
        hash_field="proposal_set_sha256",
        description="component proposal set",
    )
    if proposal_set.get("executes_original_binary") is not False:
        raise ComponentSelectionError("component proposal set has invalid runtime authority")
    selected_payload = (
        _copy_object(selection, "component selection")
        if isinstance(selection, Mapping)
        else _read_object(Path(selection), "component selection")
    )
    _require_self_hash(
        selected_payload,
        expected_format=COMPONENT_SELECTION_FORMAT,
        hash_field="selection_sha256",
        description="component selection",
    )
    proposals_by_id = {
        str(item.get("id")): item
        for item in _array(proposal_set.get("proposals"), "component proposals")
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    rows = _array(selected_payload.get("components"), "selected components")
    if not rows:
        raise ComponentSelectionError("component selection contains no components")
    stable_binding_presence = [
        isinstance(item, Mapping) and "proposal_binding_sha256" in item
        for item in rows
    ]
    if any(stable_binding_presence) and not all(stable_binding_presence):
        raise ComponentSelectionError(
            "component selection must bind either every selected proposal or none"
        )
    stable_membership_binding = all(stable_binding_presence)
    selected_proposal_set_sha256 = _digest(
        selected_payload.get("proposal_set_sha256"),
        "selected proposal-set binding",
    )
    if (
        not stable_membership_binding
        and selected_proposal_set_sha256 != proposal_set.get("proposal_set_sha256")
    ):
        raise ComponentSelectionError("component selection/proposal binding is stale")
    selected_rows: dict[str, Mapping[str, Any]] = {}
    selected_proposals: dict[str, Mapping[str, Any]] = {}
    for index, raw in enumerate(rows):
        row = _object(raw, f"selected component {index}")
        component_id = _nonempty(row.get("id"), "selected component id")
        if component_id in selected_rows:
            raise ComponentSelectionError(
                f"duplicate selected component id: {component_id}"
            )
        proposal_id = _nonempty(row.get("proposal_id"), "selected proposal id")
        proposal = proposals_by_id.get(proposal_id)
        if proposal is None:
            raise ComponentSelectionError(f"unknown selected proposal: {proposal_id}")
        if stable_membership_binding:
            expected_binding = _digest(
                row.get("proposal_binding_sha256"),
                f"selected proposal binding for {component_id}",
            )
            proposal_bindings = _object(
                proposal.get("bindings"), f"proposal bindings for {proposal_id}"
            )
            observed_binding = _digest(
                proposal_bindings.get("membership_bindings_sha256"),
                f"current proposal binding for {proposal_id}",
            )
            if expected_binding != observed_binding:
                raise ComponentSelectionError(
                    f"selected proposal membership binding is stale: {proposal_id}"
                )
        selected_rows[component_id] = row
        selected_proposals[component_id] = proposal
    components: list[dict[str, Any]] = []
    for index, raw in enumerate(rows):
        row = _object(raw, f"selected component {index}")
        proposal_id = _nonempty(row.get("proposal_id"), "selected proposal id")
        component_id = _nonempty(row.get("id"), "selected component id")
        proposal = selected_proposals[component_id]
        component_calls = _checked_component_call_dependencies(
            component_id=component_id,
            row=row,
            proposal=proposal,
            selected_rows=selected_rows,
            selected_proposals=selected_proposals,
        )
        membership = _object(proposal.get("membership"), "proposal membership")
        unit_ids = _strings(membership.get("unit_ids"), "proposal unit ids")
        if not unit_ids:
            raise ComponentSelectionError(f"proposal {proposal_id} has no machine units")
        logical = row.get("logical_interface", proposal.get("interface_hint"))
        logical_interface = _declaration_logical_interface(
            _object(logical, "selected logical interface")
        )
        reachability = _object(
            proposal.get("reachability", {}), "proposal reachability"
        )
        expected_reachability = str(
            row.get(
                "expected_reachability",
                reachability.get("classification", "any"),
            )
        )
        refinement_stage = {
            "kind": "selected_discovery_proposal",
            "proposal_id": proposal_id,
            "membership_sha256": _canonical_sha256(
                {"unit_ids": sorted(unit_ids)}
            ),
        }
        if stable_membership_binding:
            refinement_stage["proposal_binding_sha256"] = row[
                "proposal_binding_sha256"
            ]
        component = {
            "id": component_id,
            "label": _nonempty(
                row.get("label", proposal.get("label", component_id)),
                "selected component label",
            ),
            "purpose": _nonempty(
                row.get(
                    "purpose",
                    "Operator-selected component discovery proposal " + proposal_id,
                ),
                "selected component purpose",
            ),
            "kind": str(row.get("kind", proposal.get("kind", "procedure"))),
            "sharing": str(row.get("sharing", "exclusive")),
            "expected_reachability": expected_reachability,
            "membership": {"unit_ids": sorted(unit_ids), "cluster_ids": []},
            "children": _strings(row.get("children", []), "component children"),
            "component_calls": component_calls,
            "logical_interface": copy.deepcopy(dict(logical_interface)),
            "refinement": {
                "status": "not_started",
                "stages": [refinement_stage],
            },
            "emission": copy.deepcopy(
                dict(
                    _object(
                        row.get(
                            "emission",
                            {"policy": "function" if row.get("kind") != "inline" else "inline"},
                        ),
                        "component emission",
                    )
                )
            ),
            "evidence": [],
            "assumptions": copy.deepcopy(list(row.get("assumptions", []))),
        }
        components.append(component)

    known = {item["id"] for item in components}
    missing_children = sorted(
        {
            child
            for item in components
            for child in item["children"]
            if child not in known
        }
    )
    if missing_children:
        raise ComponentSelectionError(
            f"selected component children are not selected: {missing_children}"
        )
    _validate_component_call_graph(components)
    bindings = _object(proposal_set.get("bindings"), "proposal input bindings")
    core = {
        "format": SEMANTIC_COMPONENT_DECLARATIONS_FORMAT,
        "program_id": _nonempty(selected_payload.get("program_id"), "program id"),
        "bindings": {
            key: bindings[key]
            for key in (
                "machine_ir_sha256",
                "machine_ir_manifest_sha256",
                "reconstruction_plan_sha256",
                "original_binary_sha256",
            )
            if key in bindings
        },
        "selection": {
            "proposal_set_sha256": proposal_set["proposal_set_sha256"],
            "selected_proposal_set_sha256": selected_proposal_set_sha256,
            "binding_mode": (
                "stable_membership_v1"
                if stable_membership_binding
                else "exact_proposal_set_v1"
            ),
            "selection_sha256": selected_payload["selection_sha256"],
            "proposal_set_artifact_sha256": sha256_file(proposal_path),
        },
        "components": sorted(components, key=lambda item: item["id"]),
    }
    write_json(Path(out), core)
    return core


def _checked_component_call_dependencies(
    *,
    component_id: str,
    row: Mapping[str, Any],
    proposal: Mapping[str, Any],
    selected_rows: Mapping[str, Mapping[str, Any]],
    selected_proposals: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    blockers = _array(proposal.get("blockers", []), "proposal blockers")
    declarations = _array(
        row.get("component_calls", []), "selected component-call dependencies"
    )
    if not blockers:
        if declarations:
            raise ComponentSelectionError(
                f"component {component_id} declares calls that do not discharge blockers"
            )
        if proposal.get("status") != "proposed":
            raise ComponentSelectionError(
                f"selected proposal is blocked and cannot be materialized: {proposal.get('id')}"
            )
        return []
    if any(
        not isinstance(blocker, Mapping)
        or blocker.get("category") != "unclosed_internal_call_dependency"
        for blocker in blockers
    ):
        raise ComponentSelectionError(
            f"selected proposal is blocked and cannot be materialized: {proposal.get('id')}"
        )
    if not declarations:
        raise ComponentSelectionError(
            f"selected proposal is blocked and cannot be materialized: {proposal.get('id')}"
        )
    by_target: dict[int, Mapping[str, Any]] = {}
    for raw in declarations:
        declaration = _object(raw, "selected component-call dependency")
        target_component_id = _nonempty(
            declaration.get("target_component_id"), "target component id"
        )
        target_rva = declaration.get("target_rva")
        if not isinstance(target_rva, int) or target_rva < 0:
            raise ComponentSelectionError("component-call target RVA is invalid")
        if target_rva in by_target:
            raise ComponentSelectionError("duplicate component-call target RVA")
        if target_component_id == component_id or target_component_id not in selected_rows:
            raise ComponentSelectionError(
                f"component-call target is not a distinct selected component: {target_component_id}"
            )
        target_proposal = selected_proposals[target_component_id]
        target_row = selected_rows[target_component_id]
        if not _proposal_is_selectable_dependency(
            proposal=target_proposal, selection=target_row
        ):
            raise ComponentSelectionError(
                "component-call target has unresolved non-call blockers: "
                f"{target_component_id}"
            )
        by_target[target_rva] = declaration

    blocker_targets: dict[int, list[Mapping[str, Any]]] = {}
    for blocker in blockers:
        observed = _object(blocker.get("observed"), "component-call blocker target")
        target_rva = observed.get("target_rva")
        target_unit_id = observed.get("target_unit_id")
        if not isinstance(target_rva, int) or not isinstance(target_unit_id, str):
            raise ComponentSelectionError("component-call blocker target is incomplete")
        blocker_targets.setdefault(target_rva, []).append(blocker)
    if set(by_target) != set(blocker_targets):
        raise ComponentSelectionError(
            f"component-call declarations do not exactly cover blockers for {component_id}"
        )

    checked: list[dict[str, Any]] = []
    for target_rva in sorted(by_target):
        declaration = by_target[target_rva]
        target_component_id = str(declaration["target_component_id"])
        target_proposal = selected_proposals[target_component_id]
        target_ids = set(
            _strings(
                _object(target_proposal.get("membership"), "target membership").get(
                    "unit_ids"
                ),
                "target unit ids",
            )
        )
        target_unit_ids = {
            str(_object(blocker.get("observed"), "blocker target")["target_unit_id"])
            for blocker in blocker_targets[target_rva]
        }
        membership = _object(target_proposal.get("membership"), "target membership")
        if (
            len(target_unit_ids) != 1
            or not target_unit_ids.issubset(target_ids)
            or membership.get("rva_start") != target_rva
        ):
            raise ComponentSelectionError(
                f"component-call target does not bind the callee entry: {target_component_id}"
            )
        core = {
            "target_component_id": target_component_id,
            "target_proposal_id": target_proposal["id"],
            "target_rva": target_rva,
            "target_unit_id": next(iter(target_unit_ids)),
            "callsites": sorted(
                [
                    {
                        "gap_id": str(blocker.get("id")),
                        "source_unit_id": str(
                            _object(
                                blocker.get("source_location"), "blocker source"
                            ).get("unit_id")
                        ),
                    }
                    for blocker in blocker_targets[target_rva]
                ],
                key=lambda item: (item["source_unit_id"], item["gap_id"]),
            ),
        }
        checked.append({**core, "dependency_sha256": _canonical_sha256(core)})
    return checked


def _proposal_is_selectable_dependency(
    *, proposal: Mapping[str, Any], selection: Mapping[str, Any]
) -> bool:
    blockers = _array(proposal.get("blockers", []), "target proposal blockers")
    if not blockers:
        return proposal.get("status") == "proposed"
    return (
        proposal.get("status") == "blocked"
        and bool(selection.get("component_calls"))
        and all(
            isinstance(blocker, Mapping)
            and blocker.get("category") == "unclosed_internal_call_dependency"
            for blocker in blockers
        )
    )


def _validate_component_call_graph(
    components: list[Mapping[str, Any]],
) -> None:
    graph = {
        str(component["id"]): tuple(
            str(call["target_component_id"])
            for call in _array(
                component.get("component_calls", []), "component-call graph edges"
            )
        )
        for component in components
    }
    visited: set[str] = set()
    active: list[str] = []

    def visit(component_id: str) -> None:
        if component_id in active:
            cycle = active[active.index(component_id) :] + [component_id]
            raise ComponentSelectionError(
                "recursive component-call graph is unsupported: "
                + " -> ".join(cycle)
            )
        if component_id in visited:
            return
        active.append(component_id)
        for target in graph[component_id]:
            visit(target)
        active.pop()
        visited.add(component_id)

    for component_id in sorted(graph):
        visit(component_id)


def bind_component_selection(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Attach the deterministic self-hash expected by the materializer."""

    core = _copy_object(payload, "component selection")
    core.pop("selection_sha256", None)
    if core.get("format") != COMPONENT_SELECTION_FORMAT:
        raise ComponentSelectionError("unsupported component selection format")
    return {**core, "selection_sha256": _canonical_sha256(core)}


def _declaration_logical_interface(value: Mapping[str, Any]) -> dict[str, Any]:
    status = value.get("status", "proposed")
    if status not in {"proposed", "reviewed", "not_applicable"}:
        raise ComponentSelectionError("selected logical interface has invalid status")
    result: dict[str, Any] = {"status": status}
    for field in (
        "parameters",
        "results",
        "objects",
        "persistent_state",
        "services",
        "preconditions",
        "postconditions",
        "observations",
    ):
        rows = _array(value.get(field, []), f"selected logical interface {field}")
        if any(not isinstance(item, Mapping) for item in rows):
            raise ComponentSelectionError(
                f"selected logical interface {field} must contain objects"
            )
        result[field] = copy.deepcopy(rows)
    return result


def _require_self_hash(
    payload: Mapping[str, Any],
    *,
    expected_format: str,
    hash_field: str,
    description: str,
) -> None:
    if payload.get("format") != expected_format:
        raise ComponentSelectionError(f"unsupported {description} format")
    expected = payload.get(hash_field)
    core = copy.deepcopy(dict(payload))
    core.pop(hash_field, None)
    if expected != _canonical_sha256(core):
        raise ComponentSelectionError(f"{description} self-hash is stale")


def _read_object(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ComponentSelectionError(f"cannot read {description}: {exc}") from exc
    return _copy_object(value, description)


def _copy_object(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ComponentSelectionError(f"{description} must be an object")
    return copy.deepcopy(dict(value))


def _object(value: Any, description: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ComponentSelectionError(f"{description} must be an object")
    return value


def _array(value: Any, description: str) -> list[Any]:
    if not isinstance(value, list):
        raise ComponentSelectionError(f"{description} must be an array")
    return value


def _strings(value: Any, description: str) -> list[str]:
    rows = _array(value, description)
    if any(not isinstance(item, str) or not item for item in rows):
        raise ComponentSelectionError(f"{description} must contain non-empty strings")
    return list(rows)


def _nonempty(value: Any, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentSelectionError(f"{description} must be a non-empty string")
    return value


def _digest(value: Any, description: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ComponentSelectionError(f"{description} must be a lowercase SHA-256")
    return value


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


__all__ = [
    "ComponentSelectionError",
    "bind_component_selection",
    "materialize_component_declarations",
]
