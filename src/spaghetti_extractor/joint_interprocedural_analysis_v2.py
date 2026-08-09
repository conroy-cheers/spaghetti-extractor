"""Joint mutable-slot and indirect-control certificate checking.

Discovery recoveries are untrusted proposals.  They may accelerate the
bootstrap pass, but they neither grant nor deny authority.  Authority is
granted only when one unseeded interprocedural package reaches a stable graph,
stack-range, and mutable-slot fixed point.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Mapping, Sequence

from .control_analysis_v2 import exact_control_inventory_v2
from .analysis_schema_v2 import ROOTED_CONTROL_GRAPH_V2_FORMAT
from .artifact_identity_v2 import canonical_sha256


JOINT_INTERPROCEDURAL_ANALYSIS_V2_FORMAT = (
    "spaghetti-extractor-joint-interprocedural-analysis-v2"
)


def merge_recovery_proposals_v2(
    *,
    exact_exits: Sequence[Mapping[str, Any]],
    proposal_sets: Sequence[Sequence[Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    """Merge agreeing finite proposals and fail closed on disagreement."""

    by_set = [
        {
            str(row.get("id")): row
            for row in rows
            if isinstance(row, Mapping) and isinstance(row.get("id"), str)
        }
        for rows in proposal_sets
    ]
    result: list[dict[str, Any]] = []
    for exact in exact_exits:
        identity = str(exact["id"])
        recovered = [
            row[identity]
            for row in by_set
            if identity in row and row[identity].get("status") == "recovered"
        ]
        projections = {
            json.dumps(_target_projection(row), sort_keys=True, separators=(",", ":"))
            for row in recovered
        }
        if len(projections) > 1:
            result.append({
                **copy.deepcopy(dict(exact)),
                "status": "incomplete",
                "target_rvas": [],
                "target_unit_ids": [],
                "external_targets": [],
                "failure": {"code": "conflicting_recovery_proposals"},
            })
        elif recovered:
            result.append(copy.deepcopy(dict(recovered[0])))
        else:
            result.append({
                **copy.deepcopy(dict(exact)),
                "status": "incomplete",
                "target_rvas": [],
                "target_unit_ids": [],
                "external_targets": [],
                "failure": {"code": "finite_recovery_proposal_missing"},
            })
    return result


def build_proposal_control_graph_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    base_graph: Mapping[str, Any],
    recoveries: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build exact rooted closure under finite untrusted target proposals."""

    by_id = {str(row.get("id")): row for row in units}
    exact = exact_control_inventory_v2(units)
    recovery_by_id = {
        str(row.get("id")): row
        for row in recoveries
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    roots = [
        copy.deepcopy(dict(row))
        for row in base_graph.get("roots", ())
        if isinstance(row, Mapping)
        and isinstance(row.get("unit_id"), str)
        and row["unit_id"] in by_id
    ]
    successors: dict[str, set[str]] = {unit_id: set() for unit_id in by_id}
    direct_edges = [
        *exact["direct_edges"],
        *(
            {
                "source_unit_id": row["source_unit_id"],
                "target_unit_id": row["target_unit_id"],
            }
            for row in exact["internal_call_edges"]
        ),
    ]
    for row in direct_edges:
        successors[str(row["source_unit_id"])].add(str(row["target_unit_id"]))
    indirect: list[dict[str, Any]] = []
    for exact_exit in exact["indirect_exits"]:
        proposal = recovery_by_id.get(str(exact_exit["id"]))
        targets = proposal.get("target_unit_ids", ()) if proposal else ()
        external = proposal.get("external_targets", ()) if proposal else ()
        complete = (
            isinstance(proposal, Mapping)
            and proposal.get("status") == "recovered"
            and isinstance(targets, list)
            and isinstance(external, list)
            and bool(targets or external)
            and all(isinstance(target, str) and target in by_id for target in targets)
        )
        row = {
            "id": exact_exit["id"],
            "source_unit_id": exact_exit["source_unit_id"],
            "status": "complete" if complete else "incomplete",
            "target_unit_ids": sorted(set(targets)) if complete else [],
            "external_targets": copy.deepcopy(external) if complete else [],
            "proposal_failure": (
                None
                if complete
                else copy.deepcopy(
                    proposal.get("failure", {"code": "proposal_missing"})
                    if isinstance(proposal, Mapping)
                    else {"code": "proposal_missing"}
                )
            ),
        }
        indirect.append(row)
        if complete:
            successors[str(row["source_unit_id"])].update(row["target_unit_ids"])

    reachable: set[str] = set()
    pending = [str(row["unit_id"]) for row in reversed(roots)]
    while pending:
        unit_id = pending.pop()
        if unit_id in reachable:
            continue
        reachable.add(unit_id)
        pending.extend(sorted(successors.get(unit_id, ()), reverse=True))
    reachable_indirect = [
        row for row in indirect if row["source_unit_id"] in reachable
    ]
    issues = [
        {
            "status": "incomplete",
            "code": "reachable_recovery_proposal_incomplete",
            "exit_id": row["id"],
            "source_unit_id": row["source_unit_id"],
        }
        for row in reachable_indirect
        if row["status"] != "complete"
    ]
    issues.extend(
        copy.deepcopy(dict(issue))
        for issue in exact["issues"]
        if issue.get("source_unit_id") in reachable
    )
    status = (
        "violated"
        if any(row.get("status") == "violated" for row in issues)
        else "incomplete" if issues else "complete"
    )
    body = {
        "format": ROOTED_CONTROL_GRAPH_V2_FORMAT,
        "status": status,
        "roots": sorted(roots, key=lambda row: (str(row["unit_id"]), str(row.get("kind")))),
        "direct_edges": sorted(
            {
                json.dumps(row, sort_keys=True): copy.deepcopy(dict(row))
                for row in direct_edges
            }.values(),
            key=lambda row: (str(row["source_unit_id"]), str(row["target_unit_id"])),
        ),
        "indirect_exits": sorted(reachable_indirect, key=lambda row: str(row["id"])),
        "reachable_units": sorted(reachable),
        "issues": sorted(
            issues,
            key=lambda row: (
                str(row.get("status")),
                str(row.get("code")),
                str(row.get("source_unit_id", "")),
            ),
        ),
    }
    return {**body, "id": "proposal-control-graph-v2:" + canonical_sha256(body)}


def validate_joint_replay_v2(
    *,
    proposal_graph: Mapping[str, Any],
    proposal_recoveries: Sequence[Mapping[str, Any]],
    stack_range_analysis: Mapping[str, Any],
    global_slot_analysis: Mapping[str, Any],
    global_slot_authority: Mapping[str, Any],
    interprocedural: Mapping[str, Any],
    cold_graph: Mapping[str, Any],
    authoritative_evidence_stable: bool,
) -> dict[str, Any]:
    """Check one graph-bound, unseeded interprocedural authority package."""

    cold_by_id = {
        str(row.get("id")): row
        for row in interprocedural.get("recovered_targets", ())
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    reachable = set(str(value) for value in proposal_graph.get("reachable_units", ()))
    proposal_diagnostics: list[dict[str, Any]] = []
    for proposal in proposal_recoveries:
        if (
            not isinstance(proposal, Mapping)
            or proposal.get("status") != "recovered"
            or proposal.get("source_unit_id") not in reachable
        ):
            continue
        cold = cold_by_id.get(str(proposal.get("id")))
        if cold is None or cold.get("status") != "recovered":
            proposal_diagnostics.append({
                "code": "proposal_not_reproduced_cold",
                "exit_id": proposal.get("id"),
            })
        elif _target_projection(cold) != _target_projection(proposal):
            proposal_diagnostics.append({
                "code": "cold_replay_target_differs_from_proposal",
                "exit_id": proposal.get("id"),
            })
    fixed = interprocedural.get("fixed_point")
    stack_replay = stack_range_analysis.get("cold_replay")
    stack_binding = stack_range_analysis.get("binding")
    cold_complete = (
        isinstance(fixed, Mapping)
        and fixed.get("status") == "complete"
        and fixed.get("cold_replay_validated") is True
        and fixed.get("authority_replay_validated") is True
    )
    stack_binding_valid = (
        isinstance(stack_binding, Mapping)
        and stack_binding.get("rooted_graph_id") == cold_graph.get("id")
    )
    checks = {
        "stack_range_replay_complete": (
            stack_range_analysis.get("status") == "complete"
            and isinstance(stack_replay, Mapping)
            and stack_replay.get("status") == "complete"
            and stack_replay.get("deterministic") is True
            and stack_replay.get("empty_initial_state") is True
            and stack_binding_valid
        ),
        "slot_replay_complete": global_slot_analysis.get("status") == "complete",
        "slot_authority_valid": global_slot_authority.get("status") == "complete",
        "interprocedural_cold_complete": cold_complete,
        "cold_rooted_graph_complete": cold_graph.get("status") == "complete",
        "authoritative_evidence_stable": authoritative_evidence_stable,
    }
    issues: list[dict[str, Any]] = []
    if not stack_binding_valid:
        issues.append({
            "status": "violated",
            "code": "authoritative_stack_graph_binding_mismatch",
            "expected_graph_id": cold_graph.get("id"),
            "observed_graph_id": (
                stack_binding.get("rooted_graph_id")
                if isinstance(stack_binding, Mapping)
                else None
            ),
        })
    if not authoritative_evidence_stable:
        issues.append({
            "status": "incomplete",
            "code": "authoritative_joint_evidence_not_stable",
        })
    component_statuses = {
        str(value.get("status"))
        for value in (
            stack_range_analysis,
            global_slot_analysis,
            global_slot_authority,
            interprocedural,
            cold_graph,
        )
        if isinstance(value, Mapping)
    }
    status = (
        "violated"
        if "violated" in component_statuses
        or any(row["status"] == "violated" for row in issues)
        else "complete" if all(checks.values()) else "incomplete"
    )
    body = {
        "format": JOINT_INTERPROCEDURAL_ANALYSIS_V2_FORMAT,
        "status": status,
        "checks": checks,
        "proposal_graph": copy.deepcopy(dict(proposal_graph)),
        "stack_range_analysis": copy.deepcopy(dict(stack_range_analysis)),
        "global_slot_analysis": copy.deepcopy(dict(global_slot_analysis)),
        "global_slot_authority": copy.deepcopy(dict(global_slot_authority)),
        "interprocedural": copy.deepcopy(dict(interprocedural)),
        "cold_graph": copy.deepcopy(dict(cold_graph)),
        "issues": issues,
        "proposal_diagnostics": proposal_diagnostics,
        "constraints": {
            "proposal_authority": False,
            "unseeded_cold_replay_required": True,
            "stack_replay_bound_to_authoritative_graph": True,
            "proposal_agreement_required": False,
            "mutable_slots_promoted_to_roots": False,
        },
    }
    return {**body, "analysis_sha256": canonical_sha256(body)}


def _target_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "target_rvas": sorted(
            value for value in row.get("target_rvas", ()) if isinstance(value, int)
        ),
        "target_unit_ids": sorted(
            value for value in row.get("target_unit_ids", ()) if isinstance(value, str)
        ),
        "external_targets": sorted(
            (
                copy.deepcopy(dict(value))
                for value in row.get("external_targets", ())
                if isinstance(value, Mapping)
            ),
            key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")),
        ),
    }


__all__ = [
    "JOINT_INTERPROCEDURAL_ANALYSIS_V2_FORMAT",
    "build_proposal_control_graph_v2",
    "merge_recovery_proposals_v2",
    "validate_joint_replay_v2",
]
