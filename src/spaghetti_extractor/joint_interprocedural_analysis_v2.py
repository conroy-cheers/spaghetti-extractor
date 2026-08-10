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
from .call_site_effects import parse_call_site_effects
from .mutable_slot_candidates_v2 import required_recovery_slot_rvas_v2


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
    proposal_slot_dependencies: Sequence[Mapping[str, Any]] = (),
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
    call_effect_binding_valid = False
    try:
        operation = interprocedural.get("operation_provenance")
        raw_call_effects = (
            operation.get("call_site_effects", [])
            if isinstance(operation, Mapping)
            else []
        )
        if not isinstance(raw_call_effects, list):
            raise ValueError("call-site effect inventory is not an array")
        parsed_call_effects = parse_call_site_effects(
            raw_call_effects,
            finite_value_budget=256,
        )
        call_effects_sha256 = canonical_sha256([
            effect.as_json() for effect in parsed_call_effects.values()
        ])
        call_effect_binding_valid = (
            isinstance(stack_binding, Mapping)
            and stack_binding.get("call_site_effects_sha256")
            == call_effects_sha256
        )
    except (TypeError, ValueError):
        call_effect_binding_valid = False
    (
        slot_inventory_valid,
        missing_slots,
        extra_slots,
        missing_slot_dependencies,
        extra_slot_dependencies,
        slot_inventory_error,
        active_proposal_slot_dependencies,
    ) = _slot_inventory_check(
        global_slot_analysis=global_slot_analysis,
        interprocedural=interprocedural,
        proposal_slot_dependencies=proposal_slot_dependencies,
    )
    proposal_slots_discharged = not active_proposal_slot_dependencies
    checks = {
        "stack_range_replay_complete": (
            stack_range_analysis.get("status") == "complete"
            and isinstance(stack_replay, Mapping)
            and stack_replay.get("status") == "complete"
            and stack_replay.get("deterministic") is True
            and stack_replay.get("empty_initial_state") is True
            and stack_binding_valid
            and call_effect_binding_valid
        ),
        "slot_replay_complete": global_slot_analysis.get("status") == "complete",
        "slot_authority_valid": global_slot_authority.get("status") == "complete",
        "mutable_slot_requirement_inventory_exact": slot_inventory_valid,
        "proposal_slot_dependencies_discharged": proposal_slots_discharged,
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
    if not call_effect_binding_valid:
        issues.append({
            "status": "violated",
            "code": "authoritative_stack_call_effect_binding_mismatch",
            "observed_sha256": (
                stack_binding.get("call_site_effects_sha256")
                if isinstance(stack_binding, Mapping)
                else None
            ),
        })
    if not slot_inventory_valid:
        issues.append({
            "status": "violated",
            "code": (
                "authoritative_mutable_slot_requirement_inventory_malformed"
                if slot_inventory_error is not None
                else "authoritative_mutable_slot_requirement_inventory_mismatch"
            ),
            "missing_slot_rvas": missing_slots,
            "extra_slot_rvas": extra_slots,
            "missing_dependencies": missing_slot_dependencies,
            "extra_dependencies": extra_slot_dependencies,
            **(
                {"reason": slot_inventory_error}
                if slot_inventory_error is not None
                else {}
            ),
        })
    if not proposal_slots_discharged:
        issues.append({
            "status": "incomplete",
            "code": "proposal_slot_dependencies_not_discharged",
            "dependencies": [
                _slot_dependency_payload(key)
                for key in sorted(active_proposal_slot_dependencies)
            ],
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
            "active_proposal_slots_are_non_authorizing": True,
        },
    }
    return {**body, "analysis_sha256": canonical_sha256(body)}


def _slot_inventory_check(
    *,
    global_slot_analysis: Mapping[str, Any],
    interprocedural: Mapping[str, Any],
    proposal_slot_dependencies: Sequence[Mapping[str, Any]] = (),
) -> tuple[
    bool,
    list[int],
    list[int],
    list[dict[str, Any]],
    list[dict[str, Any]],
    str | None,
    set[tuple[int, str, str, int, bool]],
]:
    required: frozenset[int] = frozenset()
    required_dependencies: set[tuple[int, str, str, int, bool]] = set()
    try:
        raw_recoveries = interprocedural.get("recovered_targets", ())
        if not isinstance(raw_recoveries, Sequence) or isinstance(
            raw_recoveries, (str, bytes)
        ):
            raise ValueError("interprocedural recovery inventory is not an array")
        required = required_recovery_slot_rvas_v2(raw_recoveries)
        required_dependencies = _required_slot_dependencies(raw_recoveries)
        active_proposals = _active_proposal_slot_dependencies(
            proposal_slot_dependencies,
            recoveries=raw_recoveries,
        )
        required = required | frozenset(
            slot_rva for slot_rva, _exit_id, _unit_id, _event_index, _witness in active_proposals
        )
        required_dependencies.update(active_proposals)
        raw_slots = global_slot_analysis.get("slots", ())
        if not isinstance(raw_slots, Sequence) or isinstance(raw_slots, (str, bytes)):
            raise ValueError("global-slot replay inventory is not an array")
        if not raw_slots and not required:
            return True, [], [], [], [], None, active_proposals
        bindings = global_slot_analysis.get("bindings")
        image_base = bindings.get("image_base") if isinstance(bindings, Mapping) else None
        if not isinstance(image_base, int) or isinstance(image_base, bool):
            raise ValueError("global-slot replay has no image-base binding")
        analyzed: set[int] = set()
        for row in raw_slots:
            address = row.get("address") if isinstance(row, Mapping) else None
            if (
                not isinstance(address, int)
                or isinstance(address, bool)
                or not image_base <= address <= 0xFFFF_FFFF
            ):
                raise ValueError("global-slot replay contains a malformed address")
            analyzed.add(address - image_base)
        analyzed_dependencies = _analyzed_slot_dependencies(
            global_slot_analysis,
            image_base=image_base,
        )
    except ValueError as exc:
        return (
            False,
            sorted(required),
            [],
            [_slot_dependency_payload(key) for key in sorted(required_dependencies)],
            [],
            str(exc),
            set(),
        )
    missing_dependencies = required_dependencies - analyzed_dependencies
    extra_dependencies = analyzed_dependencies - required_dependencies
    return (
        analyzed == required
        and not missing_dependencies
        and not extra_dependencies,
        sorted(required - analyzed),
        sorted(analyzed - required),
        [_slot_dependency_payload(key) for key in sorted(missing_dependencies)],
        [_slot_dependency_payload(key) for key in sorted(extra_dependencies)],
        None,
        active_proposals,
    )


def _active_proposal_slot_dependencies(
    dependencies: Sequence[Mapping[str, Any]],
    *,
    recoveries: Sequence[Mapping[str, Any]],
) -> set[tuple[int, str, str, int, bool]]:
    """Return canonical proposal-only rows for cold-incomplete exits.

    These rows expand the diagnostic replay inventory, but the separate
    discharge check prevents them from contributing to a complete result.
    """

    if not isinstance(dependencies, Sequence) or isinstance(
        dependencies, (str, bytes)
    ):
        raise ValueError("proposal slot dependency inventory is not an array")
    cold_status = {
        str(row.get("id")): row.get("status")
        for row in recoveries
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    result: set[tuple[int, str, str, int, bool]] = set()
    observed: list[tuple[int, str, str, int, bool]] = []
    for row in dependencies:
        witness_only = row.get("witness_only") is True if isinstance(row, Mapping) else False
        expected_fields = (
            {"slot_rva", "exit_id", "witness_only", "proof_authority"}
            if witness_only
            else {
                "slot_rva", "exit_id", "unit_id", "event_index", "proof_authority"
            }
        )
        unit_id = row.get("unit_id") if isinstance(row, Mapping) else None
        event_index = row.get("event_index") if isinstance(row, Mapping) else None
        if (
            not isinstance(row, Mapping)
            or set(row) != expected_fields
            or not isinstance(row.get("slot_rva"), int)
            or isinstance(row.get("slot_rva"), bool)
            or row["slot_rva"] < 0
            or not isinstance(row.get("exit_id"), str)
            or not row["exit_id"]
            or row.get("proof_authority") is not False
            or row["exit_id"] not in cold_status
            or (
                not witness_only
                and (
                    not isinstance(unit_id, str)
                    or not unit_id
                    or not isinstance(event_index, int)
                    or isinstance(event_index, bool)
                    or event_index < 0
                )
            )
        ):
            raise ValueError("proposal slot dependency is malformed")
        identity = (
            int(row["slot_rva"]),
            str(row["exit_id"]),
            "" if witness_only else str(unit_id),
            -1 if witness_only else int(event_index),
            witness_only,
        )
        observed.append(identity)
        if cold_status[row["exit_id"]] == "incomplete":
            result.add(identity)
    if observed != sorted(set(observed)):
        raise ValueError("proposal slot dependency inventory is not canonical")
    return result


def _required_slot_dependencies(
    recoveries: Sequence[Mapping[str, Any]],
) -> set[tuple[int, str, str, int, bool]]:
    result: set[tuple[int, str, str, int, bool]] = set()
    for recovery in recoveries:
        exit_id = recovery.get("id") if isinstance(recovery, Mapping) else None
        raw_dependencies = (
            recovery.get("mutable_slot_dependencies", ())
            if isinstance(recovery, Mapping)
            else ()
        )
        if not isinstance(raw_dependencies, Sequence) or isinstance(
            raw_dependencies, (str, bytes)
        ):
            raise ValueError("mutable-slot dependency inventory is not an array")
        if raw_dependencies and (not isinstance(exit_id, str) or not exit_id):
            raise ValueError("mutable-slot recovery has no exact exit ID")
        for dependency in raw_dependencies:
            if not isinstance(dependency, Mapping):
                raise ValueError("mutable-slot dependency is not an object")
            slot_rva = dependency.get("slot_rva")
            read_sites = dependency.get("read_sites", ())
            if not isinstance(read_sites, Sequence) or isinstance(
                read_sites, (str, bytes)
            ):
                raise ValueError("mutable-slot read-site inventory is not an array")
            if not read_sites:
                result.add((int(slot_rva), str(exit_id), "", -1, True))
                continue
            for site in read_sites:
                unit_id = site.get("unit_id") if isinstance(site, Mapping) else None
                event_index = (
                    site.get("event_index") if isinstance(site, Mapping) else None
                )
                if (
                    not isinstance(unit_id, str)
                    or not unit_id
                    or not isinstance(event_index, int)
                    or isinstance(event_index, bool)
                    or event_index < 0
                ):
                    raise ValueError("mutable-slot read site is malformed")
                result.add((int(slot_rva), str(exit_id), unit_id, event_index, False))
    return result


def _analyzed_slot_dependencies(
    global_slot_analysis: Mapping[str, Any],
    *,
    image_base: int,
) -> set[tuple[int, str, str, int, bool]]:
    raw_evidence = global_slot_analysis.get("global_slot_evidence", ())
    if not isinstance(raw_evidence, Sequence) or isinstance(
        raw_evidence, (str, bytes)
    ):
        raise ValueError("global-slot evidence inventory is not an array")
    result: set[tuple[int, str, str, int, bool]] = set()
    for evidence in raw_evidence:
        address = evidence.get("address") if isinstance(evidence, Mapping) else None
        dependencies = (
            evidence.get("target_dependencies", ())
            if isinstance(evidence, Mapping)
            else ()
        )
        if (
            not isinstance(address, int)
            or isinstance(address, bool)
            or address < image_base
            or not isinstance(dependencies, Sequence)
            or isinstance(dependencies, (str, bytes))
        ):
            raise ValueError("global-slot evidence contains a malformed binding")
        slot_rva = address - image_base
        for dependency in dependencies:
            if not isinstance(dependency, Mapping):
                raise ValueError("global-slot target dependency is not an object")
            exit_id = dependency.get("exit_id")
            if not isinstance(exit_id, str) or not exit_id:
                raise ValueError("global-slot target dependency has no exit ID")
            if dependency.get("witness_only") is True:
                result.add((slot_rva, exit_id, "", -1, True))
                continue
            unit_id = dependency.get("unit_id")
            event_index = dependency.get("event_index")
            if (
                not isinstance(unit_id, str)
                or not unit_id
                or not isinstance(event_index, int)
                or isinstance(event_index, bool)
                or event_index < 0
            ):
                raise ValueError("global-slot target dependency has a malformed read site")
            result.add((slot_rva, exit_id, unit_id, event_index, False))
    return result


def _slot_dependency_payload(
    key: tuple[int, str, str, int, bool],
) -> dict[str, Any]:
    slot_rva, exit_id, unit_id, event_index, witness_only = key
    return {
        "slot_rva": slot_rva,
        "exit_id": exit_id,
        **(
            {"witness_only": True}
            if witness_only
            else {"unit_id": unit_id, "event_index": event_index}
        ),
    }


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
