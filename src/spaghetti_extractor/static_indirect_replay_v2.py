"""Exact replay of static PE32 indirect-control recoveries.

Machine-IR recovery rows are proposals. This module reconstructs the subset
that can authorize cold interprocedural analysis directly from exact unit
semantics and PE bytes. Unsupported recovery mechanisms remain incomplete.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from .indirect_target_dependency_v2 import build_bounded_selector_dependency_v2
from .reconstruction_control import recover_static_pe32_jump_table_inventory
from .stage_binary import StageABinary


def replay_exact_static_recoveries_v2(
    *,
    binary: StageABinary,
    units: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Rebuild predecessor-bounded immutable jump tables from authority inputs."""

    starts = {
        int(source["rva_start"]): unit
        for unit in units
        for source in (unit.get("source", {}).get("original", {}),)
        if isinstance(source, Mapping)
        and isinstance(source.get("rva_start"), int)
        and not isinstance(source.get("rva_start"), bool)
    }
    units_by_id = {
        str(unit.get("id")): unit
        for unit in units
        if isinstance(unit.get("id"), str)
    }
    predecessors = direct_predecessors_by_target(units)
    result: list[dict[str, Any]] = []
    for exit_record in indirect_exits:
        source_unit_id = exit_record.get("source_unit_id")
        source_unit = units_by_id.get(source_unit_id)
        if source_unit is None:
            result.append(
                _incomplete_recovery(exit_record, "static_recovery_source_missing")
            )
            continue
        target_expression = exit_record.get("target_expression")
        if not isinstance(target_expression, Mapping):
            result.append(
                _incomplete_recovery(
                    exit_record, "static_recovery_target_expression_missing"
                )
            )
            continue
        recovery = recover_static_pe32_jump_table_inventory(
            target_expression=target_expression,
            predecessor_evidence=indirect_predecessor_evidence(
                source_unit,
                predecessors_by_target=predecessors,
            ),
            image_base=binary.image_base,
            sections=binary.sections,
            read_rva=lambda rva, size: bytes(binary.pe.get_data(rva, size)),
            finite_index_domain=None,
            valid_target_rvas=starts,
        )
        recovery_kind = recovery.get("kind")
        target_rvas = [
            int(rva)
            for rva in recovery.get("target_rvas", [])
            if isinstance(rva, int) and not isinstance(rva, bool)
        ]
        resolved = sorted(rva for rva in target_rvas if rva in starts)
        unresolved = sorted(rva for rva in target_rvas if rva not in starts)
        recovery.update(
            {
                "id": exit_record.get("id"),
                "recovery_kind": recovery_kind,
                "source_unit_id": source_unit_id,
                "source_rva": exit_record.get("source_rva"),
                "source_event_index": exit_record.get("source_event_index"),
                "kind": exit_record.get("kind"),
                "target_expression": copy.deepcopy(target_expression),
                "target_unit_ids": [str(starts[rva]["id"]) for rva in resolved],
                "external_targets": [],
                "unit_binding": {
                    "status": (
                        "complete"
                        if recovery.get("status") == "recovered" and not unresolved
                        else "incomplete"
                    ),
                    "resolved_target_rvas": resolved,
                    "unmaterialized_target_rvas": unresolved,
                },
            }
        )
        if (
            recovery.get("status") == "recovered"
            and recovery.get("closure") == "checked_finite_target_inventory"
            and recovery_kind == "pe32_indexed_absolute_jump_table"
            and recovery.get("failure") is None
            and recovery["unit_binding"]["status"] == "complete"
        ):
            recovery["target_set_dependency"] = (
                build_bounded_selector_dependency_v2(recovery)
            )
        result.append(recovery)
    return result


def indirect_predecessor_evidence(
    source_unit: Mapping[str, Any],
    *,
    predecessors_by_target: Mapping[int, Sequence[Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    source_rva = int(source_unit["source"]["original"]["rva_start"])
    result: list[dict[str, Any]] = []
    for predecessor in predecessors_by_target.get(source_rva, []):
        outcome = predecessor.get("semantics", {}).get("outcome", {})
        edge_kind = "fallthrough"
        if isinstance(outcome, Mapping) and outcome.get("kind") == "branch":
            edge_kind = (
                "taken"
                if outcome.get("true_target_rva") == source_rva
                else "fallthrough"
            )
        guard = None
        for edge in predecessor.get("semantics", {}).get("edge_conditions", []):
            if isinstance(edge, Mapping) and edge.get("target_rva") == source_rva:
                guard = copy.deepcopy(edge.get("condition"))
                break
        result.append(
            {
                "source_unit_id": predecessor["id"],
                "edge_kind": edge_kind,
                "guard": guard,
                "instructions": bounded_predecessor_instruction_history(
                    predecessor,
                    predecessors_by_target=predecessors_by_target,
                ),
            }
        )
    return sorted(result, key=lambda item: str(item["source_unit_id"]))


def direct_predecessors_by_target(
    units: Sequence[Mapping[str, Any]],
) -> dict[int, list[Mapping[str, Any]]]:
    predecessors_by_target: dict[int, list[Mapping[str, Any]]] = {}
    for candidate in units:
        control = candidate.get("control")
        if not isinstance(control, Mapping):
            continue
        for target in control.get("direct_targets", []):
            if isinstance(target, int) and not isinstance(target, bool):
                predecessors_by_target.setdefault(target, []).append(candidate)
    return predecessors_by_target


def bounded_predecessor_instruction_history(
    predecessor: Mapping[str, Any],
    *,
    predecessors_by_target: Mapping[int, Sequence[Mapping[str, Any]]],
    max_units: int = 8,
) -> list[dict[str, Any]]:
    history = [
        copy.deepcopy(dict(instruction))
        for instruction in predecessor.get("instructions", [])
        if isinstance(instruction, Mapping)
    ]
    cursor = predecessor
    visited = {str(predecessor.get("id"))}
    for _ in range(max_units - 1):
        if any(
            str(instruction.get("mnemonic", "")).lower() == "cmp"
            for instruction in history
        ):
            break
        source = cursor.get("source", {}).get("original", {})
        start = source.get("rva_start") if isinstance(source, Mapping) else None
        if not isinstance(start, int) or isinstance(start, bool):
            break
        candidates = []
        for candidate in predecessors_by_target.get(start, []):
            candidate_id = str(candidate.get("id"))
            candidate_source = candidate.get("source", {}).get("original", {})
            candidate_outcome = candidate.get("semantics", {}).get("outcome", {})
            candidate_events = candidate.get("semantics", {}).get(
                "external_events", []
            )
            if (
                candidate_id in visited
                or not isinstance(candidate_source, Mapping)
                or candidate_source.get("rva_end") != start
                or not isinstance(candidate_outcome, Mapping)
                or candidate_outcome.get("kind") != "fallthrough"
                or candidate_outcome.get("target_rva") != start
                or (isinstance(candidate_events, list) and candidate_events)
            ):
                continue
            candidates.append(candidate)
        if len(candidates) != 1:
            break
        cursor = candidates[0]
        visited.add(str(cursor.get("id")))
        prefix = [
            copy.deepcopy(dict(instruction))
            for instruction in cursor.get("instructions", [])
            if isinstance(instruction, Mapping)
        ]
        history = prefix + history
    return history


def _incomplete_recovery(
    exit_record: Mapping[str, Any], code: str
) -> dict[str, Any]:
    return {
        **copy.deepcopy(dict(exit_record)),
        "status": "incomplete",
        "closure": "unresolved",
        "target_rvas": [],
        "target_unit_ids": [],
        "external_targets": [],
        "failure": {"code": code},
    }
