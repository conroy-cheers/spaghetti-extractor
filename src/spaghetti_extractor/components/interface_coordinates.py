"""Component-boundary coordinate checks over exact machine IR."""

from __future__ import annotations

import copy
from typing import Any, Mapping, Sequence

from ..machine_ir.entry_coordinates import (
    normalize_unit_expression_to_component_entry,
)
from .interface_schema import _issue, _unit_rva


def component_entry_unit_id(
    component: Mapping[str, Any],
    member_ids: Sequence[str],
    machine: Mapping[str, Any],
    issues: list[dict[str, Any]],
) -> str | None:
    boundary = component.get("machine_boundary")
    entries = boundary.get("entries") if isinstance(boundary, Mapping) else None
    exact_entries = (
        [
            row.get("unit_id")
            for row in entries
            if isinstance(row, Mapping) and isinstance(row.get("unit_id"), str)
        ]
        if isinstance(entries, list)
        else _derived_component_entries(member_ids, machine)
    )
    exact_entries = sorted(set(exact_entries))
    if len(exact_entries) != 1 or exact_entries[0] not in member_ids:
        _issue(
            issues,
            "incomplete",
            "component_entry_coordinate_not_unique",
            "/component_id",
            expected="exactly one checked machine-boundary entry in the component",
            observed=exact_entries,
            remediation=(
                "split the component by entry or define an explicit checked "
                "multi-entry state relation"
            ),
        )
        return None
    return exact_entries[0]


def normalize_component_entry_expression(
    *,
    machine: Mapping[str, Any],
    member_ids: Sequence[str],
    entry_unit_id: str,
    target_unit_id: str,
    expression: object,
    target_memory_event_count: int = 0,
    issues: list[dict[str, Any]],
    json_location: str,
) -> object | None:
    units = [machine["units_by_id"][unit_id] for unit_id in member_ids]
    result = normalize_unit_expression_to_component_entry(
        units,
        entry_unit_id=entry_unit_id,
        target_unit_id=target_unit_id,
        expression=expression,
        target_memory_event_count=target_memory_event_count,
    )
    if result.get("status") == "complete":
        return copy.deepcopy(result.get("expression"))
    _issue(
        issues,
        "incomplete",
        str(result.get("code", "component_entry_coordinate_incomplete")),
        json_location,
        unit_id=target_unit_id,
        rva=(
            _unit_rva(machine["units_by_id"][target_unit_id])
            if target_unit_id in machine["units_by_id"]
            else None
        ),
        expected="an exact finite normalization to component-entry state",
        observed=result.get("message"),
        remediation=(
            "choose an earlier evidence expression, split the component, or add "
            "the missing checked alias/control invariant"
        ),
    )
    return None


def evidence_memory_prefix_count(
    unit: Mapping[str, Any], json_pointer: str
) -> int:
    prefix = "/semantics/memory_events/"
    if json_pointer.startswith(prefix):
        remainder = json_pointer[len(prefix) :]
        index_text = remainder.split("/", 1)[0]
        if index_text.isdigit():
            return int(index_text)
    if (
        json_pointer.startswith("/semantics/register_writes/")
        or json_pointer.startswith("/semantics/flag_writes/")
        or json_pointer.startswith("/semantics/outcome")
    ):
        semantics = unit.get("semantics")
        events = (
            semantics.get("memory_events")
            if isinstance(semantics, Mapping)
            else None
        )
        return len(events) if isinstance(events, list) else 0
    if json_pointer.startswith("/semantics/external_events/"):
        remainder = json_pointer[len("/semantics/external_events/") :]
        index_text = remainder.split("/", 1)[0]
        if index_text.isdigit():
            return external_event_memory_prefix_count(unit, int(index_text))
    return 0


def external_event_memory_prefix_count(
    unit: Mapping[str, Any], event_index: int
) -> int:
    semantics = unit.get("semantics")
    ordered = (
        semantics.get("ordered_events") if isinstance(semantics, Mapping) else None
    )
    if not isinstance(ordered, list):
        return 0
    memory_count = 0
    external_count = 0
    for event in ordered:
        if not isinstance(event, Mapping):
            continue
        family = event.get("family")
        if family == "external":
            if external_count == event_index:
                return memory_count
            external_count += 1
        elif family == "memory":
            memory_count += 1
    return 0


def _derived_component_entries(
    member_ids: Sequence[str], machine: Mapping[str, Any]
) -> list[str]:
    rva_to_id = {
        _unit_rva(machine["units_by_id"][unit_id]): unit_id
        for unit_id in member_ids
    }
    incoming: set[str] = set()
    for unit_id in member_ids:
        unit = machine["units_by_id"][unit_id]
        semantics = unit.get("semantics")
        outcome = semantics.get("outcome") if isinstance(semantics, Mapping) else None
        if not isinstance(outcome, Mapping):
            continue
        for key in ("target_rva", "true_target_rva", "false_target_rva"):
            target = outcome.get(key)
            if isinstance(target, int) and target in rva_to_id:
                incoming.add(rva_to_id[target])
    return sorted(set(member_ids) - incoming)


__all__ = [
    "component_entry_unit_id",
    "evidence_memory_prefix_count",
    "external_event_memory_prefix_count",
    "normalize_component_entry_expression",
]
