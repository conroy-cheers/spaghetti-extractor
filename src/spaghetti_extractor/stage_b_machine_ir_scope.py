"""Select the explicit candidate-execution scope of a Stage B machine IR.

This module has no qualification authority.  It permits a diagnostic hybrid
candidate to omit semantically incomplete *potential* units while preserving a
stable inventory of every omitted RVA.  Missing runtime dispatch remains
fail-closed.  Reachable or ambiguously classified incomplete units are never
omitted.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def partition_candidate_machine_ir_units(
    units: list[dict[str, Any]],
    *,
    allow_deferred_potential_transfers: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not allow_deferred_potential_transfers:
        return units, []

    active: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    for index, unit in enumerate(units):
        if (
            unit.get("status") == "incomplete"
            and unit.get("reachable") is False
            and unit.get("reachability") == "potential"
        ):
            source = unit.get("source")
            original = source.get("original") if isinstance(source, Mapping) else None
            source_status = unit.get("source_status")
            source_status = source_status if isinstance(source_status, Mapping) else {}
            deferred.append({
                "transfer_index": index,
                "transfer_id": unit.get("id") if isinstance(unit.get("id"), str) else None,
                "rva_start": (
                    original.get("rva_start")
                    if isinstance(original, Mapping)
                    and isinstance(original.get("rva_start"), int)
                    and not isinstance(original.get("rva_start"), bool)
                    else None
                ),
                "code": "machine_ir_semantics_incomplete",
                "failure_phase": "semantic_qualification",
                "message": str(
                    source_status.get("blocker")
                    or "machine-IR unit has incomplete checked semantics"
                ),
                "next_action": str(
                    source_status.get("next_action")
                    or "classify the bytes as non-code or implement and qualify their semantics"
                ),
                "reachability": "potential",
                "runtime_disposition": "fail_closed_as_unimplemented_if_reached",
            })
            continue
        active.append(unit)
    return active, deferred


__all__ = ["partition_candidate_machine_ir_units"]
