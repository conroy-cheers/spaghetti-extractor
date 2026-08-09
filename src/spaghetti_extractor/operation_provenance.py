"""Public operation-provenance artifact over the shared Stage A dataflow."""

from __future__ import annotations

import copy
from typing import Any, Mapping, Sequence

from .artifact_formats import OPERATION_PROVENANCE_FORMAT


def operation_provenance_view(
    result: Mapping[str, Any],
    *,
    checked_control_exits: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Project the shared analysis into its generic, non-authoritative schema.

    Operation provenance is only one way to close an indirect transfer.  A
    separately checked static table is equally authoritative for control-flow
    discovery, so expose that closure without pretending the operation
    analysis recovered a receiver or API method.  The caller must pass the
    canonical post-conflict control inventory, never an unchecked proposal.
    """

    resolutions = _reconcile_checked_control(
        result.get("resolutions", []), checked_control_exits
    )
    issues = copy.deepcopy(result.get("issues", []))
    status = (
        "complete"
        if not issues
        and all(row.get("status") == "recovered" for row in resolutions)
        else "incomplete"
    )
    counts = copy.deepcopy(result.get("counts", {}))
    counts["checked_static_control_exits"] = sum(
        row.get("closure") == "checked_static_control_inventory"
        for row in resolutions
    )

    return {
        "format": OPERATION_PROVENANCE_FORMAT,
        "status": status,
        "proof_authority": False,
        "required_replay": copy.deepcopy(result.get("required_replay", [])),
        "profiles": copy.deepcopy(result.get("profiles", [])),
        "fixed_point": copy.deepcopy(result.get("fixed_point", {})),
        "budgets": copy.deepcopy(result.get("budgets", {})),
        "static_value_slots": copy.deepcopy(
            result.get("static_interface_slots", [])
        ),
        "resolutions": resolutions,
        "call_refinements": copy.deepcopy(
            result.get("call_argument_recoveries", [])
        ),
        "issues": issues,
        "counts": counts,
        "authority": {
            "analysis_is_proposal_only": True,
            "profile_identity_is_semantic_proof": False,
            "lean_replay_required": True,
            "environment_contract_required": True,
        },
    }


def _reconcile_checked_control(
    resolutions: Any,
    checked_control_exits: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    projected = [
        copy.deepcopy(dict(row))
        for row in resolutions
        if isinstance(row, Mapping)
    ] if isinstance(resolutions, list) else []
    by_id = {
        str(row.get("id")): index
        for index, row in enumerate(projected)
        if isinstance(row.get("id"), str)
    }
    for checked in checked_control_exits:
        recovery = checked.get("recovery")
        if (
            checked.get("closure") != "checked_finite_target_inventory"
            or not isinstance(recovery, Mapping)
            or recovery.get("kind") in {
                "bounded_external_interface_provenance",
                "bounded_external_operation_provenance",
                "bounded_value_provenance",
            }
        ):
            continue
        index = by_id.get(str(checked.get("id")))
        if index is None:
            continue
        current = projected[index]
        if current.get("status") == "recovered":
            continue
        projected[index] = {
            **current,
            "status": "recovered",
            "closure": "checked_static_control_inventory",
            "target_rvas": copy.deepcopy(checked.get("target_rvas", [])),
            "target_unit_ids": copy.deepcopy(
                checked.get("target_unit_ids", [])
            ),
            "external_targets": copy.deepcopy(
                checked.get("external_targets", [])
            ),
            "origin_count": None,
            "origin_kinds": ["checked_static_control"],
            "failure": None,
        }
    return projected


__all__ = ["OPERATION_PROVENANCE_FORMAT", "operation_provenance_view"]
