"""Public operation-provenance artifact over the shared Stage A dataflow."""

from __future__ import annotations

import copy
from typing import Any, Mapping

from .artifact_formats import OPERATION_PROVENANCE_FORMAT


def operation_provenance_view(result: Mapping[str, Any]) -> dict[str, Any]:
    """Project the shared analysis into its generic, non-authoritative schema."""

    return {
        "format": OPERATION_PROVENANCE_FORMAT,
        "status": result.get("status", "incomplete"),
        "proof_authority": False,
        "required_replay": copy.deepcopy(result.get("required_replay", [])),
        "profiles": copy.deepcopy(result.get("profiles", [])),
        "fixed_point": copy.deepcopy(result.get("fixed_point", {})),
        "budgets": copy.deepcopy(result.get("budgets", {})),
        "static_value_slots": copy.deepcopy(
            result.get("static_interface_slots", [])
        ),
        "resolutions": copy.deepcopy(result.get("resolutions", [])),
        "call_refinements": copy.deepcopy(
            result.get("call_argument_recoveries", [])
        ),
        "issues": copy.deepcopy(result.get("issues", [])),
        "counts": copy.deepcopy(result.get("counts", {})),
        "authority": {
            "analysis_is_proposal_only": True,
            "profile_identity_is_semantic_proof": False,
            "lean_replay_required": True,
            "environment_contract_required": True,
        },
    }


__all__ = ["OPERATION_PROVENANCE_FORMAT", "operation_provenance_view"]
