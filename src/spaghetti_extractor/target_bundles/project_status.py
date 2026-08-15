"""Authority-only, non-authorizing project status reports."""

from __future__ import annotations

import copy
from pathlib import Path

from ..artifacts.formats import AUTHORITY_DIAGNOSTICS_V3_FORMAT
from ..util import write_json
from .status_common import (
    StatusArtifactError,
    canonical_sha256,
    checked_bool,
    checked_count,
    checked_status,
    copied_rows,
    frontier_key,
    load_object,
)


PROJECT_STATUS_FORMAT = "spaghetti-extractor-project-status-v2"


def build_project_status(
    *,
    target_id: str,
    authority_diagnostics: Path | str,
    out: Path | str,
) -> dict[str, object]:
    """Summarize checked authority without realizing component work."""

    if not target_id:
        raise StatusArtifactError("target ID must be nonempty")
    authority = load_object(authority_diagnostics, "authority diagnostics")
    if authority.get("format") != AUTHORITY_DIAGNOSTICS_V3_FORMAT:
        raise StatusArtifactError("authority diagnostics format is unsupported")
    authority_status = checked_status(
        authority.get("status"), "authority status", allow_complete=True
    )
    authority_authorizing = checked_bool(
        authority.get("authorizing"), "authority authorizing field"
    )
    authority_ready = authority_status == "complete" and authority_authorizing
    frontiers = copied_rows(
        authority.get("primary_frontiers", []), "authority primary frontiers"
    )
    frontiers.sort(key=frontier_key)
    dependent_occurrences = checked_count(
        authority.get("counts"), "dependent_occurrences", "authority"
    )
    primary_frontier_count = checked_count(
        authority.get("counts"), "primary_frontiers", "authority"
    )
    if primary_frontier_count != len(frontiers):
        raise StatusArtifactError("authority primary frontier count is inconsistent")
    status = (
        "violated"
        if authority_status == "violated"
        else "ready"
        if authority_ready
        else "incomplete"
    )
    core: dict[str, object] = {
        "format": PROJECT_STATUS_FORMAT,
        "target_id": target_id,
        "status": status,
        "authorizing": False,
        "authority_ready": authority_ready,
        "authority": {
            "status": authority_status,
            "authorizing": authority_authorizing,
            "counts": copy.deepcopy(authority.get("counts", {})),
        },
        "counts": {
            "primary_frontiers": len(frontiers),
            "dependent_occurrences": dependent_occurrences,
        },
        "primary_frontiers": frontiers,
        "next_action": (
            copy.deepcopy(frontiers[0].get("next_action"))
            if frontiers
            else "inspect component or candidate status"
        ),
        "policy": {
            "diagnostic_only": True,
            "candidate_gate_bypassed": False,
            "original_binary_executed": False,
        },
    }
    result = {**core, "project_status_sha256": canonical_sha256(core)}
    write_json(Path(out), result)
    return result


__all__ = ["PROJECT_STATUS_FORMAT", "StatusArtifactError", "build_project_status"]
