from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from ..util import utc_now, write_json


WorkerPhase = Literal["analysis", "preparation", "proposal"]


def write_worker_diagnostic(
    *,
    out: Path,
    phase: WorkerPhase,
    started_at: str,
    original: Path,
    candidate: Path,
    reason_code: str,
    message: str,
    issues: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Write a fail-closed worker diagnostic with no proof authority."""

    issue_rows = issues or []
    payload = {
        "format": "stage-a-relational-worker-diagnostic-v1",
        "status": "incomplete",
        "acceptance_authority": False,
        "phase": phase,
        "reason_code": reason_code,
        "message": message,
        "started_at": started_at,
        "completed_at": utc_now(),
        "original": {"path": str(original)},
        "candidate": {"path": str(candidate)},
        "issues": issue_rows,
    }
    write_json(out / "worker-diagnostic.json", payload)
    write_json(
        out / "coverage_gaps.json",
        {
            "format": "stage-a-relational-coverage-gaps-v1",
            "status": "incomplete",
            "gaps": issue_rows,
        },
    )
    return payload


__all__ = ["WorkerPhase", "write_worker_diagnostic"]
