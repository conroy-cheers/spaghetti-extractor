"""Closed, non-authorizing status views over checked work subjects."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..errors import ToolkitInputError
from ..util import write_json
from .formats import OPERATOR_WORK_STATUS_FORMAT


_SUBJECT_FIELDS = {
    "subject", "state", "authority", "bindings", "blockers", "dependencies",
    "ranked_next_action",
}


def _rows(value: object, context: str) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)) or any(
        not isinstance(row, Mapping) for row in value
    ):
        raise ToolkitInputError(f"{context} must be an array of objects")
    return [copy.deepcopy(dict(row)) for row in value]


def build_operator_work_status_v1(
    subjects: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build one deterministic diagnostic view without granting authority."""

    checked: list[dict[str, Any]] = []
    for index, raw in enumerate(subjects):
        row = dict(raw)
        if set(row) != _SUBJECT_FIELDS:
            raise ToolkitInputError(
                f"operator work subject {index} fields are incomplete"
            )
        subject = row["subject"]
        state = row["state"]
        authority = row["authority"]
        next_action = row["ranked_next_action"]
        if (
            not isinstance(subject, str)
            or not subject
            or ":" not in subject
            or subject.startswith(":")
            or subject.endswith(":")
        ):
            raise ToolkitInputError(
                f"operator work subject {index} identity is malformed"
            )
        if state not in {"complete", "incomplete", "violated"}:
            raise ToolkitInputError(
                f"operator work subject {subject} state is unsupported"
            )
        if not isinstance(authority, bool) or (authority and state != "complete"):
            raise ToolkitInputError(
                f"operator work subject {subject} authority is inconsistent"
            )
        if next_action is not None and (
            not isinstance(next_action, str) or not next_action
        ):
            raise ToolkitInputError(
                f"operator work subject {subject} next action is malformed"
            )
        checked.append({
            "subject": subject,
            "state": state,
            "authority": authority,
            "bindings": _rows(row["bindings"], f"{subject} bindings"),
            "blockers": _rows(row["blockers"], f"{subject} blockers"),
            "dependencies": _rows(
                row["dependencies"], f"{subject} dependencies"
            ),
            "ranked_next_action": next_action,
        })
    checked.sort(key=lambda row: row["subject"])
    identities = [row["subject"] for row in checked]
    if identities != sorted(set(identities)):
        raise ToolkitInputError("operator work subjects are duplicated")
    counts = {
        "subjects": len(checked),
        "complete": sum(row["state"] == "complete" for row in checked),
        "incomplete": sum(row["state"] == "incomplete" for row in checked),
        "violated": sum(row["state"] == "violated" for row in checked),
        "authoritative": sum(row["authority"] for row in checked),
        "blockers": sum(len(row["blockers"]) for row in checked),
    }
    payload: dict[str, Any] = {
        "format": OPERATOR_WORK_STATUS_FORMAT,
        "status": (
            "violated" if counts["violated"]
            else "incomplete" if counts["incomplete"]
            else "complete"
        ),
        # The view reports authority held by its subjects; the view is never
        # itself an authority receipt.
        "authority": False,
        "counts": counts,
        "subjects": checked,
    }
    payload["view_sha256"] = canonical_sha256_v3(payload)
    return payload


def write_operator_work_status_v1(
    *, subjects: Sequence[Mapping[str, Any]], out: Path,
) -> dict[str, Any]:
    payload = build_operator_work_status_v1(subjects)
    output = Path(out)
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(output, payload)
    return payload


__all__ = ["build_operator_work_status_v1", "write_operator_work_status_v1"]
