"""Bounded, non-authorizing views over checked work subjects."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..errors import ToolkitInputError
from ..util import write_json
from .formats import OPERATOR_BLOCKER_DETAIL_FORMAT, OPERATOR_WORK_STATUS_FORMAT


_SUBJECT_FIELDS = {
    "subject", "kind", "state", "authority", "stage", "sources", "blockers",
    "next_action",
}
_SOURCE_FIELDS = {"role", "format", "sha256"}
_BLOCKER_FIELDS = {"family", "code", "location"}
_AUTHORITY_STATES = {"held", "missing", "not-applicable"}


def _rows(value: object, context: str) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)) or any(
        not isinstance(row, Mapping) for row in value
    ):
        raise ToolkitInputError(f"{context} must be an array of objects")
    return [copy.deepcopy(dict(row)) for row in value]


def _nonempty(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ToolkitInputError(f"{context} must be a nonempty string")
    return value


def _sha256(value: object, context: str) -> str:
    digest = _nonempty(value, context)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ToolkitInputError(f"{context} must be a lowercase SHA-256 digest")
    return digest


def _sources(value: object, subject: str) -> list[dict[str, str]]:
    rows = _rows(value, f"{subject} sources")
    checked: list[dict[str, str]] = []
    for index, row in enumerate(rows):
        if set(row) != _SOURCE_FIELDS:
            raise ToolkitInputError(f"{subject} source {index} fields are incomplete")
        checked.append({
            "role": _nonempty(row["role"], f"{subject} source role"),
            "format": _nonempty(row["format"], f"{subject} source format"),
            "sha256": _sha256(row["sha256"], f"{subject} source digest"),
        })
    checked.sort(key=lambda row: (row["role"], row["format"], row["sha256"]))
    if len({(row["role"], row["format"], row["sha256"]) for row in checked}) != len(checked):
        raise ToolkitInputError(f"{subject} sources are duplicated")
    return checked


def _blocker_summary(value: object, subject: str) -> dict[str, object]:
    rows = _rows(value, f"{subject} blockers")
    grouped: dict[tuple[str, str], dict[str, object]] = {}
    for index, row in enumerate(rows):
        if set(row) != _BLOCKER_FIELDS:
            raise ToolkitInputError(f"{subject} blocker {index} fields are incomplete")
        family = _nonempty(row["family"], f"{subject} blocker family")
        code = _nonempty(row["code"], f"{subject} blocker code")
        location = row["location"]
        if location is not None and (not isinstance(location, str) or not location):
            raise ToolkitInputError(f"{subject} blocker location is malformed")
        key = (family, code)
        if key not in grouped:
            grouped[key] = {
                "family": family,
                "code": code,
                "count": 0,
                "example_location": location,
            }
        grouped[key]["count"] = int(grouped[key]["count"]) + 1
        if grouped[key]["example_location"] is None and location is not None:
            grouped[key]["example_location"] = location
    return {
        "count": len(rows),
        "groups": [grouped[key] for key in sorted(grouped)],
    }


def build_operator_work_status_v2(
    *, target_id: str, scope: str, subjects: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build one deterministic diagnostic view without granting authority."""

    target_id = _nonempty(target_id, "operator status target ID")
    scope = _nonempty(scope, "operator status scope")
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
        kind = row["kind"]
        stage = row["stage"]
        next_action = row["next_action"]
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
        if authority not in _AUTHORITY_STATES or (
            authority == "held" and state != "complete"
        ):
            raise ToolkitInputError(
                f"operator work subject {subject} authority is inconsistent"
            )
        if not isinstance(kind, str) or not kind:
            raise ToolkitInputError(
                f"operator work subject {subject} kind is malformed"
            )
        if stage is not None and (not isinstance(stage, str) or not stage):
            raise ToolkitInputError(
                f"operator work subject {subject} stage is malformed"
            )
        if next_action is not None and (
            not isinstance(next_action, str) or not next_action
        ):
            raise ToolkitInputError(
                f"operator work subject {subject} next action is malformed"
            )
        checked.append({
            "subject": subject,
            "kind": kind,
            "state": state,
            "authority": authority,
            "stage": stage,
            "sources": _sources(row["sources"], subject),
            "blockers": _blocker_summary(row["blockers"], subject),
            "next_action": next_action,
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
        "authority_held": sum(row["authority"] == "held" for row in checked),
        "blockers": sum(int(row["blockers"]["count"]) for row in checked),
    }
    payload: dict[str, Any] = {
        "format": OPERATOR_WORK_STATUS_FORMAT,
        "target_id": target_id,
        "scope": scope,
        "status": (
            "violated" if counts["violated"]
            else "incomplete" if counts["incomplete"]
            else "complete"
        ),
        "counts": counts,
        "subjects": checked,
    }
    return payload


def write_operator_work_status_v2(
    *, target_id: str, scope: str, subjects: Sequence[Mapping[str, Any]], out: Path,
) -> dict[str, Any]:
    payload = build_operator_work_status_v2(
        target_id=target_id, scope=scope, subjects=subjects
    )
    output = Path(out)
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(output, payload)
    return payload


def build_operator_blocker_detail_v1(
    *,
    target_id: str,
    subject: str,
    source_format: str,
    source_sha256: str,
    blockers: Sequence[Mapping[str, Any]],
    family: str | None,
    code: str | None,
    limit: int | None,
) -> dict[str, object]:
    """Wrap explicitly requested source-native blockers for JSON clients."""

    if family is not None:
        family = _nonempty(family, "blocker detail family filter")
    if code is not None:
        code = _nonempty(code, "blocker detail code filter")
    if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 1):
        raise ToolkitInputError("blocker detail limit must be positive")
    rows = _rows(blockers, f"{subject} blocker details")
    returned = rows if limit is None else rows[:limit]
    return {
        "format": OPERATOR_BLOCKER_DETAIL_FORMAT,
        "target_id": _nonempty(target_id, "blocker detail target ID"),
        "subject": _nonempty(subject, "blocker detail subject"),
        "source": {
            "format": _nonempty(source_format, "blocker detail source format"),
            "sha256": _sha256(source_sha256, "blocker detail source digest"),
        },
        "filters": {"family": family, "code": code},
        "total": len(rows),
        "returned": len(returned),
        "blockers": returned,
    }


__all__ = [
    "build_operator_blocker_detail_v1",
    "build_operator_work_status_v2",
    "write_operator_work_status_v2",
]
