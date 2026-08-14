"""Checked, non-authorizing project and candidate readiness reports."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Mapping

from ..util import write_json


PROJECT_PROGRESS_FORMAT = "spaghetti-extractor-project-progress-v1"


class ProjectProgressError(ValueError):
    """A checked progress input is malformed."""


def build_project_progress(
    *,
    target_id: str,
    configuration_id: str,
    authority_diagnostics: Path | str,
    configuration_status: Path | str,
    candidate_test_suites: Mapping[str, object],
    out: Path | str,
) -> dict[str, object]:
    """Combine checked static and component frontiers without opening a gate."""

    authority = _load(authority_diagnostics, "authority diagnostics")
    configuration = _load(configuration_status, "component configuration status")
    if not target_id or not configuration_id:
        raise ProjectProgressError("target and configuration IDs must be nonempty")
    if configuration.get("configuration_id") != configuration_id:
        raise ProjectProgressError("component configuration status binds another ID")

    authority_status = _status(authority.get("status"), "authority status")
    configuration_state = _status(
        configuration.get("status"), "component configuration status"
    )
    authority_ready = authority.get("authorizing") is True
    configuration_ready = configuration_state == "ready"
    frontiers = _authority_frontiers(authority)
    configuration_frontiers = _configuration_frontiers(
        configuration, configuration_id
    )
    frontiers.extend(configuration_frontiers)
    frontiers.sort(key=_frontier_key)

    if authority_status == "violated" or configuration_state == "violated":
        status = "violated"
    elif authority_ready and configuration_ready:
        status = "ready"
    else:
        status = "incomplete"
    candidate_state = (
        "ready_to_build"
        if status == "ready"
        else "blocked_by_violation"
        if status == "violated"
        else "blocked_by_authority"
        if not authority_ready
        else "blocked_by_component_configuration"
    )
    suites = _suite_rows(candidate_test_suites, configuration_id)
    next_action = (
        copy.deepcopy(frontiers[0].get("next_action"))
        if frontiers
        else f"build candidate configuration {configuration_id}"
    )
    core: dict[str, object] = {
        "format": PROJECT_PROGRESS_FORMAT,
        "target_id": target_id,
        "configuration_id": configuration_id,
        "status": status,
        "authorizing": False,
        "static_ready": status == "ready",
        "authority": {
            "status": authority_status,
            "authorizing": authority_ready,
            "counts": copy.deepcopy(authority.get("counts", {})),
        },
        "component_configuration": {
            "status": configuration_state,
            "counts": copy.deepcopy(configuration.get("counts", {})),
        },
        "candidate": {
            "status": candidate_state,
            "declared_test_suites": suites,
            "candidate_authority_checked": False,
            "runtime_executed": False,
        },
        "counts": {
            "primary_frontiers": len(frontiers),
            "dependent_occurrences": _count(
                authority.get("counts"), "dependent_occurrences"
            )
            + sum(
                int(row.get("dependent_occurrences", 0))
                for row in configuration_frontiers
                if isinstance(row.get("dependent_occurrences", 0), int)
            ),
            "candidate_test_suites": len(suites),
        },
        "primary_frontiers": frontiers,
        "next_action": next_action,
        "policy": {
            "diagnostic_only": True,
            "candidate_gate_bypassed": False,
            "original_binary_executed": False,
        },
    }
    result = {**core, "progress_sha256": _canonical_sha256(core)}
    write_json(Path(out), result)
    return result


def _load(path: Path | str, description: str) -> Mapping[str, object]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProjectProgressError(f"cannot read {description}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ProjectProgressError(f"{description} must be an object")
    return value


def _status(value: object, description: str) -> str:
    if value not in {"complete", "incomplete", "violated", "ready"}:
        raise ProjectProgressError(f"{description} is unsupported: {value!r}")
    return str(value)


def _count(value: object, name: str) -> int:
    if not isinstance(value, Mapping):
        raise ProjectProgressError("authority counts must be an object")
    count = value.get(name, 0)
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise ProjectProgressError(f"authority count {name} is invalid")
    return count


def _authority_frontiers(value: Mapping[str, object]) -> list[dict[str, object]]:
    rows = value.get("primary_frontiers", [])
    if not isinstance(rows, list) or any(not isinstance(row, Mapping) for row in rows):
        raise ProjectProgressError("authority primary frontiers must be an array")
    return [copy.deepcopy(dict(row)) for row in rows]


def _configuration_frontiers(
    value: Mapping[str, object], configuration_id: str
) -> list[dict[str, object]]:
    rows = value.get("blockers", [])
    if not isinstance(rows, list) or any(not isinstance(row, Mapping) for row in rows):
        raise ProjectProgressError("component blockers must be an array")
    result = []
    for index, raw in enumerate(rows):
        row = dict(raw)
        code = str(row.get("code", "component_configuration_incomplete"))
        result.append(
            {
                "status": row.get("status", "incomplete"),
                "family": "component-configuration",
                "code": code,
                "record_id": f"component:{configuration_id}:{index}:{code}",
                "dependent_occurrences": 0,
                "source_location": row.get("source_location"),
                "next_action": row.get("detail")
                or row.get("message")
                or f"repair component configuration {configuration_id}",
                "details": copy.deepcopy(row),
            }
        )
    return result


def _suite_rows(
    value: Mapping[str, object], configuration_id: str
) -> list[dict[str, object]]:
    rows = []
    for identity in sorted(value):
        raw = value[identity]
        if not isinstance(raw, Mapping):
            raise ProjectProgressError("candidate test suite metadata must be objects")
        if raw.get("configurationId") == configuration_id:
            rows.append(
                {
                    "id": identity,
                    "case_ids": copy.deepcopy(raw.get("caseIds", [])),
                }
            )
    return rows


def _frontier_key(value: Mapping[str, object]) -> tuple[int, str, str, str]:
    return (
        0 if value.get("status") == "violated" else 1,
        str(value.get("family", "")),
        str(value.get("code", "")),
        str(value.get("record_id", "")),
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


__all__ = [
    "PROJECT_PROGRESS_FORMAT",
    "ProjectProgressError",
    "build_project_progress",
]
