"""Combined authority and component readiness for one candidate configuration."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Mapping

from ..components.formats import COMPONENT_CONFIGURATION_STATUS_V1_FORMAT
from ..util import write_json
from .project_status import PROJECT_STATUS_FORMAT
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


CANDIDATE_STATUS_FORMAT = "spaghetti-extractor-candidate-status-v1"


def build_candidate_status(
    *,
    target_id: str,
    configuration_id: str,
    project_status: Path | str,
    configuration_status: Path | str,
    candidate_test_suites: Mapping[str, object],
    require_candidate_test_suite: bool = False,
    out: Path | str,
) -> dict[str, object]:
    """Combine checked authority and one exact component configuration."""

    if not target_id or not configuration_id:
        raise StatusArtifactError("target and configuration IDs must be nonempty")
    project = load_object(project_status, "project status")
    configuration = load_object(
        configuration_status, "component configuration status"
    )
    if project.get("format") != PROJECT_STATUS_FORMAT:
        raise StatusArtifactError("project status format is unsupported")
    if project.get("target_id") != target_id:
        raise StatusArtifactError("project status binds another target")
    if configuration.get("configuration_id") != configuration_id:
        raise StatusArtifactError("component configuration status binds another ID")
    if configuration.get("format") != COMPONENT_CONFIGURATION_STATUS_V1_FORMAT:
        raise StatusArtifactError(
            "component configuration status format is unsupported"
        )

    project_state = checked_status(
        project.get("status"), "project status", allow_complete=False
    )
    configuration_state = checked_status(
        configuration.get("status"),
        "component configuration status",
        allow_complete=False,
    )
    authority_ready = checked_bool(
        project.get("authority_ready"), "project authority-ready field"
    )
    if authority_ready != (project_state == "ready"):
        raise StatusArtifactError("project authority readiness is inconsistent")
    configuration_ready = configuration_state == "ready"
    build_ready = authority_ready and configuration_ready
    authority_frontiers = copied_rows(
        project.get("primary_frontiers", []), "project primary frontiers"
    )
    component_frontiers = _configuration_frontiers(
        configuration, configuration_id
    )
    blocked_count = checked_count(
        configuration.get("counts"), "blocked", "component configuration"
    )
    if configuration_ready and blocked_count != 0:
        raise StatusArtifactError("ready component configuration has blockers")
    suites = _suite_rows(candidate_test_suites, configuration_id)
    test_frontiers = []
    if require_candidate_test_suite and not suites:
        test_frontiers.append(
            {
                "status": "incomplete",
                "family": "candidate-testing",
                "code": "candidate_test_suite_missing",
                "record_id": f"candidate-tests:{configuration_id}:missing",
                "dependent_occurrences": 0,
                "source_location": None,
                "next_action": (
                    "declare a candidate-only test suite for the default "
                    f"configuration {configuration_id}"
                ),
                "details": {"configuration_id": configuration_id},
            }
        )
    frontiers = authority_frontiers + component_frontiers + test_frontiers
    frontiers.sort(key=frontier_key)

    violated = project_state == "violated" or configuration_state == "violated"
    acceptance_preconditions_ready = build_ready and not test_frontiers
    status = (
        "violated"
        if violated
        else "ready"
        if acceptance_preconditions_ready
        else "incomplete"
    )
    candidate_state = (
        "ready_to_build"
        if build_ready
        else "blocked_by_violation"
        if violated
        else "blocked_by_authority"
        if not authority_ready
        else "blocked_by_component_configuration"
    )
    dependent_occurrences = checked_count(
        project.get("counts"), "dependent_occurrences", "project"
    ) + sum(
        int(row.get("dependent_occurrences", 0)) for row in component_frontiers
    )
    core: dict[str, object] = {
        "format": CANDIDATE_STATUS_FORMAT,
        "target_id": target_id,
        "configuration_id": configuration_id,
        "status": status,
        "authorizing": False,
        "authority_ready": authority_ready,
        "configuration_ready": configuration_ready,
        "build_ready": build_ready,
        "authority": copy.deepcopy(project.get("authority", {})),
        "component_configuration": {
            "status": configuration_state,
            "counts": copy.deepcopy(configuration.get("counts", {})),
        },
        "candidate": {
            "status": candidate_state,
            "acceptance_preconditions_ready": acceptance_preconditions_ready,
            "declared_test_suites": suites,
            "candidate_authority_checked": False,
            "runtime_executed": False,
        },
        "counts": {
            "primary_frontiers": len(frontiers),
            "dependent_occurrences": dependent_occurrences,
            "candidate_test_suites": len(suites),
        },
        "primary_frontiers": frontiers,
        "next_action": (
            copy.deepcopy(frontiers[0].get("next_action"))
            if frontiers
            else f"build candidate configuration {configuration_id}"
        ),
        "policy": copy.deepcopy(project.get("policy", {})),
    }
    result = {**core, "candidate_status_sha256": canonical_sha256(core)}
    write_json(Path(out), result)
    return result


def _configuration_frontiers(
    value: Mapping[str, object], configuration_id: str
) -> list[dict[str, object]]:
    rows = copied_rows(value.get("blockers", []), "component blockers")
    result = []
    for index, row in enumerate(rows):
        status = checked_status(
            row.get("status", "incomplete"),
            "component blocker status",
            allow_complete=False,
        )
        if status == "ready":
            raise StatusArtifactError("component blockers cannot be ready")
        code = str(row.get("code", "component_configuration_incomplete"))
        result.append(
            {
                "status": status,
                "family": "component-configuration",
                "code": code,
                "record_id": f"component:{configuration_id}:{index}:{code}",
                "dependent_occurrences": 0,
                "source_location": row.get("source_location"),
                "next_action": row.get("detail")
                or row.get("message")
                or row.get("remediation")
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
            raise StatusArtifactError("candidate test suite metadata must be objects")
        if raw.get("configurationId") != configuration_id:
            raise StatusArtifactError(
                "candidate test suite metadata binds another configuration"
            )
        case_ids = raw.get("caseIds", [])
        if not isinstance(case_ids, list) or any(
            not isinstance(case_id, str) for case_id in case_ids
        ):
            raise StatusArtifactError("candidate test case IDs must be strings")
        rows.append({"id": identity, "case_ids": copy.deepcopy(case_ids)})
    return rows


__all__ = [
    "CANDIDATE_STATUS_FORMAT",
    "StatusArtifactError",
    "build_candidate_status",
]
