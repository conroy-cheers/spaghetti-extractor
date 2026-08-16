"""Structural and component readiness for one candidate configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

from ..artifacts.formats import STRUCTURAL_EXECUTABLE_FORMAT
from ..components.formats import COMPONENT_CONFIGURATION_STATUS_V1_FORMAT
from ..util import write_json
from .status_common import (
    StatusArtifactError,
    canonical_sha256,
    checked_count,
    checked_status,
    copied_rows,
    frontier_key,
    load_object,
)


CANDIDATE_STATUS_FORMAT = "spaghetti-extractor-candidate-status-v2"


def build_candidate_status(
    *,
    target_id: str,
    configuration_id: str,
    structural_receipt: Path | str,
    configuration_status: Path | str,
    candidate_test_suites: Mapping[str, object],
    out: Path | str,
) -> dict[str, object]:
    """Combine the real execution gate and one exact component configuration."""

    if not target_id or not configuration_id:
        raise StatusArtifactError("target and configuration IDs must be nonempty")
    structural = load_object(structural_receipt, "structural execution receipt")
    configuration = load_object(
        configuration_status, "component configuration status"
    )
    _check_structural_receipt(structural)
    if configuration.get("configuration_id") != configuration_id:
        raise StatusArtifactError("component configuration status binds another ID")
    if configuration.get("format") != COMPONENT_CONFIGURATION_STATUS_V1_FORMAT:
        raise StatusArtifactError(
            "component configuration status format is unsupported"
        )

    structural_state = str(structural.get("status"))
    configuration_state = checked_status(
        configuration.get("status"),
        "component configuration status",
        allow_complete=False,
    )
    structural_ready = structural_state == "complete"
    configuration_ready = configuration_state == "ready"
    build_ready = structural_ready and configuration_ready
    structural_frontiers = _structural_frontiers(structural)
    component_frontiers = _configuration_frontiers(
        configuration, configuration_id
    )
    blocked_count = checked_count(
        configuration.get("counts"), "blocked", "component configuration"
    )
    if configuration_ready and blocked_count != 0:
        raise StatusArtifactError("ready component configuration has blockers")
    suites = _suite_rows(candidate_test_suites, configuration_id)
    frontiers = structural_frontiers + component_frontiers
    frontiers.sort(key=frontier_key)

    violated = configuration_state == "violated"
    status = (
        "violated"
        if violated
        else "ready"
        if build_ready
        else "incomplete"
    )
    candidate_state = (
        "ready_to_build"
        if build_ready
        else "blocked_by_violation"
        if violated
        else "blocked_by_static_closure"
        if not structural_ready
        else "blocked_by_component_configuration"
    )
    dependent_occurrences = sum(
        int(row.get("dependent_occurrences", 0)) for row in frontiers
    )
    core: dict[str, object] = {
        "format": CANDIDATE_STATUS_FORMAT,
        "target_id": target_id,
        "configuration_id": configuration_id,
        "status": status,
        "authorizing": False,
        "structural_ready": structural_ready,
        "configuration_ready": configuration_ready,
        "build_ready": build_ready,
        "structural": {
            "status": structural_state,
            "executable": structural.get("executable"),
            "families": structural.get("families"),
        },
        "component_configuration": {
            "status": configuration_state,
            "counts": dict(configuration.get("counts", {})),
        },
        "candidate": {
            "status": candidate_state,
            "structural_execution_ready": build_ready,
            "declared_test_suites": suites,
            "runtime_executed": False,
        },
        "counts": {
            "primary_frontiers": len(frontiers),
            "dependent_occurrences": dependent_occurrences,
            "candidate_test_suites": len(suites),
        },
        "primary_frontiers": frontiers,
        "next_action": (
            frontiers[0].get("next_action")
            if frontiers
            else f"build candidate configuration {configuration_id}"
        ),
        "policy": {
            "diagnostic_only": True,
            "candidate_gate_bypassed": False,
            "candidate_tests_authorize": False,
            "original_binary_executed": False,
        },
    }
    result = {**core, "candidate_status_sha256": canonical_sha256(core)}
    write_json(Path(out), result)
    return result


def _check_structural_receipt(value: Mapping[str, object]) -> None:
    if value.get("format") != STRUCTURAL_EXECUTABLE_FORMAT:
        raise StatusArtifactError("structural execution receipt format is unsupported")
    status = value.get("status")
    executable = value.get("executable")
    if status not in {"complete", "incomplete"} or executable is not (
        status == "complete"
    ):
        raise StatusArtifactError("structural execution receipt state is inconsistent")
    if value.get("release_accepted") is not False:
        raise StatusArtifactError("structural receipt cannot authorize release")
    expected = value.get("receipt_sha256")
    if not isinstance(expected, str) or len(expected) != 64:
        raise StatusArtifactError("structural execution receipt digest is invalid")
    core = dict(value)
    core.pop("receipt_sha256")
    if canonical_sha256(core) != expected:
        raise StatusArtifactError("structural execution receipt digest is stale")
    families = value.get("families")
    if not isinstance(families, list) or not families:
        raise StatusArtifactError("structural execution receipt has no families")
    identities: list[str] = []
    for row in families:
        if not isinstance(row, Mapping):
            raise StatusArtifactError("structural execution family is not an object")
        identity = row.get("id")
        family_status = row.get("status")
        count = row.get("record_count")
        blocker = row.get("blocker")
        digest = row.get("input_sha256")
        if not isinstance(identity, str) or not identity:
            raise StatusArtifactError("structural execution family ID is invalid")
        if family_status not in {"complete", "incomplete"}:
            raise StatusArtifactError("structural execution family status is invalid")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise StatusArtifactError("structural execution family count is invalid")
        if not isinstance(digest, str) or len(digest) != 64:
            raise StatusArtifactError("structural execution family digest is invalid")
        if (family_status == "complete") is not (blocker is None):
            raise StatusArtifactError("structural execution family blocker is inconsistent")
        identities.append(identity)
    if identities != sorted(identities) or len(identities) != len(set(identities)):
        raise StatusArtifactError("structural execution families are not canonical")
    if (status == "complete") is not all(
        row.get("status") == "complete" for row in families
    ):
        raise StatusArtifactError("structural execution family states contradict status")


def _structural_frontiers(
    value: Mapping[str, object],
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for row in value.get("families", []):
        if not isinstance(row, Mapping) or row.get("status") == "complete":
            continue
        identity = str(row.get("id"))
        result.append(
            {
                "status": "incomplete",
                "family": "structural-execution",
                "code": f"{identity}_incomplete",
                "record_id": f"structural:{identity}",
                # The policy receipt records the family inventory size, not the
                # number of incomplete records. Do not inflate progress counts
                # by treating every checked record as a dependent blocker.
                "dependent_occurrences": 0,
                "source_location": None,
                "next_action": row.get("blocker")
                or f"complete structural execution family {identity}",
                "details": dict(row),
            }
        )
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
                "details": dict(row),
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
        rows.append({"id": identity, "case_ids": list(case_ids)})
    return rows


__all__ = [
    "CANDIDATE_STATUS_FORMAT",
    "StatusArtifactError",
    "build_candidate_status",
]
