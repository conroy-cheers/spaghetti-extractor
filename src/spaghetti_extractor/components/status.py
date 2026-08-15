"""Operator-facing status derived from checked component artifacts."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Mapping

from ..util import write_json
from .adapter import load_component_adapter_plan
from .formats import (
    COMPONENT_ACTIVATION_PLAN_V3_FORMAT,
    COMPONENT_ADAPTER_PLAN_V1_FORMAT,
    COMPONENT_CONFIGURATION_STATUS_V1_FORMAT,
    COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
    COMPONENT_EVIDENCE_V3_FORMAT,
    COMPONENT_QUALIFICATION_V3_FORMAT,
    COMPONENT_WORK_STATUS_V1_FORMAT,
)
from .intent import ComponentIntentError
from .source import load_component_source_package


@dataclass(frozen=True)
class ArtifactStatus:
    state: str
    identity: str | None = None

    def to_payload(self) -> dict[str, object]:
        return {"state": self.state, "identity": self.identity}


def build_lift_unit_status(
    *,
    contract: Path | str,
    source: Path | str | None,
    adapter_plan: Path | str | None,
    evidence: Path | str | None,
    qualification: Path | str | None,
    out: Path | str,
) -> dict[str, object]:
    """Summarize one independently buildable leaf or group fail-closed."""

    contract_payload = _load_checked(
        contract,
        description="component contract",
        format_name=COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
        hash_field="contract_sha256",
    )
    lift_unit = _object(contract_payload.get("lift_unit"), "contract lift unit")
    lift_unit_id = _text(lift_unit.get("id"), "contract lift-unit id")

    source_payload = None
    if source is not None:
        source_payload = load_component_source_package(source)
        if source_payload.get("lift_unit_id") != lift_unit_id:
            raise ComponentIntentError("component source package identity is stale")
    adapter_payload = (
        None if adapter_plan is None else load_component_adapter_plan(adapter_plan)
    )
    if (
        adapter_payload is not None
        and adapter_payload.get("lift_unit_id") != lift_unit_id
    ):
        raise ComponentIntentError("component adapter-plan identity is stale")

    evidence_payload = (
        None
        if evidence is None
        else _load_checked(
            evidence,
            description="component evidence",
            format_name=COMPONENT_EVIDENCE_V3_FORMAT,
            hash_field="evidence_sha256",
        )
    )
    qualification_payload = (
        None
        if qualification is None
        else _load_checked(
            qualification,
            description="component qualification",
            format_name=COMPONENT_QUALIFICATION_V3_FORMAT,
            hash_field="qualification_sha256",
        )
    )

    issues: list[dict[str, object]] = []
    issues.extend(_issues(contract_payload, "blockers"))
    if source_payload is None:
        issues.append(_issue("incomplete", "portable_source_not_declared", lift_unit_id))
    if adapter_payload is None:
        issues.append(_issue("incomplete", "component_adapter_plan_not_available", lift_unit_id))
    else:
        issues.extend(_issues(adapter_payload, "issues"))
    if evidence_payload is None:
        issues.append(_issue("incomplete", "behavioral_evidence_not_available", lift_unit_id))
    else:
        issues.extend(_issues(evidence_payload, "issues"))
    if qualification_payload is None:
        issues.append(_issue("incomplete", "component_qualification_not_available", lift_unit_id))
    else:
        if qualification_payload.get("lift_unit_id") != lift_unit_id:
            issues.append(_issue("violated", "component_qualification_identity_mismatch", lift_unit_id))
        issues.extend(_issues(qualification_payload, "issues"))

    observed = {
        str(contract_payload.get("status")),
        str(adapter_payload.get("status")) if adapter_payload else "missing",
        str(evidence_payload.get("status")) if evidence_payload else "missing",
        str(qualification_payload.get("status")) if qualification_payload else "missing",
        *(str(row.get("status")) for row in issues),
    }
    status = (
        "violated"
        if "violated" in observed
        else "qualified"
        if qualification_payload is not None
        and qualification_payload.get("status") == "qualified"
        and contract_payload.get("status") == "checked"
        and source_payload is not None
        and adapter_payload is not None
        and adapter_payload.get("status") == "checked"
        and evidence_payload is not None
        and evidence_payload.get("status") == "satisfied"
        else "incomplete"
    )
    ranked = sorted(
        _deduplicate_issues(issues),
        key=lambda row: (
            0 if row.get("status") == "violated" else 1,
            str(row.get("code", "")),
        ),
    )
    core = {
        "format": COMPONENT_WORK_STATUS_V1_FORMAT,
        "status": status,
        "kind": lift_unit.get("kind"),
        "lift_unit_id": lift_unit_id,
        "label": lift_unit.get("label"),
        "unit_ids": copy.deepcopy(lift_unit.get("unit_ids", [])),
        "artifacts": {
            "contract": ArtifactStatus(
                str(contract_payload.get("status")),
                str(contract_payload.get("contract_sha256")),
            ).to_payload(),
            "source": ArtifactStatus(
                "present" if source_payload is not None else "missing",
                None if source_payload is None else str(source_payload.get("implementation_sha256")),
            ).to_payload(),
            "adapter_plan": ArtifactStatus(
                "missing" if adapter_payload is None else str(adapter_payload.get("status")),
                None if adapter_payload is None else str(adapter_payload.get("adapter_plan_sha256")),
            ).to_payload(),
            "evidence": ArtifactStatus(
                "missing" if evidence_payload is None else str(evidence_payload.get("status")),
                None if evidence_payload is None else str(evidence_payload.get("evidence_sha256")),
            ).to_payload(),
            "qualification": ArtifactStatus(
                "missing" if qualification_payload is None else str(qualification_payload.get("status")),
                None if qualification_payload is None else str(qualification_payload.get("qualification_sha256")),
            ).to_payload(),
        },
        "blockers": ranked,
        "next_action": _next_action(ranked, status),
        "policy": {
            "authorizes_runtime": False,
            "executes_original_binary": False,
            "work_package_may_be_built_independently": True,
        },
    }
    result = {**core, "status_sha256": _canonical_sha256(core)}
    write_json(Path(out), result)
    return result


def build_configuration_status(
    *, activation_plan: Path | str, out: Path | str
) -> dict[str, object]:
    """Summarize one complete ownership configuration without building it."""

    plan = _load_checked(
        activation_plan,
        description="component activation plan",
        format_name=COMPONENT_ACTIVATION_PLAN_V3_FORMAT,
        hash_field="activation_plan_sha256",
    )
    issues = sorted(
        _deduplicate_issues(_issues(plan, "issues")),
        key=lambda row: (
            0 if row.get("status") == "violated" else 1,
            str(row.get("code", "")),
            str(row.get("lift_unit_id", "")),
        ),
    )
    status = (
        "violated"
        if plan.get("status") == "violated"
        else "ready"
        if plan.get("status") == "checked" and _object(plan.get("counts"), "activation counts").get("blocked") == 0
        else "incomplete"
    )
    core = {
        "format": COMPONENT_CONFIGURATION_STATUS_V1_FORMAT,
        "status": status,
        "configuration_id": plan.get("configuration_id"),
        "counts": copy.deepcopy(plan.get("counts")),
        "selections": copy.deepcopy(plan.get("selections")),
        "blockers": issues,
        "next_action": _next_action(issues, status),
        "bindings": {
            "activation_plan_sha256": plan.get("activation_plan_sha256"),
        },
        "policy": {
            "runtime_requires_ready_configuration": True,
            "executes_original_binary": False,
        },
    }
    result = {**core, "status_sha256": _canonical_sha256(core)}
    write_json(Path(out), result)
    return result


def _load_checked(
    value: Path | str,
    *,
    description: str,
    format_name: str,
    hash_field: str,
) -> dict[str, object]:
    path = Path(value)
    if path.is_dir():
        filenames = {
            COMPONENT_CONTRACT_PACKAGE_V2_FORMAT: "contract.json",
            COMPONENT_ADAPTER_PLAN_V1_FORMAT: "adapter-plan.json",
            COMPONENT_EVIDENCE_V3_FORMAT: "evidence.json",
            COMPONENT_QUALIFICATION_V3_FORMAT: "qualification.json",
            COMPONENT_ACTIVATION_PLAN_V3_FORMAT: "activation-plan.json",
        }
        path = path / filenames[format_name]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentIntentError(f"cannot read {description}: {exc}") from exc
    row = dict(_object(payload, description))
    if row.get("format") != format_name:
        raise ComponentIntentError(f"unsupported {description} format")
    core = copy.deepcopy(row)
    expected = core.pop(hash_field, None)
    if expected != _canonical_sha256(core):
        raise ComponentIntentError(f"{description} self-hash is stale")
    return row


def _issues(payload: Mapping[str, object], field: str) -> list[dict[str, object]]:
    value = payload.get(field, [])
    if not isinstance(value, list):
        raise ComponentIntentError(f"component {field} must be an array")
    result: list[dict[str, object]] = []
    for item in value:
        row = dict(_object(item, f"component {field} entry"))
        row.setdefault("status", "incomplete")
        result.append(row)
    return result


def _deduplicate_issues(issues: list[dict[str, object]]) -> list[dict[str, object]]:
    unique: dict[str, dict[str, object]] = {}
    for issue in issues:
        unique[json.dumps(issue, sort_keys=True, separators=(",", ":"), default=str)] = issue
    return list(unique.values())


def _issue(status: str, code: str, lift_unit_id: str) -> dict[str, object]:
    return {"status": status, "code": code, "lift_unit_id": lift_unit_id}


def _next_action(blockers: list[dict[str, object]], status: str) -> dict[str, object] | None:
    if status in {"qualified", "ready"}:
        return None
    if not blockers:
        return {"code": "inspect_incomplete_artifact", "action": "inspect the checked status inputs"}
    blocker = blockers[0]
    return {
        "code": blocker.get("code"),
        "action": blocker.get("remediation", _remediation(str(blocker.get("code", "")))),
    }


def _remediation(code: str) -> str:
    if "adapter" in code:
        return "build and check the component adapter plan"
    if "review" in code or "contract" in code:
        return "review and check the generated component boundary contract"
    if "source" in code:
        return "add or repair the portable component source package"
    if "evidence" in code:
        return "produce complete candidate-only behavioral evidence"
    if "qualification" in code:
        return "qualify the exact source and evidence against the checked contract"
    return "inspect the named component artifact and its dependencies"


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentIntentError(f"{description} must be an object")
    return value


def _text(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentIntentError(f"{description} must be a nonempty string")
    return value


def _canonical_sha256(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()


__all__ = [
    "ArtifactStatus",
    "build_configuration_status",
    "build_lift_unit_status",
]
