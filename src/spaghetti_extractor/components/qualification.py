"""Fail-closed behavioral-evidence gate for independently lifted components."""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from pathlib import Path
from typing import Mapping

from .formats import (
    COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
    COMPONENT_EVIDENCE_V3_FORMAT,
    COMPONENT_QUALIFICATION_V3_FORMAT,
)
from ..util import sha256_file, write_json
from .intent import ComponentIntentError
from .source import load_component_source_package


def qualify_lift_unit(
    *,
    contract: Path | str | Mapping[str, object],
    implementation: Path | str,
    evidence: Path | str | Mapping[str, object],
    machine_ir: Path | str,
    verification: Mapping[str, object],
    out: Path | str,
) -> dict[str, object]:
    """Authorize executable activation from generated, exactly bound evidence."""

    contract_payload = _load(contract, "component contract")
    implementation_payload = load_component_source_package(implementation)
    evidence_payload = _load(evidence, "component evidence")
    _self_hash(
        contract_payload,
        format_name=COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
        field="contract_sha256",
        description="component contract",
    )
    _self_hash(
        evidence_payload,
        format_name=COMPONENT_EVIDENCE_V3_FORMAT,
        field="evidence_sha256",
        description="component evidence",
    )
    lift_unit = _object(contract_payload.get("lift_unit"), "contract lift unit")
    lift_unit_id = _string(lift_unit.get("id"), "contract lift-unit id")
    issues: list[dict[str, object]] = []
    bindings = _object(evidence_payload.get("bindings"), "component evidence bindings")
    machine_path = Path(machine_ir)
    if machine_path.is_dir():
        machine_path = machine_path / "machine-ir.jsonl"
    expected = {
        "contract_sha256": contract_payload.get("contract_sha256"),
        "implementation_sha256": implementation_payload.get("implementation_sha256"),
        "machine_ir_sha256": sha256_file(machine_path),
        "domain_sha256": _canonical_sha256(verification),
    }
    if contract_payload.get("status") != "checked":
        _issue(issues, "incomplete", "component_contract_not_checked")
    if evidence_payload.get("lift_unit_id") != lift_unit_id:
        _issue(issues, "violated", "component_evidence_identity_mismatch")
    if implementation_payload.get("lift_unit_id") != lift_unit_id:
        _issue(issues, "violated", "component_source_identity_mismatch")
    if evidence_payload.get("evidence_profile") != lift_unit.get("evidence_profile"):
        _issue(issues, "violated", "component_evidence_profile_mismatch")
    if evidence_payload.get("executes_original_binary") is not False:
        _issue(issues, "violated", "component_evidence_executed_original")
    for field, value in expected.items():
        if bindings.get(field) != value:
            _issue(
                issues,
                "violated",
                "component_evidence_binding_stale",
                field=field,
                expected=value,
                observed=bindings.get(field),
            )
    method = _object(evidence_payload.get("method"), "component evidence method")
    if (
        verification.get("producer") != "exhaustive-finite-domain-v1"
        or method.get("kind") != "exhaustive_finite_domain_v1"
        or method.get("complete_for_declared_domain") is not True
        or method.get("candidate_only") is not True
    ):
        _issue(issues, "incomplete", "component_evidence_method_not_complete")
    coverage = _object(evidence_payload.get("coverage"), "component evidence coverage")
    if coverage.get("counterexamples") not in {0, None}:
        _issue(
            issues,
            "violated",
            "component_evidence_has_counterexample",
            counterexample=coverage.get("first_counterexample"),
        )
    if evidence_payload.get("status") == "violated":
        _issue(issues, "violated", "component_evidence_reported_violation")
    elif evidence_payload.get("status") != "satisfied":
        _issue(issues, "incomplete", "component_evidence_not_satisfied")
    status = (
        "violated"
        if any(row["status"] == "violated" for row in issues)
        else "incomplete"
        if issues
        else "qualified"
    )
    core = {
        "format": COMPONENT_QUALIFICATION_V3_FORMAT,
        "status": status,
        "lift_unit_id": lift_unit_id,
        "evidence_profile": lift_unit.get("evidence_profile"),
        "bindings": {
            **expected,
            "evidence_sha256": evidence_payload["evidence_sha256"],
            "source_entry": copy.deepcopy(implementation_payload.get("entry")),
            "tool_id": bindings.get("tool_id"),
            "tool_version": bindings.get("tool_version"),
        },
        "assurance": {
            "kind": "exhaustive_over_declared_finite_domain",
            "universal_equivalence_claimed": False,
            "declared_domain_equivalence": status == "qualified",
            "original_binary_executed": False,
        },
        "activation": {
            "authorized": status == "qualified",
            "requires_exact_configuration_ownership": True,
            "fallback_on_unimplemented": False,
        },
        "issues": sorted(issues, key=lambda row: (str(row["status"]), str(row["code"]))),
    }
    result = {**core, "qualification_sha256": _canonical_sha256(core)}
    write_json(Path(out), result)
    return result


def _issue(
    issues: list[dict[str, object]],
    status: str,
    code: str,
    **details: object,
) -> None:
    issues.append({"status": status, "code": code, **details})


def _self_hash(
    payload: Mapping[str, object],
    *,
    format_name: str,
    field: str,
    description: str,
) -> None:
    if payload.get("format") != format_name:
        raise ComponentIntentError(f"unsupported {description} format")
    expected = payload.get(field)
    core = copy.deepcopy(dict(payload))
    core.pop(field, None)
    if expected != _canonical_sha256(core):
        raise ComponentIntentError(f"{description} self-hash is stale")


def _load(
    value: Path | str | Mapping[str, object], description: str
) -> dict[str, object]:
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    try:
        payload = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentIntentError(f"cannot read {description}: {exc}") from exc
    return dict(_object(payload, description))


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentIntentError(f"{description} must be an object")
    return value


def _string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentIntentError(f"{description} must be a nonempty string")
    return value


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256(encoded).hexdigest()


__all__ = [
    "qualify_lift_unit",
]
