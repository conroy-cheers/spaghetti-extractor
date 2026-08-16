"""Checked component membership used by activation receipts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import write_json
from .intent import ComponentIntentError
from .machine_binding import ComponentMachineBindingV1


COMPONENT_OWNERSHIP_RECEIPT_V1 = (
    "spaghetti-extractor-component-ownership-receipt-v1"
)


def build_component_ownership_receipt(
    *,
    contract: Path | str | None = None,
    machine_binding: Path | str | None = None,
    resolution_slice: Path | str,
    out: Path | str,
) -> dict[str, object]:
    if (contract is None) == (machine_binding is None):
        raise ComponentIntentError(
            "ownership requires exactly one legacy contract or V2 machine binding"
        )
    resolution = _load(
        resolution_slice, "component resolution slice", "component-resolution.json"
    )
    _check_hash(resolution, "resolution_sha256", "component resolution")
    issues: list[dict[str, object]] = []
    if machine_binding is not None:
        binding_payload = _load(
            machine_binding, "component machine binding", "machine-binding.json"
        )
        binding = ComponentMachineBindingV1.parse(binding_payload)
        identity = binding.identity
        unit_ids = tuple(binding.unit_ids)
        authority_bindings = {
            "component_machine_binding_sha256": binding.binding_sha256,
            "resolution_sha256": resolution.get("resolution_sha256"),
        }
    else:
        assert contract is not None
        contract_payload = _load(contract, "component contract", "contract.json")
        _check_hash(contract_payload, "contract_sha256", "component contract")
        lift_unit = _object(contract_payload.get("lift_unit"), "contract lift unit")
        identity = _text(lift_unit.get("id"), "contract lift-unit id")
        unit_ids = _strings(lift_unit.get("unit_ids"), "contract machine units")
        authority_bindings = {
            "contract_sha256": contract_payload.get("contract_sha256"),
            "resolution_sha256": resolution.get("resolution_sha256"),
        }
        if contract_payload.get("status") != "checked":
            issues.append(
                {"status": "incomplete", "code": "component_contract_not_checked"}
            )
    rows = [
        row
        for field in ("components", "groups")
        for row in _array(resolution.get(field), f"resolution {field}")
        if isinstance(row, Mapping) and row.get("id") == identity
    ]
    if len(rows) != 1:
        issues.append(
            {"status": "violated", "code": "component_resolution_identity_mismatch"}
        )
    elif _strings(rows[0].get("unit_ids"), "resolved machine units") != unit_ids:
        issues.append(
            {"status": "violated", "code": "component_membership_binding_stale"}
        )
    status = (
        "violated"
        if any(row["status"] == "violated" for row in issues)
        else "incomplete"
        if issues
        else "checked"
    )
    core: dict[str, object] = {
        "format": COMPONENT_OWNERSHIP_RECEIPT_V1,
        "status": status,
        "activation_authorized": status == "checked",
        "lift_unit_id": identity,
        "unit_ids": list(unit_ids),
        "bindings": authority_bindings,
        "issues": issues,
    }
    result = {**core, "receipt_sha256": canonical_sha256_v3(core)}
    write_json(Path(out), result)
    return result


def _load(value: Path | str, context: str, filename: str) -> dict[str, object]:
    path = Path(value)
    if path.is_dir():
        path /= filename
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentIntentError(f"cannot read {context}: {exc}") from exc
    return dict(_object(payload, context))


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentIntentError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ComponentIntentError(f"{context} must be an array")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentIntentError(f"{context} must be a nonempty string")
    return value


def _strings(value: object, context: str) -> tuple[str, ...]:
    result = tuple(_text(row, context) for row in _array(value, context))
    if not result or result != tuple(sorted(set(result))):
        raise ComponentIntentError(f"{context} must be sorted, unique, and nonempty")
    return result


def _check_hash(
    payload: Mapping[str, object], field: str, context: str
) -> None:
    expected = payload.get(field)
    core = dict(payload)
    core.pop(field, None)
    if expected != canonical_sha256_v3(core):
        raise ComponentIntentError(f"{context} self-hash is stale")


__all__ = [
    "COMPONENT_OWNERSHIP_RECEIPT_V1",
    "build_component_ownership_receipt",
]
