"""Exact target bindings for machine-independent component contracts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .formats import COMPONENT_MACHINE_BINDING_V3_FORMAT
from .machine_binding import ComponentMachineBindingV1
from .semantic_contract import ComponentSemanticContractV1
from .universal_contract import (
    ComponentContractV3,
    normalized_semantic_operation_sha256,
    read_component_contract_v3,
)


class UniversalComponentBindingError(ValueError):
    """An exact component-to-machine binding is malformed or stale."""


@dataclass(frozen=True)
class ComponentMachineBindingV3:
    component_id: str
    contract_sha256: str
    interface_sha256: str
    machine_binding_sha256: str
    machine_binding_receipt_sha256: str
    semantic_contract_sha256: str
    pe_sha256: str
    machine_ir_sha256: str
    machine_ir_manifest_sha256: str
    unit_ids: tuple[str, ...]
    operation_bindings: tuple[tuple[str, str, str], ...]
    status: str
    issues: tuple[Mapping[str, object], ...]
    binding_sha256: str

    @property
    def authorizing(self) -> bool:
        return self.status == "checked"

    @classmethod
    def parse(cls, value: object) -> "ComponentMachineBindingV3":
        row = _object(value, "universal component machine binding")
        _exact(
            row,
            {
                "format",
                "status",
                "component_id",
                "contract_sha256",
                "interface_sha256",
                "source_artifacts",
                "exact_machine",
                "operation_bindings",
                "issues",
                "policy",
                "binding_sha256",
            },
            "universal component machine binding",
        )
        if row["format"] != COMPONENT_MACHINE_BINDING_V3_FORMAT:
            raise UniversalComponentBindingError(
                "unsupported universal machine-binding format"
            )
        status = _choice(
            row["status"], {"checked", "incomplete", "violated"},
            "universal machine-binding status",
        )
        source = _object(row["source_artifacts"], "machine-binding sources")
        _exact(
            source,
            {
                "machine_binding_sha256",
                "machine_binding_receipt_sha256",
                "semantic_contract_sha256",
            },
            "machine-binding sources",
        )
        machine = _object(row["exact_machine"], "exact component machine")
        _exact(
            machine,
            {
                "pe_sha256",
                "machine_ir_sha256",
                "machine_ir_manifest_sha256",
                "unit_ids",
            },
            "exact component machine",
        )
        operation_bindings = tuple(
            (
                _identifier(_object(item, "operation binding")["id"], "operation binding id"),
                _digest(_object(item, "operation binding")["projection_sha256"], "operation projection digest"),
                _digest(_object(item, "operation binding")["semantic_sha256"], "operation semantic digest"),
            )
            for item in _array(row["operation_bindings"], "operation bindings")
        )
        if not operation_bindings or tuple(item[0] for item in operation_bindings) != tuple(
            sorted({item[0] for item in operation_bindings})
        ):
            raise UniversalComponentBindingError(
                "operation bindings must be nonempty, unique, and ordered"
            )
        issues = tuple(
            _canonical_object(item, "machine-binding issue")
            for item in _array(row["issues"], "machine-binding issues")
        )
        if status == "checked" and issues:
            raise UniversalComponentBindingError(
                "checked machine binding may not contain issues"
            )
        if status != "checked" and not issues:
            raise UniversalComponentBindingError(
                "non-checked machine binding requires an issue"
            )
        policy = _object(row["policy"], "universal machine-binding policy")
        if policy != _policy():
            raise UniversalComponentBindingError(
                "universal machine-binding policy weakens exact authority"
            )
        core = dict(row)
        observed = _digest(core.pop("binding_sha256"), "universal binding digest")
        if observed != canonical_sha256_v3(core):
            raise UniversalComponentBindingError(
                "universal machine-binding digest is stale"
            )
        return cls(
            component_id=_identifier(row["component_id"], "component id"),
            contract_sha256=_digest(row["contract_sha256"], "component contract digest"),
            interface_sha256=_digest(row["interface_sha256"], "component interface digest"),
            machine_binding_sha256=_digest(source["machine_binding_sha256"], "V1 machine-binding digest"),
            machine_binding_receipt_sha256=_digest(
                source["machine_binding_receipt_sha256"], "machine-binding receipt digest"
            ),
            semantic_contract_sha256=_digest(
                source["semantic_contract_sha256"], "semantic contract digest"
            ),
            pe_sha256=_digest(machine["pe_sha256"], "PE digest"),
            machine_ir_sha256=_digest(machine["machine_ir_sha256"], "machine-IR digest"),
            machine_ir_manifest_sha256=_digest(
                machine["machine_ir_manifest_sha256"], "machine-IR manifest digest"
            ),
            unit_ids=_strings(machine["unit_ids"], "component machine units", nonempty=True),
            operation_bindings=operation_bindings,
            status=status,
            issues=issues,
            binding_sha256=observed,
        )

    def to_payload(self) -> dict[str, object]:
        core = {
            "format": COMPONENT_MACHINE_BINDING_V3_FORMAT,
            "status": self.status,
            "component_id": self.component_id,
            "contract_sha256": self.contract_sha256,
            "interface_sha256": self.interface_sha256,
            "source_artifacts": {
                "machine_binding_sha256": self.machine_binding_sha256,
                "machine_binding_receipt_sha256": self.machine_binding_receipt_sha256,
                "semantic_contract_sha256": self.semantic_contract_sha256,
            },
            "exact_machine": {
                "pe_sha256": self.pe_sha256,
                "machine_ir_sha256": self.machine_ir_sha256,
                "machine_ir_manifest_sha256": self.machine_ir_manifest_sha256,
                "unit_ids": list(self.unit_ids),
            },
            "operation_bindings": [
                {
                    "id": operation_id,
                    "projection_sha256": projection_sha256,
                    "semantic_sha256": semantic_sha256,
                }
                for operation_id, projection_sha256, semantic_sha256
                in self.operation_bindings
            ],
            "issues": [dict(item) for item in self.issues],
            "policy": _policy(),
        }
        return {**core, "binding_sha256": self.binding_sha256}


def build_component_machine_binding_v3(
    *,
    contract: ComponentContractV3 | Path | str | Mapping[str, object],
    machine_binding: Path | str | Mapping[str, object],
    machine_binding_receipt: Path | str | Mapping[str, object],
    semantic_contract: Path | str | Mapping[str, object],
    out: Path | str | None = None,
) -> ComponentMachineBindingV3:
    checked_contract = (
        contract
        if isinstance(contract, ComponentContractV3)
        else read_component_contract_v3(contract)
    )
    v1 = ComponentMachineBindingV1.parse(
        _load(machine_binding, "component machine binding", "machine-binding.json")
    )
    receipt = _load(
        machine_binding_receipt,
        "component machine-binding receipt",
        "machine-binding-receipt.json",
    )
    semantics_payload = _load(
        semantic_contract,
        "component semantic contract",
        "semantic-contract.json",
    )
    semantics = ComponentSemanticContractV1.parse(semantics_payload)
    issues: list[dict[str, object]] = []

    if v1.identity != checked_contract.component_id:
        issues.append(_issue("violated", "machine_binding_component_mismatch"))
    if v1.interface_sha256 != checked_contract.interface_sha256:
        issues.append(_issue("violated", "machine_binding_interface_stale"))
    if semantics_payload.get("component_id") != checked_contract.component_id:
        issues.append(_issue("violated", "semantic_component_mismatch"))
    if semantics.status != "satisfied":
        issues.append(
            _issue(
                "violated" if semantics.status == "violated" else "incomplete",
                "semantic_contract_not_satisfied",
            )
        )
    receipt_sha256 = _checked_receipt_sha256(receipt, v1, issues)
    receipt_bindings = _object(receipt.get("bindings"), "machine-binding receipt bindings")
    semantic_bindings = _object(semantics_payload.get("bindings"), "semantic bindings")
    if semantic_bindings.get("machine_binding_sha256") != v1.binding_sha256:
        issues.append(_issue("violated", "semantic_machine_binding_stale"))

    semantics_by_id = {
        str(_object(item, "semantic operation").get("operation_id")):
        _object(item, "semantic operation")
        for item in _array(semantics_payload.get("operations"), "semantic operations")
    }
    v1_by_id = {item.operation_id: item for item in v1.operations}
    contract_by_id = {item.operation_id: item for item in checked_contract.operations}
    if set(semantics_by_id) != set(v1_by_id) or set(v1_by_id) != set(contract_by_id):
        issues.append(_issue("violated", "machine_operation_inventory_mismatch"))
    operation_bindings = []
    for operation_id in sorted(set(semantics_by_id) & set(v1_by_id) & set(contract_by_id)):
        semantic_sha256 = normalized_semantic_operation_sha256(
            semantics_by_id[operation_id]
        )
        if semantic_sha256 != contract_by_id[operation_id].semantic_operation_sha256:
            issues.append(
                _issue(
                    "violated", "operation_semantic_contract_stale",
                    operation_id=operation_id,
                )
            )
        operation_bindings.append(
            {
                "id": operation_id,
                "projection_sha256": canonical_sha256_v3(
                    v1_by_id[operation_id].to_payload()
                ),
                "semantic_sha256": semantic_sha256,
            }
        )

    status = (
        "violated"
        if any(item["status"] == "violated" for item in issues)
        else "incomplete"
        if issues
        else "checked"
    )
    core: dict[str, object] = {
        "format": COMPONENT_MACHINE_BINDING_V3_FORMAT,
        "status": status,
        "component_id": checked_contract.component_id,
        "contract_sha256": checked_contract.contract_sha256,
        "interface_sha256": checked_contract.interface_sha256,
        "source_artifacts": {
            "machine_binding_sha256": v1.binding_sha256,
            "machine_binding_receipt_sha256": receipt_sha256,
            "semantic_contract_sha256": semantics.contract_sha256,
        },
        "exact_machine": {
            "pe_sha256": v1.pe_sha256,
            "machine_ir_sha256": v1.machine_ir_sha256,
            "machine_ir_manifest_sha256": receipt_bindings.get(
                "machine_ir_manifest_sha256"
            ),
            "unit_ids": list(v1.unit_ids),
        },
        "operation_bindings": operation_bindings,
        "issues": sorted(
            issues,
            key=lambda item: (
                str(item.get("status", "")), str(item.get("code", "")),
                str(item.get("operation_id", "")),
            ),
        ),
        "policy": _policy(),
    }
    payload = {**core, "binding_sha256": canonical_sha256_v3(core)}
    result = ComponentMachineBindingV3.parse(payload)
    if out is not None:
        _write(Path(out), payload)
    return result


def read_component_machine_binding_v3(
    value: Path | str | Mapping[str, object],
) -> ComponentMachineBindingV3:
    return ComponentMachineBindingV3.parse(
        _load(value, "universal component machine binding", "machine-binding-v3.json")
    )


def _checked_receipt_sha256(
    receipt: Mapping[str, object],
    binding: ComponentMachineBindingV1,
    issues: list[dict[str, object]],
) -> str:
    core = dict(receipt)
    observed = core.pop("receipt_sha256", None)
    if not isinstance(observed, str) or observed != canonical_sha256_v3(core):
        issues.append(_issue("violated", "machine_binding_receipt_digest_stale"))
        return "0" * 64
    if (
        receipt.get("format")
        != "spaghetti-extractor-component-machine-binding-receipt-v1"
    ):
        issues.append(_issue("violated", "machine_binding_receipt_format_invalid"))
    if receipt.get("status") != "checked" or receipt.get("activation_authorized") is not True:
        issues.append(_issue("incomplete", "machine_binding_receipt_not_checked"))
    bindings = _object(receipt.get("bindings"), "machine-binding receipt bindings")
    expected = {
        "component_machine_binding_sha256": binding.binding_sha256,
        "interface_sha256": binding.interface_sha256,
        "machine_ir_sha256": binding.machine_ir_sha256,
        "pe_sha256": binding.pe_sha256,
    }
    if any(bindings.get(key) != value for key, value in expected.items()):
        issues.append(_issue("violated", "machine_binding_receipt_stale"))
    return observed


def _policy() -> dict[str, bool]:
    return {
        "contract_remains_machine_independent": True,
        "exact_machine_binding_checked": True,
        "unit_ownership_is_not_contract_identity": True,
        "unchecked_binding_may_not_authorize_implementation": True,
        "original_binary_executed": False,
    }


def _issue(status: str, code: str, **fields: object) -> dict[str, object]:
    return {"status": status, "code": code, **fields}


def _load(
    value: Path | str | Mapping[str, object], description: str, filename: str
) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return json.loads(json.dumps(value))
    path = Path(value)
    if path.is_dir():
        path = path / filename
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UniversalComponentBindingError(f"cannot read {description}: {exc}") from exc
    return _object(payload, description)


def _write(path: Path, payload: Mapping[str, object]) -> None:
    if path.suffix != ".json":
        path.mkdir(parents=True, exist_ok=True)
        path = path / "machine-binding-v3.json"
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise UniversalComponentBindingError(f"{description} must be an object")
    return value


def _canonical_object(value: object, description: str) -> Mapping[str, object]:
    return json.loads(json.dumps(_object(value, description)))


def _array(value: object, description: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise UniversalComponentBindingError(f"{description} must be an array")
    return value


def _exact(value: Mapping[str, object], fields: set[str], description: str) -> None:
    if set(value) != fields:
        raise UniversalComponentBindingError(
            f"{description} must contain exactly {sorted(fields)!r}"
        )


def _text(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise UniversalComponentBindingError(f"{description} must be a nonempty string")
    return value


def _identifier(value: object, description: str) -> str:
    result = _text(value, description)
    if not result[0].isalnum() or any(
        not (character.isalnum() or character in "._-:") for character in result
    ):
        raise UniversalComponentBindingError(f"{description} is invalid")
    return result


def _choice(value: object, choices: set[str], description: str) -> str:
    result = _text(value, description)
    if result not in choices:
        raise UniversalComponentBindingError(f"{description} is unsupported")
    return result


def _digest(value: object, description: str) -> str:
    result = _text(value, description)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise UniversalComponentBindingError(f"{description} is not a SHA-256 digest")
    return result


def _strings(
    value: object, description: str, *, nonempty: bool = False
) -> tuple[str, ...]:
    result = tuple(_text(item, description) for item in _array(value, description))
    if result != tuple(sorted(set(result))) or (nonempty and not result):
        raise UniversalComponentBindingError(
            f"{description} must be unique, ordered, and"
            + (" nonempty" if nonempty else " canonical")
        )
    return result


__all__ = [
    "ComponentMachineBindingV3",
    "UniversalComponentBindingError",
    "build_component_machine_binding_v3",
    "read_component_machine_binding_v3",
]
