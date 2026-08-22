"""Universal component contracts over the existing checked V2 artifacts.

The V3 contract is deliberately a small authority index.  It does not copy or
reinterpret machine semantics: it binds one portable interface to the exact
machine-derived semantic contract and gives every operation an independently
addressable identity.  Implementations can therefore change without changing
consumer contracts, while a semantic boundary change invalidates dependants.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .formats import COMPONENT_CONTRACT_V3_FORMAT
from .interface_ir import (
    COMPONENT_INTERFACE_IR_V2,
    COMPONENT_INTERFACE_IR_V3,
    COMPONENT_INTERFACE_IR_V4,
    PortableComponentInterfaceV2,
)
from .machine_binding import ComponentMachineBindingV1
from .semantic_contract import ComponentSemanticContractV1


class UniversalComponentContractError(ValueError):
    """A universal component contract is malformed or has stale bindings."""


@dataclass(frozen=True, order=True)
class ComponentOperationContractV3:
    operation_id: str
    kind: str
    interface_operation_sha256: str
    semantic_operation_sha256: str
    parameter_type_ids: tuple[str, ...]
    result_type_ids: tuple[str, ...]
    effect_ids: tuple[str, ...]
    service_ids: tuple[str, ...]
    callback_operation_ids: tuple[str, ...]

    @classmethod
    def parse(cls, value: object) -> "ComponentOperationContractV3":
        row = _object(value, "component operation contract")
        _exact(
            row,
            {
                "id",
                "kind",
                "interface_operation_sha256",
                "semantic_operation_sha256",
                "parameter_type_ids",
                "result_type_ids",
                "effect_ids",
                "service_ids",
                "callback_operation_ids",
            },
            "component operation contract",
        )
        kind = _text(row["kind"], "component operation kind")
        if kind not in {"operation", "callback"}:
            raise UniversalComponentContractError(
                f"unsupported component operation kind {kind!r}"
            )
        return cls(
            operation_id=_identifier(row["id"], "component operation id"),
            kind=kind,
            interface_operation_sha256=_digest(
                row["interface_operation_sha256"], "interface operation digest"
            ),
            semantic_operation_sha256=_digest(
                row["semantic_operation_sha256"], "semantic operation digest"
            ),
            parameter_type_ids=_identifier_sequence(
                row["parameter_type_ids"], "operation parameter types"
            ),
            result_type_ids=_identifier_sequence(
                row["result_type_ids"], "operation result types"
            ),
            effect_ids=_identifiers(row["effect_ids"], "operation effects"),
            service_ids=_identifiers(row["service_ids"], "operation services"),
            callback_operation_ids=_identifiers(
                row["callback_operation_ids"], "operation callbacks"
            ),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.operation_id,
            "kind": self.kind,
            "interface_operation_sha256": self.interface_operation_sha256,
            "semantic_operation_sha256": self.semantic_operation_sha256,
            "parameter_type_ids": list(self.parameter_type_ids),
            "result_type_ids": list(self.result_type_ids),
            "effect_ids": list(self.effect_ids),
            "service_ids": list(self.service_ids),
            "callback_operation_ids": list(self.callback_operation_ids),
        }


@dataclass(frozen=True, order=True)
class ComponentServiceContractV3:
    service_id: str
    parameter_type_ids: tuple[str, ...]
    result_type_id: str | None
    effect_ids: tuple[str, ...]

    @classmethod
    def parse(cls, value: object) -> "ComponentServiceContractV3":
        row = _object(value, "component service contract")
        _exact(
            row,
            {"id", "parameter_type_ids", "result_type_id", "effect_ids"},
            "component service contract",
        )
        result_type = row["result_type_id"]
        return cls(
            service_id=_identifier(row["id"], "component service id"),
            parameter_type_ids=_identifier_sequence(
                row["parameter_type_ids"], "component service parameter types"
            ),
            result_type_id=(
                None
                if result_type is None
                else _identifier(result_type, "component service result type")
            ),
            effect_ids=_identifiers(row["effect_ids"], "component service effects"),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.service_id,
            "parameter_type_ids": list(self.parameter_type_ids),
            "result_type_id": self.result_type_id,
            "effect_ids": list(self.effect_ids),
        }


@dataclass(frozen=True)
class ComponentContractV3:
    component_id: str
    status: str
    interface_format: str
    interface_id: str
    interface_sha256: str
    type_hashes: tuple[tuple[str, str], ...]
    operations: tuple[ComponentOperationContractV3, ...]
    state_ids: tuple[str, ...]
    effect_hashes: tuple[tuple[str, str], ...]
    services: tuple[ComponentServiceContractV3, ...]
    protocol_states: tuple[str, ...]
    initial_protocol_state: str
    issues: tuple[Mapping[str, object], ...]
    contract_sha256: str

    @classmethod
    def parse(cls, value: object) -> "ComponentContractV3":
        row = _object(value, "component contract V3")
        _exact(
            row,
            {
                "format",
                "status",
                "component_id",
                "interface",
                "semantics",
                "operations",
                "types",
                "state_ids",
                "effects",
                "services",
                "protocol",
                "issues",
                "policy",
                "contract_sha256",
            },
            "component contract V3",
        )
        if row["format"] != COMPONENT_CONTRACT_V3_FORMAT:
            raise UniversalComponentContractError(
                "unsupported universal component contract format"
            )
        status = _text(row["status"], "component contract status")
        if status not in {"checked", "incomplete", "violated"}:
            raise UniversalComponentContractError("invalid component contract status")
        interface = _object(row["interface"], "component contract interface")
        _exact(interface, {"format", "id", "sha256"}, "component contract interface")
        interface_format = _text(
            interface["format"], "component contract interface format"
        )
        if interface_format not in {
            COMPONENT_INTERFACE_IR_V2,
            COMPONENT_INTERFACE_IR_V3,
            COMPONENT_INTERFACE_IR_V4,
        }:
            raise UniversalComponentContractError(
                "unsupported component contract interface format"
            )
        semantics = _object(row["semantics"], "component contract semantics")
        _exact(semantics, {"format"}, "component contract semantics")
        protocol = _object(row["protocol"], "component contract protocol")
        _exact(protocol, {"states", "initial_state"}, "component contract protocol")
        policy = _object(row["policy"], "component contract policy")
        _exact(
            policy,
            {
                "machine_free_interface",
                "machine_semantics_checked_once",
                "implementation_independent",
                "undeclared_boundary_behavior_fails_closed",
                "original_binary_executed",
                "operator_expected_outputs_accepted",
            },
            "component contract policy",
        )
        if policy != {
            "machine_free_interface": True,
            "machine_semantics_checked_once": True,
            "implementation_independent": True,
            "undeclared_boundary_behavior_fails_closed": True,
            "original_binary_executed": False,
            "operator_expected_outputs_accepted": False,
        }:
            raise UniversalComponentContractError(
                "component contract policy weakens the universal boundary"
            )
        operations = tuple(
            ComponentOperationContractV3.parse(item)
            for item in _array(row["operations"], "component contract operations")
        )
        operation_ids = tuple(item.operation_id for item in operations)
        if not operations or operation_ids != tuple(sorted(set(operation_ids))):
            raise UniversalComponentContractError(
                "component contract operations must be nonempty, unique, and ordered"
            )
        type_rows = tuple(
            (
                _identifier(_object(item, "component type")["id"], "component type id"),
                _digest(_object(item, "component type")["sha256"], "component type digest"),
            )
            for item in _array(row["types"], "component types")
        )
        if not type_rows or tuple(item[0] for item in type_rows) != tuple(
            sorted({item[0] for item in type_rows})
        ):
            raise UniversalComponentContractError(
                "component types must be nonempty, unique, and ordered"
            )
        states = _identifiers(row["state_ids"], "component state ids")
        effects = tuple(
            (
                _identifier(_object(item, "component effect")["id"], "component effect id"),
                _digest(_object(item, "component effect")["sha256"], "component effect digest"),
            )
            for item in _array(row["effects"], "component effects")
        )
        if tuple(item[0] for item in effects) != tuple(
            sorted({item[0] for item in effects})
        ):
            raise UniversalComponentContractError(
                "component effects must be unique and ordered"
            )
        services = tuple(
            ComponentServiceContractV3.parse(item)
            for item in _array(row["services"], "component services")
        )
        service_ids = tuple(item.service_id for item in services)
        if service_ids != tuple(sorted(set(service_ids))):
            raise UniversalComponentContractError(
                "component services must be unique and canonically ordered"
            )
        protocol_states = _identifiers(
            protocol["states"], "component protocol states", nonempty=True
        )
        initial = _identifier(
            protocol["initial_state"], "component initial protocol state"
        )
        if initial not in protocol_states:
            raise UniversalComponentContractError(
                "component initial protocol state is not declared"
            )
        issues = tuple(
            _canonical_object(item, "component contract issue")
            for item in _array(row["issues"], "component contract issues")
        )
        if status == "checked" and issues:
            raise UniversalComponentContractError(
                "checked component contract may not contain issues"
            )
        if status != "checked" and not issues:
            raise UniversalComponentContractError(
                "non-checked component contract requires an issue"
            )
        core = dict(row)
        observed = _digest(core.pop("contract_sha256"), "component contract digest")
        if observed != canonical_sha256_v3(core):
            raise UniversalComponentContractError(
                "component contract digest is stale"
            )
        return cls(
            component_id=_identifier(row["component_id"], "component id"),
            status=status,
            interface_format=interface_format,
            interface_id=_identifier(interface["id"], "component interface id"),
            interface_sha256=_digest(interface["sha256"], "component interface digest"),
            type_hashes=type_rows,
            operations=operations,
            state_ids=states,
            effect_hashes=effects,
            services=services,
            protocol_states=protocol_states,
            initial_protocol_state=initial,
            issues=issues,
            contract_sha256=observed,
        )

    def to_payload(self) -> dict[str, object]:
        core = {
            "format": COMPONENT_CONTRACT_V3_FORMAT,
            "status": self.status,
            "component_id": self.component_id,
            "interface": {
                "format": self.interface_format,
                "id": self.interface_id,
                "sha256": self.interface_sha256,
            },
            "semantics": {
                "format": "spaghetti-extractor-normalized-operation-semantics-v1",
            },
            "operations": [item.to_payload() for item in self.operations],
            "types": [
                {"id": identity, "sha256": digest}
                for identity, digest in self.type_hashes
            ],
            "state_ids": list(self.state_ids),
            "effects": [
                {"id": identity, "sha256": digest}
                for identity, digest in self.effect_hashes
            ],
            "services": [item.to_payload() for item in self.services],
            "protocol": {
                "states": list(self.protocol_states),
                "initial_state": self.initial_protocol_state,
            },
            "issues": [dict(item) for item in self.issues],
            "policy": _policy(),
        }
        return {**core, "contract_sha256": self.contract_sha256}


def build_component_contract_v3(
    *,
    interface: Path | str | Mapping[str, object],
    machine_binding: Path | str | Mapping[str, object],
    machine_binding_receipt: Path | str | Mapping[str, object],
    semantic_contract: Path | str | Mapping[str, object],
    out: Path | str | None = None,
) -> ComponentContractV3:
    """Bind existing checked interface and semantic artifacts once."""

    interface_payload = _load(interface, "portable component interface")
    portable = PortableComponentInterfaceV2.parse(interface_payload)
    machine_binding_payload = _load(machine_binding, "component machine binding")
    binding = ComponentMachineBindingV1.parse(machine_binding_payload)
    receipt = _load(machine_binding_receipt, "component machine binding receipt")
    semantic_payload = _load(semantic_contract, "component semantic contract")
    semantic = ComponentSemanticContractV1.parse(semantic_payload)
    issues: list[dict[str, object]] = []

    if semantic_payload.get("component_id") != binding.identity:
        issues.append(
            _issue("violated", "semantic_component_identity_mismatch")
        )
    bindings = _object(
        semantic_payload.get("bindings"), "component semantic bindings"
    )
    if bindings.get("interface_sha256") != portable.sha256:
        issues.append(_issue("violated", "semantic_interface_binding_stale"))
    if binding.interface_id != portable.identity or binding.interface_sha256 != portable.sha256:
        issues.append(_issue("violated", "machine_interface_binding_stale"))
    if bindings.get("machine_binding_sha256") != binding.binding_sha256:
        issues.append(_issue("violated", "semantic_machine_binding_stale"))
    if bindings.get("pe_sha256") != binding.pe_sha256:
        issues.append(_issue("violated", "semantic_pe_binding_stale"))
    if bindings.get("machine_ir_sha256") != binding.machine_ir_sha256:
        issues.append(_issue("violated", "semantic_machine_ir_binding_stale"))
    _check_machine_binding_receipt(receipt, portable, binding, issues)
    if semantic.status != "satisfied":
        for item in _array(
            semantic_payload.get("issues", []), "component semantic issues"
        ):
            issue = dict(_object(item, "component semantic issue"))
            issue.setdefault(
                "status", "violated" if semantic.status == "violated" else "incomplete"
            )
            issues.append(issue)

    semantic_operations = {
        _identifier(
            _object(item, "semantic operation").get("operation_id"),
            "semantic operation id",
        ): _object(item, "semantic operation")
        for item in _array(
            semantic_payload.get("operations"), "component semantic operations"
        )
    }
    interface_operations = portable.operation_index()
    if set(semantic_operations) != set(interface_operations):
        issues.append(
            _issue(
                "violated",
                "semantic_operation_inventory_mismatch",
                expected=sorted(interface_operations),
                observed=sorted(semantic_operations),
            )
        )

    operations: list[dict[str, object]] = []
    for operation_id, operation in sorted(interface_operations.items()):
        semantic_operation = semantic_operations.get(operation_id)
        if semantic_operation is None:
            continue
        callback_ids = tuple(
            sorted(
                _identifier(item, "semantic callback operation id")
                for item in _array(
                    semantic_operation.get("callback_operation_ids", []),
                    "semantic callback operation ids",
                )
            )
        )
        operations.append(
            {
                "id": operation_id,
                "kind": operation.kind,
                "interface_operation_sha256": canonical_sha256_v3(
                    _interface_operation_payload(operation)
                ),
                "semantic_operation_sha256": canonical_sha256_v3(
                    _normalized_semantic_operation(semantic_operation)
                ),
                "parameter_type_ids": [
                    item.type_id for item in operation.parameters
                ],
                "result_type_ids": [item.type_id for item in operation.results],
                "effect_ids": list(operation.effect_ids),
                "service_ids": list(operation.allowed_service_ids),
                "callback_operation_ids": list(callback_ids),
            }
        )

    status = (
        "violated"
        if any(item.get("status") == "violated" for item in issues)
        else "incomplete"
        if issues
        else "checked"
    )
    interface_payload_exact = portable.to_payload()
    type_payloads = {
        _identifier(_object(item, "portable type")["id"], "portable type id"):
        _object(item, "portable type")
        for item in _array(interface_payload_exact["types"], "portable types")
    }
    effect_payloads = {
        _identifier(_object(item, "portable effect")["id"], "portable effect id"):
        _object(item, "portable effect")
        for item in _array(interface_payload_exact["effects"], "portable effects")
    }
    core: dict[str, object] = {
        "format": COMPONENT_CONTRACT_V3_FORMAT,
        "status": status,
        "component_id": binding.identity,
        "interface": {
            "format": portable.format_version,
            "id": portable.identity,
            "sha256": portable.sha256,
        },
        "semantics": {
            "format": "spaghetti-extractor-normalized-operation-semantics-v1",
        },
        "operations": operations,
        "types": [
            {"id": identity, "sha256": canonical_sha256_v3(payload)}
            for identity, payload in sorted(type_payloads.items())
        ],
        "state_ids": sorted(item.identity for item in portable.state),
        "effects": [
            {"id": identity, "sha256": canonical_sha256_v3(payload)}
            for identity, payload in sorted(effect_payloads.items())
        ],
        "services": [
            {
                "id": item.identity,
                "parameter_type_ids": list(item.parameter_type_ids),
                "result_type_id": item.result_type_id,
                "effect_ids": list(item.effect_ids),
            }
            for item in sorted(portable.services, key=lambda item: item.identity)
        ],
        "protocol": {
            "states": sorted(portable.protocol_states),
            "initial_state": portable.initial_protocol_state,
        },
        "issues": sorted(
            issues,
            key=lambda item: (
                str(item.get("status", "")),
                str(item.get("code", "")),
            ),
        ),
        "policy": _policy(),
    }
    result = ComponentContractV3.parse(
        {**core, "contract_sha256": canonical_sha256_v3(core)}
    )
    if out is not None:
        _write(Path(out), result.to_payload())
    return result


def read_component_contract_v3(
    value: Path | str | Mapping[str, object],
) -> ComponentContractV3:
    return ComponentContractV3.parse(_load(value, "component contract V3"))


def _interface_operation_payload(operation: object) -> dict[str, object]:
    return {
        "id": getattr(operation, "identity"),
        "kind": getattr(operation, "kind"),
        "parameters": [
            {"id": item.identity, "type_id": item.type_id}
            for item in getattr(operation, "parameters")
        ],
        "results": [
            {"id": item.identity, "type_id": item.type_id}
            for item in getattr(operation, "results")
        ],
        "effect_ids": list(getattr(operation, "effect_ids")),
        "allowed_service_ids": list(getattr(operation, "allowed_service_ids")),
        "pre_states": list(getattr(operation, "pre_states")),
        "post_states": list(getattr(operation, "post_states")),
    }


def _normalized_semantic_operation(
    operation: Mapping[str, object],
) -> dict[str, object]:
    """Drop exact binding coordinates while retaining checked behavior.

    Machine projections and unit identities live in the binding authority.  The
    contract keeps only the ordered semantic bodies and logical callback set,
    so unrelated image or unit-identity changes do not invalidate consumers.
    """

    units = []
    for item in _array(operation.get("units", []), "semantic operation units"):
        unit = _object(item, "semantic operation unit")
        units.append(
            {
                "semantics": json.loads(
                    json.dumps(_object(unit.get("semantics"), "unit semantics"))
                )
            }
        )
    return {
        "units": units,
        "callback_operation_ids": sorted(
            _text(item, "semantic callback operation id")
            for item in _array(
                operation.get("callback_operation_ids", []),
                "semantic callback operation ids",
            )
        ),
    }


def normalized_semantic_operation_sha256(
    operation: Mapping[str, object],
) -> str:
    """Return the contract identity of one checked semantic operation."""

    return canonical_sha256_v3(_normalized_semantic_operation(operation))


def _check_machine_binding_receipt(
    receipt: Mapping[str, object],
    interface: PortableComponentInterfaceV2,
    binding: ComponentMachineBindingV1,
    issues: list[dict[str, object]],
) -> None:
    expected_fields = {
        "format",
        "status",
        "activation_authorized",
        "bindings",
        "counts",
        "policy",
        "issues",
        "receipt_sha256",
    }
    if set(receipt) != expected_fields:
        issues.append(_issue("violated", "machine_binding_receipt_noncanonical"))
        return
    core = dict(receipt)
    observed = core.pop("receipt_sha256", None)
    if not isinstance(observed, str) or observed != canonical_sha256_v3(core):
        issues.append(_issue("violated", "machine_binding_receipt_digest_stale"))
        return
    if (
        receipt.get("format")
        != "spaghetti-extractor-component-machine-binding-receipt-v1"
    ):
        issues.append(_issue("violated", "machine_binding_receipt_format_invalid"))
    if receipt.get("status") != "checked" or receipt.get("activation_authorized") is not True:
        issues.append(_issue("incomplete", "machine_binding_receipt_not_checked"))
    receipt_bindings = _object(
        receipt.get("bindings"), "component machine binding receipt bindings"
    )
    expected = {
        "component_machine_binding_sha256": binding.binding_sha256,
        "interface_sha256": interface.sha256,
        "machine_ir_sha256": binding.machine_ir_sha256,
        "pe_sha256": binding.pe_sha256,
    }
    stale = sorted(
        key for key, value in expected.items() if receipt_bindings.get(key) != value
    )
    if stale:
        issues.append(
            _issue(
                "violated", "machine_binding_receipt_binding_stale", fields=stale
            )
        )


def _policy() -> dict[str, bool]:
    return {
        "machine_free_interface": True,
        "machine_semantics_checked_once": True,
        "implementation_independent": True,
        "undeclared_boundary_behavior_fails_closed": True,
        "original_binary_executed": False,
        "operator_expected_outputs_accepted": False,
    }


def _issue(status: str, code: str, **fields: object) -> dict[str, object]:
    return {"status": status, "code": code, **fields}


def _load(
    value: Path | str | Mapping[str, object], description: str
) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return json.loads(json.dumps(value))
    path = Path(value)
    if path.is_dir():
        filenames = {
            "component contract V3": "component-contract-v3.json",
            "portable component interface": "portable-interface.json",
            "component machine binding": "machine-binding.json",
            "component machine binding receipt": "machine-binding-receipt.json",
            "component semantic contract": "semantic-contract.json",
        }
        filename = filenames.get(description)
        if filename is None:
            raise UniversalComponentContractError(
                f"cannot select {description} in directory {path}"
            )
        path = path / filename
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UniversalComponentContractError(
            f"cannot read {description}: {exc}"
        ) from exc
    return _object(payload, description)


def _write(path: Path, payload: Mapping[str, object]) -> None:
    if path.suffix != ".json":
        path.mkdir(parents=True, exist_ok=True)
        path = path / "component-contract-v3.json"
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise UniversalComponentContractError(f"{description} must be an object")
    return value


def _canonical_object(value: object, description: str) -> Mapping[str, object]:
    return json.loads(json.dumps(_object(value, description)))


def _array(value: object, description: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise UniversalComponentContractError(f"{description} must be an array")
    return value


def _exact(
    value: Mapping[str, object], fields: set[str], description: str
) -> None:
    if set(value) != fields:
        raise UniversalComponentContractError(
            f"{description} must contain exactly {sorted(fields)!r}"
        )


def _text(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise UniversalComponentContractError(
            f"{description} must be a nonempty string"
        )
    return value


def _identifier(value: object, description: str) -> str:
    result = _text(value, description)
    if not result[0].isalnum() or any(
        not (character.isalnum() or character in "._-") for character in result
    ):
        raise UniversalComponentContractError(f"{description} is invalid")
    return result


def _digest(value: object, description: str) -> str:
    result = _text(value, description)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise UniversalComponentContractError(f"{description} is not a SHA-256 digest")
    return result


def _identifiers(
    value: object, description: str, *, nonempty: bool = False
) -> tuple[str, ...]:
    result = tuple(_identifier(item, description) for item in _array(value, description))
    if result != tuple(sorted(set(result))) or (nonempty and not result):
        raise UniversalComponentContractError(
            f"{description} must be unique, ordered, and"
            + (" nonempty" if nonempty else " canonical")
        )
    return result


def _strings(
    value: object, description: str, *, nonempty: bool = False
) -> tuple[str, ...]:
    result = tuple(_text(item, description) for item in _array(value, description))
    if result != tuple(sorted(set(result))) or (nonempty and not result):
        raise UniversalComponentContractError(
            f"{description} must be unique, ordered, and"
            + (" nonempty" if nonempty else " canonical")
        )
    return result


def _identifier_sequence(
    value: object, description: str
) -> tuple[str, ...]:
    return tuple(_identifier(item, description) for item in _array(value, description))


__all__ = [
    "ComponentContractV3",
    "ComponentOperationContractV3",
    "ComponentServiceContractV3",
    "UniversalComponentContractError",
    "build_component_contract_v3",
    "normalized_semantic_operation_sha256",
    "read_component_contract_v3",
]
