"""Exact machine-bound interaction sites for portable component operations."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .formats import COMPONENT_INTERACTION_INVENTORY_V1_FORMAT
from .interaction_contract import InteractionContractCatalogV1
from .interface_ir import PortableComponentInterfaceV2
from .machine_binding import ComponentMachineBindingV1


class ComponentInteractionInventoryError(ValueError):
    """An interaction inventory is malformed, stale, or ambiguous."""


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentInteractionInventoryError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise ComponentInteractionInventoryError(f"{context} must be an array")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentInteractionInventoryError(f"{context} must be a nonempty string")
    return value


@dataclass(frozen=True)
class InteractionPortBindingV1:
    identity: str
    direction: str
    type_id: str
    source: Mapping[str, object]

    @classmethod
    def parse(cls, value: object, context: str) -> "InteractionPortBindingV1":
        row = _object(value, context)
        if set(row) != {"id", "direction", "type_id", "source"}:
            raise ComponentInteractionInventoryError(f"{context} fields differ")
        direction = _text(row["direction"], f"{context} direction")
        if direction not in {"input", "output"}:
            raise ComponentInteractionInventoryError(f"{context} direction is invalid")
        source = _object(row["source"], f"{context} source")
        if source.get("kind") not in {"projection", "expression"} or "value" not in source:
            raise ComponentInteractionInventoryError(f"{context} source is invalid")
        return cls(_text(row["id"], f"{context} id"), direction, _text(row["type_id"], f"{context} type"), copy.deepcopy(dict(source)))

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "direction": self.direction,
            "type_id": self.type_id,
            "source": copy.deepcopy(dict(self.source)),
        }


@dataclass(frozen=True)
class ComponentInteractionSiteV1:
    identity: str
    primitive_id: str
    subject: Mapping[str, object]
    machine_event: Mapping[str, object]
    ports: tuple[InteractionPortBindingV1, ...]
    effect_ids: tuple[str, ...]
    contract_candidates: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "ComponentInteractionSiteV1":
        row = _object(value, context)
        if set(row) != {"id", "primitive_id", "subject", "machine_event", "ports", "effect_ids", "contract_candidates"}:
            raise ComponentInteractionInventoryError(f"{context} fields differ")
        ports = tuple(InteractionPortBindingV1.parse(item, f"{context} port {index}") for index, item in enumerate(_array(row["ports"], f"{context} ports")))
        keys = [(item.direction, item.identity) for item in ports]
        if not ports or keys != sorted(set(keys)):
            raise ComponentInteractionInventoryError(f"{context} ports are not canonical")
        effects = tuple(_text(item, f"{context} effect") for item in _array(row["effect_ids"], f"{context} effects"))
        candidates = tuple(_text(item, f"{context} candidate") for item in _array(row["contract_candidates"], f"{context} candidates"))
        if effects != tuple(sorted(set(effects))) or candidates != tuple(sorted(set(candidates))):
            raise ComponentInteractionInventoryError(f"{context} inventories are not canonical")
        return cls(
            _text(row["id"], f"{context} id"),
            _text(row["primitive_id"], f"{context} primitive"),
            copy.deepcopy(dict(_object(row["subject"], f"{context} subject"))),
            copy.deepcopy(dict(_object(row["machine_event"], f"{context} event"))),
            ports, effects, candidates,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "primitive_id": self.primitive_id,
            "subject": copy.deepcopy(dict(self.subject)),
            "machine_event": copy.deepcopy(dict(self.machine_event)),
            "ports": [item.to_payload() for item in self.ports],
            "effect_ids": list(self.effect_ids),
            "contract_candidates": list(self.contract_candidates),
        }


@dataclass(frozen=True)
class OperationInteractionInventoryV1:
    operation_id: str
    sites: tuple[ComponentInteractionSiteV1, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "OperationInteractionInventoryV1":
        row = _object(value, context)
        if set(row) != {"operation_id", "sites"}:
            raise ComponentInteractionInventoryError(f"{context} fields differ")
        sites = tuple(ComponentInteractionSiteV1.parse(item, f"{context} site {index}") for index, item in enumerate(_array(row["sites"], f"{context} sites")))
        ids = [item.identity for item in sites]
        if ids != sorted(set(ids)):
            raise ComponentInteractionInventoryError(f"{context} sites are not canonical")
        return cls(_text(row["operation_id"], f"{context} operation"), sites)

    def to_payload(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "sites": [item.to_payload() for item in self.sites],
        }


@dataclass(frozen=True)
class ComponentInteractionInventoryV1:
    component_id: str
    bindings: Mapping[str, str]
    operations: tuple[OperationInteractionInventoryV1, ...]
    inventory_sha256: str

    @classmethod
    def parse(cls, value: object) -> "ComponentInteractionInventoryV1":
        row = _object(value, "component interaction inventory")
        if set(row) != {"format", "component_id", "bindings", "operations", "inventory_sha256"} or row.get("format") != COMPONENT_INTERACTION_INVENTORY_V1_FORMAT:
            raise ComponentInteractionInventoryError("unsupported or malformed interaction inventory")
        bindings = _object(row["bindings"], "interaction inventory bindings")
        if any(not isinstance(key, str) or not isinstance(item, str) or len(item) != 64 for key, item in bindings.items()):
            raise ComponentInteractionInventoryError("interaction inventory bindings are invalid")
        operations = tuple(OperationInteractionInventoryV1.parse(item, f"interaction operation {index}") for index, item in enumerate(_array(row["operations"], "interaction operations")))
        ids = [item.operation_id for item in operations]
        if not operations or ids != sorted(set(ids)):
            raise ComponentInteractionInventoryError("interaction operations are not canonical")
        core = {key: copy.deepcopy(item) for key, item in row.items() if key != "inventory_sha256"}
        observed = _text(row["inventory_sha256"], "interaction inventory digest")
        if canonical_sha256_v3(core) != observed:
            raise ComponentInteractionInventoryError("interaction inventory digest is stale")
        return cls(_text(row["component_id"], "interaction component"), dict(sorted(bindings.items())), operations, observed)

    @classmethod
    def create(
        cls,
        *,
        component_id: str,
        bindings: Mapping[str, str],
        operations: Sequence[OperationInteractionInventoryV1],
    ) -> "ComponentInteractionInventoryV1":
        ordered = tuple(sorted(operations, key=lambda item: item.operation_id))
        operation_ids = [item.operation_id for item in ordered]
        if not ordered or operation_ids != sorted(set(operation_ids)):
            raise ComponentInteractionInventoryError(
                "interaction inventory operations must be nonempty and unique"
            )
        core = {
            "format": COMPONENT_INTERACTION_INVENTORY_V1_FORMAT,
            "component_id": component_id,
            "bindings": dict(sorted(bindings.items())),
            "operations": [item.to_payload() for item in ordered],
        }
        return cls(
            component_id,
            dict(sorted(bindings.items())),
            ordered,
            canonical_sha256_v3(core),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "format": COMPONENT_INTERACTION_INVENTORY_V1_FORMAT,
            "component_id": self.component_id,
            "bindings": dict(self.bindings),
            "operations": [item.to_payload() for item in self.operations],
            "inventory_sha256": self.inventory_sha256,
        }


def build_component_interaction_inventory(
    *,
    interface: PortableComponentInterfaceV2,
    machine_binding: ComponentMachineBindingV1,
    semantic_contract: Mapping[str, object],
    contract_catalog: InteractionContractCatalogV1,
) -> ComponentInteractionInventoryV1:
    """Normalize service and specialized effect boundaries into exact sites."""

    if machine_binding.interface_id != interface.identity:
        raise ComponentInteractionInventoryError("interaction interface identity changed")
    if machine_binding.interface_sha256 != interface.sha256:
        raise ComponentInteractionInventoryError("interaction interface binding is stale")
    if semantic_contract.get("component_id") != machine_binding.identity:
        raise ComponentInteractionInventoryError("semantic contract component changed")
    semantic_sha256 = _text(
        semantic_contract.get("contract_sha256"), "semantic contract digest"
    )
    semantic_operations = {
        _text(row.get("operation_id"), "semantic operation id"): row
        for row in (
            _object(item, "semantic operation")
            for item in _array(semantic_contract.get("operations"), "semantic operations")
        )
    }
    semantic_services = [
        _object(item, "semantic service")
        for item in _array(semantic_contract.get("services"), "semantic services")
    ]
    services = {item.identity: item for item in interface.services}
    operations = interface.operation_index()
    type_index = interface.type_index()
    inventories: list[OperationInteractionInventoryV1] = []
    for bound in machine_binding.operations:
        logical = operations[bound.operation_id]
        semantic_operation = semantic_operations.get(bound.operation_id)
        if semantic_operation is None:
            raise ComponentInteractionInventoryError(
                f"semantic operation {bound.operation_id!r} is missing"
            )
        units = {
            _text(unit.get("id"), "semantic unit id"): unit
            for unit in (
                _object(item, "semantic operation unit")
                for item in _array(semantic_operation.get("units"), "semantic operation units")
            )
        }
        sites: list[ComponentInteractionSiteV1] = []
        for service_row in semantic_services:
            service_id = _text(service_row.get("service_id"), "semantic service id")
            if service_id not in logical.allowed_service_ids:
                continue
            service = services.get(service_id)
            if service is None:
                raise ComponentInteractionInventoryError(
                    f"interaction service {service_id!r} is unknown"
                )
            provider = _object(service_row.get("provider"), "semantic service provider")
            provider_kind = provider.get("kind")
            if provider_kind not in {
                "machine_events",
                "component_operation",
                "checked_external_site_events",
            }:
                raise ComponentInteractionInventoryError(
                    f"service {service_id!r} has no exact interaction events"
                )
            for raw_event in _array(provider.get("events"), "semantic service events"):
                event = _object(raw_event, "semantic service event")
                unit_id = _text(event.get("unit_id"), "interaction unit id")
                if unit_id not in units:
                    continue
                event_index = event.get("event_index")
                if not isinstance(event_index, int) or isinstance(event_index, bool) or event_index < 0:
                    raise ComponentInteractionInventoryError("interaction event index is invalid")
                machine_event = _unit_external_event(units[unit_id], event_index)
                subject = _interaction_subject(
                    provider_kind=str(provider_kind),
                    provider=provider,
                    machine_event=machine_event,
                    service_id=service_id,
                )
                arguments = _array(event.get("arguments"), "interaction arguments")
                if len(arguments) != len(service.parameter_type_ids):
                    raise ComponentInteractionInventoryError(
                        f"service {service_id!r} interaction argument inventory differs"
                    )
                ports = [
                    InteractionPortBindingV1(
                        f"argument.{index}",
                        "input",
                        type_id,
                        {
                            "kind": (
                                "expression"
                                if provider_kind == "checked_external_site_events"
                                else "projection"
                            ),
                            "value": copy.deepcopy(argument),
                        },
                    )
                    for index, (type_id, argument) in enumerate(
                        zip(service.parameter_type_ids, arguments, strict=True)
                    )
                ]
                if service.result_type_id is not None:
                    result = event.get("result")
                    if not isinstance(result, Mapping):
                        raise ComponentInteractionInventoryError(
                            f"service {service_id!r} interaction result is unresolved"
                        )
                    ports.append(
                        InteractionPortBindingV1(
                            "result",
                            "output",
                            service.result_type_id,
                            {"kind": "projection", "value": copy.deepcopy(dict(result))},
                        )
                    )
                candidates = tuple(
                    item.identity
                    for item in contract_catalog.contracts
                    if _subjects_match(item.subject, subject)
                )
                site_id = f"service:{service_id}:{unit_id}:{event_index}"
                sites.append(
                    ComponentInteractionSiteV1(
                        site_id,
                        "service.invoke",
                        subject,
                        {
                            "family": "service",
                            "service_id": service_id,
                            "unit_id": unit_id,
                            "event_index": event_index,
                            "event_sha256": _text(
                                event.get("event_sha256"), "interaction event digest"
                            ),
                            "event": copy.deepcopy(dict(machine_event)),
                            "call_boundary": copy.deepcopy(provider.get("call_boundary")),
                        },
                        tuple(sorted(ports, key=lambda item: (item.direction, item.identity))),
                        tuple(service.effect_ids),
                        tuple(sorted(candidates)),
                    )
                )
        logical_effects = {item.identity: item for item in interface.effects}
        parameter_types = {item.identity: item.type_id for item in logical.parameters}
        parameter_projections = {item.identity: item.projection for item in bound.parameters}
        for effect_id in logical.effect_ids:
            effect = logical_effects[effect_id]
            if effect.operation not in {"compare_exchange", "exchange"}:
                continue
            target_id = effect.target_id
            if target_id is None or target_id not in parameter_projections:
                raise ComponentInteractionInventoryError("atomic interaction target is missing")
            projection = parameter_projections[target_id]
            if projection.kind != "atomic_object":
                raise ComponentInteractionInventoryError("atomic interaction target is not atomic")
            payload = projection.payload
            unit_id = _text(payload.get("unit_id"), "atomic interaction unit")
            action_id = _text(payload.get("action_id"), "atomic interaction action")
            sites.append(
                ComponentInteractionSiteV1(
                    f"atomic:{effect_id}:{action_id}",
                    "atomic.invoke",
                    {
                        "kind": "atomic_action",
                        "operation": effect.operation,
                        "profile_id": payload.get("profile_id"),
                    },
                    {
                        "family": "atomic",
                        "effect_id": effect_id,
                        "unit_id": unit_id,
                        "action_id": action_id,
                        "profile_id": payload.get("profile_id"),
                        "effect_facts": [
                            item.to_payload()
                            for item in bound.effects
                            if item.effect_id == effect_id
                        ],
                    },
                    (
                        InteractionPortBindingV1(
                            "object",
                            "input",
                            parameter_types[target_id],
                            {"kind": "projection", "value": projection.to_payload()},
                        ),
                    ),
                    (effect_id,),
                    (),
                )
            )
        sites.sort(key=lambda item: item.identity)
        site_ids = [item.identity for item in sites]
        if len(site_ids) != len(set(site_ids)):
            raise ComponentInteractionInventoryError(
                f"operation {bound.operation_id!r} has duplicate interaction sites"
            )
        inventories.append(OperationInteractionInventoryV1(bound.operation_id, tuple(sites)))
    return ComponentInteractionInventoryV1.create(
        component_id=machine_binding.identity,
        bindings={
            "interface_sha256": interface.sha256,
            "machine_binding_sha256": machine_binding.binding_sha256,
            "semantic_contract_sha256": semantic_sha256,
            "machine_ir_sha256": machine_binding.machine_ir_sha256,
            "interaction_contract_catalog_sha256": contract_catalog.catalog_sha256,
        },
        operations=inventories,
    )


def _unit_external_event(unit: Mapping[str, object], event_index: int) -> Mapping[str, object]:
    semantics = _object(unit.get("semantics"), "semantic unit semantics")
    events = _array(semantics.get("external_events"), "semantic external events")
    if event_index >= len(events):
        raise ComponentInteractionInventoryError("interaction event selector is stale")
    return _object(events[event_index], "semantic external event")


def _interaction_subject(
    *,
    provider_kind: str,
    provider: Mapping[str, object],
    machine_event: Mapping[str, object],
    service_id: str,
) -> dict[str, object]:
    if provider_kind == "checked_external_site_events":
        target_value = machine_event.get("target")
        target = (
            _object(target_value, "external interaction target")
            if isinstance(target_value, Mapping)
            else machine_event
        )
        if isinstance(target_value, Mapping) and target.get("kind") != "import":
            raise ComponentInteractionInventoryError("external interaction is not an import")
        dll, symbol = target.get("dll"), target.get("symbol")
        if not isinstance(dll, str) or not dll or not isinstance(symbol, str) or not symbol:
            raise ComponentInteractionInventoryError("external interaction import identity is missing")
        return {
            "kind": "external_import",
            "dll": dll.lower(),
            "symbol": symbol,
        }
    if provider_kind == "component_operation":
        return {
            "kind": "component_operation",
            "component_id": provider.get("component_id"),
            "operation_id": provider.get("operation_id"),
        }
    return {"kind": "machine_service", "service_id": service_id}


def _subjects_match(left: Mapping[str, object], right: Mapping[str, object]) -> bool:
    return canonical_sha256_v3(left) == canonical_sha256_v3(right)


__all__ = [
    "ComponentInteractionInventoryError",
    "ComponentInteractionInventoryV1",
    "ComponentInteractionSiteV1",
    "InteractionPortBindingV1",
    "OperationInteractionInventoryV1",
    "build_component_interaction_inventory",
]
