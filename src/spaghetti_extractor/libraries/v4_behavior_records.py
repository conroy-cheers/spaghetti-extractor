"""Canonical behavior declarations for reusable library behavior packs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ..artifacts.artifact_set import CanonicalValueV3
from ..artifacts.formats import LIBRARY_BEHAVIOR_CONTRACT_V2_FORMAT
from ..components.interface_ir import PortableComponentInterfaceV2
from .v4_record_support import (
    StrictCodec,
    array,
    canonical_sha256,
    fail,
    sha256_text,
    stable_id,
    strict_object,
    text,
    text_tuple,
    validate_text_tuple,
)


_EFFECT_KINDS = frozenset(
    {"memory", "resource", "callback", "observable", "control"}
)
_EXTERNALLY_VISIBLE_EFFECT_KINDS = frozenset(
    {"resource", "callback", "observable", "control"}
)


@dataclass(frozen=True)
class LibraryBehaviorValueV2:
    value_id: str
    type_id: str

    def __post_init__(self) -> None:
        text(self.value_id, "library behavior value.id")
        text(self.type_id, "library behavior value.type_id")

    def to_payload(self) -> dict[str, str]:
        return {"id": self.value_id, "type_id": self.type_id}

    @classmethod
    def from_payload(
        cls, value: object, location: str
    ) -> "LibraryBehaviorValueV2":
        row = strict_object(value, {"id", "type_id"}, location)
        return cls(
            text(row["id"], f"{location}.id"),
            text(row["type_id"], f"{location}.type_id"),
        )


@dataclass(frozen=True)
class LibraryBehaviorStateFieldV2:
    field_id: str
    type_id: str
    initial_value: CanonicalValueV3

    def __post_init__(self) -> None:
        text(self.field_id, "library behavior state field.id")
        text(self.type_id, "library behavior state field.type_id")

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.field_id,
            "type_id": self.type_id,
            "initial": self.initial_value.to_value(),
        }

    @classmethod
    def from_payload(
        cls, value: object, location: str
    ) -> "LibraryBehaviorStateFieldV2":
        row = strict_object(value, {"id", "type_id", "initial"}, location)
        return cls(
            text(row["id"], f"{location}.id"),
            text(row["type_id"], f"{location}.type_id"),
            CanonicalValueV3.of(row["initial"]),
        )


@dataclass(frozen=True, order=True)
class LibraryBehaviorEffectV2:
    effect_id: str
    kind: str
    target_id: str | None
    operation: str

    def __post_init__(self) -> None:
        text(self.effect_id, "library behavior effect.id")
        if self.kind not in _EFFECT_KINDS:
            fail(
                "behavior_effect_kind_invalid",
                f"unsupported effect kind {self.kind!r}",
                "library behavior effect.kind",
            )
        if self.target_id is not None:
            text(self.target_id, "library behavior effect.target_id")
        text(self.operation, "library behavior effect.operation")

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.effect_id,
            "kind": self.kind,
            "target_id": self.target_id,
            "operation": self.operation,
        }

    @classmethod
    def from_payload(
        cls, value: object, location: str
    ) -> "LibraryBehaviorEffectV2":
        row = strict_object(
            value, {"id", "kind", "target_id", "operation"}, location
        )
        return cls(
            text(row["id"], f"{location}.id"),
            text(row["kind"], f"{location}.kind"),
            (
                None
                if row["target_id"] is None
                else text(row["target_id"], f"{location}.target_id")
            ),
            text(row["operation"], f"{location}.operation"),
        )


@dataclass(frozen=True)
class LibraryBehaviorServiceV2:
    service_id: str
    parameter_type_ids: tuple[str, ...]
    result_type_id: str | None
    effect_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        text(self.service_id, "library behavior service.id")
        for index, type_id in enumerate(self.parameter_type_ids):
            text(type_id, f"library behavior service.parameter_type_ids[{index}]")
        if self.result_type_id is not None:
            text(self.result_type_id, "library behavior service.result_type_id")
        validate_text_tuple(
            self.effect_ids, "library behavior service.effect_ids"
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.service_id,
            "parameter_type_ids": list(self.parameter_type_ids),
            "result_type_id": self.result_type_id,
            "effect_ids": list(self.effect_ids),
        }

    @classmethod
    def from_payload(
        cls, value: object, location: str
    ) -> "LibraryBehaviorServiceV2":
        row = strict_object(
            value,
            {"id", "parameter_type_ids", "result_type_id", "effect_ids"},
            location,
        )
        parameters = tuple(
            text(item, f"{location}.parameter_type_ids[{index}]")
            for index, item in enumerate(
                array(row["parameter_type_ids"], f"{location}.parameter_type_ids")
            )
        )
        return cls(
            text(row["id"], f"{location}.id"),
            parameters,
            (
                None
                if row["result_type_id"] is None
                else text(row["result_type_id"], f"{location}.result_type_id")
            ),
            text_tuple(row["effect_ids"], f"{location}.effect_ids"),
        )


@dataclass(frozen=True)
class LibraryOperationBehaviorV2:
    operation_id: str
    kind: str
    parameters: tuple[LibraryBehaviorValueV2, ...]
    results: tuple[LibraryBehaviorValueV2, ...]
    effect_ids: tuple[str, ...]
    state_effect_ids: tuple[str, ...]
    memory_effect_ids: tuple[str, ...]
    resource_effect_ids: tuple[str, ...]
    callback_effect_ids: tuple[str, ...]
    externally_visible_effect_ids: tuple[str, ...]
    service_ids: tuple[str, ...]
    pre_states: tuple[str, ...]
    post_states: tuple[str, ...]

    def __post_init__(self) -> None:
        text(self.operation_id, "library operation behavior.id")
        if self.kind not in {"operation", "callback"}:
            fail(
                "behavior_operation_kind_invalid",
                f"unsupported operation kind {self.kind!r}",
                "library operation behavior.kind",
            )
        for label, values in (
            ("effect_ids", self.effect_ids),
            ("state_effect_ids", self.state_effect_ids),
            ("memory_effect_ids", self.memory_effect_ids),
            ("resource_effect_ids", self.resource_effect_ids),
            ("callback_effect_ids", self.callback_effect_ids),
            ("externally_visible_effect_ids", self.externally_visible_effect_ids),
            ("service_ids", self.service_ids),
            ("pre_states", self.pre_states),
            ("post_states", self.post_states),
        ):
            validate_text_tuple(values, f"library operation behavior.{label}")
        for label, values in (
            ("parameters", self.parameters),
            ("results", self.results),
        ):
            ids = tuple(value.value_id for value in values)
            if len(set(ids)) != len(ids):
                fail(
                    "behavior_value_inventory_invalid",
                    f"{label} must have unique IDs",
                    f"library operation behavior.{label}",
                )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.operation_id,
            "kind": self.kind,
            "parameters": [value.to_payload() for value in self.parameters],
            "results": [value.to_payload() for value in self.results],
            "effect_ids": list(self.effect_ids),
            "state_effect_ids": list(self.state_effect_ids),
            "memory_effect_ids": list(self.memory_effect_ids),
            "resource_effect_ids": list(self.resource_effect_ids),
            "callback_effect_ids": list(self.callback_effect_ids),
            "externally_visible_effect_ids": list(
                self.externally_visible_effect_ids
            ),
            "service_ids": list(self.service_ids),
            "pre_states": list(self.pre_states),
            "post_states": list(self.post_states),
        }

    @classmethod
    def from_payload(
        cls, value: object, location: str
    ) -> "LibraryOperationBehaviorV2":
        fields = {
            "id",
            "kind",
            "parameters",
            "results",
            "effect_ids",
            "state_effect_ids",
            "memory_effect_ids",
            "resource_effect_ids",
            "callback_effect_ids",
            "externally_visible_effect_ids",
            "service_ids",
            "pre_states",
            "post_states",
        }
        row = strict_object(value, fields, location)
        return cls(
            operation_id=text(row["id"], f"{location}.id"),
            kind=text(row["kind"], f"{location}.kind"),
            parameters=tuple(
                LibraryBehaviorValueV2.from_payload(
                    item, f"{location}.parameters[{index}]"
                )
                for index, item in enumerate(
                    array(row["parameters"], f"{location}.parameters")
                )
            ),
            results=tuple(
                LibraryBehaviorValueV2.from_payload(
                    item, f"{location}.results[{index}]"
                )
                for index, item in enumerate(
                    array(row["results"], f"{location}.results")
                )
            ),
            effect_ids=text_tuple(row["effect_ids"], f"{location}.effect_ids"),
            state_effect_ids=text_tuple(
                row["state_effect_ids"], f"{location}.state_effect_ids"
            ),
            memory_effect_ids=text_tuple(
                row["memory_effect_ids"], f"{location}.memory_effect_ids"
            ),
            resource_effect_ids=text_tuple(
                row["resource_effect_ids"], f"{location}.resource_effect_ids"
            ),
            callback_effect_ids=text_tuple(
                row["callback_effect_ids"], f"{location}.callback_effect_ids"
            ),
            externally_visible_effect_ids=text_tuple(
                row["externally_visible_effect_ids"],
                f"{location}.externally_visible_effect_ids",
            ),
            service_ids=text_tuple(row["service_ids"], f"{location}.service_ids"),
            pre_states=text_tuple(row["pre_states"], f"{location}.pre_states"),
            post_states=text_tuple(row["post_states"], f"{location}.post_states"),
        )


@dataclass(frozen=True)
class LibraryBehaviorContractV2:
    contract_id: str
    interface_id: str
    interface_sha256: str
    resource_type_ids: tuple[str, ...]
    callback_type_ids: tuple[str, ...]
    state_fields: tuple[LibraryBehaviorStateFieldV2, ...]
    effects: tuple[LibraryBehaviorEffectV2, ...]
    services: tuple[LibraryBehaviorServiceV2, ...]
    operations: tuple[LibraryOperationBehaviorV2, ...]
    protocol_states: tuple[str, ...]
    initial_protocol_state: str
    contract_sha256: str

    @property
    def identity_payload(self) -> dict[str, object]:
        return {
            "interface_id": self.interface_id,
            "interface_sha256": self.interface_sha256,
            "resource_type_ids": list(self.resource_type_ids),
            "callback_type_ids": list(self.callback_type_ids),
            "state": [row.to_payload() for row in self.state_fields],
            "effects": [row.to_payload() for row in self.effects],
            "services": [row.to_payload() for row in self.services],
            "operations": [row.to_payload() for row in self.operations],
            "protocol": {
                "states": list(self.protocol_states),
                "initial_state": self.initial_protocol_state,
            },
        }

    @property
    def core_payload(self) -> dict[str, object]:
        return {
            "format": LIBRARY_BEHAVIOR_CONTRACT_V2_FORMAT,
            "id": self.contract_id,
            **self.identity_payload,
        }

    def __post_init__(self) -> None:
        text(self.interface_id, "library behavior contract.interface_id")
        sha256_text(
            self.interface_sha256, "library behavior contract.interface_sha256"
        )
        for label, values in (
            ("resource_type_ids", self.resource_type_ids),
            ("callback_type_ids", self.callback_type_ids),
            ("protocol.states", self.protocol_states),
        ):
            validate_text_tuple(values, f"library behavior contract.{label}")
        text(
            self.initial_protocol_state,
            "library behavior contract.protocol.initial_state",
        )
        if self.initial_protocol_state not in self.protocol_states:
            fail(
                "behavior_protocol_state_unknown",
                "initial protocol state is not declared",
                "library behavior contract.protocol.initial_state",
            )
        self._validate_inventory()
        expected_id = stable_id(
            "library-behavior-contract-v2", self.identity_payload
        )
        if self.contract_id != expected_id:
            fail(
                "stale_behavior_contract_id",
                "behavior contract ID does not bind its contents",
                "library behavior contract.id",
            )
        sha256_text(
            self.contract_sha256, "library behavior contract.contract_sha256"
        )
        if self.contract_sha256 != canonical_sha256(self.core_payload):
            fail(
                "stale_behavior_contract_hash",
                "behavior contract hash does not bind its contents",
                "library behavior contract.contract_sha256",
            )

    def _validate_inventory(self) -> None:
        state = _index(self.state_fields, "field_id", "state")
        effects = _index(self.effects, "effect_id", "effects")
        services = _index(self.services, "service_id", "services")
        operations = _index(self.operations, "operation_id", "operations")
        used_effects: set[str] = set()
        for service in services.values():
            missing = set(service.effect_ids) - set(effects)
            if missing:
                fail(
                    "behavior_effect_unknown",
                    f"service references unknown effects {sorted(missing)!r}",
                    f"library behavior contract.services[{service.service_id}]",
                )
            used_effects.update(service.effect_ids)
        for operation in operations.values():
            missing_effects = set(operation.effect_ids) - set(effects)
            missing_services = set(operation.service_ids) - set(services)
            missing_states = (
                set(operation.pre_states) | set(operation.post_states)
            ) - set(self.protocol_states)
            if missing_effects or missing_services or missing_states:
                fail(
                    "behavior_operation_reference_unknown",
                    "operation references an unknown effect, service, or protocol state",
                    f"library behavior contract.operations[{operation.operation_id}]",
                )
            used_effects.update(operation.effect_ids)
            visible_ids = set(operation.effect_ids)
            for service_id in operation.service_ids:
                visible_ids.update(services[service_id].effect_ids)
            expected = {
                "state": tuple(
                    sorted(
                        effect_id
                        for effect_id in visible_ids
                        if effects[effect_id].target_id in state
                    )
                ),
                "memory": tuple(
                    sorted(
                        effect_id
                        for effect_id in visible_ids
                        if effects[effect_id].kind == "memory"
                    )
                ),
                "resource": tuple(
                    sorted(
                        effect_id
                        for effect_id in visible_ids
                        if effects[effect_id].kind == "resource"
                    )
                ),
                "callback": tuple(
                    sorted(
                        effect_id
                        for effect_id in visible_ids
                        if effects[effect_id].kind == "callback"
                    )
                ),
                "external": tuple(
                    sorted(
                        effect_id
                        for effect_id in visible_ids
                        if effects[effect_id].kind
                        in _EXTERNALLY_VISIBLE_EFFECT_KINDS
                        or effect_id not in operation.effect_ids
                    )
                ),
            }
            actual = {
                "state": operation.state_effect_ids,
                "memory": operation.memory_effect_ids,
                "resource": operation.resource_effect_ids,
                "callback": operation.callback_effect_ids,
                "external": operation.externally_visible_effect_ids,
            }
            if actual != expected:
                fail(
                    "behavior_effect_projection_stale",
                    "operation effect categories do not match declared effects and services",
                    f"library behavior contract.operations[{operation.operation_id}]",
                )
        unused = set(effects) - used_effects
        if unused:
            fail(
                "behavior_effect_unreachable",
                f"effects are not visible from an operation or service: {sorted(unused)!r}",
                "library behavior contract.effects",
            )

    @classmethod
    def create(
        cls, interface: PortableComponentInterfaceV2
    ) -> "LibraryBehaviorContractV2":
        effects = tuple(
            sorted(
                (
                    LibraryBehaviorEffectV2(
                        row.identity, row.kind, row.target_id, row.operation
                    )
                    for row in interface.effects
                ),
                key=lambda row: row.effect_id,
            )
        )
        effect_index = {row.effect_id: row for row in effects}
        services = tuple(
            sorted(
                (
                    LibraryBehaviorServiceV2(
                        row.identity,
                        row.parameter_type_ids,
                        row.result_type_id,
                        tuple(sorted(row.effect_ids)),
                    )
                    for row in interface.services
                ),
                key=lambda row: row.service_id,
            )
        )
        service_index = {row.service_id: row for row in services}
        state_fields = tuple(
            sorted(
                (
                    LibraryBehaviorStateFieldV2(
                        row.identity, row.type_id, row.initial_value
                    )
                    for row in interface.state
                ),
                key=lambda row: row.field_id,
            )
        )
        state_ids = {row.field_id for row in state_fields}
        operations = []
        for row in interface.operations:
            direct_effects = tuple(sorted(row.effect_ids))
            service_ids = tuple(sorted(row.allowed_service_ids))
            visible_ids = set(direct_effects)
            for service_id in service_ids:
                visible_ids.update(service_index[service_id].effect_ids)
            operations.append(
                LibraryOperationBehaviorV2(
                    operation_id=row.identity,
                    kind=row.kind,
                    parameters=tuple(
                        LibraryBehaviorValueV2(value.identity, value.type_id)
                        for value in row.parameters
                    ),
                    results=tuple(
                        LibraryBehaviorValueV2(value.identity, value.type_id)
                        for value in row.results
                    ),
                    effect_ids=direct_effects,
                    state_effect_ids=tuple(
                        sorted(
                            effect_id
                            for effect_id in visible_ids
                            if effect_index[effect_id].target_id in state_ids
                        )
                    ),
                    memory_effect_ids=_effects_of_kind(
                        visible_ids, effect_index, "memory"
                    ),
                    resource_effect_ids=_effects_of_kind(
                        visible_ids, effect_index, "resource"
                    ),
                    callback_effect_ids=_effects_of_kind(
                        visible_ids, effect_index, "callback"
                    ),
                    externally_visible_effect_ids=tuple(
                        sorted(
                            effect_id
                            for effect_id in visible_ids
                            if effect_index[effect_id].kind
                            in _EXTERNALLY_VISIBLE_EFFECT_KINDS
                            or effect_id not in direct_effects
                        )
                    ),
                    service_ids=service_ids,
                    pre_states=tuple(sorted(row.pre_states)),
                    post_states=tuple(sorted(row.post_states)),
                )
            )
        type_kinds = {row.identity: row.kind for row in interface.types}
        identity: dict[str, object] = {
            "interface_id": interface.identity,
            "interface_sha256": interface.sha256,
            "resource_type_ids": sorted(
                type_id for type_id, kind in type_kinds.items() if kind == "resource"
            ),
            "callback_type_ids": sorted(
                type_id for type_id, kind in type_kinds.items() if kind == "callback"
            ),
            "state": [row.to_payload() for row in state_fields],
            "effects": [row.to_payload() for row in effects],
            "services": [row.to_payload() for row in services],
            "operations": [
                row.to_payload()
                for row in sorted(operations, key=lambda item: item.operation_id)
            ],
            "protocol": {
                "states": sorted(interface.protocol_states),
                "initial_state": interface.initial_protocol_state,
            },
        }
        contract_id = stable_id("library-behavior-contract-v2", identity)
        core = {
            "format": LIBRARY_BEHAVIOR_CONTRACT_V2_FORMAT,
            "id": contract_id,
            **identity,
        }
        return cls(
            contract_id=contract_id,
            interface_id=interface.identity,
            interface_sha256=interface.sha256,
            resource_type_ids=tuple(identity["resource_type_ids"]),
            callback_type_ids=tuple(identity["callback_type_ids"]),
            state_fields=state_fields,
            effects=effects,
            services=services,
            operations=tuple(
                sorted(operations, key=lambda item: item.operation_id)
            ),
            protocol_states=tuple(identity["protocol"]["states"]),
            initial_protocol_state=interface.initial_protocol_state,
            contract_sha256=canonical_sha256(core),
        )

    def to_payload(self) -> dict[str, object]:
        return {**self.core_payload, "contract_sha256": self.contract_sha256}

    @classmethod
    def from_payload(
        cls, value: object, location: str
    ) -> "LibraryBehaviorContractV2":
        fields = {
            "format",
            "id",
            "interface_id",
            "interface_sha256",
            "resource_type_ids",
            "callback_type_ids",
            "state",
            "effects",
            "services",
            "operations",
            "protocol",
            "contract_sha256",
        }
        row = strict_object(value, fields, location)
        if row["format"] != LIBRARY_BEHAVIOR_CONTRACT_V2_FORMAT:
            fail(
                "wrong_artifact_format",
                "not a library behavior contract V2 artifact",
                f"{location}.format",
            )
        protocol = strict_object(
            row["protocol"], {"states", "initial_state"}, f"{location}.protocol"
        )
        return cls(
            contract_id=text(row["id"], f"{location}.id"),
            interface_id=text(row["interface_id"], f"{location}.interface_id"),
            interface_sha256=sha256_text(
                row["interface_sha256"], f"{location}.interface_sha256"
            ),
            resource_type_ids=text_tuple(
                row["resource_type_ids"], f"{location}.resource_type_ids"
            ),
            callback_type_ids=text_tuple(
                row["callback_type_ids"], f"{location}.callback_type_ids"
            ),
            state_fields=tuple(
                LibraryBehaviorStateFieldV2.from_payload(
                    item, f"{location}.state[{index}]"
                )
                for index, item in enumerate(array(row["state"], f"{location}.state"))
            ),
            effects=tuple(
                LibraryBehaviorEffectV2.from_payload(
                    item, f"{location}.effects[{index}]"
                )
                for index, item in enumerate(
                    array(row["effects"], f"{location}.effects")
                )
            ),
            services=tuple(
                LibraryBehaviorServiceV2.from_payload(
                    item, f"{location}.services[{index}]"
                )
                for index, item in enumerate(
                    array(row["services"], f"{location}.services")
                )
            ),
            operations=tuple(
                LibraryOperationBehaviorV2.from_payload(
                    item, f"{location}.operations[{index}]"
                )
                for index, item in enumerate(
                    array(row["operations"], f"{location}.operations")
                )
            ),
            protocol_states=text_tuple(
                protocol["states"], f"{location}.protocol.states"
            ),
            initial_protocol_state=text(
                protocol["initial_state"], f"{location}.protocol.initial_state"
            ),
            contract_sha256=sha256_text(
                row["contract_sha256"], f"{location}.contract_sha256"
            ),
        )

    def require_exact_interface(
        self, interface: PortableComponentInterfaceV2
    ) -> None:
        expected = type(self).create(interface)
        if self != expected:
            fail(
                "behavior_interface_binding_stale",
                "behavior contract does not exactly represent the portable interface",
                "library behavior contract",
            )


def _index(
    values: Iterable[object], attribute: str, location: str
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    ids = tuple(str(getattr(value, attribute)) for value in values)
    if tuple(sorted(set(ids))) != ids:
        fail(
            "behavior_inventory_invalid",
            "records must have unique, canonically sorted IDs",
            f"library behavior contract.{location}",
        )
    for value in values:
        result[str(getattr(value, attribute))] = value
    return result


def _effects_of_kind(
    effect_ids: Iterable[str],
    effects: dict[str, LibraryBehaviorEffectV2],
    kind: str,
) -> tuple[str, ...]:
    return tuple(
        sorted(effect_id for effect_id in effect_ids if effects[effect_id].kind == kind)
    )


LIBRARY_BEHAVIOR_CONTRACT_CODEC_V2 = StrictCodec(
    lambda value: value.to_payload(), LibraryBehaviorContractV2.from_payload
)


__all__ = [
    "LIBRARY_BEHAVIOR_CONTRACT_CODEC_V2",
    "LIBRARY_BEHAVIOR_CONTRACT_V2_FORMAT",
    "LibraryBehaviorContractV2",
    "LibraryBehaviorEffectV2",
    "LibraryBehaviorServiceV2",
    "LibraryBehaviorStateFieldV2",
    "LibraryBehaviorValueV2",
    "LibraryOperationBehaviorV2",
]
