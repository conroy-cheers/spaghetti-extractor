"""Portable component interfaces over the shared canonical boundary schema."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary import (
    BoundaryLifecycleReceiptV1,
    BoundaryLifecycleV1,
    BoundaryProjectionReceiptV1,
    BoundaryProjectionV1,
    BoundarySchemaV1,
    BoundaryValuePathV1,
    BoundaryValueV1,
    resolve_field_path_type,
)
from ..boundary._canonical import (
    BoundaryModelError,
    array,
    canonical,
    exact,
    identifier,
    object_,
    text,
)
from .formats import PORTABLE_COMPONENT_INTERFACE_V5_FORMAT


EFFECT_KINDS_V5 = frozenset(
    {"memory", "resource", "callback", "observable", "control", "atomic", "state"}
)


@dataclass(frozen=True)
class ComponentStateValueV5:
    value: BoundaryValueV1
    initial: object

    @classmethod
    def parse(cls, value: object, context: str) -> "ComponentStateValueV5":
        row = object_(value, context)
        exact(row, {"value", "initial"}, context)
        return cls(
            BoundaryValueV1.parse(row["value"], f"{context} value"),
            canonical(row["initial"]),
        )

    def to_payload(self) -> dict[str, object]:
        return {"value": self.value.to_payload(), "initial": canonical(self.initial)}


@dataclass(frozen=True)
class ComponentEffectV5:
    identity: str
    kind: str
    operation: str
    target: BoundaryValuePathV1 | None

    @classmethod
    def parse(cls, value: object, context: str) -> "ComponentEffectV5":
        row = object_(value, context)
        exact(row, {"id", "kind", "operation", "target"}, context)
        kind = text(row["kind"], f"{context} kind")
        if kind not in EFFECT_KINDS_V5:
            raise BoundaryModelError(f"{context} kind is unsupported")
        return cls(
            identifier(row["id"], f"{context} id"),
            kind,
            identifier(row["operation"], f"{context} operation"),
            None
            if row["target"] is None
            else BoundaryValuePathV1.parse(row["target"], f"{context} target"),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "kind": self.kind,
            "operation": self.operation,
            "target": None if self.target is None else self.target.to_payload(),
        }


@dataclass(frozen=True)
class ComponentServiceV5:
    identity: str
    signature_id: str
    effect_ids: tuple[str, ...]
    interaction_contract_id: str

    @classmethod
    def parse(cls, value: object, context: str) -> "ComponentServiceV5":
        row = object_(value, context)
        exact(
            row,
            {"id", "signature_id", "effect_ids", "interaction_contract_id"},
            context,
        )
        effects = tuple(
            sorted(
                set(
                    identifier(item, f"{context} effect")
                    for item in array(row["effect_ids"], f"{context} effects")
                )
            )
        )
        return cls(
            identifier(row["id"], f"{context} id"),
            identifier(row["signature_id"], f"{context} signature"),
            effects,
            identifier(
                row["interaction_contract_id"], f"{context} interaction contract"
            ),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "signature_id": self.signature_id,
            "effect_ids": list(self.effect_ids),
            "interaction_contract_id": self.interaction_contract_id,
        }


@dataclass(frozen=True)
class PortableComponentOperationV5:
    identity: str
    signature_id: str
    projection_sha256: str
    projection_receipt_sha256: str
    lifecycle_sha256: str
    lifecycle_receipt_sha256: str
    effect_ids: tuple[str, ...]
    allowed_service_ids: tuple[str, ...]
    pre_states: tuple[str, ...]
    post_states: tuple[str, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "signature_id": self.signature_id,
            "projection_sha256": self.projection_sha256,
            "projection_receipt_sha256": self.projection_receipt_sha256,
            "lifecycle_sha256": self.lifecycle_sha256,
            "lifecycle_receipt_sha256": self.lifecycle_receipt_sha256,
            "effect_ids": list(self.effect_ids),
            "allowed_service_ids": list(self.allowed_service_ids),
            "pre_states": list(self.pre_states),
            "post_states": list(self.post_states),
        }


@dataclass(frozen=True)
class PortableComponentInterfaceV5:
    identity: str
    schema_id: str
    schema_sha256: str
    state: tuple[ComponentStateValueV5, ...]
    operations: tuple[PortableComponentOperationV5, ...]
    effects: tuple[ComponentEffectV5, ...]
    services: tuple[ComponentServiceV5, ...]
    protocol_states: tuple[str, ...]
    initial_protocol_state: str
    interface_sha256: str

    @classmethod
    def create(
        cls,
        *,
        identity: str,
        schema: BoundarySchemaV1,
        state: Sequence[ComponentStateValueV5 | Mapping[str, object]],
        operation_policies: Sequence[Mapping[str, object]],
        projections: Mapping[str, BoundaryProjectionV1],
        projection_receipts: Mapping[str, BoundaryProjectionReceiptV1],
        lifecycles: Mapping[str, BoundaryLifecycleV1],
        lifecycle_receipts: Mapping[str, BoundaryLifecycleReceiptV1],
        effects: Sequence[ComponentEffectV5 | Mapping[str, object]],
        services: Sequence[ComponentServiceV5 | Mapping[str, object]],
        protocol_states: Sequence[str],
        initial_protocol_state: str,
    ) -> "PortableComponentInterfaceV5":
        component_id = identifier(identity, "component interface id")
        parsed_state = tuple(
            sorted(
                (
                    item
                    if isinstance(item, ComponentStateValueV5)
                    else ComponentStateValueV5.parse(item, f"component state {index}")
                    for index, item in enumerate(state)
                ),
                key=lambda item: item.value.identity,
            )
        )
        if [item.value.identity for item in parsed_state] != sorted(
            set(item.value.identity for item in parsed_state)
        ):
            raise BoundaryModelError("component state values are duplicated")
        for item in parsed_state:
            if item.value.type_id not in schema.type_index:
                raise BoundaryModelError("component state value has an unknown type")
        parsed_effects = tuple(
            sorted(
                (
                    item
                    if isinstance(item, ComponentEffectV5)
                    else ComponentEffectV5.parse(item, f"component effect {index}")
                    for index, item in enumerate(effects)
                ),
                key=lambda item: item.identity,
            )
        )
        parsed_services = tuple(
            sorted(
                (
                    item
                    if isinstance(item, ComponentServiceV5)
                    else ComponentServiceV5.parse(item, f"component service {index}")
                    for index, item in enumerate(services)
                ),
                key=lambda item: item.identity,
            )
        )
        effect_ids = _unique((item.identity for item in parsed_effects), "component effect")
        service_ids = _unique((item.identity for item in parsed_services), "component service")
        for service in parsed_services:
            if service.signature_id not in schema.signature_index:
                raise BoundaryModelError("component service names an unknown signature")
            if not set(service.effect_ids) <= effect_ids:
                raise BoundaryModelError("component service names an unknown effect")
        states = tuple(
            sorted(set(identifier(item, "component protocol state") for item in protocol_states))
        )
        initial = identifier(initial_protocol_state, "initial component protocol state")
        if not states or initial not in states:
            raise BoundaryModelError("component protocol states are empty or lack the initial state")
        operations: list[PortableComponentOperationV5] = []
        for index, policy_value in enumerate(operation_policies):
            policy = object_(policy_value, f"component operation policy {index}")
            exact(
                policy,
                {"id", "effect_ids", "allowed_service_ids", "pre_states", "post_states"},
                f"component operation policy {index}",
            )
            operation_id = identifier(policy["id"], "component operation id")
            projection = projections.get(operation_id)
            projection_receipt = projection_receipts.get(operation_id)
            lifecycle = lifecycles.get(operation_id)
            lifecycle_receipt = lifecycle_receipts.get(operation_id)
            if any(
                item is None
                for item in (
                    projection, projection_receipt, lifecycle, lifecycle_receipt
                )
            ):
                raise BoundaryModelError(
                    f"component operation {operation_id!r} lacks checked boundary artifacts"
                )
            assert projection is not None and projection_receipt is not None
            assert lifecycle is not None and lifecycle_receipt is not None
            if (
                projection.component_id != component_id
                or projection.operation_id != operation_id
                or projection.schema_sha256 != schema.schema_sha256
                or projection_receipt.projection_sha256 != projection.projection_sha256
                or projection_receipt.status != "complete"
                or lifecycle.schema_sha256 != schema.schema_sha256
                or lifecycle.signature_id != projection.signature_id
                or lifecycle_receipt.lifecycle_sha256 != lifecycle.lifecycle_sha256
                or lifecycle_receipt.status != "complete"
            ):
                raise BoundaryModelError(
                    f"component operation {operation_id!r} has unchecked or inconsistent boundaries"
                )
            operation_effects = tuple(
                sorted(set(identifier(item, "operation effect") for item in array(policy["effect_ids"], "operation effects")))
            )
            operation_services = tuple(
                sorted(set(identifier(item, "operation service") for item in array(policy["allowed_service_ids"], "operation services")))
            )
            before = tuple(sorted(set(identifier(item, "operation pre-state") for item in array(policy["pre_states"], "operation pre-states"))))
            after = tuple(sorted(set(identifier(item, "operation post-state") for item in array(policy["post_states"], "operation post-states"))))
            if not set(operation_effects) <= effect_ids or not set(operation_services) <= service_ids:
                raise BoundaryModelError("component operation names an unknown effect or service")
            if not before or not after or not (set(before) | set(after)) <= set(states):
                raise BoundaryModelError("component operation has invalid protocol states")
            operations.append(
                PortableComponentOperationV5(
                    operation_id, projection.signature_id,
                    projection.projection_sha256, projection_receipt.receipt_sha256,
                    lifecycle.lifecycle_sha256, lifecycle_receipt.receipt_sha256,
                    operation_effects, operation_services, before, after,
                )
            )
        ordered_operations = tuple(sorted(operations, key=lambda item: item.identity))
        operation_ids = _unique((item.identity for item in ordered_operations), "component operation")
        if not operation_ids:
            raise BoundaryModelError("portable component interface requires operations")
        if any(item.operation not in operation_ids for item in parsed_effects):
            raise BoundaryModelError("component effect names an unknown operation")
        projection_index = {item.operation_id: item for item in projections.values()}
        state_index = {item.value.identity: item.value for item in parsed_state}
        for effect in parsed_effects:
            if effect.target is not None:
                _validate_effect_path(
                    schema, effect.target, state_index, projection_index[effect.operation]
                )
        core = {
            "format": PORTABLE_COMPONENT_INTERFACE_V5_FORMAT,
            "id": component_id,
            "schema_id": schema.schema_id,
            "schema_sha256": schema.schema_sha256,
            "state": [item.to_payload() for item in parsed_state],
            "operations": [item.to_payload() for item in ordered_operations],
            "effects": [item.to_payload() for item in parsed_effects],
            "services": [item.to_payload() for item in parsed_services],
            "protocol": {"states": list(states), "initial_state": initial},
        }
        return cls(
            component_id, schema.schema_id, schema.schema_sha256, parsed_state,
            ordered_operations, parsed_effects, parsed_services, states, initial,
            canonical_sha256_v3(core),
        )

    @classmethod
    def parse(
        cls,
        value: object,
        *,
        schema: BoundarySchemaV1,
        projections: Mapping[str, BoundaryProjectionV1],
        projection_receipts: Mapping[str, BoundaryProjectionReceiptV1],
        lifecycles: Mapping[str, BoundaryLifecycleV1],
        lifecycle_receipts: Mapping[str, BoundaryLifecycleReceiptV1],
    ) -> "PortableComponentInterfaceV5":
        row = object_(value, "portable component interface V5")
        exact(
            row,
            {
                "format", "id", "schema_id", "schema_sha256", "state",
                "operations", "effects", "services", "protocol",
                "interface_sha256",
            },
            "portable component interface V5",
        )
        if (
            row["format"] != PORTABLE_COMPONENT_INTERFACE_V5_FORMAT
            or row["schema_id"] != schema.schema_id
            or row["schema_sha256"] != schema.schema_sha256
        ):
            raise BoundaryModelError(
                "portable component interface V5 binds another schema or format"
            )
        protocol = object_(row["protocol"], "component protocol")
        exact(protocol, {"states", "initial_state"}, "component protocol")
        operation_policies = []
        for index, operation_value in enumerate(
            array(row["operations"], "component operations")
        ):
            operation = object_(operation_value, f"component operation {index}")
            exact(
                operation,
                {
                    "id", "signature_id", "projection_sha256",
                    "projection_receipt_sha256", "lifecycle_sha256",
                    "lifecycle_receipt_sha256", "effect_ids",
                    "allowed_service_ids", "pre_states", "post_states",
                },
                f"component operation {index}",
            )
            operation_policies.append({
                key: operation[key]
                for key in (
                    "id", "effect_ids", "allowed_service_ids", "pre_states",
                    "post_states",
                )
            })
        result = cls.create(
            identity=str(row["id"]), schema=schema,
            state=[
                ComponentStateValueV5.parse(item, f"component state {index}")
                for index, item in enumerate(array(row["state"], "component state"))
            ],
            operation_policies=operation_policies,
            projections=projections,
            projection_receipts=projection_receipts,
            lifecycles=lifecycles,
            lifecycle_receipts=lifecycle_receipts,
            effects=[
                ComponentEffectV5.parse(item, f"component effect {index}")
                for index, item in enumerate(array(row["effects"], "component effects"))
            ],
            services=[
                ComponentServiceV5.parse(item, f"component service {index}")
                for index, item in enumerate(array(row["services"], "component services"))
            ],
            protocol_states=[
                str(item) for item in array(protocol["states"], "component states")
            ],
            initial_protocol_state=str(protocol["initial_state"]),
        )
        if result.to_payload() != dict(row):
            raise BoundaryModelError("portable component interface V5 is stale")
        return result

    def to_payload(self) -> dict[str, object]:
        return {
            "format": PORTABLE_COMPONENT_INTERFACE_V5_FORMAT,
            "id": self.identity,
            "schema_id": self.schema_id,
            "schema_sha256": self.schema_sha256,
            "state": [item.to_payload() for item in self.state],
            "operations": [item.to_payload() for item in self.operations],
            "effects": [item.to_payload() for item in self.effects],
            "services": [item.to_payload() for item in self.services],
            "protocol": {
                "states": list(self.protocol_states),
                "initial_state": self.initial_protocol_state,
            },
            "interface_sha256": self.interface_sha256,
        }


def _unique(values: Iterable[str], context: str) -> set[str]:
    rows = list(values)
    result = set(rows)
    if len(rows) != len(result):
        raise BoundaryModelError(f"{context} ids are duplicated")
    return result


def _validate_effect_path(
    schema: BoundarySchemaV1,
    path: BoundaryValuePathV1,
    state: Mapping[str, BoundaryValueV1],
    projection: BoundaryProjectionV1,
) -> None:
    if path.root == "state":
        value = state.get(path.value_id)
    elif path.root in {"parameter", "result"}:
        signature = schema.signature_index[projection.signature_id]
        rows = signature.parameters if path.root == "parameter" else signature.results
        value = next((item for item in rows if item.identity == path.value_id), None)
    else:
        value = None
    if value is None:
        raise BoundaryModelError("component effect path names an unknown value")
    resolve_field_path_type(
        schema, value.type_id, path.fields, context="component effect path"
    )


__all__ = [
    "ComponentEffectV5",
    "ComponentServiceV5",
    "ComponentStateValueV5",
    "PortableComponentInterfaceV5",
    "PortableComponentOperationV5",
]
