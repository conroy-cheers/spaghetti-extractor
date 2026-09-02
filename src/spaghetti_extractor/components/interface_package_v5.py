"""Content-bound V5 component-interface intent and deterministic compiler.

This is the clean-cut entry point for component interfaces.  It accepts only
canonical boundary artifacts and constructs checked V5 interfaces directly;
there is intentionally no V2--V4 adaptation path here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary import (
    BoundaryLifecycleReceiptV1,
    BoundaryLifecycleV1,
    BoundaryProjectionReceiptV1,
    BoundaryProjectionV1,
    BoundarySchemaV1,
)
from ..boundary._canonical import (
    BoundaryModelError,
    array,
    canonical,
    exact,
    identifier,
    object_,
)
from ..util import write_json
from .formats import COMPONENT_INTERFACE_INTENT_V1_FORMAT
from .interface_v5 import PortableComponentInterfaceV5


_OPERATION_FIELDS = {
    "id",
    "signature_id",
    "source_values",
    "projection_entries",
    "lifecycle_bindings",
    "lifecycle_additional_roots",
    "checked_interaction_contract_ids",
    "effect_ids",
    "allowed_service_ids",
    "pre_states",
    "post_states",
}


@dataclass(frozen=True)
class ComponentInterfaceIntentV1:
    """Operator intent whose digest covers every V5 interface input."""

    component_id: str
    schema: BoundarySchemaV1
    state: tuple[Mapping[str, object], ...]
    operations: tuple[Mapping[str, object], ...]
    effects: tuple[Mapping[str, object], ...]
    services: tuple[Mapping[str, object], ...]
    protocol_states: tuple[str, ...]
    initial_protocol_state: str
    intent_sha256: str

    @classmethod
    def create(
        cls,
        *,
        component_id: str,
        schema: BoundarySchemaV1,
        state: Sequence[Mapping[str, object]],
        operations: Sequence[Mapping[str, object]],
        effects: Sequence[Mapping[str, object]],
        services: Sequence[Mapping[str, object]],
        protocol_states: Sequence[str],
        initial_protocol_state: str,
    ) -> "ComponentInterfaceIntentV1":
        identity = identifier(component_id, "component interface intent id")
        normalized_operations = tuple(
            _normalize_operation(item, index)
            for index, item in enumerate(operations)
        )
        operation_ids = tuple(str(item["id"]) for item in normalized_operations)
        if not operation_ids or operation_ids != tuple(sorted(set(operation_ids))):
            raise BoundaryModelError(
                "component interface intent operations must be nonempty, unique, and ordered"
            )
        states = tuple(
            sorted(
                set(
                    identifier(item, "component interface protocol state")
                    for item in protocol_states
                )
            )
        )
        initial = identifier(
            initial_protocol_state, "component interface initial protocol state"
        )
        if not states or initial not in states:
            raise BoundaryModelError(
                "component interface intent protocol lacks its initial state"
            )
        normalized_state = tuple(
            canonical(dict(object_(item, f"component state {index}")))
            for index, item in enumerate(state)
        )
        normalized_effects = tuple(
            canonical(dict(object_(item, f"component effect {index}")))
            for index, item in enumerate(effects)
        )
        normalized_services = tuple(
            canonical(dict(object_(item, f"component service {index}")))
            for index, item in enumerate(services)
        )
        core = {
            "format": COMPONENT_INTERFACE_INTENT_V1_FORMAT,
            "status": "complete",
            "id": identity,
            "schema": schema.to_payload(),
            "state": list(normalized_state),
            "operations": list(normalized_operations),
            "effects": list(normalized_effects),
            "services": list(normalized_services),
            "protocol": {
                "states": list(states),
                "initial_state": initial,
            },
        }
        result = cls(
            identity,
            schema,
            normalized_state,
            normalized_operations,
            normalized_effects,
            normalized_services,
            states,
            initial,
            canonical_sha256_v3(core),
        )
        # Compilation is part of intent validation.  No unchecked intent can be
        # serialized and mistaken for a V5 interface input.
        compile_component_interface_v5(result)
        return result

    @classmethod
    def parse(cls, value: object) -> "ComponentInterfaceIntentV1":
        row = object_(value, "component interface intent V1")
        exact(
            row,
            {
                "format",
                "status",
                "id",
                "schema",
                "state",
                "operations",
                "effects",
                "services",
                "protocol",
                "intent_sha256",
            },
            "component interface intent V1",
        )
        if (
            row["format"] != COMPONENT_INTERFACE_INTENT_V1_FORMAT
            or row["status"] != "complete"
        ):
            raise BoundaryModelError("unsupported component interface intent format")
        protocol = object_(row["protocol"], "component interface intent protocol")
        exact(protocol, {"states", "initial_state"}, "component interface intent protocol")
        result = cls.create(
            component_id=str(row["id"]),
            schema=BoundarySchemaV1.parse(row["schema"]),
            state=[
                dict(object_(item, f"component state {index}"))
                for index, item in enumerate(array(row["state"], "component state"))
            ],
            operations=[
                dict(object_(item, f"component operation {index}"))
                for index, item in enumerate(
                    array(row["operations"], "component operations")
                )
            ],
            effects=[
                dict(object_(item, f"component effect {index}"))
                for index, item in enumerate(array(row["effects"], "component effects"))
            ],
            services=[
                dict(object_(item, f"component service {index}"))
                for index, item in enumerate(array(row["services"], "component services"))
            ],
            protocol_states=[
                str(item) for item in array(protocol["states"], "protocol states")
            ],
            initial_protocol_state=str(protocol["initial_state"]),
        )
        if row["intent_sha256"] != result.intent_sha256:
            raise BoundaryModelError("component interface intent digest is stale")
        return result

    def to_payload(self) -> dict[str, object]:
        return {
            "format": COMPONENT_INTERFACE_INTENT_V1_FORMAT,
            "status": "complete",
            "id": self.component_id,
            "schema": self.schema.to_payload(),
            "state": [canonical(dict(item)) for item in self.state],
            "operations": [canonical(dict(item)) for item in self.operations],
            "effects": [canonical(dict(item)) for item in self.effects],
            "services": [canonical(dict(item)) for item in self.services],
            "protocol": {
                "states": list(self.protocol_states),
                "initial_state": self.initial_protocol_state,
            },
            "intent_sha256": self.intent_sha256,
        }


@dataclass(frozen=True)
class CompiledComponentInterfaceV5:
    intent: ComponentInterfaceIntentV1
    projections: Mapping[str, BoundaryProjectionV1]
    projection_receipts: Mapping[str, BoundaryProjectionReceiptV1]
    lifecycles: Mapping[str, BoundaryLifecycleV1]
    lifecycle_receipts: Mapping[str, BoundaryLifecycleReceiptV1]
    interface: PortableComponentInterfaceV5


def compile_component_interface_v5(
    intent: ComponentInterfaceIntentV1,
) -> CompiledComponentInterfaceV5:
    projections: dict[str, BoundaryProjectionV1] = {}
    projection_receipts: dict[str, BoundaryProjectionReceiptV1] = {}
    lifecycles: dict[str, BoundaryLifecycleV1] = {}
    lifecycle_receipts: dict[str, BoundaryLifecycleReceiptV1] = {}
    policies: list[dict[str, object]] = []
    for operation in intent.operations:
        operation_id = str(operation["id"])
        projection = BoundaryProjectionV1.create(
            component_id=intent.component_id,
            operation_id=operation_id,
            schema=intent.schema,
            signature_id=str(operation["signature_id"]),
            source_values=list(operation["source_values"]),
            entries=list(operation["projection_entries"]),
        )
        projection_receipt = BoundaryProjectionReceiptV1.check(
            projection, schema=intent.schema
        )
        additional_roots = object_(
            operation["lifecycle_additional_roots"],
            f"component operation {operation_id} lifecycle roots",
        )
        lifecycle = BoundaryLifecycleV1.create(
            schema=intent.schema,
            signature_id=str(operation["signature_id"]),
            bindings=list(operation["lifecycle_bindings"]),
            additional_roots={
                str(root): list(array(values, f"lifecycle root {root}"))
                for root, values in additional_roots.items()
            },
        )
        lifecycle_receipt = BoundaryLifecycleReceiptV1.check(
            lifecycle,
            checked_interaction_contract_ids=list(
                operation["checked_interaction_contract_ids"]
            ),
        )
        projections[operation_id] = projection
        projection_receipts[operation_id] = projection_receipt
        lifecycles[operation_id] = lifecycle
        lifecycle_receipts[operation_id] = lifecycle_receipt
        policies.append(
            {
                key: canonical(operation[key])
                for key in (
                    "id",
                    "effect_ids",
                    "allowed_service_ids",
                    "pre_states",
                    "post_states",
                )
            }
        )
    interface = PortableComponentInterfaceV5.create(
        identity=intent.component_id,
        schema=intent.schema,
        state=list(intent.state),
        operation_policies=policies,
        projections=projections,
        projection_receipts=projection_receipts,
        lifecycles=lifecycles,
        lifecycle_receipts=lifecycle_receipts,
        effects=list(intent.effects),
        services=list(intent.services),
        protocol_states=intent.protocol_states,
        initial_protocol_state=intent.initial_protocol_state,
    )
    return CompiledComponentInterfaceV5(
        intent,
        dict(sorted(projections.items())),
        dict(sorted(projection_receipts.items())),
        dict(sorted(lifecycles.items())),
        dict(sorted(lifecycle_receipts.items())),
        interface,
    )


def write_component_interface_package_v5(
    output: Path | str, intent: ComponentInterfaceIntentV1
) -> CompiledComponentInterfaceV5:
    """Write the immutable generated V5 boundary package."""

    root = Path(output)
    bundle = compile_component_interface_v5(intent)
    write_json(root / "component-interface-intent-v1.json", intent.to_payload())
    write_json(root / "boundary-schema-v1.json", intent.schema.to_payload())
    write_json(
        root / "portable-component-interface-v5.json", bundle.interface.to_payload()
    )
    for index, operation_id in enumerate(sorted(bundle.projections)):
        operation_root = root / "operations" / f"{index:04d}"
        write_json(
            operation_root / "boundary-projection-v1.json",
            bundle.projections[operation_id].to_payload(),
        )
        write_json(
            operation_root / "boundary-projection-receipt-v1.json",
            bundle.projection_receipts[operation_id].to_payload(),
        )
        write_json(
            operation_root / "boundary-lifecycle-v1.json",
            bundle.lifecycles[operation_id].to_payload(),
        )
        write_json(
            operation_root / "boundary-lifecycle-receipt-v1.json",
            bundle.lifecycle_receipts[operation_id].to_payload(),
        )
    return bundle


def _normalize_operation(
    value: Mapping[str, object], index: int
) -> Mapping[str, object]:
    row = object_(value, f"component interface operation {index}")
    exact(row, _OPERATION_FIELDS, f"component interface operation {index}")
    result = {key: canonical(row[key]) for key in sorted(_OPERATION_FIELDS)}
    result["id"] = identifier(row["id"], f"component interface operation {index} id")
    result["signature_id"] = identifier(
        row["signature_id"], f"component interface operation {index} signature"
    )
    for field in (
        "source_values",
        "projection_entries",
        "lifecycle_bindings",
        "checked_interaction_contract_ids",
        "effect_ids",
        "allowed_service_ids",
        "pre_states",
        "post_states",
    ):
        array(row[field], f"component interface operation {index} {field}")
    object_(
        row["lifecycle_additional_roots"],
        f"component interface operation {index} lifecycle roots",
    )
    return result


__all__ = [
    "CompiledComponentInterfaceV5",
    "ComponentInterfaceIntentV1",
    "compile_component_interface_v5",
    "write_component_interface_package_v5",
]
