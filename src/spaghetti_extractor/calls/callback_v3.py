"""Callback registration and delivery over canonical checked calls."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.formats import CALLBACK_PROTOCOL_V3_FORMAT
from ..boundary import (
    BoundarySchemaV1,
    BoundaryTypeV1,
    BoundaryValuePathV1,
    resolve_field_path_type,
)
from ._canonical import CallProtocolError, array, content_id, exact, identifier, object_
from .callback import (
    CALLBACK_ACTIONS,
    INSTANCE_KINDS,
    CallbackCardinalityV2,
    CallbackDeliveryV2,
    CallbackLifetimeV2,
)
from .protocol_v2 import CheckedCallProtocolV2


@dataclass(frozen=True)
class CallbackProtocolV3:
    callback_id: str
    action: str
    registration_protocol_id: str | None
    invocation_protocol_id: str | None
    source_path: BoundaryValuePathV1 | None
    instance_kind: str
    instance_paths: tuple[BoundaryValuePathV1, ...]
    previous_disposition: str
    previous_result_path: BoundaryValuePathV1 | None
    lifetime: CallbackLifetimeV2
    delivery: CallbackDeliveryV2
    cardinality: CallbackCardinalityV2
    interaction_contract_id: str
    evidence_receipt_id: str

    @classmethod
    def create(
        cls,
        *,
        action: str,
        registration_protocol: CheckedCallProtocolV2 | None,
        invocation_protocol: CheckedCallProtocolV2 | None,
        registration_schema: BoundarySchemaV1 | None,
        invocation_schema: BoundarySchemaV1 | None,
        source_path: BoundaryValuePathV1 | Mapping[str, object] | None,
        instance_kind: str,
        instance_paths: Sequence[BoundaryValuePathV1 | Mapping[str, object]],
        previous_disposition: str,
        previous_result_path: BoundaryValuePathV1 | Mapping[str, object] | None,
        lifetime: CallbackLifetimeV2 | Mapping[str, object],
        delivery: CallbackDeliveryV2 | Mapping[str, object],
        cardinality: CallbackCardinalityV2 | Mapping[str, object],
        interaction_contract_id: str,
        evidence_receipt_id: str,
    ) -> "CallbackProtocolV3":
        if action not in CALLBACK_ACTIONS or instance_kind not in INSTANCE_KINDS:
            raise CallProtocolError("callback action or instance kind is unsupported")
        if action in {"register", "replace", "unregister"} and registration_protocol is None:
            raise CallProtocolError("callback state transition lacks a registration call")
        if action in {"register", "replace", "invoke"} and invocation_protocol is None:
            raise CallProtocolError("callback protocol lacks an invocation call")
        for protocol in (registration_protocol, invocation_protocol):
            if protocol is not None and protocol.status != "complete":
                raise CallProtocolError("callback protocol references an unchecked call")
        if (registration_protocol is None) != (registration_schema is None):
            raise CallProtocolError("callback registration schema and protocol disagree")
        if (invocation_protocol is None) != (invocation_schema is None):
            raise CallProtocolError("callback invocation schema and protocol disagree")
        for protocol, schema in (
            (registration_protocol, registration_schema),
            (invocation_protocol, invocation_schema),
        ):
            if protocol is not None and schema is not None and protocol.schema_sha256 != schema.schema_sha256:
                raise CallProtocolError("callback call protocol binds another boundary schema")
        source = (
            source_path
            if isinstance(source_path, BoundaryValuePathV1)
            else None
            if source_path is None
            else BoundaryValuePathV1.parse(source_path, "callback source path")
        )
        if (action in {"register", "replace"}) != (source is not None):
            raise CallProtocolError("callback registration and source path disagree")
        if source is not None:
            assert registration_schema is not None and registration_protocol is not None
            source_type = _validate_signature_path(
                registration_schema, registration_protocol.signature_id, source
            )
            assert invocation_schema is not None and invocation_protocol is not None
            invocation_function_id = invocation_schema.signature_index[
                invocation_protocol.signature_id
            ].function_type_id
            if (
                registration_schema.schema_sha256 != invocation_schema.schema_sha256
                or source_type.kind != "pointer"
                or source_type.body["pointee_type_id"] != invocation_function_id
            ):
                raise CallProtocolError(
                    "callback source does not point to the checked invocation signature"
                )
        instances = tuple(
            item
            if isinstance(item, BoundaryValuePathV1)
            else BoundaryValuePathV1.parse(item, f"callback instance path {index}")
            for index, item in enumerate(instance_paths)
        )
        if (instance_kind == "singleton") == bool(instances):
            raise CallProtocolError("callback instance kind and key paths disagree")
        previous = (
            previous_result_path
            if isinstance(previous_result_path, BoundaryValuePathV1)
            else None
            if previous_result_path is None
            else BoundaryValuePathV1.parse(
                previous_result_path, "callback previous-result path"
            )
        )
        if previous_disposition not in {"none", "not_exposed", "returned"}:
            raise CallProtocolError("callback previous-handler disposition is unsupported")
        if action != "replace" and previous_disposition != "none":
            raise CallProtocolError("non-replacement callback carries previous-handler policy")
        if action == "replace" and previous_disposition == "none":
            raise CallProtocolError("callback replacement lacks previous-handler policy")
        if (previous_disposition == "returned") != (previous is not None):
            raise CallProtocolError("callback previous-handler result path disagrees")
        if previous is not None:
            assert registration_schema is not None and registration_protocol is not None
            previous_type = _validate_signature_path(
                registration_schema, registration_protocol.signature_id, previous
            )
            assert invocation_schema is not None and invocation_protocol is not None
            if (
                previous_type.kind != "pointer"
                or previous_type.body["pointee_type_id"]
                != invocation_schema.signature_index[
                    invocation_protocol.signature_id
                ].function_type_id
            ):
                raise CallProtocolError(
                    "previous callback result has another invocation signature"
                )
        parsed_lifetime = lifetime if isinstance(lifetime, CallbackLifetimeV2) else CallbackLifetimeV2.parse(lifetime)
        parsed_delivery = delivery if isinstance(delivery, CallbackDeliveryV2) else CallbackDeliveryV2.parse(delivery)
        parsed_cardinality = cardinality if isinstance(cardinality, CallbackCardinalityV2) else CallbackCardinalityV2.parse(cardinality)
        core = {
            "format": CALLBACK_PROTOCOL_V3_FORMAT,
            "action": action,
            "registration_protocol_id": None if registration_protocol is None else registration_protocol.protocol_id,
            "invocation_protocol_id": None if invocation_protocol is None else invocation_protocol.protocol_id,
            "source_path": None if source is None else source.to_payload(),
            "instance": {"kind": instance_kind, "paths": [item.to_payload() for item in instances]},
            "previous_disposition": previous_disposition,
            "previous_result_path": None if previous is None else previous.to_payload(),
            "lifetime": parsed_lifetime.to_payload(),
            "delivery": parsed_delivery.to_payload(),
            "cardinality": parsed_cardinality.to_payload(),
            "interaction_contract_id": identifier(interaction_contract_id, "callback interaction contract"),
            "evidence_receipt_id": identifier(evidence_receipt_id, "callback evidence receipt"),
        }
        return cls(
            content_id("callback-protocol-v3", core), action,
            core["registration_protocol_id"], core["invocation_protocol_id"],
            source, instance_kind, instances, previous_disposition, previous,
            parsed_lifetime,
            parsed_delivery, parsed_cardinality, str(core["interaction_contract_id"]),
            str(core["evidence_receipt_id"]),
        )

    @classmethod
    def parse(
        cls,
        value: object,
        *,
        protocols: Mapping[str, CheckedCallProtocolV2],
        schemas_by_sha256: Mapping[str, BoundarySchemaV1],
    ) -> "CallbackProtocolV3":
        row = object_(value, "callback protocol V3")
        exact(
            row,
            {
                "format", "id", "action", "registration_protocol_id",
                "invocation_protocol_id", "source_path", "instance",
                "previous_disposition", "previous_result_path", "lifetime",
                "delivery", "cardinality", "interaction_contract_id",
                "evidence_receipt_id",
            },
            "callback protocol V3",
        )
        if row["format"] != CALLBACK_PROTOCOL_V3_FORMAT:
            raise CallProtocolError("unsupported callback protocol V3 format")
        registration = (
            None
            if row["registration_protocol_id"] is None
            else protocols.get(str(row["registration_protocol_id"]))
        )
        invocation = (
            None
            if row["invocation_protocol_id"] is None
            else protocols.get(str(row["invocation_protocol_id"]))
        )
        if (
            registration is None
            and row["registration_protocol_id"] is not None
        ) or (invocation is None and row["invocation_protocol_id"] is not None):
            raise CallProtocolError("callback protocol V3 references an absent checked call")
        registration_schema = (
            None
            if registration is None
            else schemas_by_sha256.get(registration.schema_sha256)
        )
        invocation_schema = (
            None
            if invocation is None
            else schemas_by_sha256.get(invocation.schema_sha256)
        )
        if (registration is not None and registration_schema is None) or (
            invocation is not None and invocation_schema is None
        ):
            raise CallProtocolError("callback protocol V3 schema is absent")
        instance = object_(row["instance"], "callback instance")
        exact(instance, {"kind", "paths"}, "callback instance")
        result = cls.create(
            action=str(row["action"]),
            registration_protocol=registration,
            invocation_protocol=invocation,
            registration_schema=registration_schema,
            invocation_schema=invocation_schema,
            source_path=row["source_path"],
            instance_kind=str(instance["kind"]),
            instance_paths=array(instance["paths"], "callback instance paths"),
            previous_disposition=str(row["previous_disposition"]),
            previous_result_path=row["previous_result_path"],
            lifetime=row["lifetime"],
            delivery=row["delivery"],
            cardinality=row["cardinality"],
            interaction_contract_id=str(row["interaction_contract_id"]),
            evidence_receipt_id=str(row["evidence_receipt_id"]),
        )
        if row["id"] != result.callback_id:
            raise CallProtocolError("callback protocol V3 id does not bind its contents")
        return result

    def to_payload(self) -> dict[str, object]:
        return {
            "format": CALLBACK_PROTOCOL_V3_FORMAT, "id": self.callback_id,
            "action": self.action,
            "registration_protocol_id": self.registration_protocol_id,
            "invocation_protocol_id": self.invocation_protocol_id,
            "source_path": None if self.source_path is None else self.source_path.to_payload(),
            "instance": {"kind": self.instance_kind, "paths": [item.to_payload() for item in self.instance_paths]},
            "previous_disposition": self.previous_disposition,
            "previous_result_path": None if self.previous_result_path is None else self.previous_result_path.to_payload(),
            "lifetime": self.lifetime.to_payload(), "delivery": self.delivery.to_payload(),
            "cardinality": self.cardinality.to_payload(),
            "interaction_contract_id": self.interaction_contract_id,
            "evidence_receipt_id": self.evidence_receipt_id,
        }


def _validate_signature_path(
    schema: BoundarySchemaV1, signature_id: str, path: BoundaryValuePathV1
) -> BoundaryTypeV1:
    signature = schema.signature_index[signature_id]
    values = (
        signature.parameters
        if path.root == "parameter"
        else signature.results
        if path.root == "result"
        else ()
    )
    value = next((item for item in values if item.identity == path.value_id), None)
    if value is None:
        raise CallProtocolError("callback path names an unknown checked call value")
    return resolve_field_path_type(
        schema, value.type_id, path.fields, context="callback path"
    )


__all__ = ["CallbackProtocolV3"]
