"""Typed callback registration and delivery protocols.

The invocation signature is a checked call protocol reference.  Registration
state is described here; argument widths, result registers, and stack cleanup
are deliberately absent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.formats import CALLBACK_PROTOCOL_V2_FORMAT
from ._canonical import CallProtocolError, array, content_id, exact, identifier, object_, text, uint
from .lifecycle import ValuePathV1
from .protocol import CheckedCallProtocolV1


CALLBACK_ACTIONS = frozenset({"register", "replace", "unregister", "invoke"})
INSTANCE_KINDS = frozenset({"singleton", "value", "provider_resource", "registration_sequence"})
LIFETIMES = frozenset({"during_call", "one_shot", "until_replaced", "until_resource_event", "until_process_exit"})
DELIVERY_TIMINGS = frozenset({"nested", "deferred", "nested_or_deferred"})
THREAD_RELATIONS = frozenset({"same_thread", "provider_serialized", "external_concurrent"})


@dataclass(frozen=True)
class CallbackDeliveryV2:
    timing: str
    thread_relation: str
    reentrancy: str

    @classmethod
    def parse(cls, value: object, context: str = "callback delivery") -> "CallbackDeliveryV2":
        row = object_(value, context)
        exact(row, {"timing", "thread_relation", "reentrancy"}, context)
        timing = text(row["timing"], f"{context} timing")
        thread = text(row["thread_relation"], f"{context} thread relation")
        reentrancy = text(row["reentrancy"], f"{context} reentrancy")
        if timing not in DELIVERY_TIMINGS or thread not in THREAD_RELATIONS or reentrancy not in {"forbidden", "allowed", "provider_serialized"}:
            raise CallProtocolError(f"{context} policy is unsupported")
        return cls(timing, thread, reentrancy)

    def to_payload(self) -> dict[str, object]:
        return {"timing": self.timing, "thread_relation": self.thread_relation, "reentrancy": self.reentrancy}


@dataclass(frozen=True)
class CallbackLifetimeV2:
    kind: str
    end_event: str | None

    @classmethod
    def parse(cls, value: object, context: str = "callback lifetime") -> "CallbackLifetimeV2":
        row = object_(value, context)
        exact(row, {"kind", "end_event"}, context)
        kind = text(row["kind"], f"{context} kind")
        if kind not in LIFETIMES:
            raise CallProtocolError(f"{context} kind is unsupported")
        event = None if row["end_event"] is None else identifier(row["end_event"], f"{context} end event")
        if kind == "until_resource_event" and event is None:
            raise CallProtocolError(f"{context} resource lifetime lacks an end event")
        if kind != "until_resource_event" and event is not None:
            raise CallProtocolError(f"{context} end event is valid only for resource lifetime")
        return cls(kind, event)

    def to_payload(self) -> dict[str, object]:
        return {"kind": self.kind, "end_event": self.end_event}


@dataclass(frozen=True)
class CallbackCardinalityV2:
    minimum: int
    maximum: int | None
    scope: str

    @classmethod
    def parse(cls, value: object, context: str = "callback cardinality") -> "CallbackCardinalityV2":
        row = object_(value, context)
        exact(row, {"minimum", "maximum", "scope"}, context)
        minimum = uint(row["minimum"], f"{context} minimum")
        maximum = None if row["maximum"] is None else uint(row["maximum"], f"{context} maximum")
        if maximum is not None and maximum < minimum:
            raise CallProtocolError(f"{context} maximum is below its minimum")
        return cls(minimum, maximum, identifier(row["scope"], f"{context} scope"))

    def to_payload(self) -> dict[str, object]:
        return {"minimum": self.minimum, "maximum": self.maximum, "scope": self.scope}


@dataclass(frozen=True)
class CallbackProtocolV2:
    callback_id: str
    action: str
    invocation_protocol_id: str
    source_path: ValuePathV1 | None
    instance_kind: str
    instance_paths: tuple[ValuePathV1, ...]
    previous_result_path: ValuePathV1 | None
    lifetime: CallbackLifetimeV2
    delivery: CallbackDeliveryV2
    cardinality: CallbackCardinalityV2
    interaction_contract_id: str

    @classmethod
    def create(
        cls,
        *,
        action: str,
        invocation_protocol: CheckedCallProtocolV1,
        source_path: ValuePathV1 | Mapping[str, object] | None,
        instance_kind: str,
        instance_paths: Sequence[ValuePathV1 | Mapping[str, object]],
        previous_result_path: ValuePathV1 | Mapping[str, object] | None,
        lifetime: CallbackLifetimeV2 | Mapping[str, object],
        delivery: CallbackDeliveryV2 | Mapping[str, object],
        cardinality: CallbackCardinalityV2 | Mapping[str, object],
        interaction_contract_id: str,
    ) -> "CallbackProtocolV2":
        if action not in CALLBACK_ACTIONS:
            raise CallProtocolError("callback action is unsupported")
        if invocation_protocol.status != "complete":
            raise CallProtocolError("callback invocation requires a complete checked call protocol")
        source = source_path if isinstance(source_path, ValuePathV1) else None if source_path is None else ValuePathV1.parse(source_path, "callback source path")
        if (action in {"register", "replace"}) != (source is not None):
            raise CallProtocolError("callback registration and source path disagree")
        if instance_kind not in INSTANCE_KINDS:
            raise CallProtocolError("callback instance kind is unsupported")
        instances = tuple(item if isinstance(item, ValuePathV1) else ValuePathV1.parse(item, f"callback instance path {index}") for index, item in enumerate(instance_paths))
        if instance_kind == "singleton" and instances:
            raise CallProtocolError("singleton callback instance cannot have key paths")
        if instance_kind != "singleton" and not instances:
            raise CallProtocolError("keyed callback instance lacks key paths")
        previous = previous_result_path if isinstance(previous_result_path, ValuePathV1) else None if previous_result_path is None else ValuePathV1.parse(previous_result_path, "callback previous-result path")
        if (action == "replace") != (previous is not None):
            raise CallProtocolError("callback replacement and previous-result path disagree")
        parsed_lifetime = lifetime if isinstance(lifetime, CallbackLifetimeV2) else CallbackLifetimeV2.parse(lifetime)
        parsed_delivery = delivery if isinstance(delivery, CallbackDeliveryV2) else CallbackDeliveryV2.parse(delivery)
        parsed_cardinality = cardinality if isinstance(cardinality, CallbackCardinalityV2) else CallbackCardinalityV2.parse(cardinality)
        core = {
            "format": CALLBACK_PROTOCOL_V2_FORMAT,
            "action": action,
            "invocation_protocol_id": invocation_protocol.protocol_id,
            "source_path": None if source is None else source.to_payload(),
            "instance": {"kind": instance_kind, "paths": [item.to_payload() for item in instances]},
            "previous_result_path": None if previous is None else previous.to_payload(),
            "lifetime": parsed_lifetime.to_payload(),
            "delivery": parsed_delivery.to_payload(),
            "cardinality": parsed_cardinality.to_payload(),
            "interaction_contract_id": identifier(interaction_contract_id, "callback interaction contract id"),
        }
        return cls(content_id("callback-protocol-v2", core), action, invocation_protocol.protocol_id, source, instance_kind, instances, previous, parsed_lifetime, parsed_delivery, parsed_cardinality, str(core["interaction_contract_id"]))

    @classmethod
    def parse(cls, value: object, *, protocols: Mapping[str, CheckedCallProtocolV1]) -> "CallbackProtocolV2":
        row = object_(value, "callback protocol")
        exact(row, {"format", "id", "action", "invocation_protocol_id", "source_path", "instance", "previous_result_path", "lifetime", "delivery", "cardinality", "interaction_contract_id"}, "callback protocol")
        if row["format"] != CALLBACK_PROTOCOL_V2_FORMAT:
            raise CallProtocolError("unsupported callback protocol format")
        protocol_id = identifier(row["invocation_protocol_id"], "callback invocation protocol id")
        invocation = protocols.get(protocol_id)
        if invocation is None:
            raise CallProtocolError("callback invocation protocol is absent from the checked registry")
        instance = object_(row["instance"], "callback instance")
        exact(instance, {"kind", "paths"}, "callback instance")
        result = cls.create(action=str(row["action"]), invocation_protocol=invocation, source_path=row["source_path"], instance_kind=str(instance["kind"]), instance_paths=array(instance["paths"], "callback instance paths"), previous_result_path=row["previous_result_path"], lifetime=row["lifetime"], delivery=row["delivery"], cardinality=row["cardinality"], interaction_contract_id=str(row["interaction_contract_id"]))
        if row["id"] != result.callback_id:
            raise CallProtocolError("callback protocol id does not bind its contents")
        return result

    def to_payload(self) -> dict[str, object]:
        return {
            "format": CALLBACK_PROTOCOL_V2_FORMAT,
            "id": self.callback_id,
            "action": self.action,
            "invocation_protocol_id": self.invocation_protocol_id,
            "source_path": None if self.source_path is None else self.source_path.to_payload(),
            "instance": {"kind": self.instance_kind, "paths": [item.to_payload() for item in self.instance_paths]},
            "previous_result_path": None if self.previous_result_path is None else self.previous_result_path.to_payload(),
            "lifetime": self.lifetime.to_payload(),
            "delivery": self.delivery.to_payload(),
            "cardinality": self.cardinality.to_payload(),
            "interaction_contract_id": self.interaction_contract_id,
        }


__all__ = ["CallbackProtocolV2"]
