"""Canonical callback protocol contracts.

Callback protocols describe provider-owned registration state and delivery
constraints.  They intentionally do not describe a scheduler: invocation
start/end events and per-instance linearization are the observable model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .artifact_set import canonical_sha256_v3
from ..errors import ToolkitInputError


CALLBACK_PROTOCOL_FORMAT = "spaghetti-extractor-callback-protocol-v1"
CALLBACK_ACTIONS = frozenset({"register", "replace", "unregister", "invoke"})
CALLBACK_INSTANCE_KINDS = frozenset(
    {"singleton", "argument", "provider_resource", "registration_sequence"}
)
CALLBACK_LIFETIMES = frozenset(
    {
        "during_call",
        "one_shot_or_process_exit",
        "until_replaced_or_process_exit",
        "until_resource_event_or_process_exit",
    }
)
CALLBACK_DELIVERY_TIMINGS = frozenset({"nested", "deferred", "nested_or_deferred"})
CALLBACK_THREAD_RELATIONS = frozenset(
    {"same_thread", "provider_serialized", "external_concurrent"}
)
CALLBACK_RESULT_KINDS = frozenset({"void", "word"})
CALLBACK_SENTINEL_KINDS = frozenset({"null", "default", "ignore"})


def _error(context: str, message: str) -> ToolkitInputError:
    return ToolkitInputError(f"{context} {message}")


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _error(context, "must be an object")
    return value


def _exact(value: Mapping[str, Any], fields: set[str], context: str) -> None:
    if set(value) != fields:
        raise _error(
            context,
            f"fields differ: missing={sorted(fields-set(value))!r}, "
            f"extra={sorted(set(value)-fields)!r}",
        )


def _text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise _error(context, "must be a nonempty string")
    return value


def _u32(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFF_FFFF:
        raise _error(context, "must be an unsigned 32-bit integer")
    return value


@dataclass(frozen=True)
class CallbackSentinelV1:
    word: int
    kind: str

    def to_payload(self) -> dict[str, Any]:
        return {"word": self.word, "kind": self.kind}


@dataclass(frozen=True)
class CallbackSourceV1:
    kind: str
    argument: int
    offset: int
    sentinels: tuple[CallbackSentinelV1, ...]

    def to_payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "kind": self.kind,
            "argument": self.argument,
            "sentinels": [row.to_payload() for row in self.sentinels],
        }
        if self.kind == "argument_pointee":
            result["offset"] = self.offset
        return result


@dataclass(frozen=True)
class CallbackSignatureV1:
    abi_template: str
    argument_words: int
    stack_cleanup_bytes: int
    result_kind: str
    result_register: str | None

    def to_payload(self) -> dict[str, Any]:
        return {
            "abi_template": self.abi_template,
            "argument_words": self.argument_words,
            "stack_cleanup_bytes": self.stack_cleanup_bytes,
            "result": {
                "kind": self.result_kind,
                **(
                    {"register": self.result_register}
                    if self.result_register is not None
                    else {}
                ),
            },
        }


@dataclass(frozen=True)
class CallbackInstanceV1:
    kind: str
    argument: int | None = None
    callback_argument: int | None = None

    def to_payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {"kind": self.kind}
        if self.argument is not None:
            result["argument"] = self.argument
        if self.callback_argument is not None:
            result["callback_argument"] = self.callback_argument
        return result


@dataclass(frozen=True)
class CallbackLifetimeV1:
    kind: str
    end_event: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            **({"end_event": self.end_event} if self.end_event is not None else {}),
        }


@dataclass(frozen=True)
class CallbackDeliveryV1:
    timing: str
    thread: str

    def to_payload(self) -> dict[str, Any]:
        return {"timing": self.timing, "thread": self.thread}


@dataclass(frozen=True)
class CallbackCardinalityV1:
    minimum: int
    maximum: int | None
    scope: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "minimum": self.minimum,
            "maximum": self.maximum,
            "scope": self.scope,
        }


@dataclass(frozen=True)
class CallbackPreviousResultV1:
    register: str
    nullable: bool
    sentinels: tuple[CallbackSentinelV1, ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "register": self.register,
            "nullable": self.nullable,
            "sentinels": [row.to_payload() for row in self.sentinels],
        }


@dataclass(frozen=True)
class CallbackProtocolV1:
    protocol_id: str
    action: str
    source: CallbackSourceV1 | None
    signature: CallbackSignatureV1
    instance: CallbackInstanceV1
    previous_result: CallbackPreviousResultV1 | None
    lifetime: CallbackLifetimeV1
    delivery: CallbackDeliveryV1
    cardinality: CallbackCardinalityV1
    provider_behavior: Mapping[str, Any] | None = None

    @property
    def signature_sha256(self) -> str:
        return canonical_sha256_v3(self.signature.to_payload())

    @property
    def sha256(self) -> str:
        return canonical_sha256_v3(self.to_payload())

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": CALLBACK_PROTOCOL_FORMAT,
            "id": self.protocol_id,
            "action": self.action,
            "source": None if self.source is None else self.source.to_payload(),
            "signature": self.signature.to_payload(),
            "instance": self.instance.to_payload(),
            "previous_result": (
                None
                if self.previous_result is None
                else self.previous_result.to_payload()
            ),
            "lifetime": self.lifetime.to_payload(),
            "delivery": self.delivery.to_payload(),
            "cardinality": self.cardinality.to_payload(),
            "provider_behavior": (
                None
                if self.provider_behavior is None
                else dict(self.provider_behavior)
            ),
        }


def parse_callback_protocol(
    value: Any, *, registration_argument_words: int, context: str
) -> CallbackProtocolV1:
    row = _object(value, context)
    _exact(
        row,
        {
            "format", "id", "action", "source", "signature", "instance",
            "previous_result", "lifetime", "delivery", "cardinality",
            "provider_behavior",
        },
        context,
    )
    if row["format"] != CALLBACK_PROTOCOL_FORMAT:
        raise _error(context, "has an unsupported format")
    action = _text(row["action"], f"{context} action")
    if action not in CALLBACK_ACTIONS:
        raise _error(context, "has an unsupported action")
    source = _parse_source(
        row["source"], argument_words=registration_argument_words, context=context
    )
    if action in {"register", "replace"} and source is None:
        raise _error(context, "registration action requires a source")
    if action in {"unregister", "invoke"} and source is not None:
        raise _error(context, "non-registration action cannot declare a source")
    signature = _parse_signature(row["signature"], context=context)
    instance = _parse_instance(
        row["instance"],
        registration_argument_words=registration_argument_words,
        callback_argument_words=signature.argument_words,
        context=context,
    )
    previous = _parse_previous(row["previous_result"], context=context)
    if previous is not None and action != "replace":
        raise _error(context, "previous_result is valid only for replacement")
    lifetime = _parse_lifetime(row["lifetime"], context=context)
    delivery = _parse_delivery(row["delivery"], context=context)
    cardinality = _parse_cardinality(row["cardinality"], context=context)
    behavior = row["provider_behavior"]
    if behavior is not None:
        behavior = _parse_provider_behavior(
            behavior,
            registration_argument_words=registration_argument_words,
            callback_argument_words=signature.argument_words,
            instance=instance,
            context=context,
        )
    return CallbackProtocolV1(
        protocol_id=_text(row["id"], f"{context} id"),
        action=action,
        source=source,
        signature=signature,
        instance=instance,
        previous_result=previous,
        lifetime=lifetime,
        delivery=delivery,
        cardinality=cardinality,
        provider_behavior=behavior,
    )


def callback_protocol_from_contract(
    contract: Mapping[str, Any], *, argument_words: int, context: str
) -> CallbackProtocolV1 | None:
    value = contract.get("callback_protocol")
    if value is None:
        return None
    return parse_callback_protocol(
        value, registration_argument_words=argument_words, context=context
    )


def callback_protocol_from_machine_contract(
    contract: Mapping[str, Any], *, context: str
) -> CallbackProtocolV1 | None:
    words = contract.get("argument_words")
    if not isinstance(words, int) or isinstance(words, bool):
        arity = contract.get("arity")
        words = (
            arity.get("words")
            if isinstance(arity, Mapping) and arity.get("kind") == "fixed"
            else None
        )
    if not isinstance(words, int) or isinstance(words, bool):
        if contract.get("callback_protocol") is None:
            return None
        raise _error(context, "callback protocol has no fixed registration arity")
    return callback_protocol_from_contract(
        contract, argument_words=words, context=context
    )


def callback_lifetime_identity(protocol: CallbackProtocolV1) -> str:
    """Stable textual lifetime identity retained by callback target evidence."""

    end = protocol.lifetime.end_event
    return protocol.lifetime.kind if end is None else f"{protocol.lifetime.kind}:{end}"


def _parse_source(
    value: Any, *, argument_words: int, context: str
) -> CallbackSourceV1 | None:
    if value is None:
        return None
    row = _object(value, f"{context} source")
    kind = row.get("kind")
    fields = {"kind", "argument", "sentinels"}
    if kind == "argument_pointee":
        fields.add("offset")
    _exact(row, fields, f"{context} source")
    if kind not in {"argument_word", "argument_pointee"}:
        raise _error(context, "has an unsupported callback source")
    argument = _u32(row["argument"], f"{context} source argument")
    if argument >= argument_words:
        raise _error(context, "callback source argument is out of range")
    offset = _u32(row.get("offset", 0), f"{context} source offset")
    sentinels = _parse_sentinels(row["sentinels"], context=f"{context} source")
    return CallbackSourceV1(str(kind), argument, offset, sentinels)


def _parse_signature(value: Any, *, context: str) -> CallbackSignatureV1:
    row = _object(value, f"{context} signature")
    _exact(
        row,
        {"abi_template", "argument_words", "stack_cleanup_bytes", "result"},
        f"{context} signature",
    )
    abi = _text(row["abi_template"], f"{context} callback ABI")
    if abi not in {"pe32-cdecl-v1", "pe32-stdcall-v1"}:
        raise _error(context, "has an unsupported callback ABI")
    words = _u32(row["argument_words"], f"{context} callback argument count")
    if words > 64:
        raise _error(context, "callback argument count exceeds 64")
    cleanup = _u32(row["stack_cleanup_bytes"], f"{context} callback cleanup")
    if cleanup > 0xFFFF or cleanup % 4:
        raise _error(context, "callback cleanup is invalid")
    if (abi == "pe32-cdecl-v1" and cleanup != 0) or (
        abi == "pe32-stdcall-v1" and cleanup != words * 4
    ):
        raise _error(context, "callback cleanup contradicts its ABI")
    result = _object(row["result"], f"{context} callback result")
    kind = result.get("kind")
    _exact(
        result,
        {"kind"} if kind == "void" else {"kind", "register"},
        f"{context} callback result",
    )
    if kind not in CALLBACK_RESULT_KINDS:
        raise _error(context, "has an unsupported callback result")
    register = None if kind == "void" else _text(
        result["register"], f"{context} callback result register"
    ).lower()
    if register is not None and register not in {"eax", "edx"}:
        raise _error(context, "has an unsupported callback result register")
    return CallbackSignatureV1(abi, words, cleanup, str(kind), register)


def _parse_instance(
    value: Any,
    *,
    registration_argument_words: int,
    callback_argument_words: int,
    context: str,
) -> CallbackInstanceV1:
    row = _object(value, f"{context} instance")
    kind = row.get("kind")
    fields = {"kind"}
    if kind in {"argument", "provider_resource"}:
        fields.add("argument")
    if kind in {"argument", "provider_resource"} and "callback_argument" in row:
        fields.add("callback_argument")
    _exact(row, fields, f"{context} instance")
    if kind not in CALLBACK_INSTANCE_KINDS:
        raise _error(context, "has an unsupported instance policy")
    argument = None
    callback_argument = None
    if "argument" in row:
        argument = _u32(row["argument"], f"{context} instance argument")
        if argument >= registration_argument_words:
            raise _error(context, "instance argument is out of range")
    if kind == "provider_resource" and "callback_argument" not in row:
        raise _error(context, "provider-resource instance requires a callback argument")
    if "callback_argument" in row:
        callback_argument = _u32(
            row["callback_argument"], f"{context} callback instance argument"
        )
        if callback_argument >= callback_argument_words:
            raise _error(context, "callback instance argument is out of range")
    return CallbackInstanceV1(str(kind), argument, callback_argument)


def _parse_lifetime(value: Any, *, context: str) -> CallbackLifetimeV1:
    row = _object(value, f"{context} lifetime")
    kind = row.get("kind")
    fields = {"kind", "end_event"} if kind == "until_resource_event_or_process_exit" else {"kind"}
    _exact(row, fields, f"{context} lifetime")
    if kind not in CALLBACK_LIFETIMES:
        raise _error(context, "has an unsupported lifetime")
    end_event = None if "end_event" not in row else _text(
        row["end_event"], f"{context} lifetime end event"
    )
    return CallbackLifetimeV1(str(kind), end_event)


def _parse_delivery(value: Any, *, context: str) -> CallbackDeliveryV1:
    row = _object(value, f"{context} delivery")
    _exact(row, {"timing", "thread"}, f"{context} delivery")
    timing = row["timing"]
    thread = row["thread"]
    if timing not in CALLBACK_DELIVERY_TIMINGS or thread not in CALLBACK_THREAD_RELATIONS:
        raise _error(context, "has an unsupported delivery policy")
    if timing == "nested" and thread != "same_thread":
        raise _error(context, "nested delivery must be same-thread")
    return CallbackDeliveryV1(str(timing), str(thread))


def _parse_cardinality(value: Any, *, context: str) -> CallbackCardinalityV1:
    row = _object(value, f"{context} cardinality")
    _exact(row, {"minimum", "maximum", "scope"}, f"{context} cardinality")
    minimum = _u32(row["minimum"], f"{context} minimum cardinality")
    maximum_raw = row["maximum"]
    maximum = None if maximum_raw is None else _u32(
        maximum_raw, f"{context} maximum cardinality"
    )
    if maximum is not None and maximum < minimum:
        raise _error(context, "maximum cardinality is below minimum")
    if row["scope"] != "registration_generation":
        raise _error(context, "cardinality scope must be registration_generation")
    return CallbackCardinalityV1(minimum, maximum, "registration_generation")


def _parse_previous(value: Any, *, context: str) -> CallbackPreviousResultV1 | None:
    if value is None:
        return None
    row = _object(value, f"{context} previous result")
    _exact(row, {"register", "nullable", "sentinels"}, f"{context} previous result")
    register = _text(row["register"], f"{context} previous result register").lower()
    if register not in {"eax", "edx"} or not isinstance(row["nullable"], bool):
        raise _error(context, "has an invalid previous result")
    sentinels = _parse_sentinels(row["sentinels"], context=f"{context} previous result")
    return CallbackPreviousResultV1(register, bool(row["nullable"]), sentinels)


def _parse_sentinels(value: Any, *, context: str) -> tuple[CallbackSentinelV1, ...]:
    if not isinstance(value, list):
        raise _error(context, "sentinels must be a list")
    result: list[CallbackSentinelV1] = []
    for index, item in enumerate(value):
        row = _object(item, f"{context} sentinel {index}")
        _exact(row, {"word", "kind"}, f"{context} sentinel {index}")
        kind = row["kind"]
        if kind not in CALLBACK_SENTINEL_KINDS:
            raise _error(context, "has an unsupported sentinel kind")
        result.append(
            CallbackSentinelV1(
                _u32(row["word"], f"{context} sentinel word"), str(kind)
            )
        )
    if tuple(row.word for row in result) != tuple(sorted({row.word for row in result})):
        raise _error(context, "sentinels must be sorted and unique")
    return tuple(result)


def _parse_provider_behavior(
    value: Any,
    *,
    registration_argument_words: int,
    callback_argument_words: int,
    instance: CallbackInstanceV1,
    context: str,
) -> dict[str, Any]:
    row = _object(value, f"{context} provider behavior")
    if set(row) == {"instance_relation"}:
        if row["instance_relation"] != "registered_class_for_window":
            raise _error(context, "has an unsupported resource instance relation")
        if instance.kind != "provider_resource":
            raise _error(context, "resource instance relation requires provider_resource")
        return dict(row)
    _exact(
        row,
        {
            "kind", "provider_relation", "activation", "message_argument",
            "message_values", "resource_argument", "payload_arguments",
        },
        f"{context} provider behavior",
    )
    if (
        row["kind"] != "same_pinned_native_provider_v1"
        or row["provider_relation"] != "same_pinned_native_provider_v1"
        or instance.argument is None
        or instance.callback_argument is None
        or callback_argument_words == 0
        or registration_argument_words == 0
    ):
        raise _error(context, "has an unsupported provider behavior")
    activation = _object(row["activation"], f"{context} provider activation")
    _exact(
        activation,
        {"kind", "argument", "mask", "value"},
        f"{context} provider activation",
    )
    argument = _u32(activation["argument"], f"{context} activation argument")
    mask = _u32(activation["mask"], f"{context} activation mask")
    expected = _u32(activation["value"], f"{context} activation value")
    if (
        activation["kind"] != "masked_argument_equals"
        or argument >= registration_argument_words
        or mask == 0
        or expected & ~mask
    ):
        raise _error(context, "has an invalid provider activation")
    message_argument = _u32(
        row["message_argument"], f"{context} message argument"
    )
    resource_argument = _u32(
        row["resource_argument"], f"{context} resource argument"
    )
    raw_messages = row["message_values"]
    if not isinstance(raw_messages, list) or not raw_messages:
        raise _error(context, "provider message values must be nonempty")
    messages = tuple(
        _u32(item, f"{context} message value {index}")
        for index, item in enumerate(raw_messages)
    )
    if len(set(messages)) != len(messages):
        raise _error(context, "provider message values must be unique")
    raw_payloads = row["payload_arguments"]
    if not isinstance(raw_payloads, list):
        raise _error(context, "provider payload arguments must be an array")
    payloads = tuple(
        _u32(item, f"{context} payload argument {index}")
        for index, item in enumerate(raw_payloads)
    )
    classified = (
        resource_argument,
        message_argument,
        instance.callback_argument,
        *payloads,
    )
    if (
        any(item >= callback_argument_words for item in classified)
        or len(set(payloads)) != len(payloads)
        or len(set(classified)) != len(classified)
        or set(classified) != set(range(callback_argument_words))
    ):
        raise _error(context, "provider callback argument roles are not exact")
    return dict(row)


__all__ = [
    "CALLBACK_PROTOCOL_FORMAT",
    "CallbackCardinalityV1",
    "CallbackDeliveryV1",
    "CallbackInstanceV1",
    "CallbackLifetimeV1",
    "CallbackPreviousResultV1",
    "CallbackProtocolV1",
    "CallbackSentinelV1",
    "CallbackSignatureV1",
    "CallbackSourceV1",
    "callback_protocol_from_contract",
    "callback_protocol_from_machine_contract",
    "callback_lifetime_identity",
    "parse_callback_protocol",
]
