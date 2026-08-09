"""Typed callback-registration contracts shared by Stage A and Stage B."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .stage_binary import StageAInputError


@dataclass(frozen=True)
class CallbackSource:
    kind: str
    argument_index: int
    pointee_offset: int = 0

    def as_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "kind": self.kind,
            "argument": self.argument_index,
        }
        if self.kind == "argument_pointee":
            result["offset"] = self.pointee_offset
        return result

    def stack_argument_offset(self, argument_base_offset: int) -> int:
        return argument_base_offset + self.argument_index * 4


@dataclass(frozen=True)
class CallbackABI:
    kind: str
    argument_words: int
    stack_cleanup_bytes: int
    nullable: bool

    def as_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "argument_words": self.argument_words,
            "stack_cleanup_bytes": self.stack_cleanup_bytes,
            "nullable": self.nullable,
        }


@dataclass(frozen=True)
class CallbackResult:
    register: str
    origin: str
    nullable: bool

    def as_json(self) -> dict[str, Any]:
        return {
            "register": self.register,
            "origin": self.origin,
            "nullable": self.nullable,
        }


@dataclass(frozen=True)
class CallbackActivationGuard:
    argument_index: int
    mask: int
    value: int

    def as_json(self) -> dict[str, Any]:
        return {
            "kind": "masked_argument_equals",
            "argument": self.argument_index,
            "mask": self.mask,
            "value": self.value,
        }


@dataclass(frozen=True)
class NestedNativeCallbackBehavior:
    activation: CallbackActivationGuard
    message_argument: int
    message_values: tuple[int, ...]
    resource_argument: int
    instance_callback_argument: int
    instance_registration_argument: int
    payload_arguments: tuple[int, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "kind": "nested_native_callback_v1",
            "provider_relation": "same_pinned_native_provider_v1",
            "delivery": "during_call_or_until_lifetime_end",
            "activation": self.activation.as_json(),
            "message_argument": self.message_argument,
            "message_values": list(self.message_values),
            "resource_argument": self.resource_argument,
            "instance_binding": {
                "callback_argument": self.instance_callback_argument,
                "registration_argument": self.instance_registration_argument,
            },
            "payload_arguments": list(self.payload_arguments),
        }


def parse_callback_source(
    contract: Mapping[str, Any],
    *,
    argument_words: int,
    context: str,
) -> CallbackSource:
    """Parse the canonical source or one legacy direct-argument declaration."""

    raw_source = contract.get("callback_source")
    legacy_argument = contract.get("world_effect_argument")
    if raw_source is None:
        if argument_words == 0:
            raise StageAInputError(f"{context} callback argument is out of range")
        argument_index = _bounded_u32(
            legacy_argument,
            f"{context} callback argument",
            maximum=argument_words - 1,
        )
        parse_nested_native_callback_behavior(
            contract,
            registration_argument_words=argument_words,
            context=context,
        )
        return CallbackSource("argument_word", argument_index)
    if legacy_argument is not None:
        raise StageAInputError(
            f"{context} declares both callback_source and world_effect_argument"
        )
    if not isinstance(raw_source, Mapping):
        raise StageAInputError(f"{context} callback_source must be an object")
    kind = raw_source.get("kind")
    if kind == "argument_word":
        if set(raw_source) != {"kind", "argument"}:
            raise StageAInputError(
                f"{context} argument-word callback source has unknown fields"
            )
        pointee_offset = 0
    elif kind == "argument_pointee":
        if set(raw_source) != {"kind", "argument", "offset"}:
            raise StageAInputError(
                f"{context} argument-pointee callback source has unknown fields"
            )
        pointee_offset = _bounded_u32(
            raw_source.get("offset"),
            f"{context} callback pointee offset",
            maximum=0xFFFF,
        )
    else:
        raise StageAInputError(
            f"{context} callback source kind must be argument_word or argument_pointee"
        )
    if argument_words == 0:
        raise StageAInputError(f"{context} callback argument is out of range")
    argument_index = _bounded_u32(
        raw_source.get("argument"),
        f"{context} callback argument",
        maximum=argument_words - 1,
    )
    parse_nested_native_callback_behavior(
        contract,
        registration_argument_words=argument_words,
        context=context,
    )
    return CallbackSource(str(kind), argument_index, pointee_offset)


def parse_callback_abi(
    contract: Mapping[str, Any], *, context: str
) -> CallbackABI:
    raw = contract.get("callback_abi")
    if not isinstance(raw, Mapping) or set(raw) != {
        "kind",
        "argument_words",
        "stack_cleanup_bytes",
        "nullable",
    }:
        raise StageAInputError(f"{context} has no exact callback ABI")
    kind = raw.get("kind")
    argument_words = _bounded_u32(
        raw.get("argument_words"),
        f"{context} callback argument count",
        maximum=64,
    )
    stack_cleanup_bytes = _bounded_u32(
        raw.get("stack_cleanup_bytes"),
        f"{context} callback stack cleanup",
        maximum=0xFFFF,
    )
    nullable = raw.get("nullable")
    if kind != "generic_callback" or not isinstance(nullable, bool):
        raise StageAInputError(f"{context} has an invalid callback ABI")
    return CallbackABI(
        kind=str(kind),
        argument_words=argument_words,
        stack_cleanup_bytes=stack_cleanup_bytes,
        nullable=nullable,
    )


def parse_callback_result(
    contract: Mapping[str, Any], *, context: str
) -> CallbackResult | None:
    raw = contract.get("callback_result")
    if raw is None:
        return None
    if not isinstance(raw, Mapping) or set(raw) != {
        "register",
        "origin",
        "nullable",
    }:
        raise StageAInputError(f"{context} has an invalid callback result")
    register = raw.get("register")
    origin = raw.get("origin")
    nullable = raw.get("nullable")
    if (
        not isinstance(register, str)
        or register.lower()
        not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"}
        or origin != "previous_registered_callback"
        or not isinstance(nullable, bool)
    ):
        raise StageAInputError(f"{context} has an invalid callback result")
    return CallbackResult(register.lower(), str(origin), nullable)


def parse_nested_native_callback_behavior(
    contract: Mapping[str, Any],
    *,
    registration_argument_words: int,
    context: str,
) -> NestedNativeCallbackBehavior | None:
    """Validate a callback protocol supplied and invoked by one pinned provider."""

    raw = contract.get("callback_behavior")
    if raw is None or raw == "registration":
        return None
    expected_keys = {
        "kind",
        "provider_relation",
        "delivery",
        "activation",
        "message_argument",
        "message_values",
        "resource_argument",
        "instance_binding",
        "payload_arguments",
    }
    if not isinstance(raw, Mapping) or set(raw) != expected_keys:
        raise StageAInputError(
            f"{context} has an invalid nested native callback behavior"
        )
    if (
        raw.get("kind") != "nested_native_callback_v1"
        or raw.get("provider_relation") != "same_pinned_native_provider_v1"
        or raw.get("delivery") != "during_call_or_until_lifetime_end"
    ):
        raise StageAInputError(
            f"{context} has an unsupported nested native callback behavior"
        )

    callback_abi = contract.get("callback_abi")
    if not isinstance(callback_abi, Mapping):
        raise StageAInputError(f"{context} has no exact callback ABI")
    callback_argument_words = _bounded_u32(
        callback_abi.get("argument_words"),
        f"{context} callback argument count",
        maximum=64,
    )
    if callback_argument_words == 0:
        raise StageAInputError(
            f"{context} nested native callback must have arguments"
        )
    if registration_argument_words == 0:
        raise StageAInputError(
            f"{context} callback registration must have arguments"
        )

    activation = raw.get("activation")
    if not isinstance(activation, Mapping) or set(activation) != {
        "kind", "argument", "mask", "value",
    }:
        raise StageAInputError(
            f"{context} has an invalid callback activation guard"
        )
    activation_argument = _bounded_u32(
        activation.get("argument"),
        f"{context} callback activation argument",
        maximum=registration_argument_words - 1,
    )
    mask = _bounded_u32(
        activation.get("mask"),
        f"{context} callback activation mask",
        maximum=0xFFFF_FFFF,
    )
    value = _bounded_u32(
        activation.get("value"),
        f"{context} callback activation value",
        maximum=0xFFFF_FFFF,
    )
    if (
        activation.get("kind") != "masked_argument_equals"
        or mask == 0
        or value & ~mask
    ):
        raise StageAInputError(
            f"{context} has an invalid callback activation guard"
        )

    message_argument = _bounded_u32(
        raw.get("message_argument"),
        f"{context} callback message argument",
        maximum=callback_argument_words - 1,
    )
    resource_argument = _bounded_u32(
        raw.get("resource_argument"),
        f"{context} callback resource argument",
        maximum=callback_argument_words - 1,
    )
    raw_messages = raw.get("message_values")
    if not isinstance(raw_messages, list) or not raw_messages:
        raise StageAInputError(
            f"{context} callback message values must be a nonempty list"
        )
    message_values = tuple(
        _bounded_u32(
            item,
            f"{context} callback message value {index}",
            maximum=0xFFFF_FFFF,
        )
        for index, item in enumerate(raw_messages)
    )
    if len(set(message_values)) != len(message_values):
        raise StageAInputError(
            f"{context} callback message values must be unique"
        )

    instance = raw.get("instance_binding")
    if not isinstance(instance, Mapping) or set(instance) != {
        "callback_argument", "registration_argument",
    }:
        raise StageAInputError(
            f"{context} has an invalid callback instance binding"
        )
    instance_callback_argument = _bounded_u32(
        instance.get("callback_argument"),
        f"{context} callback instance argument",
        maximum=callback_argument_words - 1,
    )
    instance_registration_argument = _bounded_u32(
        instance.get("registration_argument"),
        f"{context} registration instance argument",
        maximum=registration_argument_words - 1,
    )

    raw_payloads = raw.get("payload_arguments")
    if not isinstance(raw_payloads, list):
        raise StageAInputError(
            f"{context} callback payload arguments must be a list"
        )
    payload_arguments = tuple(
        _bounded_u32(
            item,
            f"{context} callback payload argument {index}",
            maximum=callback_argument_words - 1,
        )
        for index, item in enumerate(raw_payloads)
    )
    classified_arguments = (
        resource_argument,
        message_argument,
        instance_callback_argument,
        *payload_arguments,
    )
    if (
        len(set(payload_arguments)) != len(payload_arguments)
        or len(set(classified_arguments)) != len(classified_arguments)
        or set(classified_arguments) != set(range(callback_argument_words))
    ):
        raise StageAInputError(
            f"{context} callback argument roles must classify every word exactly once"
        )

    return NestedNativeCallbackBehavior(
        activation=CallbackActivationGuard(
            activation_argument,
            mask,
            value,
        ),
        message_argument=message_argument,
        message_values=message_values,
        resource_argument=resource_argument,
        instance_callback_argument=instance_callback_argument,
        instance_registration_argument=instance_registration_argument,
        payload_arguments=payload_arguments,
    )


def _bounded_u32(value: Any, context: str, *, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= maximum
    ):
        raise StageAInputError(f"{context} must be between 0 and {maximum}")
    return value
