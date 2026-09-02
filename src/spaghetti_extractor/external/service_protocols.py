"""Checked protocols for external services that are not ordinary calls.

The machine-import profile remains the authority for physical ABI.  This
small codec describes the additional runtime transduction required when the
native API observes guest control or nested exception objects.  It is carried
through the existing external-environment contract; it is not an executable
backend and it never grants a runtime implementation by itself.
"""

from __future__ import annotations

import copy
from typing import Any, Mapping

from ..errors import ToolkitInputError
from .formats import CHECKED_EXTERNAL_SERVICE_PROTOCOL_FORMAT


class CheckedExternalServiceProtocolError(ToolkitInputError):
    """An external-service protocol is malformed or fail-open."""


def _fail(message: str) -> None:
    raise CheckedExternalServiceProtocolError(message)


def _argument(value: object, *, words: int, context: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value < words
    ):
        _fail(f"{context} is outside the checked physical frame")
    return int(value)


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{context} must be nonempty text")
    return value


def parse_checked_external_service_protocol_v1(
    value: object, *, argument_words: int, context: str
) -> dict[str, Any] | None:
    """Parse the closed external-service inventory used by PE32 profiles."""

    if value is None:
        return None
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    if value.get("format") != CHECKED_EXTERNAL_SERVICE_PROTOCOL_FORMAT:
        _fail(f"{context} has an unsupported format")
    protocol_id = _text(value.get("id"), f"{context} ID")
    kind = value.get("kind")
    arguments = value.get("arguments")
    behavior = value.get("behavior")
    if not isinstance(arguments, Mapping) or not isinstance(behavior, Mapping):
        _fail(f"{context} has no exact argument and behavior contracts")

    if kind == "nonlocal_unwind":
        if set(value) != {"format", "id", "kind", "arguments", "behavior"}:
            _fail(f"{context} nonlocal-unwind fields are incomplete")
        expected_arguments = {
            "target_frame", "target_instruction", "exception_record",
            "return_value",
        }
        expected_behavior = {
            "frame_selection": "registered_seh_ancestor",
            "target_selection": "checked_guest_code_capability",
            "exception_record": "nullable_checked_exception_record",
            "return_value": "eax_word",
            "unwind": "x86_seh_unwind",
            "abandoned_lifetimes": "invalidate",
            "outcome": "nonlocal",
        }
        if set(arguments) != expected_arguments or behavior != expected_behavior:
            _fail(f"{context} nonlocal-unwind contract is unsupported")
        indexes = {
            name: _argument(
                arguments[name], words=argument_words,
                context=f"{context} {name} argument",
            )
            for name in sorted(expected_arguments)
        }
        if len(set(indexes.values())) != len(indexes):
            _fail(f"{context} nonlocal-unwind arguments are ambiguous")
    elif kind == "unhandled_exception_filter":
        if set(value) != {
            "format", "id", "kind", "arguments", "behavior",
            "object_view", "registered_filter",
        }:
            _fail(f"{context} exception-filter fields are incomplete")
        if set(arguments) != {"exception_pointers"}:
            _fail(f"{context} exception-filter argument contract is incomplete")
        _argument(
            arguments["exception_pointers"], words=argument_words,
            context=f"{context} exception-pointers argument",
        )
        if behavior != {
            "active_filter": "invoke_once_on_same_thread",
            "fallback": "loader_owned_unhandled_exception_policy",
            "outcome": "normal",
        }:
            _fail(f"{context} exception-filter behavior is unsupported")
        object_view = value.get("object_view")
        if not isinstance(object_view, Mapping) or object_view != {
            "kind": "win32_exception_pointers_v1",
            "size_bytes": 8,
            "exception_record_pointer_offset": 0,
            "context_pointer_offset": 4,
            "exception_record_view": "checked_exception_record_v1",
            "context_view": "x86_context_v1",
            "root_access": "read",
            "referent_access": "read_write",
            "lifetime": "during_call",
        }:
            _fail(f"{context} exception-pointers view is unsupported")
        registered = value.get("registered_filter")
        if not isinstance(registered, Mapping) or set(registered) != {
            "protocol_id", "absence", "result_register",
        } or registered.get("absence") != "host_fallback" or registered.get(
            "result_register"
        ) != "eax":
            _fail(f"{context} registered-filter relation is unsupported")
        _text(
            registered.get("protocol_id"),
            f"{context} registered-filter protocol ID",
        )
    else:
        _fail(f"{context} kind {kind!r} is unsupported")

    # Copy only after the complete closed validation above so callers can
    # safely content-bind and serialize the returned value.
    result = copy.deepcopy(dict(value))
    result["id"] = protocol_id
    return result


def external_service_outcomes_v1(value: object) -> tuple[str, ...]:
    """Project one parsed service onto the physical-frame outcome inventory."""

    if value is None:
        return ()
    if not isinstance(value, Mapping) or not isinstance(
        value.get("behavior"), Mapping
    ):
        _fail("checked external-service protocol is malformed")
    outcome = value["behavior"].get("outcome")
    if outcome not in {"normal", "nonlocal"}:
        _fail("checked external-service outcome is unsupported")
    return (str(outcome),)


__all__ = [
    "CheckedExternalServiceProtocolError",
    "external_service_outcomes_v1",
    "parse_checked_external_service_protocol_v1",
]
