"""Exact local PE32 stack-argument recovery from ordered machine effects."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


CALL_ARGUMENT_RECOVERY_FORMAT = "stage-a-pe32-call-argument-recovery-v1"
_CALL_KINDS = frozenset({"external_call", "indirect_call", "internal_call"})


@dataclass(frozen=True)
class CallArgumentRecovery:
    status: str
    arguments: tuple[Any, ...]
    evidence: tuple[Mapping[str, Any], ...]
    failure_code: str | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "format": CALL_ARGUMENT_RECOVERY_FORMAT,
            "status": self.status,
            "proof_authority": False,
            "required_replay": (
                "Lean must replay ordered writes and the exact call-time ESP expression"
            ),
            "arguments": [copy.deepcopy(value) for value in self.arguments],
            "evidence": [copy.deepcopy(dict(value)) for value in self.evidence],
            "failure": (
                None
                if self.failure_code is None
                else {"code": self.failure_code}
            ),
        }


def recover_pe32_stack_call_arguments(
    unit: Mapping[str, Any],
    *,
    event_index: int,
    argument_words: int,
) -> CallArgumentRecovery:
    """Recover arguments written in the same exact ordered-effect unit.

    This is deliberately local.  Arguments prepared in predecessor units are
    left incomplete until an inter-unit stack witness is available.
    """

    if (
        not isinstance(event_index, int)
        or isinstance(event_index, bool)
        or event_index < 0
        or not isinstance(argument_words, int)
        or isinstance(argument_words, bool)
        or not 0 <= argument_words <= 64
    ):
        raise ValueError("call argument recovery indices are out of range")
    semantics = _mapping(unit.get("semantics"))
    events = semantics.get("external_events")
    ordered = semantics.get("ordered_events")
    if not isinstance(events, list) or not 0 <= event_index < len(events):
        return _failure("missing_call_event")
    if not isinstance(ordered, list):
        return _failure("missing_ordered_effects")
    desired = _mapping(events[event_index])
    if desired.get("kind") not in _CALL_KINDS:
        return _failure("selected_event_is_not_call")
    register_inputs = _mapping(desired.get("register_inputs"))
    call_esp = _affine_esp(register_inputs.get("esp"))
    if call_esp is None:
        return _failure("call_esp_not_affine")

    stack_writes: dict[int, tuple[Any, dict[str, Any]]] = {}
    observed_call_index = -1
    selected = False
    for ordered_index, raw in enumerate(ordered):
        event = _mapping(raw)
        kind = event.get("kind")
        if kind in _CALL_KINDS:
            observed_call_index += 1
            if observed_call_index == event_index:
                if not _same_call(desired, event):
                    return _failure("ordered_call_identity_mismatch")
                selected = True
                break
            continue
        if kind != "write":
            continue
        width = event.get("width")
        offset = _affine_esp(event.get("address"))
        if width != 4 or offset is None:
            return _failure("non_affine_pre_call_memory_write")
        stack_writes[offset] = (
            copy.deepcopy(event.get("value")),
            {
                "ordered_event_index": ordered_index,
                "instruction_rva": event.get("instruction_rva"),
                "stack_offset_from_unit_input": offset,
                "width": 4,
            },
        )
    if not selected:
        return _failure("ordered_call_missing")

    arguments: list[Any] = []
    evidence: list[Mapping[str, Any]] = []
    for argument_index in range(argument_words):
        offset = call_esp + argument_index * 4
        recovered = stack_writes.get(offset)
        if recovered is None:
            return _failure("argument_write_missing")
        value, witness = recovered
        arguments.append(value)
        evidence.append({
            **witness,
            "argument_index": argument_index,
            "call_esp_offset": call_esp,
        })
    return CallArgumentRecovery(
        status="complete",
        arguments=tuple(arguments),
        evidence=tuple(evidence),
    )


def _failure(code: str) -> CallArgumentRecovery:
    return CallArgumentRecovery(
        status="incomplete",
        arguments=(),
        evidence=(),
        failure_code=code,
    )


def _affine_esp(expression: Any) -> int | None:
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op") or "").lower()
    if op in {"reg", "input_reg", "register"}:
        name = expression.get("name", expression.get("reg"))
        return 0 if isinstance(name, str) and name.lower() == "esp" else None
    if op not in {"add", "add32", "sub", "sub32"}:
        return None
    operands = _binary_operands(expression)
    if operands is None:
        return None
    left_esp = _affine_esp(operands[0])
    right_esp = _affine_esp(operands[1])
    left_const = _constant(operands[0])
    right_const = _constant(operands[1])
    if left_esp is not None and right_const is not None:
        return (
            left_esp - right_const
            if op in {"sub", "sub32"}
            else left_esp + right_const
        )
    if op in {"add", "add32"} and left_const is not None and right_esp is not None:
        return left_const + right_esp
    return None


def _constant(expression: Any) -> int | None:
    if not isinstance(expression, Mapping):
        return None
    if str(expression.get("op") or "").lower() not in {"const", "constant"}:
        return None
    value = expression.get("value")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _binary_operands(expression: Mapping[str, Any]) -> tuple[Any, Any] | None:
    arguments = expression.get("args")
    if (
        isinstance(arguments, Sequence)
        and not isinstance(arguments, (str, bytes))
        and len(arguments) == 2
    ):
        return arguments[0], arguments[1]
    if "left" in expression and "right" in expression:
        return expression["left"], expression["right"]
    return None


def _same_call(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return all(
        left.get(field) == right.get(field)
        for field in ("kind", "dll", "symbol", "ordinal", "return_rva")
    )


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


__all__ = [
    "CALL_ARGUMENT_RECOVERY_FORMAT",
    "CallArgumentRecovery",
    "recover_pe32_stack_call_arguments",
]
