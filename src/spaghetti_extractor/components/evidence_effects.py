"""Checked machine-effect execution used by component evidence."""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, MutableSet, Sequence
from dataclasses import dataclass
from typing import Protocol

from ..external.contracts import (
    CheckedExternalSiteContract,
    CheckedExternalSiteContractError,
    parse_checked_external_site_contract,
)
from .external_models import (
    ExternalCallEvaluation,
    ExternalEvidenceModelError,
    evaluate_checked_external_call,
)


class EvidenceEffectError(ValueError):
    """A machine effect cannot be evaluated from checked evidence."""


class EvidenceMemory(Protocol):
    def read(self, address: int, width: int) -> int: ...

    def write(self, address: int, width: int, value: int) -> None: ...


ExpressionEvaluator = Callable[[object, Mapping[str, int], EvidenceMemory], int]


@dataclass(frozen=True)
class ExecutedExternalCall:
    unit_id: str
    event_index: int
    evaluation: ExternalCallEvaluation


def execute_ordered_effects(
    *,
    unit_id: str,
    semantics: Mapping[str, object],
    state: MutableMapping[str, int],
    defined_fields: MutableSet[str],
    memory: EvidenceMemory,
    external_contracts: Mapping[tuple[str, int], CheckedExternalSiteContract],
    evaluate_expression: ExpressionEvaluator,
) -> tuple[ExecutedExternalCall, ...]:
    ordered = _array(semantics.get("ordered_events", []), "ordered events")
    if not ordered:
        ordered = [
            {"family": "memory", **dict(_object(row, "memory event"))}
            for row in _array(semantics.get("memory_events", []), "memory events")
        ] + [
            {"family": "external", **dict(_object(row, "external event"))}
            for row in _array(semantics.get("external_events", []), "external events")
        ]
    external_index = 0
    executed_calls: list[ExecutedExternalCall] = []
    for raw_event in ordered:
        event = _object(raw_event, "ordered machine event")
        family = event.get("family")
        if family == "memory":
            if not expression_is_defined(event.get("address"), defined_fields):
                raise EvidenceEffectError(
                    "machine memory address depends on undefined state"
                )
            address = evaluate_expression(event.get("address"), state, memory)
            width = int(event.get("width", 4))
            if event.get("kind") == "read":
                memory.read(address, width)
            elif event.get("kind") == "write":
                if not expression_is_defined(event.get("value"), defined_fields):
                    raise EvidenceEffectError(
                        "machine memory write depends on undefined state"
                    )
                memory.write(
                    address,
                    width,
                    evaluate_expression(event.get("value"), state, memory),
                )
            else:
                raise EvidenceEffectError("machine memory event kind is unsupported")
            continue
        if family != "external":
            raise EvidenceEffectError(
                f"ordered machine event family {family!r} is unsupported"
            )
        contract = external_contracts.get((unit_id, external_index))
        if contract is None:
            raise EvidenceEffectError(
                "external component event has no checked adapter contract"
            )
        if any(
            not expression_is_defined(argument, defined_fields)
            for argument in contract.arguments
        ):
            raise EvidenceEffectError(
                "external component arguments depend on undefined state"
            )
        arguments = [
            evaluate_expression(argument, state, memory)
            for argument in contract.arguments
        ]
        try:
            response = evaluate_checked_external_call(
                contract, arguments, state, memory.read
            )
        except ExternalEvidenceModelError as exc:
            raise EvidenceEffectError(str(exc)) from exc
        for register, value in response.register_values.items():
            key = call_register_key(external_index, register)
            state[key] = int(value) & 0xFFFFFFFF
            _set_defined(
                defined_fields, key, register in response.defined_registers
            )
        for flag, value in response.flag_values.items():
            key = call_flag_key(external_index, flag)
            state[key] = int(value) & 1
            _set_defined(defined_fields, key, flag in response.defined_flags)
        executed_calls.append(
            ExecutedExternalCall(
                unit_id=unit_id,
                event_index=external_index,
                evaluation=response,
            )
        )
        external_index += 1
    return tuple(executed_calls)


def parse_adapter_external_contracts(
    adapter: Mapping[str, object],
) -> dict[tuple[str, int], CheckedExternalSiteContract]:
    lowering = _object(adapter.get("lowering"), "component adapter lowering")
    result: dict[tuple[str, int], CheckedExternalSiteContract] = {}
    for raw in _array(
        lowering.get("external_calls", []), "component adapter external calls"
    ):
        row = _object(raw, "component adapter external call")
        unit_id = _string(row.get("unit_id"), "component external-call unit")
        event_index = row.get("event_index")
        contract_payload = row.get("contract")
        if (
            not isinstance(event_index, int)
            or isinstance(event_index, bool)
            or event_index < 0
            or not isinstance(contract_payload, Mapping)
        ):
            raise EvidenceEffectError(
                "component adapter external-call record is malformed"
            )
        try:
            contract = parse_checked_external_site_contract(
                contract_payload,
                context=f"component adapter call {unit_id}:{event_index}",
            )
        except CheckedExternalSiteContractError as exc:
            raise EvidenceEffectError(str(exc)) from exc
        key = (unit_id, event_index)
        if key in result:
            raise EvidenceEffectError(
                "component adapter external-call record is duplicated"
            )
        result[key] = contract
    return result


def expression_is_defined(value: object, defined_fields: Sequence[str]) -> bool:
    if not isinstance(value, Mapping):
        return isinstance(value, (int, bool))
    op = value.get("op")
    if op in {"const", "false", "true"}:
        return True
    if op in {"reg", "flag"}:
        name = value.get("name")
        return isinstance(name, str) and name in defined_fields
    if op == "call_response":
        register = value.get("register")
        call_index = value.get("call_index")
        return (
            isinstance(register, str)
            and isinstance(call_index, int)
            and not isinstance(call_index, bool)
            and call_register_key(call_index, register) in defined_fields
        )
    if op == "call_flag":
        flag = value.get("flag")
        call_index = value.get("call_index")
        return (
            isinstance(flag, str)
            and isinstance(call_index, int)
            and not isinstance(call_index, bool)
            and call_flag_key(call_index, flag) in defined_fields
        )
    if op == "load" and not expression_is_defined(
        value.get("address"), defined_fields
    ):
        return False
    raw_args = value.get("args", [])
    return isinstance(raw_args, list) and all(
        expression_is_defined(argument, defined_fields) for argument in raw_args
    )


def call_register_key(call_index: int, register: str) -> str:
    return f"@call:{call_index}:register:{register.lower()}"


def call_flag_key(call_index: int, flag: str) -> str:
    return f"@call:{call_index}:flag:{flag.lower()}"


def _set_defined(fields: MutableSet[str], name: str, value: bool) -> None:
    if value:
        fields.add(name)
    else:
        fields.discard(name)


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise EvidenceEffectError(f"{description} must be an object")
    return value


def _array(value: object, description: str) -> list[object]:
    if not isinstance(value, list):
        raise EvidenceEffectError(f"{description} must be an array")
    return value


def _string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceEffectError(f"{description} must be a nonempty string")
    return value


__all__ = [
    "EvidenceEffectError",
    "ExecutedExternalCall",
    "call_flag_key",
    "call_register_key",
    "execute_ordered_effects",
    "expression_is_defined",
    "parse_adapter_external_contracts",
]
