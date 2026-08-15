"""Evaluate reviewed component adapter completion against concrete evidence."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol


class EvidenceCompletionError(ValueError):
    """A reviewed completion cannot be evaluated from checked evidence."""


class CompletionMemory(Protocol):
    def clone(self) -> "CompletionMemory": ...

    def write(self, address: int, width: int, value: int) -> None: ...


ExpressionEvaluator = Callable[[object, Mapping[str, int], CompletionMemory], int]


def evaluate_adapter_completion(
    adapter: Mapping[str, object],
    *,
    state_fields: Sequence[str],
    entry_state: Mapping[str, int],
    entry_memory: CompletionMemory,
    logical_result: int,
    result_id: str,
    external_result_values: Mapping[tuple[str, int, str], int],
    external_result_defined: frozenset[tuple[str, int, str]],
    evaluate_expression: ExpressionEvaluator,
) -> dict[str, object]:
    lowering = _object(adapter.get("lowering"), "component adapter lowering")
    if lowering.get("kind") != "checked-object-view-v1":
        raise EvidenceCompletionError(
            "logical-object-c-v1 evidence requires checked-object-view-v1 lowering"
        )
    completion = _object(
        lowering.get("completion"), "component adapter completion"
    )
    if completion.get("kind") != "explicit-machine-state-v1":
        raise EvidenceCompletionError(
            "logical-object-c-v1 adapter completion kind is unsupported"
        )
    state = _object(completion.get("state"), "component adapter completion state")
    if set(state) != set(state_fields):
        raise EvidenceCompletionError(
            "logical-object-c-v1 adapter completion state is not total"
        )

    def evaluate(value: object) -> int:
        transformed = _completion_machine_expr(
            value,
            state_fields=state_fields,
            entry_state=entry_state,
            logical_result=logical_result,
            result_id=result_id,
            external_result_values=external_result_values,
            external_result_defined=external_result_defined,
        )
        return evaluate_expression(transformed, {}, entry_memory)

    completed_state = {
        name: evaluate(state[name]) & 0xFFFFFFFF for name in state_fields
    }
    return_target = evaluate(completion.get("return_target"))
    memory = entry_memory.clone()
    pending_writes: list[tuple[int, int, int]] = []
    for raw in _array(
        completion.get("memory_writes"),
        "component adapter completion memory writes",
    ):
        write = _object(raw, "component adapter completion memory write")
        width = write.get("width")
        if width not in {1, 2, 4} or isinstance(width, bool):
            raise EvidenceCompletionError(
                "logical-object-c-v1 adapter completion memory-write width is unsupported"
            )
        pending_writes.append(
            (
                evaluate(write.get("address")) & 0xFFFFFFFF,
                int(width),
                evaluate(write.get("value")),
            )
        )
    for address, width, value in pending_writes:
        memory.write(address, width, value)
    return {
        "state": completed_state,
        "memory": memory,
        "return_target": return_target & 0xFFFFFFFF,
    }


def _completion_machine_expr(
    value: object,
    *,
    state_fields: Sequence[str],
    entry_state: Mapping[str, int],
    logical_result: int,
    result_id: str,
    external_result_values: Mapping[tuple[str, int, str], int],
    external_result_defined: frozenset[tuple[str, int, str]],
) -> Mapping[str, object]:
    expression = _object(value, "component adapter completion expression")
    op = expression.get("op")
    if op == "entry":
        name = expression.get("name")
        if not isinstance(name, str) or name not in state_fields:
            raise EvidenceCompletionError(
                f"adapter completion references unsupported entry state {name!r}"
            )
        return {"op": "const", "value": int(entry_state[name]), "width": 32}
    if op == "logical_result":
        if expression.get("result_id") != result_id:
            raise EvidenceCompletionError(
                "adapter completion references an unsupported logical result"
            )
        return {"op": "const", "value": logical_result, "width": 32}
    if op == "external_result":
        key = (
            expression.get("unit_id"),
            expression.get("event_index"),
            expression.get("register"),
        )
        if key not in external_result_values or key not in external_result_defined:
            raise EvidenceCompletionError(
                "adapter completion references an unavailable external result"
            )
        return {
            "op": "const",
            "value": int(external_result_values[key]),
            "width": 32,
        }
    transformed = copy.deepcopy(dict(expression))
    if isinstance(expression.get("address"), Mapping):
        transformed["address"] = _completion_machine_expr(
            expression["address"],
            state_fields=state_fields,
            entry_state=entry_state,
            logical_result=logical_result,
            result_id=result_id,
            external_result_values=external_result_values,
            external_result_defined=external_result_defined,
        )
    raw_args = expression.get("args", [])
    if not isinstance(raw_args, list):
        raise EvidenceCompletionError("adapter completion arguments are malformed")
    transformed["args"] = [
        _completion_machine_expr(
            argument,
            state_fields=state_fields,
            entry_state=entry_state,
            logical_result=logical_result,
            result_id=result_id,
            external_result_values=external_result_values,
            external_result_defined=external_result_defined,
        )
        if isinstance(argument, Mapping)
        else argument
        for argument in raw_args
    ]
    return transformed


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise EvidenceCompletionError(f"{description} must be an object")
    return value


def _array(value: object, description: str) -> list[object]:
    if not isinstance(value, list):
        raise EvidenceCompletionError(f"{description} must be an array")
    return value


__all__ = ["EvidenceCompletionError", "evaluate_adapter_completion"]
