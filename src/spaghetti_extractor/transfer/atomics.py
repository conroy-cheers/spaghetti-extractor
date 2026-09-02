"""Atomic action selection and lowering for executable transfers."""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from .model import TransferPlanError, _Action
from .values import _list, _object, _width


class _AtomicCompiler(Protocol):
    identity: str
    row: Mapping[str, Any]
    actions: list[_Action]
    scheduled_word_evaluations: set[int]
    consumed_atomic_action_ids: set[str]

    def word(self, raw: Any) -> int: ...


def atomic_action_for_rva(
    compiler: _AtomicCompiler, instruction_rva: int | None
) -> Mapping[str, Any] | None:
    if instruction_rva is None:
        return None
    graph = compiler.row.get("memory_actions")
    if graph is None:
        return None
    graph_object = _object(graph, f"{compiler.identity} memory action graph")
    raw_actions = _list(
        graph_object.get("actions"), f"{compiler.identity} memory actions"
    )
    matches = [
        _object(raw, f"{compiler.identity} memory action")
        for raw in raw_actions
        if isinstance(raw, Mapping)
        and raw.get("kind") == "rmw"
        and raw.get("instruction_rva") == instruction_rva
    ]
    if len(matches) > 1:
        raise TransferPlanError(
            f"{compiler.identity}: instruction has multiple RMW actions",
            code="malformed_memory_action_graph",
        )
    if not matches:
        return None
    identity = matches[0].get("id")
    if (
        not isinstance(identity, str)
        or identity in compiler.consumed_atomic_action_ids
    ):
        raise TransferPlanError(
            f"{compiler.identity}: RMW action identity is missing or repeated",
            code="malformed_memory_action_graph",
        )
    compiler.consumed_atomic_action_ids.add(identity)
    return matches[0]


def compile_atomic_action(
    compiler: _AtomicCompiler,
    action: Mapping[str, Any],
    ordered: list[Any],
) -> None:
    operation = action.get("operation")
    if operation not in {"compare_exchange", "exchange"}:
        raise TransferPlanError(
            f"{compiler.identity}: RMW operation {operation!r} has no exact backend",
            code="unsupported_atomic_rmw_lowering",
            next_action=(
                "add one direct backend primitive whose event graph is one matching RMW action"
            ),
        )
    memory_events = [
        event
        for event in ordered
        if isinstance(event, Mapping) and event.get("family") == "memory"
    ]
    if len(memory_events) != 2 or sorted(
        str(event.get("kind")) for event in memory_events
    ) != ["read", "write"]:
        raise TransferPlanError(
            f"{compiler.identity}: atomic RMW is not tied to one read and one write",
            code="malformed_memory_action_graph",
        )
    width = _width(action.get("width_bytes"))
    transition = _object(action.get("transition"), "atomic RMW transition")
    observed_expression = transition.get("observed")
    if operation == "compare_exchange":
        compare = _object(action.get("compare"), "compare/exchange observation")
        expected = compare.get("expected")
        desired = compare.get("desired")
    else:
        expected = None
        desired = transition.get("written")
    if desired is None or observed_expression is None or (
        operation == "compare_exchange" and expected is None
    ):
        raise TransferPlanError(
            f"{compiler.identity}: atomic RMW operands are incomplete",
            code="malformed_memory_action_graph",
        )
    address_node = compiler.word(action.get("address"))
    expected_node = (
        compiler.word(expected) if operation == "compare_exchange" else None
    )
    desired_node = compiler.word(desired)
    before = len(compiler.actions)
    observed_node = compiler.word(observed_expression)
    if (
        len(compiler.actions) != before + 1
        or compiler.actions[-1] != _Action("eval_word", (observed_node,))
    ):
        raise TransferPlanError(
            f"{compiler.identity}: atomic RMW observed value was already evaluated",
            code="atomic_observation_order_violation",
        )
    compiler.actions.pop()
    # The atomic runtime action materializes this node. This prevents later
    # register/flag expressions from issuing another load after the RMW.
    compiler.scheduled_word_evaluations.add(observed_node)
    if operation == "compare_exchange":
        assert expected_node is not None
        compiler.actions.append(
            _Action(
                "atomic_compare_exchange",
                (address_node, expected_node, desired_node, observed_node),
                width,
            )
        )
    else:
        compiler.actions.append(
            _Action(
                "atomic_exchange",
                (address_node, desired_node, observed_node),
                width,
            )
        )


__all__ = ["atomic_action_for_rva", "compile_atomic_action"]
