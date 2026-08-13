"""Bounded finite-value dataflow for machine-IR control expressions."""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
from typing import Any


FINITE_U32_DOMAIN_FORMAT = "stage-a-finite-u32-expression-domain-v1"

_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_REGISTER_INDEX = {name: index for index, name in enumerate(_REGISTERS)}
_Domain = frozenset[int] | None
_Residues = tuple[tuple[int, frozenset[int]], ...]
_Value = tuple[_Domain, _Residues]
_State = tuple[_Value, ...]
_TOP_VALUE: _Value = (None, ())


@dataclass(frozen=True)
class _Edge:
    target_id: str
    guard: Mapping[str, Any]


def _recovered_edge_inventory(
    recoveries: Sequence[Mapping[str, Any]],
    units: Mapping[str, Mapping[str, Any]],
) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    for recovery in recoveries:
        if (
            not isinstance(recovery, Mapping)
            or recovery.get("status") != "recovered"
        ):
            continue
        source_id = recovery.get("source_unit_id")
        raw_targets = recovery.get("target_unit_ids")
        if (
            not isinstance(source_id, str)
            or source_id not in units
            or not isinstance(raw_targets, Sequence)
            or isinstance(raw_targets, (str, bytes))
        ):
            continue
        result.update(
            (source_id, target_id)
            for raw_target in raw_targets
            if (target_id := str(raw_target)) in units
        )
    return result


class FiniteU32Dataflow:
    """One bounded, monotonically extensible machine-IR interpretation."""

    def __init__(
        self,
        *,
        units: Sequence[Mapping[str, Any]],
        roots: Sequence[str],
        recovered_indirect_targets: Sequence[Mapping[str, Any]] = (),
        max_values: int = 256,
        step_budget: int | None = None,
    ) -> None:
        if max_values <= 0:
            raise ValueError("max_values must be positive")
        self.max_values = max_values
        self._guard_constraints: dict[
            int,
            tuple[tuple[Mapping[str, Any], int, frozenset[int]], ...],
        ] = {}
        self._guard_domains: dict[tuple[int, int], _Domain] = {}
        self._units = {
            str(unit["id"]): unit
            for unit in units
            if isinstance(unit, Mapping) and isinstance(unit.get("id"), str)
        }
        by_rva: dict[int, list[str]] = {}
        for unit_id, unit in self._units.items():
            rva = _unit_start(unit)
            if rva is not None:
                by_rva.setdefault(rva, []).append(unit_id)
        self._outgoing: dict[str, list[_Edge]] = {
            unit_id: [] for unit_id in self._units
        }
        for source_id, unit in self._units.items():
            for target_rva in _direct_targets(unit):
                guard = _edge_guard(unit, target_rva)
                for target_id in sorted(by_rva.get(target_rva, [])):
                    self._outgoing[source_id].append(_Edge(target_id, guard))
            for target_rva in _internal_call_targets(unit):
                for target_id in sorted(by_rva.get(target_rva, [])):
                    self._outgoing[source_id].append(
                        _Edge(target_id, {"op": "true"})
                    )
        self._recovered_edges: set[tuple[str, str]] = set()
        self._add_recovered_edges(recovered_indirect_targets)
        for source_id, edges in self._outgoing.items():
            unique = {
                (edge.target_id, _canonical_json(edge.guard)): edge for edge in edges
            }
            self._outgoing[source_id] = [unique[key] for key in sorted(unique)]

        self._states: dict[str, _State] = {}
        work: deque[str] = deque()
        top = tuple(_TOP_VALUE for _register in _REGISTERS)
        for root in sorted(set(roots) & set(self._units)):
            self._states[root] = top
            work.append(root)
        self._step_budget = step_budget or max(1024, len(self._units) * 64)
        converged, steps = self._propagate(work)
        self.converged = converged
        self.steps = steps
        self.reached_units = len(self._states)

    def extend_recovered_indirect_targets(
        self,
        recoveries: Sequence[Mapping[str, Any]],
    ) -> bool:
        """Incrementally add a monotone checked finite-target inventory.

        Returning ``False`` asks the caller to reconstruct from a cold graph;
        no state is reused when a target disappears or a prior run exhausted
        its budget.
        """

        desired = _recovered_edge_inventory(recoveries, self._units)
        if not self.converged or not self._recovered_edges <= desired:
            return False
        additions = desired - self._recovered_edges
        if not additions:
            return True
        affected: set[str] = set()
        for source_id, target_id in sorted(additions):
            edge = _Edge(target_id, {"op": "true"})
            existing = {
                (item.target_id, _canonical_json(item.guard))
                for item in self._outgoing[source_id]
            }
            identity = (edge.target_id, _canonical_json(edge.guard))
            if identity not in existing:
                self._outgoing[source_id].append(edge)
                self._outgoing[source_id].sort(
                    key=lambda item: (
                        item.target_id,
                        _canonical_json(item.guard),
                    )
                )
                affected.add(source_id)
        self._recovered_edges = desired
        work = deque(
            source_id
            for source_id in sorted(affected)
            if source_id in self._states
        )
        converged, steps = self._propagate(work)
        self.converged = converged
        self.steps += steps
        self.reached_units = len(self._states)
        return converged

    def _add_recovered_edges(
        self,
        recoveries: Sequence[Mapping[str, Any]],
    ) -> None:
        self._recovered_edges = _recovered_edge_inventory(
            recoveries,
            self._units,
        )
        for source_id, target_id in sorted(self._recovered_edges):
            self._outgoing[source_id].append(
                _Edge(target_id, {"op": "true"})
            )

    def _propagate(self, work: deque[str]) -> tuple[bool, int]:
        queued = set(work)
        steps = 0
        converged = True
        while work:
            if steps >= self._step_budget:
                converged = False
                break
            source_id = work.popleft()
            queued.remove(source_id)
            source_state = self._states[source_id]
            source_unit = self._units[source_id]
            for edge in self._outgoing[source_id]:
                contribution = self._transfer(
                    source_unit,
                    source_state,
                    edge.guard,
                )
                if contribution is None:
                    continue
                joined = _join_states(
                    self._states.get(edge.target_id),
                    contribution,
                    self.max_values,
                )
                if joined != self._states.get(edge.target_id):
                    self._states[edge.target_id] = joined
                    if edge.target_id not in queued:
                        work.append(edge.target_id)
                        queued.add(edge.target_id)
            steps += 1
        return converged, steps

    def expression_domain(
        self, unit_id: str, expression: Mapping[str, Any]
    ) -> dict[str, Any]:
        expression_sha256 = sha256(
            _canonical_json(expression).encode("utf-8")
        ).hexdigest()
        state = self._states.get(unit_id)
        if not self.converged:
            return _incomplete_domain(
                unit_id,
                expression_sha256,
                self,
                "dataflow_budget_exhausted",
            )
        if state is None:
            return _incomplete_domain(
                unit_id,
                expression_sha256,
                self,
                "source_unit_unreached",
            )
        values = self._evaluate(expression, state, {"op": "true"})
        if values is None:
            return _incomplete_domain(
                unit_id,
                expression_sha256,
                self,
                "expression_domain_unbounded",
            )
        return {
            "format": FINITE_U32_DOMAIN_FORMAT,
            "status": "complete",
            "source_unit_id": unit_id,
            "expression_sha256": expression_sha256,
            "values": sorted(values),
            "value_count": len(values),
            "max_values": self.max_values,
            "analysis": {
                "converged": self.converged,
                "steps": self.steps,
                "reached_units": self.reached_units,
            },
            "failure": None,
        }

    def _transfer(
        self,
        unit: Mapping[str, Any],
        state: _State,
        guard: Mapping[str, Any],
    ) -> _State | None:
        semantics = unit.get("semantics")
        if not isinstance(semantics, Mapping):
            return tuple(_TOP_VALUE for _register in _REGISTERS)
        events = semantics.get("external_events")
        if (
            isinstance(events, Sequence)
            and not isinstance(events, (str, bytes))
            and any(
                not isinstance(event, Mapping)
                or event.get("kind") not in {"rep_movs", "rep_scas", "rep_stos"}
                for event in events
            )
        ):
            return tuple(_TOP_VALUE for _register in _REGISTERS)
        guard_id = id(guard)
        constraints = self._guard_constraints.get(guard_id)
        if constraints is None:
            constraints = tuple(
                _masked_expression_constraints(guard, self.max_values)
            )
            self._guard_constraints[guard_id] = constraints
        refined_state = _refine_state_with_constraints(
            state,
            constraints,
            self.max_values,
        )
        if refined_state is None:
            return None
        writes = {
            str(row.get("register")): row.get("value")
            for row in semantics.get("register_writes", [])
            if isinstance(row, Mapping)
            and str(row.get("register")) in _REGISTER_INDEX
            and isinstance(row.get("value"), Mapping)
        }
        result: list[_Value] = []
        for register in _REGISTERS:
            expression = writes.get(
                register,
                {"op": "reg", "name": register, "width": 32},
            )
            copied_register = _register_name(expression)
            inherited_residues = (
                refined_state[_REGISTER_INDEX[copied_register]][1]
                if copied_register is not None
                else ()
            )
            value = (
                self._evaluate(expression, refined_state, guard),
                inherited_residues,
            )
            result.append(
                _refine_value_with_constraints(
                    expression,
                    value,
                    constraints,
                    self.max_values,
                )
            )
        return tuple(result)

    def _evaluate(
        self,
        expression: Any,
        state: _State,
        guard: Mapping[str, Any],
    ) -> _Domain:
        if not isinstance(expression, Mapping):
            return None
        cache_key = (id(expression), id(guard))
        if cache_key in self._guard_domains:
            bounded = self._guard_domains[cache_key]
        else:
            bounded = _guard_domain(expression, guard, self.max_values)
            self._guard_domains[cache_key] = bounded
        if bounded is not None:
            return bounded
        op = str(expression.get("op", "")).lower()
        if op in {"const", "constant"}:
            value = expression.get("value")
            return (
                frozenset({int(value) & 0xFFFFFFFF})
                if isinstance(value, int) and not isinstance(value, bool)
                else None
            )
        if op in {"reg", "register", "input_reg"}:
            name = str(expression.get("name", expression.get("reg", ""))).lower()
            index = _REGISTER_INDEX.get(name)
            return state[index][0] if index is not None else None
        operands = _operands(expression)
        if op in {"and", "and32", "bit_and"} and operands is not None:
            mask = _constant_operand(operands)
            if mask is not None:
                masked = _masked_register_domain(operands, mask, state)
                if masked is not None:
                    return masked
                intrinsic = _submask_domain(mask, self.max_values)
                if intrinsic is not None:
                    finite = self._binary_values(op, operands, state, guard)
                    return intrinsic if finite is None else finite
        if operands is not None and op in {
            "and", "and32", "bit_and",
            "or", "or32", "bit_or",
            "xor", "xor32", "bit_xor",
            "add", "add32",
            "sub", "sub32",
            "mul", "mul32", "multiply",
            "lshr", "lshr32",
            "shl", "shl32",
        }:
            return self._binary_values(op, operands, state, guard)
        arguments = expression.get("args")
        if op in {"neg", "neg32"} and _sequence(arguments) and len(arguments) == 1:
            values = self._evaluate(arguments[0], state, guard)
            return (
                None
                if values is None
                else frozenset((-value) & 0xFFFFFFFF for value in values)
            )
        if (
            op in {"zero_extend", "zext", "truncate"}
            and _sequence(arguments)
            and len(arguments) == 1
        ):
            values = self._evaluate(arguments[0], state, guard)
            width = expression.get("width", expression.get("width_bits", 32))
            if values is None or not isinstance(width, int) or not 1 <= width <= 32:
                return None
            mask = (1 << width) - 1 if width < 32 else 0xFFFFFFFF
            return frozenset(value & mask for value in values)
        if op == "ite" and _sequence(arguments) and len(arguments) == 3:
            return _join_domains(
                self._evaluate(arguments[1], state, guard),
                self._evaluate(arguments[2], state, guard),
                self.max_values,
            )
        return None

    def _binary_values(
        self,
        op: str,
        operands: tuple[Any, Any],
        state: _State,
        guard: Mapping[str, Any],
    ) -> _Domain:
        left = self._evaluate(operands[0], state, guard)
        right = self._evaluate(operands[1], state, guard)
        canonical = {
            "and32": "and", "bit_and": "and",
            "or32": "or", "bit_or": "or",
            "xor32": "xor", "bit_xor": "xor",
            "add32": "add", "sub32": "sub",
            "mul32": "mul", "multiply": "mul",
            "lshr32": "lshr", "shl32": "shl",
        }.get(op, op)
        if canonical == "and" and (left is None or right is None):
            finite = right if left is None else left
            return _and_with_unknown_domain(finite, self.max_values)
        if left is None or right is None or len(left) * len(right) > self.max_values:
            return None
        operations = {
            "and": lambda a, b: a & b,
            "or": lambda a, b: a | b,
            "xor": lambda a, b: a ^ b,
            "add": lambda a, b: a + b,
            "sub": lambda a, b: a - b,
            "mul": lambda a, b: a * b,
            "lshr": lambda a, b: a >> (b & 31),
            "shl": lambda a, b: a << (b & 31),
        }
        operation = operations[canonical]
        values = {
            operation(first, second) & 0xFFFFFFFF
            for first in left
            for second in right
        }
        return frozenset(values) if len(values) <= self.max_values else None


def _incomplete_domain(
    unit_id: str,
    expression_sha256: str,
    analysis: FiniteU32Dataflow,
    code: str,
) -> dict[str, Any]:
    return {
        "format": FINITE_U32_DOMAIN_FORMAT,
        "status": "incomplete",
        "source_unit_id": unit_id,
        "expression_sha256": expression_sha256,
        "values": [],
        "value_count": 0,
        "max_values": analysis.max_values,
        "analysis": {
            "converged": analysis.converged,
            "steps": analysis.steps,
            "reached_units": analysis.reached_units,
        },
        "failure": {"code": code},
    }


def _join_states(existing: _State | None, incoming: _State, limit: int) -> _State:
    if existing is None:
        return incoming
    return tuple(
        _join_values(first, second, limit)
        for first, second in zip(existing, incoming, strict=True)
    )


def _join_values(first: _Value, second: _Value, limit: int) -> _Value:
    domain = _join_domains(first[0], second[0], limit)
    masks = {mask for mask, _values in first[1]} | {
        mask for mask, _values in second[1]
    }
    residues: list[tuple[int, frozenset[int]]] = []
    for mask in sorted(masks):
        left = _value_mask_domain(first, mask)
        right = _value_mask_domain(second, mask)
        if left is None or right is None:
            continue
        values = left | right
        if len(values) <= limit:
            residues.append((mask, values))
    return domain, tuple(residues)


def _join_domains(first: _Domain, second: _Domain, limit: int) -> _Domain:
    if first is None or second is None:
        return None
    values = first | second
    return values if len(values) <= limit else None


def _refine_state_with_constraints(
    state: _State,
    constraints: Sequence[tuple[Mapping[str, Any], int, frozenset[int]]],
    limit: int,
) -> _State | None:
    result = list(state)
    for expression, mask, allowed in constraints:
        register = _register_name(expression)
        if register is None:
            continue
        index = _REGISTER_INDEX[register]
        domain, raw_residues = result[index]
        current = _value_mask_domain(result[index], mask)
        if current is None:
            current = _submask_domain(mask, limit)
        if current is None:
            continue
        narrowed = current & allowed
        if not narrowed:
            return None
        if domain is not None:
            domain = frozenset(value for value in domain if value & mask in narrowed)
            if not domain:
                return None
        residues = dict(raw_residues)
        residues[mask] = narrowed
        result[index] = domain, tuple(sorted(residues.items()))
    return tuple(result)


def _refine_value_with_constraints(
    expression: Mapping[str, Any],
    value: _Value,
    constraints: Sequence[tuple[Mapping[str, Any], int, frozenset[int]]],
    limit: int,
) -> _Value:
    domain, raw_residues = value
    residues = dict(raw_residues)
    for guarded_expression, mask, allowed in constraints:
        if not _same_expression(expression, guarded_expression):
            continue
        current = _value_mask_domain((domain, tuple(residues.items())), mask)
        if current is None:
            current = _submask_domain(mask, limit)
        if current is None:
            continue
        narrowed = current & allowed
        if domain is not None:
            domain = frozenset(item for item in domain if item & mask in narrowed)
        residues[mask] = narrowed
    return domain, tuple(sorted(residues.items()))


def _masked_expression_constraints(
    guard: Mapping[str, Any],
    limit: int,
    *,
    polarity: bool = True,
) -> list[tuple[Mapping[str, Any], int, frozenset[int]]]:
    op = str(guard.get("op", "")).lower()
    arguments = guard.get("args")
    if op in {"not", "logical_not"} and _sequence(arguments) and len(arguments) == 1:
        child = arguments[0]
        return (
            _masked_expression_constraints(child, limit, polarity=not polarity)
            if isinstance(child, Mapping)
            else []
        )
    if op in {"and_bool", "logical_and"} and polarity and _sequence(arguments):
        result: list[tuple[Mapping[str, Any], int, frozenset[int]]] = []
        for child in arguments:
            if isinstance(child, Mapping):
                result.extend(_masked_expression_constraints(child, limit))
        return result
    if op not in {"eq", "eq32", "equal"}:
        return []
    operands = _operands(guard)
    if operands is None:
        return []
    for masked, constant in (operands, reversed(operands)):
        value = _constant_value(constant)
        shape = _masked_expression_shape(masked)
        if value is None or shape is None:
            continue
        expression, mask = shape
        possible = _submask_domain(mask, limit)
        if possible is None:
            return []
        selected = value & mask
        allowed = (
            frozenset({selected})
            if polarity
            else frozenset(possible - {selected})
        )
        return [(expression, mask, allowed)]
    return []


def _masked_register_domain(
    operands: tuple[Any, Any],
    mask: int,
    state: _State,
) -> _Domain:
    for register_expression, constant_expression in (operands, reversed(operands)):
        if _constant_value(constant_expression) != mask:
            continue
        register = _register_name(register_expression)
        if register is not None:
            return _value_mask_domain(state[_REGISTER_INDEX[register]], mask)
    return None


def _masked_expression_shape(
    expression: Any,
) -> tuple[Mapping[str, Any], int] | None:
    if (
        not isinstance(expression, Mapping)
        or str(expression.get("op", "")).lower()
        not in {"and", "and32", "bit_and"}
    ):
        return None
    operands = _operands(expression)
    if operands is None:
        return None
    for value_expression, constant_expression in (operands, reversed(operands)):
        mask = _constant_value(constant_expression)
        if isinstance(value_expression, Mapping) and mask is not None:
            return value_expression, mask & 0xFFFFFFFF
    return None


def _value_mask_domain(value: _Value, mask: int) -> _Domain:
    domain, residues = value
    if domain is not None:
        return frozenset(item & mask for item in domain)
    return dict(residues).get(mask)


def _register_name(expression: Any) -> str | None:
    if (
        not isinstance(expression, Mapping)
        or str(expression.get("op", "")).lower()
        not in {"reg", "register", "input_reg"}
    ):
        return None
    name = str(expression.get("name", expression.get("reg", ""))).lower()
    return name if name in _REGISTER_INDEX else None


def _guard_domain(
    expression: Mapping[str, Any],
    guard: Mapping[str, Any],
    limit: int,
) -> _Domain:
    op = str(guard.get("op", "")).lower()
    operands = _operands(guard)
    if op in {"and_bool", "logical_and"}:
        arguments = guard.get("args")
        if _sequence(arguments):
            for argument in arguments:
                if isinstance(argument, Mapping):
                    result = _guard_domain(expression, argument, limit)
                    if result is not None:
                        return result
        return None
    if operands is None:
        return None
    left, right = operands
    if op in {"ult", "ult32", "unsigned_less", "unsigned_lt"}:
        upper = _constant_value(right)
        if _same_expression(left, expression) and upper is not None and upper <= limit:
            return frozenset(range(upper))
    if op in {"ule", "ule32", "unsigned_less_equal", "unsigned_le"}:
        upper = _constant_value(right)
        if (
            _same_expression(left, expression)
            and upper is not None
            and upper < 0xFFFFFFFF
            and upper + 1 <= limit
        ):
            return frozenset(range(upper + 1))
    if op in {"eq", "eq32", "equal"}:
        for value_expression, constant_expression in ((left, right), (right, left)):
            value = _constant_value(constant_expression)
            if _same_expression(value_expression, expression) and value is not None:
                return frozenset({value & 0xFFFFFFFF})
    return None


@lru_cache(maxsize=4096)
def _submask_domain(mask: int, limit: int) -> _Domain:
    mask &= 0xFFFFFFFF
    bits = [index for index in range(32) if mask & (1 << index)]
    if len(bits) >= 32 or 1 << len(bits) > limit:
        return None
    return frozenset(
        sum(
            1 << bit
            for ordinal, bit in enumerate(bits)
            if subset & (1 << ordinal)
        )
        for subset in range(1 << len(bits))
    )


def _and_with_unknown_domain(finite: _Domain, limit: int) -> _Domain:
    if finite is None:
        return None
    result: set[int] = set()
    for value in finite:
        possible = _submask_domain(value, limit)
        if possible is None:
            return None
        result.update(possible)
        if len(result) > limit:
            return None
    return frozenset(result)


def _constant_operand(operands: tuple[Any, Any]) -> int | None:
    for operand in operands:
        value = _constant_value(operand)
        if value is not None:
            return value
    return None


def _constant_value(expression: Any) -> int | None:
    if (
        not isinstance(expression, Mapping)
        or str(expression.get("op", "")).lower()
        not in {"const", "constant"}
    ):
        return None
    value = expression.get("value")
    return (
        int(value)
        if isinstance(value, int) and not isinstance(value, bool)
        else None
    )


def _operands(expression: Mapping[str, Any]) -> tuple[Any, Any] | None:
    if "left" in expression and "right" in expression:
        return expression["left"], expression["right"]
    arguments = expression.get("args")
    return (
        (arguments[0], arguments[1])
        if _sequence(arguments) and len(arguments) == 2
        else None
    )


def _sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes))


def _unit_start(unit: Mapping[str, Any]) -> int | None:
    source = unit.get("source")
    original = source.get("original") if isinstance(source, Mapping) else None
    value = original.get("rva_start") if isinstance(original, Mapping) else None
    return (
        int(value)
        if isinstance(value, int) and not isinstance(value, bool)
        else None
    )


def _direct_targets(unit: Mapping[str, Any]) -> tuple[int, ...]:
    control = unit.get("control")
    raw = control.get("direct_targets") if isinstance(control, Mapping) else None
    if not _sequence(raw):
        return ()
    return tuple(
        int(value)
        for value in raw
        if isinstance(value, int) and not isinstance(value, bool)
    )


def _internal_call_targets(unit: Mapping[str, Any]) -> tuple[int, ...]:
    semantics = unit.get("semantics")
    events = (
        semantics.get("external_events")
        if isinstance(semantics, Mapping)
        else None
    )
    if not _sequence(events):
        return ()
    return tuple(sorted({
        int(event["target_rva"])
        for event in events
        if isinstance(event, Mapping)
        and event.get("kind") == "internal_call"
        and isinstance(event.get("target_rva"), int)
        and not isinstance(event.get("target_rva"), bool)
    }))


def _edge_guard(unit: Mapping[str, Any], target_rva: int) -> Mapping[str, Any]:
    semantics = unit.get("semantics")
    edges = semantics.get("edge_conditions") if isinstance(semantics, Mapping) else None
    if _sequence(edges):
        for edge in edges:
            if isinstance(edge, Mapping) and edge.get("target_rva") == target_rva:
                condition = edge.get("condition")
                if isinstance(condition, Mapping):
                    return condition
    return {"op": "true"}


def _same_expression(first: Any, second: Any) -> bool:
    return _canonical_json(first) == _canonical_json(second)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


__all__ = ["FINITE_U32_DOMAIN_FORMAT", "FiniteU32Dataflow"]
