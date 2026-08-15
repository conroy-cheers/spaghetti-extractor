"""Checked normalization of unit-local expressions to component entry state.

Machine-IR summaries describe expressions relative to each unit's pre-state.
Component adapters execute at the component entry, so a later unit's expression
cannot be consumed directly.  This module follows one finite direct prefix,
substitutes register and flag state, and forwards exact memory writes.  Any
branch, external event, or possible alias that prevents an exact rewrite fails
closed.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_FLAGS = ("cf", "zf", "sf", "of", "pf", "df")
_WORD_MASK = 0xFFFFFFFF


@dataclass(frozen=True)
class _Write:
    address: object
    width: int
    value: object


class _IncompleteNormalization(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def normalize_unit_expression_to_component_entry(
    units: Sequence[Mapping[str, Any]],
    *,
    entry_unit_id: str,
    target_unit_id: str,
    expression: object,
    target_memory_event_count: int = 0,
) -> dict[str, Any]:
    """Rewrite ``expression`` from target-unit state to component-entry state."""

    try:
        prefix = _direct_prefix(
            units,
            entry_unit_id=entry_unit_id,
            target_unit_id=target_unit_id,
        )
        registers: dict[str, object] = {
            name: {"op": "reg", "name": name, "width": 32}
            for name in _REGISTERS
        }
        flags: dict[str, object] = {
            name: {"op": "flag", "name": name} for name in _FLAGS
        }
        writes: list[_Write] = []

        for unit in prefix[:-1]:
            semantics = _semantics(unit)
            external_events = semantics.get("external_events", [])
            if not isinstance(external_events, list) or external_events:
                raise _IncompleteNormalization(
                    "entry_coordinate_external_prefix",
                    "an external transition occurs before the evidence unit",
                )
            before_registers = copy.deepcopy(registers)
            before_flags = copy.deepcopy(flags)
            unit_writes: list[_Write] = []
            memory_events = semantics.get("memory_events", [])
            if not isinstance(memory_events, list):
                raise _IncompleteNormalization(
                    "entry_coordinate_malformed_memory",
                    "a prefix unit has no normalized memory-event inventory",
                )
            for event in memory_events:
                if not isinstance(event, Mapping):
                    raise _IncompleteNormalization(
                        "entry_coordinate_malformed_memory",
                        "a prefix unit contains a malformed memory event",
                    )
                if event.get("kind") != "write":
                    continue
                width = event.get("width")
                if (
                    not isinstance(width, int)
                    or isinstance(width, bool)
                    or width <= 0
                ):
                    raise _IncompleteNormalization(
                        "entry_coordinate_malformed_memory",
                        "a prefix memory write has an invalid width",
                    )
                visible_writes = [*writes, *unit_writes]
                address = _rewrite(
                    event.get("address"),
                    before_registers,
                    before_flags,
                    visible_writes,
                )
                value = _rewrite(
                    event.get("value"),
                    before_registers,
                    before_flags,
                    visible_writes,
                )
                unit_writes.append(_Write(address, width, value))

            visible_writes = [*writes, *unit_writes]
            register_writes = semantics.get("register_writes", [])
            flag_writes = semantics.get("flag_writes", [])
            if not isinstance(register_writes, list) or not isinstance(
                flag_writes, list
            ):
                raise _IncompleteNormalization(
                    "entry_coordinate_malformed_state",
                    "a prefix unit has malformed state writes",
                )
            register_updates: dict[str, object] = {}
            for write in register_writes:
                if not isinstance(write, Mapping):
                    raise _IncompleteNormalization(
                        "entry_coordinate_malformed_state",
                        "a prefix unit has a malformed register write",
                    )
                register = write.get("register")
                if not isinstance(register, str) or register not in registers:
                    continue
                register_updates[register] = _rewrite(
                    write.get("value"),
                    before_registers,
                    before_flags,
                    visible_writes,
                )
            flag_updates: dict[str, object] = {}
            for write in flag_writes:
                if not isinstance(write, Mapping):
                    raise _IncompleteNormalization(
                        "entry_coordinate_malformed_state",
                        "a prefix unit has a malformed flag write",
                    )
                flag = write.get("flag")
                if not isinstance(flag, str) or flag not in flags:
                    continue
                flag_updates[flag] = _rewrite(
                    write.get("value"),
                    before_registers,
                    before_flags,
                    visible_writes,
                )
            registers.update(register_updates)
            flags.update(flag_updates)
            writes.extend(unit_writes)

        if target_memory_event_count < 0:
            raise _IncompleteNormalization(
                "entry_coordinate_invalid_phase",
                "the target memory-event prefix is negative",
            )
        target_semantics = _semantics(prefix[-1])
        target_events = target_semantics.get("memory_events", [])
        if not isinstance(target_events, list) or target_memory_event_count > len(
            target_events
        ):
            raise _IncompleteNormalization(
                "entry_coordinate_invalid_phase",
                "the target memory-event prefix is outside the unit",
            )
        for event in target_events[:target_memory_event_count]:
            if not isinstance(event, Mapping):
                raise _IncompleteNormalization(
                    "entry_coordinate_malformed_memory",
                    "the target unit contains a malformed memory event",
                )
            if event.get("kind") != "write":
                continue
            width = event.get("width")
            if (
                not isinstance(width, int)
                or isinstance(width, bool)
                or width <= 0
            ):
                raise _IncompleteNormalization(
                    "entry_coordinate_malformed_memory",
                    "a target memory write has an invalid width",
                )
            address = _rewrite(
                event.get("address"), registers, flags, writes
            )
            value = _rewrite(event.get("value"), registers, flags, writes)
            writes.append(_Write(address, width, value))
        normalized = _rewrite(expression, registers, flags, writes)
    except _IncompleteNormalization as error:
        return {
            "status": "incomplete",
            "code": error.code,
            "message": error.message,
        }
    return {
        "status": "complete",
        "entry_unit_id": entry_unit_id,
        "target_unit_id": target_unit_id,
        "expression": normalized,
    }


def _direct_prefix(
    units: Sequence[Mapping[str, Any]],
    *,
    entry_unit_id: str,
    target_unit_id: str,
) -> list[Mapping[str, Any]]:
    by_id = {
        str(unit.get("id")): unit
        for unit in units
        if isinstance(unit.get("id"), str)
    }
    if len(by_id) != len(units):
        raise _IncompleteNormalization(
            "entry_coordinate_duplicate_unit",
            "component unit IDs are missing or duplicated",
        )
    by_rva = {_unit_start(unit): unit for unit in units}
    if len(by_rva) != len(units):
        raise _IncompleteNormalization(
            "entry_coordinate_duplicate_rva",
            "component unit entry RVAs are duplicated",
        )
    if entry_unit_id not in by_id or target_unit_id not in by_id:
        raise _IncompleteNormalization(
            "entry_coordinate_unknown_unit",
            "the coordinate normalization references a unit outside the component",
        )
    current = by_id[entry_unit_id]
    prefix: list[Mapping[str, Any]] = []
    visited: set[str] = set()
    while True:
        identity = str(current["id"])
        if identity in visited:
            raise _IncompleteNormalization(
                "entry_coordinate_cycle",
                "the evidence unit is behind a cycle and needs an invariant",
            )
        visited.add(identity)
        prefix.append(current)
        if identity == target_unit_id:
            return prefix
        outcome = _semantics(current).get("outcome")
        if not isinstance(outcome, Mapping):
            raise _IncompleteNormalization(
                "entry_coordinate_missing_outcome",
                "a prefix unit has no normalized outcome",
            )
        target = _single_unconditional_target(outcome)
        if target is None or target not in by_rva:
            raise _IncompleteNormalization(
                "entry_coordinate_nonlinear_prefix",
                "the evidence unit is not reached by one checked direct prefix",
            )
        current = by_rva[target]


def _single_unconditional_target(outcome: Mapping[str, Any]) -> int | None:
    if outcome.get("kind") not in {"fallthrough", "jump"}:
        return None
    target = outcome.get("target_rva")
    return target if isinstance(target, int) and not isinstance(target, bool) else None


def _rewrite(
    value: object,
    registers: Mapping[str, object],
    flags: Mapping[str, object],
    writes: Sequence[_Write],
) -> object:
    if isinstance(value, list):
        return [_rewrite(item, registers, flags, writes) for item in value]
    if not isinstance(value, Mapping):
        return copy.deepcopy(value)
    op = value.get("op")
    if op == "reg" and str(value.get("name")) in registers:
        return copy.deepcopy(registers[str(value["name"])])
    if op == "flag" and str(value.get("name")) in flags:
        return copy.deepcopy(flags[str(value["name"])])
    rewritten = {
        str(key): _rewrite(child, registers, flags, writes)
        for key, child in value.items()
        if key != "address"
    }
    if "address" in value:
        rewritten["address"] = _rewrite(
            value["address"], registers, flags, writes
        )
    rewritten = _simplify(rewritten)
    if op != "load":
        return rewritten
    width = rewritten.get("width")
    address = rewritten.get("address")
    if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
        raise _IncompleteNormalization(
            "entry_coordinate_malformed_load", "a rewritten load has an invalid width"
        )
    for write in reversed(writes):
        relation = _range_relation(address, width, write.address, write.width)
        if relation == "equal":
            return copy.deepcopy(write.value)
        if relation != "disjoint":
            raise _IncompleteNormalization(
                "entry_coordinate_possible_alias",
                "a prior write may overlap the normalized input expression",
            )
    return rewritten


def _range_relation(
    left: object, left_width: int, right: object, right_width: int
) -> str:
    left_affine = _affine_address(left)
    right_affine = _affine_address(right)
    if left_affine is None or right_affine is None:
        return "unknown"
    left_base, left_offset = left_affine
    right_base, right_offset = right_affine
    if left_base != right_base:
        return "unknown"
    if left_offset == right_offset and left_width == right_width:
        return "equal"
    left_bytes = {(left_offset + index) & _WORD_MASK for index in range(left_width)}
    right_bytes = {
        (right_offset + index) & _WORD_MASK for index in range(right_width)
    }
    return "disjoint" if left_bytes.isdisjoint(right_bytes) else "overlap"


def _affine_address(value: object) -> tuple[object, int] | None:
    constant = 0
    dynamic: list[object] = []

    def collect(item: object, sign: int = 1) -> bool:
        nonlocal constant
        if isinstance(item, Mapping) and item.get("op") == "const" and isinstance(
            item.get("value"), int
        ):
            constant = (constant + sign * int(item["value"])) & _WORD_MASK
            return True
        if isinstance(item, Mapping) and item.get("op") == "add32" and isinstance(
            item.get("args"), list
        ):
            return all(collect(child, sign) for child in item["args"])
        if isinstance(item, Mapping) and item.get("op") == "sub32" and isinstance(
            item.get("args"), list
        ) and len(item["args"]) == 2:
            return collect(item["args"][0], sign) and collect(
                item["args"][1], -sign
            )
        if sign != 1:
            return False
        dynamic.append(copy.deepcopy(item))
        return True

    if not collect(value) or len(dynamic) != 1:
        return None
    return dynamic[0], constant


def _simplify(value: dict[str, Any]) -> dict[str, Any]:
    op = value.get("op")
    args = value.get("args")
    if op not in {"add32", "sub32"} or not isinstance(args, list):
        return value
    affine = _affine_address(value)
    if affine is None:
        return value
    base, offset = affine
    if offset == 0:
        return copy.deepcopy(base) if isinstance(base, dict) else value
    return {
        "op": "add32",
        "args": [
            {"op": "const", "value": offset, "width": 32},
            copy.deepcopy(base),
        ],
    }


def _semantics(unit: Mapping[str, Any]) -> Mapping[str, Any]:
    semantics = unit.get("semantics")
    if not isinstance(semantics, Mapping):
        raise _IncompleteNormalization(
            "entry_coordinate_missing_semantics",
            f"unit {unit.get('id')} has no normalized semantics",
        )
    return semantics


def _unit_start(unit: Mapping[str, Any]) -> int:
    source = unit.get("source")
    original = source.get("original") if isinstance(source, Mapping) else None
    value = original.get("rva_start") if isinstance(original, Mapping) else None
    if not isinstance(value, int) or isinstance(value, bool):
        raise _IncompleteNormalization(
            "entry_coordinate_missing_rva",
            f"unit {unit.get('id')} has no exact original entry RVA",
        )
    return value


__all__ = ["normalize_unit_expression_to_component_entry"]
