"""Fail-closed composition of straight-line reconstruction machine IR.

The machine IR describes each cutpoint-bounded unit relative to that unit's
pre-state.  A source workspace for several units needs one cluster-relative
summary; concatenating the local summaries would silently reset registers such
as ESP at every cutpoint.  This module follows one finite direct path and
substitutes each local pre-state through the preceding units.

The result is untrusted reconstruction guidance. Candidate assurance still
checks the sanitized interpreter and the rebuilt program independently.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping, Sequence
from hashlib import sha256
from typing import Any


_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_FLAGS = ("cf", "zf", "sf", "of", "pf", "df")
_WORD_MASK = 0xFFFFFFFF


def compose_linear_reconstruction_cluster(
    units: Sequence[Mapping[str, Any]], *, entry_unit_id: str
) -> dict[str, Any]:
    """Compose a finite single-entry path into one initial-state summary.

    Only acyclic paths whose internal exits have one unconditional direct
    destination are accepted.  This intentionally excludes branch joins,
    loops, indirect internal control, and multi-entry regions until they have
    dedicated path/invariant contracts.
    """

    normalized = [copy.deepcopy(dict(unit)) for unit in units]
    by_id = {str(unit.get("id")): unit for unit in normalized}
    by_rva = {_unit_start(unit): unit for unit in normalized}
    issues: list[dict[str, Any]] = []
    if len(by_id) != len(normalized):
        return _incomplete("duplicate_unit_id", "cluster unit ids are not unique")
    if len(by_rva) != len(normalized):
        return _incomplete("duplicate_unit_rva", "cluster unit entry RVAs are not unique")
    if entry_unit_id not in by_id:
        return _incomplete("missing_entry_unit", "cluster entry unit is absent")

    order: list[dict[str, Any]] = []
    current = by_id[entry_unit_id]
    visited: set[str] = set()
    while True:
        identity = str(current["id"])
        if identity in visited:
            return _incomplete(
                "cyclic_cluster",
                "linear composition does not accept a cycle; use a loop invariant",
                unit_ids=[str(item["id"]) for item in order],
            )
        visited.add(identity)
        order.append(current)
        outcome = _semantics(current).get("outcome")
        if not isinstance(outcome, Mapping):
            return _incomplete(
                "missing_outcome", f"unit {identity} has no normalized outcome"
            )
        internal_targets = [target for target in _outcome_targets(outcome) if target in by_rva]
        if not internal_targets:
            break
        if not _unconditional_direct_outcome(outcome) or len(internal_targets) != 1:
            return _incomplete(
                "nonlinear_internal_exit",
                f"unit {identity} has a branch or ambiguous internal destination",
            )
        current = by_rva[internal_targets[0]]

    omitted = sorted(set(by_id) - visited)
    if omitted:
        return _incomplete(
            "unvisited_cluster_units",
            "the proposed cluster is not one finite path from its declared entry",
            unit_ids=[str(item["id"]) for item in order],
            omitted_unit_ids=omitted,
        )

    registers: dict[str, Any] = {
        name: {"op": "reg", "name": name, "width": 32} for name in _REGISTERS
    }
    flags: dict[str, Any] = {
        name: {"op": "flag", "name": name} for name in _FLAGS
    }
    memory_events: list[dict[str, Any]] = []
    external_events: list[dict[str, Any]] = []
    ordered_events: list[dict[str, Any]] = []
    faults: list[dict[str, Any]] = []
    prior_writes: list[dict[str, Any]] = []
    final_outcome: Any = None

    for path_index, unit in enumerate(order):
        semantics = _semantics(unit)
        before_registers = copy.deepcopy(registers)
        before_flags = copy.deepcopy(flags)
        unit_prior_writes = copy.deepcopy(prior_writes)
        final_outcome = _substitute(
            semantics.get("outcome"),
            before_registers,
            before_flags,
            unit_prior_writes,
        )
        unit_writes: list[dict[str, Any]] = []

        for event_index, event in enumerate(semantics.get("memory_events", [])):
            if not isinstance(event, Mapping):
                issues.append(
                    _issue("malformed_memory_event", unit, event_index=event_index)
                )
                continue
            rewritten = _substitute(
                event, before_registers, before_flags, unit_prior_writes
            )
            rewritten["source_unit_id"] = str(unit["id"])
            rewritten["source_event_index"] = event_index
            rewritten["cluster_event_index"] = len(memory_events)
            memory_events.append(rewritten)
            if rewritten.get("kind") == "write":
                unit_writes.append(
                    {
                        "address": copy.deepcopy(rewritten.get("address")),
                        "width": rewritten.get("width"),
                        "value": copy.deepcopy(rewritten.get("value")),
                        "cluster_event_index": rewritten["cluster_event_index"],
                    }
                )

        for event_index, event in enumerate(semantics.get("external_events", [])):
            if not isinstance(event, Mapping):
                issues.append(
                    _issue("malformed_external_event", unit, event_index=event_index)
                )
                continue
            rewritten = _substitute(
                event, before_registers, before_flags, unit_prior_writes
            )
            rewritten["source_unit_id"] = str(unit["id"])
            rewritten["source_event_index"] = event_index
            rewritten["cluster_event_index"] = len(external_events)
            external_events.append(rewritten)

        for fault_index, fault in enumerate(semantics.get("faults", [])):
            if not isinstance(fault, Mapping):
                issues.append(_issue("malformed_fault", unit, event_index=fault_index))
                continue
            rewritten = _substitute(
                fault, before_registers, before_flags, unit_prior_writes
            )
            rewritten["source_unit_id"] = str(unit["id"])
            rewritten["source_fault_index"] = fault_index
            faults.append(rewritten)

        register_updates: dict[str, Any] = {}
        for write in semantics.get("register_writes", []):
            if not isinstance(write, Mapping) or str(write.get("register")) not in registers:
                issues.append(_issue("malformed_register_write", unit))
                continue
            register_updates[str(write["register"])] = _substitute(
                write.get("value"),
                before_registers,
                before_flags,
                unit_prior_writes,
            )
        flag_updates: dict[str, Any] = {}
        for write in semantics.get("flag_writes", []):
            if not isinstance(write, Mapping) or str(write.get("flag")) not in flags:
                issues.append(_issue("malformed_flag_write", unit))
                continue
            flag_updates[str(write["flag"])] = _substitute(
                write.get("value"),
                before_registers,
                before_flags,
                unit_prior_writes,
            )
        registers.update(register_updates)
        flags.update(flag_updates)
        raw_ordered = semantics.get("ordered_events", [])
        if isinstance(raw_ordered, list):
            for event in raw_ordered:
                if isinstance(event, Mapping):
                    rewritten = _substitute(
                        event,
                        before_registers,
                        before_flags,
                        unit_prior_writes,
                    )
                    rewritten["source_unit_id"] = str(unit["id"])
                    rewritten["cluster_order_index"] = len(ordered_events)
                    ordered_events.append(rewritten)
        prior_writes.extend(unit_writes)

    if issues:
        return {
            "status": "incomplete",
            "kind": "finite_linear_path",
            "unit_ids": [str(item["id"]) for item in order],
            "issues": issues,
        }

    final = order[-1]
    register_writes = [
        {"register": name, "value": value}
        for name, value in registers.items()
        if value != {"op": "reg", "name": name, "width": 32}
    ]
    flag_writes = [
        {"flag": name, "value": value}
        for name, value in flags.items()
        if value != {"op": "flag", "name": name}
    ]
    stack_expression = registers["esp"]
    net_bytes = _constant_register_delta(stack_expression, "esp")
    semantics = {
        "register_writes": register_writes,
        "flag_writes": flag_writes,
        "memory_events": memory_events,
        "ordered_events": (
            ordered_events
            if ordered_events
            else _ordered_effects(memory_events, external_events)
        ),
        "external_events": external_events,
        "faults": faults,
        "outcome": final_outcome,
        "edge_conditions": _edge_conditions(final_outcome),
        "stack_delta": {
            "status": "derived" if net_bytes is not None else "symbolic",
            "expression": copy.deepcopy(stack_expression),
            "net_bytes": net_bytes,
        },
    }
    summary_unit = {
        "id": "composed:" + "+".join(str(item["id"]) for item in order),
        "status": "qualified",
        "instructions": [
            copy.deepcopy(instruction)
            for item in order
            for instruction in item.get("instructions", [])
            if isinstance(instruction, Mapping)
        ],
        "source": {
            "original": {
                "rva_start": _unit_start(order[0]),
                "rva_end": _unit_end(order[-1]),
            }
        },
        "semantics": semantics,
        "composition": {
            "kind": "finite_linear_path",
            "unit_ids": [str(item["id"]) for item in order],
        },
    }
    return {
        "status": "complete",
        "kind": "finite_linear_path",
        "entry_unit_id": entry_unit_id,
        "unit_ids": [str(item["id"]) for item in order],
        "unit_entry_rvas": [_unit_start(item) for item in order],
        "summary_unit": summary_unit,
        "issues": [],
    }


def _substitute(
    value: Any,
    registers: Mapping[str, Any],
    flags: Mapping[str, Any],
    prior_writes: Sequence[Mapping[str, Any]] = (),
) -> Any:
    if isinstance(value, list):
        return [
            _substitute(item, registers, flags, prior_writes) for item in value
        ]
    if not isinstance(value, Mapping):
        return copy.deepcopy(value)
    op = value.get("op")
    if op == "reg" and str(value.get("name")) in registers:
        return copy.deepcopy(registers[str(value["name"])])
    if op == "flag" and str(value.get("name")) in flags:
        return copy.deepcopy(flags[str(value["name"])])
    rewritten = {
        str(key): _substitute(child, registers, flags, prior_writes)
        for key, child in value.items()
    }
    if op == "load" and prior_writes:
        return {
            "op": "load_after_writes",
            "address": rewritten.get("address"),
            "width": rewritten.get("width"),
            "prior_writes": copy.deepcopy(list(prior_writes)),
        }
    return _simplify(rewritten)


def _simplify(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("op") != "add32" or not isinstance(value.get("args"), list):
        return value
    dynamic: list[Any] = []
    constant = 0

    def collect(item: Any) -> None:
        nonlocal constant
        if isinstance(item, Mapping) and item.get("op") == "add32" and isinstance(item.get("args"), list):
            for child in item["args"]:
                collect(child)
        elif isinstance(item, Mapping) and item.get("op") == "const" and isinstance(item.get("value"), int):
            constant = (constant + int(item["value"])) & _WORD_MASK
        else:
            dynamic.append(copy.deepcopy(item))

    for item in value["args"]:
        collect(item)
    args: list[Any] = []
    if constant or not dynamic:
        args.append({"op": "const", "value": constant, "width": 32})
    args.extend(dynamic)
    if len(args) == 1 and isinstance(args[0], Mapping):
        return dict(args[0])
    return {"op": "add32", "args": args}


def _outcome_targets(outcome: Mapping[str, Any]) -> list[int]:
    result = []
    for key in ("target_rva", "true_target_rva", "false_target_rva"):
        value = outcome.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            result.append(value)
    return result


def _unconditional_direct_outcome(outcome: Mapping[str, Any]) -> bool:
    return outcome.get("kind") in {"fallthrough", "jump"} and isinstance(
        outcome.get("target_rva"), int
    )


def _edge_conditions(outcome: Mapping[str, Any]) -> list[dict[str, Any]]:
    kind = outcome.get("kind")
    if kind in {"fallthrough", "jump"} and isinstance(outcome.get("target_rva"), int):
        return [{"condition": {"op": "true"}, "target_rva": outcome["target_rva"]}]
    if kind == "branch":
        condition = copy.deepcopy(outcome.get("condition"))
        return [
            {"condition": condition, "target_rva": outcome.get("true_target_rva")},
            {
                "condition": {"op": "not", "args": [condition]},
                "target_rva": outcome.get("false_target_rva"),
            },
        ]
    return []


def _ordered_effects(
    memory_events: Sequence[Mapping[str, Any]],
    external_events: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    rows = [
        {"family": "memory", **copy.deepcopy(dict(event))} for event in memory_events
    ]
    rows.extend(
        {"family": "external", **copy.deepcopy(dict(event))}
        for event in external_events
    )
    rows.sort(
        key=lambda item: (
            int(item.get("cluster_event_index", 0)),
            0 if item["family"] == "memory" else 1,
        )
    )
    return rows


def _constant_register_delta(expression: Any, register: str) -> int | None:
    if expression == {"op": "reg", "name": register, "width": 32}:
        return 0
    if not isinstance(expression, Mapping) or expression.get("op") != "add32":
        return None
    args = expression.get("args")
    if not isinstance(args, list) or len(args) != 2:
        return None
    constant = next(
        (
            int(item["value"])
            for item in args
            if isinstance(item, Mapping)
            and item.get("op") == "const"
            and isinstance(item.get("value"), int)
        ),
        None,
    )
    base = next(
        (
            item
            for item in args
            if isinstance(item, Mapping) and item.get("op") == "reg"
        ),
        None,
    )
    if constant is None or base != {"op": "reg", "name": register, "width": 32}:
        return None
    return constant if constant < 0x80000000 else constant - 0x1_0000_0000


def _unit_start(unit: Mapping[str, Any]) -> int:
    return int(unit["source"]["original"]["rva_start"])


def _unit_end(unit: Mapping[str, Any]) -> int:
    return int(unit["source"]["original"]["rva_end"])


def _semantics(unit: Mapping[str, Any]) -> Mapping[str, Any]:
    value = unit.get("semantics")
    if not isinstance(value, Mapping):
        raise ValueError(f"unit {unit.get('id')!r} has no semantics")
    return value


def _issue(code: str, unit: Mapping[str, Any], **extra: Any) -> dict[str, Any]:
    return {"code": code, "unit_id": str(unit.get("id")), **extra}


def _incomplete(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {
        "status": "incomplete",
        "kind": "finite_linear_path",
        "issues": [{"code": code, "message": message}],
        **extra,
    }


def canonical_composition_sha256(payload: Mapping[str, Any]) -> str:
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


__all__ = ["compose_linear_reconstruction_cluster", "canonical_composition_sha256"]
