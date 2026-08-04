"""Bounded value-origin analysis for machine-IR indirect control.

The analysis is proposal logic. It only consumes exact machine-IR expressions,
PE import cells, and explicit machine ABI profiles. Unknown joins and missing
call summaries remain unresolved instead of being widened into targets.
"""

from __future__ import annotations

import copy
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterable, Mapping, Sequence

from .import_abi import SelectedImportABI
from .machine_import_profiles import MachineImportIdentity


VALUE_PROVENANCE_FORMAT = "stage-a-value-provenance-v1"
_REGISTERS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")
_CALL_KINDS = frozenset({"external_call", "indirect_call", "internal_call"})


@dataclass(frozen=True, order=True)
class _Origin:
    kind: str
    key: tuple[Any, ...]


_Origins = frozenset[_Origin]
_Value = _Origins | None
_State = dict[str, _Value]


@dataclass(frozen=True)
class _Edge:
    kind: str
    target_id: str
    event_index: int | None = None


@dataclass(frozen=True)
class _Transfer:
    output: _State
    call_entries: tuple[_State | None, ...]


def recover_indirect_targets_from_value_provenance(
    *,
    units: Sequence[Mapping[str, Any]],
    roots: Iterable[str],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    recovered_indirect_edges: Sequence[Mapping[str, Any]] = (),
    indirect_exits: Sequence[Mapping[str, Any]],
    image_base: int,
    imports: Sequence[Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    finite_target_budget: int = 64,
) -> dict[str, Any]:
    """Recover finite code/import targets through checked register carries."""

    if finite_target_budget <= 0:
        raise ValueError("finite target budget must be positive")
    by_id = {str(unit["id"]): unit for unit in units}
    if len(by_id) != len(units):
        raise ValueError("value provenance requires unique unit IDs")
    unit_targets: dict[int, list[tuple[int, str]]] = defaultdict(list)
    for unit in units:
        source = _mapping(_mapping(unit.get("source"))["original"])
        rva = _integer(source.get("rva_start"))
        if rva is not None:
            unit_targets[(image_base + rva) & 0xFFFFFFFF].append((rva, str(unit["id"])))

    iat: dict[int, MachineImportIdentity] = {}
    for raw in imports:
        imported = _mapping(raw)
        dll = imported.get("dll")
        symbol = imported.get("symbol")
        ordinal = imported.get("ordinal")
        thunk_rva = _integer(imported.get("thunk_rva"))
        if not isinstance(dll, str) or thunk_rva is None:
            continue
        if isinstance(symbol, str) and symbol:
            identity = MachineImportIdentity(dll.lower(), "symbol", symbol)
        elif ordinal is not None and _integer(ordinal) is not None:
            identity = MachineImportIdentity(dll.lower(), "ordinal", int(ordinal))
        else:
            continue
        address = (image_base + thunk_rva) & 0xFFFFFFFF
        if address in iat and iat[address] != identity:
            raise ValueError(f"ambiguous IAT cell at 0x{address:08x}")
        iat[address] = identity

    outgoing: dict[str, set[_Edge]] = defaultdict(set)
    for raw in direct_edges:
        source = raw.get("source_unit_id")
        target = raw.get("target_unit_id", raw.get("resolved_unit_id"))
        if isinstance(source, str) and isinstance(target, str) and source in by_id and target in by_id:
            outgoing[source].add(_Edge("direct", target))
    for raw in internal_call_edges:
        source = raw.get("source_unit_id")
        target = raw.get("target_unit_id", raw.get("resolved_unit_id"))
        event_index = _integer(raw.get("source_event_index"))
        if isinstance(source, str) and isinstance(target, str) and source in by_id and target in by_id:
            outgoing[source].add(_Edge("internal_call", target, event_index))
    for raw in recovered_indirect_edges:
        if raw.get("status") != "recovered":
            continue
        source = raw.get("source_unit_id")
        event_index = _integer(raw.get("source_event_index"))
        kind = "indirect_call" if raw.get("kind") == "indirect_call" else "direct"
        raw_targets = raw.get("target_unit_ids")
        if not isinstance(source, str) or not isinstance(raw_targets, Sequence):
            continue
        for target in raw_targets:
            if isinstance(target, str) and source in by_id and target in by_id:
                outgoing[source].add(_Edge(kind, target, event_index))

    input_states: dict[str, _State] = {}
    work: deque[str] = deque()
    root_state = {register: None for register in _REGISTERS}
    for root in sorted({str(value) for value in roots} & set(by_id)):
        input_states[root] = copy.deepcopy(root_state)
        work.append(root)

    evaluations = 0
    budget_exceeded = 0
    while work:
        source_id = work.popleft()
        transfer, exceeded = _transfer_unit(
            by_id[source_id],
            input_states[source_id],
            iat=iat,
            import_abis=import_abis,
            budget=finite_target_budget,
        )
        evaluations += 1
        budget_exceeded += exceeded
        for edge in sorted(outgoing.get(source_id, ()), key=lambda item: (item.target_id, item.kind, item.event_index or -1)):
            contribution = transfer.output
            if edge.kind in {"internal_call", "indirect_call"}:
                index = edge.event_index
                if index is None or not 0 <= index < len(transfer.call_entries):
                    contribution = root_state
                else:
                    contribution = transfer.call_entries[index] or root_state
            changed = _join_input(
                input_states,
                edge.target_id,
                contribution,
                finite_target_budget,
            )
            if changed:
                work.append(edge.target_id)

    resolutions: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for exit_record in sorted(indirect_exits, key=lambda value: str(value.get("id") or "")):
        source_id = str(exit_record.get("source_unit_id") or "")
        identity = str(exit_record.get("id") or _stable_id("indirect-exit", exit_record))
        state = input_states.get(source_id)
        target_expression = exit_record.get("target_expression")
        if state is None or source_id not in by_id:
            origins = None
        else:
            unit = by_id[source_id]
            event_index = _integer(exit_record.get("source_event_index"))
            if event_index is not None:
                events = _events(unit)
                target_expression = (
                    events[event_index].get("target")
                    if 0 <= event_index < len(events)
                    else None
                )
            origins = _evaluate(
                target_expression,
                state,
                iat=iat,
                budget=finite_target_budget,
            )
        classified = _classify_targets(
            origins,
            unit_targets=unit_targets,
            import_abis=import_abis,
        )
        base = {
            "id": identity,
            "source_unit_id": source_id,
            "source_rva": exit_record.get("source_rva"),
            "source_event_index": exit_record.get("source_event_index"),
            "kind": exit_record.get("kind"),
        }
        if classified is None:
            row = {
                **base,
                "status": "incomplete",
                "closure": "unresolved",
                "target_rvas": [],
                "target_unit_ids": [],
                "external_targets": [],
                "failure": {
                    "code": "value_origin_unresolved",
                    "message": "target value does not have one bounded checked origin set",
                },
            }
            issues.append({
                "code": "value_origin_unresolved",
                "indirect_exit_id": identity,
                "source_unit_id": source_id,
            })
        else:
            internal, external = classified
            row = {
                **base,
                "status": "recovered",
                "closure": "checked_finite_value_origin_inventory",
                "target_rvas": sorted({item[0] for item in internal}),
                "target_unit_ids": sorted({item[1] for item in internal}),
                "external_targets": external,
                "origin_count": len(origins or ()),
                "failure": None,
            }
        resolutions.append(row)

    complete = sum(row["status"] == "recovered" for row in resolutions)
    return {
        "format": VALUE_PROVENANCE_FORMAT,
        "status": "complete" if complete == len(resolutions) else "incomplete",
        "finite_target_budget": finite_target_budget,
        "resolutions": resolutions,
        "issues": issues,
        "counts": {
            "units": len(units),
            "reached_units": len(input_states),
            "transfer_evaluations": evaluations,
            "indirect_exits": len(resolutions),
            "recovered_indirect_exits": complete,
            "external_target_exits": sum(bool(row["external_targets"]) for row in resolutions),
            "internal_target_exits": sum(bool(row["target_unit_ids"]) for row in resolutions),
            "finite_budget_exceeded": budget_exceeded,
        },
    }


def _transfer_unit(
    unit: Mapping[str, Any],
    input_state: _State,
    *,
    iat: Mapping[int, MachineImportIdentity],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    budget: int,
) -> tuple[_Transfer, int]:
    events = _events(unit)
    calls = [event for event in events if event.get("kind") in _CALL_KINDS]
    call_entries: list[_State | None] = [None] * len(events)
    exceeded = 0
    for index, event in enumerate(events):
        if event.get("kind") in _CALL_KINDS:
            call_entries[index] = _event_register_state(
                event, input_state, iat=iat, budget=budget
            )
    if calls:
        if len(calls) != 1:
            return _Transfer({register: None for register in _REGISTERS}, tuple(call_entries)), exceeded
        event = calls[0]
        event_index = events.index(event)
        pre_call = call_entries[event_index] or {register: None for register in _REGISTERS}
        abi = _event_abi(
            event,
            input_state,
            iat=iat,
            import_abis=import_abis,
            budget=budget,
        )
        output = {register: None for register in _REGISTERS}
        if abi is not None and event.get("kind") != "internal_call":
            for register in abi:
                output[register] = pre_call.get(register)
        return _Transfer(output, tuple(call_entries)), exceeded

    output = dict(input_state)
    semantics = _mapping(unit.get("semantics"))
    writes = semantics.get("register_writes")
    if not isinstance(writes, list):
        return _Transfer({register: None for register in _REGISTERS}, tuple(call_entries)), exceeded
    for raw in writes:
        write = _mapping(raw)
        register = write.get("register")
        if not isinstance(register, str) or register not in output:
            continue
        value = _evaluate(write.get("value"), input_state, iat=iat, budget=budget)
        if value is not None and len(value) > budget:
            exceeded += 1
            value = None
        output[register] = value
    return _Transfer(output, tuple(call_entries)), exceeded


def _event_register_state(
    event: Mapping[str, Any],
    input_state: _State,
    *,
    iat: Mapping[int, MachineImportIdentity],
    budget: int,
) -> _State:
    raw = event.get("register_inputs")
    if not isinstance(raw, Mapping):
        return {register: input_state.get(register) for register in _REGISTERS}
    return {
        register: _evaluate(raw.get(register), input_state, iat=iat, budget=budget)
        for register in _REGISTERS
    }


def _event_abi(
    event: Mapping[str, Any],
    input_state: _State,
    *,
    iat: Mapping[int, MachineImportIdentity],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    budget: int,
) -> frozenset[str] | None:
    kind = event.get("kind")
    identities: set[MachineImportIdentity] = set()
    if kind == "external_call":
        identity = _event_import_identity(event)
        if identity is not None:
            identities.add(identity)
    elif kind == "indirect_call":
        origins = _evaluate(event.get("target"), input_state, iat=iat, budget=budget)
        if origins is None or not origins:
            return None
        for origin in origins:
            if origin.kind != "import":
                return None
            identities.add(_origin_import_identity(origin))
    else:
        return None
    selected = [import_abis.get(identity) for identity in sorted(identities)]
    if not selected or any(item is None for item in selected):
        return None
    preserved = set(selected[0].abi.preserved_registers)  # type: ignore[union-attr]
    for item in selected[1:]:
        assert item is not None
        preserved &= set(item.abi.preserved_registers)
    return frozenset(preserved)


def _evaluate(
    expression: Any,
    state: _State,
    *,
    iat: Mapping[int, MachineImportIdentity],
    budget: int,
) -> _Value:
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op") or "").lower()
    if op in {"reg", "input_reg", "register"}:
        name = expression.get("name", expression.get("reg"))
        return state.get(str(name).lower()) if name is not None else None
    if op in {"const", "constant"}:
        value = _integer(expression.get("value"))
        return None if value is None else frozenset({_Origin("exact", (value & 0xFFFFFFFF,))})
    if op in {"load", "read32", "mem32"}:
        width = expression.get("width", expression.get("width_bits", 32))
        if width not in {4, 32, None}:
            return None
        addresses = _exact_values(
            _evaluate(expression.get("address"), state, iat=iat, budget=budget)
        )
        if addresses is None or not addresses:
            return None
        identities = {iat.get(address) for address in addresses}
        if None in identities or not identities:
            return None
        return frozenset(_import_origin(identity) for identity in identities if identity is not None)
    if op in {"add", "add32", "sub", "sub32"}:
        operands = _binary_operands(expression)
        if operands is None:
            return None
        left = _exact_values(_evaluate(operands[0], state, iat=iat, budget=budget))
        right = _exact_values(_evaluate(operands[1], state, iat=iat, budget=budget))
        if left is None or right is None or len(left) * len(right) > budget:
            return None
        values = {
            ((a + b) if op in {"add", "add32"} else (a - b)) & 0xFFFFFFFF
            for a in left for b in right
        }
        return frozenset(_Origin("exact", (value,)) for value in values)
    return None


def _classify_targets(
    origins: _Value,
    *,
    unit_targets: Mapping[int, Sequence[tuple[int, str]]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
) -> tuple[list[tuple[int, str]], list[dict[str, Any]]] | None:
    if origins is None or not origins:
        return None
    internal: set[tuple[int, str]] = set()
    external: dict[tuple[str, str, str | int], dict[str, Any]] = {}
    for origin in origins:
        if origin.kind == "exact":
            candidates = unit_targets.get(int(origin.key[0]), ())
            if len(candidates) != 1:
                return None
            internal.add(candidates[0])
        elif origin.kind == "import":
            identity = _origin_import_identity(origin)
            selected = import_abis.get(identity)
            if selected is None:
                return None
            key = (identity.dll, identity.kind, identity.value)
            external[key] = selected.as_json()
        else:
            return None
    return sorted(internal), [external[key] for key in sorted(external)]


def _join_input(
    states: dict[str, _State], target: str, contribution: _State, budget: int
) -> bool:
    prior = states.get(target)
    if prior is None:
        states[target] = copy.deepcopy(contribution)
        return True
    joined = {
        register: _join_value(prior.get(register), contribution.get(register), budget)
        for register in _REGISTERS
    }
    if joined == prior:
        return False
    states[target] = joined
    return True


def _join_value(left: _Value, right: _Value, budget: int) -> _Value:
    if left is None or right is None:
        return None
    result = left | right
    return result if len(result) <= budget else None


def _events(unit: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = _mapping(unit.get("semantics")).get("external_events")
    return [value for value in raw if isinstance(value, Mapping)] if isinstance(raw, list) else []


def _event_import_identity(event: Mapping[str, Any]) -> MachineImportIdentity | None:
    dll = event.get("dll")
    symbol = event.get("symbol")
    ordinal = _integer(event.get("ordinal"))
    if not isinstance(dll, str):
        return None
    if isinstance(symbol, str) and symbol:
        return MachineImportIdentity(dll.lower(), "symbol", symbol)
    if ordinal is not None:
        return MachineImportIdentity(dll.lower(), "ordinal", ordinal)
    return None


def _import_origin(identity: MachineImportIdentity) -> _Origin:
    return _Origin("import", (identity.dll, identity.kind, identity.value))


def _origin_import_identity(origin: _Origin) -> MachineImportIdentity:
    return MachineImportIdentity(str(origin.key[0]), str(origin.key[1]), origin.key[2])


def _exact_values(origins: _Value) -> set[int] | None:
    if origins is None or any(origin.kind != "exact" for origin in origins):
        return None
    return {int(origin.key[0]) & 0xFFFFFFFF for origin in origins}


def _binary_operands(expression: Mapping[str, Any]) -> tuple[Any, Any] | None:
    arguments = expression.get("args")
    if isinstance(arguments, Sequence) and not isinstance(arguments, (str, bytes)) and len(arguments) == 2:
        return arguments[0], arguments[1]
    if "left" in expression and "right" in expression:
        return expression["left"], expression["right"]
    return None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _stable_id(prefix: str, value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"{prefix}:{sha256(encoded).hexdigest()[:20]}"


__all__ = [
    "VALUE_PROVENANCE_FORMAT",
    "recover_indirect_targets_from_value_provenance",
]
