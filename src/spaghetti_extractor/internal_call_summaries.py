"""Fail-closed same-image preservation summaries for internal PE32 calls.

The summaries are proposal evidence, not acceptance authority.  They traverse
the exported machine IR, retain only values whose origins survive every
returning path, and abandon claims at unresolved control or bounded-analysis
frontiers.  Lean must replay any summary used by a final proof.
"""

from __future__ import annotations

import copy
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .import_abi import SelectedImportABI
from .machine_import_profiles import MachineImportIdentity


INTERNAL_CALL_SUMMARY_FORMAT = "stage-a-internal-call-preservation-v1"
_REGISTERS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")
_SUMMARY_REGISTERS = frozenset({"ebp", "ebx", "edi", "esi"})
_CALL_KINDS = frozenset({"external_call", "indirect_call", "internal_call"})
_TERMINAL_KINDS = frozenset({"fault", "terminate", "terminated", "halt"})


@dataclass(frozen=True)
class _RegisterOrigin:
    register: str


@dataclass(frozen=True)
class _StackAddress:
    offset: int


@dataclass(frozen=True)
class _Exact:
    value: int


_Value = _RegisterOrigin | _StackAddress | _Exact | None


@dataclass
class _State:
    registers: dict[str, _Value]
    stack_words: dict[int, _Value]


def derive_internal_call_preservation_summaries(
    *,
    units: Sequence[Mapping[str, Any]],
    roots: Iterable[str],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    recovered_indirect_targets: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    max_units_per_summary: int = 4096,
    max_stack_words: int = 256,
    max_fixed_point_rounds: int = 64,
) -> dict[str, Any]:
    """Propose nonvolatile-register preservation for reachable callees."""

    if min(max_units_per_summary, max_stack_words, max_fixed_point_rounds) <= 0:
        raise ValueError("internal call summary budgets must be positive")
    by_id = {str(unit["id"]): unit for unit in units}
    if len(by_id) != len(units):
        raise ValueError("internal call summaries require unique unit IDs")

    normal_edges: dict[str, set[str]] = defaultdict(set)
    unresolved_direct_sources: set[str] = set()
    for edge in direct_edges:
        source = edge.get("source_unit_id")
        target = edge.get("target_unit_id", edge.get("resolved_unit_id"))
        if not isinstance(source, str) or source not in by_id:
            continue
        if (
            edge.get("status") in {None, "resolved"}
            and isinstance(target, str)
            and target in by_id
        ):
            normal_edges[source].add(target)
        else:
            unresolved_direct_sources.add(source)

    direct_calls: dict[tuple[str, int], str] = {}
    for edge in internal_call_edges:
        source = edge.get("source_unit_id")
        target = edge.get("target_unit_id", edge.get("resolved_unit_id"))
        event_index = _integer(edge.get("source_event_index"))
        if (
            edge.get("status") in {None, "resolved"}
            and isinstance(source, str)
            and isinstance(target, str)
            and event_index is not None
            and source in by_id
            and target in by_id
        ):
            direct_calls[(source, event_index)] = target

    exits_by_site = {
        (str(row.get("source_unit_id") or ""), _integer(row.get("source_event_index"))): row
        for row in indirect_exits
    }
    recoveries_by_id = {
        str(row.get("id")): row
        for row in recovered_indirect_targets
        if row.get("status") == "recovered"
    }
    unresolved_jump_sources: set[str] = set()
    recovered_calls: dict[tuple[str, int], Mapping[str, Any]] = {}
    recovered_call_targets: dict[str, set[str]] = defaultdict(set)
    for site, exit_record in exits_by_site.items():
        recovery = recoveries_by_id.get(str(exit_record.get("id")))
        source, event_index = site
        if exit_record.get("kind") == "indirect_jump":
            if recovery is None or recovery.get("external_targets"):
                unresolved_jump_sources.add(source)
                continue
            targets = recovery.get("target_unit_ids")
            if not isinstance(targets, Sequence) or isinstance(targets, (str, bytes)):
                unresolved_jump_sources.add(source)
                continue
            valid = {
                str(target)
                for target in targets
                if isinstance(target, str) and target in by_id
            }
            if len(valid) != len(targets) or not valid:
                unresolved_jump_sources.add(source)
                continue
            normal_edges[source].update(valid)
        elif (
            exit_record.get("kind") == "indirect_call"
            and event_index is not None
            and recovery is not None
        ):
            recovered_calls[(source, event_index)] = recovery
            for target in recovery.get("target_unit_ids", []):
                if isinstance(target, str) and target in by_id:
                    recovered_call_targets[source].add(target)

    eligible_units, callee_roots = _reachable_call_roots(
        roots={str(root) for root in roots if str(root) in by_id},
        normal_edges=normal_edges,
        direct_calls=direct_calls,
        recovered_call_targets=recovered_call_targets,
    )
    summaries: dict[str, dict[str, Any]] = {}
    rounds = 0
    fixed_point_complete = not callee_roots
    for rounds in range(1, max_fixed_point_rounds + 1):
        changed = False
        for root in sorted(callee_roots):
            proposed = _analyze_callee(
                root=root,
                by_id=by_id,
                normal_edges=normal_edges,
                unresolved_direct_sources=unresolved_direct_sources,
                unresolved_jump_sources=unresolved_jump_sources,
                direct_calls=direct_calls,
                recovered_calls=recovered_calls,
                summaries=summaries,
                import_abis=import_abis,
                max_units=max_units_per_summary,
                max_stack_words=max_stack_words,
            )
            if summaries.get(root) != proposed:
                summaries[root] = proposed
                changed = True
        if not changed:
            fixed_point_complete = True
            break

    rows: list[dict[str, Any]] = []
    for root in sorted(callee_roots):
        source = _mapping(_mapping(by_id[root].get("source")).get("original"))
        rows.append(
            {
                "target_unit_id": root,
                "target_rva": _integer(source.get("rva_start")),
                **summaries[root],
            }
        )
    complete = [row for row in rows if row["status"] == "complete"]
    return {
        "format": INTERNAL_CALL_SUMMARY_FORMAT,
        "status": (
            "complete"
            if fixed_point_complete and len(complete) == len(rows)
            else "incomplete"
        ),
        "proof_authority": False,
        "required_replay": "Lean must replay CFG closure and every preserved origin",
        "budgets": {
            "max_units_per_summary": max_units_per_summary,
            "max_stack_words": max_stack_words,
            "max_fixed_point_rounds": max_fixed_point_rounds,
        },
        "fixed_point_rounds": rounds,
        "fixed_point_complete": fixed_point_complete,
        "eligible_units": sorted(eligible_units),
        "summaries": rows,
        "counts": {
            "eligible_units": len(eligible_units),
            "call_targets": len(rows),
            "complete_summaries": len(complete),
            "incomplete_summaries": len(rows) - len(complete),
            "preserved_register_claims": sum(
                len(row["preserved_registers"]) for row in complete
            ),
        },
    }


def _reachable_call_roots(
    *,
    roots: set[str],
    normal_edges: Mapping[str, set[str]],
    direct_calls: Mapping[tuple[str, int], str],
    recovered_call_targets: Mapping[str, set[str]],
) -> tuple[set[str], set[str]]:
    callees_by_source: dict[str, set[str]] = defaultdict(set)
    for (source, _), target in direct_calls.items():
        callees_by_source[source].add(target)
    for source, targets in recovered_call_targets.items():
        callees_by_source[source].update(targets)
    reached = set(roots)
    callees: set[str] = set()
    work = deque(sorted(roots))
    while work:
        source = work.popleft()
        call_targets = callees_by_source.get(source, set())
        callees.update(call_targets)
        for target in sorted(normal_edges.get(source, set()) | call_targets):
            if target not in reached:
                reached.add(target)
                work.append(target)
    return reached, callees


def _analyze_callee(
    *,
    root: str,
    by_id: Mapping[str, Mapping[str, Any]],
    normal_edges: Mapping[str, set[str]],
    unresolved_direct_sources: set[str],
    unresolved_jump_sources: set[str],
    direct_calls: Mapping[tuple[str, int], str],
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
    summaries: Mapping[str, Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    max_units: int,
    max_stack_words: int,
) -> dict[str, Any]:
    initial = _State(
        registers={
            register: (
                _StackAddress(0)
                if register == "esp"
                else _RegisterOrigin(register)
            )
            for register in _REGISTERS
        },
        stack_words={},
    )
    states = {root: initial}
    work = deque([root])
    return_states: list[_State] = []
    blockers: set[str] = set()
    evaluations = 0
    while work:
        unit_id = work.popleft()
        evaluations += 1
        if len(states) > max_units or evaluations > max_units * 16:
            blockers.add("callee_summary_budget_exceeded")
            break
        unit = by_id[unit_id]
        output, transfer_blockers = _transfer(
            unit_id=unit_id,
            unit=unit,
            state=states[unit_id],
            direct_calls=direct_calls,
            recovered_calls=recovered_calls,
            summaries=summaries,
            import_abis=import_abis,
            max_stack_words=max_stack_words,
        )
        blockers.update(transfer_blockers)
        kind = _mapping(_mapping(unit.get("semantics")).get("outcome")).get("kind")
        if kind == "return":
            return_states.append(output)
            continue
        if unit_id in unresolved_direct_sources:
            blockers.add("unresolved_direct_control")
        if unit_id in unresolved_jump_sources:
            blockers.add("unresolved_indirect_jump")
        successors = normal_edges.get(unit_id, set())
        if not successors:
            if kind not in _TERMINAL_KINDS:
                blockers.add("unterminated_control_path")
            continue
        for target in sorted(successors):
            prior = states.get(target)
            joined = copy.deepcopy(output) if prior is None else _join_states(prior, output)
            if prior != joined:
                states[target] = joined
                work.append(target)

    if not return_states:
        blockers.add("return_inventory_empty")
    preserved = sorted(
        register
        for register in _SUMMARY_REGISTERS
        if return_states
        and all(
            state.registers.get(register) == _RegisterOrigin(register)
            for state in return_states
        )
    )
    control_complete = not {
        "callee_summary_budget_exceeded",
        "unresolved_direct_control",
        "unresolved_indirect_jump",
        "unterminated_control_path",
        "return_inventory_empty",
    } & blockers
    return {
        "status": "complete" if control_complete else "incomplete",
        "preserved_registers": preserved if control_complete else [],
        "reached_units": len(states),
        "transfer_evaluations": evaluations,
        "return_nodes": len(return_states),
        "blocker_codes": sorted(blockers),
    }


def _transfer(
    *,
    unit_id: str,
    unit: Mapping[str, Any],
    state: _State,
    direct_calls: Mapping[tuple[str, int], str],
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
    summaries: Mapping[str, Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    max_stack_words: int,
) -> tuple[_State, set[str]]:
    events = _events(unit)
    calls = [
        (index, event)
        for index, event in enumerate(events)
        if event.get("kind") in _CALL_KINDS
    ]
    if calls:
        if len(calls) != 1:
            return _unknown_state(), {"multiple_calls_in_unit"}
        event_index, event = calls[0]
        pre_call = _event_state(event, state)
        preserved = _call_preserved(
            unit_id=unit_id,
            event_index=event_index,
            event=event,
            direct_calls=direct_calls,
            recovered_calls=recovered_calls,
            summaries=summaries,
            import_abis=import_abis,
        )
        return (
            _State(
                registers={
                    register: (
                        pre_call.registers.get(register)
                        if register in preserved
                        else None
                    )
                    for register in _REGISTERS
                },
                stack_words={},
            ),
            set(),
        )

    semantics = _mapping(unit.get("semantics"))
    writes = semantics.get("register_writes")
    if not isinstance(writes, list):
        return _unknown_state(), {"register_write_inventory_invalid"}
    registers = dict(state.registers)
    for raw in writes:
        write = _mapping(raw)
        register = write.get("register")
        if isinstance(register, str) and register in registers:
            registers[register] = _evaluate(write.get("value"), state)

    stack_words = dict(state.stack_words)
    memory_events = semantics.get("memory_events")
    if not isinstance(memory_events, list):
        stack_words.clear()
    else:
        for raw in memory_events:
            event = _mapping(raw)
            if event.get("kind") != "write":
                continue
            address = _evaluate(event.get("address"), state)
            width = _integer(event.get("width"))
            if isinstance(address, _StackAddress) and width is not None:
                _invalidate_overlapping(stack_words, address.offset, width)
                value = _evaluate(event.get("value"), state)
                if width == 4 and value is not None:
                    stack_words[address.offset] = value
            elif not isinstance(address, _Exact):
                stack_words.clear()
    schedule = _mapping(semantics.get("instruction_effect_schedule"))
    blockers = schedule.get("blockers")
    if isinstance(blockers, list):
        instructions = unit.get("instructions")
        for raw in blockers:
            blocker = _mapping(raw)
            index = _integer(blocker.get("index"))
            if (
                index is None
                or not isinstance(instructions, list)
                or not 0 <= index < len(instructions)
            ):
                registers = {register: None for register in _REGISTERS}
                stack_words.clear()
                continue
            instruction = _mapping(instructions[index])
            written = instruction.get("registers_written")
            if isinstance(written, list):
                for register in written:
                    if isinstance(register, str) and register in registers:
                        registers[register] = None
            operands = instruction.get("operands")
            if isinstance(operands, list) and any(
                isinstance(operand, Mapping)
                and operand.get("kind") == "memory"
                and operand.get("access") in {"write", "read_write"}
                for operand in operands
            ):
                stack_words.clear()
    if len(stack_words) > max_stack_words:
        stack_words.clear()
    return _State(registers=registers, stack_words=stack_words), set()


def _call_preserved(
    *,
    unit_id: str,
    event_index: int,
    event: Mapping[str, Any],
    direct_calls: Mapping[tuple[str, int], str],
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
    summaries: Mapping[str, Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
) -> frozenset[str]:
    kind = event.get("kind")
    if kind == "external_call":
        identity = _event_import_identity(event)
        selected = import_abis.get(identity) if identity is not None else None
        return frozenset(selected.abi.preserved_registers) if selected else frozenset()
    if kind == "internal_call":
        target = direct_calls.get((unit_id, event_index))
        return _summary_preserved(summaries.get(target))
    if kind != "indirect_call":
        return frozenset()
    recovery = recovered_calls.get((unit_id, event_index))
    if recovery is None:
        return frozenset()
    alternatives: list[set[str]] = []
    for external in recovery.get("external_targets", []):
        identity = _event_import_identity(_mapping(external.get("import")))
        selected = import_abis.get(identity) if identity is not None else None
        if selected is None:
            return frozenset()
        alternatives.append(set(selected.abi.preserved_registers))
    for target in recovery.get("target_unit_ids", []):
        summary = summaries.get(str(target))
        if summary is None or summary.get("status") != "complete":
            return frozenset()
        alternatives.append(set(_summary_preserved(summary)))
    if not alternatives:
        return frozenset()
    result = alternatives[0]
    for alternative in alternatives[1:]:
        result &= alternative
    return frozenset(result)


def _summary_preserved(summary: Mapping[str, Any] | None) -> frozenset[str]:
    if summary is None or summary.get("status") != "complete":
        return frozenset()
    raw = summary.get("preserved_registers")
    if not isinstance(raw, list):
        return frozenset()
    return frozenset(str(register) for register in raw if register in _SUMMARY_REGISTERS)


def _event_state(event: Mapping[str, Any], state: _State) -> _State:
    raw = event.get("register_inputs")
    registers = (
        {
            register: _evaluate(raw.get(register), state)
            for register in _REGISTERS
        }
        if isinstance(raw, Mapping)
        else dict(state.registers)
    )
    return _State(registers=registers, stack_words=dict(state.stack_words))


def _evaluate(expression: Any, state: _State) -> _Value:
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op") or "").lower()
    if op in {"reg", "input_reg", "register"}:
        name = expression.get("name", expression.get("reg"))
        return state.registers.get(str(name).lower()) if name is not None else None
    if op in {"const", "constant"}:
        value = _integer(expression.get("value"))
        return _Exact(value & 0xFFFFFFFF) if value is not None else None
    if op in {"add", "add32", "sub", "sub32"}:
        operands = _binary_operands(expression)
        if operands is None:
            return None
        left = _evaluate(operands[0], state)
        right = _evaluate(operands[1], state)
        subtract = op in {"sub", "sub32"}
        if isinstance(left, _Exact) and isinstance(right, _Exact):
            value = left.value - right.value if subtract else left.value + right.value
            return _Exact(value & 0xFFFFFFFF)
        if isinstance(left, _StackAddress) and isinstance(right, _Exact):
            offset = left.offset - right.value if subtract else left.offset + right.value
            return _StackAddress(offset)
        if not subtract and isinstance(left, _Exact) and isinstance(right, _StackAddress):
            return _StackAddress(left.value + right.offset)
        return None
    if op in {"load", "read32", "mem32"}:
        width = expression.get("width", expression.get("width_bits", 4))
        if width not in {4, 32, None}:
            return None
        address = _evaluate(expression.get("address"), state)
        return state.stack_words.get(address.offset) if isinstance(address, _StackAddress) else None
    return None


def _join_states(left: _State, right: _State) -> _State:
    registers = {
        register: (
            left.registers.get(register)
            if left.registers.get(register) == right.registers.get(register)
            else None
        )
        for register in _REGISTERS
    }
    stack_words = {
        offset: value
        for offset, value in left.stack_words.items()
        if value is not None and right.stack_words.get(offset) == value
    }
    return _State(registers=registers, stack_words=stack_words)


def _unknown_state() -> _State:
    return _State(
        registers={register: None for register in _REGISTERS},
        stack_words={},
    )


def _invalidate_overlapping(
    stack_words: dict[int, _Value], start: int, width: int
) -> None:
    end = start + max(width, 0)
    for offset in list(stack_words):
        if offset < end and start < offset + 4:
            del stack_words[offset]


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


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


__all__ = [
    "INTERNAL_CALL_SUMMARY_FORMAT",
    "derive_internal_call_preservation_summaries",
]
