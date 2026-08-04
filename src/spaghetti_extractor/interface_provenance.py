"""Bounded external-interface value provenance for PE32 machine IR.

The analysis resolves profile-backed vtable calls and proposes typed
out-parameter updates.  It is not proof authority; every target expression,
call argument, memory update, and external frame must be replayed by Stage A.
"""

from __future__ import annotations

import copy
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterable, Mapping, Sequence

from .call_arguments import recover_pe32_stack_call_arguments
from .external_interface_profiles import (
    ExternalInterfaceProfile,
    InterfaceFactory,
    InterfaceMethod,
)
from .import_abi import SelectedImportABI
from .machine_import_profiles import MachineImportIdentity


INTERFACE_PROVENANCE_FORMAT = "stage-a-external-interface-provenance-v1"
_REGISTERS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")
_CALL_KINDS = frozenset({"external_call", "indirect_call", "internal_call"})


@dataclass(frozen=True, order=True)
class _Origin:
    kind: str
    key: tuple[Any, ...]


_Value = frozenset[_Origin] | None


@dataclass
class _State:
    registers: dict[str, _Value]
    memory: dict[int, _Value]


@dataclass(frozen=True)
class _Edge:
    kind: str
    target_id: str
    event_index: int | None = None


@dataclass
class _RunResult:
    states: dict[str, _State]
    resolutions: list[dict[str, Any]]
    proposed_slots: dict[int, _Value]
    tainted_slots: set[int]
    issues: list[dict[str, Any]]
    evaluations: int
    budget_exceeded: int


def recover_external_interface_targets(
    *,
    units: Sequence[Mapping[str, Any]],
    roots: Iterable[str],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    recovered_indirect_edges: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    profiles: Sequence[ExternalInterfaceProfile],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    internal_call_preserved_registers: Mapping[int, frozenset[str]],
    image_base: int,
    finite_value_budget: int = 32,
    static_slot_budget: int = 256,
    fixed_point_budget: int = 16,
) -> dict[str, Any]:
    """Recover finite external method targets from typed interface origins."""

    if min(finite_value_budget, static_slot_budget, fixed_point_budget) <= 0:
        raise ValueError("interface provenance budgets must be positive")
    inventory = _ProfileInventory(profiles)
    by_id = {str(unit["id"]): unit for unit in units}
    if len(by_id) != len(units):
        raise ValueError("interface provenance requires unique unit IDs")
    outgoing = _outgoing_edges(
        by_id,
        direct_edges=direct_edges,
        internal_call_edges=internal_call_edges,
        recovered_indirect_edges=recovered_indirect_edges,
    )
    roots_set = {str(root) for root in roots if str(root) in by_id}
    known_slots: dict[int, _Value] = {}
    final: _RunResult | None = None
    converged = False
    rounds = 0
    for rounds in range(1, fixed_point_budget + 1):
        final = _run_dataflow(
            by_id=by_id,
            roots=roots_set,
            outgoing=outgoing,
            indirect_exits=indirect_exits,
            inventory=inventory,
            import_abis=import_abis,
            internal_call_preserved_registers=internal_call_preserved_registers,
            image_base=image_base,
            known_slots=known_slots,
            finite_value_budget=finite_value_budget,
            static_slot_budget=static_slot_budget,
        )
        proposed = {
            address: origins
            for address, origins in final.proposed_slots.items()
            if address not in final.tainted_slots
            and origins is not None
            and origins
            and all(origin.kind == "interface_object" for origin in origins)
        }
        merged = _merge_slot_facts(
            known_slots, proposed, finite_value_budget, static_slot_budget
        )
        if merged == known_slots:
            converged = True
            break
        known_slots = merged
    assert final is not None
    if known_slots and converged:
        # Emit resolutions against the stable facts rather than the preceding
        # discovery round that first established them.
        final = _run_dataflow(
            by_id=by_id,
            roots=roots_set,
            outgoing=outgoing,
            indirect_exits=indirect_exits,
            inventory=inventory,
            import_abis=import_abis,
            internal_call_preserved_registers=internal_call_preserved_registers,
            image_base=image_base,
            known_slots=known_slots,
            finite_value_budget=finite_value_budget,
            static_slot_budget=static_slot_budget,
        )
    if not converged:
        final.issues.append({
            "code": "interface_provenance_fixed_point_budget_exceeded",
            "rounds": rounds,
        })
    recovered = sum(row["status"] == "recovered" for row in final.resolutions)
    return {
        "format": INTERFACE_PROVENANCE_FORMAT,
        "status": (
            "complete"
            if converged
            and recovered == len(final.resolutions)
            and not final.issues
            else "incomplete"
        ),
        "proof_authority": False,
        "required_replay": [
            "exact expression evaluation and bounded joins",
            "ordered call argument writes and out-parameter updates",
            "external machine-call footprints and successor worlds",
            "static-slot initialization and path invariants",
        ],
        "profiles": [
            {"id": profile.profile_id, "sha256": profile.sha256}
            for profile in sorted(profiles, key=lambda item: item.profile_id)
        ],
        "fixed_point": {"rounds": rounds, "converged": converged},
        "static_interface_slots": [
            {
                "address": address,
                "origins": _origins_json(origins),
                "tainted": address in final.tainted_slots,
            }
            for address, origins in sorted(known_slots.items())
        ],
        "resolutions": final.resolutions,
        "issues": final.issues,
        "counts": {
            "units": len(units),
            "reached_units": len(final.states),
            "transfer_evaluations": final.evaluations,
            "indirect_exits": len(final.resolutions),
            "recovered_method_exits": recovered,
            "static_interface_slots": len(known_slots),
            "tainted_static_slots": len(final.tainted_slots),
            "finite_budget_exceeded": final.budget_exceeded,
            "issues": len(final.issues),
        },
    }


class _ProfileInventory:
    def __init__(self, profiles: Sequence[ExternalInterfaceProfile]) -> None:
        self.profiles = {
            profile.sha256: profile for profile in profiles
        }
        if len(self.profiles) != len(profiles):
            raise ValueError("duplicate external-interface profile")
        self.factories: dict[MachineImportIdentity, tuple[str, InterfaceFactory]] = {}
        self.interfaces: dict[tuple[str, str], Any] = {}
        for profile in profiles:
            for identity, factory in profile.factories_by_identity().items():
                if identity in self.factories:
                    raise ValueError(f"ambiguous interface factory {identity}")
                self.factories[identity] = (profile.sha256, factory)
            for interface_id, interface in profile.interfaces_by_id().items():
                key = (profile.sha256, interface_id)
                self.interfaces[key] = interface

    def method(
        self, profile_sha256: str, interface_id: str, offset: int
    ) -> InterfaceMethod | None:
        interface = self.interfaces.get((profile_sha256, interface_id))
        return None if interface is None else interface.method_at_offset(offset)

    def profile(self, profile_sha256: str) -> ExternalInterfaceProfile:
        return self.profiles[profile_sha256]


def _run_dataflow(
    *,
    by_id: Mapping[str, Mapping[str, Any]],
    roots: set[str],
    outgoing: Mapping[str, set[_Edge]],
    indirect_exits: Sequence[Mapping[str, Any]],
    inventory: _ProfileInventory,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    internal_call_preserved_registers: Mapping[int, frozenset[str]],
    image_base: int,
    known_slots: Mapping[int, _Value],
    finite_value_budget: int,
    static_slot_budget: int,
) -> _RunResult:
    unknown_registers = {register: None for register in _REGISTERS}
    input_states = {
        root: _State(copy.deepcopy(unknown_registers), {}) for root in roots
    }
    work = deque(sorted(roots))
    proposed_slots: dict[int, _Value] = {}
    tainted_slots: set[int] = set()
    issues: list[dict[str, Any]] = []
    evaluations = 0
    budget_exceeded = 0
    while work:
        source_id = work.popleft()
        transfer, proposals, taints, transfer_issues, exceeded = _transfer_unit(
            unit_id=source_id,
            unit=by_id[source_id],
            input_state=input_states[source_id],
            inventory=inventory,
            import_abis=import_abis,
            internal_call_preserved_registers=internal_call_preserved_registers,
            image_base=image_base,
            known_slots=known_slots,
            finite_value_budget=finite_value_budget,
            static_slot_budget=static_slot_budget,
        )
        evaluations += 1
        budget_exceeded += exceeded
        issues.extend(transfer_issues)
        tainted_slots.update(taints)
        for address, origins in proposals.items():
            proposed_slots[address] = _join_value(
                proposed_slots.get(address), origins, finite_value_budget,
                missing_is_identity=True,
            )
        for edge in sorted(
            outgoing.get(source_id, ()),
            key=lambda item: (item.target_id, item.kind, item.event_index or -1),
        ):
            contribution = transfer[0]
            if edge.kind in {"internal_call", "indirect_call"}:
                index = edge.event_index
                contribution = (
                    transfer[1].get(index)
                    if index is not None
                    else None
                )
                if contribution is None:
                    contribution = _State(copy.deepcopy(unknown_registers), {})
            if _join_state(
                input_states,
                edge.target_id,
                contribution,
                finite_value_budget,
                static_slot_budget,
            ):
                work.append(edge.target_id)

    resolutions = _resolve_exits(
        indirect_exits,
        by_id=by_id,
        states=input_states,
        inventory=inventory,
        known_slots=known_slots,
        finite_value_budget=finite_value_budget,
    )
    return _RunResult(
        states=input_states,
        resolutions=resolutions,
        proposed_slots=proposed_slots,
        tainted_slots=tainted_slots,
        issues=_deduplicate(issues),
        evaluations=evaluations,
        budget_exceeded=budget_exceeded,
    )


def _transfer_unit(
    *,
    unit_id: str,
    unit: Mapping[str, Any],
    input_state: _State,
    inventory: _ProfileInventory,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    internal_call_preserved_registers: Mapping[int, frozenset[str]],
    image_base: int,
    known_slots: Mapping[int, _Value],
    finite_value_budget: int,
    static_slot_budget: int,
) -> tuple[
    tuple[_State, dict[int, _State]],
    dict[int, _Value],
    set[int],
    list[dict[str, Any]],
    int,
]:
    events = _events(unit)
    call_entries: dict[int, _State] = {}
    for event_index, event in enumerate(events):
        if event.get("kind") in _CALL_KINDS:
            call_entries[event_index] = _event_state(
                event,
                input_state,
                inventory=inventory,
                known_slots=known_slots,
                budget=finite_value_budget,
            )
    calls = [
        (index, event)
        for index, event in enumerate(events)
        if event.get("kind") in _CALL_KINDS
    ]
    proposals: dict[int, _Value] = {}
    taints: set[int] = set()
    issues: list[dict[str, Any]] = []
    if calls:
        if len(calls) != 1:
            issues.append({"code": "multiple_calls_in_interface_unit", "unit_id": unit_id})
            return (
                (_unknown_state(), call_entries),
                proposals,
                taints,
                issues,
                0,
            )
        event_index, event = calls[0]
        pre_call = call_entries[event_index]
        preserved, outputs, call_issues = _call_contract(
            unit_id=unit_id,
            unit=unit,
            event_index=event_index,
            event=event,
            state=input_state,
            pre_call=pre_call,
            inventory=inventory,
            import_abis=import_abis,
            internal_call_preserved_registers=internal_call_preserved_registers,
            image_base=image_base,
            known_slots=known_slots,
            budget=finite_value_budget,
        )
        issues.extend(call_issues)
        output = _State(
            registers={
                register: (
                    pre_call.registers.get(register)
                    if preserved is not None and register in preserved
                    else None
                )
                for register in _REGISTERS
            },
            memory=dict(input_state.memory),
        )
        for address, origins in outputs.items():
            output.memory[address] = origins
            proposals[address] = origins
        return (output, call_entries), proposals, taints, issues, 0

    output = _State(dict(input_state.registers), dict(input_state.memory))
    exceeded = 0
    semantics = _mapping(unit.get("semantics"))
    writes = semantics.get("register_writes")
    if not isinstance(writes, list):
        return (_unknown_state(), call_entries), proposals, taints, issues, exceeded
    for raw in writes:
        write = _mapping(raw)
        register = write.get("register")
        if not isinstance(register, str) or register not in output.registers:
            continue
        value = _evaluate(
            write.get("value"),
            input_state,
            inventory=inventory,
            known_slots=known_slots,
            budget=finite_value_budget,
        )
        if value is not None and len(value) > finite_value_budget:
            value = None
            exceeded += 1
        output.registers[register] = value
    memory_events = semantics.get("memory_events")
    if isinstance(memory_events, list):
        for raw in memory_events:
            event = _mapping(raw)
            if event.get("kind") != "write" or event.get("width") != 4:
                continue
            addresses = _exact_values(_evaluate(
                event.get("address"),
                input_state,
                inventory=inventory,
                known_slots=known_slots,
                budget=finite_value_budget,
            ))
            if addresses is None or len(addresses) != 1:
                continue
            address = next(iter(addresses))
            value = _evaluate(
                event.get("value"),
                input_state,
                inventory=inventory,
                known_slots=known_slots,
                budget=finite_value_budget,
            )
            if value is None:
                output.memory.pop(address, None)
                taints.add(address)
                continue
            output.memory[address] = value
            if all(origin.kind == "interface_object" for origin in value):
                proposals[address] = value
            else:
                taints.add(address)
    _invalidate_schedule_blockers(unit, output)
    if len(output.memory) > static_slot_budget:
        output.memory.clear()
        exceeded += 1
    return (output, call_entries), proposals, taints, issues, exceeded


def _call_contract(
    *,
    unit_id: str,
    unit: Mapping[str, Any],
    event_index: int,
    event: Mapping[str, Any],
    state: _State,
    pre_call: _State,
    inventory: _ProfileInventory,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    internal_call_preserved_registers: Mapping[int, frozenset[str]],
    image_base: int,
    known_slots: Mapping[int, _Value],
    budget: int,
) -> tuple[frozenset[str] | None, dict[int, _Value], list[dict[str, Any]]]:
    kind = event.get("kind")
    outputs: dict[int, _Value] = {}
    issues: list[dict[str, Any]] = []
    if kind == "external_call":
        identity = _event_import_identity(event)
        factory_entry = inventory.factories.get(identity) if identity is not None else None
        selected = import_abis.get(identity) if identity is not None else None
        if factory_entry is None:
            return (
                frozenset(selected.abi.preserved_registers) if selected else None,
                outputs,
                issues,
            )
        profile_sha256, factory = factory_entry
        recovery = recover_pe32_stack_call_arguments(
            unit,
            event_index=event_index,
            argument_words=factory.argument_words,
        )
        if recovery.status != "complete":
            issues.append({
                "code": "interface_factory_arguments_incomplete",
                "unit_id": unit_id,
                "factory": factory.declaration,
                "failure": recovery.failure_code,
            })
        else:
            outputs.update(_output_effects(
                recovery.arguments,
                factory.outputs,
                state=state,
                profile_sha256=profile_sha256,
                inventory=inventory,
                known_slots=known_slots,
                budget=budget,
                issues=issues,
                unit_id=unit_id,
            ))
        return frozenset(factory.abi.preserved_registers), outputs, issues
    if kind == "internal_call":
        target_rva = _integer(event.get("target_rva"))
        preserved = (
            None
            if target_rva is None
            else internal_call_preserved_registers.get(
                (image_base + target_rva) & 0xFFFFFFFF
            )
        )
        return preserved, outputs, issues
    if kind != "indirect_call":
        return None, outputs, issues

    targets = _evaluate(
        event.get("target"),
        pre_call,
        inventory=inventory,
        known_slots=known_slots,
        budget=budget,
    )
    methods = _method_origins(targets, inventory)
    if methods is None:
        return None, outputs, issues
    preserved_sets = [set(method.abi.preserved_registers) for _, method in methods]
    preserved = preserved_sets[0]
    for values in preserved_sets[1:]:
        preserved &= values
    for profile_sha256, method in methods:
        if not method.outputs:
            continue
        recovery = recover_pe32_stack_call_arguments(
            unit,
            event_index=event_index,
            argument_words=method.argument_words,
        )
        if recovery.status != "complete":
            issues.append({
                "code": "interface_method_arguments_incomplete",
                "unit_id": unit_id,
                "interface_id": method.interface_id,
                "method": method.name,
                "failure": recovery.failure_code,
            })
            continue
        outputs.update(_output_effects(
            recovery.arguments,
            method.outputs,
            state=state,
            profile_sha256=profile_sha256,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
            issues=issues,
            unit_id=unit_id,
        ))
    return frozenset(preserved), outputs, issues


def _output_effects(
    arguments: Sequence[Any],
    declarations: Sequence[Any],
    *,
    state: _State,
    profile_sha256: str,
    inventory: _ProfileInventory,
    known_slots: Mapping[int, _Value],
    budget: int,
    issues: list[dict[str, Any]],
    unit_id: str,
) -> dict[int, _Value]:
    result: dict[int, _Value] = {}
    for output in declarations:
        addresses = _exact_values(_evaluate(
            arguments[output.argument_index],
            state,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
        ))
        if addresses is None or len(addresses) != 1:
            issues.append({
                "code": "interface_out_pointer_unresolved",
                "unit_id": unit_id,
                "argument_index": output.argument_index,
                "interface_id": output.interface_id,
            })
            continue
        address = next(iter(addresses))
        result[address] = frozenset({
            _Origin("interface_object", (profile_sha256, output.interface_id))
        })
    return result


def _resolve_exits(
    indirect_exits: Sequence[Mapping[str, Any]],
    *,
    by_id: Mapping[str, Mapping[str, Any]],
    states: Mapping[str, _State],
    inventory: _ProfileInventory,
    known_slots: Mapping[int, _Value],
    finite_value_budget: int,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for exit_record in sorted(indirect_exits, key=lambda row: str(row.get("id") or "")):
        source = str(exit_record.get("source_unit_id") or "")
        identity = str(exit_record.get("id") or _stable_id(exit_record))
        state = states.get(source)
        target = exit_record.get("target_expression")
        event_index = _integer(exit_record.get("source_event_index"))
        if state is not None and source in by_id and event_index is not None:
            events = _events(by_id[source])
            if 0 <= event_index < len(events):
                target = events[event_index].get("target")
        origins = (
            None
            if state is None
            else _evaluate(
                target,
                state,
                inventory=inventory,
                known_slots=known_slots,
                budget=finite_value_budget,
            )
        )
        methods = _method_origins(origins, inventory)
        base = {
            "id": identity,
            "source_unit_id": source,
            "source_rva": exit_record.get("source_rva"),
            "source_event_index": exit_record.get("source_event_index"),
            "kind": exit_record.get("kind"),
            "target_rvas": [],
            "target_unit_ids": [],
        }
        if methods is None:
            result.append({
                **base,
                "status": "incomplete",
                "closure": "unresolved",
                "external_targets": [],
                "failure": {"code": "interface_method_origin_unresolved"},
            })
            continue
        targets = []
        for profile_sha256, method in methods:
            profile = inventory.profile(profile_sha256)
            targets.append(method.target_json(
                profile_id=profile.profile_id,
                profile_sha256=profile.sha256,
            ))
        result.append({
            **base,
            "status": "recovered",
            "closure": "checked_profile_interface_method_inventory",
            "external_targets": sorted(
                targets,
                key=lambda row: (
                    row["external_protocol"]["profile_sha256"],
                    row["external_protocol"]["interface_id"],
                    row["external_protocol"]["slot"],
                ),
            ),
            "origin_count": len(origins or ()),
            "failure": None,
        })
    return result


def _evaluate(
    expression: Any,
    state: _State,
    *,
    inventory: _ProfileInventory,
    known_slots: Mapping[int, _Value],
    budget: int,
) -> _Value:
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op") or "").lower()
    if op in {"reg", "input_reg", "register"}:
        name = expression.get("name", expression.get("reg"))
        return state.registers.get(str(name).lower()) if name is not None else None
    if op in {"const", "constant"}:
        value = _integer(expression.get("value"))
        return (
            None
            if value is None
            else frozenset({_Origin("exact", (value & 0xFFFFFFFF,))})
        )
    if op in {"add", "add32", "sub", "sub32"}:
        operands = _binary_operands(expression)
        if operands is None:
            return None
        left = _evaluate(
            operands[0], state, inventory=inventory, known_slots=known_slots, budget=budget
        )
        right = _evaluate(
            operands[1], state, inventory=inventory, known_slots=known_slots, budget=budget
        )
        return _add_values(left, right, subtract=op in {"sub", "sub32"}, budget=budget)
    if op in {"load", "read32", "mem32"}:
        width = expression.get("width", expression.get("width_bits", 4))
        if width not in {4, 32, None}:
            return None
        addresses = _evaluate(
            expression.get("address"),
            state,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
        )
        if addresses is None:
            return None
        result: set[_Origin] = set()
        for address in addresses:
            if address.kind == "exact":
                concrete = int(address.key[0]) & 0xFFFFFFFF
                value = state.memory.get(concrete, known_slots.get(concrete))
                if value is None:
                    return None
                result.update(value)
            elif address.kind == "interface_object":
                result.add(_Origin("interface_vtable", address.key))
            elif address.kind == "interface_vtable":
                profile_sha256, interface_id = address.key
                method = inventory.method(
                    str(profile_sha256), str(interface_id), 0
                )
                if method is None:
                    return None
                result.add(_Origin(
                    "interface_method",
                    (profile_sha256, interface_id, method.slot),
                ))
            elif address.kind == "interface_slot":
                profile_sha256, interface_id, offset = address.key
                method = inventory.method(
                    str(profile_sha256), str(interface_id), int(offset)
                )
                if method is None:
                    return None
                result.add(_Origin(
                    "interface_method",
                    (profile_sha256, interface_id, method.slot),
                ))
            else:
                return None
        return frozenset(result) if result and len(result) <= budget else None
    return None


def _add_values(
    left: _Value, right: _Value, *, subtract: bool, budget: int
) -> _Value:
    if left is None or right is None or len(left) * len(right) > budget:
        return None
    result: set[_Origin] = set()
    for lhs in left:
        for rhs in right:
            if lhs.kind == "exact" and rhs.kind == "exact":
                value = (
                    int(lhs.key[0]) - int(rhs.key[0])
                    if subtract
                    else int(lhs.key[0]) + int(rhs.key[0])
                )
                result.add(_Origin("exact", (value & 0xFFFFFFFF,)))
            elif not subtract and lhs.kind == "interface_vtable" and rhs.kind == "exact":
                result.add(_Origin("interface_slot", (*lhs.key, int(rhs.key[0]))))
            elif not subtract and lhs.kind == "exact" and rhs.kind == "interface_vtable":
                result.add(_Origin("interface_slot", (*rhs.key, int(lhs.key[0]))))
            else:
                return None
    return frozenset(result) if result and len(result) <= budget else None


def _method_origins(
    origins: _Value, inventory: _ProfileInventory
) -> list[tuple[str, InterfaceMethod]] | None:
    if origins is None or not origins:
        return None
    result: dict[tuple[str, str, int], tuple[str, InterfaceMethod]] = {}
    for origin in origins:
        if origin.kind != "interface_method":
            return None
        profile_sha256, interface_id, slot = origin.key
        method = inventory.method(
            str(profile_sha256), str(interface_id), int(slot) * 4
        )
        if method is None:
            return None
        result[(str(profile_sha256), str(interface_id), int(slot))] = (
            str(profile_sha256), method
        )
    return [result[key] for key in sorted(result)]


def _event_state(
    event: Mapping[str, Any],
    state: _State,
    *,
    inventory: _ProfileInventory,
    known_slots: Mapping[int, _Value],
    budget: int,
) -> _State:
    raw = event.get("register_inputs")
    registers = (
        {
            register: _evaluate(
                raw.get(register),
                state,
                inventory=inventory,
                known_slots=known_slots,
                budget=budget,
            )
            for register in _REGISTERS
        }
        if isinstance(raw, Mapping)
        else dict(state.registers)
    )
    return _State(registers, dict(state.memory))


def _outgoing_edges(
    by_id: Mapping[str, Mapping[str, Any]],
    *,
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    recovered_indirect_edges: Sequence[Mapping[str, Any]],
) -> dict[str, set[_Edge]]:
    result: dict[str, set[_Edge]] = defaultdict(set)
    for raw in direct_edges:
        source = raw.get("source_unit_id")
        target = raw.get("target_unit_id", raw.get("resolved_unit_id"))
        if isinstance(source, str) and isinstance(target, str) and source in by_id and target in by_id:
            result[source].add(_Edge("direct", target))
    for raw in internal_call_edges:
        source = raw.get("source_unit_id")
        target = raw.get("target_unit_id", raw.get("resolved_unit_id"))
        event_index = _integer(raw.get("source_event_index"))
        if isinstance(source, str) and isinstance(target, str) and source in by_id and target in by_id:
            result[source].add(_Edge("internal_call", target, event_index))
    for raw in recovered_indirect_edges:
        if raw.get("status") != "recovered":
            continue
        source = raw.get("source_unit_id")
        targets = raw.get("target_unit_ids")
        event_index = _integer(raw.get("source_event_index"))
        if not isinstance(source, str) or not isinstance(targets, Sequence):
            continue
        kind = "indirect_call" if raw.get("kind") == "indirect_call" else "direct"
        for target in targets:
            if isinstance(target, str) and source in by_id and target in by_id:
                result[source].add(_Edge(kind, target, event_index))
    return result


def _join_state(
    states: dict[str, _State],
    target: str,
    contribution: _State,
    value_budget: int,
    slot_budget: int,
) -> bool:
    prior = states.get(target)
    if prior is None:
        states[target] = copy.deepcopy(contribution)
        return True
    registers = {
        register: _join_value(
            prior.registers.get(register),
            contribution.registers.get(register),
            value_budget,
        )
        for register in _REGISTERS
    }
    memory = {
        address: joined
        for address in prior.memory.keys() & contribution.memory.keys()
        if (
            joined := _join_value(
                prior.memory[address], contribution.memory[address], value_budget
            )
        ) is not None
    }
    if len(memory) > slot_budget:
        memory = {}
    joined_state = _State(registers, memory)
    if joined_state == prior:
        return False
    states[target] = joined_state
    return True


def _join_value(
    left: _Value,
    right: _Value,
    budget: int,
    *,
    missing_is_identity: bool = False,
) -> _Value:
    if missing_is_identity:
        if left is None:
            return right
        if right is None:
            return left
    if left is None or right is None:
        return None
    result = left | right
    return result if len(result) <= budget else None


def _merge_slot_facts(
    left: Mapping[int, _Value],
    right: Mapping[int, _Value],
    value_budget: int,
    slot_budget: int,
) -> dict[int, _Value]:
    result = dict(left)
    for address, origins in right.items():
        result[address] = _join_value(
            result.get(address), origins, value_budget, missing_is_identity=True
        )
    return result if len(result) <= slot_budget else {}


def _invalidate_schedule_blockers(unit: Mapping[str, Any], state: _State) -> None:
    semantics = _mapping(unit.get("semantics"))
    schedule = _mapping(semantics.get("instruction_effect_schedule"))
    blockers = schedule.get("blockers")
    instructions = unit.get("instructions")
    if not isinstance(blockers, list):
        return
    for raw in blockers:
        index = _integer(_mapping(raw).get("index"))
        if (
            index is None
            or not isinstance(instructions, list)
            or not 0 <= index < len(instructions)
        ):
            state.registers = {register: None for register in _REGISTERS}
            state.memory.clear()
            continue
        instruction = _mapping(instructions[index])
        written = instruction.get("registers_written")
        if isinstance(written, list):
            for register in written:
                if isinstance(register, str) and register in state.registers:
                    state.registers[register] = None
        operands = instruction.get("operands")
        if isinstance(operands, list) and any(
            isinstance(operand, Mapping)
            and operand.get("kind") == "memory"
            and operand.get("access") in {"write", "read_write"}
            for operand in operands
        ):
            state.memory.clear()


def _unknown_state() -> _State:
    return _State({register: None for register in _REGISTERS}, {})


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


def _exact_values(origins: _Value) -> set[int] | None:
    if origins is None or any(origin.kind != "exact" for origin in origins):
        return None
    return {int(origin.key[0]) & 0xFFFFFFFF for origin in origins}


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


def _origins_json(origins: _Value) -> list[dict[str, Any]]:
    if origins is None:
        return []
    return [
        {"kind": origin.kind, "key": list(origin.key)}
        for origin in sorted(origins)
    ]


def _deduplicate(values: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows = {
        json.dumps(value, sort_keys=True, separators=(",", ":")): dict(value)
        for value in values
    }
    return [rows[key] for key in sorted(rows)]


def _stable_id(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return f"interface-exit:{sha256(encoded).hexdigest()[:20]}"


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


__all__ = [
    "INTERFACE_PROVENANCE_FORMAT",
    "recover_external_interface_targets",
]
