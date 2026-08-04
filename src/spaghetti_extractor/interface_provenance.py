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

from .call_arguments import CallArgumentRecovery, recover_pe32_stack_call_arguments
from .external_interface_profiles import (
    ExternalInterfaceProfile,
    InterfaceFactory,
    InterfaceMethod,
)
from .import_abi import SelectedImportABI
from .machine_abi import MachineCallABI
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
    stack: dict[int, "_StackCell"]


@dataclass(frozen=True, order=True)
class _StackWriteWitness:
    unit_id: str
    event_index: int
    instruction_rva: int | None
    stack_offset: int

    def as_json(self) -> dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            "ordered_event_index": self.event_index,
            "instruction_rva": self.instruction_rva,
            "stack_offset": self.stack_offset,
            "width": 4,
        }


@dataclass(frozen=True)
class _StackCell:
    value: _Value
    witnesses: tuple[_StackWriteWitness, ...]


@dataclass(frozen=True)
class _CallFacts:
    preserved: frozenset[str] | None
    abi: MachineCallABI | None
    argument_words: int | None
    stack_cleanup_bytes: int | None
    outputs: Mapping[_Origin, _Value]


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
    argument_recoveries: list[dict[str, Any]]
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
    internal_call_stack_cleanup: Mapping[int, int] | None = None,
    finite_value_budget: int = 32,
    static_slot_budget: int = 256,
    stack_slot_budget: int = 256,
    fixed_point_budget: int = 16,
) -> dict[str, Any]:
    """Recover finite external method targets from typed interface origins."""

    if min(
        finite_value_budget,
        static_slot_budget,
        stack_slot_budget,
        fixed_point_budget,
    ) <= 0:
        raise ValueError("interface provenance budgets must be positive")
    inventory = _ProfileInventory(profiles)
    call_stack_cleanup = internal_call_stack_cleanup or {}
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
            internal_call_stack_cleanup=call_stack_cleanup,
            image_base=image_base,
            known_slots=known_slots,
            finite_value_budget=finite_value_budget,
            static_slot_budget=static_slot_budget,
            stack_slot_budget=stack_slot_budget,
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
            internal_call_stack_cleanup=call_stack_cleanup,
            image_base=image_base,
            known_slots=known_slots,
            finite_value_budget=finite_value_budget,
            static_slot_budget=static_slot_budget,
            stack_slot_budget=stack_slot_budget,
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
            "ordered inter-unit stack writes and out-parameter updates",
            "external machine-call footprints and successor worlds",
            "static-slot initialization and path invariants",
        ],
        "profiles": [
            {"id": profile.profile_id, "sha256": profile.sha256}
            for profile in sorted(profiles, key=lambda item: item.profile_id)
        ],
        "fixed_point": {"rounds": rounds, "converged": converged},
        "budgets": {
            "finite_values": finite_value_budget,
            "static_slots": static_slot_budget,
            "stack_slots": stack_slot_budget,
            "fixed_point_rounds": fixed_point_budget,
        },
        "static_interface_slots": [
            {
                "address": address,
                "origins": _origins_json(origins),
                "tainted": address in final.tainted_slots,
            }
            for address, origins in sorted(known_slots.items())
        ],
        "resolutions": final.resolutions,
        "call_argument_recoveries": final.argument_recoveries,
        "issues": final.issues,
        "counts": {
            "units": len(units),
            "reached_units": len(final.states),
            "transfer_evaluations": final.evaluations,
            "indirect_exits": len(final.resolutions),
            "recovered_method_exits": recovered,
            "static_interface_slots": len(known_slots),
            "tainted_static_slots": len(final.tainted_slots),
            "call_argument_recoveries": len(final.argument_recoveries),
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
    internal_call_stack_cleanup: Mapping[int, int],
    image_base: int,
    known_slots: Mapping[int, _Value],
    finite_value_budget: int,
    static_slot_budget: int,
    stack_slot_budget: int,
) -> _RunResult:
    unknown_registers = {register: None for register in _REGISTERS}
    unknown_registers["esp"] = _stack_location(0)
    input_states = {
        root: _State(copy.deepcopy(unknown_registers), {}, {}) for root in roots
    }
    work = deque(sorted(roots))
    proposed_slots: dict[int, _Value] = {}
    tainted_slots: set[int] = set()
    issues: list[dict[str, Any]] = []
    argument_recoveries: list[dict[str, Any]] = []
    evaluations = 0
    budget_exceeded = 0
    while work:
        source_id = work.popleft()
        (
            transfer,
            _,
            _,
            _,
            _,
            exceeded,
        ) = _transfer_unit(
            unit_id=source_id,
            unit=by_id[source_id],
            input_state=input_states[source_id],
            inventory=inventory,
            import_abis=import_abis,
            internal_call_preserved_registers=internal_call_preserved_registers,
            internal_call_stack_cleanup=internal_call_stack_cleanup,
            image_base=image_base,
            known_slots=known_slots,
            finite_value_budget=finite_value_budget,
            static_slot_budget=static_slot_budget,
            stack_slot_budget=stack_slot_budget,
        )
        evaluations += 1
        budget_exceeded += exceeded
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
                    contribution = _unknown_state()
                else:
                    contribution = _enter_call_frame(contribution)
            if _join_state(
                input_states,
                edge.target_id,
                contribution,
                finite_value_budget,
                static_slot_budget,
                stack_slot_budget,
            ):
                work.append(edge.target_id)

    # Diagnostics and global-slot proposals must describe the converged input
    # states, not transient worklist states observed on the way to the fixed
    # point.
    for source_id in sorted(input_states):
        (
            _,
            proposals,
            taints,
            transfer_issues,
            unit_argument_recoveries,
            exceeded,
        ) = _transfer_unit(
            unit_id=source_id,
            unit=by_id[source_id],
            input_state=input_states[source_id],
            inventory=inventory,
            import_abis=import_abis,
            internal_call_preserved_registers=internal_call_preserved_registers,
            internal_call_stack_cleanup=internal_call_stack_cleanup,
            image_base=image_base,
            known_slots=known_slots,
            finite_value_budget=finite_value_budget,
            static_slot_budget=static_slot_budget,
            stack_slot_budget=stack_slot_budget,
        )
        evaluations += 1
        budget_exceeded += exceeded
        issues.extend(transfer_issues)
        argument_recoveries.extend(unit_argument_recoveries)
        tainted_slots.update(taints)
        for address, origins in proposals.items():
            proposed_slots[address] = _join_value(
                proposed_slots.get(address),
                origins,
                finite_value_budget,
                missing_is_identity=True,
            )

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
        argument_recoveries=_deduplicate(argument_recoveries),
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
    internal_call_stack_cleanup: Mapping[int, int],
    image_base: int,
    known_slots: Mapping[int, _Value],
    finite_value_budget: int,
    static_slot_budget: int,
    stack_slot_budget: int,
) -> tuple[
    tuple[_State, dict[int, _State]],
    dict[int, _Value],
    set[int],
    list[dict[str, Any]],
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
                unit_id=unit_id,
                unit=unit,
                event_index=event_index,
                inventory=inventory,
                known_slots=known_slots,
                budget=finite_value_budget,
                stack_slot_budget=stack_slot_budget,
            )
    calls = [
        (index, event)
        for index, event in enumerate(events)
        if event.get("kind") in _CALL_KINDS
    ]
    proposals: dict[int, _Value] = {}
    taints: set[int] = set()
    issues: list[dict[str, Any]] = []
    argument_recoveries: list[dict[str, Any]] = []
    if calls:
        if len(calls) != 1:
            issues.append({"code": "multiple_calls_in_interface_unit", "unit_id": unit_id})
            return (
                (_unknown_state(), call_entries),
                proposals,
                taints,
                issues,
                argument_recoveries,
                0,
            )
        event_index, event = calls[0]
        pre_call = call_entries[event_index]
        facts, call_issues, call_argument_recoveries = _call_contract(
            unit_id=unit_id,
            unit=unit,
            event_index=event_index,
            event=event,
            state=input_state,
            pre_call=pre_call,
            inventory=inventory,
            import_abis=import_abis,
            internal_call_preserved_registers=internal_call_preserved_registers,
            internal_call_stack_cleanup=internal_call_stack_cleanup,
            image_base=image_base,
            known_slots=known_slots,
            budget=finite_value_budget,
        )
        issues.extend(call_issues)
        argument_recoveries.extend(call_argument_recoveries)
        output = _State(
            registers={
                register: (
                    pre_call.registers.get(register)
                    if facts.preserved is not None and register in facts.preserved
                    else None
                )
                for register in _REGISTERS
            },
            memory=dict(pre_call.memory),
            stack=dict(pre_call.stack),
        )
        _apply_call_stack_result(output, pre_call, facts)
        for address, origins in facts.outputs.items():
            if address.kind == "exact":
                concrete = int(address.key[0]) & 0xFFFFFFFF
                output.memory[concrete] = origins
                proposals[concrete] = origins
            elif address.kind == "stack_location":
                offset = int(address.key[0])
                output.stack[offset] = _StackCell(origins, ())
        if len(output.stack) > stack_slot_budget:
            output.stack.clear()
            output.registers["esp"] = None
            return (
                (output, call_entries),
                proposals,
                taints,
                issues,
                argument_recoveries,
                1,
            )
        return (
            (output, call_entries),
            proposals,
            taints,
            issues,
            argument_recoveries,
            0,
        )

    output = _State(
        dict(input_state.registers),
        dict(input_state.memory),
        dict(input_state.stack),
    )
    exceeded = 0
    semantics = _mapping(unit.get("semantics"))
    writes = semantics.get("register_writes")
    if not isinstance(writes, list):
        return (
            (_unknown_state(), call_entries),
            proposals,
            taints,
            issues,
            argument_recoveries,
            exceeded,
        )
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
    memory_events = semantics.get("ordered_events")
    if not isinstance(memory_events, list) or not memory_events:
        memory_events = semantics.get("memory_events")
    if isinstance(memory_events, list):
        for memory_event_index, raw in enumerate(memory_events):
            event = _mapping(raw)
            if event.get("kind") != "write" or event.get("width") != 4:
                continue
            addresses = _evaluate(
                event.get("address"),
                input_state,
                inventory=inventory,
                known_slots=known_slots,
                budget=finite_value_budget,
            )
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
            if address.kind == "exact":
                concrete = int(address.key[0]) & 0xFFFFFFFF
                if value is None:
                    output.memory.pop(concrete, None)
                    taints.add(concrete)
                    continue
                output.memory[concrete] = value
                if all(origin.kind == "interface_object" for origin in value):
                    proposals[concrete] = value
                else:
                    taints.add(concrete)
            elif address.kind == "stack_location":
                offset = int(address.key[0])
                if value is None:
                    output.stack.pop(offset, None)
                    continue
                output.stack[offset] = _StackCell(
                    value,
                    (_stack_write_witness(unit_id, memory_event_index, event, offset),),
                )
    _invalidate_schedule_blockers(unit, output)
    if len(output.memory) > static_slot_budget:
        output.memory.clear()
        exceeded += 1
    if len(output.stack) > stack_slot_budget:
        output.stack.clear()
        output.registers["esp"] = None
        exceeded += 1
    return (
        (output, call_entries),
        proposals,
        taints,
        issues,
        argument_recoveries,
        exceeded,
    )


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
    internal_call_stack_cleanup: Mapping[int, int],
    image_base: int,
    known_slots: Mapping[int, _Value],
    budget: int,
) -> tuple[_CallFacts, list[dict[str, Any]], list[dict[str, Any]]]:
    kind = event.get("kind")
    outputs: dict[_Origin, _Value] = {}
    issues: list[dict[str, Any]] = []
    argument_recoveries: list[dict[str, Any]] = []
    if kind == "external_call":
        identity = _event_import_identity(event)
        factory_entry = inventory.factories.get(identity) if identity is not None else None
        selected = import_abis.get(identity) if identity is not None else None
        if factory_entry is None:
            return (
                _CallFacts(
                    frozenset(selected.abi.preserved_registers) if selected else None,
                    selected.abi if selected else None,
                    selected.argument_words if selected else None,
                    None,
                    outputs,
                ),
                issues,
                argument_recoveries,
            )
        profile_sha256, factory = factory_entry
        arguments, recovery = _recover_call_arguments(
            pre_call,
            state,
            unit,
            unit_id=unit_id,
            event_index=event_index,
            argument_words=factory.argument_words,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
        )
        argument_recoveries.append(recovery)
        if recovery["status"] != "complete":
            issues.append({
                "code": "interface_factory_arguments_incomplete",
                "unit_id": unit_id,
                "factory": factory.declaration,
                "failure": recovery["failure"]["code"],
            })
        if arguments is not None:
            outputs.update(_output_effects(
                arguments,
                factory.outputs,
                profile_sha256=profile_sha256,
                issues=issues,
                unit_id=unit_id,
            ))
        return (
            _CallFacts(
                frozenset(factory.abi.preserved_registers),
                factory.abi,
                factory.argument_words,
                None,
                outputs,
            ),
            issues,
            argument_recoveries,
        )
    if kind == "internal_call":
        target_rva = _integer(event.get("target_rva"))
        target_address = (
            None
            if target_rva is None
            else (image_base + target_rva) & 0xFFFFFFFF
        )
        preserved = (
            None
            if target_address is None
            else internal_call_preserved_registers.get(target_address)
        )
        cleanup = (
            None
            if target_address is None
            else internal_call_stack_cleanup.get(target_address)
        )
        return (
            _CallFacts(preserved, None, None, cleanup, outputs),
            issues,
            argument_recoveries,
        )
    if kind != "indirect_call":
        return _CallFacts(None, None, None, None, outputs), issues, argument_recoveries

    targets = _evaluate(
        event.get("target"),
        pre_call,
        inventory=inventory,
        known_slots=known_slots,
        budget=budget,
    )
    methods = _method_origins(targets, inventory)
    if methods is None:
        return _CallFacts(None, None, None, None, outputs), issues, argument_recoveries
    preserved_sets = [set(method.abi.preserved_registers) for _, method in methods]
    preserved = preserved_sets[0]
    for values in preserved_sets[1:]:
        preserved &= values
    common_abi = methods[0][1].abi
    common_argument_words = methods[0][1].argument_words
    if any(
        method.abi != common_abi or method.argument_words != common_argument_words
        for _, method in methods[1:]
    ):
        common_abi = None
        common_argument_words = None
    for profile_sha256, method in methods:
        arguments, recovery = _recover_call_arguments(
            pre_call,
            state,
            unit,
            unit_id=unit_id,
            event_index=event_index,
            argument_words=method.argument_words,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
        )
        recovery["interface_id"] = method.interface_id
        recovery["method"] = method.name
        argument_recoveries.append(recovery)
        if recovery["status"] != "complete":
            issues.append({
                "code": "interface_method_arguments_incomplete",
                "unit_id": unit_id,
                "interface_id": method.interface_id,
                "method": method.name,
                "failure": recovery["failure"]["code"],
            })
        if arguments is None or not method.outputs:
            continue
        outputs.update(_output_effects(
            arguments,
            method.outputs,
            profile_sha256=profile_sha256,
            issues=issues,
            unit_id=unit_id,
        ))
    return (
        _CallFacts(
            frozenset(preserved),
            common_abi,
            common_argument_words,
            None,
            outputs,
        ),
        issues,
        argument_recoveries,
    )


def _recover_call_arguments(
    pre_call: _State,
    input_state: _State,
    unit: Mapping[str, Any],
    *,
    unit_id: str,
    event_index: int,
    argument_words: int,
    inventory: _ProfileInventory,
    known_slots: Mapping[int, _Value],
    budget: int,
) -> tuple[tuple[_Value, ...] | None, dict[str, Any]]:
    local = recover_pe32_stack_call_arguments(
        unit,
        event_index=event_index,
        argument_words=argument_words,
    )
    local_evidence = {
        "status": local.status,
        "failure": local.failure_code,
        "writes": [dict(row) for row in local.evidence],
    }
    offsets = _stack_offsets(pre_call.registers.get("esp"))
    if offsets is None or len(offsets) != 1:
        return _local_or_incomplete_arguments(
            local,
            input_state=input_state,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
            unit_id=unit_id,
            event_index=event_index,
            argument_words=argument_words,
            dataflow_failure="call_esp_origin_unresolved",
            local_evidence=local_evidence,
        )
    call_esp = next(iter(offsets))
    arguments: list[_Value] = []
    evidence: list[dict[str, Any]] = []
    for argument_index in range(argument_words):
        offset = call_esp + argument_index * 4
        cell = pre_call.stack.get(offset)
        if cell is None or cell.value is None:
            return _local_or_incomplete_arguments(
                local,
                input_state=input_state,
                inventory=inventory,
                known_slots=known_slots,
                budget=budget,
                unit_id=unit_id,
                event_index=event_index,
                argument_words=argument_words,
                call_esp=call_esp,
                dataflow_failure="argument_stack_word_missing",
                local_evidence=local_evidence,
            )
        arguments.append(cell.value)
        evidence.append({
            "argument_index": argument_index,
            "stack_offset": offset,
            "origins": _origins_json(cell.value),
            "writes": [witness.as_json() for witness in cell.witnesses],
        })
    return tuple(arguments), _argument_recovery_json(
        unit_id=unit_id,
        event_index=event_index,
        argument_words=argument_words,
        call_esp=call_esp,
        arguments=evidence,
        local_evidence=local_evidence,
        recovery_mode="rooted_inter_unit_stack",
    )


def _local_or_incomplete_arguments(
    local: CallArgumentRecovery,
    *,
    input_state: _State,
    inventory: _ProfileInventory,
    known_slots: Mapping[int, _Value],
    budget: int,
    unit_id: str,
    event_index: int,
    argument_words: int,
    dataflow_failure: str,
    local_evidence: Mapping[str, Any],
    call_esp: int | None = None,
) -> tuple[tuple[_Value, ...] | None, dict[str, Any]]:
    if local.status == "complete":
        values = tuple(
            _evaluate(
                expression,
                input_state,
                inventory=inventory,
                known_slots=known_slots,
                budget=budget,
            )
            for expression in local.arguments
        )
        if all(value is not None for value in values):
            evidence = [
                {
                    "argument_index": index,
                    "stack_offset": None,
                    "origins": _origins_json(value),
                    "writes": [dict(local.evidence[index])],
                }
                for index, value in enumerate(values)
            ]
            return values, _argument_recovery_json(
                unit_id=unit_id,
                event_index=event_index,
                argument_words=argument_words,
                call_esp=call_esp,
                arguments=evidence,
                local_evidence=local_evidence,
                recovery_mode="exact_same_unit",
            )
        evidence = [
            {
                "argument_index": index,
                "stack_offset": None,
                "origins": _origins_json(value),
                "writes": [dict(local.evidence[index])],
            }
            for index, value in enumerate(values)
        ]
        return values, _argument_recovery_json(
            unit_id=unit_id,
            event_index=event_index,
            argument_words=argument_words,
            call_esp=call_esp,
            arguments=evidence,
            failure="local_argument_origin_unresolved",
            local_evidence=local_evidence,
            recovery_mode="exact_same_unit_partial",
        )
    return None, _argument_recovery_json(
        unit_id=unit_id,
        event_index=event_index,
        argument_words=argument_words,
        call_esp=call_esp,
        failure=dataflow_failure,
        local_evidence=local_evidence,
        recovery_mode="incomplete",
    )


def _argument_recovery_json(
    *,
    unit_id: str,
    event_index: int,
    argument_words: int,
    local_evidence: Mapping[str, Any],
    call_esp: int | None = None,
    arguments: Sequence[Mapping[str, Any]] = (),
    failure: str | None = None,
    recovery_mode: str,
) -> dict[str, Any]:
    return {
        "format": "stage-a-pe32-dataflow-call-argument-recovery-v1",
        "status": "complete" if failure is None else "incomplete",
        "proof_authority": False,
        "required_replay": (
            "Lean must replay the rooted stack origin, ordered writes, direct edges, "
            "joins, and exact call-time ESP"
        ),
        "unit_id": unit_id,
        "event_index": event_index,
        "argument_words": argument_words,
        "recovery_mode": recovery_mode,
        "call_esp_stack_offset": call_esp,
        "arguments": [dict(row) for row in arguments],
        "local_exact_recovery": dict(local_evidence),
        "failure": None if failure is None else {"code": failure},
    }


def _apply_call_stack_result(
    output: _State,
    pre_call: _State,
    facts: _CallFacts,
) -> None:
    if facts.stack_cleanup_bytes is not None:
        output.registers["esp"] = _add_stack_offset(
            pre_call.registers.get("esp"), facts.stack_cleanup_bytes
        )
        if output.registers["esp"] is None:
            output.stack.clear()
        return
    if facts.abi is None:
        output.registers["esp"] = None
        output.stack.clear()
        return
    if not facts.abi.callee_cleanup:
        output.registers["esp"] = pre_call.registers.get("esp")
        return
    if facts.argument_words is None:
        output.registers["esp"] = None
        output.stack.clear()
        return
    output.registers["esp"] = _add_stack_offset(
        pre_call.registers.get("esp"),
        facts.argument_words * 4,
    )
    if output.registers["esp"] is None:
        output.stack.clear()


def _enter_call_frame(state: _State) -> _State:
    output = _State(
        dict(state.registers),
        dict(state.memory),
        {},
    )
    # A callee gets an independent relational frame origin. Incoming argument
    # cells are intentionally not inferred until a checked call-frame bridge
    # supplies them.
    output.registers["esp"] = _stack_location(0)
    return output


def _output_effects(
    arguments: Sequence[_Value],
    declarations: Sequence[Any],
    *,
    profile_sha256: str,
    issues: list[dict[str, Any]],
    unit_id: str,
) -> dict[_Origin, _Value]:
    result: dict[_Origin, _Value] = {}
    for output in declarations:
        addresses = arguments[output.argument_index]
        if (
            addresses is None
            or len(addresses) != 1
            or next(iter(addresses)).kind not in {"exact", "stack_location"}
        ):
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
            elif address.kind == "stack_location":
                cell = state.stack.get(int(address.key[0]))
                if cell is None or cell.value is None:
                    return None
                result.update(cell.value)
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
            elif lhs.kind == "stack_location" and rhs.kind == "exact":
                offset = int(lhs.key[0])
                delta = _signed_u32(int(rhs.key[0]))
                result.add(_Origin(
                    "stack_location",
                    (offset - delta if subtract else offset + delta,),
                ))
            elif (
                not subtract
                and lhs.kind == "exact"
                and rhs.kind == "stack_location"
            ):
                result.add(_Origin(
                    "stack_location",
                    (int(rhs.key[0]) + _signed_u32(int(lhs.key[0])),),
                ))
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
    unit_id: str,
    unit: Mapping[str, Any],
    event_index: int,
    inventory: _ProfileInventory,
    known_slots: Mapping[int, _Value],
    budget: int,
    stack_slot_budget: int,
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
    output = _State(registers, dict(state.memory), dict(state.stack))
    ordered = _mapping(unit.get("semantics")).get("ordered_events")
    if not isinstance(ordered, list):
        return output
    external = _events(unit)
    selected_ordinal = sum(
        value.get("kind") in _CALL_KINDS for value in external[:event_index]
    )
    observed_ordinal = 0
    for ordered_index, raw_event in enumerate(ordered):
        ordered_event = _mapping(raw_event)
        kind = ordered_event.get("kind")
        if kind in _CALL_KINDS:
            if observed_ordinal == selected_ordinal:
                break
            observed_ordinal += 1
            continue
        if kind != "write" or ordered_event.get("width") != 4:
            continue
        addresses = _evaluate(
            ordered_event.get("address"),
            state,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
        )
        if addresses is None or len(addresses) != 1:
            continue
        address = next(iter(addresses))
        value = _evaluate(
            ordered_event.get("value"),
            state,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
        )
        if address.kind == "exact":
            concrete = int(address.key[0]) & 0xFFFFFFFF
            if value is None:
                output.memory.pop(concrete, None)
            else:
                output.memory[concrete] = value
        elif address.kind == "stack_location":
            offset = int(address.key[0])
            if value is None:
                output.stack.pop(offset, None)
            else:
                output.stack[offset] = _StackCell(
                    value,
                    (_stack_write_witness(
                        unit_id, ordered_index, ordered_event, offset
                    ),),
                )
    if len(output.stack) > stack_slot_budget:
        output.stack.clear()
        output.registers["esp"] = None
    return output


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
    stack_slot_budget: int,
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
    stack = {
        offset: joined
        for offset in prior.stack.keys() & contribution.stack.keys()
        if (
            joined := _join_stack_cell(
                prior.stack[offset], contribution.stack[offset], value_budget
            )
        ) is not None
    }
    if len(stack) > stack_slot_budget:
        stack = {}
        registers["esp"] = None
    joined_state = _State(registers, memory, stack)
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


def _join_stack_cell(
    left: _StackCell,
    right: _StackCell,
    budget: int,
) -> _StackCell | None:
    value = _join_value(left.value, right.value, budget)
    if value is None:
        return None
    witnesses = tuple(sorted(set(left.witnesses) | set(right.witnesses)))
    return _StackCell(value, witnesses) if len(witnesses) <= budget else None


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
            state.stack.clear()
            continue
        instruction = _mapping(instructions[index])
        written = instruction.get("registers_written")
        if isinstance(written, list):
            for register in written:
                if isinstance(register, str) and register in state.registers:
                    state.registers[register] = None
                    if register == "esp":
                        state.stack.clear()
        operands = instruction.get("operands")
        if isinstance(operands, list) and any(
            isinstance(operand, Mapping)
            and operand.get("kind") == "memory"
            and operand.get("access") in {"write", "read_write"}
            for operand in operands
        ):
            state.memory.clear()
            state.stack.clear()


def _unknown_state() -> _State:
    return _State({register: None for register in _REGISTERS}, {}, {})


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


def _stack_location(offset: int) -> _Value:
    return frozenset({_Origin("stack_location", (offset,))})


def _stack_offsets(origins: _Value) -> set[int] | None:
    if origins is None or any(
        origin.kind != "stack_location" for origin in origins
    ):
        return None
    return {int(origin.key[0]) for origin in origins}


def _add_stack_offset(origins: _Value, delta: int) -> _Value:
    offsets = _stack_offsets(origins)
    if offsets is None:
        return None
    return frozenset(
        _Origin("stack_location", (offset + delta,)) for offset in offsets
    )


def _stack_write_witness(
    unit_id: str,
    event_index: int,
    event: Mapping[str, Any],
    offset: int,
) -> _StackWriteWitness:
    return _StackWriteWitness(
        unit_id=unit_id,
        event_index=event_index,
        instruction_rva=_integer(event.get("instruction_rva")),
        stack_offset=offset,
    )


def _signed_u32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


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
