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
from typing import Any, Callable, Iterable, Mapping, Sequence

from .call_arguments import CallArgumentRecovery, recover_pe32_stack_call_arguments
from .external_interface_profiles import (
    ExternalInterfaceProfile,
    InterfaceFactory,
    InterfaceMethod,
)
from .external_operation_profiles import (
    DiscriminatorOutputView,
    ExternalOperation,
    ExternalOperationContract,
    ExternalOperationProfile,
    FixedOutputView,
    OutArgumentOperationOutput,
    OutArgumentOutput,
    ReturnRegisterOperationOutput,
    ReturnRegisterOutput,
    SuccessGuard,
)
from .import_abi import SelectedImportABI
from .machine_abi import MachineCallABI
from .machine_import_profiles import MachineImportIdentity
from .provenance_domain import (
    FiniteValue,
    ValueOrigin,
    join_finite_values,
)


INTERFACE_PROVENANCE_FORMAT = "stage-a-external-interface-provenance-v1"
_REGISTERS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")
_CALL_KINDS = frozenset({"external_call", "indirect_call", "internal_call"})


_Origin = ValueOrigin
_Value = FiniteValue


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
    guard_json: str | None = None


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
    operation_profiles: Sequence[ExternalOperationProfile] = (),
    imports: Sequence[Mapping[str, Any]] = (),
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    internal_call_preserved_registers: Mapping[int, frozenset[str]],
    image_base: int,
    internal_call_stack_cleanup: Mapping[int, int] | None = None,
    finite_value_budget: int = 32,
    static_slot_budget: int = 256,
    stack_slot_budget: int = 256,
    fixed_point_budget: int = 16,
    static_data_reader: Callable[[int, int], bytes | None] | None = None,
) -> dict[str, Any]:
    """Recover finite external method targets from typed interface origins."""

    if min(
        finite_value_budget,
        static_slot_budget,
        stack_slot_budget,
        fixed_point_budget,
    ) <= 0:
        raise ValueError("interface provenance budgets must be positive")
    call_stack_cleanup = internal_call_stack_cleanup or {}
    by_id = {str(unit["id"]): unit for unit in units}
    if len(by_id) != len(units):
        raise ValueError("interface provenance requires unique unit IDs")
    inventory = _ProfileInventory(
        profiles,
        operation_profiles=operation_profiles,
        imports=imports,
        units=units,
        image_base=image_base,
        static_data_reader=static_data_reader,
    )
    outgoing = _outgoing_edges(
        by_id,
        direct_edges=direct_edges,
        internal_call_edges=internal_call_edges,
        recovered_indirect_edges=recovered_indirect_edges,
    )
    recovered_calls = _recovered_call_inventory(recovered_indirect_edges)
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
            recovered_calls=recovered_calls,
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
            and all(_persistent_origin(origin) for origin in origins)
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
            recovered_calls=recovered_calls,
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
    recovered_interface = sum(
        row["status"] == "recovered"
        and "interface_operation" in row.get("origin_kinds", [])
        for row in final.resolutions
    )
    recovered_operation = sum(
        row["status"] == "recovered"
        and "profile_operation" in row.get("origin_kinds", [])
        for row in final.resolutions
    )
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
            {
                "id": profile.profile_id,
                "sha256": profile.sha256,
                "kind": "interface-v1",
            }
            for profile in sorted(profiles, key=lambda item: item.profile_id)
        ] + [
            {
                "id": profile.profile_id,
                "sha256": profile.sha256,
                "kind": "operation-v2",
            }
            for profile in sorted(
                operation_profiles, key=lambda item: item.profile_id
            )
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
            "recovered_method_exits": recovered_interface,
            "recovered_operation_exits": recovered_operation,
            "recovered_indirect_exits": recovered,
            "static_interface_slots": len(known_slots),
            "static_value_slots": len(known_slots),
            "tainted_static_slots": len(final.tainted_slots),
            "call_argument_recoveries": len(final.argument_recoveries),
            "finite_budget_exceeded": final.budget_exceeded,
            "issues": len(final.issues),
        },
    }


class _ProfileInventory:
    def __init__(
        self,
        profiles: Sequence[ExternalInterfaceProfile],
        *,
        operation_profiles: Sequence[ExternalOperationProfile],
        imports: Sequence[Mapping[str, Any]],
        units: Sequence[Mapping[str, Any]],
        image_base: int,
        static_data_reader: Callable[[int, int], bytes | None] | None,
    ) -> None:
        self.profiles = {
            profile.sha256: profile for profile in profiles
        }
        if len(self.profiles) != len(profiles):
            raise ValueError("duplicate external-interface profile")
        self.factories: dict[MachineImportIdentity, tuple[str, InterfaceFactory]] = {}
        self.interfaces: dict[tuple[str, str], Any] = {}
        self.iat: dict[int, MachineImportIdentity] = {}
        self.unit_targets: dict[int, list[tuple[int, str]]] = defaultdict(list)
        self.static_data_reader = static_data_reader
        all_operation_profiles = list(operation_profiles)
        self.operation_profiles = {
            profile.sha256: profile for profile in all_operation_profiles
        }
        if len(self.operation_profiles) != len(all_operation_profiles):
            raise ValueError("duplicate external-operation profile")
        self.operation_imports: dict[
            MachineImportIdentity, tuple[str, ExternalOperation]
        ] = {}
        self.operation_views: dict[tuple[str, str], ExternalOperationProfile] = {}
        for profile in all_operation_profiles:
            for view in profile.table_views:
                self.operation_views[(profile.sha256, view.view_id)] = profile
            for selector in profile.selectors:
                identity = getattr(selector, "identity", None)
                if not isinstance(identity, MachineImportIdentity):
                    continue
                operation = profile.operations_by_id()[selector.operation_id]
                if identity in self.operation_imports:
                    raise ValueError(f"ambiguous external operation import {identity}")
                self.operation_imports[identity] = (profile.sha256, operation)
        for profile in profiles:
            for identity, factory in profile.factories_by_identity().items():
                if identity in self.factories:
                    raise ValueError(f"ambiguous interface factory {identity}")
                self.factories[identity] = (profile.sha256, factory)
            for interface_id, interface in profile.interfaces_by_id().items():
                key = (profile.sha256, interface_id)
                self.interfaces[key] = interface
        for raw in imports:
            imported = _mapping(raw)
            dll = imported.get("dll")
            symbol = imported.get("symbol")
            ordinal = _integer(imported.get("ordinal"))
            thunk_rva = _integer(imported.get("thunk_rva"))
            if not isinstance(dll, str) or thunk_rva is None:
                continue
            identity = (
                MachineImportIdentity(dll.lower(), "symbol", symbol)
                if isinstance(symbol, str) and symbol
                else MachineImportIdentity(dll.lower(), "ordinal", ordinal)
                if ordinal is not None
                else None
            )
            if identity is None:
                continue
            address = (image_base + thunk_rva) & 0xFFFFFFFF
            if address in self.iat and self.iat[address] != identity:
                raise ValueError(f"ambiguous IAT cell at 0x{address:08x}")
            self.iat[address] = identity
        for unit in units:
            source = _mapping(_mapping(unit.get("source")).get("original"))
            rva = _integer(source.get("rva_start"))
            identifier = unit.get("id")
            if rva is not None and isinstance(identifier, str):
                self.unit_targets[(image_base + rva) & 0xFFFFFFFF].append(
                    (rva, identifier)
                )

    def method(
        self, profile_sha256: str, interface_id: str, offset: int
    ) -> InterfaceMethod | None:
        interface = self.interfaces.get((profile_sha256, interface_id))
        return None if interface is None else interface.method_at_offset(offset)

    def profile(self, profile_sha256: str) -> ExternalInterfaceProfile:
        return self.profiles[profile_sha256]

    def operation_for_slot(
        self, profile_sha256: str, view_id: str, offset: int
    ) -> ExternalOperation | None:
        if offset < 0 or offset % 4:
            return None
        profile = self.operation_views.get((profile_sha256, view_id))
        return (
            None
            if profile is None
            else profile.operation_for_table_slot(view_id, offset // 4)
        )

    def operation_view_access(
        self, profile_sha256: str, view_id: str
    ) -> str | None:
        profile = self.operation_views.get((profile_sha256, view_id))
        if profile is None:
            return None
        view = profile.views_by_id().get(view_id)
        return None if view is None else view.access

    def operation(
        self, profile_sha256: str, operation_id: str
    ) -> ExternalOperation | None:
        profile = self.operation_profiles.get(profile_sha256)
        return (
            None
            if profile is None
            else profile.operations_by_id().get(operation_id)
        )

    def operation_for_resolver_result(
        self,
        profile_sha256: str,
        resolver_operation_id: str,
        result_id: str,
    ) -> ExternalOperation | None:
        profile = self.operation_profiles.get(profile_sha256)
        return (
            None
            if profile is None
            else profile.operation_for_resolver_result(
                resolver_operation_id, result_id
            )
        )

    def operation_target_json(
        self, profile_sha256: str, operation: ExternalOperation
    ) -> dict[str, Any]:
        profile = self.operation_profiles[profile_sha256]
        selectors = profile.selectors_by_operation_id()[operation.operation_id]
        contract = profile.contracts_by_id()[operation.environment_contract_id]
        return {
            "external_protocol": {
                "kind": "pe32-operation",
                "profile_id": profile.profile_id,
                "profile_sha256": profile.sha256,
                "operation_id": operation.operation_id,
                "transfer_kind": "call",
                "selectors": [selector.as_json() for selector in selectors],
                "environment_contract_id": operation.environment_contract_id,
            },
            "abi": operation.abi.as_json(),
            "argument_words": operation.argument_words,
            "output_rules": [rule.as_json() for rule in operation.output_rules],
            "environment_contract": contract.as_json(),
        }

    def operation_contract(
        self, profile_sha256: str, operation: ExternalOperation
    ) -> ExternalOperationContract:
        profile = self.operation_profiles[profile_sha256]
        return profile.contracts_by_id()[operation.environment_contract_id]


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
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
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
            recovered_calls=recovered_calls,
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
            key=lambda item: (
                item.target_id,
                item.kind,
                item.event_index or -1,
                item.guard_json or "",
            ),
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
            if edge.guard_json is not None:
                contribution = _refine_state_for_guard(
                    contribution,
                    json.loads(edge.guard_json),
                )
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
            recovered_calls=recovered_calls,
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
        import_abis=import_abis,
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
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
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
            recovered_calls=recovered_calls,
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
            elif address.kind == "register_location":
                register = str(address.key[0])
                if register in output.registers:
                    output.registers[register] = origins
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
                if all(_persistent_origin(origin) for origin in value):
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
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
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
        operation_entry = (
            inventory.operation_imports.get(identity)
            if identity is not None
            else None
        )
        if operation_entry is not None:
            profile_sha256, operation = operation_entry
            arguments, recovery = _recover_call_arguments(
                pre_call,
                state,
                unit,
                unit_id=unit_id,
                event_index=event_index,
                argument_words=operation.argument_words,
                inventory=inventory,
                known_slots=known_slots,
                budget=budget,
            )
            recovery["operation_id"] = operation.operation_id
            _record_operation_contract_status(
                recovery,
                issues,
                unit_id=unit_id,
                profile_sha256=profile_sha256,
                operation=operation,
                inventory=inventory,
            )
            argument_recoveries.append(recovery)
            if recovery["status"] != "complete":
                issues.append({
                    "code": "operation_arguments_incomplete",
                    "unit_id": unit_id,
                    "operation_id": operation.operation_id,
                    "failure": recovery["failure"]["code"],
                })
            if arguments is not None:
                outputs.update(_operation_output_effects(
                    arguments,
                    operation,
                    profile_sha256=profile_sha256,
                    producer_id=f"{unit_id}:{event_index}:{operation.operation_id}",
                    inventory=inventory,
                    issues=issues,
                    unit_id=unit_id,
                ))
            recovery["world_effects"] = _operation_world_effect_evidence(
                arguments,
                operation,
                profile_sha256=profile_sha256,
                inventory=inventory,
            )
            return (
                _CallFacts(
                    frozenset(operation.abi.preserved_registers),
                    operation.abi,
                    operation.argument_words,
                    None,
                    outputs,
                ),
                issues,
                argument_recoveries,
            )
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
    operations = _operation_origins(targets, inventory)
    if operations is not None:
        preserved_sets = [
            set(operation.abi.preserved_registers)
            for _, operation in operations
        ]
        preserved = preserved_sets[0]
        for values in preserved_sets[1:]:
            preserved &= values
        common_abi = operations[0][1].abi
        common_argument_words = operations[0][1].argument_words
        if any(
            operation.abi != common_abi
            or operation.argument_words != common_argument_words
            for _, operation in operations[1:]
        ):
            common_abi = None
            common_argument_words = None
        for profile_sha256, operation in operations:
            arguments, recovery = _recover_call_arguments(
                pre_call,
                state,
                unit,
                unit_id=unit_id,
                event_index=event_index,
                argument_words=operation.argument_words,
                inventory=inventory,
                known_slots=known_slots,
                budget=budget,
            )
            recovery["operation_id"] = operation.operation_id
            _record_operation_contract_status(
                recovery,
                issues,
                unit_id=unit_id,
                profile_sha256=profile_sha256,
                operation=operation,
                inventory=inventory,
            )
            argument_recoveries.append(recovery)
            if recovery["status"] != "complete":
                issues.append({
                    "code": "operation_arguments_incomplete",
                    "unit_id": unit_id,
                    "operation_id": operation.operation_id,
                    "failure": recovery["failure"]["code"],
                })
            if arguments is not None:
                outputs.update(_operation_output_effects(
                    arguments,
                    operation,
                    profile_sha256=profile_sha256,
                    producer_id=f"{unit_id}:{event_index}:{operation.operation_id}",
                    inventory=inventory,
                    issues=issues,
                    unit_id=unit_id,
                ))
            recovery["world_effects"] = _operation_world_effect_evidence(
                arguments,
                operation,
                profile_sha256=profile_sha256,
                inventory=inventory,
            )
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
    if methods is None:
        direct_facts = _origin_call_facts(
            targets,
            import_abis=import_abis,
            internal_call_preserved_registers=internal_call_preserved_registers,
            internal_call_stack_cleanup=internal_call_stack_cleanup,
        )
        if direct_facts is not None:
            return direct_facts, issues, argument_recoveries
        recovered = recovered_calls.get((unit_id, event_index))
        facts = _recovered_call_facts(
            recovered,
            inventory=inventory,
            import_abis=import_abis,
            internal_call_preserved_registers=internal_call_preserved_registers,
            internal_call_stack_cleanup=internal_call_stack_cleanup,
            image_base=image_base,
        )
        return (
            facts or _CallFacts(None, None, None, None, outputs),
            issues,
            argument_recoveries,
        )
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


def _origin_call_facts(
    origins: _Value,
    *,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    internal_call_preserved_registers: Mapping[int, frozenset[str]],
    internal_call_stack_cleanup: Mapping[int, int],
) -> _CallFacts | None:
    if origins is None or not origins:
        return None
    alternatives: list[_CallFacts] = []
    for origin in origins:
        if origin.kind == "import":
            selected = import_abis.get(_origin_import_identity(origin))
            if selected is None:
                return None
            alternatives.append(_CallFacts(
                frozenset(selected.abi.preserved_registers),
                selected.abi,
                selected.argument_words,
                _abi_stack_cleanup(selected.abi, selected.argument_words),
                {},
            ))
            continue
        if origin.kind == "exact":
            address = int(origin.key[0]) & 0xFFFFFFFF
            preserved = internal_call_preserved_registers.get(address)
            cleanup = internal_call_stack_cleanup.get(address)
            if preserved is None:
                return None
            alternatives.append(_CallFacts(preserved, None, None, cleanup, {}))
            continue
        return None
    return _combine_call_facts(alternatives)


def _recovered_call_facts(
    recovery: Mapping[str, Any] | None,
    *,
    inventory: _ProfileInventory,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    internal_call_preserved_registers: Mapping[int, frozenset[str]],
    internal_call_stack_cleanup: Mapping[int, int],
    image_base: int,
) -> _CallFacts | None:
    if recovery is None or recovery.get("status") != "recovered":
        return None
    raw_external = recovery.get("external_targets", [])
    raw_target_rvas = recovery.get("target_rvas", [])
    raw_target_units = recovery.get("target_unit_ids", [])
    if not _is_sequence(raw_external) or not _is_sequence(raw_target_rvas):
        return None
    if not _is_sequence(raw_target_units):
        return None
    if raw_target_units and not raw_target_rvas:
        return None

    alternatives: list[_CallFacts] = []
    for raw in raw_external:
        if not isinstance(raw, Mapping):
            return None
        facts = _external_target_call_facts(
            raw,
            inventory=inventory,
            import_abis=import_abis,
        )
        if facts is None:
            return None
        alternatives.append(facts)
    for raw_rva in raw_target_rvas:
        target_rva = _integer(raw_rva)
        if target_rva is None:
            return None
        target_address = (image_base + target_rva) & 0xFFFFFFFF
        preserved = internal_call_preserved_registers.get(target_address)
        cleanup = internal_call_stack_cleanup.get(target_address)
        if preserved is None or cleanup is None:
            return None
        alternatives.append(_CallFacts(preserved, None, None, cleanup, {}))
    return _combine_call_facts(alternatives)


def _external_target_call_facts(
    target: Mapping[str, Any],
    *,
    inventory: _ProfileInventory,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
) -> _CallFacts | None:
    protocol = _mapping(target.get("external_protocol"))
    if protocol:
        profile_sha256 = protocol.get("profile_sha256")
        if protocol.get("kind") == "pe32-operation":
            operation_id = protocol.get("operation_id")
            if not isinstance(profile_sha256, str) or not isinstance(operation_id, str):
                return None
            operation = inventory.operation(profile_sha256, operation_id)
            profile = inventory.operation_profiles.get(profile_sha256)
            if (
                operation is None
                or profile is None
                or target != inventory.operation_target_json(
                    profile_sha256, operation
                )
            ):
                return None
            return _CallFacts(
                frozenset(operation.abi.preserved_registers),
                operation.abi,
                operation.argument_words,
                _abi_stack_cleanup(operation.abi, operation.argument_words),
                {},
            )
        interface_id = protocol.get("interface_id")
        offset = _integer(protocol.get("offset"))
        if (
            not isinstance(profile_sha256, str)
            or not isinstance(interface_id, str)
            or offset is None
        ):
            return None
        method = inventory.method(profile_sha256, interface_id, offset)
        profile = inventory.profiles.get(profile_sha256)
        if (
            method is None
            or profile is None
            or protocol.get("profile_id") != profile.profile_id
            or protocol.get("kind") != "pe32-interface-method"
            or protocol.get("method") != method.name
            or protocol.get("slot") != method.slot
            or _mapping(target.get("abi")) != method.abi.as_json()
            or _integer(target.get("argument_words")) != method.argument_words
        ):
            return None
        return _CallFacts(
            frozenset(method.abi.preserved_registers),
            method.abi,
            method.argument_words,
            _abi_stack_cleanup(method.abi, method.argument_words),
            {},
        )

    identity = _event_import_identity(_mapping(target.get("import")))
    selected = import_abis.get(identity) if identity is not None else None
    raw_argument_words = target.get("argument_words")
    if (
        selected is None
        or _mapping(target.get("abi")) != selected.abi.as_json()
        or (
            raw_argument_words is not None
            and _integer(raw_argument_words) != selected.argument_words
        )
        or (raw_argument_words is None and selected.argument_words is not None)
    ):
        return None
    return _CallFacts(
        frozenset(selected.abi.preserved_registers),
        selected.abi,
        selected.argument_words,
        _abi_stack_cleanup(selected.abi, selected.argument_words),
        {},
    )


def _combine_call_facts(alternatives: Sequence[_CallFacts]) -> _CallFacts | None:
    if not alternatives or any(facts.preserved is None for facts in alternatives):
        return None
    preserved = set(alternatives[0].preserved or ())
    for facts in alternatives[1:]:
        preserved.intersection_update(facts.preserved or ())
    abis = {facts.abi for facts in alternatives}
    argument_counts = {facts.argument_words for facts in alternatives}
    cleanups = {facts.stack_cleanup_bytes for facts in alternatives}
    return _CallFacts(
        frozenset(preserved),
        next(iter(abis)) if len(abis) == 1 else None,
        next(iter(argument_counts)) if len(argument_counts) == 1 else None,
        (
            next(iter(cleanups))
            if len(cleanups) == 1 and None not in cleanups
            else None
        ),
        {},
    )


def _abi_stack_cleanup(abi: MachineCallABI, argument_words: int | None) -> int | None:
    if not abi.callee_cleanup:
        return 0
    return argument_words * 4 if argument_words is not None else None


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


def _operation_output_effects(
    arguments: Sequence[_Value],
    operation: ExternalOperation,
    *,
    profile_sha256: str,
    producer_id: str,
    inventory: _ProfileInventory,
    issues: list[dict[str, Any]],
    unit_id: str,
) -> dict[_Origin, _Value]:
    result: dict[_Origin, _Value] = {}
    for output_index, rule in enumerate(operation.output_rules):
        if isinstance(
            rule,
            (ReturnRegisterOperationOutput, OutArgumentOperationOutput),
        ):
            target_operation = inventory.operation_for_resolver_result(
                profile_sha256,
                operation.operation_id,
                rule.result_id,
            )
            if target_operation is None:
                issues.append({
                    "code": "operation_resolver_result_unresolved",
                    "unit_id": unit_id,
                    "operation_id": operation.operation_id,
                    "result_id": rule.result_id,
                    "output_index": output_index,
                })
                continue
            origins = frozenset({_operation_target_origin(
                profile_sha256,
                target_operation.operation_id,
                producer_id,
                rule.success_guard,
            )})
        else:
            view_ids = _operation_output_views(
                rule.view, arguments, inventory=inventory
            )
            if view_ids is None:
                issues.append({
                    "code": "operation_output_discriminator_unresolved",
                    "unit_id": unit_id,
                    "operation_id": operation.operation_id,
                    "output_index": output_index,
                })
                continue
            origins = frozenset(
                _operation_output_origin(
                    profile_sha256,
                    view_id,
                    producer_id,
                    rule.success_guard,
                )
                for view_id in view_ids
            )
        if isinstance(
            rule, (ReturnRegisterOutput, ReturnRegisterOperationOutput)
        ):
            location = _Origin("register_location", (rule.register,))
        elif isinstance(rule, (OutArgumentOutput, OutArgumentOperationOutput)):
            addresses = arguments[rule.argument_index]
            if (
                addresses is None
                or len(addresses) != 1
                or next(iter(addresses)).kind not in {"exact", "stack_location"}
            ):
                issues.append({
                    "code": "operation_out_pointer_unresolved",
                    "unit_id": unit_id,
                    "operation_id": operation.operation_id,
                    "argument_index": rule.argument_index,
                })
                continue
            location = next(iter(addresses))
        else:  # pragma: no cover - typed profile parser closes this case.
            continue
        result[location] = origins
        guard = rule.success_guard
        if guard is not None and guard.register != getattr(rule, "register", None):
            result.setdefault(
                _Origin("register_location", (guard.register,)),
                frozenset({_Origin(
                    "call_result",
                    (producer_id, guard.register),
                )}),
            )
    return result


def _operation_world_effect_evidence(
    arguments: Sequence[_Value] | None,
    operation: ExternalOperation,
    *,
    profile_sha256: str,
    inventory: _ProfileInventory,
) -> list[dict[str, Any]]:
    contract = inventory.operation_contract(profile_sha256, operation)
    result: list[dict[str, Any]] = []
    for effect in contract.world_effects:
        row: dict[str, Any] = {
            "kind": effect.kind,
            "argument_index": effect.argument_index,
            "callback_id": effect.callback_id,
            "status": "declared",
        }
        if effect.kind != "callbackRegistration":
            result.append(row)
            continue
        if arguments is None or effect.argument_index is None:
            result.append({
                **row,
                "status": "incomplete",
                "failure": {"code": "callback_argument_origin_unresolved"},
            })
            continue
        origins = arguments[effect.argument_index]
        targets: set[tuple[int, str]] = set()
        if origins is None or not origins:
            complete = False
        else:
            complete = True
            for origin in origins:
                if origin.kind != "exact":
                    complete = False
                    break
                candidates = inventory.unit_targets.get(
                    int(origin.key[0]) & 0xFFFFFFFF, ()
                )
                if len(candidates) != 1:
                    complete = False
                    break
                targets.add(candidates[0])
        if not complete or not targets:
            result.append({
                **row,
                "status": "incomplete",
                "origins": _origins_json(origins),
                "failure": {"code": "callback_target_not_canonical_code"},
            })
            continue
        result.append({
            **row,
            "status": "complete",
            "origins": _origins_json(origins),
            "target_rvas": sorted(target[0] for target in targets),
            "target_unit_ids": sorted(target[1] for target in targets),
            "failure": None,
        })
    return result


def _record_operation_contract_status(
    recovery: dict[str, Any],
    issues: list[dict[str, Any]],
    *,
    unit_id: str,
    profile_sha256: str,
    operation: ExternalOperation,
    inventory: _ProfileInventory,
) -> None:
    contract = inventory.operation_contract(profile_sha256, operation)
    recovery["environment_contract"] = {
        "id": contract.contract_id,
        "status": contract.status,
        "blockers": list(contract.blockers),
    }
    if contract.status != "complete":
        issues.append({
            "code": "operation_environment_contract_incomplete",
            "unit_id": unit_id,
            "operation_id": operation.operation_id,
            "environment_contract_id": contract.contract_id,
            "blockers": list(contract.blockers),
        })


def _operation_output_views(
    view: FixedOutputView | DiscriminatorOutputView,
    arguments: Sequence[_Value],
    *,
    inventory: _ProfileInventory,
) -> tuple[str, ...] | None:
    if isinstance(view, FixedOutputView):
        return (view.view_id,)
    values = arguments[view.argument_index]
    if values is None or any(origin.kind != "exact" for origin in values):
        return None
    if view.read_bytes is None:
        cases = {case.value: case.view_id for case in view.cases}
        selected = {
            cases.get(int(origin.key[0]) & 0xFFFFFFFF)
            for origin in values
        }
    else:
        if inventory.static_data_reader is None:
            return None
        cases = {case.bytes_sha256: case.view_id for case in view.cases}
        selected = set()
        for origin in values:
            data = inventory.static_data_reader(
                int(origin.key[0]) & 0xFFFFFFFF,
                view.read_bytes,
            )
            if data is None or len(data) != view.read_bytes:
                return None
            selected.add(cases.get(sha256(data).hexdigest()))
    return (
        tuple(sorted(value for value in selected if value is not None))
        if None not in selected and selected
        else None
    )


def _operation_output_origin(
    profile_sha256: str,
    view_id: str,
    producer_id: str,
    guard: SuccessGuard | None,
) -> _Origin:
    if guard is None:
        return _Origin(
            "resource_view",
            (profile_sha256, view_id, producer_id),
        )
    return _Origin(
        "guarded_resource_view",
        (
            profile_sha256,
            view_id,
            producer_id,
            guard.kind,
            guard.register,
            guard.value,
            guard.mask,
        ),
    )


def _operation_target_origin(
    profile_sha256: str,
    operation_id: str,
    producer_id: str,
    guard: SuccessGuard | None,
) -> _Origin:
    if guard is None:
        return _Origin("operation_target", (profile_sha256, operation_id))
    return _Origin(
        "guarded_operation_target",
        (
            profile_sha256,
            operation_id,
            producer_id,
            guard.kind,
            guard.register,
            guard.value,
            guard.mask,
        ),
    )


def _resolve_exits(
    indirect_exits: Sequence[Mapping[str, Any]],
    *,
    by_id: Mapping[str, Mapping[str, Any]],
    states: Mapping[str, _State],
    inventory: _ProfileInventory,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
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
        base = {
            "id": identity,
            "source_unit_id": source,
            "source_rva": exit_record.get("source_rva"),
            "source_event_index": exit_record.get("source_event_index"),
            "kind": exit_record.get("kind"),
            "target_expression": copy.deepcopy(target),
            "target_rvas": [],
            "target_unit_ids": [],
        }
        classified = _classify_target_origins(
            origins,
            inventory=inventory,
            import_abis=import_abis,
        )
        if classified is None:
            failure = _target_resolution_failure(target, origins)
            result.append({
                **base,
                "status": "incomplete",
                "closure": "unresolved",
                "external_targets": [],
                "failure": failure,
            })
            continue
        internal, targets, target_kinds = classified
        result.append({
            **base,
            "status": "recovered",
            "closure": (
                "checked_profile_interface_method_inventory"
                if target_kinds == {"interface_operation"}
                else "checked_external_operation_inventory"
                if target_kinds == {"profile_operation"}
                else "checked_finite_operation_origin_inventory"
            ),
            "target_rvas": sorted({item[0] for item in internal}),
            "target_unit_ids": sorted({item[1] for item in internal}),
            "external_targets": sorted(
                targets,
                key=lambda row: json.dumps(row, sort_keys=True),
            ),
            "origin_count": len(origins or ()),
            "origin_kinds": sorted(target_kinds),
            "failure": None,
        })
    return result


def _target_resolution_failure(
    expression: Any,
    origins: _Value,
) -> dict[str, Any]:
    if origins is not None:
        return {
            "code": "target_origin_kind_unsupported",
            "observed_origin_kinds": sorted({origin.kind for origin in origins}),
            "next_action": (
                "add or repair the producer, call-frame, or operation-profile rule "
                "for the observed bounded origin"
            ),
        }
    row = _mapping(expression)
    op = str(row.get("op") or "").lower()
    if op in {"reg", "input_reg", "register"}:
        return {
            "code": "register_target_origin_missing",
            "register": row.get("name", row.get("reg")),
            "next_action": (
                "recover the register producer or add the missing call/return "
                "preservation contract"
            ),
        }
    if op in {"load", "read32", "mem32"}:
        address = _mapping(row.get("address"))
        address_op = str(address.get("op") or "").lower()
        if address_op in {"const", "constant"}:
            return {
                "code": "static_slot_target_origin_missing",
                "address": address.get("value"),
                "next_action": (
                    "classify the static slot initializer and every reachable write"
                ),
            }
        return {
            "code": "operation_view_origin_missing",
            "next_action": (
                "recover the receiver resource view, table load, and slot offset "
                "from a pinned operation profile"
            ),
        }
    return {
        "code": "target_expression_not_normalized",
        "next_action": "extend the generic expression normalizer for this x86 form",
    }


def _classify_target_origins(
    origins: _Value,
    *,
    inventory: _ProfileInventory,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
) -> tuple[list[tuple[int, str]], list[dict[str, Any]], set[str]] | None:
    if origins is None or not origins:
        return None
    internal: set[tuple[int, str]] = set()
    external: dict[str, dict[str, Any]] = {}
    kinds: set[str] = set()
    for origin in origins:
        if origin.kind == "exact":
            candidates = inventory.unit_targets.get(int(origin.key[0]) & 0xFFFFFFFF, ())
            if len(candidates) != 1:
                return None
            internal.add(candidates[0])
            kinds.add("internal")
            continue
        if origin.kind == "import":
            identity = _origin_import_identity(origin)
            selected = import_abis.get(identity)
            if selected is None:
                return None
            rendered = selected.as_json()
            external[json.dumps(rendered, sort_keys=True)] = rendered
            kinds.add("import")
            continue
        if origin.kind == "interface_method":
            profile_sha256, interface_id, slot = origin.key
            method = inventory.method(
                str(profile_sha256), str(interface_id), int(slot) * 4
            )
            if method is None:
                return None
            profile = inventory.profile(str(profile_sha256))
            rendered = method.target_json(
                profile_id=profile.profile_id,
                profile_sha256=profile.sha256,
            )
            external[json.dumps(rendered, sort_keys=True)] = rendered
            kinds.add("interface_operation")
            continue
        if origin.kind == "operation_target":
            profile_sha256, operation_id = origin.key
            operation = inventory.operation(
                str(profile_sha256), str(operation_id)
            )
            if operation is None:
                return None
            rendered = inventory.operation_target_json(
                str(profile_sha256), operation
            )
            external[json.dumps(rendered, sort_keys=True)] = rendered
            kinds.add("profile_operation")
            continue
        return None
    return sorted(internal), [external[key] for key in sorted(external)], kinds


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
        return _add_values(
            left,
            right,
            subtract=op in {"sub", "sub32"},
            budget=budget,
            inventory=inventory,
        )
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
                if value is None and concrete in inventory.iat:
                    value = frozenset({_import_origin(inventory.iat[concrete])})
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
            elif address.kind == "resource_view":
                profile_sha256, view_id, *_ = address.key
                access = inventory.operation_view_access(
                    str(profile_sha256), str(view_id)
                )
                if access == "object_table":
                    result.add(_Origin("operation_table", address.key))
                elif access == "direct_table":
                    operation = inventory.operation_for_slot(
                        str(profile_sha256), str(view_id), 0
                    )
                    if operation is None:
                        return None
                    result.add(_Origin(
                        "operation_target",
                        (profile_sha256, operation.operation_id),
                    ))
                else:
                    return None
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
            elif address.kind == "operation_table":
                profile_sha256, view_id, *_ = address.key
                operation = inventory.operation_for_slot(
                    str(profile_sha256), str(view_id), 0
                )
                if operation is None:
                    return None
                result.add(_Origin(
                    "operation_target",
                    (profile_sha256, operation.operation_id),
                ))
            elif address.kind == "operation_slot":
                profile_sha256, view_id, offset, *_ = address.key
                operation = inventory.operation_for_slot(
                    str(profile_sha256), str(view_id), int(offset)
                )
                if operation is None:
                    return None
                result.add(_Origin(
                    "operation_target",
                    (profile_sha256, operation.operation_id),
                ))
            else:
                return None
        return frozenset(result) if result and len(result) <= budget else None
    return None


def _add_values(
    left: _Value,
    right: _Value,
    *,
    subtract: bool,
    budget: int,
    inventory: _ProfileInventory,
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
            elif not subtract and lhs.kind == "operation_table" and rhs.kind == "exact":
                result.add(_Origin(
                    "operation_slot", (lhs.key[0], lhs.key[1], int(rhs.key[0]), *lhs.key[2:])
                ))
            elif not subtract and lhs.kind == "exact" and rhs.kind == "operation_table":
                result.add(_Origin(
                    "operation_slot", (rhs.key[0], rhs.key[1], int(lhs.key[0]), *rhs.key[2:])
                ))
            elif not subtract and lhs.kind == "resource_view" and rhs.kind == "exact":
                if inventory.operation_view_access(
                    str(lhs.key[0]), str(lhs.key[1])
                ) != "direct_table":
                    return None
                result.add(_Origin(
                    "operation_slot",
                    (lhs.key[0], lhs.key[1], int(rhs.key[0]), *lhs.key[2:]),
                ))
            elif not subtract and lhs.kind == "exact" and rhs.kind == "resource_view":
                if inventory.operation_view_access(
                    str(rhs.key[0]), str(rhs.key[1])
                ) != "direct_table":
                    return None
                result.add(_Origin(
                    "operation_slot",
                    (rhs.key[0], rhs.key[1], int(lhs.key[0]), *rhs.key[2:]),
                ))
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


def _operation_origins(
    origins: _Value,
    inventory: _ProfileInventory,
) -> list[tuple[str, ExternalOperation]] | None:
    if origins is None or not origins:
        return None
    result: dict[tuple[str, str], tuple[str, ExternalOperation]] = {}
    for origin in origins:
        if origin.kind != "operation_target":
            return None
        profile_sha256, operation_id = origin.key
        operation = inventory.operation(str(profile_sha256), str(operation_id))
        if operation is None:
            return None
        result[(str(profile_sha256), str(operation_id))] = (
            str(profile_sha256),
            operation,
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
            guard = raw.get("guard")
            guard_json = (
                json.dumps(guard, sort_keys=True, separators=(",", ":"))
                if isinstance(guard, Mapping)
                else None
            )
            result[source].add(_Edge("direct", target, guard_json=guard_json))
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


def _recovered_call_inventory(
    recoveries: Sequence[Mapping[str, Any]],
) -> dict[tuple[str, int], Mapping[str, Any]]:
    result: dict[tuple[str, int], Mapping[str, Any]] = {}
    for recovery in recoveries:
        if (
            recovery.get("status") != "recovered"
            or recovery.get("kind") != "indirect_call"
        ):
            continue
        source = recovery.get("source_unit_id")
        event_index = _integer(recovery.get("source_event_index"))
        if not isinstance(source, str) or event_index is None:
            continue
        key = (source, event_index)
        if key in result:
            raise ValueError(
                "interface provenance received duplicate recovered call sites"
            )
        result[key] = recovery
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
    return join_finite_values(
        left,
        right,
        budget,
        missing_is_identity=missing_is_identity,
    )


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


def _persistent_origin(origin: _Origin) -> bool:
    return origin.kind in {
        "exact",
        "import",
        "static_code",
        "static_data",
        "resource",
        "resource_view",
        "operation_table",
        "operation_slot",
        "operation_target",
        "callback",
        "interface_object",
        "interface_vtable",
        "interface_slot",
        "interface_method",
    }


def _refine_state_for_guard(state: _State, guard: Mapping[str, Any]) -> _State:
    constraint = _guard_constraint(guard)
    if constraint is None:
        return state
    register, relation, value, mask = constraint
    registers = {
        name: _refine_guarded_value(origins, constraint, constrain_exact=name == register)
        for name, origins in state.registers.items()
    }
    memory = {
        address: refined
        for address, origins in state.memory.items()
        if (refined := _refine_guarded_value(origins, constraint)) is not None
    }
    stack = {
        offset: _StackCell(refined, cell.witnesses)
        for offset, cell in state.stack.items()
        if (refined := _refine_guarded_value(cell.value, constraint)) is not None
    }
    return _State(registers, memory, stack)


def _refine_guarded_value(
    origins: _Value,
    constraint: tuple[str, str, int, int | None],
    *,
    constrain_exact: bool = False,
) -> _Value:
    if origins is None:
        return None
    result: set[_Origin] = set()
    for origin in origins:
        if origin.kind == "guarded_resource_view":
            relation = _guarded_origin_relation(origin, constraint)
            if relation is True:
                result.add(_Origin("resource_view", origin.key[:3]))
            elif relation is None:
                result.add(origin)
            continue
        if origin.kind == "guarded_operation_target":
            relation = _guarded_operation_relation(origin, constraint)
            if relation is True:
                result.add(_Origin("operation_target", origin.key[:2]))
            elif relation is None:
                result.add(origin)
            continue
        if constrain_exact and origin.kind == "exact":
            concrete = int(origin.key[0]) & 0xFFFFFFFF
            if not _constraint_accepts(concrete, constraint):
                continue
        result.add(origin)
    return frozenset(result) if result else None


def _guarded_origin_relation(
    origin: _Origin,
    constraint: tuple[str, str, int, int | None],
) -> bool | None:
    _, _, _, kind, register, value, mask = origin.key
    return _guard_relation(kind, register, value, mask, constraint)


def _guard_relation(
    kind: Any,
    register: Any,
    value: Any,
    mask: Any,
    constraint: tuple[str, str, int, int | None],
) -> bool | None:
    constrained_register, relation, selected, selected_mask = constraint
    if register != constrained_register:
        return None
    success = (
        (kind == "nonzero" and relation == "ne" and selected == 0)
        or (
            kind == "equals"
            and relation == "eq"
            and selected == int(value or 0)
        )
        or (
            kind == "masked_equals"
            and relation == "masked_eq"
            and selected == int(value or 0)
            and selected_mask == int(mask or 0)
        )
    )
    failure = (
        (kind == "nonzero" and relation == "eq" and selected == 0)
        or (
            kind == "equals"
            and relation == "ne"
            and selected == int(value or 0)
        )
        or (
            kind == "masked_equals"
            and relation == "masked_ne"
            and selected == int(value or 0)
            and selected_mask == int(mask or 0)
        )
    )
    return True if success else False if failure else None


def _guarded_operation_relation(
    origin: _Origin,
    constraint: tuple[str, str, int, int | None],
) -> bool | None:
    _, _, _, kind, register, value, mask = origin.key
    return _guard_relation(kind, register, value, mask, constraint)


def _constraint_accepts(
    concrete: int,
    constraint: tuple[str, str, int, int | None],
) -> bool:
    _, relation, value, mask = constraint
    selected = concrete if mask is None else concrete & mask
    return selected == value if relation in {"eq", "masked_eq"} else selected != value


def _guard_constraint(
    guard: Mapping[str, Any],
    *,
    polarity: bool = True,
) -> tuple[str, str, int, int | None] | None:
    op = str(guard.get("op") or "").lower()
    arguments = guard.get("args")
    if (
        op in {"not", "logical_not"}
        and isinstance(arguments, Sequence)
        and not isinstance(arguments, (str, bytes))
        and len(arguments) == 1
        and isinstance(arguments[0], Mapping)
    ):
        return _guard_constraint(arguments[0], polarity=not polarity)
    operands = _binary_operands(guard)
    if operands is None or op not in {"eq", "eq32", "equal", "ne", "ne32", "not_equal"}:
        return None
    equality = op in {"eq", "eq32", "equal"}
    if not polarity:
        equality = not equality
    for expression, constant in (operands, reversed(operands)):
        selected = _integer(_mapping(constant).get("value"))
        if selected is None:
            continue
        register = _register_expression(expression)
        if register is not None:
            return register, "eq" if equality else "ne", selected & 0xFFFFFFFF, None
        masked = _masked_register_expression(expression)
        if masked is not None:
            register, mask = masked
            return (
                register,
                "masked_eq" if equality else "masked_ne",
                selected & mask,
                mask,
            )
    return None


def _register_expression(expression: Any) -> str | None:
    row = _mapping(expression)
    if str(row.get("op") or "").lower() not in {"reg", "input_reg", "register"}:
        return None
    name = row.get("name", row.get("reg"))
    return str(name).lower() if isinstance(name, str) else None


def _masked_register_expression(expression: Any) -> tuple[str, int] | None:
    row = _mapping(expression)
    if str(row.get("op") or "").lower() not in {"and", "and32", "bit_and"}:
        return None
    operands = _binary_operands(row)
    if operands is None:
        return None
    for candidate, constant in (operands, reversed(operands)):
        register = _register_expression(candidate)
        mask = _integer(_mapping(constant).get("value"))
        if register is not None and mask is not None:
            return register, mask & 0xFFFFFFFF
    return None


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


def _import_origin(identity: MachineImportIdentity) -> _Origin:
    return _Origin("import", (identity.dll, identity.kind, identity.value))


def _origin_import_identity(origin: _Origin) -> MachineImportIdentity:
    return MachineImportIdentity(str(origin.key[0]), str(origin.key[1]), origin.key[2])


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


def _is_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes))


__all__ = [
    "INTERFACE_PROVENANCE_FORMAT",
    "recover_external_interface_targets",
]
