"""Bounded external-interface value provenance for PE32 machine IR.

The analysis resolves profile-backed vtable calls and proposes typed
out-parameter updates.  It is not proof authority; every target expression,
call argument, memory update, and external frame must be replayed by Stage A.
"""

from __future__ import annotations

import copy
import heapq
import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Callable, Iterable, Mapping, Sequence

from .callback_contracts import (
    parse_callback_abi,
    parse_nested_native_callback_behavior,
    parse_callback_result,
    parse_callback_source,
)
from .call_arguments import CallArgumentRecovery, recover_pe32_stack_call_arguments
from .call_site_effects import (
    CallOutput,
    CallSiteEffect,
    CallSiteId,
    CallWriteSpan,
)
from .call_frame_hypotheses import (
    PreservedRegisterHypothesis,
    hypothesis_id as call_frame_hypothesis_id,
)
from .address_expression_v2 import affine_register_offset
from .external_interface_profiles import (
    ExternalInterfaceProfile,
    InterfaceCallerMemoryFrame,
    InterfaceFactory,
    InterfaceMethod,
)
from .external_capabilities import (
    CallableExternalProfile,
    CallableExternalTargetProfileSpec,
    CallableResolverProfileSpec,
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
from .machine_abi import MachineCallABI, resolve_machine_call_abi
from .machine_import_profiles import MachineImportIdentity, MachineImportProfileError
from .checked_memory_access_v2 import MEMORY_ACCESS_PROPOSAL_V2_FORMAT
from .provenance_domain import (
    FiniteValue,
    ValueOrigin,
    is_persistent_origin,
    join_finite_values,
    origin_concrete_value,
    origins_json,
    parse_finite_value,
    value_dependencies,
    with_origin_dependencies,
    with_value_dependencies,
)


INTERFACE_PROVENANCE_FORMAT = "stage-a-external-interface-provenance-v1"
_REGISTERS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")
_CALL_KINDS = frozenset({"external_call", "indirect_call", "internal_call"})


_Origin = ValueOrigin
_Value = FiniteValue
_MemoryLocation = int | _Origin


@dataclass
class _State:
    registers: dict[str, _Value]
    memory: dict[_MemoryLocation, _Value]
    stack: dict[int, "_StackCell"]
    memory_invalidated: bool = False


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
    memory_preserved: bool = False
    memory_writes: tuple["_WriteSpan", ...] | None = None
    dependencies: frozenset[str] = frozenset()
    register_dependencies: Mapping[str, frozenset[str]] = field(
        default_factory=dict
    )


@dataclass(frozen=True, order=True)
class _WriteSpan:
    base: _Origin
    size: int | None


def _parse_preserved_register_hypotheses(
    rows: Sequence[Mapping[str, Any]],
) -> dict[CallSiteId, dict[str, PreservedRegisterHypothesis]]:
    result: dict[CallSiteId, dict[str, PreservedRegisterHypothesis]] = {}
    identities: set[str] = set()
    for raw in rows:
        hypothesis = PreservedRegisterHypothesis.parse(raw)
        if hypothesis.id in identities:
            raise ValueError("duplicate preserved-register hypothesis ID")
        identities.add(hypothesis.id)
        site = CallSiteId(hypothesis.unit_id, hypothesis.event_index)
        by_register = result.setdefault(site, {})
        if hypothesis.register in by_register:
            raise ValueError(
                "duplicate preserved-register hypothesis for one call site"
            )
        by_register[hypothesis.register] = hypothesis
    return result


def _with_preserved_register_hypotheses(
    facts: _CallFacts,
    hypotheses: Mapping[str, PreservedRegisterHypothesis],
) -> _CallFacts:
    if facts.preserved is not None:
        return facts
    return _CallFacts(
        preserved=frozenset(hypotheses),
        abi=facts.abi,
        argument_words=facts.argument_words,
        stack_cleanup_bytes=facts.stack_cleanup_bytes,
        outputs=facts.outputs,
        memory_preserved=facts.memory_preserved,
        memory_writes=facts.memory_writes,
        dependencies=facts.dependencies,
        register_dependencies={
            register: frozenset({hypothesis.id})
            for register, hypothesis in hypotheses.items()
        },
    )


def _call_site_effect(
    *,
    unit_id: str,
    event_index: int,
    transfer_kind: str,
    facts: _CallFacts,
    failure_codes: Iterable[str] = (),
) -> CallSiteEffect:
    cleanup = facts.stack_cleanup_bytes
    if cleanup is None and facts.abi is not None:
        cleanup = _abi_stack_cleanup(facts.abi, facts.argument_words)

    register_status = (
        "complete" if facts.preserved is not None else "incomplete"
    )
    stack_status = "complete" if cleanup is not None else "incomplete"
    result_status = (
        "complete"
        if all(value is not None and value for value in facts.outputs.values())
        else "incomplete"
    )
    memory_status = (
        "complete"
        if facts.memory_preserved or facts.memory_writes is not None
        else "incomplete"
    )
    failures = set(failure_codes)
    for status, code in (
        (register_status, "register_frame_unknown"),
        (stack_status, "stack_frame_unknown"),
        (result_status, "result_frame_unknown"),
        (memory_status, "memory_frame_unknown"),
    ):
        if status == "incomplete":
            failures.add(code)
    return CallSiteEffect(
        site=CallSiteId(unit_id, event_index),
        transfer_kind=transfer_kind,
        status="complete" if not failures else "incomplete",
        register_frame_status=register_status,
        preserved_registers=(
            facts.preserved if facts.preserved is not None else frozenset()
        ),
        stack_frame_status=stack_status,
        stack_cleanup_bytes=cleanup,
        result_status=result_status,
        outputs=(
            tuple(
                CallOutput(location, value)
                for location, value in sorted(facts.outputs.items())
                if value is not None
            )
            if result_status == "complete"
            else ()
        ),
        memory_frame_status=memory_status,
        memory_preserved=(
            facts.memory_preserved if memory_status == "complete" else False
        ),
        memory_writes=(
            tuple(
                CallWriteSpan(span.base, span.size)
                for span in facts.memory_writes or ()
            )
            if memory_status == "complete"
            else ()
        ),
        abi=facts.abi,
        argument_words=facts.argument_words,
        dependencies=tuple(sorted(
            facts.dependencies
            | frozenset().union(*facts.register_dependencies.values())
        )),
        failure_codes=tuple(sorted(failures)),
    )


@dataclass(frozen=True)
class _Edge:
    kind: str
    target_id: str
    event_index: int | None = None
    guard_json: str | None = None


@dataclass(frozen=True)
class _InternalCleanupEvidence:
    target_address: int
    target_unit_id: str
    cleanup_bytes: int | None
    return_unit_ids: tuple[str, ...]
    status: str
    failure_code: str | None = None

    def as_json(self, *, image_base: int) -> dict[str, Any]:
        return {
            "target_address": self.target_address,
            "target_rva": (self.target_address - image_base) & 0xFFFFFFFF,
            "target_unit_id": self.target_unit_id,
            "status": self.status,
            "cleanup_bytes": self.cleanup_bytes,
            "return_unit_ids": list(self.return_unit_ids),
            "failure": (
                None
                if self.failure_code is None
                else {"code": self.failure_code}
            ),
        }


@dataclass
class _RunResult:
    states: dict[str, _State]
    resolutions: list[dict[str, Any]]
    path_recovery_proposals: list[dict[str, Any]]
    proposed_slots: dict[_MemoryLocation, _Value]
    tainted_slots: set[_MemoryLocation]
    issues: list[dict[str, Any]]
    argument_recoveries: list[dict[str, Any]]
    call_site_effects: list[CallSiteEffect]
    evaluations: int
    transfer_requests: int
    transfer_cache_hits: int
    budget_exceeded: int
    context_states: int
    context_evaluations: int
    context_truncated_calls: int
    context_dropped_states: int


@dataclass(frozen=True, order=True)
class _CallContextFrame:
    source_unit_id: str
    event_index: int
    target_unit_id: str

    def as_json(self) -> dict[str, Any]:
        return {
            "source_unit_id": self.source_unit_id,
            "event_index": self.event_index,
            "target_unit_id": self.target_unit_id,
        }


@dataclass(frozen=True, order=True)
class _PathContext:
    root_unit_id: str
    calls: tuple[_CallContextFrame, ...] = ()

    def push(
        self, frame: _CallContextFrame, *, depth: int
    ) -> tuple["_PathContext", bool]:
        calls = (*self.calls, frame)
        truncated = len(calls) > depth
        return _PathContext(self.root_unit_id, tuple(calls[-depth:])), truncated

    def as_json(self) -> dict[str, Any]:
        core = {
            "root_unit_id": self.root_unit_id,
            "calls": [frame.as_json() for frame in self.calls],
        }
        return {
            "id": "bounded-call-context-v1:" + sha256(
                json.dumps(
                    core,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("ascii")
            ).hexdigest(),
            **core,
        }


@dataclass
class _ContextDiscoveryResult:
    proposals: list[dict[str, Any]]
    issues: list[dict[str, Any]]
    context_states: int
    truncated_calls: int
    dropped_contexts: int
    evaluations: int


_UnitTransfer = tuple[
    tuple[_State, dict[int, _State]],
    dict[_MemoryLocation, _Value],
    set[_MemoryLocation],
    list[dict[str, Any]],
    list[dict[str, Any]],
    tuple[CallSiteEffect, ...],
    int,
]


def recover_external_interface_targets(
    *,
    units: Sequence[Mapping[str, Any]],
    roots: Iterable[str],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    recovered_indirect_edges: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    profiles: Sequence[ExternalInterfaceProfile],
    callable_external_profiles: Sequence[CallableExternalProfile] = (),
    operation_profiles: Sequence[ExternalOperationProfile] = (),
    imports: Sequence[Mapping[str, Any]] = (),
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    internal_call_preserved_registers: Mapping[int, frozenset[str]],
    image_base: int,
    internal_call_stack_cleanup: Mapping[int, int] | None = None,
    internal_call_result_relations: Mapping[
        int, Mapping[str, Sequence[Mapping[str, Any]]]
    ] | None = None,
    internal_call_memory_preservation: Mapping[int, bool] | None = None,
    internal_call_memory_result_relations: Mapping[
        int, Mapping[_Origin, _Value]
    ] | None = None,
    finite_value_budget: int = 32,
    static_slot_budget: int = 256,
    stack_slot_budget: int = 256,
    fixed_point_budget: int | None = None,
    static_data_reader: Callable[[int, int], bytes | None] | None = None,
    bootstrap_unknown_call_preserved_registers: frozenset[str] | None = None,
    initial_known_slots: Mapping[_MemoryLocation, _Value] | None = None,
    initial_root_argument_origins: Mapping[
        str, Mapping[int, _Value]
    ] | None = None,
    recovered_known_slots: dict[_MemoryLocation, _Value] | None = None,
    checked_stack_entry_offsets: Mapping[str, Sequence[int]] | None = None,
    allow_global_slot_promotion: bool = True,
    collect_path_recovery_proposals: bool = False,
    preserved_register_hypotheses: Sequence[Mapping[str, Any]] = (),
    path_context_depth: int = 1,
    path_context_budget: int = 64,
) -> dict[str, Any]:
    """Recover finite external method targets from typed interface origins."""

    if min(finite_value_budget, static_slot_budget, stack_slot_budget) <= 0 or (
        fixed_point_budget is not None and fixed_point_budget <= 0
    ):
        raise ValueError("interface provenance budgets must be positive")
    if not isinstance(allow_global_slot_promotion, bool):
        raise ValueError("allow_global_slot_promotion must be a boolean")
    if not isinstance(collect_path_recovery_proposals, bool):
        raise ValueError("path-recovery proposal selection must be a boolean")
    if (
        not isinstance(path_context_depth, int)
        or isinstance(path_context_depth, bool)
        or path_context_depth <= 0
        or not isinstance(path_context_budget, int)
        or isinstance(path_context_budget, bool)
        or path_context_budget <= 0
    ):
        raise ValueError("bounded call-context budgets must be positive integers")
    parsed_call_hypotheses = _parse_preserved_register_hypotheses(
        preserved_register_hypotheses
    )
    effective_fixed_point_budget = (
        fixed_point_budget
        if fixed_point_budget is not None
        else 1 + static_slot_budget * (finite_value_budget + 3)
    )
    if (
        bootstrap_unknown_call_preserved_registers is not None
        and not bootstrap_unknown_call_preserved_registers <= frozenset(_REGISTERS)
    ):
        raise ValueError("bootstrap call preservation contains an unknown register")
    supplied_call_stack_cleanup = dict(internal_call_stack_cleanup or {})
    supplied_call_result_relations = dict(internal_call_result_relations or {})
    supplied_call_memory_preservation = dict(
        internal_call_memory_preservation or {}
    )
    supplied_call_memory_results = _normalize_internal_call_memory_results(
        internal_call_memory_result_relations or {},
        finite_value_budget=finite_value_budget,
    )
    internal_call_dependency_ids: dict[tuple[str, int], frozenset[str]] = {}
    for edge in internal_call_edges:
        source = edge.get("source_unit_id")
        event_index = _integer(edge.get("source_event_index"))
        target = edge.get("target_unit_id")
        if (
            isinstance(source, str)
            and event_index is not None
            and isinstance(target, str)
        ):
            key = (source, event_index)
            internal_call_dependency_ids[key] = (
                internal_call_dependency_ids.get(key, frozenset())
                | {_call_frame_dependency_id(source, event_index, target)}
            )
    stack_entry_offsets = _normalize_checked_stack_entry_offsets(
        checked_stack_entry_offsets or {},
        finite_value_budget=finite_value_budget,
    )
    by_id = {str(unit["id"]): unit for unit in units}
    if len(by_id) != len(units):
        raise ValueError("interface provenance requires unique unit IDs")
    inventory = _ProfileInventory(
        profiles,
        callable_external_profiles=callable_external_profiles,
        operation_profiles=operation_profiles,
        imports=imports,
        units=units,
        image_base=image_base,
        static_data_reader=static_data_reader,
    )
    effective_import_abis = _merge_import_abi_evidence(
        import_abis,
        inventory.observed_import_abis,
    )
    outgoing = _outgoing_edges(
        by_id,
        direct_edges=direct_edges,
        internal_call_edges=internal_call_edges,
        recovered_indirect_edges=recovered_indirect_edges,
    )
    cleanup_evidence = _infer_internal_call_cleanups(
        by_id=by_id,
        outgoing=outgoing,
        internal_call_edges=internal_call_edges,
        image_base=image_base,
    )
    call_stack_cleanup = dict(supplied_call_stack_cleanup)
    cleanup_conflicts: list[dict[str, Any]] = []
    for evidence in cleanup_evidence:
        if evidence.status != "complete" or evidence.cleanup_bytes is None:
            continue
        supplied = supplied_call_stack_cleanup.get(evidence.target_address)
        if supplied is not None and supplied != evidence.cleanup_bytes:
            cleanup_conflicts.append({
                "code": "internal_call_cleanup_evidence_conflict",
                "target_address": evidence.target_address,
                "supplied_cleanup_bytes": supplied,
                "inferred_cleanup_bytes": evidence.cleanup_bytes,
            })
            call_stack_cleanup.pop(evidence.target_address, None)
            continue
        call_stack_cleanup.setdefault(
            evidence.target_address, evidence.cleanup_bytes
        )
    recovered_calls = _recovered_call_inventory(recovered_indirect_edges)
    roots_set = {str(root) for root in roots if str(root) in by_id}
    known_slots = dict(initial_known_slots or {})
    if len(known_slots) > static_slot_budget or any(
        not isinstance(location, (int, _Origin))
        or origins is None
        or not origins
        or len(origins) > finite_value_budget
        or any(not _persistent_origin(origin) for origin in origins)
        for location, origins in known_slots.items()
    ):
        raise ValueError("initial interface-provenance slot seed is invalid")
    initial_known_slot_count = len(known_slots)
    root_argument_origins = _normalize_root_argument_origins(
        initial_root_argument_origins or {},
        roots=roots_set,
        finite_value_budget=finite_value_budget,
    )
    rejected_tainted_slots: set[_MemoryLocation] = set()
    final: _RunResult | None = None
    converged = False
    rounds = 0
    slot_capacity_exceeded = False
    for rounds in range(1, effective_fixed_point_budget + 1):
        final = _run_dataflow(
            by_id=by_id,
            roots=roots_set,
            outgoing=outgoing,
            indirect_exits=indirect_exits,
            inventory=inventory,
            import_abis=effective_import_abis,
            internal_call_preserved_registers=internal_call_preserved_registers,
            internal_call_stack_cleanup=call_stack_cleanup,
            internal_call_result_relations=supplied_call_result_relations,
            internal_call_memory_preservation=(
                supplied_call_memory_preservation
            ),
            internal_call_memory_result_relations=(
                supplied_call_memory_results
            ),
            internal_call_dependency_ids=internal_call_dependency_ids,
            recovered_calls=recovered_calls,
            bootstrap_unknown_call_preserved_registers=(
                bootstrap_unknown_call_preserved_registers
            ),
            image_base=image_base,
            known_slots=known_slots,
            root_argument_origins=root_argument_origins,
            finite_value_budget=finite_value_budget,
            static_slot_budget=static_slot_budget,
            stack_slot_budget=stack_slot_budget,
            checked_stack_entry_offsets=stack_entry_offsets,
            collect_path_recovery_proposals=collect_path_recovery_proposals,
            preserved_register_hypotheses=parsed_call_hypotheses,
            path_context_depth=path_context_depth,
            path_context_budget=path_context_budget,
        )
        proposed = {
            address: origins
            for address, origins in final.proposed_slots.items()
            if origins is not None
            and origins
            and address not in final.tainted_slots
            and address not in rejected_tainted_slots
            and all(_persistent_origin(origin) for origin in origins)
        }
        rejected_tainted_slots.update(final.tainted_slots)
        if not allow_global_slot_promotion:
            known_slots = {
                address: origins
                for address, origins in known_slots.items()
                if address not in rejected_tainted_slots
            }
            converged = True
            break
        retained_slots = {
            address: origins
            for address, origins in known_slots.items()
            if address not in rejected_tainted_slots
        }
        merged = _merge_slot_facts(
            retained_slots, proposed, finite_value_budget, static_slot_budget
        )
        if merged is None:
            slot_capacity_exceeded = True
            final.issues.append({
                "code": "interface_provenance_slot_capacity_exceeded",
                "slot_budget": static_slot_budget,
            })
            break
        if merged == known_slots:
            converged = True
            break
        known_slots = merged
    assert final is not None
    if not converged and not slot_capacity_exceeded:
        final.issues.append({
            "code": "interface_provenance_fixed_point_budget_exceeded",
            "rounds": rounds,
            "derived_domain_bound": fixed_point_budget is None,
        })
    final.issues.extend(cleanup_conflicts)
    callback_registrations = [
        row
        for row in final.argument_recoveries
        if row.get("record_kind") == "callback_registration"
    ]
    call_argument_recoveries = [
        row
        for row in final.argument_recoveries
        if row.get("record_kind") != "callback_registration"
    ]
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
    recovered_callable = sum(
        row["status"] == "recovered"
        and "resolved_export" in row.get("origin_kinds", [])
        for row in final.resolutions
    )
    memory_access_proposals = _memory_access_proposals(
        by_id=by_id,
        states=final.states,
        inventory=inventory,
        known_slots=known_slots,
        checked_stack_entry_offsets=stack_entry_offsets,
        finite_value_budget=finite_value_budget,
    )
    if recovered_known_slots is not None:
        recovered_known_slots.clear()
        recovered_known_slots.update({
            location: origins
            for location, origins in known_slots.items()
            if origins
        })
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
        "global_slot_promotion": {
            "enabled": allow_global_slot_promotion,
            "authority": (
                "diagnostic_proposal_only"
                if allow_global_slot_promotion
                else "disabled_requires_checked_global_slot_invariants_v2"
            ),
        },
        "required_replay": [
            "exact expression evaluation and bounded joins",
            "ordered inter-unit stack writes and out-parameter updates",
            "external machine-call footprints and successor worlds",
            "static-slot initialization and path invariants",
            "dynamic-range identities and field-update footprints",
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
        ] + [
            {
                "id": profile.profile_id,
                "sha256": profile.sha256,
                "kind": "callable-external-v2",
            }
            for profile in sorted(
                callable_external_profiles, key=lambda item: item.profile_id
            )
        ],
        "fixed_point": {
            "rounds": rounds,
            "converged": converged,
            "initial_known_slots": initial_known_slot_count,
        },
        "internal_call_cleanup_inference": [
            evidence.as_json(image_base=image_base)
            for evidence in cleanup_evidence
        ],
        "call_site_effects": [
            effect.as_json() for effect in final.call_site_effects
        ],
        "budgets": {
            "finite_values": finite_value_budget,
            "static_slots": static_slot_budget,
            "stack_slots": stack_slot_budget,
            "fixed_point_rounds": effective_fixed_point_budget,
            "path_context_depth": path_context_depth,
            "path_contexts_per_unit": path_context_budget,
            "fixed_point_bound_kind": (
                "explicit" if fixed_point_budget is not None else "finite_domain_height"
            ),
        },
        "static_interface_slots": [
            {
                "address": address,
                "origins": _origins_json(origins),
                "tainted": address in final.tainted_slots,
            }
            for address, origins in sorted(
                (
                    (address, origins)
                    for address, origins in known_slots.items()
                    if isinstance(address, int)
                ),
                key=lambda item: item[0],
            )
        ],
        "dynamic_interface_slots": [
            {
                "location": address.as_json(),
                "origins": _origins_json(origins),
                "tainted": address in final.tainted_slots,
            }
            for address, origins in sorted(
                (
                    (address, origins)
                    for address, origins in known_slots.items()
                    if isinstance(address, _Origin)
                ),
                key=lambda item: item[0],
            )
        ],
        "rejected_tainted_slots": [
            (
                {"kind": "static", "address": address}
                if isinstance(address, int)
                else {"kind": "dynamic", "location": address.as_json()}
            )
            for address in sorted(
                rejected_tainted_slots, key=_memory_location_sort_key
            )
        ],
        "resolutions": final.resolutions,
        # These path-sensitive rows are discovery hints only.  They capture a
        # finite target observed before a must-analysis join loses provenance;
        # the interprocedural driver must reproduce them in an unseeded or
        # explicitly inductive replay before they become authority.
        "path_recovery_proposals": final.path_recovery_proposals,
        "call_argument_recoveries": call_argument_recoveries,
        "callback_registrations": callback_registrations,
        "memory_access_proposals": memory_access_proposals,
        "issues": final.issues,
        "counts": {
            "units": len(units),
            "reached_units": len(final.states),
            "transfer_evaluations": final.evaluations,
            "transfer_requests": final.transfer_requests,
            "transfer_cache_hits": final.transfer_cache_hits,
            "indirect_exits": len(final.resolutions),
            "recovered_method_exits": recovered_interface,
            "recovered_operation_exits": recovered_operation,
            "recovered_callable_exits": recovered_callable,
            "recovered_indirect_exits": recovered,
            "path_recovery_proposals": len(final.path_recovery_proposals),
            "path_context_states": final.context_states,
            "path_context_evaluations": final.context_evaluations,
            "path_context_truncated_calls": final.context_truncated_calls,
            "path_context_dropped_states": final.context_dropped_states,
            "static_interface_slots": sum(
                isinstance(address, int) for address in known_slots
            ),
            "static_value_slots": sum(
                isinstance(address, int) for address in known_slots
            ),
            "dynamic_value_slots": sum(
                isinstance(address, _Origin) for address in known_slots
            ),
            "tainted_static_slots": sum(
                isinstance(address, int) for address in rejected_tainted_slots
            ),
            "tainted_dynamic_slots": sum(
                isinstance(address, _Origin) for address in rejected_tainted_slots
            ),
            "call_argument_recoveries": len(call_argument_recoveries),
            "callback_registrations": len(callback_registrations),
            "complete_callback_registrations": sum(
                row.get("status") == "complete"
                for row in callback_registrations
            ),
            "memory_access_proposals": len(memory_access_proposals),
            "inferred_internal_call_cleanups": sum(
                evidence.status == "complete"
                and evidence.target_address not in supplied_call_stack_cleanup
                for evidence in cleanup_evidence
            ),
            "finite_budget_exceeded": final.budget_exceeded,
            "issues": len(final.issues),
        },
    }


def _memory_access_proposals(
    *,
    by_id: Mapping[str, Mapping[str, Any]],
    states: Mapping[str, _State],
    inventory: "_ProfileInventory",
    known_slots: Mapping[_MemoryLocation, _Value],
    checked_stack_entry_offsets: Mapping[str, frozenset[int]],
    finite_value_budget: int,
) -> list[dict[str, Any]]:
    """Export bounded event-address facts from the converged input states.

    These remain proposals until the enclosing cold interprocedural pass binds
    them to exact unit/event identities and seals them with its authority hash.
    Mutable-slot-derived addresses are deliberately omitted so a slot invariant
    can never justify its own non-aliasing premise.
    """

    result: list[dict[str, Any]] = []
    for unit_id, input_state in sorted(states.items()):
        unit = by_id.get(unit_id)
        if unit is None:
            continue
        state = _with_checked_stack_entry(
            input_state,
            unit_id=unit_id,
            checked_stack_entry_offsets=checked_stack_entry_offsets,
        )
        semantics = _mapping(unit.get("semantics"))
        events = semantics.get("memory_events")
        if not isinstance(events, list):
            continue
        for event_index, raw in enumerate(events):
            event = _mapping(raw)
            kind = event.get("kind")
            width = _integer(event.get("width"))
            if kind not in {"read", "write", "read_write"} or width is None:
                continue
            origins = _evaluate(
                event.get("address"),
                state,
                inventory=inventory,
                known_slots=known_slots,
                budget=finite_value_budget,
            )
            if (
                origins is None
                or not origins
                or len(origins) > finite_value_budget
                or _has_global_slot_authority_dependency(origins)
            ):
                continue
            result.append({
                "format": MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
                "status": "complete",
                "unit_id": unit_id,
                "event_index": event_index,
                "memory_kind": kind,
                "width_bytes": width,
                "address_expression": copy.deepcopy(event.get("address")),
                "address_origins": _origins_json(origins),
                "authority_dependencies": list(value_dependencies(origins)),
            })
    return result


class _ProfileInventory:
    def __init__(
        self,
        profiles: Sequence[ExternalInterfaceProfile],
        *,
        callable_external_profiles: Sequence[CallableExternalProfile],
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
        self.observed_import_abis: dict[
            MachineImportIdentity, SelectedImportABI
        ] = {}
        self.static_data_reader = static_data_reader
        self.callable_profiles = {
            profile.sha256: profile for profile in callable_external_profiles
        }
        if len(self.callable_profiles) != len(callable_external_profiles):
            raise ValueError("duplicate callable-external profile")
        self.callable_resolvers: dict[
            MachineImportIdentity, tuple[str, CallableResolverProfileSpec]
        ] = {}
        self.callable_loaders: dict[
            MachineImportIdentity,
            list[tuple[str, CallableExternalTargetProfileSpec]],
        ] = defaultdict(list)
        for profile in callable_external_profiles:
            resolver_by_id = profile.resolver_by_id()
            for resolver in profile.resolvers:
                if resolver.identity in self.callable_resolvers:
                    raise ValueError(
                        f"ambiguous callable resolver import {resolver.identity}"
                    )
                self.callable_resolvers[resolver.identity] = (
                    profile.sha256,
                    resolver,
                )
            for target in profile.targets:
                if target.resolver_id not in resolver_by_id:
                    raise ValueError("callable target names an unknown resolver")
                self.callable_loaders[target.module.loader_identity].append(
                    (profile.sha256, target)
                )
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
            for event in _events(unit):
                selected = _selected_site_import_abi(event)
                if selected is None:
                    continue
                prior = self.observed_import_abis.get(selected.identity)
                if prior is not None and prior != selected:
                    raise ValueError(
                        "conflicting hash-bound import ABI contracts for "
                        f"{selected.identity}"
                    )
                self.observed_import_abis[selected.identity] = selected

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

    def callable_target(
        self, profile_sha256: str, target_id: int
    ) -> CallableExternalTargetProfileSpec | None:
        profile = self.callable_profiles.get(profile_sha256)
        return None if profile is None else profile.target_by_id(target_id)

    def callable_target_json(
        self,
        profile_sha256: str,
        target: CallableExternalTargetProfileSpec,
        *,
        transfer: str,
    ) -> dict[str, Any] | None:
        profile = self.callable_profiles.get(profile_sha256)
        if profile is None:
            return None
        resolver = profile.resolver_by_id().get(target.resolver_id)
        if resolver is None:
            return None
        return target.target_json(
            profile_id=profile.profile_id,
            profile_sha256=profile.sha256,
            resolver=resolver,
            transfer=transfer,
        )

    def immutable_u32_origin(self, address: int) -> _Origin | None:
        if self.static_data_reader is None:
            return None
        data = self.static_data_reader(address, 4)
        if data is None or len(data) != 4:
            return None
        value = int.from_bytes(data, "little") & 0xFFFFFFFF
        kind = "static_code" if len(self.unit_targets.get(value, ())) == 1 else "static_data"
        return _Origin(kind, (value, (address & 0xFFFFFFFF,)))


def _normalize_internal_call_memory_results(
    values: Mapping[int, Mapping[_Origin, _Value]],
    *,
    finite_value_budget: int,
) -> dict[int, dict[_Origin, _Value]]:
    """Validate bounded caller-visible memory outputs from call summaries."""

    result: dict[int, dict[_Origin, _Value]] = {}
    for target, raw_outputs in values.items():
        if (
            not isinstance(target, int)
            or isinstance(target, bool)
            or not 0 <= target <= 0xFFFFFFFF
            or not isinstance(raw_outputs, Mapping)
        ):
            raise ValueError("internal-call memory-result relation is invalid")
        outputs: dict[_Origin, _Value] = {}
        for location, origins in raw_outputs.items():
            if (
                not isinstance(location, _Origin)
                or location.kind
                not in {
                    "exact",
                    "stack_location",
                    "dynamic_range",
                    "dynamic_location",
                    "symbolic_affine",
                }
                or origins is None
                or not isinstance(origins, frozenset)
                or not origins
                or len(origins) > finite_value_budget
                or any(
                    not isinstance(origin, _Origin)
                    or not _persistent_origin(origin)
                    for origin in origins
                )
            ):
                raise ValueError(
                    "internal-call memory-result output is invalid"
                )
            outputs[location] = origins
        result[target] = outputs
    return result


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
    internal_call_result_relations: Mapping[
        int, Mapping[str, Sequence[Mapping[str, Any]]]
    ],
    internal_call_memory_preservation: Mapping[int, bool],
    internal_call_memory_result_relations: Mapping[
        int, Mapping[_Origin, _Value]
    ],
    internal_call_dependency_ids: Mapping[tuple[str, int], frozenset[str]],
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
    bootstrap_unknown_call_preserved_registers: frozenset[str] | None,
    image_base: int,
    known_slots: Mapping[_MemoryLocation, _Value],
    root_argument_origins: Mapping[str, Mapping[int, _Value]],
    finite_value_budget: int,
    static_slot_budget: int,
    stack_slot_budget: int,
    checked_stack_entry_offsets: Mapping[str, frozenset[int]],
    collect_path_recovery_proposals: bool,
    preserved_register_hypotheses: Mapping[
        CallSiteId, Mapping[str, PreservedRegisterHypothesis]
    ],
    path_context_depth: int,
    path_context_budget: int,
) -> _RunResult:
    input_states = {
        root: _initial_root_state(
            root,
            known_slots,
            root_argument_origins.get(root, {}),
        )
        for root in roots
    }
    priorities = _reverse_postorder_priorities(roots, outgoing)
    work = [(priorities[root], root) for root in sorted(roots)]
    heapq.heapify(work)
    queued = set(roots)
    proposed_slots: dict[_MemoryLocation, _Value] = {}
    tainted_slots: set[_MemoryLocation] = set()
    issues: list[dict[str, Any]] = []
    argument_recoveries: list[dict[str, Any]] = []
    call_site_effects: list[CallSiteEffect] = []
    evaluations = 0
    transfer_requests = 0
    transfer_cache_hits = 0
    budget_exceeded = 0
    transfer_cache: dict[tuple[str, tuple[Any, ...]], _UnitTransfer] = {}
    exits_by_source: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for exit_record in indirect_exits:
        source = exit_record.get("source_unit_id")
        if isinstance(source, str):
            exits_by_source[source].append(exit_record)
    path_recoveries: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)

    def transfer_state(source_id: str, input_state: _State) -> _UnitTransfer:
        nonlocal evaluations, transfer_requests, transfer_cache_hits, budget_exceeded
        transfer_requests += 1
        checked_state = _with_checked_stack_entry(
            input_state,
            unit_id=source_id,
            checked_stack_entry_offsets=checked_stack_entry_offsets,
        )
        key = (source_id, _state_cache_key(checked_state))
        cached = transfer_cache.get(key)
        if cached is not None:
            transfer_cache_hits += 1
            return cached
        result = _transfer_unit(
            unit_id=source_id,
            unit=by_id[source_id],
            input_state=checked_state,
            inventory=inventory,
            import_abis=import_abis,
            internal_call_preserved_registers=internal_call_preserved_registers,
            internal_call_stack_cleanup=internal_call_stack_cleanup,
            internal_call_result_relations=internal_call_result_relations,
            internal_call_memory_preservation=(
                internal_call_memory_preservation
            ),
            internal_call_memory_result_relations=(
                internal_call_memory_result_relations
            ),
            internal_call_dependency_ids=internal_call_dependency_ids,
            recovered_calls=recovered_calls,
            bootstrap_unknown_call_preserved_registers=(
                bootstrap_unknown_call_preserved_registers
            ),
            preserved_register_hypotheses=preserved_register_hypotheses,
            image_base=image_base,
            known_slots=known_slots,
            finite_value_budget=finite_value_budget,
            static_slot_budget=static_slot_budget,
            stack_slot_budget=stack_slot_budget,
        )
        transfer_cache[key] = result
        evaluations += 1
        budget_exceeded += result[-1]
        return result

    def transfer_unit(source_id: str) -> _UnitTransfer:
        return transfer_state(source_id, input_states[source_id])

    while work:
        _, source_id = heapq.heappop(work)
        queued.remove(source_id)
        if collect_path_recovery_proposals and exits_by_source.get(source_id):
            checked_state = _with_checked_stack_entry(
                input_states[source_id],
                unit_id=source_id,
                checked_stack_entry_offsets=checked_stack_entry_offsets,
            )
            for proposal in _resolve_exits(
                exits_by_source[source_id],
                by_id=by_id,
                states={source_id: checked_state},
                inventory=inventory,
                import_abis=import_abis,
                known_slots=known_slots,
                finite_value_budget=finite_value_budget,
            ):
                if proposal.get("status") != "recovered":
                    continue
                identity = str(proposal.get("id") or "")
                projection = _recovery_target_projection(proposal)
                key = json.dumps(
                    projection,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                )
                existing = path_recoveries[identity].get(key)
                path_recoveries[identity][key] = _merge_path_recovery_proposal(
                    existing,
                    proposal,
                    finite_value_budget=finite_value_budget,
                )
        (
            transfer,
            _,
            _,
            _,
            _,
            _,
            exceeded,
        ) = transfer_unit(source_id)
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
                    return_rva = None
                    if index is not None:
                        events = _events(by_id[source_id])
                        if 0 <= index < len(events):
                            return_rva = _integer(events[index].get("return_rva"))
                    contribution = _enter_call_frame(
                        contribution,
                        return_address=(
                            None
                            if return_rva is None
                            else (image_base + return_rva) & 0xFFFFFFFF
                        ),
                    )
            if edge.guard_json is not None:
                guard = _guard_in_post_state(
                    by_id[source_id], json.loads(edge.guard_json)
                )
                contribution = _refine_state_for_guard(
                    contribution,
                    guard,
                    inventory=inventory,
                    known_slots=known_slots,
                    finite_value_budget=finite_value_budget,
                )
                if contribution is None:
                    continue
            if _join_state(
                input_states,
                edge.target_id,
                contribution,
                finite_value_budget,
                static_slot_budget,
                stack_slot_budget,
            ) and edge.target_id not in queued:
                heapq.heappush(
                    work,
                    (priorities.get(edge.target_id, len(priorities)), edge.target_id),
                )
                queued.add(edge.target_id)

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
            unit_call_site_effects,
            exceeded,
        ) = transfer_unit(source_id)
        issues.extend(transfer_issues)
        argument_recoveries.extend(unit_argument_recoveries)
        call_site_effects.extend(unit_call_site_effects)
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
    legacy_path_proposals = _finalize_path_recovery_proposals(
        resolutions, path_recoveries
    )
    contextual = (
        _run_contextual_target_discovery(
            by_id=by_id,
            roots=roots,
            outgoing=outgoing,
            indirect_exits=indirect_exits,
            target_exit_ids=_context_target_exit_ids(
                legacy_path_proposals=legacy_path_proposals,
                final_resolutions=resolutions,
            ),
            final_resolutions=resolutions,
            inventory=inventory,
            import_abis=import_abis,
            known_slots=known_slots,
            root_argument_origins=root_argument_origins,
            image_base=image_base,
            finite_value_budget=finite_value_budget,
            static_slot_budget=static_slot_budget,
            stack_slot_budget=stack_slot_budget,
            checked_stack_entry_offsets=checked_stack_entry_offsets,
            transfer_state=transfer_state,
            context_depth=path_context_depth,
            contexts_per_unit=path_context_budget,
        )
        if collect_path_recovery_proposals
        else _ContextDiscoveryResult([], [], 0, 0, 0, 0)
    )
    issues.extend(contextual.issues)
    path_recovery_proposals = _merge_context_and_legacy_proposals(
        contextual.proposals,
        legacy_path_proposals,
    )
    return _RunResult(
        states=input_states,
        resolutions=resolutions,
        path_recovery_proposals=path_recovery_proposals,
        proposed_slots=proposed_slots,
        tainted_slots=tainted_slots,
        issues=_deduplicate(issues),
        argument_recoveries=_deduplicate(argument_recoveries),
        call_site_effects=sorted(
            call_site_effects,
            key=lambda effect: (
                effect.site.unit_id,
                effect.site.event_index,
            ),
        ),
        evaluations=evaluations,
        transfer_requests=transfer_requests,
        transfer_cache_hits=transfer_cache_hits,
        budget_exceeded=budget_exceeded,
        context_states=contextual.context_states,
        context_evaluations=contextual.evaluations,
        context_truncated_calls=contextual.truncated_calls,
        context_dropped_states=contextual.dropped_contexts,
    )


def _normalize_root_argument_origins(
    value: Mapping[str, Mapping[int, _Value]],
    *,
    roots: set[str],
    finite_value_budget: int,
) -> dict[str, dict[int, frozenset[_Origin]]]:
    result: dict[str, dict[int, frozenset[_Origin]]] = {}
    for unit_id, arguments in value.items():
        if unit_id not in roots or not isinstance(arguments, Mapping):
            raise ValueError("callback root arguments reference an unknown root")
        normalized: dict[int, frozenset[_Origin]] = {}
        for argument_index, origins in arguments.items():
            if (
                not isinstance(argument_index, int)
                or isinstance(argument_index, bool)
                or not 0 <= argument_index < 64
                or origins is None
                or not 1 <= len(origins) <= finite_value_budget
                or any(
                    not isinstance(origin, _Origin)
                    or not _persistent_origin(origin)
                    for origin in origins
                )
            ):
                raise ValueError("callback root argument origin is invalid")
            normalized[argument_index] = frozenset(origins)
        result[unit_id] = normalized
    return result


def _initial_root_state(
    root: str,
    known_slots: Mapping[_MemoryLocation, _Value],
    argument_origins: Mapping[int, _Value] | None = None,
) -> _State:
    return _State(
        {
            register: (
                _stack_location(0)
                if register == "esp"
                else _symbolic_affine_value(f"{root}:{register}")
            )
            for register in _REGISTERS
        },
        dict(known_slots),
        {
            4 + argument_index * 4: _StackCell(origins, ())
            for argument_index, origins in (argument_origins or {}).items()
        },
    )


def _context_target_exit_ids(
    *,
    legacy_path_proposals: Sequence[Mapping[str, Any]],
    final_resolutions: Sequence[Mapping[str, Any]],
) -> frozenset[str]:
    """Select exits where bounded call history can recover lost provenance."""

    identities = {
        str(row.get("id"))
        for row in legacy_path_proposals
        if isinstance(row.get("id"), str)
    }
    identities.update(
        str(row["id"])
        for row in final_resolutions
        if isinstance(row.get("id"), str)
        and row.get("status") != "recovered"
        and _mapping(row.get("failure")).get("code")
        == "register_target_origin_missing"
    )
    return frozenset(identities)


def _run_contextual_target_discovery(
    *,
    by_id: Mapping[str, Mapping[str, Any]],
    roots: set[str],
    outgoing: Mapping[str, set[_Edge]],
    indirect_exits: Sequence[Mapping[str, Any]],
    target_exit_ids: frozenset[str],
    final_resolutions: Sequence[Mapping[str, Any]],
    inventory: _ProfileInventory,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    known_slots: Mapping[_MemoryLocation, _Value],
    root_argument_origins: Mapping[str, Mapping[int, _Value]],
    image_base: int,
    finite_value_budget: int,
    static_slot_budget: int,
    stack_slot_budget: int,
    checked_stack_entry_offsets: Mapping[str, frozenset[int]],
    transfer_state: Callable[[str, _State], _UnitTransfer],
    context_depth: int = 1,
    contexts_per_unit: int = 64,
) -> _ContextDiscoveryResult:
    """Recover targets without collapsing distinct bounded call histories."""

    selected_exits = [
        row
        for row in indirect_exits
        if isinstance(row.get("id"), str)
        and row.get("id") in target_exit_ids
        and isinstance(row.get("source_unit_id"), str)
    ]
    exit_sources = {
        str(row["source_unit_id"])
        for row in selected_exits
    }
    relevant_units = _backward_slice_units(exit_sources, outgoing=outgoing)
    states: dict[tuple[str, _PathContext], _State] = {}
    contexts_by_unit: dict[str, set[_PathContext]] = defaultdict(set)
    pending: deque[tuple[str, _PathContext]] = deque()
    queued: set[tuple[str, _PathContext]] = set()
    for root in sorted(roots & relevant_units):
        context = _PathContext(root)
        key = (root, context)
        states[key] = _initial_root_state(
            root,
            known_slots,
            root_argument_origins.get(root, {}),
        )
        contexts_by_unit[root].add(context)
        pending.append(key)
        queued.add(key)

    exits_by_source: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for exit_record in selected_exits:
        source = exit_record.get("source_unit_id")
        if isinstance(source, str):
            exits_by_source[source].append(exit_record)

    dropped_units: set[str] = set()
    truncated_calls = 0
    dropped_contexts = 0
    evaluations = 0
    step_budget = max(
        4096,
        len(by_id) * min(contexts_per_unit, 8) * (finite_value_budget + 3),
    )
    steps = 0
    while pending and steps < step_budget:
        source_id, context = pending.popleft()
        queued.discard((source_id, context))
        steps += 1
        state = states[(source_id, context)]
        transfer = transfer_state(source_id, state)
        evaluations += 1
        for edge in sorted(
            outgoing.get(source_id, ()),
            key=lambda item: (
                item.target_id,
                item.kind,
                item.event_index or -1,
                item.guard_json or "",
            ),
        ):
            if edge.target_id not in relevant_units:
                continue
            contribution = transfer[0][0]
            next_context = context
            if edge.kind in {"internal_call", "indirect_call"}:
                event_index = edge.event_index
                contribution = (
                    transfer[0][1].get(event_index)
                    if event_index is not None
                    else None
                )
                if contribution is None:
                    contribution = _unknown_state()
                else:
                    return_rva = None
                    if event_index is not None:
                        events = _events(by_id[source_id])
                        if 0 <= event_index < len(events):
                            return_rva = _integer(
                                events[event_index].get("return_rva")
                            )
                    contribution = _enter_call_frame(
                        contribution,
                        return_address=(
                            None
                            if return_rva is None
                            else (image_base + return_rva) & 0xFFFFFFFF
                        ),
                    )
                    next_context, truncated = context.push(
                        _CallContextFrame(
                            source_id,
                            -1 if event_index is None else event_index,
                            edge.target_id,
                        ),
                        depth=context_depth,
                    )
                    truncated_calls += int(truncated)
            if edge.guard_json is not None:
                guard = _guard_in_post_state(
                    by_id[source_id], json.loads(edge.guard_json)
                )
                contribution = _refine_state_for_guard(
                    contribution,
                    guard,
                    inventory=inventory,
                    known_slots=known_slots,
                    finite_value_budget=finite_value_budget,
                )
                if contribution is None:
                    continue
            target_key = (edge.target_id, next_context)
            if (
                target_key not in states
                and next_context not in contexts_by_unit[edge.target_id]
                and len(contexts_by_unit[edge.target_id]) >= contexts_per_unit
            ):
                dropped_units.add(edge.target_id)
                dropped_contexts += 1
                continue
            contexts_by_unit[edge.target_id].add(next_context)
            if _join_context_state(
                states,
                target_key,
                contribution,
                finite_value_budget,
                static_slot_budget,
                stack_slot_budget,
            ) and target_key not in queued:
                pending.append(target_key)
                queued.add(target_key)

    work_budget_exceeded = bool(pending)
    if work_budget_exceeded:
        dropped_units.update(unit_id for unit_id, _context in pending)

    impacted_exits = _context_overflow_impacted_exits(
        dropped_units=dropped_units,
        outgoing=outgoing,
        exits_by_source=exits_by_source,
    )
    final_by_id = {
        str(row.get("id")): row
        for row in final_resolutions
        if isinstance(row.get("id"), str)
    }
    contextual_rows: dict[str, list[tuple[_PathContext, dict[str, Any]]]] = (
        defaultdict(list)
    )
    for (source_id, context), state in sorted(states.items()):
        exits = exits_by_source.get(source_id, ())
        if not exits:
            continue
        checked = _with_checked_stack_entry(
            state,
            unit_id=source_id,
            checked_stack_entry_offsets=checked_stack_entry_offsets,
        )
        for resolution in _resolve_exits(
            exits,
            by_id=by_id,
            states={source_id: checked},
            inventory=inventory,
            import_abis=import_abis,
            known_slots=known_slots,
            finite_value_budget=finite_value_budget,
        ):
            identity = resolution.get("id")
            if isinstance(identity, str):
                contextual_rows[identity].append((context, resolution))

    proposals = [
        _contextual_recovery_proposal(
            identity=identity,
            final_resolution=final_by_id.get(identity, {}),
            rows=rows,
            impacted=identity in impacted_exits or work_budget_exceeded,
            finite_value_budget=finite_value_budget,
            truncated_calls=truncated_calls,
        )
        for identity, rows in sorted(contextual_rows.items())
        if final_by_id.get(identity, {}).get("status") != "recovered"
    ]
    issues: list[dict[str, Any]] = []
    if dropped_contexts:
        issues.append({
            "code": "bounded_call_context_budget_exceeded",
            "contexts_per_unit": contexts_per_unit,
            "dropped_contexts": dropped_contexts,
            "impacted_exit_ids": sorted(impacted_exits),
        })
    if work_budget_exceeded:
        issues.append({
            "code": "bounded_call_context_work_budget_exceeded",
            "step_budget": step_budget,
            "pending_states": len(pending),
        })
    return _ContextDiscoveryResult(
        proposals=proposals,
        issues=issues,
        context_states=len(states),
        truncated_calls=truncated_calls,
        dropped_contexts=dropped_contexts,
        evaluations=evaluations,
    )


def _backward_slice_units(
    exit_sources: set[str], *, outgoing: Mapping[str, set[_Edge]]
) -> set[str]:
    """Retain every graph path that can reach a selected unresolved exit."""

    incoming: dict[str, set[str]] = defaultdict(set)
    for source, edges in outgoing.items():
        for edge in edges:
            incoming[edge.target_id].add(source)
    relevant = set(exit_sources)
    pending = deque(sorted(exit_sources))
    while pending:
        target = pending.popleft()
        for source in sorted(incoming.get(target, ())):
            if source in relevant:
                continue
            relevant.add(source)
            pending.append(source)
    return relevant


def _join_context_state(
    states: dict[tuple[str, _PathContext], _State],
    target: tuple[str, _PathContext],
    contribution: _State,
    value_budget: int,
    slot_budget: int,
    stack_slot_budget: int,
) -> bool:
    prior = states.get(target)
    if prior is None:
        states[target] = contribution
        return True
    temporary = {target[0]: prior}
    changed = _join_state(
        temporary,
        target[0],
        contribution,
        value_budget,
        slot_budget,
        stack_slot_budget,
    )
    if changed:
        states[target] = temporary[target[0]]
    return changed


def _context_overflow_impacted_exits(
    *,
    dropped_units: set[str],
    outgoing: Mapping[str, set[_Edge]],
    exits_by_source: Mapping[str, Sequence[Mapping[str, Any]]],
) -> set[str]:
    impacted: set[str] = set()
    pending = deque(sorted(dropped_units))
    seen: set[str] = set()
    while pending:
        unit_id = pending.popleft()
        if unit_id in seen:
            continue
        seen.add(unit_id)
        impacted.update(
            str(row.get("id"))
            for row in exits_by_source.get(unit_id, ())
            if isinstance(row.get("id"), str)
        )
        pending.extend(
            edge.target_id
            for edge in outgoing.get(unit_id, ())
            if edge.target_id not in seen
        )
    return impacted


def _contextual_recovery_proposal(
    *,
    identity: str,
    final_resolution: Mapping[str, Any],
    rows: Sequence[tuple[_PathContext, Mapping[str, Any]]],
    impacted: bool,
    finite_value_budget: int,
    truncated_calls: int,
) -> dict[str, Any]:
    context_records = [
        {
            **context.as_json(),
            "status": str(row.get("status") or "incomplete"),
            "target_rvas": copy.deepcopy(row.get("target_rvas", [])),
            "target_unit_ids": copy.deepcopy(row.get("target_unit_ids", [])),
            "failure": copy.deepcopy(row.get("failure")),
        }
        for context, row in sorted(rows, key=lambda item: item[0])
    ]
    incomplete = [
        record for record in context_records if record["status"] != "recovered"
    ]
    target_rvas = sorted({
        int(value)
        for _context, row in rows
        for value in row.get("target_rvas", ())
        if isinstance(value, int) and not isinstance(value, bool)
    })
    target_unit_ids = sorted({
        str(value)
        for _context, row in rows
        for value in row.get("target_unit_ids", ())
        if isinstance(value, str)
    })
    external_by_key = {
        json.dumps(value, sort_keys=True, separators=(",", ":")): copy.deepcopy(value)
        for _context, row in rows
        for value in row.get("external_targets", ())
        if isinstance(value, Mapping)
    }
    target_count = len(target_rvas) + len(external_by_key)
    complete = (
        bool(rows)
        and not impacted
        and not incomplete
        and 0 < target_count <= finite_value_budget
    )
    coverage = {
        "format": "bounded-call-context-coverage-v1",
        "status": "complete" if complete else "incomplete",
        "context_count": len(context_records),
        "complete_contexts": len(context_records) - len(incomplete),
        "incomplete_contexts": len(incomplete),
        "impacted_by_budget": impacted,
        "truncated_call_histories": truncated_calls,
        "contexts": context_records,
    }
    base = copy.deepcopy(dict(final_resolution))
    if not complete:
        return {
            **base,
            "id": identity,
            "status": "incomplete",
            "closure": "unresolved",
            "target_rvas": [],
            "target_unit_ids": [],
            "external_targets": [],
            "proposal_source": "bounded_call_context_v1",
            "proof_authority": False,
            "context_coverage": coverage,
            "failure": {
                "code": (
                    "bounded_call_context_target_budget_exceeded"
                    if target_count > finite_value_budget
                    else "bounded_call_context_coverage_incomplete"
                ),
                "target_count": target_count,
            },
        }
    witnesses = {
        json.dumps(value, sort_keys=True, separators=(",", ":")): copy.deepcopy(value)
        for _context, row in rows
        for value in row.get("target_origin_witnesses", ())
        if isinstance(value, Mapping)
    }
    dependencies = sorted({
        str(value)
        for _context, row in rows
        for value in row.get("analysis_dependencies", ())
        if isinstance(value, str)
    })
    origin_kinds = sorted({
        str(value)
        for _context, row in rows
        for value in row.get("origin_kinds", ())
        if isinstance(value, str)
    })
    exemplar = copy.deepcopy(dict(rows[0][1]))
    return {
        **exemplar,
        "id": identity,
        "status": "recovered",
        "closure": "checked_finite_bounded_call_context_union",
        "target_rvas": target_rvas,
        "target_unit_ids": target_unit_ids,
        "external_targets": [external_by_key[key] for key in sorted(external_by_key)],
        "origin_count": len(witnesses),
        "origin_kinds": origin_kinds,
        "target_origin_witnesses": [witnesses[key] for key in sorted(witnesses)],
        "analysis_dependencies": dependencies,
        "proposal_source": "bounded_call_context_v1",
        "proof_authority": False,
        "context_coverage": coverage,
        "failure": None,
    }


def _merge_context_and_legacy_proposals(
    contextual: Sequence[Mapping[str, Any]],
    legacy: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Prefer complete context coverage; retain legacy hints as diagnostics."""

    contextual_by_id = {
        str(row.get("id")): row
        for row in contextual
        if isinstance(row.get("id"), str)
    }
    legacy_by_id = {
        str(row.get("id")): row
        for row in legacy
        if isinstance(row.get("id"), str)
    }
    result: list[dict[str, Any]] = []
    for identity in sorted(contextual_by_id.keys() | legacy_by_id.keys()):
        contextual_row = contextual_by_id.get(identity)
        legacy_row = legacy_by_id.get(identity)
        if contextual_row is not None:
            selected = copy.deepcopy(dict(contextual_row))
            if legacy_row is not None:
                selected["legacy_path_hint"] = copy.deepcopy(dict(legacy_row))
            result.append(selected)
            continue
        assert legacy_row is not None
        selected = copy.deepcopy(dict(legacy_row))
        selected.update({
            "status": "incomplete",
            "closure": "unresolved",
            "target_rvas": [],
            "target_unit_ids": [],
            "external_targets": [],
            "failure": {"code": "bounded_call_context_coverage_missing"},
        })
        result.append(selected)
    return result


def _state_cache_key(state: _State) -> tuple[Any, ...]:
    """Canonical immutable identity for one abstract unit input state."""

    return (
        tuple(
            (register, _value_cache_key(state.registers.get(register)))
            for register in _REGISTERS
        ),
        tuple(
            sorted(
                (
                    _memory_location_cache_key(location),
                    _value_cache_key(value),
                )
                for location, value in state.memory.items()
            )
        ),
        tuple(
            (
                offset,
                _value_cache_key(cell.value),
                tuple(cell.witnesses),
            )
            for offset, cell in sorted(state.stack.items())
        ),
        state.memory_invalidated,
    )


def _memory_location_cache_key(location: _MemoryLocation) -> tuple[Any, ...]:
    if isinstance(location, int):
        return ("exact", location & 0xFFFFFFFF)
    return ("origin", location.kind, _canonical_origin_key(location.key))


def _value_cache_key(value: _Value) -> tuple[Any, ...] | None:
    if value is None:
        return None
    return tuple(
        (
            origin.kind,
            _canonical_origin_key(origin.key),
            origin.dependencies,
        )
        for origin in sorted(value)
    )


def _canonical_origin_key(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _reverse_postorder_priorities(
    roots: Iterable[str], outgoing: Mapping[str, set[_Edge]]
) -> dict[str, int]:
    visited: set[str] = set()
    postorder: list[str] = []
    for root in sorted(set(roots)):
        if root in visited:
            continue
        stack: list[tuple[str, bool]] = [(root, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                postorder.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.append((node, True))
            successors = sorted(
                {edge.target_id for edge in outgoing.get(node, ())},
                reverse=True,
            )
            stack.extend((target, False) for target in successors)
    return {
        node: index
        for index, node in enumerate(reversed(postorder))
    }


def _normalize_checked_stack_entry_offsets(
    values: Mapping[str, Sequence[int]],
    *,
    finite_value_budget: int,
) -> dict[str, frozenset[int]]:
    result: dict[str, frozenset[int]] = {}
    for unit_id, raw_offsets in values.items():
        if not isinstance(unit_id, str) or not unit_id:
            raise ValueError("checked stack-entry unit ID is invalid")
        if not isinstance(raw_offsets, Sequence) or isinstance(
            raw_offsets, (str, bytes)
        ):
            raise ValueError(
                f"checked stack-entry offsets for {unit_id!r} are not a sequence"
            )
        if not raw_offsets:
            raise ValueError(
                f"checked stack-entry offsets for {unit_id!r} are empty"
            )
        if len(raw_offsets) > finite_value_budget:
            raise ValueError(
                "checked stack-entry offsets exceed the finite-value budget: "
                f"unit={unit_id!r} alternatives={len(raw_offsets)} "
                f"budget={finite_value_budget}"
            )
        if any(
            not isinstance(offset, int) or isinstance(offset, bool)
            for offset in raw_offsets
        ):
            raise ValueError(
                f"checked stack-entry offsets for {unit_id!r} contain a non-integer"
            )
        result[unit_id] = frozenset(int(offset) for offset in raw_offsets)
    return result


def _with_checked_stack_entry(
    state: _State,
    *,
    unit_id: str,
    checked_stack_entry_offsets: Mapping[str, frozenset[int]],
) -> _State:
    offsets = checked_stack_entry_offsets.get(unit_id)
    if not offsets:
        return state
    checked = frozenset(
        _Origin("stack_location", (offset,)) for offset in offsets
    )
    existing = state.registers.get("esp")
    if existing is None:
        selected = checked
    elif all(origin.kind == "stack_location" for origin in existing):
        selected = existing & checked
        if not selected:
            return state
    else:
        return state
    if selected == existing:
        return state
    return _State(
        {**state.registers, "esp": selected},
        state.memory,
        state.stack,
        state.memory_invalidated,
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
    internal_call_result_relations: Mapping[
        int, Mapping[str, Sequence[Mapping[str, Any]]]
    ],
    internal_call_memory_preservation: Mapping[int, bool],
    internal_call_memory_result_relations: Mapping[
        int, Mapping[_Origin, _Value]
    ],
    internal_call_dependency_ids: Mapping[tuple[str, int], frozenset[str]],
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
    bootstrap_unknown_call_preserved_registers: frozenset[str] | None,
    preserved_register_hypotheses: Mapping[
        CallSiteId, Mapping[str, PreservedRegisterHypothesis]
    ],
    image_base: int,
    known_slots: Mapping[_MemoryLocation, _Value],
    finite_value_budget: int,
    static_slot_budget: int,
    stack_slot_budget: int,
) -> _UnitTransfer:
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
    proposals: dict[_MemoryLocation, _Value] = {}
    taints: set[_MemoryLocation] = set()
    issues: list[dict[str, Any]] = []
    argument_recoveries: list[dict[str, Any]] = []
    if calls:
        if len(calls) != 1:
            issues.append({"code": "multiple_calls_in_interface_unit", "unit_id": unit_id})
            call_site_effects = tuple(
                _call_site_effect(
                    unit_id=unit_id,
                    event_index=event_index,
                    transfer_kind=str(event["kind"]),
                    facts=_CallFacts(None, None, None, None, {}),
                    failure_codes=("multiple_calls_in_interface_unit",),
                )
                for event_index, event in calls
            )
            return (
                (_unknown_state(), call_entries),
                proposals,
                taints,
                issues,
                argument_recoveries,
                call_site_effects,
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
            internal_call_result_relations=internal_call_result_relations,
            internal_call_memory_preservation=(
                internal_call_memory_preservation
            ),
            internal_call_memory_result_relations=(
                internal_call_memory_result_relations
            ),
            internal_call_dependency_ids=internal_call_dependency_ids,
            recovered_calls=recovered_calls,
            image_base=image_base,
            known_slots=known_slots,
            budget=finite_value_budget,
        )
        issues.extend(call_issues)
        argument_recoveries.extend(call_argument_recoveries)
        hypotheses = preserved_register_hypotheses.get(
            CallSiteId(unit_id, event_index), {}
        )
        if facts.preserved is None and hypotheses:
            facts = _with_preserved_register_hypotheses(facts, hypotheses)
            issues.append({
                "code": "inductive_call_frame_hypothesis_used",
                "unit_id": unit_id,
                "event_index": event_index,
                "hypothesis_ids": sorted(
                    hypothesis.id for hypothesis in hypotheses.values()
                ),
            })
        if (
            facts.preserved is None
            and bootstrap_unknown_call_preserved_registers is not None
        ):
            site = CallSiteId(unit_id, event_index)
            register_dependencies = {
                register: frozenset({
                    call_frame_hypothesis_id(
                        site.unit_id, site.event_index, register
                    )
                })
                for register in bootstrap_unknown_call_preserved_registers
            }
            facts = _CallFacts(
                preserved=bootstrap_unknown_call_preserved_registers,
                abi=facts.abi,
                argument_words=facts.argument_words,
                stack_cleanup_bytes=facts.stack_cleanup_bytes,
                outputs=facts.outputs,
                memory_preserved=facts.memory_preserved,
                memory_writes=facts.memory_writes,
                dependencies=facts.dependencies,
                register_dependencies=register_dependencies,
            )
            issues.append({
                "code": "bootstrap_call_preservation_used",
                "unit_id": unit_id,
                "event_index": event_index,
                "call_kind": str(event["kind"]),
                "preserved_registers": sorted(
                    bootstrap_unknown_call_preserved_registers
                ),
                "hypothesis_ids": sorted(
                    next(iter(dependencies))
                    for dependencies in register_dependencies.values()
                ),
            })
        call_site_effects = (_call_site_effect(
            unit_id=unit_id,
            event_index=event_index,
            transfer_kind=str(event["kind"]),
            facts=facts,
        ),)
        framed_memory, framed_stack, memory_invalidated = _apply_call_memory_frame(
            pre_call, facts
        )
        if facts.memory_writes is not None:
            taints.update(
                location
                for location in pre_call.memory
                if location not in framed_memory
                and (
                    isinstance(location, int)
                    or location.kind in {"dynamic_range", "dynamic_location"}
                )
            )
        output = _State(
            registers={
                register: (
                    with_value_dependencies(
                        pre_call.registers.get(register),
                        facts.dependencies
                        | facts.register_dependencies.get(register, frozenset()),
                    )
                    if facts.preserved is not None and register in facts.preserved
                    else None
                )
                for register in _REGISTERS
            },
            memory={
                location: with_value_dependencies(value, facts.dependencies)
                for location, value in framed_memory.items()
            },
            stack={
                offset: _StackCell(
                    with_value_dependencies(cell.value, facts.dependencies),
                    cell.witnesses,
                )
                for offset, cell in framed_stack.items()
            },
            memory_invalidated=memory_invalidated,
        )
        _apply_call_stack_result(output, pre_call, facts)
        for address, origins in facts.outputs.items():
            origins = with_value_dependencies(origins, facts.dependencies)
            if address.kind == "exact":
                concrete = int(address.key[0]) & 0xFFFFFFFF
                output.memory[concrete] = origins
                proposals[concrete] = origins
                taints.discard(concrete)
            elif address.kind == "stack_location":
                offset = int(address.key[0])
                output.stack[offset] = _StackCell(origins, ())
            elif address.kind == "register_location":
                register = str(address.key[0])
                if register in output.registers:
                    output.registers[register] = origins
            elif address.kind in {"dynamic_range", "dynamic_location"}:
                location = _dynamic_memory_location(address)
                output.memory[location] = origins
                proposals[location] = origins
                taints.discard(location)
            elif address.kind == "symbolic_affine":
                # Parametric addresses remain local replay facts.  They are
                # deliberately excluded from persistent slot proposals.
                output.memory[address] = origins
                taints.discard(address)
        if len(output.stack) > stack_slot_budget:
            output.stack.clear()
            output.registers["esp"] = None
            return (
                (output, call_entries),
                proposals,
                taints,
                issues,
                argument_recoveries,
                call_site_effects,
                1,
            )
        return (
            (output, call_entries),
            proposals,
            taints,
            issues,
            argument_recoveries,
            call_site_effects,
            0,
        )

    output = _State(
        dict(input_state.registers),
        dict(input_state.memory),
        dict(input_state.stack),
        input_state.memory_invalidated,
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
            (),
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
                _invalidate_unknown_memory_write(
                    output,
                    proposals=proposals,
                    taints=taints,
                )
                issues.append({
                    "code": "memory_write_address_not_singleton",
                    "unit_id": unit_id,
                    "event_index": memory_event_index,
                })
                continue
            address = next(iter(addresses))
            value = _evaluate(
                event.get("value"),
                input_state,
                inventory=inventory,
                known_slots=known_slots,
                budget=finite_value_budget,
            )
            value = with_value_dependencies(value, address.dependencies)
            if address.kind == "exact":
                # An exact concrete update supersedes any symbolic location
                # that might denote the same address.  Concrete and checked
                # range locations remain point-sensitive.
                output.memory = {
                    location: origins
                    for location, origins in output.memory.items()
                    if not (
                        isinstance(location, _Origin)
                        and location.kind == "symbolic_affine"
                    )
                }
                concrete = int(address.key[0]) & 0xFFFFFFFF
                if value is None:
                    output.memory[concrete] = None
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
            elif address.kind in {"dynamic_range", "dynamic_location"}:
                location = _dynamic_memory_location(address)
                if value is None:
                    output.memory[location] = None
                    taints.add(location)
                    continue
                output.memory[location] = value
                if all(_persistent_origin(origin) for origin in value):
                    proposals[location] = value
                else:
                    taints.add(location)
            elif address.kind == "symbolic_affine":
                # Equality of canonical affine expressions is useful for an
                # immediate write/read pair, but unequal expressions are not
                # an alias-disjointness proof.  Preserve only this write and
                # fail closed for every fact it may have overwritten.
                _invalidate_unknown_memory_write(
                    output,
                    proposals=proposals,
                    taints=taints,
                )
                location = _Origin(address.kind, address.key)
                if value is None:
                    output.memory[location] = None
                    continue
                output.memory[location] = value
    _invalidate_schedule_blockers(unit, output)
    if len(output.memory) > static_slot_budget:
        output.memory.clear()
        output.memory_invalidated = True
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
        (),
        exceeded,
    )


def _invalidate_unknown_memory_write(
    state: _State,
    *,
    proposals: dict[_MemoryLocation, _Value],
    taints: set[_MemoryLocation],
) -> None:
    taints.update(
        location
        for location in state.memory
        if isinstance(location, int)
    )
    proposals.clear()
    state.memory.clear()
    state.stack.clear()
    state.memory_invalidated = True


def _indirect_import_identity(
    event: Mapping[str, Any],
    state: _State,
    *,
    inventory: _ProfileInventory,
    known_slots: Mapping[Any, _Value],
    budget: int,
) -> MachineImportIdentity | None:
    if event.get("kind") != "indirect_call":
        return None
    origins = _evaluate(
        event.get("target"),
        state,
        inventory=inventory,
        known_slots=known_slots,
        budget=budget,
    )
    if origins is None or not origins or any(origin.kind != "import" for origin in origins):
        return None
    identities = {_origin_import_identity(origin) for origin in origins}
    return next(iter(identities)) if len(identities) == 1 else None


def _static_identity_matches(
    value: _Value,
    expected: bytes,
    reader: Callable[[int, int], bytes | None] | None,
) -> bool:
    if reader is None or value is None or not value:
        return False
    addresses = {
        int(origin.key[0]) & 0xFFFFFFFF
        for origin in value
        if origin.kind == "exact"
    }
    if len(addresses) != 1 or any(origin.kind != "exact" for origin in value):
        return False
    observed = reader(next(iter(addresses)), len(expected) + 1)
    return observed == expected + b"\0"


def _selected_import_call_facts(
    selected: SelectedImportABI | None,
    outputs: Mapping[_Origin, _Value],
    *,
    memory_writes: tuple["_WriteSpan", ...] | None = None,
) -> _CallFacts:
    return _CallFacts(
        frozenset(selected.abi.preserved_registers) if selected else None,
        selected.abi if selected else None,
        selected.argument_words if selected else None,
        None,
        outputs,
        memory_preserved=_selected_import_memory_preserved(selected),
        memory_writes=memory_writes,
    )


def _selected_import_memory_preserved(
    selected: SelectedImportABI | None,
) -> bool:
    contract = selected.contract if selected is not None else None
    return isinstance(contract, Mapping) and contract.get("memory_effect") in {
        "none",
        "readOnly",
        "read_only",
    }


def _selected_import_memory_write_argument_indices(
    selected: SelectedImportABI | None,
) -> frozenset[int] | None:
    """Return writable caller-memory arguments from one reviewed import frame.

    ``None`` means the selected contract has no usable frame and therefore
    cannot justify retaining any caller-memory fact.  An empty set is useful
    evidence: the reviewed call may touch opaque resources, but cannot write
    through caller-memory arguments.
    """

    declarations = _selected_import_caller_memory_declarations(selected)
    if declarations is not None:
        return frozenset(
            int(raw["argument_index"])
            for raw in declarations
            if raw["role"] == "caller_memory" and raw["access"] != "read"
        )
    footprints = _selected_import_write_footprints(selected)
    if footprints is None:
        return None
    result: set[int] = set()
    for footprint in footprints:
        result.add(int(footprint["base_argument"]))
        size = footprint["size"]
        if size["kind"] == "argument":
            result.add(int(size["argument"]))
    return frozenset(result)


def _selected_import_caller_memory_declarations(
    selected: SelectedImportABI | None,
) -> tuple[Mapping[str, Any], ...] | None:
    contract = selected.contract if selected is not None else None
    frame = contract.get("caller_memory_frame") if isinstance(contract, Mapping) else None
    raw_declarations = frame.get("arguments") if isinstance(frame, Mapping) else None
    if (
        selected is None
        or selected.argument_words is None
        or not isinstance(frame, Mapping)
        or frame.get("status") != "complete"
        or frame.get("model") != "pe32-declared-pointer-arguments-v1"
        or not isinstance(raw_declarations, list)
    ):
        return None
    declarations: list[Mapping[str, Any]] = []
    seen: set[int] = set()
    for raw in raw_declarations:
        if not isinstance(raw, Mapping):
            return None
        index = _integer(raw.get("argument_index"))
        role = raw.get("role")
        access = raw.get("access")
        extent = raw.get("extent")
        retention = raw.get("retention")
        if (
            index is None
            or not 0 <= index < selected.argument_words
            or index in seen
            or role not in {"caller_memory", "interface_resource", "callback"}
            or access not in {"read", "read_write"}
            or extent not in {"fixed_word", "enclosing_object", "opaque_resource"}
            or retention not in {"during_call", "callback_contract"}
            or (role == "caller_memory" and extent == "opaque_resource")
            or (role != "caller_memory" and extent != "opaque_resource")
            or (role == "callback" and retention != "callback_contract")
            or (role != "callback" and retention != "during_call")
        ):
            return None
        seen.add(index)
        declarations.append(raw)
    return tuple(declarations)


def _selected_import_write_footprints(
    selected: SelectedImportABI | None,
) -> tuple[Mapping[str, Any], ...] | None:
    contract = selected.contract if selected is not None else None
    if not isinstance(contract, Mapping) or selected is None:
        return None
    effect = contract.get("memory_effect")
    raw_footprints = contract.get("memory_footprints")
    if effect in {"none", "readOnly", "read_only"}:
        if raw_footprints is None or raw_footprints == [] or raw_footprints == ():
            return ()
        if not isinstance(raw_footprints, (list, tuple)):
            return None
        return () if all(
            isinstance(raw, Mapping) and raw.get("access") == "read"
            for raw in raw_footprints
        ) else None
    if effect != "argumentRanges" or not isinstance(raw_footprints, list):
        return None
    result: list[Mapping[str, Any]] = []
    for raw in raw_footprints:
        if not isinstance(raw, Mapping):
            return None
        access = raw.get("access")
        if access == "read":
            continue
        base_argument = _integer(raw.get("base_argument"))
        offset = _integer(raw.get("offset"))
        nullable = raw.get("nullable")
        size = raw.get("size")
        if (
            access not in {"write", "read_write"}
            or base_argument is None
            or selected.argument_words is None
            or not 0 <= base_argument < selected.argument_words
            or offset is None
            or not isinstance(nullable, bool)
            or not isinstance(size, Mapping)
        ):
            return None
        size_kind = size.get("kind")
        if size_kind == "fixed":
            byte_count = _integer(size.get("bytes"))
            if byte_count is None or byte_count < 0:
                return None
        elif size_kind == "argument":
            size_argument = _integer(size.get("argument"))
            scale = _integer(size.get("scale"))
            if (
                size_argument is None
                or not 0 <= size_argument < selected.argument_words
                or scale is None
                or scale <= 0
            ):
                return None
        else:
            return None
        result.append(raw)
    return tuple(result)


def _selected_import_memory_writes(
    selected: SelectedImportABI | None,
    arguments: Sequence[_Value] | None,
) -> tuple["_WriteSpan", ...] | None:
    required = _selected_import_memory_write_argument_indices(selected)
    if required is None:
        return None
    if not required:
        return ()
    declarations = _selected_import_caller_memory_declarations(selected)
    if arguments is None:
        return None
    writes: set[_WriteSpan] = set()
    if declarations is not None:
        for raw in declarations:
            if raw["role"] != "caller_memory" or raw["access"] == "read":
                continue
            index = int(raw["argument_index"])
            origins = arguments[index]
            if origins is None:
                return None
            size = 4 if raw["extent"] == "fixed_word" else None
            for origin in origins:
                if origin.kind not in {
                    "exact",
                    "stack_location",
                    "dynamic_range",
                    "dynamic_location",
                }:
                    return None
                if origin.kind == "exact" and int(origin.key[0]) & 0xFFFFFFFF == 0:
                    continue
                writes.add(_WriteSpan(origin, size))
        return tuple(sorted(writes))
    footprints = _selected_import_write_footprints(selected)
    if footprints is None:
        return None
    for footprint in footprints:
        base_values = arguments[int(footprint["base_argument"])]
        if base_values is None:
            return None
        size_spec = footprint["size"]
        if size_spec["kind"] == "fixed":
            sizes = {int(size_spec["bytes"])}
        else:
            size_values = arguments[int(size_spec["argument"])]
            if size_values is None:
                return None
            scale = int(size_spec["scale"])
            concrete_sizes = {
                origin_concrete_value(origin) for origin in size_values
            }
            if None in concrete_sizes:
                return None
            sizes = {int(value) * scale for value in concrete_sizes}
        offset = int(footprint["offset"])
        for base in base_values:
            shifted = _offset_write_base(base, offset)
            if shifted is None:
                return None
            if shifted.kind == "exact" and int(shifted.key[0]) & 0xFFFFFFFF == 0:
                continue
            for size in sizes:
                if size < 0 or size > 0xFFFFFFFF:
                    return None
                if size:
                    writes.add(_WriteSpan(shifted, size))
    return tuple(sorted(writes))


def _offset_write_base(origin: _Origin, offset: int) -> _Origin | None:
    if origin.kind == "exact":
        return _Origin("exact", ((int(origin.key[0]) + offset) & 0xFFFFFFFF,))
    if origin.kind == "stack_location":
        return _Origin("stack_location", (int(origin.key[0]) + offset,))
    if origin.kind in {"dynamic_range", "dynamic_location"}:
        return _offset_dynamic_location(origin, offset)
    return None


def _selected_import_frame_facts(
    selected: SelectedImportABI | None,
    outputs: Mapping[_Origin, _Value],
    *,
    unit_id: str,
    unit: Mapping[str, Any],
    event_index: int,
    pre_call: _State,
    input_state: _State,
    inventory: _ProfileInventory,
    known_slots: Mapping[Any, _Value],
    budget: int,
) -> tuple[_CallFacts, dict[str, Any] | None]:
    required = _selected_import_memory_write_argument_indices(selected)
    if required is None:
        return _selected_import_call_facts(selected, outputs), None
    if not required:
        return (
            _selected_import_call_facts(selected, outputs, memory_writes=()),
            None,
        )
    if (
        selected is None
        or selected.argument_words is None
        or any(index >= selected.argument_words for index in required)
    ):
        return _selected_import_call_facts(selected, outputs), None
    arguments, recovery = _recover_call_arguments(
        pre_call,
        input_state,
        unit,
        unit_id=unit_id,
        event_index=event_index,
        argument_words=selected.argument_words,
        inventory=inventory,
        known_slots=known_slots,
        budget=budget,
        required_argument_indices=required,
    )
    recovery["purpose"] = "machine_import_memory_frame"
    recovery["machine_import"] = {
        "dll": selected.identity.dll,
        selected.identity.kind: selected.identity.value,
    }
    return (
        _selected_import_call_facts(
            selected,
            outputs,
            memory_writes=_selected_import_memory_writes(selected, arguments),
        ),
        recovery,
    )


def _dynamic_range_origin(
    *,
    producer_unit_id: str,
    event_index: int,
    identity: MachineImportIdentity,
    nullable: bool,
) -> _Value:
    dynamic = _Origin(
        "dynamic_range",
        (
            producer_unit_id,
            event_index,
            identity.dll,
            identity.kind,
            identity.value,
        ),
    )
    return frozenset(
        {_Origin("exact", (0,)), dynamic} if nullable else {dynamic}
    )


def _internal_dynamic_range_origin(
    *,
    contract_id: str,
    producer_unit_id: str,
    event_index: int,
    nullable: bool,
) -> _Value:
    dynamic = _Origin(
        "dynamic_range",
        ("internal_contract", contract_id, producer_unit_id, event_index),
    )
    return frozenset(
        {_Origin("exact", (0,)), dynamic} if nullable else {dynamic}
    )


def _selected_import_result_outputs(
    selected: SelectedImportABI,
    *,
    unit_id: str,
    event_index: int,
) -> dict[_Origin, _Value]:
    contract = selected.contract
    if not isinstance(contract, Mapping):
        return {}
    raw_relations = contract.get("result_register_relations")
    if not isinstance(raw_relations, list):
        return {}
    outputs: dict[_Origin, _Value] = {}
    for raw in raw_relations:
        relation = _mapping(raw)
        register = relation.get("register")
        if register not in _REGISTERS:
            continue
        if relation.get("relation") == "dynamic_range_base" and isinstance(
            relation.get("nullable"), bool
        ):
            outputs[_Origin("register_location", (str(register),))] = (
                _dynamic_range_origin(
                    producer_unit_id=unit_id,
                    event_index=event_index,
                    identity=selected.identity,
                    nullable=bool(relation["nullable"]),
                )
            )
    return outputs


def _internal_call_result_outputs(
    relations: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    producer_unit_id: str,
    event_index: int,
    pre_call: _State,
    inventory: _ProfileInventory,
    budget: int,
) -> dict[_Origin, _Value]:
    outputs: dict[_Origin, _Value] = {}
    for register, raw_origins in relations.items():
        if register not in _REGISTERS or not isinstance(raw_origins, Sequence):
            continue
        origins: set[_Origin] = set()
        malformed = False
        for raw in raw_origins:
            row = _mapping(raw)
            kind = row.get("kind")
            if kind == "typed_origins":
                value = _typed_summary_origins(row, budget=budget)
                if value is None:
                    malformed = True
                    break
                origins.update(value)
                continue
            if kind == "exact":
                value = _integer(row.get("value"))
                if value is None:
                    malformed = True
                    break
                origins.add(_Origin("exact", (value & 0xFFFFFFFF,)))
                continue
            if kind == "input_register":
                source = row.get("register")
                value = (
                    pre_call.registers.get(str(source))
                    if source in _REGISTERS
                    else None
                )
                if value is None:
                    malformed = True
                    break
                origins.update(value)
                continue
            if kind == "stack_address":
                value = _instantiate_stack_summary_value(
                    row,
                    pre_call=pre_call,
                    inventory=inventory,
                    budget=budget,
                )
                if value is None:
                    malformed = True
                    break
                origins.update(value)
                continue
            if kind == "internal_contract_result":
                contract_id = row.get("contract_id")
                nullable = row.get("nullable")
                if (
                    not isinstance(contract_id, str)
                    or not contract_id
                    or row.get("relation") != "dynamic_range_base"
                    or not isinstance(nullable, bool)
                ):
                    malformed = True
                    break
                value = _internal_dynamic_range_origin(
                    contract_id=contract_id,
                    producer_unit_id=producer_unit_id,
                    event_index=event_index,
                    nullable=nullable,
                )
                if value is None:
                    malformed = True
                    break
                origins.update(value)
                continue
            if kind != "external_result":
                malformed = True
                break
            imported = _mapping(row.get("import"))
            try:
                identity = MachineImportIdentity.from_mapping(
                    imported, context="internal result relation"
                )
            except MachineImportProfileError:
                malformed = True
                break
            producer = row.get("producer_unit_id")
            relation_event_index = _integer(row.get("event_index"))
            nullable = row.get("nullable")
            if (
                not isinstance(producer, str)
                or relation_event_index is None
                or row.get("relation") != "dynamic_range_base"
                or not isinstance(nullable, bool)
            ):
                malformed = True
                break
            value = _dynamic_range_origin(
                producer_unit_id=producer,
                event_index=relation_event_index,
                identity=identity,
                nullable=nullable,
            )
            if value is None:
                malformed = True
                break
            origins.update(value)
        location = _Origin("register_location", (register,))
        if malformed or len(origins) > budget:
            outputs[location] = None
        elif origins:
            outputs[location] = frozenset(origins)
    return outputs


def _typed_summary_origins(
    row: Mapping[str, Any], *, budget: int
) -> frozenset[_Origin] | None:
    if set(row) != {"kind", "origins"}:
        return None
    raw_origins = row.get("origins")
    if (
        not isinstance(raw_origins, list)
        or not 1 <= len(raw_origins) <= budget
    ):
        return None
    origins: list[_Origin] = []
    try:
        for raw in raw_origins:
            if not isinstance(raw, Mapping):
                return None
            if not {"kind", "key"} <= set(raw) <= {
                "kind",
                "key",
                "authority_dependencies",
            }:
                return None
            kind = raw.get("kind")
            key = raw.get("key")
            dependencies = raw.get("authority_dependencies", [])
            if (
                not isinstance(kind, str)
                or not isinstance(key, list)
                or not isinstance(dependencies, list)
                or any(
                    not isinstance(value, str) or not value
                    for value in dependencies
                )
                or dependencies != sorted(set(dependencies))
            ):
                return None
            origins.append(_Origin(
                kind,
                tuple(_freeze_typed_origin_key(value) for value in key),
                tuple(dependencies),
            ))
    except (TypeError, ValueError):
        return None
    value = frozenset(origins)
    if len(value) != len(raw_origins):
        return None
    try:
        normalized_json = json.dumps(
            origins_json(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        supplied_json = json.dumps(
            raw_origins,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        return None
    if normalized_json != supplied_json:
        return None
    return value


def _freeze_typed_origin_key(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool)) or (
        isinstance(value, int) and not isinstance(value, bool)
    ):
        return value
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_typed_origin_key(item) for item in value)
    raise ValueError("typed origin key is not canonical JSON data")


def _internal_target_call_facts(
    target_address: int,
    *,
    producer_unit_id: str,
    event_index: int,
    pre_call: _State,
    inventory: _ProfileInventory,
    internal_call_preserved_registers: Mapping[int, frozenset[str]],
    internal_call_stack_cleanup: Mapping[int, int],
    internal_call_result_relations: Mapping[
        int, Mapping[str, Sequence[Mapping[str, Any]]]
    ],
    internal_call_memory_preservation: Mapping[int, bool],
    internal_call_memory_result_relations: Mapping[
        int, Mapping[_Origin, _Value]
    ],
    dependencies: frozenset[str],
    budget: int,
    issues: list[dict[str, Any]],
) -> _CallFacts:
    outputs: dict[_Origin, _Value] = {}
    _merge_output_effects(
        outputs,
        _internal_call_result_outputs(
            internal_call_result_relations.get(target_address, {}),
            producer_unit_id=producer_unit_id,
            event_index=event_index,
            pre_call=pre_call,
            inventory=inventory,
            budget=budget,
        ),
        budget=budget,
        issues=issues,
        unit_id=producer_unit_id,
    )
    _merge_output_effects(
        outputs,
        internal_call_memory_result_relations.get(target_address, {}),
        budget=budget,
        issues=issues,
        unit_id=producer_unit_id,
    )
    return _CallFacts(
        internal_call_preserved_registers.get(target_address),
        None,
        None,
        internal_call_stack_cleanup.get(target_address),
        outputs,
        memory_preserved=bool(
            internal_call_memory_preservation.get(target_address)
        ),
        dependencies=dependencies,
    )


def _instantiate_stack_summary_value(
    row: Mapping[str, Any],
    *,
    pre_call: _State,
    inventory: _ProfileInventory,
    budget: int,
) -> _Value:
    offset = _integer(row.get("offset"))
    raw_terms = row.get("register_terms", [])
    if offset is None or not isinstance(raw_terms, list):
        return None
    value = _add_values(
        pre_call.registers.get("esp"),
        frozenset({_Origin("exact", ((offset - 4) & 0xFFFFFFFF,))}),
        subtract=False,
        budget=budget,
        inventory=inventory,
    )
    for raw_term in raw_terms:
        term = _mapping(raw_term)
        register = term.get("register")
        coefficient = _integer(term.get("coefficient"))
        if register not in _REGISTERS or coefficient in {None, 0}:
            return None
        scaled = _multiply_values(
            pre_call.registers.get(str(register)),
            frozenset({_Origin("exact", (int(coefficient) & 0xFFFFFFFF,))}),
            budget=budget,
        )
        value = _add_values(
            value,
            scaled,
            subtract=False,
            budget=budget,
            inventory=inventory,
        )
        if value is None:
            return None
    return value


def _callable_external_call(
    *,
    identity: MachineImportIdentity | None,
    unit_id: str,
    unit: Mapping[str, Any],
    event_index: int,
    pre_call: _State,
    state: _State,
    inventory: _ProfileInventory,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    known_slots: Mapping[int, _Value],
    budget: int,
) -> tuple[_CallFacts, list[dict[str, Any]], list[dict[str, Any]]] | None:
    if identity is None:
        return None
    resolver_entry = inventory.callable_resolvers.get(identity)
    loader_entries = inventory.callable_loaders.get(identity, ())
    if resolver_entry is None and not loader_entries:
        return None

    selected = import_abis.get(identity)
    issues: list[dict[str, Any]] = []
    recoveries: list[dict[str, Any]] = []
    outputs: dict[_Origin, _Value] = {}
    if resolver_entry is not None:
        profile_sha256, resolver = resolver_entry
        argument_words = max(
            (resolver.module_argument_index, *resolver.identity_argument_indices)
        ) + 1
        arguments, recovery = _recover_call_arguments(
            pre_call,
            state,
            unit,
            unit_id=unit_id,
            event_index=event_index,
            argument_words=argument_words,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
        )
        recovery["callable_resolver"] = {
            "profile_sha256": profile_sha256,
            "resolver_id": resolver.id,
        }
        recoveries.append(recovery)
        matches: list[CallableExternalTargetProfileSpec] = []
        if arguments is not None:
            module_value = arguments[resolver.module_argument_index]
            expected_module = _Origin(
                "loaded_module",
                (profile_sha256, resolver.id),
            )
            module_exact = module_value == frozenset({expected_module})
            if module_exact:
                profile = inventory.callable_profiles[profile_sha256]
                for target in profile.targets_by_resolver(resolver.id):
                    if _static_identity_matches(
                        arguments[target.name_argument_index],
                        target.name_bytes,
                        inventory.static_data_reader,
                    ):
                        matches.append(target)
        if len(matches) == 1:
            target = matches[0]
            outputs[_Origin("register_location", (resolver.result_register,))] = (
                frozenset({_Origin("resolved_export", (profile_sha256, target.id))})
            )
            recovery["resolved_target"] = {
                "target_id": target.id,
                "dll": target.identity.dll,
                target.identity.kind: target.identity.value,
            }
        else:
            issues.append({
                "code": "callable_resolver_identity_unknown_or_ambiguous",
                "unit_id": unit_id,
                "event_index": event_index,
                "resolver": {
                    "dll": identity.dll,
                    identity.kind: identity.value,
                },
                "match_count": len(matches),
            })
        return _selected_import_call_facts(selected, outputs), issues, recoveries

    argument_words = max(
        target.module.loader_name_argument_index for _, target in loader_entries
    ) + 1
    arguments, recovery = _recover_call_arguments(
        pre_call,
        state,
        unit,
        unit_id=unit_id,
        event_index=event_index,
        argument_words=argument_words,
        inventory=inventory,
        known_slots=known_slots,
        budget=budget,
    )
    recovery["callable_loader"] = {
        "dll": identity.dll,
        identity.kind: identity.value,
    }
    recoveries.append(recovery)
    module_routes = {
        (profile_sha256, target.resolver_id): target
        for profile_sha256, target in loader_entries
        if arguments is not None
        and _static_identity_matches(
            arguments[target.module.loader_name_argument_index],
            target.module.name_bytes,
            inventory.static_data_reader,
        )
    }
    if len(module_routes) == 1:
        profile_sha256, resolver_id = next(iter(module_routes))
        target = module_routes[(profile_sha256, resolver_id)]
        if arguments is not None:
            outputs[_Origin("register_location", ("eax",))] = frozenset({
                _Origin("loaded_module", (profile_sha256, resolver_id))
            })
    else:
        issues.append({
            "code": "callable_loader_identity_unknown_or_ambiguous",
            "unit_id": unit_id,
            "event_index": event_index,
            "loader": {"dll": identity.dll, identity.kind: identity.value},
            "match_count": len(module_routes),
        })
    return _selected_import_call_facts(selected, outputs), issues, recoveries


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
    internal_call_result_relations: Mapping[
        int, Mapping[str, Sequence[Mapping[str, Any]]]
    ],
    internal_call_memory_preservation: Mapping[int, bool],
    internal_call_memory_result_relations: Mapping[
        int, Mapping[_Origin, _Value]
    ],
    internal_call_dependency_ids: Mapping[tuple[str, int], frozenset[str]],
    recovered_calls: Mapping[tuple[str, int], Mapping[str, Any]],
    image_base: int,
    known_slots: Mapping[_MemoryLocation, _Value],
    budget: int,
) -> tuple[_CallFacts, list[dict[str, Any]], list[dict[str, Any]]]:
    kind = event.get("kind")
    outputs: dict[_Origin, _Value] = {}
    issues: list[dict[str, Any]] = []
    argument_recoveries: list[dict[str, Any]] = []
    call_identity = (
        _event_import_identity(event)
        if kind == "external_call"
        else _indirect_import_identity(
            event,
            pre_call,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
        )
    )
    callable_facts = _callable_external_call(
        identity=call_identity,
        unit_id=unit_id,
        unit=unit,
        event_index=event_index,
        pre_call=pre_call,
        state=state,
        inventory=inventory,
        import_abis=import_abis,
        known_slots=known_slots,
        budget=budget,
    )
    if callable_facts is not None:
        return callable_facts
    if kind == "external_call":
        identity = _event_import_identity(event)
        selected = import_abis.get(identity) if identity is not None else None
        if selected is not None:
            _merge_output_effects(
                outputs,
                _selected_import_result_outputs(
                    selected, unit_id=unit_id, event_index=event_index
                ),
                budget=budget,
                issues=issues,
                unit_id=unit_id,
            )
        callback = _machine_callback_registration(
            unit_id=unit_id,
            unit=unit,
            event_index=event_index,
            event=event,
            state=state,
            pre_call=pre_call,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
        )
        if callback is not None:
            callback_evidence, callback_arguments = callback
            argument_recoveries.extend(
                (callback_arguments, callback_evidence)
            )
            if callback_evidence["status"] != "complete":
                issues.append({
                    "code": "callback_registration_provenance_incomplete",
                    "unit_id": unit_id,
                    "event_index": event_index,
                    "instruction_rva": event.get("instruction_rva"),
                    "failure": callback_evidence["failure"]["code"],
                })
            raw_contract = _mapping(event.get("abi_contract"))
            callback_result = parse_callback_result(
                raw_contract,
                context=f"{unit_id} external event {event_index}",
            )
            if callback_result is not None:
                callback_abi = parse_callback_abi(
                    raw_contract,
                    context=f"{unit_id} external event {event_index}",
                )
                profile_binding = json.dumps(
                    raw_contract.get("profile_binding"),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                outputs[_Origin(
                    "register_location", (callback_result.register,)
                )] = frozenset({_Origin(
                    "callback_token",
                    (
                        str(raw_contract.get("contract_id") or "callback"),
                        profile_binding,
                        callback_abi.kind,
                        callback_abi.argument_words,
                        callback_abi.stack_cleanup_bytes,
                        callback_result.nullable,
                        str(raw_contract.get("callback_lifetime") or "unknown"),
                    ),
                )})
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
                _merge_output_effects(outputs, _operation_output_effects(
                    arguments,
                    operation,
                    profile_sha256=profile_sha256,
                    producer_id=f"{unit_id}:{event_index}:{operation.operation_id}",
                    inventory=inventory,
                    issues=issues,
                    unit_id=unit_id,
                ), budget=budget, issues=issues, unit_id=unit_id)
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
        if factory_entry is None:
            facts, recovery = _selected_import_frame_facts(
                selected,
                outputs,
                unit_id=unit_id,
                unit=unit,
                event_index=event_index,
                pre_call=pre_call,
                input_state=state,
                inventory=inventory,
                known_slots=known_slots,
                budget=budget,
            )
            if recovery is not None:
                argument_recoveries.append(recovery)
                if recovery["status"] != "complete":
                    issues.append({
                        "code": "machine_import_memory_frame_arguments_incomplete",
                        "unit_id": unit_id,
                        "event_index": event_index,
                        "failure": recovery["failure"]["code"],
                    })
            return facts, issues, argument_recoveries
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
            required_argument_indices=frozenset(
                output.argument_index for output in factory.outputs
            ),
        )
        argument_recoveries.append(recovery)
        if not _interface_outputs_recoverable(arguments, factory.outputs):
            issues.append({
                "code": "interface_factory_arguments_incomplete",
                "unit_id": unit_id,
                "factory": factory.declaration,
                "failure": (
                    _mapping(recovery.get("failure")).get("code")
                    or "interface_out_pointer_unresolved"
                ),
            })
        if arguments is not None:
            _merge_output_effects(outputs, _output_effects(
                arguments,
                factory.outputs,
                profile_sha256=profile_sha256,
                issues=issues,
                unit_id=unit_id,
            ), budget=budget, issues=issues, unit_id=unit_id)
        return (
            _CallFacts(
                frozenset(factory.abi.preserved_registers),
                factory.abi,
                factory.argument_words,
                None,
                outputs,
                memory_writes=_interface_memory_writes(
                    factory.caller_memory_frame, arguments
                ),
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
        dependencies = internal_call_dependency_ids.get(
            (unit_id, event_index), frozenset()
        )
        facts = (
            _CallFacts(None, None, None, None, {}, dependencies=dependencies)
            if target_address is None
            else _internal_target_call_facts(
                target_address,
                producer_unit_id=unit_id,
                event_index=event_index,
                pre_call=pre_call,
                inventory=inventory,
                internal_call_preserved_registers=(
                    internal_call_preserved_registers
                ),
                internal_call_stack_cleanup=internal_call_stack_cleanup,
                internal_call_result_relations=internal_call_result_relations,
                internal_call_memory_preservation=(
                    internal_call_memory_preservation
                ),
                internal_call_memory_result_relations=(
                    internal_call_memory_result_relations
                ),
                dependencies=dependencies,
                budget=budget,
                issues=issues,
            )
        )
        return facts, issues, argument_recoveries
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
                _merge_output_effects(outputs, _operation_output_effects(
                    arguments,
                    operation,
                    profile_sha256=profile_sha256,
                    producer_id=f"{unit_id}:{event_index}:{operation.operation_id}",
                    inventory=inventory,
                    issues=issues,
                    unit_id=unit_id,
                ), budget=budget, issues=issues, unit_id=unit_id)
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
        selected = (
            import_abis.get(call_identity)
            if call_identity is not None
            else None
        )
        if selected is not None:
            _merge_output_effects(
                outputs,
                _selected_import_result_outputs(
                    selected, unit_id=unit_id, event_index=event_index
                ),
                budget=budget,
                issues=issues,
                unit_id=unit_id,
            )
            facts, recovery = _selected_import_frame_facts(
                selected,
                outputs,
                unit_id=unit_id,
                unit=unit,
                event_index=event_index,
                pre_call=pre_call,
                input_state=state,
                inventory=inventory,
                known_slots=known_slots,
                budget=budget,
            )
            if recovery is not None:
                argument_recoveries.append(recovery)
                if recovery["status"] != "complete":
                    issues.append({
                        "code": "machine_import_memory_frame_arguments_incomplete",
                        "unit_id": unit_id,
                        "event_index": event_index,
                        "failure": recovery["failure"]["code"],
                    })
            return facts, issues, argument_recoveries
        recovered = recovered_calls.get((unit_id, event_index))
        call_dependencies = frozenset(
            _call_frame_dependency_id(unit_id, event_index, target)
            for target in (
                recovered.get("target_unit_ids", ())
                if isinstance(recovered, Mapping)
                else ()
            )
            if isinstance(target, str)
        )
        direct_facts = _origin_call_facts(
            targets,
            producer_unit_id=unit_id,
            event_index=event_index,
            pre_call=pre_call,
            inventory=inventory,
            import_abis=import_abis,
            internal_call_preserved_registers=internal_call_preserved_registers,
            internal_call_stack_cleanup=internal_call_stack_cleanup,
            internal_call_result_relations=internal_call_result_relations,
            internal_call_memory_preservation=(
                internal_call_memory_preservation
            ),
            internal_call_memory_result_relations=(
                internal_call_memory_result_relations
            ),
            dependencies=call_dependencies,
            budget=budget,
            issues=issues,
        )
        if direct_facts is not None:
            return direct_facts, issues, argument_recoveries
        facts, recovered_issues, recovered_argument_recoveries = (
            _recovered_call_facts(
                recovered,
                unit_id=unit_id,
                unit=unit,
                event_index=event_index,
                event=event,
                state=state,
                pre_call=pre_call,
                inventory=inventory,
                import_abis=import_abis,
                internal_call_preserved_registers=(
                    internal_call_preserved_registers
                ),
                internal_call_stack_cleanup=internal_call_stack_cleanup,
                internal_call_result_relations=internal_call_result_relations,
                internal_call_memory_preservation=(
                    internal_call_memory_preservation
                ),
                internal_call_memory_result_relations=(
                    internal_call_memory_result_relations
                ),
                image_base=image_base,
                known_slots=known_slots,
                budget=budget,
            )
        )
        issues.extend(recovered_issues)
        argument_recoveries.extend(recovered_argument_recoveries)
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
    method_arguments: list[Sequence[_Value] | None] = []
    method_memory_writes: list[tuple[_WriteSpan, ...] | None] = []
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
        method_arguments.append(arguments)
        method_memory_writes.append(_interface_memory_writes(
            method.caller_memory_frame, arguments
        ))
        if not _interface_outputs_recoverable(arguments, method.outputs):
            issues.append({
                "code": "interface_method_arguments_incomplete",
                "unit_id": unit_id,
                "interface_id": method.interface_id,
                "method": method.name,
                "failure": (
                    _mapping(recovery.get("failure")).get("code")
                    or "interface_out_pointer_unresolved"
                ),
            })
        if arguments is None or not method.outputs:
            continue
        _merge_output_effects(outputs, _output_effects(
            arguments,
            method.outputs,
            profile_sha256=profile_sha256,
            issues=issues,
            unit_id=unit_id,
        ), budget=budget, issues=issues, unit_id=unit_id)
    callback_evidence = _interface_method_callback_registration(
        unit_id=unit_id,
        unit=unit,
        event_index=event_index,
        event=event,
        methods=methods,
        arguments=method_arguments,
        inventory=inventory,
        finite_value_budget=budget,
    )
    if callback_evidence is not None:
        argument_recoveries.append(callback_evidence)
        if callback_evidence["status"] != "complete":
            issues.append({
                "code": "interface_method_callback_provenance_incomplete",
                "unit_id": unit_id,
                "event_index": event_index,
                "instruction_rva": callback_evidence["instruction_rva"],
                "failure": callback_evidence["failure"]["code"],
            })
    return (
        _CallFacts(
            frozenset(preserved),
            common_abi,
            common_argument_words,
            None,
            outputs,
            memory_writes=_combine_memory_writes(method_memory_writes),
        ),
        issues,
        argument_recoveries,
    )


def _interface_outputs_recoverable(
    arguments: Sequence[_Value] | None,
    declarations: Sequence[Any],
) -> bool:
    """Whether every type-producing out pointer has a finite address origin.

    Scalar argument values are runtime data and are not required merely to
    recover the interface type written by a call.  External-effect contracts
    remain responsible for their ABI and memory interpretation.
    """

    if not declarations:
        return True
    if arguments is None:
        return False
    for declaration in declarations:
        index = declaration.argument_index
        if not 0 <= index < len(arguments):
            return False
        origins = arguments[index]
        if (
            origins is None
            or len(origins) != 1
            or next(iter(origins)).kind not in {
                "exact",
                "stack_location",
                "dynamic_range",
                "dynamic_location",
                "symbolic_affine",
            }
        ):
            return False
    return True


def _interface_memory_writes(
    frame: InterfaceCallerMemoryFrame | None,
    arguments: Sequence[_Value] | None,
) -> tuple[_WriteSpan, ...] | None:
    if frame is None:
        return None
    declarations = tuple(
        declaration
        for declaration in frame.arguments
        if declaration.role == "caller_memory" and declaration.access != "read"
    )
    if not declarations:
        return ()
    if arguments is None:
        return None
    writes: set[_WriteSpan] = set()
    for declaration in declarations:
        if not 0 <= declaration.argument_index < len(arguments):
            return None
        origins = arguments[declaration.argument_index]
        if origins is None:
            return None
        size = 4 if declaration.extent == "fixed_word" else None
        for origin in origins:
            if origin.kind not in {
                "exact", "stack_location", "dynamic_range", "dynamic_location"
            }:
                return None
            if origin.kind == "exact" and int(origin.key[0]) & 0xFFFFFFFF == 0:
                continue
            writes.add(_WriteSpan(origin, size))
    return tuple(sorted(writes))


def _combine_memory_writes(
    alternatives: Sequence[tuple[_WriteSpan, ...] | None],
) -> tuple[_WriteSpan, ...] | None:
    if not alternatives or any(value is None for value in alternatives):
        return None
    return tuple(sorted({span for value in alternatives for span in value or ()}))


def _apply_call_memory_frame(
    state: _State,
    facts: _CallFacts,
) -> tuple[dict[_MemoryLocation, _Value], dict[int, _StackCell], bool]:
    if facts.memory_writes is None:
        return (
            dict(state.memory) if facts.memory_preserved else {},
            dict(state.stack),
            state.memory_invalidated or not facts.memory_preserved,
        )
    memory = dict(state.memory)
    stack = dict(state.stack)
    for span in facts.memory_writes:
        base = span.base
        if base.kind == "exact":
            address = int(base.key[0]) & 0xFFFFFFFF
            if address == 0:
                continue
            if span.size is None:
                memory = {
                    location: value
                    for location, value in memory.items()
                    if not isinstance(location, int)
                }
            else:
                memory = {
                    location: value
                    for location, value in memory.items()
                    if not isinstance(location, int)
                    or not _ranges_overlap_u32(
                        address, span.size, location & 0xFFFFFFFF, 4
                    )
                }
        elif base.kind == "stack_location":
            offset = int(base.key[0])
            if span.size is None:
                stack.clear()
            else:
                stack = {
                    location: cell
                    for location, cell in stack.items()
                    if not _ranges_overlap_linear(offset, span.size, location, 4)
                }
        elif base.kind in {"dynamic_range", "dynamic_location"}:
            location = _dynamic_memory_location(base)
            identity = location.key[:-1]
            if span.size is None:
                memory = {
                    candidate: value
                    for candidate, value in memory.items()
                    if not (
                        isinstance(candidate, _Origin)
                        and candidate.kind == "dynamic_location"
                        and candidate.key[:-1] == identity
                    )
                }
            else:
                start = int(location.key[-1])
                memory = {
                    candidate: value
                    for candidate, value in memory.items()
                    if not (
                        isinstance(candidate, _Origin)
                        and candidate.kind == "dynamic_location"
                        and candidate.key[:-1] == identity
                        and _ranges_overlap_linear(
                            start, span.size, int(candidate.key[-1]), 4
                        )
                    )
                }
        else:
            # A complete frame must still fail closed when its runtime base
            # cannot be assigned to one of the checked address regions.
            return {}, {}, True
    return memory, stack, state.memory_invalidated


def _ranges_overlap_u32(
    left_start: int,
    left_size: int,
    right_start: int,
    right_size: int,
) -> bool:
    if min(left_size, right_size) <= 0:
        return False
    left_end = left_start + left_size
    right_end = right_start + right_size
    if left_end > 0x1_0000_0000 or right_end > 0x1_0000_0000:
        return True
    return left_start < right_end and right_start < left_end


def _ranges_overlap_linear(
    left_start: int,
    left_size: int,
    right_start: int,
    right_size: int,
) -> bool:
    return (
        min(left_size, right_size) > 0
        and left_start < right_start + right_size
        and right_start < left_start + left_size
    )


def _merge_output_effects(
    destination: dict[_Origin, _Value],
    effects: Mapping[_Origin, _Value],
    *,
    budget: int,
    issues: list[dict[str, Any]],
    unit_id: str,
) -> None:
    for location, origins in effects.items():
        if location not in destination:
            destination[location] = origins
            continue
        merged = _join_value(destination[location], origins, budget)
        destination[location] = merged
        if merged is None:
            issues.append({
                "code": "call_output_alternative_budget_exceeded",
                "unit_id": unit_id,
                "location": location.as_json(),
                "finite_value_budget": budget,
            })


def _interface_method_callback_registration(
    *,
    unit_id: str,
    unit: Mapping[str, Any],
    event_index: int,
    event: Mapping[str, Any],
    methods: Sequence[tuple[str, InterfaceMethod]],
    arguments: Sequence[Sequence[_Value] | None],
    inventory: _ProfileInventory,
    finite_value_budget: int,
) -> dict[str, Any] | None:
    effects = [method.effects for _, method in methods]
    categories = {
        None if effect is None else effect.callback_effect for effect in effects
    }
    if categories <= {None, "none"}:
        return None
    instruction_rva = _call_instruction_rva(
        unit, event=event, event_index=event_index
    )
    protocols = [
        {
            "profile_sha256": profile_sha256,
            "interface_id": method.interface_id,
            "method": method.name,
            "slot": method.slot,
            "callback_arguments": [
                dict(argument)
                for argument in (
                    method.effects.callback_arguments if method.effects else ()
                )
            ],
        }
        for profile_sha256, method in methods
    ]
    base = {
        "format": "stage-a-callback-registration-provenance-v1",
        "record_kind": "callback_registration",
        "proof_authority": False,
        "required_replay": (
            "replay the interface call arguments, finite callback target "
            "classification, exact callback ABI, and declared lifetime"
        ),
        "unit_id": unit_id,
        "event_index": event_index,
        "instruction_rva": instruction_rva,
        "import": None,
        "contract_id": "interface-method-callback",
        "profile_binding": {"interface_protocols": protocols},
        "callback_source": None,
        "callback_abi": None,
        "callback_lifetime": None,
        "callback_behavior": None,
        "callback_activation": None,
        "callback_instance": None,
        "callback_entry_arguments": [],
        "origins": [],
        "source_locations": [],
        "target_rvas": [],
        "target_unit_ids": [],
    }
    callback_contracts = {
        json.dumps({
            "source": effect.callback_source,
            "abi": effect.callback_abi,
            "lifetime": effect.callback_lifetime,
            "status": effect.callback_status,
            "blockers": list(effect.callback_blockers),
        }, sort_keys=True, separators=(",", ":"))
        for effect in effects
        if effect is not None and effect.callback_effect == "explicit"
    }
    if categories != {"explicit"} or len(callback_contracts) != 1:
        return {
            **base,
            "status": "incomplete",
            "failure": {"code": "interface_callback_contract_ambiguous"},
        }
    effect = effects[0]
    assert effect is not None
    base.update({
        "callback_source": copy.deepcopy(effect.callback_source),
        "callback_abi": copy.deepcopy(effect.callback_abi),
        "callback_lifetime": effect.callback_lifetime,
    })
    if effect.callback_status != "complete":
        return {
            **base,
            "status": "incomplete",
            "failure": {
                "code": "interface_callback_contract_incomplete",
                "blockers": list(effect.callback_blockers),
            },
        }
    source = effect.callback_source
    callback_abi = effect.callback_abi
    if source is None or callback_abi is None:
        return {
            **base,
            "status": "incomplete",
            "failure": {"code": "interface_callback_contract_incomplete"},
        }
    argument_index = int(source["argument"])
    recovered_arguments = [value for value in arguments if value is not None]
    if (
        len(recovered_arguments) != len(arguments)
        or not recovered_arguments
        or any(value != recovered_arguments[0] for value in recovered_arguments[1:])
        or not 0 <= argument_index < len(recovered_arguments[0])
    ):
        return {
            **base,
            "status": "incomplete",
            "failure": {"code": "callback_argument_origin_unresolved"},
        }
    origins = recovered_arguments[0][argument_index]
    if origins is None or not origins:
        return {
            **base,
            "status": "incomplete",
            "failure": {"code": "callback_argument_origin_unresolved"},
        }
    nullable = bool(callback_abi["nullable"])
    targets: set[tuple[int, str]] = set()
    for origin in origins:
        if origin.kind != "exact":
            return {
                **base,
                "status": "incomplete",
                "origins": _origins_json(origins),
                "failure": {"code": "callback_target_origin_not_exact"},
            }
        address = int(origin.key[0]) & 0xFFFFFFFF
        if address == 0 and nullable:
            continue
        candidates = inventory.unit_targets.get(address, ())
        if len(candidates) != 1:
            return {
                **base,
                "status": "incomplete",
                "origins": _origins_json(origins),
                "failure": {"code": "callback_target_not_canonical_code"},
            }
        targets.add(candidates[0])
    if not targets and not nullable:
        return {
            **base,
            "status": "incomplete",
            "origins": _origins_json(origins),
            "failure": {"code": "callback_target_null_forbidden"},
        }
    argument_index_sets = [
        {
            int(argument["argument_index"])
            for argument in (
                method.effects.callback_arguments if method.effects else ()
            )
        }
        for _, method in methods
    ]
    common_argument_indices = (
        set.intersection(*argument_index_sets) if argument_index_sets else set()
    )
    callback_entry_arguments: list[dict[str, Any]] = []
    for callback_argument_index in sorted(common_argument_indices):
        entry_origins = frozenset(
            _Origin(
                "interface_object",
                (profile_sha256, str(argument["interface_id"])),
            )
            for profile_sha256, method in methods
            for argument in (method.effects.callback_arguments if method.effects else ())
            if int(argument["argument_index"]) == callback_argument_index
            and argument.get("kind") == "interface_object"
        )
        if not entry_origins:
            continue
        if len(entry_origins) > finite_value_budget:
            return {
                **base,
                "status": "incomplete",
                "origins": _origins_json(origins),
                "failure": {
                    "code": "callback_entry_argument_alternative_budget_exceeded",
                    "argument_index": callback_argument_index,
                    "finite_value_budget": finite_value_budget,
                },
            }
        callback_entry_arguments.append({
            "argument_index": callback_argument_index,
            "origins": _origins_json(entry_origins),
        })
    return {
        **base,
        "status": "complete",
        "origins": _origins_json(origins),
        "target_rvas": sorted(target[0] for target in targets),
        "target_unit_ids": sorted(target[1] for target in targets),
        "callback_entry_arguments": callback_entry_arguments,
        "failure": None,
    }


def callback_root_argument_origins(
    provenance: Mapping[str, Any],
    *,
    finite_value_budget: int,
) -> dict[str, dict[int, frozenset[_Origin]]]:
    """Instantiate checked callback stack inputs from complete registrations.

    The returned facts are analysis inputs, not proof authority.  Cold replay
    must rediscover the registration, exact callback target, profile-bound ABI,
    and finite argument origins before they can influence an accepted target.
    """

    if finite_value_budget <= 0:
        raise ValueError("finite-value budget must be positive")
    registrations_by_target: dict[
        str, list[dict[int, frozenset[_Origin]]]
    ] = defaultdict(list)
    for registration in provenance.get("callback_registrations", ()):
        if (
            not isinstance(registration, Mapping)
            or registration.get("status") != "complete"
        ):
            continue
        target_ids = registration.get("target_unit_ids")
        arguments = registration.get("callback_entry_arguments")
        if (
            not isinstance(target_ids, Sequence)
            or isinstance(target_ids, (str, bytes))
            or not isinstance(arguments, Sequence)
            or isinstance(arguments, (str, bytes))
        ):
            continue
        parsed_arguments: dict[int, frozenset[_Origin]] = {}
        malformed = False
        for raw in arguments:
            if not isinstance(raw, Mapping):
                malformed = True
                break
            argument_index = raw.get("argument_index")
            if (
                not isinstance(argument_index, int)
                or isinstance(argument_index, bool)
                or not 0 <= argument_index < 64
                or argument_index in parsed_arguments
            ):
                malformed = True
                break
            try:
                parsed_arguments[argument_index] = parse_finite_value(
                    raw.get("origins"),
                    finite_value_budget=finite_value_budget,
                    context=f"callback argument {argument_index}",
                )
            except ValueError:
                malformed = True
                break
        if malformed:
            parsed_arguments = {}
        for target_id in target_ids:
            if isinstance(target_id, str) and target_id:
                registrations_by_target[target_id].append(parsed_arguments)

    result: dict[str, dict[int, frozenset[_Origin]]] = {}
    for target_id, registrations in registrations_by_target.items():
        common_indices = (
            set.intersection(*(set(arguments) for arguments in registrations))
            if registrations
            else set()
        )
        target: dict[int, frozenset[_Origin]] = {}
        for argument_index in common_indices:
            merged: _Value = frozenset()
            for arguments in registrations:
                merged = join_finite_values(
                    merged,
                    arguments[argument_index],
                    finite_value_budget,
                    missing_is_identity=True,
                )
                if merged is None:
                    break
            if merged:
                target[argument_index] = merged
        if target:
            result[target_id] = target
    return result


def _machine_callback_registration(
    *,
    unit_id: str,
    unit: Mapping[str, Any],
    event_index: int,
    event: Mapping[str, Any],
    state: _State,
    pre_call: _State,
    inventory: _ProfileInventory,
    known_slots: Mapping[int, _Value],
    budget: int,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    contract = event.get("abi_contract")
    if not isinstance(contract, Mapping) or not (
        contract.get("world_effect") == "callbackRegistration"
        or contract.get("callback_effect") == "explicit"
    ):
        return None
    argument_words = _integer(contract.get("argument_words"))
    if argument_words is None or not 0 <= argument_words <= 64:
        return None
    context = f"{unit_id} external event {event_index}"
    source = parse_callback_source(
        contract, argument_words=argument_words, context=context
    )
    callback_abi = parse_callback_abi(contract, context=context)
    callback_behavior = parse_nested_native_callback_behavior(
        contract,
        registration_argument_words=argument_words,
        context=context,
    )
    instruction_rva = _call_instruction_rva(
        unit, event=event, event_index=event_index
    )
    required_arguments = {source.argument_index}
    if callback_behavior is not None:
        required_arguments.update({
            callback_behavior.activation.argument_index,
            callback_behavior.instance_registration_argument,
        })
    arguments, recovery = _recover_call_arguments(
        pre_call,
        state,
        unit,
        unit_id=unit_id,
        event_index=event_index,
        argument_words=argument_words,
        inventory=inventory,
        known_slots=known_slots,
        budget=budget,
        required_argument_indices=frozenset(required_arguments),
    )
    recovery["contract_id"] = contract.get("contract_id")
    recovery["purpose"] = "callback_registration_arguments"
    base = {
        "format": "stage-a-callback-registration-provenance-v1",
        "record_kind": "callback_registration",
        "proof_authority": False,
        "required_replay": (
            "replay the rooted argument, pointee offset, ordered memory writes, "
            "finite target classification, and exact callback ABI"
        ),
        "unit_id": unit_id,
        "event_index": event_index,
        "instruction_rva": instruction_rva,
        "import": {
            "dll": event.get("dll"),
            "symbol": event.get("symbol"),
            "ordinal": event.get("ordinal"),
        },
        "contract_id": contract.get("contract_id"),
        "profile_binding": copy.deepcopy(contract.get("profile_binding")),
        "callback_source": source.as_json(),
        "callback_abi": callback_abi.as_json(),
        "callback_lifetime": copy.deepcopy(contract.get("callback_lifetime")),
        "callback_behavior": (
            None if callback_behavior is None else callback_behavior.as_json()
        ),
        "callback_activation": None,
        "origins": [],
        "source_locations": [],
        "target_rvas": [],
        "target_unit_ids": [],
    }
    if callback_behavior is not None:
        activation = callback_behavior.activation
        activation_evidence = _callback_activation_evidence(
            (
                None
                if arguments is None
                else arguments[activation.argument_index]
            ),
            argument_index=activation.argument_index,
            mask=activation.mask,
            expected=activation.value,
        )
        base["callback_activation"] = activation_evidence
        if activation_evidence["status"] != "complete":
            return ({
                **base,
                "status": "incomplete",
                "failure": copy.deepcopy(activation_evidence["failure"]),
            }, recovery)
        instance_argument = callback_behavior.instance_registration_argument
        instance_origins = (
            None if arguments is None else arguments[instance_argument]
        )
        if instance_origins is None or not instance_origins:
            return ({
                **base,
                "status": "incomplete",
                "failure": {"code": "callback_instance_argument_unresolved"},
            }, recovery)
        base["callback_instance"] = {
            "kind": "registration_argument_origins_v1",
            "registration_argument": instance_argument,
            "callback_argument": callback_behavior.instance_callback_argument,
            "origins": _origins_json(instance_origins),
        }
    if arguments is None or recovery["status"] != "complete":
        return ({
            **base,
            "status": "incomplete",
            "failure": {"code": "callback_argument_origin_unresolved"},
        }, recovery)
    origins, locations = _callback_source_origins(
        arguments[source.argument_index],
        source_kind=source.kind,
        pointee_offset=source.pointee_offset,
        state=pre_call,
        known_slots=known_slots,
        budget=budget,
    )
    if origins is None:
        return ({
            **base,
            "status": "incomplete",
            "source_locations": locations,
            "failure": {"code": "callback_source_location_unresolved"},
        }, recovery)
    targets: set[tuple[int, str]] = set()
    for origin in origins:
        if origin.kind != "exact":
            return ({
                **base,
                "status": "incomplete",
                "origins": _origins_json(origins),
                "source_locations": locations,
                "failure": {"code": "callback_target_origin_not_exact"},
            }, recovery)
        address = int(origin.key[0]) & 0xFFFFFFFF
        if address == 0 and callback_abi.nullable:
            continue
        candidates = inventory.unit_targets.get(address, ())
        if len(candidates) != 1:
            return ({
                **base,
                "status": "incomplete",
                "origins": _origins_json(origins),
                "source_locations": locations,
                "failure": {"code": "callback_target_not_canonical_code"},
            }, recovery)
        targets.add(candidates[0])
    if not targets and not callback_abi.nullable:
        return ({
            **base,
            "status": "incomplete",
            "origins": _origins_json(origins),
            "source_locations": locations,
            "failure": {"code": "callback_target_null_forbidden"},
        }, recovery)
    return ({
        **base,
        "status": "complete",
        "origins": _origins_json(origins),
        "source_locations": locations,
        "target_rvas": sorted(target[0] for target in targets),
        "target_unit_ids": sorted(target[1] for target in targets),
        "failure": None,
    }, recovery)


def _callback_activation_evidence(
    origins: _Value,
    *,
    argument_index: int,
    mask: int,
    expected: int,
) -> dict[str, Any]:
    base = {
        "kind": "masked_argument_equals",
        "argument_index": argument_index,
        "mask": mask,
        "expected_value": expected,
        "origins": _origins_json(origins),
        "exact_value": None,
        "masked_value": None,
    }
    if origins is None or not origins:
        return {
            **base,
            "status": "incomplete",
            "failure": {"code": "callback_activation_argument_unresolved"},
        }
    if any(
        origin.kind != "exact"
        or len(origin.key) != 1
        or not isinstance(origin.key[0], int)
        or isinstance(origin.key[0], bool)
        for origin in origins
    ):
        return {
            **base,
            "status": "incomplete",
            "failure": {"code": "callback_activation_origin_not_exact"},
        }
    values = sorted({int(origin.key[0]) & 0xFFFF_FFFF for origin in origins})
    if len(values) != 1:
        return {
            **base,
            "status": "incomplete",
            "failure": {"code": "callback_activation_argument_ambiguous"},
        }
    value = values[0]
    masked = value & mask
    if masked != expected:
        return {
            **base,
            "status": "incomplete",
            "exact_value": value,
            "masked_value": masked,
            "failure": {"code": "callback_activation_guard_mismatch"},
        }
    return {
        **base,
        "status": "complete",
        "exact_value": value,
        "masked_value": masked,
        "failure": None,
    }


def _callback_source_origins(
    argument_origins: _Value,
    *,
    source_kind: str,
    pointee_offset: int,
    state: _State,
    known_slots: Mapping[int, _Value],
    budget: int,
) -> tuple[_Value, list[dict[str, Any]]]:
    if source_kind == "argument_word":
        return argument_origins, []
    if argument_origins is None or not argument_origins:
        return None, []
    result: _Value = frozenset()
    locations: list[dict[str, Any]] = []
    for pointer in sorted(argument_origins):
        cell: _StackCell | None = None
        value: _Value = None
        if pointer.kind == "stack_location":
            offset = int(pointer.key[0]) + pointee_offset
            cell = state.stack.get(offset)
            value = None if cell is None else cell.value
            locations.append({
                "kind": "stack_location",
                "offset": offset,
                "writes": (
                    []
                    if cell is None
                    else [witness.as_json() for witness in cell.witnesses]
                ),
            })
        elif pointer.kind == "exact":
            address = (int(pointer.key[0]) + pointee_offset) & 0xFFFFFFFF
            value = _read_memory_fact(
                state,
                address,
                known_slots=known_slots,
            )
            locations.append({
                "kind": "exact",
                "address": address,
                "writes": [],
            })
        else:
            return None, locations
        if value is None:
            return None, locations
        result = _join_value(
            result,
            value,
            budget,
            missing_is_identity=True,
        )
        if result is None:
            return None, locations
    return result, locations


def _call_instruction_rva(
    unit: Mapping[str, Any],
    *,
    event: Mapping[str, Any],
    event_index: int,
) -> int | None:
    direct = _integer(event.get("instruction_rva"))
    if direct is not None:
        return direct
    ordered = _mapping(unit.get("semantics")).get("ordered_events")
    if not isinstance(ordered, list):
        return None
    call_ordinal = -1
    for raw in ordered:
        candidate = _mapping(raw)
        if candidate.get("kind") not in _CALL_KINDS:
            continue
        call_ordinal += 1
        if call_ordinal != event_index:
            continue
        if all(
            candidate.get(field) == event.get(field)
            for field in ("kind", "dll", "symbol", "ordinal", "return_rva")
        ):
            return _integer(candidate.get("instruction_rva"))
        return None
    return None


def _origin_call_facts(
    origins: _Value,
    *,
    producer_unit_id: str,
    event_index: int,
    pre_call: _State,
    inventory: _ProfileInventory,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    internal_call_preserved_registers: Mapping[int, frozenset[str]],
    internal_call_stack_cleanup: Mapping[int, int],
    internal_call_result_relations: Mapping[
        int, Mapping[str, Sequence[Mapping[str, Any]]]
    ],
    internal_call_memory_preservation: Mapping[int, bool],
    internal_call_memory_result_relations: Mapping[
        int, Mapping[_Origin, _Value]
    ],
    dependencies: frozenset[str] = frozenset(),
    budget: int,
    issues: list[dict[str, Any]],
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
                memory_preserved=_selected_import_memory_preserved(selected),
                dependencies=dependencies,
            ))
            continue
        if origin.kind == "exact":
            address = int(origin.key[0]) & 0xFFFFFFFF
            facts = _internal_target_call_facts(
                address,
                producer_unit_id=producer_unit_id,
                event_index=event_index,
                pre_call=pre_call,
                inventory=inventory,
                internal_call_preserved_registers=(
                    internal_call_preserved_registers
                ),
                internal_call_stack_cleanup=internal_call_stack_cleanup,
                internal_call_result_relations=internal_call_result_relations,
                internal_call_memory_preservation=(
                    internal_call_memory_preservation
                ),
                internal_call_memory_result_relations=(
                    internal_call_memory_result_relations
                ),
                dependencies=dependencies,
                budget=budget,
                issues=issues,
            )
            if facts.preserved is None:
                return None
            alternatives.append(facts)
            continue
        return None
    return _combine_call_facts(alternatives, budget=budget)


def _recovered_call_facts(
    recovery: Mapping[str, Any] | None,
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
    internal_call_result_relations: Mapping[
        int, Mapping[str, Sequence[Mapping[str, Any]]]
    ],
    internal_call_memory_preservation: Mapping[int, bool],
    internal_call_memory_result_relations: Mapping[
        int, Mapping[_Origin, _Value]
    ],
    image_base: int,
    known_slots: Mapping[int, _Value],
    budget: int,
) -> tuple[_CallFacts | None, list[dict[str, Any]], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    argument_recoveries: list[dict[str, Any]] = []
    if recovery is None or recovery.get("status") != "recovered":
        return None, issues, argument_recoveries
    raw_external = recovery.get("external_targets", [])
    raw_target_rvas = recovery.get("target_rvas", [])
    raw_target_units = recovery.get("target_unit_ids", [])
    if not _is_sequence(raw_external) or not _is_sequence(raw_target_rvas):
        return None, issues, argument_recoveries
    if not _is_sequence(raw_target_units):
        return None, issues, argument_recoveries
    if raw_target_units and not raw_target_rvas:
        return None, issues, argument_recoveries

    alternatives: list[_CallFacts] = []
    recovery_id = recovery.get("id")
    dependencies = frozenset({recovery_id}) if isinstance(
        recovery_id, str
    ) and recovery_id else frozenset()
    dependencies |= frozenset(
        _call_frame_dependency_id(
            str(recovery.get("source_unit_id") or "unknown"),
            _integer(recovery.get("source_event_index")) or 0,
            target,
        )
        for target in raw_target_units
        if isinstance(target, str)
    )
    for raw in raw_external:
        if not isinstance(raw, Mapping):
            return None, issues, argument_recoveries
        facts, target_issues, target_recoveries = (
            _instantiate_recovered_external_call_facts(
                raw,
                unit_id=unit_id,
                unit=unit,
                event_index=event_index,
                event=event,
                state=state,
                pre_call=pre_call,
                inventory=inventory,
                import_abis=import_abis,
                known_slots=known_slots,
                budget=budget,
            )
        )
        issues.extend(target_issues)
        argument_recoveries.extend(target_recoveries)
        if facts is None:
            return None, issues, argument_recoveries
        alternatives.append(_with_call_dependencies(facts, dependencies))
    for raw_rva in raw_target_rvas:
        target_rva = _integer(raw_rva)
        if target_rva is None:
            return None, issues, argument_recoveries
        target_address = (image_base + target_rva) & 0xFFFFFFFF
        facts = _internal_target_call_facts(
            target_address,
            producer_unit_id=unit_id,
            event_index=event_index,
            pre_call=pre_call,
            inventory=inventory,
            internal_call_preserved_registers=(
                internal_call_preserved_registers
            ),
            internal_call_stack_cleanup=internal_call_stack_cleanup,
            internal_call_result_relations=internal_call_result_relations,
            internal_call_memory_preservation=(
                internal_call_memory_preservation
            ),
            internal_call_memory_result_relations=(
                internal_call_memory_result_relations
            ),
            dependencies=dependencies,
            budget=budget,
            issues=issues,
        )
        if facts.preserved is None or facts.stack_cleanup_bytes is None:
            return None, issues, argument_recoveries
        alternatives.append(facts)
    return (
        _combine_call_facts(alternatives, budget=budget),
        issues,
        argument_recoveries,
    )


def _instantiate_recovered_external_call_facts(
    target: Mapping[str, Any],
    *,
    unit_id: str,
    unit: Mapping[str, Any],
    event_index: int,
    event: Mapping[str, Any],
    state: _State,
    pre_call: _State,
    inventory: _ProfileInventory,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    known_slots: Mapping[int, _Value],
    budget: int,
) -> tuple[_CallFacts | None, list[dict[str, Any]], list[dict[str, Any]]]:
    """Re-bind a recovered target to its call-site effects.

    Target recovery proves which native operation is invoked.  It does not by
    itself replay that operation's out-parameters or memory frame.  Repeating
    that binding here keeps later fixed-point rounds semantically equivalent
    to a call whose target provenance was available locally.
    """

    base = _external_target_call_facts(
        target,
        inventory=inventory,
        import_abis=import_abis,
    )
    issues: list[dict[str, Any]] = []
    recoveries: list[dict[str, Any]] = []
    if base is None:
        issues.append({
            "code": "recovered_external_target_contract_invalid",
            "unit_id": unit_id,
            "event_index": event_index,
        })
        return None, issues, recoveries

    protocol = _mapping(target.get("external_protocol"))
    profile_sha256 = protocol.get("profile_sha256")
    if protocol.get("kind") == "pe32-interface-method":
        interface_id = protocol.get("interface_id")
        offset = _integer(protocol.get("offset"))
        method = (
            inventory.method(profile_sha256, interface_id, offset)
            if isinstance(profile_sha256, str)
            and isinstance(interface_id, str)
            and offset is not None
            else None
        )
        if method is None:
            return None, issues, recoveries
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
        recovery["target_source"] = "recovered_indirect_exit"
        recoveries.append(recovery)
        if not _interface_outputs_recoverable(arguments, method.outputs):
            issues.append({
                "code": "interface_method_arguments_incomplete",
                "unit_id": unit_id,
                "interface_id": method.interface_id,
                "method": method.name,
                "failure": (
                    _mapping(recovery.get("failure")).get("code")
                    or "interface_out_pointer_unresolved"
                ),
            })
        outputs = (
            {}
            if arguments is None or not method.outputs
            else _output_effects(
                arguments,
                method.outputs,
                profile_sha256=profile_sha256,
                issues=issues,
                unit_id=unit_id,
            )
        )
        callback_evidence = _interface_method_callback_registration(
            unit_id=unit_id,
            unit=unit,
            event_index=event_index,
            event=event,
            methods=[(profile_sha256, method)],
            arguments=[arguments],
            inventory=inventory,
            finite_value_budget=budget,
        )
        if callback_evidence is not None:
            recoveries.append(callback_evidence)
            if callback_evidence["status"] != "complete":
                issues.append({
                    "code": "interface_method_callback_provenance_incomplete",
                    "unit_id": unit_id,
                    "event_index": event_index,
                    "instruction_rva": callback_evidence["instruction_rva"],
                    "failure": callback_evidence["failure"]["code"],
                })
        return (
            _CallFacts(
                base.preserved,
                base.abi,
                base.argument_words,
                base.stack_cleanup_bytes,
                outputs,
                memory_writes=_interface_memory_writes(
                    method.caller_memory_frame, arguments
                ),
            ),
            issues,
            recoveries,
        )

    if protocol.get("kind") == "pe32-operation":
        operation_id = protocol.get("operation_id")
        operation = (
            inventory.operation(profile_sha256, operation_id)
            if isinstance(profile_sha256, str)
            and isinstance(operation_id, str)
            else None
        )
        if operation is None:
            return None, issues, recoveries
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
        recovery["target_source"] = "recovered_indirect_exit"
        _record_operation_contract_status(
            recovery,
            issues,
            unit_id=unit_id,
            profile_sha256=profile_sha256,
            operation=operation,
            inventory=inventory,
        )
        recoveries.append(recovery)
        outputs = (
            {}
            if arguments is None
            else _operation_output_effects(
                arguments,
                operation,
                profile_sha256=profile_sha256,
                producer_id=(
                    f"{unit_id}:{event_index}:{operation.operation_id}"
                ),
                inventory=inventory,
                issues=issues,
                unit_id=unit_id,
            )
        )
        return (
            _CallFacts(
                base.preserved,
                base.abi,
                base.argument_words,
                base.stack_cleanup_bytes,
                outputs,
            ),
            issues,
            recoveries,
        )

    return base, issues, recoveries


def _with_call_dependencies(
    facts: _CallFacts,
    dependencies: frozenset[str],
) -> _CallFacts:
    return _CallFacts(
        facts.preserved,
        facts.abi,
        facts.argument_words,
        facts.stack_cleanup_bytes,
        facts.outputs,
        memory_preserved=facts.memory_preserved,
        memory_writes=facts.memory_writes,
        dependencies=facts.dependencies | dependencies,
        register_dependencies=facts.register_dependencies,
    )


def _external_target_call_facts(
    target: Mapping[str, Any],
    *,
    inventory: _ProfileInventory,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
) -> _CallFacts | None:
    protocol = _mapping(target.get("external_protocol"))
    if protocol:
        if protocol.get("kind") == "pe32-previous-callback":
            raw_abi = _mapping(protocol.get("callback_abi"))
            argument_words = _integer(raw_abi.get("argument_words"))
            cleanup = _integer(raw_abi.get("stack_cleanup_bytes"))
            if (
                raw_abi.get("kind") != "generic_callback"
                or argument_words is None
                or cleanup is None
                or cleanup != argument_words * 4
                or _integer(target.get("argument_words")) != argument_words
            ):
                return None
            abi = resolve_machine_call_abi("pe32-stdcall-v1")
            if _mapping(target.get("abi")) != abi.as_json():
                return None
            return _CallFacts(
                frozenset(abi.preserved_registers),
                abi,
                argument_words,
                cleanup,
                {},
            )
        if protocol.get("kind") == "pe32-resolved-export":
            profile_sha256 = protocol.get("profile_sha256")
            target_id = _integer(protocol.get("target_id"))
            if not isinstance(profile_sha256, str) or target_id is None:
                return None
            target_spec = inventory.callable_target(profile_sha256, target_id)
            expected = (
                None
                if target_spec is None
                else inventory.callable_target_json(
                    profile_sha256, target_spec, transfer="call"
                )
            )
            if expected is None or target != expected:
                return None
            return _CallFacts(
                frozenset(target_spec.abi.preserved_registers),
                target_spec.abi,
                target_spec.argument_words,
                _abi_stack_cleanup(target_spec.abi, target_spec.argument_words),
                {},
            )
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
        memory_preserved=_selected_import_memory_preserved(selected),
    )


def _combine_call_facts(
    alternatives: Sequence[_CallFacts],
    *,
    budget: int = 32,
) -> _CallFacts | None:
    if not alternatives or any(facts.preserved is None for facts in alternatives):
        return None
    preserved = set(alternatives[0].preserved or ())
    for facts in alternatives[1:]:
        preserved.intersection_update(facts.preserved or ())
    abis = {facts.abi for facts in alternatives}
    argument_counts = {facts.argument_words for facts in alternatives}
    cleanups = {facts.stack_cleanup_bytes for facts in alternatives}
    common_output_locations = set(alternatives[0].outputs)
    for facts in alternatives[1:]:
        common_output_locations.intersection_update(facts.outputs)
    outputs: dict[_Origin, _Value] = {}
    for location in common_output_locations:
        value: _Value = frozenset()
        for facts in alternatives:
            value = _join_value(value, facts.outputs[location], budget)
            if value is None:
                break
        outputs[location] = value
    return _CallFacts(
        frozenset(preserved),
        next(iter(abis)) if len(abis) == 1 else None,
        next(iter(argument_counts)) if len(argument_counts) == 1 else None,
        (
            next(iter(cleanups))
            if len(cleanups) == 1 and None not in cleanups
            else None
        ),
        outputs,
        memory_preserved=all(
            facts.memory_preserved for facts in alternatives
        ),
        memory_writes=_combine_memory_writes(
            [facts.memory_writes for facts in alternatives]
        ),
        dependencies=frozenset().union(
            *(facts.dependencies for facts in alternatives)
        ),
        register_dependencies={
            register: frozenset().union(*(
                facts.register_dependencies.get(register, frozenset())
                for facts in alternatives
            ))
            for register in preserved
            if any(
                facts.register_dependencies.get(register)
                for facts in alternatives
            )
        },
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
    required_argument_indices: frozenset[int] | None = None,
) -> tuple[tuple[_Value, ...] | None, dict[str, Any]]:
    required = (
        frozenset(range(argument_words))
        if required_argument_indices is None
        else required_argument_indices
    )
    if any(index < 0 or index >= argument_words for index in required):
        raise ValueError("required call argument index is out of range")
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
            required_argument_indices=required,
        )
    call_esp = next(iter(offsets))
    arguments: list[_Value] = []
    evidence: list[dict[str, Any]] = []
    unresolved: list[int] = []
    for argument_index in range(argument_words):
        offset = call_esp + argument_index * 4
        cell = pre_call.stack.get(offset)
        if cell is None or cell.value is None:
            arguments.append(None)
            unresolved.append(argument_index)
            evidence.append({
                "argument_index": argument_index,
                "stack_offset": offset,
                "origins": None,
                "writes": [],
            })
            continue
        arguments.append(cell.value)
        evidence.append({
            "argument_index": argument_index,
            "stack_offset": offset,
            "origins": _origins_json(cell.value),
            "writes": [witness.as_json() for witness in cell.witnesses],
        })
    if required.intersection(unresolved):
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
            required_argument_indices=required,
        )
    return tuple(arguments), _argument_recovery_json(
        unit_id=unit_id,
        event_index=event_index,
        argument_words=argument_words,
        call_esp=call_esp,
        arguments=evidence,
        required_argument_indices=required,
        unresolved_argument_indices=unresolved,
        local_evidence=local_evidence,
        recovery_mode=(
            "rooted_inter_unit_stack_partial"
            if unresolved
            else "rooted_inter_unit_stack"
        ),
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
    required_argument_indices: frozenset[int],
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
        unresolved = [
            index for index, value in enumerate(values) if value is None
        ]
        if not required_argument_indices.intersection(unresolved):
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
                required_argument_indices=required_argument_indices,
                unresolved_argument_indices=unresolved,
                local_evidence=local_evidence,
                recovery_mode=(
                    "exact_same_unit_partial"
                    if unresolved
                    else "exact_same_unit"
                ),
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
            required_argument_indices=required_argument_indices,
            unresolved_argument_indices=unresolved,
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
        required_argument_indices=required_argument_indices,
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
    required_argument_indices: Iterable[int] = (),
    unresolved_argument_indices: Iterable[int] = (),
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
        "required_argument_indices": sorted(set(required_argument_indices)),
        "unresolved_argument_indices": sorted(set(unresolved_argument_indices)),
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


def _enter_call_frame(
    state: _State,
    *,
    return_address: int | None = None,
) -> _State:
    """Translate one checked caller stack into a fresh callee frame.

    Call-event states describe ESP immediately before x86 pushes the return
    address.  Cells at and above that ESP are therefore arguments and retain
    their relative offsets in the callee after a four-byte frame shift.  Cells
    below the call-time ESP are caller temporaries and are deliberately hidden.
    """

    call_offsets = _stack_offsets(state.registers.get("esp"))
    translated_stack: dict[int, _StackCell] = {}
    if call_offsets is not None and len(call_offsets) == 1:
        call_esp = next(iter(call_offsets))
        translated_stack = {
            offset - call_esp + 4: cell
            for offset, cell in state.stack.items()
            if offset >= call_esp
        }
    if return_address is not None:
        translated_stack[0] = _StackCell(
            frozenset({_Origin("exact", (return_address,))}),
            (),
        )
    output = _State(
        dict(state.registers),
        dict(state.memory),
        translated_stack,
        state.memory_invalidated,
    )
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
            or next(iter(addresses)).kind not in {
                "exact",
                "stack_location",
                "dynamic_range",
                "dynamic_location",
                "symbolic_affine",
            }
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
    known_slots: Mapping[Any, _Value],
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
            transfer=(
                "call" if exit_record.get("kind") == "indirect_call" else "jump"
            ),
        )
        if classified is None:
            failure = _target_resolution_failure(
                target,
                origins,
                state=state,
                inventory=inventory,
                known_slots=known_slots,
                finite_value_budget=finite_value_budget,
            )
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
                else "checked_resolver_export_inventory"
                if target_kinds == {"resolved_export"}
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
            "target_origin_witnesses": origins_json(origins),
            "analysis_dependencies": list(value_dependencies(origins)),
            "failure": None,
        })
    return result


def _recovery_target_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    """Project one finite recovery onto the target set it proposes."""

    return {
        "target_rvas": row.get("target_rvas", []),
        "target_unit_ids": row.get("target_unit_ids", []),
        "external_targets": row.get("external_targets", []),
    }


def _merge_path_recovery_proposal(
    existing: Mapping[str, Any] | None,
    candidate: Mapping[str, Any],
    *,
    finite_value_budget: int,
) -> dict[str, Any]:
    """Keep one deterministic witnessed state for an agreeing path target."""

    if existing is None:
        return copy.deepcopy(dict(candidate))
    choices = [existing, candidate]

    def rank(row: Mapping[str, Any]) -> tuple[int, int, str]:
        dependencies = row.get("analysis_dependencies", ())
        witnesses = row.get("target_origin_witnesses", ())
        dependency_count = (
            len(dependencies)
            if isinstance(dependencies, Sequence)
            and not isinstance(dependencies, (str, bytes))
            else 0
        )
        witness_count = (
            len(witnesses)
            if isinstance(witnesses, Sequence)
            and not isinstance(witnesses, (str, bytes))
            and len(witnesses) <= finite_value_budget
            else 0
        )
        return (
            dependency_count,
            witness_count,
            json.dumps(
                row,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ),
        )

    return copy.deepcopy(dict(max(choices, key=rank)))


def _finalize_path_recovery_proposals(
    final_resolutions: Sequence[Mapping[str, Any]],
    candidates: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    """Emit non-authorizing finite path hints, rejecting disagreements."""

    by_id = {
        str(row.get("id")): row
        for row in final_resolutions
        if isinstance(row.get("id"), str)
    }
    result: list[dict[str, Any]] = []
    for identity, alternatives in sorted(candidates.items()):
        if len(alternatives) == 1:
            row = copy.deepcopy(dict(next(iter(alternatives.values()))))
            row["proposal_source"] = "path_sensitive_pre_widening_v1"
            row["proof_authority"] = False
            result.append(row)
            continue
        base = copy.deepcopy(dict(by_id.get(identity, {})))
        result.append({
            **base,
            "id": identity,
            "status": "incomplete",
            "closure": "unresolved",
            "target_rvas": [],
            "target_unit_ids": [],
            "external_targets": [],
            "proposal_source": "path_sensitive_pre_widening_v1",
            "proof_authority": False,
            "failure": {
                "code": "conflicting_path_recovery_proposals",
                "alternative_count": len(alternatives),
            },
        })
    return result


def _target_resolution_failure(
    expression: Any,
    origins: _Value,
    *,
    state: _State | None = None,
    inventory: _ProfileInventory | None = None,
    known_slots: Mapping[int, _Value] | None = None,
    finite_value_budget: int = 32,
) -> dict[str, Any]:
    frontier = (
        None
        if state is None or inventory is None
        else _expression_analysis_frontier(
            expression,
            state=state,
            inventory=inventory,
            known_slots=known_slots or {},
            budget=finite_value_budget,
            path="target",
        )
    )

    def with_frontier(result: dict[str, Any]) -> dict[str, Any]:
        return result if frontier is None else {**result, "analysis_frontier": frontier}

    if origins is not None:
        return with_frontier({
            "code": "target_origin_kind_unsupported",
            "observed_origin_kinds": sorted({origin.kind for origin in origins}),
            "next_action": (
                "add or repair the producer, call-frame, or operation-profile rule "
                "for the observed bounded origin"
            ),
        })
    row = _mapping(expression)
    op = str(row.get("op") or "").lower()
    if op in {"reg", "input_reg", "register"}:
        return with_frontier({
            "code": "register_target_origin_missing",
            "register": row.get("name", row.get("reg")),
            "next_action": (
                "recover the register producer or add the missing call/return "
                "preservation contract"
            ),
        })
    if op in {"load", "read32", "mem32"}:
        address = _mapping(row.get("address"))
        address_op = str(address.get("op") or "").lower()
        if address_op in {"const", "constant"}:
            return with_frontier({
                "code": "static_slot_target_origin_missing",
                "address": address.get("value"),
                "next_action": (
                    "classify the static slot initializer and every reachable write"
                ),
            })
        return with_frontier({
            "code": "operation_view_origin_missing",
            "next_action": (
                "recover the receiver resource view, table load, and slot offset "
                "from a pinned operation profile"
            ),
        })
    return with_frontier({
        "code": "target_expression_not_normalized",
        "next_action": "extend the generic expression normalizer for this x86 form",
    })


def _expression_analysis_frontier(
    expression: Any,
    *,
    state: _State,
    inventory: _ProfileInventory,
    known_slots: Mapping[int, _Value],
    budget: int,
    path: str,
) -> dict[str, Any]:
    """Explain the deepest checked-expression fact which prevented evaluation."""

    row = _mapping(expression)
    op = str(row.get("op") or "").lower()
    evaluated = _evaluate(
        expression,
        state,
        inventory=inventory,
        known_slots=known_slots,
        budget=budget,
    )
    if evaluated is not None:
        return {
            "code": "expression_origin_not_callable",
            "path": path,
            "op": op,
            "observed_origin_kinds": sorted({origin.kind for origin in evaluated}),
            "observed_origins": _origins_json(evaluated),
        }
    if op in {"reg", "input_reg", "register"}:
        return {
            "code": "register_origin_missing",
            "path": path,
            "op": op,
            "register": row.get("name", row.get("reg")),
        }
    if op in {
        "add",
        "add32",
        "sub",
        "sub32",
        "mul",
        "mul32",
        "and",
        "and32",
    }:
        operands = (
            _binary_operands(row)
            if op in {"sub", "sub32"}
            else _arithmetic_operands(row, associative=True)
        )
        if operands is None:
            return {
                "code": "binary_expression_malformed",
                "path": path,
                "op": op,
            }
        values = tuple(
            _evaluate(
                operand,
                state,
                inventory=inventory,
                known_slots=known_slots,
                budget=budget,
            )
            for operand in operands
        )
        for index, value in enumerate(values):
            if value is None:
                return {
                    "code": "operand_origin_missing",
                    "path": path,
                    "op": op,
                    "operand_index": index,
                    "cause": _expression_analysis_frontier(
                        operands[index],
                        state=state,
                        inventory=inventory,
                        known_slots=known_slots,
                        budget=budget,
                        path=f"{path}.args[{index}]",
                    ),
                }
        return {
            "code": "origin_combination_unsupported",
            "path": path,
            "op": op,
            "operand_origin_kinds": [
                sorted({origin.kind for origin in value or ()}) for value in values
            ],
        }
    if op in {"neg", "neg32"}:
        operand = _unary_operand(row)
        if operand is None:
            return {
                "code": "unary_expression_malformed",
                "path": path,
                "op": op,
            }
        return {
            "code": "unary_operand_origin_missing",
            "path": path,
            "op": op,
            "cause": _expression_analysis_frontier(
                operand,
                state=state,
                inventory=inventory,
                known_slots=known_slots,
                budget=budget,
                path=f"{path}.args[0]",
            ),
        }
    if op in {"load", "read32", "mem32"}:
        address_expression = row.get("address")
        addresses = _evaluate(
            address_expression,
            state,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
        )
        if addresses is None:
            return {
                "code": "load_address_origin_missing",
                "path": path,
                "op": op,
                "cause": _expression_analysis_frontier(
                    address_expression,
                    state=state,
                    inventory=inventory,
                    known_slots=known_slots,
                    budget=budget,
                    path=f"{path}.address",
                ),
            }
        causes = [
            failure
            for address in sorted(addresses)
            if (
                failure := _load_origin_failure(
                    address,
                    state=state,
                    inventory=inventory,
                    known_slots=known_slots,
                )
            ) is not None
        ]
        return {
            "code": "load_value_origin_missing",
            "path": path,
            "op": op,
            "address_origins": _origins_json(addresses),
            "causes": causes,
        }
    return {
        "code": "expression_form_unsupported",
        "path": path,
        "op": op,
    }


def _load_origin_failure(
    address: _Origin,
    *,
    state: _State,
    inventory: _ProfileInventory,
    known_slots: Mapping[int, _Value],
) -> dict[str, Any] | None:
    """Classify why a successfully evaluated address has no load result."""

    base = {"address_origin": address.as_json()}
    if address.kind == "exact":
        concrete = int(address.key[0]) & 0xFFFFFFFF
        if concrete in state.memory:
            if state.memory[concrete] is not None:
                return None
        elif concrete in inventory.iat:
            return None
        elif inventory.immutable_u32_origin(concrete) is not None:
            return None
        elif (known := known_slots.get(concrete)) is not None and not (
            state.memory_invalidated
            and _has_global_slot_authority_dependency(known)
        ):
            return None
        return {
            **base,
            "code": (
                "exact_memory_fact_invalidated"
                if state.memory_invalidated
                else "exact_memory_fact_missing"
            ),
            "address": concrete,
            "known_static_slot": concrete in known_slots,
            "known_import_slot": concrete in inventory.iat,
        }
    if address.kind == "stack_location":
        cell = state.stack.get(int(address.key[0]))
        if cell is not None and cell.value is not None:
            return None
        return {
            **base,
            "code": "stack_memory_fact_missing",
            "stack_offset": int(address.key[0]),
        }
    if address.kind in {"dynamic_range", "dynamic_location"}:
        if _read_memory_fact(
            state,
            _dynamic_memory_location(address),
            known_slots=known_slots,
        ) is not None:
            return None
        return {**base, "code": "dynamic_memory_fact_missing"}
    if address.kind == "symbolic_affine":
        if _read_memory_fact(
            state,
            _Origin(address.kind, address.key),
            known_slots=known_slots,
        ) is not None:
            return None
        return {**base, "code": "symbolic_memory_fact_missing"}
    if address.kind == "interface_object":
        return None
    if address.kind == "interface_vtable":
        profile_sha256, interface_id = address.key
        if inventory.method(str(profile_sha256), str(interface_id), 0) is not None:
            return None
        return {**base, "code": "interface_profile_slot_missing"}
    if address.kind == "interface_slot":
        profile_sha256, interface_id, offset = address.key
        if inventory.method(
            str(profile_sha256), str(interface_id), int(offset)
        ) is not None:
            return None
        return {**base, "code": "interface_profile_slot_missing"}
    if address.kind == "resource_view":
        profile_sha256, view_id, *_ = address.key
        access = inventory.operation_view_access(
            str(profile_sha256), str(view_id)
        )
        if access == "object_table" or (
            access == "direct_table"
            and inventory.operation_for_slot(
                str(profile_sha256), str(view_id), 0
            ) is not None
        ):
            return None
        return {**base, "code": "operation_profile_slot_missing"}
    if address.kind in {"operation_table", "operation_slot"}:
        profile_sha256, view_id, *rest = address.key
        offset = 0 if address.kind == "operation_table" else int(rest[0])
        if inventory.operation_for_slot(
            str(profile_sha256), str(view_id), offset
        ) is not None:
            return None
        return {**base, "code": "operation_profile_slot_missing"}
    return {**base, "code": "load_address_origin_unsupported"}


def _classify_target_origins(
    origins: _Value,
    *,
    inventory: _ProfileInventory,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    transfer: str,
) -> tuple[list[tuple[int, str]], list[dict[str, Any]], set[str]] | None:
    if origins is None or not origins:
        return None
    internal: set[tuple[int, str]] = set()
    external: dict[str, dict[str, Any]] = {}
    kinds: set[str] = set()
    for origin in origins:
        if origin.kind in {"exact", "static_code", "static_data"}:
            concrete = origin_concrete_value(origin)
            if concrete is None:
                return None
            candidates = inventory.unit_targets.get(concrete, ())
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
            rendered["external_protocol"]["transfer_kind"] = transfer
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
        if origin.kind == "resolved_export":
            profile_sha256, target_id = origin.key
            target = inventory.callable_target(str(profile_sha256), int(target_id))
            if target is None or transfer not in target.transfers:
                return None
            rendered = inventory.callable_target_json(
                str(profile_sha256), target, transfer=transfer
            )
            if rendered is None:
                return None
            external[json.dumps(rendered, sort_keys=True)] = rendered
            kinds.add("resolved_export")
            continue
        if origin.kind == "callback_token":
            (
                contract_id,
                profile_binding,
                callback_kind,
                argument_words,
                stack_cleanup_bytes,
                nullable,
                lifetime,
            ) = origin.key
            abi = resolve_machine_call_abi("pe32-stdcall-v1")
            rendered = {
                "external_protocol": {
                    "kind": "pe32-previous-callback",
                    "contract_id": str(contract_id),
                    "profile_binding": json.loads(str(profile_binding)),
                    "callback_abi": {
                        "kind": str(callback_kind),
                        "argument_words": int(argument_words),
                        "stack_cleanup_bytes": int(stack_cleanup_bytes),
                        "nullable": bool(nullable),
                    },
                    "callback_lifetime": str(lifetime),
                    "effect_model": "same-process-callback-callthrough-v1",
                },
                "abi": abi.as_json(),
                "argument_words": int(argument_words),
            }
            external[json.dumps(rendered, sort_keys=True)] = rendered
            kinds.add("callback_token")
            continue
        return None
    return sorted(internal), [external[key] for key in sorted(external)], kinds


def _evaluate(
    expression: Any,
    state: _State,
    *,
    inventory: _ProfileInventory,
    known_slots: Mapping[_MemoryLocation, _Value],
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
    if op in {
        "add",
        "add32",
        "mul",
        "mul32",
        "and",
        "and32",
    }:
        operands = _arithmetic_operands(expression, associative=True)
        if operands is None:
            return None
        result = _evaluate(
            operands[0],
            state,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
        )
        for operand in operands[1:]:
            value = _evaluate(
                operand,
                state,
                inventory=inventory,
                known_slots=known_slots,
                budget=budget,
            )
            if op in {"and", "and32"}:
                result = _bitwise_and_values(result, value, budget=budget)
            elif op in {"mul", "mul32"}:
                result = _multiply_values(result, value, budget=budget)
            else:
                result = _add_values(
                    result,
                    value,
                    subtract=False,
                    budget=budget,
                    inventory=inventory,
                )
            if result is None:
                return None
        return result
    if op in {"sub", "sub32"}:
        operands = _binary_operands(expression)
        if operands is None:
            return None
        left = _evaluate(
            operands[0],
            state,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
        )
        right = _evaluate(
            operands[1],
            state,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
        )
        return _add_values(
            left,
            right,
            subtract=True,
            budget=budget,
            inventory=inventory,
        )
    if op in {"neg", "neg32"}:
        operand = _unary_operand(expression)
        return (
            None
            if operand is None
            else _negate_values(
                _evaluate(
                    operand,
                    state,
                    inventory=inventory,
                    known_slots=known_slots,
                    budget=budget,
                ),
                budget=budget,
            )
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
            address_dependencies = address.dependencies
            if address.kind == "exact":
                concrete = int(address.key[0]) & 0xFFFFFFFF
                if concrete in state.memory:
                    value = state.memory[concrete]
                elif concrete in inventory.iat:
                    value = frozenset({_import_origin(inventory.iat[concrete])})
                else:
                    static_origin = inventory.immutable_u32_origin(concrete)
                    if static_origin is not None:
                        value = frozenset({static_origin})
                    elif concrete in known_slots:
                        value = known_slots[concrete]
                        if (
                            state.memory_invalidated
                            and _has_global_slot_authority_dependency(value)
                        ):
                            value = None
                    elif state.memory_invalidated:
                        value = None
                    else:
                        value = None
                if value is None:
                    return None
                result.update(
                    with_value_dependencies(value, address_dependencies) or ()
                )
            elif address.kind == "stack_location":
                cell = state.stack.get(int(address.key[0]))
                if cell is None or cell.value is None:
                    return None
                result.update(
                    with_value_dependencies(
                        cell.value, address_dependencies
                    ) or ()
                )
            elif address.kind in {"dynamic_range", "dynamic_location"}:
                location = _dynamic_memory_location(address)
                value = _read_memory_fact(
                    state,
                    location,
                    known_slots=known_slots,
                )
                if value is None:
                    return None
                result.update(
                    with_value_dependencies(value, address_dependencies) or ()
                )
            elif address.kind == "symbolic_affine":
                value = _read_memory_fact(
                    state,
                    _Origin(address.kind, address.key),
                    known_slots=known_slots,
                )
                if value is None:
                    return None
                result.update(
                    with_value_dependencies(value, address_dependencies) or ()
                )
            elif address.kind == "interface_object":
                result.add(_Origin(
                    "interface_vtable", address.key, address.dependencies
                ))
            elif address.kind == "resource_view":
                profile_sha256, view_id, *_ = address.key
                access = inventory.operation_view_access(
                    str(profile_sha256), str(view_id)
                )
                if access == "object_table":
                    result.add(_Origin(
                        "operation_table", address.key, address.dependencies
                    ))
                elif access == "direct_table":
                    operation = inventory.operation_for_slot(
                        str(profile_sha256), str(view_id), 0
                    )
                    if operation is None:
                        return None
                    result.add(_Origin(
                        "operation_target",
                        (profile_sha256, operation.operation_id),
                        address.dependencies,
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
                    address.dependencies,
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
                    address.dependencies,
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
                    address.dependencies,
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
            dependencies = tuple(sorted(
                set(lhs.dependencies) | set(rhs.dependencies)
            ))

            def emit(origin: _Origin) -> None:
                result.add(with_origin_dependencies(origin, dependencies))

            lhs_concrete = origin_concrete_value(lhs)
            rhs_concrete = origin_concrete_value(rhs)
            if lhs_concrete is not None and rhs_concrete is not None:
                value = (
                    lhs_concrete - rhs_concrete
                    if subtract
                    else lhs_concrete + rhs_concrete
                )
                emit(_concrete_result_origin(value, lhs, rhs))
            elif (
                lhs.kind == "symbolic_affine"
                or rhs.kind == "symbolic_affine"
            ):
                affine = _combine_affine_origins(
                    lhs,
                    rhs,
                    subtract=subtract,
                )
                if affine is None:
                    return None
                emit(affine)
            elif not subtract and lhs.kind == "interface_vtable" and rhs.kind == "exact":
                emit(_Origin("interface_slot", (*lhs.key, int(rhs.key[0]))))
            elif not subtract and lhs.kind == "exact" and rhs.kind == "interface_vtable":
                emit(_Origin("interface_slot", (*rhs.key, int(lhs.key[0]))))
            elif not subtract and lhs.kind == "operation_table" and rhs.kind == "exact":
                emit(_Origin(
                    "operation_slot", (lhs.key[0], lhs.key[1], int(rhs.key[0]), *lhs.key[2:])
                ))
            elif not subtract and lhs.kind == "exact" and rhs.kind == "operation_table":
                emit(_Origin(
                    "operation_slot", (rhs.key[0], rhs.key[1], int(lhs.key[0]), *rhs.key[2:])
                ))
            elif not subtract and lhs.kind == "resource_view" and rhs.kind == "exact":
                if inventory.operation_view_access(
                    str(lhs.key[0]), str(lhs.key[1])
                ) != "direct_table":
                    return None
                emit(_Origin(
                    "operation_slot",
                    (lhs.key[0], lhs.key[1], int(rhs.key[0]), *lhs.key[2:]),
                ))
            elif not subtract and lhs.kind == "exact" and rhs.kind == "resource_view":
                if inventory.operation_view_access(
                    str(rhs.key[0]), str(rhs.key[1])
                ) != "direct_table":
                    return None
                emit(_Origin(
                    "operation_slot",
                    (rhs.key[0], rhs.key[1], int(lhs.key[0]), *rhs.key[2:]),
                ))
            elif lhs.kind == "stack_location" and rhs.kind == "exact":
                offset = int(lhs.key[0])
                delta = _signed_u32(int(rhs.key[0]))
                emit(_Origin(
                    "stack_location",
                    (offset - delta if subtract else offset + delta,),
                ))
            elif (
                not subtract
                and lhs.kind == "exact"
                and rhs.kind == "stack_location"
            ):
                emit(_Origin(
                    "stack_location",
                    (int(rhs.key[0]) + _signed_u32(int(lhs.key[0])),),
                ))
            elif lhs.kind in {"dynamic_range", "dynamic_location"} and rhs.kind == "exact":
                emit(_offset_dynamic_location(
                    lhs,
                    -_signed_u32(int(rhs.key[0]))
                    if subtract
                    else _signed_u32(int(rhs.key[0])),
                ))
            elif (
                not subtract
                and lhs.kind == "exact"
                and rhs.kind in {"dynamic_range", "dynamic_location"}
            ):
                emit(_offset_dynamic_location(
                    rhs, _signed_u32(int(lhs.key[0]))
                ))
            else:
                return None
    return frozenset(result) if result and len(result) <= budget else None


def _multiply_values(left: _Value, right: _Value, *, budget: int) -> _Value:
    if left is None or right is None or len(left) * len(right) > budget:
        return None
    result: set[_Origin] = set()
    for lhs in left:
        for rhs in right:
            dependencies = tuple(sorted(
                set(lhs.dependencies) | set(rhs.dependencies)
            ))

            def emit(origin: _Origin) -> None:
                result.add(with_origin_dependencies(origin, dependencies))

            lhs_concrete = origin_concrete_value(lhs)
            rhs_concrete = origin_concrete_value(rhs)
            if lhs_concrete is not None and rhs_concrete is not None:
                emit(_concrete_result_origin(
                    lhs_concrete * rhs_concrete,
                    lhs,
                    rhs,
                ))
                continue
            if lhs.kind == "symbolic_affine" and rhs_concrete is not None:
                emit(_scale_affine_origin(lhs, rhs_concrete))
                continue
            if rhs.kind == "symbolic_affine" and lhs_concrete is not None:
                emit(_scale_affine_origin(rhs, lhs_concrete))
                continue
            return None
    return frozenset(result) if result and len(result) <= budget else None


def _bitwise_and_values(left: _Value, right: _Value, *, budget: int) -> _Value:
    """Evaluate exact ANDs or enumerate every result of a bounded mask."""

    left_concrete = _concrete_origins(left)
    right_concrete = _concrete_origins(right)
    if left_concrete is not None and right_concrete is not None:
        result = {
            with_origin_dependencies(
                _concrete_result_origin(lhs_value & rhs_value, lhs, rhs),
                set(lhs.dependencies) | set(rhs.dependencies),
            )
            for lhs, lhs_value in left_concrete
            for rhs, rhs_value in right_concrete
        }
        return frozenset(result) if result and len(result) <= budget else None

    masks = left_concrete if left_concrete is not None else right_concrete
    unknown = right if left_concrete is not None else left
    if masks is None:
        return None
    dependencies = set(value_dependencies(unknown))
    result: set[_Origin] = set()
    for mask_origin, mask in masks:
        mask_dependencies = tuple(sorted(dependencies | set(mask_origin.dependencies)))
        subset = mask & 0xFFFFFFFF
        while True:
            result.add(_Origin("exact", (subset,), mask_dependencies))
            if len(result) > budget:
                return None
            if subset == 0:
                break
            subset = (subset - 1) & mask
    return frozenset(result) if result else None


def _negate_values(value: _Value, *, budget: int) -> _Value:
    if value is None or len(value) > budget:
        return None
    result: set[_Origin] = set()
    for origin in value:
        concrete = origin_concrete_value(origin)
        if concrete is not None:
            result.add(with_origin_dependencies(
                _concrete_result_origin(-concrete, origin),
                origin.dependencies,
            ))
        elif origin.kind == "symbolic_affine":
            result.add(with_origin_dependencies(
                _scale_affine_origin(origin, 0xFFFFFFFF),
                origin.dependencies,
            ))
        else:
            return None
    return frozenset(result) if result and len(result) <= budget else None


def _concrete_origins(
    value: _Value,
) -> tuple[tuple[_Origin, int], ...] | None:
    if value is None:
        return None
    result: list[tuple[_Origin, int]] = []
    for origin in value:
        concrete = origin_concrete_value(origin)
        if concrete is None:
            return None
        result.append((origin, concrete))
    return tuple(result)


def _symbolic_affine_value(symbol: str) -> _Value:
    return frozenset({_Origin("symbolic_affine", (0, ((symbol, 1),)))})


def _affine_parts(origin: _Origin) -> tuple[int, dict[str, int]] | None:
    if origin.kind == "symbolic_affine" and len(origin.key) == 2:
        constant, raw_terms = origin.key
        if not isinstance(constant, int) or not isinstance(raw_terms, tuple):
            return None
        terms: dict[str, int] = {}
        for raw in raw_terms:
            if (
                not isinstance(raw, tuple)
                or len(raw) != 2
                or not isinstance(raw[0], str)
                or not isinstance(raw[1], int)
            ):
                return None
            coefficient = int(raw[1]) & 0xFFFFFFFF
            if coefficient:
                terms[str(raw[0])] = coefficient
        return int(constant) & 0xFFFFFFFF, terms
    concrete = origin_concrete_value(origin)
    if concrete is not None:
        return concrete, {}
    return None


def _make_affine_origin(constant: int, terms: Mapping[str, int]) -> _Origin:
    normalized = tuple(sorted(
        (str(symbol), int(coefficient) & 0xFFFFFFFF)
        for symbol, coefficient in terms.items()
        if int(coefficient) & 0xFFFFFFFF
    ))
    constant &= 0xFFFFFFFF
    if not normalized:
        return _Origin("exact", (constant,))
    return _Origin("symbolic_affine", (constant, normalized))


def _combine_affine_origins(
    left: _Origin,
    right: _Origin,
    *,
    subtract: bool,
) -> _Origin | None:
    left_parts = _affine_parts(left)
    right_parts = _affine_parts(right)
    if left_parts is None or right_parts is None:
        return None
    left_constant, left_terms = left_parts
    right_constant, right_terms = right_parts
    sign = -1 if subtract else 1
    terms = dict(left_terms)
    for symbol, coefficient in right_terms.items():
        terms[symbol] = (
            terms.get(symbol, 0) + sign * coefficient
        ) & 0xFFFFFFFF
    return _make_affine_origin(
        left_constant + sign * right_constant,
        terms,
    )


def _scale_affine_origin(origin: _Origin, factor: int) -> _Origin:
    parts = _affine_parts(origin)
    if parts is None:
        raise ValueError("affine scaling requires an affine origin")
    constant, terms = parts
    factor &= 0xFFFFFFFF
    return _make_affine_origin(
        constant * factor,
        {symbol: coefficient * factor for symbol, coefficient in terms.items()},
    )


def _dynamic_memory_location(origin: _Origin) -> _Origin:
    if origin.kind == "dynamic_location":
        return _Origin(origin.kind, origin.key)
    if origin.kind != "dynamic_range":
        raise ValueError("dynamic memory location requires a dynamic origin")
    return _Origin("dynamic_location", (*origin.key, 0))


def _offset_dynamic_location(origin: _Origin, delta: int) -> _Origin:
    location = _dynamic_memory_location(origin)
    return _Origin(
        "dynamic_location",
        (*location.key[:-1], int(location.key[-1]) + delta),
    )


def _concrete_result_origin(value: int, *inputs: _Origin) -> _Origin:
    sources = tuple(sorted({
        int(address) & 0xFFFFFFFF
        for origin in inputs
        if origin.kind in {"static_code", "static_data"}
        for address in origin.key[1]
    }))
    concrete = value & 0xFFFFFFFF
    return (
        _Origin("exact", (concrete,))
        if not sources
        else _Origin("static_data", (concrete, sources))
    )


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
    output = _State(
        registers,
        dict(state.memory),
        dict(state.stack),
        state.memory_invalidated,
    )
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
        elif address.kind in {"dynamic_range", "dynamic_location"}:
            location = _dynamic_memory_location(address)
            output.memory[location] = value
        elif address.kind == "symbolic_affine":
            output.memory[address] = value
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


def _infer_internal_call_cleanups(
    *,
    by_id: Mapping[str, Mapping[str, Any]],
    outgoing: Mapping[str, set[_Edge]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    image_base: int,
    unit_budget: int = 4096,
) -> tuple[_InternalCleanupEvidence, ...]:
    """Infer caller-visible cleanup from exact reachable ``ret`` forms.

    The cleanup performed by an x86 callee is determined by the immediate on
    each returning ``ret`` instruction.  Prologue stack motion and nested calls
    do not affect that caller-visible fact.  This deliberately follows only
    represented non-call continuations, requires every returning path to agree,
    and refuses open or oversized bodies.
    """

    targets: dict[int, str] = {}
    ambiguous: set[int] = set()
    for raw in internal_call_edges:
        target_id = raw.get("target_unit_id", raw.get("resolved_unit_id"))
        if not isinstance(target_id, str) or target_id not in by_id:
            continue
        source = _mapping(_mapping(by_id[target_id].get("source")).get("original"))
        target_rva = _integer(source.get("rva_start"))
        if target_rva is None:
            continue
        address = (image_base + target_rva) & 0xFFFFFFFF
        prior = targets.get(address)
        if prior is not None and prior != target_id:
            ambiguous.add(address)
            continue
        targets[address] = target_id

    result: list[_InternalCleanupEvidence] = []
    for address, target_id in sorted(targets.items()):
        if address in ambiguous:
            result.append(_InternalCleanupEvidence(
                address,
                target_id,
                None,
                (),
                "incomplete",
                "internal_call_target_unit_ambiguous",
            ))
            continue
        result.append(_infer_target_cleanup(
            target_address=address,
            target_unit_id=target_id,
            by_id=by_id,
            outgoing=outgoing,
            unit_budget=unit_budget,
        ))
    return tuple(result)


def _infer_target_cleanup(
    *,
    target_address: int,
    target_unit_id: str,
    by_id: Mapping[str, Mapping[str, Any]],
    outgoing: Mapping[str, set[_Edge]],
    unit_budget: int,
) -> _InternalCleanupEvidence:
    work = deque([target_unit_id])
    visited: set[str] = set()
    returns: dict[str, int] = {}
    while work:
        unit_id = work.popleft()
        if unit_id in visited:
            continue
        if len(visited) >= unit_budget:
            return _InternalCleanupEvidence(
                target_address,
                target_unit_id,
                None,
                tuple(sorted(returns)),
                "incomplete",
                "internal_call_cleanup_unit_budget_exceeded",
            )
        unit = by_id.get(unit_id)
        if unit is None:
            return _InternalCleanupEvidence(
                target_address,
                target_unit_id,
                None,
                tuple(sorted(returns)),
                "incomplete",
                "internal_call_cleanup_unit_missing",
            )
        visited.add(unit_id)
        outcome = _mapping(_mapping(unit.get("semantics")).get("outcome"))
        if outcome.get("kind") == "return":
            cleanup = _return_cleanup_bytes(unit)
            if cleanup is None:
                return _InternalCleanupEvidence(
                    target_address,
                    target_unit_id,
                    None,
                    tuple(sorted((*returns, unit_id))),
                    "incomplete",
                    "internal_call_return_form_unsupported",
                )
            returns[unit_id] = cleanup
            continue

        successors = sorted(
            edge.target_id
            for edge in outgoing.get(unit_id, ())
            if edge.kind == "direct"
        )
        if successors:
            work.extend(successors)
            continue
        if outcome.get("kind") in {
            "fault",
            "halt",
            "nonreturning",
            "termination",
            "unreachable",
        }:
            continue
        return _InternalCleanupEvidence(
            target_address,
            target_unit_id,
            None,
            tuple(sorted(returns)),
            "incomplete",
            "internal_call_return_frontier_open",
        )

    cleanup_values = set(returns.values())
    if not returns:
        return _InternalCleanupEvidence(
            target_address,
            target_unit_id,
            None,
            (),
            "incomplete",
            "internal_call_has_no_represented_return",
        )
    if len(cleanup_values) != 1:
        return _InternalCleanupEvidence(
            target_address,
            target_unit_id,
            None,
            tuple(sorted(returns)),
            "incomplete",
            "internal_call_return_cleanup_ambiguous",
        )
    return _InternalCleanupEvidence(
        target_address,
        target_unit_id,
        next(iter(cleanup_values)),
        tuple(sorted(returns)),
        "complete",
    )


def _return_cleanup_bytes(unit: Mapping[str, Any]) -> int | None:
    instructions = unit.get("instructions")
    if not isinstance(instructions, list) or not instructions:
        return None
    returns = [
        _mapping(raw)
        for raw in instructions
        if str(_mapping(raw).get("mnemonic") or "").lower().startswith("ret")
    ]
    if len(returns) != 1:
        return None
    operands = returns[0].get("operands")
    if not isinstance(operands, list):
        return None
    if not operands:
        return 0
    if len(operands) != 1:
        return None
    operand = _mapping(operands[0])
    if operand.get("kind") not in {"immediate", None}:
        return None
    immediate = _integer(operand.get("value"))
    return immediate if immediate is not None and 0 <= immediate <= 0xFFFF else None


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
        # States are replaced, never mutated in place. Sharing the first
        # contribution avoids copying every register, memory fact, version,
        # and stack witness once per newly reached edge.
        states[target] = contribution
        return True
    if prior is contribution:
        return False
    changed = False
    registers: dict[str, _Value] = {}
    for register in _REGISTERS:
        joined = _join_value(
            prior.registers.get(register),
            contribution.registers.get(register),
            value_budget,
        )
        registers[register] = joined
        changed = changed or joined != prior.registers.get(register)
    if (
        prior.memory is contribution.memory
        or prior.memory == contribution.memory
    ):
        memory = prior.memory
    else:
        memory = {}
        # Join order cannot affect the lattice result. Canonical ordering
        # belongs at artifact serialization, not in this hot path.
        for address in prior.memory.keys() | contribution.memory.keys():
            left_present = address in prior.memory
            right_present = address in contribution.memory
            left = prior.memory.get(address)
            right = contribution.memory.get(address)
            joined = (
                _join_value(left, right, value_budget)
                if left_present and right_present
                else None
            )
            memory[address] = joined
            changed = changed or not left_present or joined != left
    memory_over_budget = len(memory) > slot_budget
    if memory_over_budget:
        memory = {}
        changed = changed or bool(prior.memory)
    if prior.stack is contribution.stack or prior.stack == contribution.stack:
        stack = prior.stack
    else:
        stack = {}
        for offset in prior.stack.keys() & contribution.stack.keys():
            joined = _join_stack_cell(
                prior.stack[offset], contribution.stack[offset], value_budget
            )
            if joined is None:
                continue
            stack[offset] = joined
            changed = changed or joined != prior.stack[offset]
        changed = changed or len(stack) != len(prior.stack)
    if len(stack) > stack_slot_budget:
        stack = {}
        registers["esp"] = None
        changed = (
            changed
            or bool(prior.stack)
            or prior.registers.get("esp") is not None
        )
    memory_invalidated = (
        prior.memory_invalidated
        or contribution.memory_invalidated
        or memory_over_budget
    )
    changed = changed or memory_invalidated != prior.memory_invalidated
    if not changed:
        return False
    joined_state = _State(
        registers,
        memory,
        stack,
        memory_invalidated,
    )
    states[target] = joined_state
    return True


def _join_value(
    left: _Value,
    right: _Value,
    budget: int,
    *,
    missing_is_identity: bool = False,
) -> _Value:
    if left is right:
        return left
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
    if left is right or left == right:
        return left
    value = _join_value(left.value, right.value, budget)
    if value is None:
        return None
    witnesses = tuple(sorted(set(left.witnesses) | set(right.witnesses)))
    return _StackCell(value, witnesses) if len(witnesses) <= budget else None


def _merge_slot_facts(
    left: Mapping[_MemoryLocation, _Value],
    right: Mapping[_MemoryLocation, _Value],
    value_budget: int,
    slot_budget: int,
) -> dict[_MemoryLocation, _Value] | None:
    result = dict(left)
    for address, origins in right.items():
        result[address] = (
            _join_value(result[address], origins, value_budget)
            if address in result
            else origins
        )
    return result if len(result) <= slot_budget else None


def _persistent_origin(origin: _Origin) -> bool:
    return is_persistent_origin(origin)


def _has_global_slot_authority_dependency(value: _Value) -> bool:
    prefix = "hybrid-authority-v2:global_slot_invariant:"
    return value is not None and any(
        dependency.startswith(prefix)
        for origin in value
        for dependency in origin.dependencies
    )


def _refine_state_for_guard(
    state: _State,
    guard: Mapping[str, Any],
    *,
    inventory: _ProfileInventory | None = None,
    known_slots: Mapping[_MemoryLocation, _Value] | None = None,
    finite_value_budget: int = 32,
) -> _State | None:
    if inventory is not None:
        truth = _finite_guard_truth(
            guard,
            state=state,
            inventory=inventory,
            known_slots=known_slots or {},
            budget=finite_value_budget,
        )
        if truth is False:
            return None
        if truth is True:
            return state
    relational = _refine_relational_register_guard(state, guard)
    if relational is not state:
        return relational
    constraint = _guard_constraint(guard)
    if constraint is None:
        return state
    register, _relation, _value, _mask = constraint
    registers = {
        name: _refine_guarded_value(origins, constraint, constrain_exact=name == register)
        for name, origins in state.registers.items()
    }
    if state.registers.get(register) is not None and registers[register] is None:
        return None
    memory = {
        address: _refine_guarded_value(value, constraint)
        for address, value in state.memory.items()
    }
    stack = {
        offset: _StackCell(refined, cell.witnesses)
        for offset, cell in state.stack.items()
        if (refined := _refine_guarded_value(cell.value, constraint)) is not None
    }
    return _State(
        registers,
        memory,
        stack,
        state.memory_invalidated,
    )


def _guard_in_post_state(
    unit: Mapping[str, Any], guard: Mapping[str, Any]
) -> Mapping[str, Any]:
    """Rewrite exact terminal expressions to their post-state registers."""

    raw_writes = _mapping(unit.get("semantics")).get("register_writes")
    if not isinstance(raw_writes, list):
        return guard
    by_expression: dict[str, str | None] = {}
    for raw in raw_writes:
        row = _mapping(raw)
        register = row.get("register")
        value = row.get("value")
        if not isinstance(register, str) or not isinstance(value, Mapping):
            continue
        key = json.dumps(value, sort_keys=True, separators=(",", ":"))
        normalized = register.lower()
        prior = by_expression.get(key)
        by_expression[key] = normalized if prior in {None, normalized} else ""
    if not by_expression:
        return guard

    def rewrite(value: Any) -> Any:
        if isinstance(value, list):
            return [rewrite(child) for child in value]
        if not isinstance(value, Mapping):
            return copy.deepcopy(value)
        key = json.dumps(value, sort_keys=True, separators=(",", ":"))
        register = by_expression.get(key)
        if register:
            return {"op": "reg", "name": register, "width": 32}
        result = {str(name): rewrite(child) for name, child in value.items()}
        arguments = result.get("args")
        if (
            str(result.get("op") or "").lower() in {"and", "and32", "bit_and"}
            and isinstance(arguments, list)
            and len(arguments) == 2
            and arguments[0] == arguments[1]
        ):
            return arguments[0]
        return result

    rewritten = rewrite(guard)
    return rewritten if isinstance(rewritten, Mapping) else guard


def _finite_guard_truth(
    guard: Mapping[str, Any],
    *,
    state: _State,
    inventory: _ProfileInventory,
    known_slots: Mapping[_MemoryLocation, _Value],
    budget: int,
) -> bool | None:
    op = str(guard.get("op") or "").lower()
    if op in {"true", "always"}:
        return True
    if op in {"false", "never"}:
        return False
    arguments = guard.get("args")
    if (
        op in {"not", "logical_not"}
        and isinstance(arguments, list)
        and len(arguments) == 1
        and isinstance(arguments[0], Mapping)
    ):
        nested = _finite_guard_truth(
            arguments[0],
            state=state,
            inventory=inventory,
            known_slots=known_slots,
            budget=budget,
        )
        return None if nested is None else not nested
    comparison = _comparison_operands(guard)
    if comparison is None:
        return None
    relation, left_expression, right_expression = comparison
    left = _evaluate(
        left_expression,
        state,
        inventory=inventory,
        known_slots=known_slots,
        budget=budget,
    )
    right = _evaluate(
        right_expression,
        state,
        inventory=inventory,
        known_slots=known_slots,
        budget=budget,
    )
    left_values = _concrete_values(left)
    right_values = _concrete_values(right)
    if (
        left_values is None
        or right_values is None
        or len(left_values) * len(right_values) > budget
    ):
        return None
    outcomes = {
        _compare_u32(lhs, rhs, relation)
        for lhs in left_values
        for rhs in right_values
    }
    return next(iter(outcomes)) if len(outcomes) == 1 else None


def _refine_relational_register_guard(
    state: _State, guard: Mapping[str, Any]
) -> _State | None:
    comparison = _comparison_operands(guard)
    if comparison is None:
        return state
    relation, left_expression, right_expression = comparison
    left = _affine_guard_term(left_expression)
    right = _affine_guard_term(right_expression)
    if left is None or right is None or (left[0] is None and right[0] is None):
        return state
    registers = {value for value in (left[0], right[0]) if value is not None}
    origins_by_register: dict[str, tuple[tuple[_Origin, int], ...]] = {}
    for register in registers:
        value = state.registers.get(register)
        concrete = _concrete_origins(value)
        if concrete is None:
            return state
        origins_by_register[register] = concrete

    assignments: list[dict[str, tuple[_Origin, int]]] = []
    if left[0] is not None and right[0] == left[0]:
        assignments = [
            {left[0]: pair} for pair in origins_by_register[left[0]]
        ]
    elif left[0] is not None and right[0] is not None:
        assignments = [
            {left[0]: lhs, right[0]: rhs}
            for lhs in origins_by_register[left[0]]
            for rhs in origins_by_register[right[0]]
        ]
    else:
        register = left[0] or right[0]
        assert register is not None
        assignments = [{register: pair} for pair in origins_by_register[register]]

    accepted: list[dict[str, tuple[_Origin, int]]] = []
    for assignment in assignments:
        lhs = (
            left[1]
            if left[0] is None
            else assignment[left[0]][1] + left[1]
        ) & 0xFFFFFFFF
        rhs = (
            right[1]
            if right[0] is None
            else assignment[right[0]][1] + right[1]
        ) & 0xFFFFFFFF
        if _compare_u32(lhs, rhs, relation):
            accepted.append(assignment)
    if not accepted:
        return None
    selected = dict(state.registers)
    changed = False
    for register in registers:
        kept = frozenset(
            assignment[register][0]
            for assignment in accepted
            if register in assignment
        )
        if kept != selected.get(register):
            selected[register] = kept
            changed = True
    return (
        _State(selected, state.memory, state.stack, state.memory_invalidated)
        if changed
        else state
    )


def _comparison_operands(
    guard: Mapping[str, Any], *, polarity: bool = True
) -> tuple[str, Any, Any] | None:
    op = str(guard.get("op") or "").lower()
    arguments = guard.get("args")
    if (
        op in {"not", "logical_not"}
        and isinstance(arguments, list)
        and len(arguments) == 1
        and isinstance(arguments[0], Mapping)
    ):
        return _comparison_operands(arguments[0], polarity=not polarity)
    relations = {
        "eq": "eq", "eq32": "eq", "equal": "eq",
        "ne": "ne", "ne32": "ne", "not_equal": "ne",
        "ult": "ult", "ult32": "ult", "unsigned_less_than": "ult",
        "ule": "ule", "ule32": "ule",
        "ugt": "ugt", "ugt32": "ugt",
        "uge": "uge", "uge32": "uge",
        "slt": "slt", "slt32": "slt", "signed_less_than": "slt",
        "sle": "sle", "sle32": "sle",
        "sgt": "sgt", "sgt32": "sgt",
        "sge": "sge", "sge32": "sge",
    }
    relation = relations.get(op)
    operands = _binary_operands(guard)
    if relation is None or operands is None:
        return None
    inverse = {
        "eq": "ne", "ne": "eq",
        "ult": "uge", "ule": "ugt", "ugt": "ule", "uge": "ult",
        "slt": "sge", "sle": "sgt", "sgt": "sle", "sge": "slt",
    }
    return (relation if polarity else inverse[relation], operands[0], operands[1])


def _affine_guard_term(expression: Any) -> tuple[str | None, int] | None:
    row = _mapping(expression)
    if str(row.get("op") or "").lower() in {"const", "constant"}:
        value = _integer(row.get("value"))
        return None if value is None else (None, value & 0xFFFFFFFF)
    matches = [
        (register, offset)
        for register in _REGISTERS
        if (offset := affine_register_offset(expression, register)) is not None
    ]
    return matches[0] if len(matches) == 1 else None


def _concrete_values(value: _Value) -> tuple[int, ...] | None:
    pairs = _concrete_origins(value)
    return None if pairs is None else tuple(pair[1] for pair in pairs)


def _compare_u32(left: int, right: int, relation: str) -> bool:
    left &= 0xFFFFFFFF
    right &= 0xFFFFFFFF
    if relation == "eq":
        return left == right
    if relation == "ne":
        return left != right
    if relation == "ult":
        return left < right
    if relation == "ule":
        return left <= right
    if relation == "ugt":
        return left > right
    if relation == "uge":
        return left >= right
    signed_left = left - 0x100000000 if left & 0x80000000 else left
    signed_right = right - 0x100000000 if right & 0x80000000 else right
    if relation == "slt":
        return signed_left < signed_right
    if relation == "sle":
        return signed_left <= signed_right
    if relation == "sgt":
        return signed_left > signed_right
    if relation == "sge":
        return signed_left >= signed_right
    raise ValueError(f"unsupported comparison relation {relation!r}")


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
        if constrain_exact:
            concrete = origin_concrete_value(origin)
            if concrete is not None and not _constraint_accepts(
                concrete, constraint
            ):
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
            state.memory_invalidated = True
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
            state.memory_invalidated = True
            state.stack.clear()


def _unknown_state() -> _State:
    return _State(
        {register: None for register in _REGISTERS},
        {},
        {},
        memory_invalidated=True,
    )


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


def _selected_site_import_abi(
    event: Mapping[str, Any],
) -> SelectedImportABI | None:
    if event.get("kind") != "external_call":
        return None
    identity = _event_import_identity(event)
    contract = event.get("abi_contract")
    if identity is None or not isinstance(contract, Mapping):
        return None
    abi = resolve_machine_call_abi(contract.get("template"))
    argument_words = _integer(contract.get("argument_words"))
    binding = contract.get("profile_binding")
    if (
        abi is None
        or argument_words is None
        or not 0 <= argument_words <= 64
        or not isinstance(binding, Mapping)
    ):
        return None
    profile_id = binding.get("profile_id", binding.get("id"))
    profile_sha256 = binding.get("profile_sha256", binding.get("sha256"))
    entry_key = binding.get("entry_key")
    entry_index = _integer(binding.get("entry_index"))
    if (
        not isinstance(profile_id, str)
        or not profile_id
        or not isinstance(profile_sha256, str)
        or len(profile_sha256) != 64
        or any(character not in "0123456789abcdef" for character in profile_sha256)
        or not isinstance(entry_key, str)
        or not entry_key
        or entry_index is None
        or entry_index < 0
    ):
        return None
    return SelectedImportABI(
        identity=identity,
        abi=abi,
        profile_id=profile_id,
        profile_sha256=profile_sha256,
        entry_key=entry_key,
        entry_index=entry_index,
        argument_words=argument_words,
    )


def _merge_import_abi_evidence(
    selected: Mapping[MachineImportIdentity, SelectedImportABI],
    observed: Mapping[MachineImportIdentity, SelectedImportABI],
) -> dict[MachineImportIdentity, SelectedImportABI]:
    result = dict(selected)
    for identity, site in observed.items():
        prior = result.get(identity)
        if prior is None:
            result[identity] = site
            continue
        if prior.abi != site.abi:
            raise ValueError(f"import ABI evidence conflicts for {identity}")
        if (
            prior.argument_words is not None
            and prior.argument_words != site.argument_words
        ):
            raise ValueError(f"import arity evidence conflicts for {identity}")
        if prior.argument_words is None:
            result[identity] = site
    return result


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


def _read_memory_fact(
    state: _State,
    location: _MemoryLocation,
    *,
    known_slots: Mapping[_MemoryLocation, _Value],
) -> _Value:
    if location in state.memory:
        return state.memory[location]
    if state.memory_invalidated:
        return None
    return known_slots.get(location)


def _memory_location_sort_key(location: _MemoryLocation) -> tuple[int, str]:
    if isinstance(location, int):
        return 0, f"{location & 0xFFFFFFFF:08x}"
    return 1, json.dumps(
        location.as_json(), sort_keys=True, separators=(",", ":")
    )


def _signed_u32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _binary_operands(expression: Mapping[str, Any]) -> tuple[Any, Any] | None:
    operands = _arithmetic_operands(expression, associative=False)
    return None if operands is None else (operands[0], operands[1])


def _arithmetic_operands(
    expression: Mapping[str, Any], *, associative: bool
) -> tuple[Any, ...] | None:
    arguments = expression.get("args")
    if (
        isinstance(arguments, Sequence)
        and not isinstance(arguments, (str, bytes))
        and len(arguments) >= 2
        and (associative or len(arguments) == 2)
    ):
        return tuple(arguments)
    if "left" in expression and "right" in expression:
        return expression["left"], expression["right"]
    return None


def _unary_operand(expression: Mapping[str, Any]) -> Any | None:
    arguments = expression.get("args")
    if (
        isinstance(arguments, Sequence)
        and not isinstance(arguments, (str, bytes))
        and len(arguments) == 1
    ):
        return arguments[0]
    if "value" in expression:
        return expression["value"]
    if "arg" in expression:
        return expression["arg"]
    return None


def _origins_json(origins: _Value) -> list[dict[str, Any]]:
    if origins is None:
        return []
    return [origin.as_json() for origin in sorted(origins)]


def _call_frame_dependency_id(
    source_unit_id: str, event_index: int, target_unit_id: str
) -> str:
    payload = json.dumps(
        [source_unit_id, event_index, target_unit_id],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return f"call-frame:{payload}"


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
