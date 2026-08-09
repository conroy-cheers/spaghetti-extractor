"""Joint fail-closed interprocedural analysis for static hybrid closure.

The existing call-summary and provenance engines are transfer adapters.  This
module gives their outputs one typed, immutable fixed-point domain and schedules
the resulting dependencies by strongly connected component.  Proposal seeds
may accelerate discovery, but only an unseeded cold replay can authorize the
result.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Callable, Hashable, Mapping, Sequence

from .analysis.interprocedural_lattice import (
    Bottom,
    Conflict,
    Exact,
    Finite,
    InterproceduralFact,
    MustPreservedRegisters,
    NoExactValue,
    ReturnBehavior,
    Taint,
    Top,
)
from .analysis.scc_worklist import SCCDecomposition, SCCWorklist, decompose_scc
from .analysis_schema_v2 import interprocedural_authority_signature_v2
from .address_expression_v2 import affine_register_offset, constant_u32
from .external_capabilities import CallableExternalProfile
from .external_interface_profiles import ExternalInterfaceProfile
from .external_operation_profiles import ExternalOperationProfile
from .import_abi import SelectedImportABI
from .authority_bindings_v2 import AuthorityDataError
from .authority_bindings_v2 import BinaryBinding
from .checked_memory_access_v2 import (
    prepare_checked_memory_access_facts_v2,
    seal_checked_memory_access_facts_v2,
)
from .authority_record_core_v2 import AuthorityStatus
from .global_slot_contract_v2 import GlobalSlotInvariant
from .indirect_target_dependency_v2 import (
    has_value_independent_target_set_v2,
)
from .interface_provenance import recover_external_interface_targets
from .internal_call_summaries import derive_internal_call_preservation_summaries
from .machine_import_profiles import MachineImportIdentity
from .provenance_domain import (
    PROVENANCE_KINDS,
    ValueOrigin,
    is_persistent_origin,
)
from .value_provenance import legacy_value_provenance_view


INTERPROCEDURAL_ANALYSIS_FORMAT = "stage-a-interprocedural-analysis-v2"

_REGISTER_UNIVERSE = frozenset(
    {"eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp"}
)


@dataclass(frozen=True, order=True)
class _TargetAlternative:
    kind: str
    identity: Hashable


@dataclass(frozen=True)
class _Influence:
    """Mutable image slots which may have supplied one machine value."""

    slot_rvas: frozenset[int] = frozenset()
    read_sites: frozenset[tuple[int, str, int]] = frozenset()
    unsafe: bool = False
    overflow: bool = False

    def join(self, other: "_Influence", *, maximum: int) -> "_Influence":
        slots = self.slot_rvas | other.slot_rvas
        sites = self.read_sites | other.read_sites
        overflow = (
            self.overflow
            or other.overflow
            or len(slots) > maximum
            or len(sites) > maximum
        )
        return _Influence(
            slot_rvas=frozenset(sorted(slots)[:maximum]),
            read_sites=frozenset(sorted(sites)[:maximum]),
            unsafe=self.unsafe or other.unsafe or overflow,
            overflow=overflow,
        )


@dataclass(frozen=True)
class _MutableCell:
    value: _Influence
    initialized: bool = True
    tainted: bool = False

    def join(self, other: "_MutableCell", *, maximum: int) -> "_MutableCell":
        return _MutableCell(
            value=self.value.join(other.value, maximum=maximum),
            initialized=self.initialized and other.initialized,
            tainted=self.tainted or other.tainted,
        )


@dataclass(frozen=True)
class _MutableState:
    registers: tuple[tuple[str, _Influence], ...]
    memory: tuple[tuple[int, _MutableCell], ...] = ()
    unknown_write: bool = False


@dataclass(frozen=True)
class _MutableExitInfluence:
    slot_rvas: tuple[int, ...]
    read_sites: tuple[tuple[int, str, int], ...]
    unsafe: bool
    overflow: bool


@dataclass(frozen=True)
class _NodeState:
    """One immutable abstract fact plus its latest diagnostic disposition."""

    fact: InterproceduralFact[_TargetAlternative, Hashable, Hashable, str]
    status: str
    failure_reasons: tuple[str, ...] = ()

    def join(self, other: "_NodeState", *, maximum: int) -> "_NodeState":
        joined = self.fact.join(other.fact, maximum=maximum)
        return _NodeState(
            fact=joined,
            status=_joined_status(self.status, other.status, joined.complete),
            failure_reasons=tuple(
                sorted(set(self.failure_reasons) | set(other.failure_reasons))
            ),
        )


@dataclass(frozen=True)
class _PassResult:
    converged: bool
    evaluations: int
    scc_evaluations: int
    facts: Mapping[str, _NodeState]
    dependency_edges: frozenset[tuple[str, str]]
    decomposition: SCCDecomposition[str]
    summaries: Mapping[str, Any]
    operation_provenance: Mapping[str, Any]
    value_provenance: Mapping[str, Any]
    recoveries: tuple[Mapping[str, Any], ...]
    roots: tuple[str, ...]

    @property
    def lattice_complete(self) -> bool:
        return all(
            state.status == "complete" and state.fact.complete
            for state in self.facts.values()
        )


@dataclass(frozen=True)
class InterproceduralAnalysisResult:
    value_provenance: Mapping[str, Any]
    operation_provenance: Mapping[str, Any]
    call_summaries: Mapping[str, Any]
    recovered_targets: tuple[Mapping[str, Any], ...]
    fixed_point: Mapping[str, Any]
    proposal_artifacts: Mapping[str, Any]

    @property
    def complete(self) -> bool:
        return (
            self.fixed_point.get("status") == "complete"
            and self.fixed_point.get("cold_replay_validated") is True
        )


def analyze_interprocedural_control(
    *,
    units: Sequence[Mapping[str, Any]],
    roots: Sequence[str],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    static_recoveries: Sequence[Mapping[str, Any]],
    static_recovery_authority: str = "untrusted_input",
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    imports: Sequence[Mapping[str, Any]],
    image_base: int,
    pe_sha256: str | None = None,
    machine_ir_sha256: str | None = None,
    static_data_reader: Callable[[int, int], bytes | None] | None,
    proposal_static_data_reader: Callable[[int, int], bytes | None] | None = None,
    image_size: int | None = None,
    writable_image_ranges: Sequence[tuple[int, int]] = (),
    interface_profiles: Sequence[ExternalInterfaceProfile] = (),
    operation_profiles: Sequence[ExternalOperationProfile] = (),
    callable_profiles: Sequence[CallableExternalProfile] = (),
    internal_function_contracts: Mapping[str, Mapping[str, Any]] | None = None,
    proposal_recoveries: Sequence[Mapping[str, Any]] = (),
    inductive_hypothesis_recoveries: Sequence[Mapping[str, Any]] = (),
    global_slot_invariants: Sequence[
        GlobalSlotInvariant | Mapping[str, Any]
    ] = (),
    checked_stack_entry_offsets: Mapping[str, Sequence[int]] | None = None,
    checked_nonimage_stack_units: Sequence[str] = (),
    finite_value_budget: int = 32,
    max_rounds: int | None = None,
    proposal_only: bool = False,
    authority_only: bool = False,
) -> InterproceduralAnalysisResult:
    """Compute summaries and targets together, then reproduce them cold.

    The transfer adapters are still proposal logic.  Convergence is over the
    typed product facts and their dependency graph, never serialized JSON.
    Writable-slot promotion is disabled in both passes.  Complete mutable-slot
    invariants are dependencies of point-sensitive recoveries; they are never
    copied into the entry state of every root.
    """

    if finite_value_budget <= 0:
        raise ValueError("finite_value_budget must be positive")
    if proposal_only and authority_only:
        raise ValueError("proposal_only and authority_only are mutually exclusive")
    if (pe_sha256 is None) != (machine_ir_sha256 is None):
        raise ValueError(
            "interprocedural memory-access authority requires both binary digests"
        )
    if static_recovery_authority not in {
        "exact_pe_replay_v2",
        "untrusted_input",
    }:
        raise ValueError("static recovery authority is unsupported")
    unit_ids = tuple(_unit_id(unit) for unit in units)
    if len(set(unit_ids)) != len(unit_ids):
        raise ValueError("interprocedural analysis requires unique unit IDs")
    if not set(roots) <= set(unit_ids):
        raise ValueError("interprocedural roots reference unknown units")
    exit_ids = tuple(_required_string(row, "id") for row in indirect_exits)
    if len(set(exit_ids)) != len(exit_ids):
        raise ValueError("interprocedural analysis requires unique exit IDs")

    # The explicit bound is a resource limit, not a claimed lattice height.
    # Default capacity allows every finite target and every analysis node to be
    # discovered, then requires one additional stability evaluation.
    node_capacity = len(unit_ids) + len(exit_ids) + 1
    evaluation_budget = (
        max(4, 2 * node_capacity * (finite_value_budget + 2))
        if max_rounds is None
        else max_rounds
    )
    if evaluation_budget <= 0:
        raise ValueError("interprocedural fixed-point budget must be positive")
    normalized_image_size = (
        (1 << 32) - image_base if image_size is None else image_size
    )
    normalized_global_slots = _normalize_global_slot_invariants(
        global_slot_invariants
    )
    normalized_writable_ranges = _normalize_writable_image_ranges(
        writable_image_ranges
    )

    discovery = None if authority_only else _run_typed_pass(
        units=units,
        roots=roots,
        direct_edges=direct_edges,
        internal_call_edges=internal_call_edges,
        indirect_exits=indirect_exits,
        static_recoveries=static_recoveries,
        import_abis=import_abis,
        imports=imports,
        image_base=image_base,
        image_size=normalized_image_size,
        static_data_reader=(proposal_static_data_reader or static_data_reader),
        interface_profiles=interface_profiles,
        operation_profiles=operation_profiles,
        callable_profiles=callable_profiles,
        internal_function_contracts=internal_function_contracts or {},
        finite_value_budget=finite_value_budget,
        max_evaluations=evaluation_budget,
        initial_recoveries=proposal_recoveries,
        global_slot_invariants=normalized_global_slots,
        checked_stack_entry_offsets=checked_stack_entry_offsets or {},
        checked_nonimage_stack_units=frozenset(checked_nonimage_stack_units),
        writable_image_ranges=normalized_writable_ranges,
        allow_bootstrap=True,
    )
    cold = None if proposal_only else _run_typed_pass(
        units=units,
        roots=roots,
        direct_edges=direct_edges,
        internal_call_edges=internal_call_edges,
        indirect_exits=indirect_exits,
        static_recoveries=static_recoveries,
        import_abis=import_abis,
        imports=imports,
        image_base=image_base,
        image_size=normalized_image_size,
        static_data_reader=static_data_reader,
        interface_profiles=interface_profiles,
        operation_profiles=operation_profiles,
        callable_profiles=callable_profiles,
        internal_function_contracts=internal_function_contracts or {},
        finite_value_budget=finite_value_budget,
        max_evaluations=evaluation_budget,
        initial_recoveries=(),
        global_slot_invariants=normalized_global_slots,
        checked_stack_entry_offsets=checked_stack_entry_offsets or {},
        checked_nonimage_stack_units=frozenset(checked_nonimage_stack_units),
        writable_image_ranges=normalized_writable_ranges,
        allow_bootstrap=False,
    )
    inductive_required = bool(
        not proposal_only
        and cold is not None
        and inductive_hypothesis_recoveries
        and _requires_inductive_replay(
            units=units,
            roots=roots,
            direct_edges=direct_edges,
            internal_call_edges=internal_call_edges,
            indirect_exits=indirect_exits,
            summaries=cold.summaries,
            hypotheses=inductive_hypothesis_recoveries,
        )
    )
    effective_hypotheses = (
        inductive_hypothesis_recoveries if inductive_required else ()
    )
    inductive = (
        None
        if not inductive_required
        else _run_typed_pass(
            units=units,
            roots=roots,
            direct_edges=direct_edges,
            internal_call_edges=internal_call_edges,
            indirect_exits=indirect_exits,
            static_recoveries=static_recoveries,
            import_abis=import_abis,
            imports=imports,
            image_base=image_base,
            image_size=normalized_image_size,
            static_data_reader=static_data_reader,
            interface_profiles=interface_profiles,
            operation_profiles=operation_profiles,
            callable_profiles=callable_profiles,
            internal_function_contracts=internal_function_contracts or {},
            finite_value_budget=finite_value_budget,
            max_evaluations=evaluation_budget,
            initial_recoveries=effective_hypotheses,
            global_slot_invariants=normalized_global_slots,
            checked_stack_entry_offsets=checked_stack_entry_offsets or {},
            checked_nonimage_stack_units=frozenset(
                checked_nonimage_stack_units
            ),
            writable_image_ranges=normalized_writable_ranges,
            allow_bootstrap=False,
        )
    )

    if discovery is None and cold is None:
        raise AssertionError("interprocedural analysis produced no pass")
    inductive_reproduction = _inductive_reproduction_status(
        hypotheses=effective_hypotheses,
        replay=inductive,
    )
    inductive_selection = _select_inductive_authority(
        cold=cold,
        replay=inductive,
        hypotheses=effective_hypotheses,
        reproduction=inductive_reproduction,
    )
    inductive_validated = bool(
        inductive is not None
        and inductive.converged
        and set(inductive_selection["accepted_nodes"])
        & {
            str(row.get("id"))
            for row in inductive_hypothesis_recoveries
            if isinstance(row, Mapping)
            and isinstance(row.get("id"), str)
            and row.get("status") == "recovered"
        }
    )
    authority_pass = (
        discovery
        if cold is None
        else inductive_selection["authority_pass"]
    )
    assert authority_pass is not None
    same_facts = (
        None
        if discovery is None or cold is None
        else discovery.facts == cold.facts
    )
    same_dependencies = (
        None
        if discovery is None or cold is None
        else discovery.dependency_edges == cold.dependency_edges
    )
    same_roots = (
        None
        if discovery is None or cold is None
        else discovery.roots == cold.roots
    )
    discovery_signature = None if discovery is None else _pass_signature(discovery)
    cold_replay_signature = None if cold is None else _pass_signature(cold)
    # Proposal discovery is an optimization and diagnostic oracle.  The
    # unseeded pass is authoritative even when it legitimately differs from a
    # stale or over-approximating proposal inventory.
    cold_validated = bool(cold is not None and cold.converged)
    authority_replay_validated = cold_validated and (
        inductive is None or inductive.converged
    )
    lattice_complete = authority_pass.lattice_complete
    reachable_targets_complete = _reachable_targets_complete(
        units=units,
        roots=authority_pass.roots,
        direct_edges=direct_edges,
        internal_call_edges=internal_call_edges,
        indirect_exits=indirect_exits,
        recoveries=authority_pass.recoveries,
    )
    status = (
        "complete"
        if not proposal_only
        and authority_replay_validated
        and lattice_complete
        and reachable_targets_complete
        else "incomplete"
    )
    failures = (
        ["proposal_only_non_authorizing"]
        if proposal_only
        else _fixed_point_failures(
            cold_converged=authority_replay_validated,
            lattice_complete=lattice_complete,
            reachable_targets_complete=reachable_targets_complete,
        )
    )
    dependency_inventory = _dependency_inventory(
        facts=authority_pass.facts,
        dependency_edges=authority_pass.dependency_edges,
        decomposition=authority_pass.decomposition,
    )
    authorizing_recoveries = _apply_lattice_failures(
        authority_pass.recoveries,
        authority_pass.facts,
        finite_value_budget=finite_value_budget,
    )
    access_proposals = authority_pass.operation_provenance.get(
        "memory_access_proposals", []
    )
    if not isinstance(access_proposals, list) or any(
        not isinstance(row, Mapping) for row in access_proposals
    ):
        raise ValueError("interprocedural memory-access proposal inventory is invalid")
    prepared_memory_access_facts = (
        ()
        if pe_sha256 is None or machine_ir_sha256 is None
        else prepare_checked_memory_access_facts_v2(
            access_proposals,
            units=units,
            binary=BinaryBinding(
                pe_sha256=pe_sha256,
                machine_ir_sha256=machine_ir_sha256,
            ),
        )
    )
    authority_artifact_sha256 = interprocedural_authority_signature_v2(
        root_unit_ids=authority_pass.roots,
        dependency_inventory=dependency_inventory,
        call_summaries=authority_pass.summaries,
        recovered_targets=authorizing_recoveries,
        memory_access_facts=prepared_memory_access_facts,
    )
    checked_memory_access_facts = seal_checked_memory_access_facts_v2(
        prepared_memory_access_facts,
        interprocedural_authority_sha256=authority_artifact_sha256,
    )
    operation_provenance = copy.deepcopy(
        dict(authority_pass.operation_provenance)
    )
    operation_provenance.pop("memory_access_proposals", None)
    operation_provenance["checked_memory_access_facts"] = list(
        checked_memory_access_facts
    )
    fixed_point = {
        "format": INTERPROCEDURAL_ANALYSIS_FORMAT,
        "status": status,
        "rounds": (0 if discovery is None else discovery.evaluations) + (
            0 if cold is None else cold.evaluations
        ) + (0 if inductive is None else inductive.evaluations),
        "discovery_rounds": 0 if discovery is None else discovery.evaluations,
        "cold_replay_rounds": 0 if cold is None else cold.evaluations,
        "scc_evaluations": (0 if discovery is None else discovery.scc_evaluations) + (
            0 if cold is None else cold.scc_evaluations
        ) + (0 if inductive is None else inductive.scc_evaluations),
        "cold_replay_validated": cold_validated,
        "authority_replay_validated": authority_replay_validated,
        "cold_initial_recoveries_empty": cold is not None,
        "inductive_replay": {
            **inductive_reproduction,
            "required": inductive_required,
            "executed": inductive is not None,
            "skipped_reason": (
                None
                if inductive_required
                else "no_recursive_hypothesis_scc"
                if inductive_hypothesis_recoveries
                else "no_hypotheses"
            ),
            "converged": inductive is not None and inductive.converged,
            "signature": (
                None if inductive is None else _pass_signature(inductive)
            ),
            "hypothesis_count": sum(
                row.get("status") == "recovered"
                for row in inductive_hypothesis_recoveries
                if isinstance(row, Mapping)
            ),
            "proof_authority": inductive_validated,
            "all_hypotheses_reproduced": (
                inductive_reproduction["status"] in {"complete", "not_applicable"}
            ),
            "accepted_nodes": list(inductive_selection["accepted_nodes"]),
            "accepted_sccs": list(inductive_selection["accepted_sccs"]),
            "rejected_nodes": list(inductive_selection["rejected_nodes"]),
        },
        "proposal_only": proposal_only,
        "authority_only": authority_only,
        "static_recovery_authority": static_recovery_authority,
        "static_recovery_authority_seeded": (
            static_recovery_authority != "exact_pe_replay_v2"
            and any(row.get("status") == "recovered" for row in static_recoveries)
        ),
        "discovery_signature": discovery_signature,
        "cold_replay_signature": cold_replay_signature,
        "authority_artifact_sha256": authority_artifact_sha256,
        "proposal_seed_count": len(proposal_recoveries),
        "root_unit_ids": list(authority_pass.roots),
        "callback_root_count": len(set(authority_pass.roots) - set(roots)),
        "global_slot_promotion": False,
        "mutable_slot_handoff": "point_sensitive_dependency_v2",
        "finite_value_budget": finite_value_budget,
        "round_bound": evaluation_budget,
        "round_bound_kind": "transfer_evaluation_resource_limit",
        "typed_fact_count": len(authority_pass.facts),
        "checked_memory_access_fact_count": len(checked_memory_access_facts),
        "reachable_targets_complete": reachable_targets_complete,
        "dependency_edge_count": len(authority_pass.dependency_edges),
        "scc_count": len(authority_pass.decomposition.components),
        "recursive_sccs": _recursive_components(
            authority_pass.decomposition, authority_pass.dependency_edges
        ),
        "recursive_summary_roots": list(
            authority_pass.summaries.get("recursive_summary_roots", [])
        ),
        "dependencies": dependency_inventory,
        "failure_reasons": failures,
        "proposal_diagnostics": {
            "discovery_executed": discovery is not None,
            "same_authorizing_facts": same_facts,
            "same_dependency_graph": same_dependencies,
            "same_callback_roots": same_roots,
            "agreement_required": False,
        },
    }
    return InterproceduralAnalysisResult(
        value_provenance=authority_pass.value_provenance,
        operation_provenance=operation_provenance,
        call_summaries=authority_pass.summaries,
        recovered_targets=authorizing_recoveries,
        fixed_point=fixed_point,
        proposal_artifacts={
            "proof_authority": False,
            "recoveries": [
                copy.deepcopy(dict(row))
                for row in (
                    proposal_recoveries
                    if discovery is None
                    else discovery.recoveries
                )
            ],
            "signature": discovery_signature,
        },
    )


def _pass_signature(result: _PassResult) -> str:
    """Bind the complete typed fixed point and dependency graph canonically."""

    payload = {
        "roots": list(result.roots),
        "facts": [
            {
                "id": node_id,
                "status": state.status,
                "failure_reasons": list(state.failure_reasons),
                "fact": state.fact.project(),
            }
            for node_id, state in sorted(result.facts.items())
        ],
        "dependency_edges": [
            [dependency, dependent]
            for dependency, dependent in sorted(result.dependency_edges)
        ],
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _select_inductive_authority(
    *,
    cold: _PassResult | None,
    replay: _PassResult | None,
    hypotheses: Sequence[Mapping[str, Any]],
    reproduction: Mapping[str, Any],
) -> dict[str, Any]:
    """Select independently closed replay SCCs without global all-or-nothing loss.

    The inductive pass may expose finite target edges as hypotheses.  Its
    monotone fact table therefore cannot by itself distinguish a reproduced
    fact from a stale first-round seed.  Eligibility is taken from the final
    adapter outputs, and hypothesized exits additionally require exact target
    and origin-witness reproduction.  Provider-to-consumer dependencies then
    select the greatest closed set over cold-complete facts and simultaneous
    replay SCCs.
    """

    empty = {
        "authority_pass": cold,
        "accepted_nodes": (),
        "accepted_sccs": (),
        "rejected_nodes": (),
    }
    if cold is None or replay is None or not replay.converged:
        return empty

    hypothesis_ids = {
        str(row.get("id"))
        for row in hypotheses
        if isinstance(row, Mapping)
        and isinstance(row.get("id"), str)
        and row.get("status") == "recovered"
    }
    reproduced_ids = {
        str(identity)
        for identity in reproduction.get("reproduced_ids", ())
        if isinstance(identity, str)
    }
    cold_complete = _complete_output_nodes(cold, require_origin_witnesses=False)
    replay_complete = _complete_output_nodes(replay, require_origin_witnesses=True)
    candidates = {
        node
        for node in replay_complete
        if node not in hypothesis_ids or node in reproduced_ids
    }
    incoming: dict[str, set[str]] = defaultdict(set)
    for dependency, dependent in replay.dependency_edges:
        incoming[dependent].add(dependency)

    accepted = set(candidates)
    while True:
        invalid = {
            node
            for node in accepted
            if any(
                dependency not in cold_complete and dependency not in accepted
                for dependency in incoming.get(node, ())
            )
        }
        if not invalid:
            break
        accepted.difference_update(invalid)

    promoted = {
        node
        for node in accepted
        if node not in cold_complete
        or replay.facts.get(node) != cold.facts.get(node)
    }
    if not promoted:
        return {
            **empty,
            "rejected_nodes": tuple(sorted(replay_complete - cold_complete)),
        }

    merged_facts = dict(cold.facts)
    for node in promoted:
        state = replay.facts.get(node)
        if state is not None:
            merged_facts[node] = state

    merged_recoveries = _merge_recovery_outputs(
        cold.recoveries,
        replay.recoveries,
        promoted,
    )
    merged_summaries = _merge_summary_outputs(
        cold.summaries,
        replay.summaries,
        promoted,
    )
    merged_edges = frozenset(
        set(cold.dependency_edges)
        | {
            edge
            for edge in replay.dependency_edges
            if edge[1] in promoted
        }
    )
    decomposition = decompose_scc(tuple(merged_facts), merged_edges)
    authority = _PassResult(
        converged=True,
        evaluations=cold.evaluations + replay.evaluations,
        scc_evaluations=cold.scc_evaluations + replay.scc_evaluations,
        facts=merged_facts,
        dependency_edges=merged_edges,
        decomposition=decomposition,
        summaries=merged_summaries,
        operation_provenance=cold.operation_provenance,
        value_provenance=cold.value_provenance,
        recoveries=merged_recoveries,
        # New callback roots require their own entry-state contracts and are
        # promoted by the launch/root phase, not by an inductive target seed.
        roots=cold.roots,
    )
    promoted_components = sorted({
        decomposition.component_index(node)
        for node in promoted
        if node in merged_facts
    })
    return {
        "authority_pass": authority,
        "accepted_nodes": tuple(sorted(promoted)),
        "accepted_sccs": tuple(
            {
                "scc_id": component_id,
                "nodes": list(decomposition.components[component_id]),
            }
            for component_id in promoted_components
        ),
        "rejected_nodes": tuple(sorted(replay_complete - accepted)),
    }


def _complete_output_nodes(
    result: _PassResult, *, require_origin_witnesses: bool
) -> set[str]:
    """Return final complete adapter outputs, excluding stale lattice seeds."""

    complete = {
        str(row.get("id"))
        for row in result.recoveries
        if isinstance(row, Mapping)
        and isinstance(row.get("id"), str)
        and row.get("status") == "recovered"
        and (
            not require_origin_witnesses
            or _has_inductive_origin_witnesses(row)
        )
    }
    for row in result.summaries.get("summaries", ()):
        if not isinstance(row, Mapping) or row.get("status") != "complete":
            continue
        unit_id = row.get("target_unit_id")
        if isinstance(unit_id, str):
            complete.add(_summary_node(unit_id))
    complete.update(
        node
        for node, state in result.facts.items()
        if node.startswith("hybrid-authority-v2:global_slot_invariant:")
        and state.status == "complete"
        and state.fact.complete
    )
    return complete


def _merge_recovery_outputs(
    cold: Sequence[Mapping[str, Any]],
    replay: Sequence[Mapping[str, Any]],
    promoted: set[str],
) -> tuple[Mapping[str, Any], ...]:
    replay_by_id = {
        str(row.get("id")): row
        for row in replay
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    return tuple(
        copy.deepcopy(
            dict(replay_by_id[identity])
            if identity in promoted and identity in replay_by_id
            else dict(row)
        )
        for row in cold
        for identity in (str(row.get("id")),)
    )


def _merge_summary_outputs(
    cold: Mapping[str, Any],
    replay: Mapping[str, Any],
    promoted: set[str],
) -> Mapping[str, Any]:
    replay_by_root = {
        str(row.get("target_unit_id")): row
        for row in replay.get("summaries", ())
        if isinstance(row, Mapping) and isinstance(row.get("target_unit_id"), str)
    }
    rows = [
        copy.deepcopy(
            dict(replay_by_root[root])
            if _summary_node(root) in promoted and root in replay_by_root
            else dict(row)
        )
        for row in cold.get("summaries", ())
        if isinstance(row, Mapping)
        for root in (str(row.get("target_unit_id")),)
    ]
    complete = sum(row.get("status") == "complete" for row in rows)
    result = copy.deepcopy(dict(cold))
    result["summaries"] = rows
    result["status"] = "complete" if complete == len(rows) else "incomplete"
    counts = result.get("counts")
    if isinstance(counts, Mapping):
        result["counts"] = {
            **copy.deepcopy(dict(counts)),
            "complete_summaries": complete,
            "incomplete_summaries": len(rows) - complete,
        }
    return result


def _requires_inductive_replay(
    *,
    units: Sequence[Mapping[str, Any]],
    roots: Sequence[str],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    summaries: Mapping[str, Any],
    hypotheses: Sequence[Mapping[str, Any]],
) -> bool:
    """Use simultaneous hypotheses only for an actual recursive dependency."""

    recovered = tuple(
        row
        for row in hypotheses
        if isinstance(row, Mapping) and row.get("status") == "recovered"
    )
    hypothesis_ids = {
        str(row.get("id"))
        for row in recovered
        if isinstance(row.get("id"), str)
    }
    if not hypothesis_ids:
        return False
    existing_summaries = [
        row
        for row in summaries.get("summaries", ())
        if isinstance(row, Mapping)
    ]
    existing_targets = {
        str(row.get("target_unit_id"))
        for row in existing_summaries
        if isinstance(row.get("target_unit_id"), str)
    }
    hypothesis_targets = {
        str(target)
        for row in recovered
        for target in row.get("target_unit_ids", ())
        if isinstance(target, str)
    }
    dependency_summaries = {
        **dict(summaries),
        "summaries": [
            *existing_summaries,
            *(
                {"target_unit_id": target}
                for target in sorted(hypothesis_targets - existing_targets)
            ),
        ],
    }
    edges = _derive_dependency_edges(
        units=units,
        roots=roots,
        direct_edges=direct_edges,
        internal_call_edges=internal_call_edges,
        indirect_exits=indirect_exits,
        summaries=dependency_summaries,
        recoveries=recovered,
    )
    nodes = {
        node for edge in edges for node in edge
    } | hypothesis_ids
    decomposition = decompose_scc(nodes, edges)
    return any(
        hypothesis_ids.intersection(component)
        for component in _recursive_components(decomposition, edges)
    )


def _run_typed_pass(
    *,
    units: Sequence[Mapping[str, Any]],
    roots: Sequence[str],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    static_recoveries: Sequence[Mapping[str, Any]],
    initial_recoveries: Sequence[Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    imports: Sequence[Mapping[str, Any]],
    image_base: int,
    image_size: int,
    static_data_reader: Callable[[int, int], bytes | None] | None,
    interface_profiles: Sequence[ExternalInterfaceProfile],
    operation_profiles: Sequence[ExternalOperationProfile],
    callable_profiles: Sequence[CallableExternalProfile],
    internal_function_contracts: Mapping[str, Mapping[str, Any]],
    finite_value_budget: int,
    max_evaluations: int,
    allow_bootstrap: bool,
    global_slot_invariants: Sequence[GlobalSlotInvariant],
    checked_stack_entry_offsets: Mapping[str, Sequence[int]],
    checked_nonimage_stack_units: frozenset[str],
    writable_image_ranges: tuple[tuple[int, int], ...],
) -> _PassResult:
    known_unit_ids = frozenset(_unit_id(unit) for unit in units)
    selected = _prefer_indirect_recoveries(
        static_recoveries, initial_recoveries
    )
    facts: dict[str, _NodeState] = {}
    dependency_edges: frozenset[tuple[str, str]] = frozenset()
    summaries: Mapping[str, Any] = {"summaries": []}
    operation_provenance: Mapping[str, Any] = {"resolutions": []}
    call_site_effects: tuple[Mapping[str, Any], ...] = ()
    value_provenance: Mapping[str, Any] = {"resolutions": []}
    scc_evaluations = 0
    decomposition: SCCDecomposition[str] = decompose_scc(tuple[str]())
    active_roots = set(roots)
    checked_global_slots = _global_slot_known_values(
        global_slot_invariants,
        image_base=image_base,
        finite_value_budget=finite_value_budget,
    )

    for evaluation in range(1, max_evaluations + 1):
        current_roots = tuple(sorted(active_roots))
        input_recoveries = _freeze_recovery_inputs(selected)
        input_call_site_effects = _freeze_call_site_effects(call_site_effects)
        summaries = derive_internal_call_preservation_summaries(
            units=units,
            roots=current_roots,
            direct_edges=direct_edges,
            internal_call_edges=internal_call_edges,
            recovered_indirect_targets=selected,
            indirect_exits=indirect_exits,
            import_abis=import_abis,
            call_site_effects=call_site_effects,
            # Reviewed source/RE contracts are discovery hints.  They have not
            # been replayed against the machine semantics, so allowing them in
            # the unseeded pass would turn an operator assertion into v2 call
            # authority.  Cold and inductive authority passes must derive the
            # same families from exact machine IR or remain incomplete.
            declared_summaries=(
                internal_function_contracts if allow_bootstrap else {}
            ),
            max_value_alternatives=finite_value_budget,
        )
        preserved, cleanup, results = _call_summary_inputs(
            summaries, image_base=image_base
        )
        memory_preservation = _call_summary_memory_preservation(
            summaries, image_base=image_base
        )
        call_memory_preservation = _call_site_memory_preservation(
            units=units,
            internal_call_edges=internal_call_edges,
            recoveries=selected,
            internal_memory_preservation=memory_preservation,
            import_abis=import_abis,
            image_base=image_base,
        )
        operation_provenance = recover_external_interface_targets(
            units=units,
            roots=current_roots,
            direct_edges=direct_edges,
            internal_call_edges=internal_call_edges,
            recovered_indirect_edges=selected,
            indirect_exits=indirect_exits,
            profiles=interface_profiles,
            operation_profiles=operation_profiles,
            callable_external_profiles=callable_profiles,
            imports=imports,
            import_abis=import_abis,
            internal_call_preserved_registers=preserved,
            internal_call_stack_cleanup=cleanup,
            internal_call_result_relations=results,
            internal_call_memory_preservation=memory_preservation,
            image_base=image_base,
            finite_value_budget=finite_value_budget,
            static_data_reader=static_data_reader,
            bootstrap_unknown_call_preserved_registers=(
                frozenset({"ebp", "ebx", "edi", "esi"})
                if allow_bootstrap and evaluation == 1
                else None
            ),
            allow_global_slot_promotion=False,
            initial_known_slots=checked_global_slots,
            checked_stack_entry_offsets=checked_stack_entry_offsets,
        )
        next_call_site_effects = _call_site_effect_rows(operation_provenance)
        next_roots = active_roots | _callback_root_unit_ids(
            operation_provenance, known_units=known_unit_ids
        )
        value_provenance = legacy_value_provenance_view(
            operation_provenance,
            finite_target_budget=finite_value_budget,
        )
        mutable_influence = _analyze_mutable_slot_influence(
            units=units,
            roots=current_roots,
            direct_edges=direct_edges,
            internal_call_edges=internal_call_edges,
            recovered_indirect_edges=selected,
            indirect_exits=indirect_exits,
            image_base=image_base,
            image_size=image_size,
            finite_value_budget=finite_value_budget,
            checked_nonimage_stack_units=checked_nonimage_stack_units,
            call_memory_preservation=call_memory_preservation,
            global_slot_invariants=global_slot_invariants,
        )
        next_selected = _prefer_indirect_recoveries(
            static_recoveries,
            value_provenance.get("resolutions", []),
            operation_provenance.get("resolutions", []),
        )
        next_selected = _bind_mutable_slot_dependencies(
            next_selected,
            exit_influence=mutable_influence,
            global_slot_invariants=global_slot_invariants,
            finite_value_budget=finite_value_budget,
            writable_image_ranges=writable_image_ranges,
            image_base=image_base,
        )
        used_global_slots = _used_global_slot_invariants(
            next_selected, global_slot_invariants
        )
        proposals = _typed_proposals(
            summaries=summaries,
            recoveries=next_selected,
            global_slot_invariants=used_global_slots,
            finite_value_budget=finite_value_budget,
        )
        proposed_edges = _derive_dependency_edges(
            units=units,
            roots=current_roots,
            direct_edges=direct_edges,
            internal_call_edges=internal_call_edges,
            indirect_exits=indirect_exits,
            summaries=summaries,
            recoveries=next_selected,
        )
        next_edges = dependency_edges | proposed_edges
        nodes = set(facts) | set(proposals)
        nodes.update(node for edge in next_edges for node in edge)
        worklist = SCCWorklist(nodes, next_edges)
        next_facts = dict(facts)
        while worklist:
            component = worklist.pop()
            scc_evaluations += 1
            for node in component:
                proposal = proposals.get(node)
                if proposal is None:
                    continue
                prior = next_facts.get(node)
                next_facts[node] = (
                    proposal
                    if prior is None
                    else prior.join(proposal, maximum=finite_value_budget)
                )
        decomposition = worklist.decomposition

        transfer_stable = _freeze_recovery_inputs(next_selected) == input_recoveries
        call_effects_stable = (
            _freeze_call_site_effects(next_call_site_effects)
            == input_call_site_effects
        )
        roots_stable = next_roots == active_roots
        facts = next_facts
        dependency_edges = next_edges
        selected = next_selected
        active_roots = next_roots
        # Proposals are a deterministic function of the frozen recovery inputs
        # and roots.  Once those inputs are stable, another whole-program
        # transfer would emit the same proposals; lattice joins and edge unions
        # are idempotent, so the state below is already the least fixed point.
        if transfer_stable and call_effects_stable and roots_stable:
            return _PassResult(
                True,
                evaluation,
                scc_evaluations,
                facts,
                dependency_edges,
                decomposition,
                summaries,
                operation_provenance,
                value_provenance,
                tuple(copy.deepcopy(row) for row in selected),
                tuple(sorted(active_roots)),
            )
        call_site_effects = next_call_site_effects

    return _PassResult(
        False,
        max_evaluations,
        scc_evaluations,
        facts,
        dependency_edges,
        decomposition,
        summaries,
        operation_provenance,
        value_provenance,
        tuple(copy.deepcopy(row) for row in selected),
        tuple(sorted(active_roots)),
    )


def _callback_root_unit_ids(
    operation_provenance: Mapping[str, Any],
    *,
    known_units: frozenset[str],
) -> set[str]:
    """Extract only complete, finite callback targets from checked analysis."""

    result: set[str] = set()
    registrations = operation_provenance.get("callback_registrations", ())
    if not isinstance(registrations, list):
        return result
    for registration in registrations:
        if not isinstance(registration, Mapping) or registration.get("status") != "complete":
            continue
        targets = registration.get("target_unit_ids")
        if not isinstance(targets, list) or not targets:
            continue
        if all(isinstance(target, str) and target in known_units for target in targets):
            result.update(str(target) for target in targets)
    return result


def _normalize_global_slot_invariants(
    values: Sequence[GlobalSlotInvariant | Mapping[str, Any]],
) -> tuple[GlobalSlotInvariant, ...]:
    result: list[GlobalSlotInvariant] = []
    for value in values:
        if isinstance(value, GlobalSlotInvariant):
            result.append(value)
            continue
        if not isinstance(value, Mapping):
            raise ValueError("global-slot invariant input must be an object")
        try:
            result.append(GlobalSlotInvariant.parse(value))
        except AuthorityDataError as exc:
            raise ValueError(f"invalid global-slot invariant v2: {exc}") from exc
    return tuple(sorted(result, key=lambda item: item.content_id))


def _normalize_writable_image_ranges(
    ranges: Sequence[tuple[int, int]],
) -> tuple[tuple[int, int], ...]:
    normalized: list[tuple[int, int]] = []
    for value in ranges:
        if (
            not isinstance(value, Sequence)
            or isinstance(value, (str, bytes))
            or len(value) != 2
        ):
            raise ValueError("writable image range must be a start/end pair")
        start, end = value
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or not 0 <= start < end <= 0x1_0000_0000
        ):
            raise ValueError("writable image range is invalid")
        normalized.append((start, end))
    normalized.sort()
    if any(left_end > right_start for (_, left_end), (right_start, _) in zip(
        normalized, normalized[1:]
    )):
        raise ValueError("writable image ranges overlap")
    return tuple(normalized)


def _global_slot_known_values(
    invariants: Sequence[GlobalSlotInvariant],
    *,
    image_base: int,
    finite_value_budget: int,
) -> dict[int, frozenset[ValueOrigin]]:
    """Translate complete checked invariants into dependency-bearing facts."""

    result: dict[int, frozenset[ValueOrigin]] = {}
    for invariant in invariants:
        if invariant.status is not AuthorityStatus.COMPLETE:
            continue
        if invariant.width_bytes != 4 or invariant.alternatives is None:
            raise ValueError(
                "only complete 32-bit global-slot invariants may seed provenance"
            )
        if len(invariant.alternatives.values) > finite_value_budget:
            raise ValueError("global-slot alternatives exceed the provenance budget")
        origins: set[ValueOrigin] = set()
        for encoded in invariant.alternatives.values:
            value = encoded.to_value()
            if not isinstance(value, Mapping):
                raise ValueError("global-slot alternative is not an origin object")
            kind = value.get("kind")
            if kind == "exact_bits":
                concrete = value.get("value")
                width = value.get("width_bits")
                if (
                    not isinstance(concrete, int)
                    or isinstance(concrete, bool)
                    or not 0 <= concrete <= 0xFFFF_FFFF
                    or width != 32
                ):
                    raise ValueError("global-slot exact-bits alternative is invalid")
                origin = ValueOrigin(
                    "exact",
                    (concrete,),
                    (invariant.content_id,),
                )
            else:
                key = value.get("key")
                if (
                    not isinstance(kind, str)
                    or kind not in PROVENANCE_KINDS
                    or not isinstance(key, list)
                ):
                    raise ValueError("global-slot origin alternative is unsupported")
                origin = ValueOrigin(
                    kind,
                    tuple(_freeze_value(item) for item in key),
                    (invariant.content_id,),
                )
            if not is_persistent_origin(origin):
                raise ValueError(
                    "global-slot alternative cannot persist as a memory fact"
                )
            origins.add(origin)
        if not origins or len(origins) > finite_value_budget:
            raise ValueError("global-slot origin set is empty or over budget")
        address = (image_base + invariant.slot_rva) & 0xFFFF_FFFF
        if address in result:
            raise ValueError("global-slot invariants duplicate one exact address")
        result[address] = frozenset(origins)
    return result


def _analyze_mutable_slot_influence(
    *,
    units: Sequence[Mapping[str, Any]],
    roots: Sequence[str],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    recovered_indirect_edges: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    image_base: int,
    image_size: int,
    finite_value_budget: int,
    checked_nonimage_stack_units: frozenset[str],
    call_memory_preservation: Mapping[str, bool],
    global_slot_invariants: Sequence[GlobalSlotInvariant],
) -> Mapping[str, _MutableExitInfluence]:
    """Replay slot influence from empty root memories over reachable edges.

    This is deliberately not an initial-slot seed.  A slot enters the domain
    only when an exact reachable write is observed, or when an unknown write
    makes a later exact image load potentially mutable.
    """

    by_id = {_unit_id(unit): unit for unit in units}
    successors: dict[str, set[str]] = {
        source: set(targets)
        for source, targets in _normal_edges(direct_edges, by_id).items()
    }
    for source, targets in _explicit_call_edges(
        internal_call_edges, by_id
    ).items():
        successors.setdefault(source, set()).update(targets)
    for recovery in recovered_indirect_edges:
        if recovery.get("status") != "recovered":
            continue
        source = recovery.get("source_unit_id")
        if not isinstance(source, str) or source not in by_id:
            continue
        successors.setdefault(source, set()).update(
            target
            for target in recovery.get("target_unit_ids", ())
            if isinstance(target, str) and target in by_id
        )

    unknown_registers = tuple(
        (register, _Influence(unsafe=True))
        for register in sorted(_REGISTER_UNIVERSE)
    )
    initial_memory = tuple(
        sorted(
            (
                invariant.slot_rva,
                _MutableCell(
                    _Influence(slot_rvas=frozenset({invariant.slot_rva})),
                    initialized=True,
                    tainted=False,
                ),
            )
            for invariant in global_slot_invariants
            if invariant.status is AuthorityStatus.COMPLETE
            and invariant.width_bytes == 4
        )
    )
    states: dict[str, _MutableState] = {
        root: _MutableState(unknown_registers, initial_memory)
        for root in roots
        if root in by_id
    }
    queue = deque(sorted(states))
    in_queue = set(queue)
    evaluations = 0
    evaluation_budget = max(
        4,
        (len(by_id) + len(indirect_exits) + 1) * (finite_value_budget + 2),
    )
    while queue and evaluations < evaluation_budget:
        source = queue.popleft()
        in_queue.discard(source)
        output = _transfer_mutable_state(
            by_id[source],
            states[source],
            unit_id=source,
            image_base=image_base,
            image_size=image_size,
            maximum=finite_value_budget,
            checked_nonimage_stack=(source in checked_nonimage_stack_units),
            calls_preserve_memory=call_memory_preservation.get(source, True),
        )
        evaluations += 1
        for target in sorted(successors.get(source, ())):
            previous = states.get(target)
            joined = (
                output
                if previous is None
                else _join_mutable_states(
                    previous, output, maximum=finite_value_budget
                )
            )
            if previous != joined:
                states[target] = joined
                if target not in in_queue:
                    queue.append(target)
                    in_queue.add(target)

    exhausted = bool(queue)
    result: dict[str, _MutableExitInfluence] = {}
    for row in indirect_exits:
        identity = _required_string(row, "id")
        source = row.get("source_unit_id")
        if not isinstance(source, str) or source not in states or source not in by_id:
            result[identity] = _MutableExitInfluence(
                (), (), exhausted, exhausted
            )
            continue
        output = _transfer_mutable_state(
            by_id[source],
            states[source],
            unit_id=source,
            image_base=image_base,
            image_size=image_size,
            maximum=finite_value_budget,
            checked_nonimage_stack=(source in checked_nonimage_stack_units),
            calls_preserve_memory=call_memory_preservation.get(source, True),
        )
        influence = _expression_influence(
            row.get("target_expression"),
            output,
            unit_id=source,
            unit=by_id[source],
            image_base=image_base,
            image_size=image_size,
            maximum=finite_value_budget,
        )
        result[identity] = _MutableExitInfluence(
            tuple(sorted(influence.slot_rvas)),
            tuple(sorted(influence.read_sites)),
            influence.unsafe or exhausted,
            influence.overflow or exhausted,
        )
    return result


def _transfer_mutable_state(
    unit: Mapping[str, Any],
    state: _MutableState,
    *,
    unit_id: str,
    image_base: int,
    image_size: int,
    maximum: int,
    checked_nonimage_stack: bool,
    calls_preserve_memory: bool,
) -> _MutableState:
    registers = dict(state.registers)
    memory = dict(state.memory)
    unknown_write = state.unknown_write
    semantics = unit.get("semantics")
    semantics = semantics if isinstance(semantics, Mapping) else {}
    read_sites = _mutable_read_sites(
        unit_id=unit_id,
        semantics=semantics,
        image_base=image_base,
        image_size=image_size,
    )

    raw_writes = semantics.get("register_writes", ())
    if isinstance(raw_writes, Sequence) and not isinstance(raw_writes, (str, bytes)):
        for raw in raw_writes:
            if not isinstance(raw, Mapping):
                continue
            register = raw.get("register")
            if isinstance(register, str) and register.lower() in _REGISTER_UNIVERSE:
                registers[register.lower()] = _expression_influence_parts(
                    raw.get("value"),
                    registers=registers,
                    memory=memory,
                    unknown_write=unknown_write,
                    read_sites=read_sites,
                    image_base=image_base,
                    image_size=image_size,
                    maximum=maximum,
                )

    raw_events = semantics.get("ordered_events")
    if not isinstance(raw_events, Sequence) or isinstance(raw_events, (str, bytes)):
        raw_events = semantics.get("memory_events", ())
    if isinstance(raw_events, Sequence) and not isinstance(raw_events, (str, bytes)):
        for raw in raw_events:
            if not isinstance(raw, Mapping) or raw.get("kind") not in {
                "write",
                "read_write",
            }:
                continue
            if raw.get("width") not in {4, 32}:
                continue
            address_expression = raw.get("address")
            address = constant_u32(address_expression)
            value = _expression_influence_parts(
                raw.get("value"),
                registers=registers,
                memory=memory,
                unknown_write=unknown_write,
                read_sites=read_sites,
                image_base=image_base,
                image_size=image_size,
                maximum=maximum,
            )
            if address is None:
                if (
                    checked_nonimage_stack
                    and affine_register_offset(address_expression, "esp")
                    is not None
                ):
                    continue
                unknown_write = True
                memory = {
                    slot: _MutableCell(
                        cell.value,
                        initialized=cell.initialized,
                        tainted=True,
                    )
                    for slot, cell in memory.items()
                }
                continue
            slot_rva = _image_slot_rva(
                address,
                image_base=image_base,
                image_size=image_size,
            )
            if slot_rva is None:
                continue
            memory[slot_rva] = _MutableCell(
                value=value,
                initialized=True,
                tainted=value.unsafe or value.overflow,
            )

    if not calls_preserve_memory:
        unknown_write = True
        memory = {
            slot: _MutableCell(
                cell.value,
                initialized=cell.initialized,
                tainted=True,
            )
            for slot, cell in memory.items()
        }

    return _MutableState(
        tuple(sorted(registers.items())),
        tuple(sorted(memory.items())),
        unknown_write,
    )


def _join_mutable_states(
    left: _MutableState, right: _MutableState, *, maximum: int
) -> _MutableState:
    left_registers = dict(left.registers)
    right_registers = dict(right.registers)
    registers = {
        register: left_registers.get(register, _Influence(unsafe=True)).join(
            right_registers.get(register, _Influence(unsafe=True)),
            maximum=maximum,
        )
        for register in sorted(_REGISTER_UNIVERSE)
    }
    left_memory = dict(left.memory)
    right_memory = dict(right.memory)
    memory: dict[int, _MutableCell] = {}
    for slot in sorted(left_memory.keys() | right_memory.keys()):
        left_cell = left_memory.get(slot)
        right_cell = right_memory.get(slot)
        if left_cell is None or right_cell is None:
            cell = left_cell if left_cell is not None else right_cell
            assert cell is not None
            memory[slot] = _MutableCell(
                cell.value,
                initialized=False,
                tainted=True,
            )
        else:
            memory[slot] = left_cell.join(right_cell, maximum=maximum)
    return _MutableState(
        tuple(registers.items()),
        tuple(memory.items()),
        left.unknown_write or right.unknown_write,
    )


def _mutable_read_sites(
    *,
    unit_id: str,
    semantics: Mapping[str, Any],
    image_base: int,
    image_size: int,
) -> Mapping[int, frozenset[tuple[int, str, int]]]:
    """Index exact image-slot reads which can feed target provenance."""

    result: dict[int, set[tuple[int, str, int]]] = defaultdict(set)
    events = semantics.get("memory_events", ())
    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
        return {}
    for event_index, raw in enumerate(events):
        if (
            not isinstance(raw, Mapping)
            or raw.get("kind") not in {"read", "read_write"}
            or raw.get("width") not in {4, 32}
        ):
            continue
        address = constant_u32(raw.get("address"))
        if address is None:
            continue
        slot_rva = _image_slot_rva(
            address,
            image_base=image_base,
            image_size=image_size,
        )
        if slot_rva is not None:
            result[slot_rva].add((slot_rva, unit_id, event_index))
    return {
        slot_rva: frozenset(sites)
        for slot_rva, sites in sorted(result.items())
    }


def _expression_influence(
    expression: Any,
    state: _MutableState,
    *,
    unit_id: str,
    unit: Mapping[str, Any],
    image_base: int,
    image_size: int,
    maximum: int,
) -> _Influence:
    return _expression_influence_parts(
        expression,
        registers=dict(state.registers),
        memory=dict(state.memory),
        unknown_write=state.unknown_write,
        read_sites=_mutable_read_sites(
            unit_id=unit_id,
            semantics=(
                unit.get("semantics")
                if isinstance(unit.get("semantics"), Mapping)
                else {}
            ),
            image_base=image_base,
            image_size=image_size,
        ),
        image_base=image_base,
        image_size=image_size,
        maximum=maximum,
    )


def _expression_influence_parts(
    expression: Any,
    *,
    registers: Mapping[str, _Influence],
    memory: Mapping[int, _MutableCell],
    unknown_write: bool,
    read_sites: Mapping[int, frozenset[tuple[int, str, int]]],
    image_base: int,
    image_size: int,
    maximum: int,
) -> _Influence:
    if not isinstance(expression, Mapping):
        return _Influence(unsafe=True)
    op = str(expression.get("op") or "").lower()
    if op in {"const", "constant"}:
        return _Influence()
    if op in {"reg", "input_reg", "register"}:
        register = str(expression.get("name", expression.get("reg", ""))).lower()
        return registers.get(register, _Influence(unsafe=True))
    if op in {"load", "read32", "mem32"}:
        address_expression = expression.get("address")
        address = constant_u32(address_expression)
        address_influence = _expression_influence_parts(
            address_expression,
            registers=registers,
            memory=memory,
            unknown_write=unknown_write,
            read_sites=read_sites,
            image_base=image_base,
            image_size=image_size,
            maximum=maximum,
        )
        if address is None:
            # An unresolved address is one primary provenance frontier.  It
            # must not be expanded into a dependency on every mutable cell in
            # the program: that loses point sensitivity and creates a large
            # set of false slot repair tasks.
            return address_influence.join(
                _Influence(unsafe=True),
                maximum=maximum,
            )
        slot_rva = _image_slot_rva(
            address,
            image_base=image_base,
            image_size=image_size,
        )
        if slot_rva is None:
            return address_influence
        site_witnesses = read_sites.get(slot_rva, frozenset())
        cell = memory.get(slot_rva)
        if cell is None:
            return address_influence.join(
                _Influence(
                    slot_rvas=(
                        frozenset({slot_rva})
                        if unknown_write
                        else frozenset()
                    ),
                    read_sites=site_witnesses,
                    unsafe=unknown_write,
                ),
                maximum=maximum,
            )
        return address_influence.join(
            _Influence(
                slot_rvas=frozenset({slot_rva}) | cell.value.slot_rvas,
                read_sites=site_witnesses | cell.value.read_sites,
                unsafe=(
                    unknown_write
                    or cell.tainted
                    or not cell.initialized
                    or cell.value.unsafe
                ),
                overflow=cell.value.overflow,
            ),
            maximum=maximum,
        )

    result = _Influence()
    observed = False
    for key, value in expression.items():
        if key in {"op", "width", "name", "reg", "value"}:
            continue
        values = (
            value
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes))
            else (value,)
        )
        for child in values:
            if not isinstance(child, Mapping):
                continue
            observed = True
            result = result.join(
                _expression_influence_parts(
                    child,
                    registers=registers,
                    memory=memory,
                    unknown_write=unknown_write,
                    read_sites=read_sites,
                    image_base=image_base,
                    image_size=image_size,
                    maximum=maximum,
                ),
                maximum=maximum,
            )
    return result if observed else _Influence(unsafe=True)


def _image_slot_rva(
    address: int, *, image_base: int, image_size: int
) -> int | None:
    image_end = image_base + image_size
    if (
        not 0 <= image_base <= address <= 0xFFFF_FFFB
        or image_size <= 0
        or image_end > 0x1_0000_0000
        or address + 4 > image_end
    ):
        return None
    return address - image_base


def _bind_mutable_slot_dependencies(
    recoveries: Sequence[Mapping[str, Any]],
    *,
    exit_influence: Mapping[str, _MutableExitInfluence],
    global_slot_invariants: Sequence[GlobalSlotInvariant],
    finite_value_budget: int,
    writable_image_ranges: Sequence[tuple[int, int]],
    image_base: int,
) -> list[dict[str, Any]]:
    by_slot: dict[int, list[GlobalSlotInvariant]] = defaultdict(list)
    by_content_id: dict[str, GlobalSlotInvariant] = {}
    for invariant in global_slot_invariants:
        if invariant.width_bytes == 4:
            by_slot[invariant.slot_rva].append(invariant)
            by_content_id[invariant.content_id] = invariant

    result: list[dict[str, Any]] = []
    for raw in recoveries:
        row = copy.deepcopy(dict(raw))
        if has_value_independent_target_set_v2(row):
            # The checked predecessor/dataflow bound and immutable table
            # inventory already quantify over every selector value that can
            # reach this exit. Mutable data may choose an inventory member, but
            # cannot change the complete target set. Do not invent a global
            # value-invariant obligation for that selector.
            row.pop("mutable_slot_dependencies", None)
            result.append(row)
            continue
        identity = row.get("id")
        influence = exit_influence.get(identity) if isinstance(identity, str) else None
        witnessed_dependencies = _target_origin_authority_dependencies(row)
        witnessed_slot_rvas = _target_origin_writable_slot_rvas(
            row,
            writable_image_ranges=writable_image_ranges,
            image_base=image_base,
        )
        analysis_invariants = {
            by_content_id[dependency]
            for dependency in row.get("analysis_dependencies", ())
            if isinstance(dependency, str)
            and dependency in by_content_id
            and dependency in witnessed_dependencies
        }
        if influence is None:
            influence = _MutableExitInfluence((), (), False, False)
        effective_slot_rvas = tuple(sorted(
            set(influence.slot_rvas)
            | set(witnessed_slot_rvas)
            | {invariant.slot_rva for invariant in analysis_invariants}
        ))
        if not effective_slot_rvas:
            row.pop("mutable_slot_dependencies", None)
            if (
                row.get("status") == "recovered"
                and (influence.unsafe or influence.overflow)
            ) and _has_unresolved_memory_load(row.get("target_expression")):
                row.update({
                    "status": "incomplete",
                    "closure": "unresolved",
                    "target_rvas": [],
                    "target_unit_ids": [],
                    "external_targets": [],
                    "failure": {
                        "code": (
                            "target_memory_provenance_budget_exceeded"
                            if influence.overflow
                            else "target_memory_address_unresolved"
                        ),
                    },
                })
            result.append(row)
            continue

        details: list[dict[str, Any]] = []
        dependencies: list[dict[str, str]] = [
            copy.deepcopy(dict(item))
            for item in row.get("authority_dependencies", ())
            if isinstance(item, Mapping)
            and item.get("role") != "mutable_slot_invariant"
        ]
        failure_code: str | None = None
        dependency_backed = bool(analysis_invariants or witnessed_slot_rvas)
        if influence.overflow or len(effective_slot_rvas) > finite_value_budget:
            failure_code = "mutable_slot_dependency_budget_exceeded"
        elif influence.unsafe and not dependency_backed:
            failure_code = "mutable_slot_tainted"

        for slot_rva in effective_slot_rvas:
            read_sites = [
                {"unit_id": unit_id, "event_index": event_index}
                for observed_slot, unit_id, event_index in influence.read_sites
                if observed_slot == slot_rva
            ]
            candidates = by_slot.get(slot_rva, ())
            if len(candidates) != 1:
                failure_code = failure_code or (
                    "mutable_slot_invariant_missing"
                    if not candidates
                    else "mutable_slot_invariant_ambiguous"
                )
                details.append({
                    "slot_rva": slot_rva,
                    "width_bytes": 4,
                    "read_sites": read_sites,
                    "origin_witnessed": slot_rva in witnessed_slot_rvas,
                })
                continue
            invariant = candidates[0]
            details.append({
                "slot_rva": slot_rva,
                "width_bytes": 4,
                "content_id": invariant.content_id,
                "read_sites": read_sites,
                "origin_witnessed": slot_rva in witnessed_slot_rvas,
            })
            dependencies.append({
                "role": "mutable_slot_invariant",
                "content_id": invariant.content_id,
            })
            if (
                invariant.alternatives is not None
                and len(invariant.alternatives.values) > finite_value_budget
            ):
                failure_code = failure_code or "mutable_slot_dependency_budget_exceeded"
            elif invariant.status is not AuthorityStatus.COMPLETE:
                failure_code = failure_code or "mutable_slot_invariant_incomplete"

        row["mutable_slot_dependencies"] = sorted(
            details,
            key=lambda item: (int(item["slot_rva"]), str(item.get("content_id", ""))),
        )
        row["authority_dependencies"] = sorted(
            {
                (str(item["role"]), str(item["content_id"]))
                for item in dependencies
                if isinstance(item.get("role"), str)
                and isinstance(item.get("content_id"), str)
            },
        )
        row["authority_dependencies"] = [
            {"role": role, "content_id": content_id}
            for role, content_id in row["authority_dependencies"]
        ]
        if failure_code is not None:
            row.update({
                "status": "incomplete",
                "closure": "unresolved",
                "target_rvas": [],
                "target_unit_ids": [],
                "external_targets": [],
                "failure": {
                    "code": failure_code,
                    "slot_rvas": list(influence.slot_rvas),
                },
            })
        result.append(row)
    return result


def _target_origin_authority_dependencies(
    recovery: Mapping[str, Any],
) -> frozenset[str]:
    witnesses = recovery.get("target_origin_witnesses")
    if not isinstance(witnesses, Sequence) or isinstance(witnesses, (str, bytes)):
        return frozenset()
    return frozenset(
        dependency
        for witness in witnesses
        if isinstance(witness, Mapping)
        for dependency in witness.get("authority_dependencies", ())
        if isinstance(dependency, str) and dependency
    )


def _target_origin_writable_slot_rvas(
    recovery: Mapping[str, Any],
    *,
    writable_image_ranges: Sequence[tuple[int, int]],
    image_base: int,
) -> frozenset[int]:
    witnesses = recovery.get("target_origin_witnesses")
    if not isinstance(witnesses, Sequence) or isinstance(witnesses, (str, bytes)):
        return frozenset()
    addresses: set[int] = set()
    for witness in witnesses:
        if (
            not isinstance(witness, Mapping)
            or witness.get("kind") not in {"static_code", "static_data"}
        ):
            continue
        key = witness.get("key")
        sources = key[1] if isinstance(key, list) and len(key) == 2 else None
        if not isinstance(sources, list):
            continue
        for address in sources:
            if (
                isinstance(address, int)
                and not isinstance(address, bool)
                and any(
                    start <= address and address + 4 <= end
                    for start, end in writable_image_ranges
                )
            ):
                addresses.add(address)
    return frozenset(address - image_base for address in addresses)


def _has_unresolved_memory_load(expression: Any) -> bool:
    if not isinstance(expression, Mapping):
        return False
    op = str(expression.get("op") or "").lower()
    if op in {"load", "read32", "mem32"}:
        return constant_u32(expression.get("address")) is None
    return any(
        _has_unresolved_memory_load(value)
        for key, raw in expression.items()
        if key not in {"op", "width", "name", "reg", "value"}
        for value in (
            raw
            if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes))
            else (raw,)
        )
    )


def _used_global_slot_invariants(
    recoveries: Sequence[Mapping[str, Any]],
    invariants: Sequence[GlobalSlotInvariant],
) -> tuple[GlobalSlotInvariant, ...]:
    used = {
        item.get("content_id")
        for recovery in recoveries
        for item in recovery.get("authority_dependencies", ())
        if isinstance(item, Mapping)
        and item.get("role") == "mutable_slot_invariant"
        and isinstance(item.get("content_id"), str)
    }
    return tuple(
        invariant for invariant in invariants if invariant.content_id in used
    )


def _typed_proposals(
    *,
    summaries: Mapping[str, Any],
    recoveries: Sequence[Mapping[str, Any]],
    global_slot_invariants: Sequence[GlobalSlotInvariant],
    finite_value_budget: int,
) -> dict[str, _NodeState]:
    result: dict[str, _NodeState] = {}
    for raw in summaries.get("summaries", []):
        if not isinstance(raw, Mapping):
            continue
        unit_id = raw.get("target_unit_id")
        if isinstance(unit_id, str):
            result[_summary_node(unit_id)] = _summary_state(raw)
    for raw in recoveries:
        identity = raw.get("id")
        if isinstance(identity, str):
            result[identity] = _recovery_state(
                raw, finite_value_budget=finite_value_budget
            )
    for invariant in global_slot_invariants:
        result[invariant.content_id] = _global_slot_state(
            invariant, finite_value_budget=finite_value_budget
        )
    return result


def _global_slot_state(
    invariant: GlobalSlotInvariant, *, finite_value_budget: int
) -> _NodeState:
    alternatives = (
        ()
        if invariant.alternatives is None
        else tuple(
            _TargetAlternative("value_origin", _freeze_value(value.to_value()))
            for value in invariant.alternatives.values
        )
    )
    complete = (
        invariant.status is AuthorityStatus.COMPLETE
        and bool(alternatives)
        and len(alternatives) <= finite_value_budget
    )
    may_values: Any
    if len(alternatives) > finite_value_budget:
        may_values = Top()
    elif complete:
        may_values = Finite.of(alternatives)
    else:
        may_values = Top()
    reasons = tuple(sorted(issue.code for issue in invariant.issues))
    if not complete and not reasons:
        reasons = ("global_slot_invariant_incomplete",)
    return _NodeState(
        InterproceduralFact(
            may_values=may_values,
            preserved_registers=MustPreservedRegisters(_REGISTER_UNIVERSE),
            stack_cleanup=NoExactValue(),
            results=NoExactValue(),
            return_behavior=ReturnBehavior(),
            taint=Taint.of(reasons),
        ),
        "complete" if complete else "incomplete",
        reasons,
    )


def _summary_state(raw: Mapping[str, Any]) -> _NodeState:
    complete = raw.get("status") == "complete"
    blockers = tuple(
        sorted(
            str(code)
            for code in raw.get("blocker_codes", [])
            if isinstance(code, str)
        )
    )
    hard_conflict = any(_is_conflict_reason(code) for code in blockers)
    preservation_row = raw.get("register_preservation")
    preservation_complete = (
        isinstance(preservation_row, Mapping)
        and preservation_row.get("status") == "complete"
    )
    preserved = raw.get("preserved_registers")
    preserved_fact = MustPreservedRegisters(
        frozenset(str(register).lower() for register in preserved)
        if preservation_complete and isinstance(preserved, list)
        else _REGISTER_UNIVERSE
    )
    stack_row = raw.get("stack_cleanup")
    stack_fact: Any = NoExactValue()
    if isinstance(stack_row, Mapping) and stack_row.get("status") in {
        "complete",
        "not_applicable",
    }:
        stack_fact = Exact(_freeze_value(dict(stack_row)))
    elif hard_conflict:
        stack_fact = Conflict()
    result_row = raw.get("result_register_origins")
    result_fact: Any = NoExactValue()
    if (
        isinstance(result_row, Mapping)
        and result_row.get("status") == "complete"
    ):
        result_fact = Exact(_freeze_value(dict(result_row)))
    elif hard_conflict:
        result_fact = Conflict()
    behavior_row = raw.get("return_behavior")
    behavior = ReturnBehavior(incomplete=True)
    if (
        isinstance(behavior_row, Mapping)
        and behavior_row.get("status") == "complete"
    ):
        behavior = ReturnBehavior(
            may_return=behavior_row.get("may_return") is True,
            may_not_return=behavior_row.get("may_not_return") is True,
        )
    fact = InterproceduralFact(
        may_values=Bottom(),
        preserved_registers=preserved_fact,
        stack_cleanup=stack_fact,
        results=result_fact,
        return_behavior=behavior,
        taint=Taint.of(blockers if hard_conflict else ()),
    )
    return _NodeState(fact, "complete" if complete else "incomplete", blockers)


def _recovery_state(
    raw: Mapping[str, Any], *, finite_value_budget: int
) -> _NodeState:
    failure = raw.get("failure")
    failure_code = (
        str(failure.get("code"))
        if isinstance(failure, Mapping) and isinstance(failure.get("code"), str)
        else ""
    )
    alternatives = _target_alternatives(raw)
    overflow = len(alternatives) > finite_value_budget or _is_overflow_reason(
        failure_code
    )
    conflict = _is_conflict_reason(failure_code)
    authority_incomplete = failure_code.startswith("mutable_slot_")
    if overflow or conflict or authority_incomplete:
        may_values: Any = Top()
    elif raw.get("status") == "recovered":
        may_values = Finite.of(alternatives)
    else:
        may_values = Bottom()
    fact = InterproceduralFact(
        may_values=may_values,
        preserved_registers=MustPreservedRegisters(_REGISTER_UNIVERSE),
        stack_cleanup=NoExactValue(),
        results=Conflict() if conflict else NoExactValue(),
        return_behavior=ReturnBehavior(),
        taint=Taint.of(
            (failure_code,) if overflow or conflict or authority_incomplete else ()
        ),
    )
    failures = (failure_code,) if failure_code else ()
    return _NodeState(
        fact,
        "complete" if raw.get("status") == "recovered" else "incomplete",
        failures,
    )


def _target_alternatives(raw: Mapping[str, Any]) -> frozenset[_TargetAlternative]:
    targets: set[_TargetAlternative] = set()
    internal_units = [
        unit_id
        for unit_id in raw.get("target_unit_ids", [])
        if isinstance(unit_id, str)
    ]
    for unit_id in internal_units:
        if isinstance(unit_id, str):
            targets.add(_TargetAlternative("internal_unit", unit_id))
    # A unit ID and its RVA are two names for one internal alternative.  RVA
    # values are used only when no exact unit binding was recovered.
    if not internal_units:
        for rva in raw.get("target_rvas", []):
            if isinstance(rva, int) and not isinstance(rva, bool):
                targets.add(_TargetAlternative("internal_rva", rva))
    for target in raw.get("external_targets", []):
        if isinstance(target, Mapping):
            targets.add(_TargetAlternative("external", _freeze_value(dict(target))))
    return frozenset(targets)


def _derive_dependency_edges(
    *,
    units: Sequence[Mapping[str, Any]],
    roots: Sequence[str],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    summaries: Mapping[str, Any],
    recoveries: Sequence[Mapping[str, Any]],
) -> frozenset[tuple[str, str]]:
    """Derive provider-to-consumer dependencies from represented behavior."""

    by_id = {_unit_id(unit): unit for unit in units}
    by_rva: dict[int, list[str]] = defaultdict(list)
    for unit_id, unit in by_id.items():
        rva = _unit_rva(unit)
        if rva is not None:
            by_rva[rva].append(unit_id)
    normal = _normal_edges(direct_edges, by_id)
    exits_by_source: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    exits_by_id = {
        _required_string(row, "id"): row for row in indirect_exits
    }
    for row in indirect_exits:
        source = row.get("source_unit_id")
        if isinstance(source, str) and source in by_id:
            exits_by_source[source].append(row)
    recovery_by_id = {
        str(row.get("id")): row
        for row in recoveries
        if isinstance(row.get("id"), str)
    }
    calls = _call_targets_by_source(
        by_id=by_id,
        by_rva=by_rva,
        internal_call_edges=internal_call_edges,
        recoveries=recoveries,
    )

    summary_roots = {
        str(row.get("target_unit_id"))
        for row in summaries.get("summaries", [])
        if isinstance(row, Mapping)
        and isinstance(row.get("target_unit_id"), str)
    }
    dependencies: set[tuple[str, str]] = set()

    # A function summary consumes every call summary and indirect-exit
    # certificate encountered in its represented non-call body.
    body_graph = {source: set(targets) for source, targets in normal.items()}
    for recovery_id, recovery in recovery_by_id.items():
        if recovery.get("status") != "recovered" or recovery.get("kind") != "indirect_jump":
            continue
        source = recovery.get("source_unit_id")
        if not isinstance(source, str):
            continue
        for target in recovery.get("target_unit_ids", []):
            if isinstance(target, str) and target in by_id:
                body_graph.setdefault(source, set()).add(target)
    for root in sorted(summary_roots):
        body = _reachable(root, body_graph)
        consumer = _summary_node(root)
        for source in body:
            for target in calls.get(source, ()):
                if target in summary_roots:
                    dependencies.add((_summary_node(target), consumer))
            for exit_row in exits_by_source.get(source, ()):
                dependencies.add((_required_string(exit_row, "id"), consumer))

    # An indirect target certificate is also the reachability authority for
    # each callee summary introduced through that edge.  Without this edge a
    # stale target hypothesis could expose a valid leaf summary even when the
    # target itself was not reproduced.
    for recovery_id, recovery in recovery_by_id.items():
        if recovery.get("status") != "recovered":
            continue
        for target in recovery.get("target_unit_ids", ()):
            if isinstance(target, str) and target in summary_roots:
                dependencies.add((recovery_id, _summary_node(target)))

    # Target provenance carries the exact summaries used to preserve or
    # produce that value.  Path-wide attribution invents dependencies from
    # unrelated calls and creates artificial recursive SCCs.
    for recovery_id, recovery in recovery_by_id.items():
        if recovery.get("status") != "recovered":
            continue
        raw_dependencies = recovery.get("analysis_dependencies", ())
        if not isinstance(raw_dependencies, Sequence) or isinstance(
            raw_dependencies, (str, bytes)
        ):
            continue
        for dependency in raw_dependencies:
            target = _call_frame_dependency_target(dependency)
            if target is not None and target in summary_roots:
                dependencies.add((_summary_node(target), recovery_id))
    for recovery_id, recovery in recovery_by_id.items():
        raw_dependencies = recovery.get("authority_dependencies", ())
        if not isinstance(raw_dependencies, Sequence) or isinstance(
            raw_dependencies, (str, bytes)
        ):
            continue
        for raw in raw_dependencies:
            if not isinstance(raw, Mapping):
                continue
            content_id = raw.get("content_id")
            if (
                raw.get("role") == "mutable_slot_invariant"
                and isinstance(content_id, str)
            ):
                dependencies.add((content_id, recovery_id))
    return frozenset(dependencies)


def _call_frame_dependency_target(value: Any) -> str | None:
    if not isinstance(value, str) or not value.startswith("call-frame:"):
        return None
    try:
        payload = json.loads(value.removeprefix("call-frame:"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if (
        not isinstance(payload, list)
        or len(payload) != 3
        or not isinstance(payload[0], str)
        or not isinstance(payload[1], int)
        or isinstance(payload[1], bool)
        or payload[1] < 0
        or not isinstance(payload[2], str)
    ):
        return None
    return payload[2]


def _call_targets_by_source(
    *,
    by_id: Mapping[str, Mapping[str, Any]],
    by_rva: Mapping[int, Sequence[str]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    recoveries: Sequence[Mapping[str, Any]],
) -> Mapping[str, frozenset[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for source, targets in _explicit_call_edges(internal_call_edges, by_id).items():
        result[source].update(targets)
    for source, unit in by_id.items():
        for event in _events(unit):
            if event.get("kind") != "internal_call":
                continue
            rva = event.get("target_rva")
            if isinstance(rva, int) and not isinstance(rva, bool):
                matches = by_rva.get(rva, ())
                if len(matches) == 1:
                    result[source].add(matches[0])
    for recovery in recoveries:
        if recovery.get("status") != "recovered" or recovery.get("kind") != "indirect_call":
            continue
        source = recovery.get("source_unit_id")
        if not isinstance(source, str):
            continue
        result[source].update(
            target
            for target in recovery.get("target_unit_ids", [])
            if isinstance(target, str) and target in by_id
        )
    return {source: frozenset(targets) for source, targets in result.items()}


def _explicit_call_edges(
    edges: Sequence[Mapping[str, Any]],
    by_id: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, frozenset[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        source = edge.get("source_unit_id")
        target = edge.get("target_unit_id", edge.get("resolved_unit_id"))
        if (
            edge.get("status") in {None, "resolved"}
            and isinstance(source, str)
            and isinstance(target, str)
            and source in by_id
            and target in by_id
        ):
            result[source].add(target)
    return {source: frozenset(targets) for source, targets in result.items()}


def _normal_edges(
    edges: Sequence[Mapping[str, Any]],
    by_id: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, frozenset[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        source = edge.get("source_unit_id")
        target = edge.get("target_unit_id", edge.get("resolved_unit_id"))
        if (
            edge.get("status") in {None, "resolved"}
            and isinstance(source, str)
            and isinstance(target, str)
            and source in by_id
            and target in by_id
        ):
            result[source].add(target)
    return {source: frozenset(targets) for source, targets in result.items()}


def _reachable(root: str, graph: Mapping[str, set[str]]) -> frozenset[str]:
    reached: set[str] = set()
    work = [root]
    while work:
        node = work.pop()
        if node in reached:
            continue
        reached.add(node)
        work.extend(sorted(graph.get(node, ()), reverse=True))
    return frozenset(reached)


def _call_summary_inputs(
    summaries: Mapping[str, Any], *, image_base: int
) -> tuple[
    dict[int, frozenset[str]],
    dict[int, int],
    dict[int, dict[str, list[Mapping[str, Any]]]],
]:
    preserved: dict[int, frozenset[str]] = {}
    cleanup: dict[int, int] = {}
    results: dict[int, dict[str, list[Mapping[str, Any]]]] = {}
    for raw in summaries.get("summaries", []):
        if not isinstance(raw, Mapping):
            continue
        rva = raw.get("target_rva")
        if not isinstance(rva, int) or isinstance(rva, bool):
            continue
        address = (image_base + rva) & 0xFFFFFFFF
        raw_preserved = raw.get("preserved_registers")
        preservation = raw.get("register_preservation")
        if (
            isinstance(preservation, Mapping)
            and preservation.get("status") == "complete"
            and isinstance(raw_preserved, list)
        ):
            preserved[address] = frozenset(str(register) for register in raw_preserved)
        stack = raw.get("stack_cleanup")
        return_instruction = raw.get("return_instruction_cleanup")
        cleanup_values = {
            value
            for value in (
                stack.get("stack_delta")
                if isinstance(stack, Mapping)
                and stack.get("status") == "complete"
                else None,
                return_instruction.get("cleanup_bytes")
                if isinstance(return_instruction, Mapping)
                and return_instruction.get("status") == "complete"
                else None,
            )
            if isinstance(value, int) and not isinstance(value, bool)
        }
        if len(cleanup_values) == 1:
            cleanup[address] = next(iter(cleanup_values))
        elif (
            isinstance(stack, Mapping)
            and stack.get("status") == "complete"
            and isinstance(stack.get("stack_delta"), int)
            and not isinstance(stack.get("stack_delta"), bool)
        ):
            # A contradictory independent return-instruction family must fail
            # closed instead of preferring the older aggregate stack result.
            cleanup.pop(address, None)
        inventory = raw.get("result_register_origins")
        registers = (
            inventory.get("registers")
            if isinstance(inventory, Mapping) and inventory.get("status") == "complete"
            else None
        )
        if isinstance(registers, Mapping):
            normalized = {
                str(register): [copy.deepcopy(origin)]
                for register, origin in registers.items()
                if isinstance(register, str) and isinstance(origin, Mapping)
            }
            if normalized:
                results[address] = normalized
    return preserved, cleanup, results


def _call_summary_memory_preservation(
    summaries: Mapping[str, Any], *, image_base: int
) -> dict[int, bool]:
    """Prove callee memory framing from exact effect inventories.

    The fixed point is a greatest set of summaries whose own reachable bodies
    contain no write, no external event, and whose delegated internal callees
    are themselves in the set.  Unknown or indirect dependencies are excluded.
    """

    rows = {
        str(row.get("target_unit_id")): row
        for row in summaries.get("summaries", ())
        if isinstance(row, Mapping)
        and isinstance(row.get("target_unit_id"), str)
    }
    candidates: set[str] = set()
    dependencies: dict[str, set[str]] = {}
    for unit_id, row in rows.items():
        memory = row.get("memory_effects")
        world = row.get("world_effects")
        if (
            row.get("status") != "complete"
            or not isinstance(memory, Mapping)
            or memory.get("status") != "complete"
            or not isinstance(world, Mapping)
            or world.get("status") != "complete"
        ):
            continue
        sites = memory.get("local_sites")
        external = world.get("external_sites")
        raw_dependencies = row.get("target_dependencies")
        if (
            not isinstance(sites, list)
            or any(
                not isinstance(site, Mapping)
                or site.get("kind") in {"write", "read_write"}
                for site in sites
            )
            or not isinstance(external, list)
            or external
            or not isinstance(raw_dependencies, list)
        ):
            continue
        callees: set[str] = set()
        unsupported = False
        for dependency in raw_dependencies:
            if not isinstance(dependency, str) or not dependency.startswith(
                "call-summary:"
            ):
                unsupported = True
                break
            callees.add(dependency.removeprefix("call-summary:"))
        if unsupported:
            continue
        candidates.add(unit_id)
        dependencies[unit_id] = callees

    changed = True
    while changed:
        rejected = {
            unit_id
            for unit_id in candidates
            if not dependencies.get(unit_id, set()) <= candidates
        }
        changed = bool(rejected)
        candidates.difference_update(rejected)

    result: dict[int, bool] = {}
    for unit_id in sorted(candidates):
        rva = rows[unit_id].get("target_rva")
        if isinstance(rva, int) and not isinstance(rva, bool):
            result[(image_base + rva) & 0xFFFFFFFF] = True
    return result


def _call_site_memory_preservation(
    *,
    units: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    recoveries: Sequence[Mapping[str, Any]],
    internal_memory_preservation: Mapping[int, bool],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    image_base: int,
) -> dict[str, bool]:
    """Classify each unit's calls by checked memory-effect evidence."""

    by_id = {_unit_id(unit): unit for unit in units}
    direct_targets: dict[tuple[str, int], set[str]] = defaultdict(set)
    for edge in internal_call_edges:
        source = edge.get("source_unit_id")
        event_index = edge.get("source_event_index")
        target = edge.get("target_unit_id")
        if (
            isinstance(source, str)
            and isinstance(event_index, int)
            and not isinstance(event_index, bool)
            and isinstance(target, str)
            and target in by_id
        ):
            direct_targets[(source, event_index)].add(target)
    recovery_by_site = {
        (str(row.get("source_unit_id")), int(row.get("source_event_index"))): row
        for row in recoveries
        if row.get("status") == "recovered"
        and isinstance(row.get("source_unit_id"), str)
        and isinstance(row.get("source_event_index"), int)
        and not isinstance(row.get("source_event_index"), bool)
    }

    def internal_targets_preserve(targets: Sequence[Any]) -> bool:
        addresses = []
        for target in targets:
            if not isinstance(target, str) or target not in by_id:
                return False
            rva = _unit_rva(by_id[target])
            if rva is None:
                return False
            addresses.append((image_base + rva) & 0xFFFFFFFF)
        return bool(addresses) and all(
            internal_memory_preservation.get(address) is True
            for address in addresses
        )

    result: dict[str, bool] = {}
    for unit_id, unit in by_id.items():
        calls = [
            (index, event)
            for index, event in enumerate(_events(unit))
            if event.get("kind") in {
                "external_call",
                "internal_call",
                "indirect_call",
            }
        ]
        preserved = True
        for event_index, event in calls:
            kind = event.get("kind")
            if kind == "internal_call":
                preserved = preserved and internal_targets_preserve(
                    tuple(direct_targets.get((unit_id, event_index), ()))
                )
                continue
            if kind == "external_call":
                identity = _machine_import_identity(event)
                selected = import_abis.get(identity) if identity is not None else None
                contract = selected.contract if selected is not None else None
                preserved = preserved and isinstance(contract, Mapping) and (
                    contract.get("memory_effect") in {"none", "read_only"}
                )
                continue
            recovery = recovery_by_site.get((unit_id, event_index))
            if not isinstance(recovery, Mapping):
                preserved = False
                continue
            raw_internal = recovery.get("target_unit_ids", ())
            raw_external = recovery.get("external_targets", ())
            if (
                not isinstance(raw_internal, Sequence)
                or isinstance(raw_internal, (str, bytes))
                or not isinstance(raw_external, Sequence)
                or isinstance(raw_external, (str, bytes))
            ):
                preserved = False
                continue
            internal_ok = not raw_internal or internal_targets_preserve(raw_internal)
            external_ok = all(
                _external_target_memory_preserved(target, import_abis)
                for target in raw_external
                if isinstance(target, Mapping)
            ) and all(isinstance(target, Mapping) for target in raw_external)
            preserved = preserved and bool(raw_internal or raw_external)
            preserved = preserved and internal_ok and external_ok
        result[unit_id] = preserved
    return result


def _machine_import_identity(
    value: Mapping[str, Any],
) -> MachineImportIdentity | None:
    dll = value.get("dll")
    symbol = value.get("symbol")
    ordinal = value.get("ordinal")
    if not isinstance(dll, str) or not dll:
        return None
    if isinstance(symbol, str) and symbol and ordinal is None:
        return MachineImportIdentity(dll.lower(), "symbol", symbol)
    if (
        symbol is None
        and isinstance(ordinal, int)
        and not isinstance(ordinal, bool)
        and ordinal >= 0
    ):
        return MachineImportIdentity(dll.lower(), "ordinal", ordinal)
    return None


def _external_target_memory_preserved(
    target: Mapping[str, Any],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
) -> bool:
    identity_source = target.get("import")
    identity = (
        _machine_import_identity(identity_source)
        if isinstance(identity_source, Mapping)
        else None
    )
    selected = import_abis.get(identity) if identity is not None else None
    contract = selected.contract if selected is not None else None
    return isinstance(contract, Mapping) and contract.get("memory_effect") in {
        "none",
        "read_only",
    }


def _prefer_indirect_recoveries(
    static_recoveries: Sequence[Mapping[str, Any]],
    *proposal_sets: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    proposals_by_id = [
        {str(row.get("id")): row for row in proposals}
        for proposals in proposal_sets
    ]
    result: list[dict[str, Any]] = []
    for static in static_recoveries:
        candidates = [
            candidate
            for candidate in (
                static,
                *(proposals.get(str(static.get("id"))) for proposals in proposals_by_id),
            )
            if isinstance(candidate, Mapping) and candidate.get("status") == "recovered"
        ]
        alternatives = {
            _target_alternatives(candidate) for candidate in candidates
        }
        if len(alternatives) > 1:
            selected: Mapping[str, Any] = {
                **dict(static),
                "status": "incomplete",
                "closure": "unresolved",
                "target_rvas": [],
                "target_unit_ids": [],
                "external_targets": [],
                "failure": {
                    "code": "conflicting_indirect_recovery_evidence",
                    "message": "independent finite target mechanisms disagree",
                },
            }
        else:
            # A recovered fact is authority-relevant and therefore keeps the
            # established source ordering.  Incomplete rows are diagnostic
            # only: prefer the latest analysis layer so the report retains the
            # actual failed expression/provenance check instead of the generic
            # static-replay placeholder.
            incomplete = [
                candidate
                for candidate in (
                    *(
                        proposals.get(str(static.get("id")))
                        for proposals in reversed(proposals_by_id)
                    ),
                    static,
                )
                if isinstance(candidate, Mapping)
                and candidate.get("status") != "recovered"
            ]
            selected = candidates[0] if candidates else incomplete[0]
        result.append(copy.deepcopy(dict(selected)))
    return result


def _freeze_recovery_inputs(
    recoveries: Sequence[Mapping[str, Any]],
) -> tuple[Hashable, ...]:
    return tuple(
        sorted(
            (_freeze_value(_recovery_projection(row)) for row in recoveries),
            key=repr,
        )
    )


def _call_site_effect_rows(
    operation_provenance: Mapping[str, Any],
) -> tuple[Mapping[str, Any], ...]:
    raw = operation_provenance.get("call_site_effects", [])
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ValueError("operation provenance call-site effects must be an array")
    if any(not isinstance(row, Mapping) for row in raw):
        raise ValueError("operation provenance call-site effect is not an object")
    return tuple(copy.deepcopy(dict(row)) for row in raw)


def _freeze_call_site_effects(
    effects: Sequence[Mapping[str, Any]],
) -> tuple[Hashable, ...]:
    return tuple(sorted((_freeze_value(row) for row in effects), key=repr))


def _inductive_reproduction_status(
    *,
    hypotheses: Sequence[Mapping[str, Any]],
    replay: _PassResult | None,
) -> dict[str, Any]:
    """Check that every finite recovery hypothesis is reproduced exactly.

    Hypotheses only expose control edges to the transfer adapters.  They do
    not inject register or memory values.  Exact reproduction therefore forms
    an assume/guarantee certificate: summaries may rely on the hypothesized
    edge while target provenance must independently reconstruct the same
    bounded target set from the rooted machine state.
    """

    expected = {
        str(row.get("id")): _freeze_value(_inductive_target_projection(row))
        for row in hypotheses
        if isinstance(row, Mapping)
        and isinstance(row.get("id"), str)
        and row.get("status") == "recovered"
    }
    if not expected:
        return {
            "status": "not_applicable",
            "reproduced_ids": [],
            "missing_ids": [],
            "mismatched_ids": [],
        }
    if replay is None:
        return {
            "status": "incomplete",
            "reproduced_ids": [],
            "missing_ids": sorted(expected),
            "mismatched_ids": [],
        }
    observed_rows = {
        str(row.get("id")): row
        for row in replay.recoveries
        if isinstance(row, Mapping)
        and isinstance(row.get("id"), str)
        and row.get("status") == "recovered"
    }
    observed = {
        identity: _freeze_value(_inductive_target_projection(row))
        for identity, row in observed_rows.items()
        if _has_inductive_origin_witnesses(row)
    }
    reproduced = sorted(
        identity
        for identity, projection in expected.items()
        if observed.get(identity) == projection
    )
    missing = sorted(set(expected) - set(observed))
    mismatched = sorted(
        identity
        for identity in set(expected) & set(observed)
        if expected[identity] != observed[identity]
    )
    return {
        "status": (
            "complete"
            if len(reproduced) == len(expected)
            else "incomplete"
        ),
        "reproduced_ids": reproduced,
        "missing_ids": missing,
        "mismatched_ids": mismatched,
    }


def _inductive_target_projection(row: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "id": row.get("id"),
        "kind": row.get("kind"),
        "recovery_kind": row.get("recovery_kind"),
        "source_unit_id": row.get("source_unit_id"),
        "source_rva": row.get("source_rva"),
        "source_event_index": row.get("source_event_index"),
        "target_expression": row.get("target_expression"),
        "target_rvas": row.get("target_rvas", []),
        "target_unit_ids": row.get("target_unit_ids", []),
        "external_targets": row.get("external_targets", []),
        "target_set_dependency": row.get("target_set_dependency"),
    }


def _has_inductive_origin_witnesses(row: Mapping[str, Any]) -> bool:
    if has_value_independent_target_set_v2(row):
        return True
    witnesses = row.get("target_origin_witnesses")
    count = row.get("origin_count")
    if (
        not isinstance(witnesses, list)
        or not witnesses
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count != len(witnesses)
    ):
        return False
    return all(
        isinstance(witness, Mapping)
        and isinstance(witness.get("kind"), str)
        and isinstance(witness.get("key"), list)
        for witness in witnesses
    )


def _recovery_projection(row: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "id": row.get("id"),
        "status": row.get("status"),
        "kind": row.get("kind"),
        "recovery_kind": row.get("recovery_kind"),
        "source_unit_id": row.get("source_unit_id"),
        "source_rva": row.get("source_rva"),
        "source_event_index": row.get("source_event_index"),
        "target_expression": row.get("target_expression"),
        "target_rvas": row.get("target_rvas", []),
        "target_unit_ids": row.get("target_unit_ids", []),
        "external_targets": row.get("external_targets", []),
        "target_origin_witnesses": row.get("target_origin_witnesses", []),
        "analysis_dependencies": row.get("analysis_dependencies", []),
        "authority_dependencies": row.get("authority_dependencies", []),
        "mutable_slot_dependencies": row.get("mutable_slot_dependencies", []),
        "target_set_dependency": row.get("target_set_dependency"),
        "failure": row.get("failure"),
    }


def _freeze_value(value: Any) -> Hashable:
    if value is None or isinstance(value, (bool, int, str, bytes)):
        return value
    if isinstance(value, Mapping):
        return (
            "mapping",
            tuple(
                (str(key), _freeze_value(item))
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            ),
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return ("sequence", tuple(_freeze_value(item) for item in value))
    if isinstance(value, (set, frozenset)):
        return ("set", tuple(sorted((_freeze_value(item) for item in value), key=repr)))
    raise TypeError(f"interprocedural facts cannot freeze {type(value).__name__}")


def _dependency_inventory(
    *,
    facts: Mapping[str, _NodeState],
    dependency_edges: frozenset[tuple[str, str]],
    decomposition: SCCDecomposition[str],
) -> list[dict[str, Any]]:
    dependencies: dict[str, list[str]] = defaultdict(list)
    for dependency, dependent in dependency_edges:
        dependencies[dependent].append(dependency)
    component_ids = {
        node: index
        for index, component in enumerate(decomposition.components)
        for node in component
    }
    result = []
    for node_id, state in sorted(facts.items()):
        result.append(
            {
                "id": node_id,
                "kind": (
                    "call_summary"
                    if node_id.startswith("call-summary:")
                    else "global_slot_invariant"
                    if node_id.startswith("global_slot_invariant:")
                    else "indirect_exit"
                ),
                "status": state.status,
                "lattice_complete": state.fact.complete,
                "fact": state.fact.project(),
                "dependencies": sorted(dependencies.get(node_id, [])),
                "scc_id": component_ids.get(node_id),
                "failure_reasons": list(state.failure_reasons),
            }
        )
    return result


def _recursive_components(
    decomposition: SCCDecomposition[str],
    dependency_edges: frozenset[tuple[str, str]],
) -> list[list[str]]:
    return [
        list(component)
        for component in decomposition.components
        if len(component) > 1
        or (
            bool(component)
            and (component[0], component[0]) in dependency_edges
        )
    ]


def _apply_lattice_failures(
    recoveries: tuple[Mapping[str, Any], ...],
    facts: Mapping[str, _NodeState],
    *,
    finite_value_budget: int,
) -> tuple[Mapping[str, Any], ...]:
    result: list[Mapping[str, Any]] = []
    for recovery in recoveries:
        identity = recovery.get("id")
        state = facts.get(identity) if isinstance(identity, str) else None
        if state is not None and not state.fact.complete:
            failure = recovery.get("failure")
            existing_code = (
                failure.get("code")
                if isinstance(failure, Mapping)
                and isinstance(failure.get("code"), str)
                else None
            )
            result.append(
                {
                    **copy.deepcopy(dict(recovery)),
                    "status": "incomplete",
                    "closure": "unresolved",
                    "target_rvas": [],
                    "target_unit_ids": [],
                    "external_targets": [],
                    "failure": {
                        "code": (
                            existing_code
                            if existing_code is not None
                            and existing_code.startswith("mutable_slot_")
                            else "finite_value_budget_exceeded"
                            if isinstance(state.fact.may_values, Top)
                            else "conflicting_interprocedural_exact_fact"
                        ),
                        "finite_value_budget": finite_value_budget,
                    },
                }
            )
        else:
            result.append(copy.deepcopy(dict(recovery)))
    return tuple(result)


def _fixed_point_failures(
    *,
    cold_converged: bool,
    lattice_complete: bool,
    reachable_targets_complete: bool,
) -> list[str]:
    failures: list[str] = []
    if not cold_converged:
        failures.append("cold_replay_fixed_point_incomplete")
    if not lattice_complete:
        failures.append("interprocedural_lattice_overflow_or_conflict")
    if not reachable_targets_complete:
        failures.append("reachable_indirect_targets_incomplete")
    return failures


def _reachable_targets_complete(
    *,
    units: Sequence[Mapping[str, Any]],
    roots: Sequence[str],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    recoveries: Sequence[Mapping[str, Any]],
) -> bool:
    """Check target closure only for exits reached by exact recovered edges."""

    by_id = {_unit_id(unit): unit for unit in units}
    successors = {
        source: set(targets)
        for source, targets in _normal_edges(direct_edges, by_id).items()
    }
    for source, targets in _explicit_call_edges(
        internal_call_edges, by_id
    ).items():
        successors.setdefault(source, set()).update(targets)
    recovery_by_id = {
        str(row.get("id")): row
        for row in recoveries
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    for recovery in recovery_by_id.values():
        if recovery.get("status") != "recovered":
            continue
        source = recovery.get("source_unit_id")
        if not isinstance(source, str) or source not in by_id:
            continue
        successors.setdefault(source, set()).update(
            target
            for target in recovery.get("target_unit_ids", ())
            if isinstance(target, str) and target in by_id
        )
    reachable: set[str] = set()
    pending = [root for root in roots if root in by_id]
    while pending:
        unit_id = pending.pop()
        if unit_id in reachable:
            continue
        reachable.add(unit_id)
        pending.extend(sorted(successors.get(unit_id, ()), reverse=True))
    for exit_row in indirect_exits:
        if exit_row.get("source_unit_id") not in reachable:
            continue
        recovery = recovery_by_id.get(str(exit_row.get("id")))
        if not isinstance(recovery, Mapping) or recovery.get("status") != "recovered":
            return False
        targets = recovery.get("target_unit_ids")
        external = recovery.get("external_targets")
        if (
            not isinstance(targets, list)
            or not isinstance(external, list)
            or not (targets or external)
            or any(target not in by_id for target in targets)
        ):
            return False
    return True


def _joined_status(left: str, right: str, lattice_complete: bool) -> str:
    if not lattice_complete:
        return "incomplete"
    if left == "complete" or right == "complete":
        return "complete"
    return "incomplete"


def _is_conflict_reason(reason: str) -> bool:
    lowered = reason.lower()
    return "conflict" in lowered or "ambiguous" in lowered


def _is_overflow_reason(reason: str) -> bool:
    lowered = reason.lower()
    return "budget" in lowered or "overflow" in lowered or "unbounded" in lowered


def _summary_node(unit_id: str) -> str:
    return f"call-summary:{unit_id}"


def _unit_id(unit: Mapping[str, Any]) -> str:
    return _required_string(unit, "id")


def _required_string(row: Mapping[str, Any], field: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"interprocedural analysis requires non-empty {field}")
    return value


def _unit_rva(unit: Mapping[str, Any]) -> int | None:
    source = unit.get("source")
    original = source.get("original") if isinstance(source, Mapping) else None
    rva = original.get("rva_start") if isinstance(original, Mapping) else None
    return rva if isinstance(rva, int) and not isinstance(rva, bool) else None


def _events(unit: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    semantics = unit.get("semantics")
    raw = semantics.get("external_events") if isinstance(semantics, Mapping) else None
    if not isinstance(raw, list):
        return ()
    return tuple(event for event in raw if isinstance(event, Mapping))


__all__ = [
    "INTERPROCEDURAL_ANALYSIS_FORMAT",
    "InterproceduralAnalysisResult",
    "analyze_interprocedural_control",
]
