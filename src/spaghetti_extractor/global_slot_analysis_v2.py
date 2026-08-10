"""Point-sensitive replay evidence for mutable 32-bit image slots.

The analyzer consumes exact machine-IR units and an already checked rooted
control graph.  It does not infer that stack or dynamic addresses are disjoint
from the image: symbolic accesses are excluded only by an event-bound spatial
fact whose rooted stack analysis is replayed before evidence promotion.
Legacy unit-wide range facts remain readable diagnostics but cannot authorize
an exclusion.

The emitted ``global_slot_evidence`` records are deliberately shaped for
``entry_state_analysis_v2.propose_global_slot_invariant``.  This module only
constructs replay evidence; the entry-state analyzer remains the authority that
promotes complete evidence to ``GlobalSlotInvariant`` records.

Authority-relevant slot facts are scoped to the state entering each required
read.  Process-wide write inventories remain deterministic diagnostics.
"""

from __future__ import annotations

import copy
import json
from collections import deque
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterable, Mapping, Sequence

from .address_expression_v2 import affine_register_offset
from .analysis_schema_v2 import (
    CHECKED_MEMORY_RANGE_FACT_V2_FORMAT,
    ROOTED_CONTROL_GRAPH_V2_FORMAT,
)
from .artifact_identity_v2 import canonical_sha256
from .authority_bindings_v2 import BinaryBinding
from .call_site_effects import (
    CallSiteEffect,
    CallSiteId,
    parse_call_site_effects,
)
from .checked_memory_access_v2 import (
    CheckedMemoryAccessFact,
    CheckedMemoryAccessV2Error,
    validate_checked_memory_access_facts_v2,
)
from .checked_memory_address_domain_v2 import (
    CheckedMemoryAddressDomain,
    CheckedMemoryAddressDomainV2Error,
    validate_checked_memory_address_domains_v2,
)
from .memory_range_invariants_v2 import validate_memory_range_invariants_v2
from .launch_memory_ranges_v2 import (
    validate_launch_memory_range_analysis_v2,
)
from .stack_range_analysis_v2 import (
    CHECKED_STACK_ORIGIN_SPATIAL_FACT_V2_FORMAT,
    CHECKED_STACK_SPATIAL_FACT_V2_FORMAT,
)


GLOBAL_SLOT_ANALYSIS_V2_FORMAT = "stage-a-global-slot-analysis-v2"
GLOBAL_SLOT_REPLAY_EVIDENCE_V2_FORMAT = "stage-a-global-slot-replay-evidence-v2"

_DIGEST_LENGTH = 64
_UINT32_LIMIT = 1 << 32
_MEMORY_KINDS = frozenset({"read", "write", "read_write"})
_DIAGNOSTIC_SITE_LIMIT = 32
_INDUCTIVE_GRAPH_FRONTIER_CODES = frozenset({
    "rooted_control_graph_incomplete",
    "indirect_exit_certificate_incomplete",
})


class GlobalSlotAnalysisV2Error(ValueError):
    """A caller option, rather than submitted evidence, is invalid."""


@dataclass(frozen=True, order=True)
class _Site:
    unit_id: str
    event_index: int
    instruction_rva: int | None

    def payload(self) -> dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            "event_index": self.event_index,
            "instruction_rva": self.instruction_rva,
        }


@dataclass(frozen=True)
class _Event:
    node_id: str
    site: _Site
    kind: str
    width: int | None
    address: Any
    value: Any
    raw: Mapping[str, Any]
    order_key: tuple[int, int, int]


@dataclass(frozen=True)
class _FlowState:
    reachable: bool = False
    initialized: bool = False
    tainted: bool = False
    overflow: bool = False
    alternatives: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Access:
    classification: str
    dependency_ids: tuple[str, ...] = ()
    reason: str | None = None


def analyze_global_slots_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    graph: Mapping[str, Any],
    candidate_slot_addresses: Sequence[int],
    image_base: int,
    size_of_image: int,
    entry_range_facts: Sequence[Mapping[str, Any]] = (),
    world_range_facts: Sequence[Mapping[str, Any]] = (),
    range_authority_binding: Mapping[str, Any] | None = None,
    relevant_read_dependencies: Sequence[Mapping[str, Any]] | None = None,
    launch_initial_values: Mapping[int, int] | None = None,
    checked_memory_access_facts: Sequence[Mapping[str, Any]] = (),
    checked_memory_address_domains: Sequence[Mapping[str, Any]] = (),
    call_site_effects: Sequence[Mapping[str, Any]] = (),
    checked_memory_spatial_facts: Sequence[Mapping[str, Any]] = (),
    launch_memory_range_analysis: Mapping[str, Any] | None = None,
    launch_assumptions: Mapping[str, Any] | None = None,
    memory_range_invariant_analysis: Mapping[str, Any] | None = None,
    pe_sha256: str | None = None,
    machine_ir_sha256: str | None = None,
    interprocedural_authority_sha256: str | None = None,
    alternative_budget: int = 32,
) -> dict[str, Any]:
    """Replay all rooted memory accesses for each candidate 4-byte slot.

    Missing proof evidence is reported as ``incomplete``.  Contradictory exact
    bindings and malformed authority inputs are ``violated``.  Analysis is run
    twice from an empty state; the cold replay digest binds the deterministic
    second result and must match the first result.
    """

    if (
        not isinstance(alternative_budget, int)
        or isinstance(alternative_budget, bool)
        or not 0 < alternative_budget <= 256
    ):
        raise GlobalSlotAnalysisV2Error(
            "alternative budget must be an integer between 1 and 256"
        )
    if not _u32(image_base) or not isinstance(size_of_image, int) or isinstance(
        size_of_image, bool
    ) or not 0 < size_of_image <= _UINT32_LIMIT:
        raise GlobalSlotAnalysisV2Error("image range is invalid")
    if image_base + size_of_image > _UINT32_LIMIT:
        raise GlobalSlotAnalysisV2Error("image range wraps the 32-bit address space")

    normalized_slots: list[int] = []
    option_issues: list[dict[str, Any]] = []
    for index, value in enumerate(candidate_slot_addresses):
        if not _u32(value) or value + 4 > _UINT32_LIMIT:
            option_issues.append(
                _issue("violated", "candidate_slot_address_invalid", index=index)
            )
            continue
        if not (image_base <= value and value + 4 <= image_base + size_of_image):
            option_issues.append(
                _issue(
                    "violated",
                    "candidate_slot_outside_image",
                    address=value,
                )
            )
            continue
        normalized_slots.append(value)
    if len(normalized_slots) != len(set(normalized_slots)):
        option_issues.append(_issue("violated", "candidate_slot_duplicated"))
    normalized_slots = sorted(set(normalized_slots))
    initial_values, initial_value_issues = _normalize_launch_initial_values(
        launch_initial_values,
        candidate_addresses=frozenset(normalized_slots),
    )
    normalized_units, unit_issues = _normalize_units(units)
    normalized_call_effects, call_effect_issues = _normalize_call_site_effects(
        call_site_effects,
        units=normalized_units,
        finite_value_budget=alternative_budget,
        interprocedural_authority_sha256=interprocedural_authority_sha256,
    )
    access_facts: dict[str, CheckedMemoryAccessFact] = {}
    address_domain_facts: dict[str, CheckedMemoryAddressDomain] = {}
    access_range_facts: dict[str, Mapping[str, Any]] = {}
    access_spatial_facts: dict[str, Mapping[str, Any]] = {}
    access_fact_issues: list[dict[str, Any]] = []
    if checked_memory_access_facts:
        if not all(
            _digest(value)
            for value in (
                pe_sha256,
                machine_ir_sha256,
                interprocedural_authority_sha256,
            )
        ):
            access_fact_issues.append(
                _issue("violated", "checked_memory_access_binding_missing")
            )
        else:
            try:
                access_facts = validate_checked_memory_access_facts_v2(
                    checked_memory_access_facts,
                    units=list(normalized_units.values()),
                    binary=BinaryBinding(
                        pe_sha256=str(pe_sha256),
                        machine_ir_sha256=str(machine_ir_sha256),
                    ),
                    interprocedural_authority_sha256=str(
                        interprocedural_authority_sha256
                    ),
                )
            except (CheckedMemoryAccessV2Error, ValueError) as exc:
                access_fact_issues.append(_issue(
                    "violated",
                    "checked_memory_access_fact_invalid",
                    reason=str(exc),
                ))
    if checked_memory_address_domains:
        if not all(
            _digest(value)
            for value in (
                pe_sha256,
                machine_ir_sha256,
                interprocedural_authority_sha256,
            )
        ):
            access_fact_issues.append(
                _issue("violated", "checked_memory_address_domain_binding_missing")
            )
        else:
            try:
                address_domain_facts = (
                    validate_checked_memory_address_domains_v2(
                        checked_memory_address_domains,
                        units=list(normalized_units.values()),
                        binary=BinaryBinding(
                            pe_sha256=str(pe_sha256),
                            machine_ir_sha256=str(machine_ir_sha256),
                        ),
                        interprocedural_authority_sha256=str(
                            interprocedural_authority_sha256
                        ),
                    )
                )
            except (CheckedMemoryAddressDomainV2Error, ValueError) as exc:
                access_fact_issues.append(_issue(
                    "violated",
                    "checked_memory_address_domain_invalid",
                    reason=str(exc),
                ))
    if memory_range_invariant_analysis is not None:
        if not _digest(pe_sha256) or not _digest(machine_ir_sha256):
            access_fact_issues.append(
                _issue("violated", "memory_range_invariant_binding_missing")
            )
        else:
            try:
                access_range_facts = validate_memory_range_invariants_v2(
                    memory_range_invariant_analysis,
                    units=list(normalized_units.values()),
                    binary_sha256=str(pe_sha256),
                    machine_ir_sha256=str(machine_ir_sha256),
                )
            except (TypeError, ValueError) as exc:
                access_fact_issues.append(_issue(
                    "violated",
                    "memory_range_invariant_analysis_invalid",
                    reason=str(exc),
                ))
    range_facts, range_issues = _normalize_range_facts(
        [
            *(('entry', fact) for fact in entry_range_facts),
            *(('world', fact) for fact in world_range_facts),
        ],
        image_base=image_base,
        size_of_image=size_of_image,
        known_units=frozenset(normalized_units),
        authority_binding=range_authority_binding,
    )
    spatial_facts, spatial_issues = _normalize_spatial_facts(
        checked_memory_spatial_facts,
        units=normalized_units,
        access_facts=access_facts,
        image_base=image_base,
        size_of_image=size_of_image,
        authority_binding=range_authority_binding,
    )
    launch_spatial_facts: list[dict[str, Any]] = []
    if launch_memory_range_analysis is not None:
        if (
            not isinstance(launch_assumptions, Mapping)
            or not _digest(pe_sha256)
            or not _digest(machine_ir_sha256)
        ):
            spatial_issues.append(_issue(
                "violated", "launch_memory_spatial_binding_missing"
            ))
        else:
            try:
                replayed_launch = validate_launch_memory_range_analysis_v2(
                    launch_memory_range_analysis,
                    units=list(normalized_units.values()),
                    launch_assumptions=launch_assumptions,
                    pe_sha256=str(pe_sha256),
                    machine_ir_sha256=str(machine_ir_sha256),
                    image_base=image_base,
                    size_of_image=size_of_image,
                )
                launch_spatial_facts = [
                    copy.deepcopy(dict(row))
                    for row in replayed_launch.values()
                ]
            except (TypeError, ValueError) as exc:
                spatial_issues.append(_issue(
                    "violated",
                    "launch_memory_spatial_analysis_invalid",
                    reason=str(exc),
                ))
    spatial_facts = sorted(
        [*spatial_facts, *launch_spatial_facts],
        key=lambda row: (
            str(row["unit_id"]), int(row["event_index"]), str(row["id"])
        ),
    )
    access_spatial_facts = {
        _event_node(str(row["unit_id"]), int(row["event_index"])): row
        for row in spatial_facts
    }
    if len(access_spatial_facts) != len(spatial_facts):
        spatial_issues.append(_issue(
            "violated", "checked_memory_spatial_event_duplicated"
        ))
    graph_info, graph_issues = _normalize_graph(graph, normalized_units)
    relevant_reads, relevant_read_issues = _normalize_relevant_reads(
        relevant_read_dependencies,
        units=normalized_units,
        image_base=image_base,
        candidate_addresses=frozenset(normalized_slots),
        access_facts=access_facts,
        address_domain_facts=address_domain_facts,
    )
    global_issues = _deduplicate_issues(
        [
            *option_issues,
            *unit_issues,
            *access_fact_issues,
            *call_effect_issues,
            *range_issues,
            *spatial_issues,
            *graph_issues,
            *relevant_read_issues,
            *initial_value_issues,
        ]
    )
    inductive_graph_frontiers = [
        issue
        for issue in global_issues
        if issue.get("code") in _INDUCTIVE_GRAPH_FRONTIER_CODES
        and issue.get("status") == "incomplete"
    ]
    slot_replay_issues = [
        issue for issue in global_issues if issue not in inductive_graph_frontiers
    ]

    first = _analyze_once(
        units=normalized_units,
        graph_info=graph_info,
        slots=normalized_slots,
        access_facts=access_facts,
        address_domain_facts=address_domain_facts,
        access_range_facts=access_range_facts,
        access_spatial_facts=access_spatial_facts,
        alternative_budget=alternative_budget,
        global_issues=slot_replay_issues,
        inductive_graph_frontiers=inductive_graph_frontiers,
        relevant_reads=relevant_reads,
        launch_initial_values=initial_values,
        call_site_effects=normalized_call_effects,
        interprocedural_authority_sha256=interprocedural_authority_sha256,
    )
    first_bytes = _canonical_json(first).encode("ascii")
    first_digest = sha256(first_bytes).hexdigest()
    del first
    second = _analyze_once(
        units=normalized_units,
        graph_info=graph_info,
        slots=normalized_slots,
        access_facts=access_facts,
        address_domain_facts=address_domain_facts,
        access_range_facts=access_range_facts,
        access_spatial_facts=access_spatial_facts,
        alternative_budget=alternative_budget,
        global_issues=slot_replay_issues,
        inductive_graph_frontiers=inductive_graph_frontiers,
        relevant_reads=relevant_reads,
        launch_initial_values=initial_values,
        call_site_effects=normalized_call_effects,
        interprocedural_authority_sha256=interprocedural_authority_sha256,
    )
    second_digest = canonical_sha256(second)
    del second
    first = json.loads(first_bytes)
    cold_status = "complete" if first_digest == second_digest else "violated"
    if cold_status == "violated":
        global_issues = _deduplicate_issues(
            [*global_issues, _issue("violated", "cold_replay_mismatch")]
        )

    evidence_rows: list[dict[str, Any]] = []
    slot_results: list[dict[str, Any]] = []
    for row in first["slots"]:
        evidence = copy.deepcopy(row["evidence"])
        evidence["cold_replay_sha256"] = second_digest
        evidence_rows.append(evidence)
        slot_results.append(
            {
                **copy.deepcopy(row),
                "evidence": evidence,
            }
        )

    issues = _deduplicate_issues(
        [
            *global_issues,
            *(
                [_issue("violated", "cold_replay_mismatch")]
                if cold_status == "violated"
                else []
            ),
        ]
    )
    slot_statuses = [str(row["status"]) for row in slot_results]
    status = _aggregate_status([*slot_statuses, *[str(i["status"]) for i in issues]])
    result = {
        "format": GLOBAL_SLOT_ANALYSIS_V2_FORMAT,
        "status": status,
        "bindings": {
            "image_base": image_base,
            "size_of_image": size_of_image,
            "machine_ir_sha256": first["machine_ir_sha256"],
            "rooted_graph_sha256": first["rooted_graph_sha256"],
            "interprocedural_authority_sha256": (
                interprocedural_authority_sha256
                if (
                    checked_memory_access_facts
                    or checked_memory_address_domains
                    or call_site_effects
                )
                else None
            ),
        },
        "counts": {
            "units": len(normalized_units),
            "reachable_units": len(graph_info["reachable_units"]),
            "candidate_slots": len(normalized_slots),
            "launch_initialized_slots": len(initial_values),
            "complete_slots": sum(value == "complete" for value in slot_statuses),
            "incomplete_slots": sum(value == "incomplete" for value in slot_statuses),
            "violated_slots": sum(value == "violated" for value in slot_statuses),
            "checked_memory_access_facts": len(access_facts),
            "checked_memory_address_domains": len(address_domain_facts),
            "call_site_effects": len(normalized_call_effects),
            "checked_memory_address_ranges": len(access_range_facts),
            "checked_memory_spatial_facts": len(access_spatial_facts),
        },
        "checked_memory_access_facts": [
            fact.to_payload() for fact in access_facts.values()
        ],
        "checked_memory_address_domains": [
            domain.to_payload() for domain in address_domain_facts.values()
        ],
        "call_site_effects": [
            effect.as_json()
            for effect in normalized_call_effects.values()
        ],
        "checked_memory_spatial_facts": spatial_facts,
        "memory_range_invariant_analysis": (
            None
            if memory_range_invariant_analysis is None
            else copy.deepcopy(dict(memory_range_invariant_analysis))
        ),
        "global_slot_evidence": evidence_rows,
        "slots": slot_results,
        "cold_replay": {
            "status": cold_status,
            "unseeded": True,
            "first_sha256": first_digest,
            "replay_sha256": second_digest,
        },
        "issues": issues,
    }
    result["analysis_sha256"] = canonical_sha256(result)
    return result


def _analyze_once(
    *,
    units: Mapping[str, Mapping[str, Any]],
    graph_info: Mapping[str, Any],
    slots: Sequence[int],
    access_facts: Mapping[str, CheckedMemoryAccessFact],
    address_domain_facts: Mapping[str, CheckedMemoryAddressDomain],
    access_range_facts: Mapping[str, Mapping[str, Any]],
    access_spatial_facts: Mapping[str, Mapping[str, Any]],
    alternative_budget: int,
    global_issues: Sequence[Mapping[str, Any]],
    inductive_graph_frontiers: Sequence[Mapping[str, Any]],
    relevant_reads: Mapping[int, Mapping[str, Any]] | None,
    launch_initial_values: Mapping[int, int],
    call_site_effects: Mapping[CallSiteId, CallSiteEffect],
    interprocedural_authority_sha256: str | None,
) -> dict[str, Any]:
    reachable = frozenset(str(value) for value in graph_info["reachable_units"])
    events = _events(
        units,
        reachable,
        call_site_effects=call_site_effects,
        interprocedural_authority_sha256=interprocedural_authority_sha256,
    )
    event_graph = _event_graph(
        units=units,
        reachable=reachable,
        roots=graph_info["roots"],
        successors=graph_info["successors"],
        events=events,
    )
    machine_ir_sha256 = canonical_sha256(
        [units[unit_id] for unit_id in sorted(units)]
    )
    machine_ir_dependency = {
        "kind": "machine_ir_inventory",
        "id": f"machine-ir:{machine_ir_sha256}",
        "sha256": machine_ir_sha256,
    }
    graph_dependency = {
        "kind": "rooted_control_graph",
        "id": str(graph_info["graph_id"]),
        "sha256": str(graph_info["graph_sha256"]),
    }

    rows = [
        _analyze_slot(
            address=address,
            events=events,
            event_graph=event_graph,
            access_facts=access_facts,
            address_domain_facts=address_domain_facts,
            access_range_facts=access_range_facts,
            access_spatial_facts=access_spatial_facts,
            alternative_budget=alternative_budget,
            machine_ir_dependency=machine_ir_dependency,
            graph_dependency=graph_dependency,
            root_kinds=graph_info["root_kinds"],
            global_issues=_issues_for_slot(global_issues, address=address),
            inductive_graph_frontiers=inductive_graph_frontiers,
            relevant_read_dependency=(
                None if relevant_reads is None else relevant_reads.get(address)
            ),
            relevant_read_inventory_explicit=relevant_reads is not None,
            launch_initial_value=launch_initial_values.get(address),
        )
        for address in slots
    ]
    return {
        "machine_ir_sha256": machine_ir_sha256,
        "rooted_graph_sha256": graph_info["graph_sha256"],
        "slots": rows,
    }


def _analyze_slot(
    *,
    address: int,
    events: Mapping[str, _Event],
    event_graph: Mapping[str, Any],
    access_facts: Mapping[str, CheckedMemoryAccessFact],
    address_domain_facts: Mapping[str, CheckedMemoryAddressDomain],
    access_range_facts: Mapping[str, Mapping[str, Any]],
    access_spatial_facts: Mapping[str, Mapping[str, Any]],
    alternative_budget: int,
    machine_ir_dependency: Mapping[str, Any],
    graph_dependency: Mapping[str, Any],
    root_kinds: Mapping[str, str],
    global_issues: Sequence[Mapping[str, Any]],
    inductive_graph_frontiers: Sequence[Mapping[str, Any]],
    relevant_read_dependency: Mapping[str, Any] | None,
    relevant_read_inventory_explicit: bool,
    launch_initial_value: int | None,
) -> dict[str, Any]:
    accesses: dict[str, _Access] = {}
    used_fact_ids: set[str] = set()
    used_interprocedural_authority: set[str] = set()
    exact_write_values: dict[str, list[Any]] = {}
    overflow_writes: set[str] = set()
    for node_id, event in sorted(events.items()):
        access = _classify_access(
            event,
            slot_address=address,
            checked_domain=address_domain_facts.get(node_id),
            checked_fact=access_facts.get(node_id),
            checked_range=access_range_facts.get(node_id),
            checked_spatial=access_spatial_facts.get(node_id),
        )
        accesses[node_id] = access
        used_fact_ids.update(access.dependency_ids)
        authority_sha256 = event.raw.get(
            "interprocedural_authority_sha256"
        )
        if access.classification != "disjoint" and _digest(authority_sha256):
            used_interprocedural_authority.add(str(authority_sha256))
        if event.kind in {"write", "read_write"} and access.classification == "exact":
            alternatives = _event_alternatives(event.value, event.raw)
            if alternatives is None:
                accesses[node_id] = _Access(
                    "unknown",
                    access.dependency_ids,
                    "write_value_not_finite",
                )
            else:
                exact_write_values[node_id] = alternatives
                if len(alternatives) > alternative_budget:
                    overflow_writes.add(node_id)

    flow = _flow_replay(
        event_graph=event_graph,
        events=events,
        accesses=accesses,
        exact_write_values=exact_write_values,
        alternative_budget=alternative_budget,
        initial_alternatives=(
            ()
            if launch_initial_value is None
            else ({
                "kind": "exact_bits",
                "value": launch_initial_value,
                "width_bits": 32,
            },)
        ),
    )

    exact_writes = sorted(
        node_id
        for node_id, event in events.items()
        if event.kind in {"write", "read_write"}
        and accesses[node_id].classification == "exact"
        and node_id in exact_write_values
    )
    unknown_writes = sorted(
        node_id
        for node_id, event in events.items()
        if event.kind in {"write", "read_write"}
        and accesses[node_id].classification == "unknown"
    )
    aliasing_writes = sorted(
        node_id
        for node_id, event in events.items()
        if event.kind in {"write", "read_write"}
        and accesses[node_id].classification == "alias"
    )
    requested_relevant_reads: list[str] = []
    if relevant_read_inventory_explicit:
        requested_relevant_reads = sorted(
            str(node_id)
            for node_id in (
                ()
                if relevant_read_dependency is None
                else relevant_read_dependency.get("node_ids", ())
            )
            if isinstance(node_id, str)
        )
        relevant_reads = [
            node_id for node_id in requested_relevant_reads if node_id in events
        ]
    else:
        relevant_reads = sorted(
            node_id
            for node_id, event in events.items()
            if event.kind in {"read", "read_write"}
            and accesses[node_id].classification
            in {"exact", "conditional_exact", "alias", "unknown"}
        )
    missing_relevant_reads = sorted(
        set(requested_relevant_reads).difference(relevant_reads)
    )

    initializer = (
        None
        if launch_initial_value is not None
        else _common_dominating_write(
            event_graph=event_graph,
            candidate_writes=exact_writes,
            relevant_reads=relevant_reads,
        )
    )

    read_provenance = {
        node_id: _reaching_write_provenance(
            node_id=node_id,
            event_graph=event_graph,
            events=events,
            accesses=accesses,
            exact_write_values=exact_write_values,
        )
        for node_id in relevant_reads
    }

    issues: list[dict[str, Any]] = [copy.deepcopy(dict(issue)) for issue in global_issues]
    if not flow["converged"]:
        issues.append(_issue("incomplete", "global_slot_replay_did_not_converge"))
    if launch_initial_value is None and not exact_writes:
        issues.append(_issue("incomplete", "global_slot_exact_write_missing"))
    if relevant_read_inventory_explicit and relevant_read_dependency is None:
        issues.append(
            _issue("incomplete", "global_slot_relevant_read_inventory_missing")
        )
    if missing_relevant_reads:
        issues.append(
            _issue(
                "incomplete",
                "global_slot_relevant_read_unreachable",
                node_ids=missing_relevant_reads[:_DIAGNOSTIC_SITE_LIMIT],
                node_count=len(missing_relevant_reads),
            )
        )

    base_read_issues = _deduplicate_issues(issues)
    read_details: dict[str, dict[str, Any]] = {}
    read_frontiers: dict[str, list[str]] = {}
    reaching_exact_writes: set[str] = set()
    reaching_unknown_writes: set[str] = set()
    reaching_aliasing_writes: set[str] = set()
    overflow_reads: list[str] = []
    uninitialized_reads: list[str] = []
    for node_id in relevant_reads:
        state = flow["in_states"].get(node_id, _FlowState())
        provenance = read_provenance[node_id]
        local_issues: list[dict[str, Any]] = []
        provenance_tainted = bool(
            provenance["unknown_writes"] or provenance["aliasing_writes"]
        )
        provenance_alternatives = {
            _canonical_json(alternative)
            for write_node in provenance["writes"]
            for alternative in exact_write_values[write_node]
        }
        if launch_initial_value is not None and provenance["launch_reaches"]:
            provenance_alternatives.add(
                _canonical_json({
                    "kind": "exact_bits",
                    "value": launch_initial_value,
                    "width_bits": 32,
                })
            )
        if flow["converged"] and (
            state.tainted != provenance_tainted
            or (
                not state.overflow
                and tuple(sorted(provenance_alternatives)) != state.alternatives
            )
        ):
            local_issues.append(
                _issue(
                    "violated",
                    "global_slot_read_replay_provenance_mismatch",
                    site=events[node_id].site.payload(),
                )
            )
        if not state.reachable:
            local_issues.append(
                _issue(
                    "incomplete",
                    "global_slot_relevant_read_unreachable",
                    site=events[node_id].site.payload(),
                )
            )
        if not state.initialized:
            uninitialized_reads.append(node_id)
            root_kind = _uninitialized_callback_root_kind(
                node_id=node_id,
                event_graph=event_graph,
                root_kinds=root_kinds,
            )
            code = (
                "callback_entry_global_slot_invariant_missing"
                if root_kind == "callback"
                else "global_slot_read_before_dominated_initialization"
            )
            read_frontiers.setdefault(code, []).append(node_id)
            local_issues.append(
                _issue("incomplete", code, site=events[node_id].site.payload())
            )
        if state.tainted or provenance_tainted:
            read_frontiers.setdefault(
                "global_slot_read_reached_by_tainted_value", []
            ).append(node_id)
            local_issues.append(
                _issue(
                    "incomplete",
                    "global_slot_read_reached_by_tainted_value",
                    site=events[node_id].site.payload(),
                )
            )
        if state.overflow:
            overflow_reads.append(node_id)
            local_issues.append(
                _issue(
                    "incomplete",
                    "global_slot_alternative_budget_exceeded",
                    site=events[node_id].site.payload(),
                    budget=alternative_budget,
                )
            )
        if accesses[node_id].classification not in {
            "exact",
            "conditional_exact",
        }:
            read_frontiers.setdefault(
                "global_slot_read_alias_unresolved", []
            ).append(node_id)
            local_issues.append(
                _issue(
                    "incomplete",
                    "global_slot_read_alias_unresolved",
                    site=events[node_id].site.payload(),
                    classification=accesses[node_id].classification,
                )
            )
        read_issues = _deduplicate_issues([*base_read_issues, *local_issues])
        read_details[node_id] = {
            "state": state,
            "provenance": provenance,
            "status": _aggregate_status(
                str(issue["status"]) for issue in read_issues
            ),
            "issues": read_issues,
        }
        reaching_exact_writes.update(provenance["writes"])
        reaching_unknown_writes.update(provenance["unknown_writes"])
        reaching_aliasing_writes.update(provenance["aliasing_writes"])

    if reaching_unknown_writes:
        issues.append(
            _issue(
                "incomplete",
                "global_slot_unknown_write_taint",
                sites=[
                    events[node].site.payload()
                    for node in sorted(reaching_unknown_writes)[
                        :_DIAGNOSTIC_SITE_LIMIT
                    ]
                ],
                site_count=len(reaching_unknown_writes),
            )
        )
    if reaching_aliasing_writes:
        issues.append(
            _issue(
                "incomplete",
                "global_slot_aliasing_write_taint",
                sites=[
                    events[node].site.payload()
                    for node in sorted(reaching_aliasing_writes)[
                        :_DIAGNOSTIC_SITE_LIMIT
                    ]
                ],
                site_count=len(reaching_aliasing_writes),
            )
        )
    if overflow_reads:
        issues.append(
            _issue(
                "incomplete",
                "global_slot_alternative_budget_exceeded",
                budget=alternative_budget,
                sites=[
                    events[node].site.payload()
                    for node in overflow_reads[:_DIAGNOSTIC_SITE_LIMIT]
                ],
                site_count=len(overflow_reads),
            )
        )
    if uninitialized_reads and launch_initial_value is None:
        issues.append(
            _issue(
                "incomplete",
                "global_slot_initialization_does_not_dominate_reads",
                reads=[
                    events[node].site.payload()
                    for node in uninitialized_reads[:_DIAGNOSTIC_SITE_LIMIT]
                ],
                read_count=len(uninitialized_reads),
            )
        )
    for code, nodes in sorted(read_frontiers.items()):
        issues.append(
            _issue(
                "incomplete",
                code,
                sites=[
                    events[node].site.payload()
                    for node in nodes[:_DIAGNOSTIC_SITE_LIMIT]
                ],
                site_count=len(nodes),
                classifications=sorted({
                    accesses[node].classification for node in nodes
                }),
            )
        )
    issues = _deduplicate_issues(issues)
    status = _aggregate_status(str(issue["status"]) for issue in issues)

    launch_alternatives = (
        []
        if launch_initial_value is None
        else [{
            "kind": "exact_bits",
            "value": launch_initial_value,
            "width_bits": 32,
        }]
    )
    alternatives = _deduplicate_json([
        *launch_alternatives,
        *(
            alternative
            for node_id in exact_writes
            for alternative in exact_write_values[node_id]
        ),
    ])
    dependencies = [graph_dependency, machine_ir_dependency]
    access_by_id = {
        fact.fact_id: fact.to_payload() for fact in access_facts.values()
    }
    dependencies.extend(
        {
            "kind": "checked_memory_access_fact",
            "id": identity,
            "sha256": str(access_by_id[identity]["fact_sha256"]),
        }
        for identity in sorted(used_fact_ids)
        if identity in access_by_id
    )
    domain_by_id = {
        domain.domain_id: domain.to_payload()
        for domain in address_domain_facts.values()
    }
    dependencies.extend(
        {
            "kind": "checked_memory_address_domain",
            "id": identity,
            "sha256": str(domain_by_id[identity]["domain_sha256"]),
        }
        for identity in sorted(used_fact_ids)
        if identity in domain_by_id
    )
    dependencies.extend(
        {
            "kind": "interprocedural_authority",
            "id": f"interprocedural-authority:{identity}",
            "sha256": identity,
        }
        for identity in sorted(used_interprocedural_authority)
    )
    access_range_by_id = {
        str(fact["id"]): fact for fact in access_range_facts.values()
    }
    dependencies.extend(
        {
            "kind": "checked_memory_address_range",
            "id": identity,
            "sha256": str(access_range_by_id[identity]["fact_sha256"]),
        }
        for identity in sorted(used_fact_ids)
        if identity in access_range_by_id
    )
    access_spatial_by_id = {
        str(fact["id"]): fact for fact in access_spatial_facts.values()
    }
    dependencies.extend(
        {
            "kind": "checked_memory_spatial_fact",
            "id": identity,
            "sha256": str(access_spatial_by_id[identity]["fact_sha256"]),
        }
        for identity in sorted(used_fact_ids)
        if identity in access_spatial_by_id
    )
    dependencies = sorted(dependencies, key=lambda row: (str(row["kind"]), str(row["id"])))

    process_global_inventory_incomplete = bool(
        unknown_writes
        or aliasing_writes
        or overflow_writes
        or flow["overflow"]
    )
    diagnostic_only = status != "complete" or process_global_inventory_incomplete
    selected_exact_writes = sorted(
        set(
            exact_writes[:_DIAGNOSTIC_SITE_LIMIT]
            if diagnostic_only
            else exact_writes
        )
        | reaching_exact_writes
    )
    selected_unknown_writes = sorted(
        set(
            unknown_writes[:_DIAGNOSTIC_SITE_LIMIT]
            if diagnostic_only
            else unknown_writes
        )
        | reaching_unknown_writes
    )
    selected_aliasing_writes = sorted(
        set(
            aliasing_writes[:_DIAGNOSTIC_SITE_LIMIT]
            if diagnostic_only
            else aliasing_writes
        )
        | reaching_aliasing_writes
    )
    # Required-read evidence is authority-bearing and must never be truncated.
    selected_reads = relevant_reads
    writes_payload = [
        {
            "site": events[node_id].site.payload(),
            "classification": (
                "initializer"
                if node_id == initializer
                else "bounded_alternatives"
            ),
            "alternatives": copy.deepcopy(exact_write_values[node_id]),
        }
        for node_id in selected_exact_writes
    ]
    unknown_payload = [
        _access_payload(events[node_id], accesses[node_id])
        for node_id in selected_unknown_writes
    ]
    alias_payload = [
        _access_payload(events[node_id], accesses[node_id])
        for node_id in selected_aliasing_writes
    ]
    incoming_payloads: dict[str, dict[str, Any]] = {}
    for node_id in selected_reads:
        detail = read_details[node_id]
        state = detail["state"]
        provenance = detail["provenance"]
        incoming_payloads[node_id] = {
            "status": detail["status"],
            **_state_payload(state),
            "launch_initializer": (
                {
                    "kind": "launch_image",
                    "address": address,
                    "value_origin": copy.deepcopy(launch_alternatives[0]),
                }
                if launch_initial_value is not None
                and provenance["launch_reaches"]
                else None
            ),
            "writes": [
                {
                    "site": events[write_node].site.payload(),
                    "classification": (
                        "initializer"
                        if write_node == initializer
                        else "bounded_alternatives"
                    ),
                    "alternatives": copy.deepcopy(exact_write_values[write_node]),
                    "dependencies": list(accesses[write_node].dependency_ids),
                }
                for write_node in provenance["writes"]
            ],
            "unknown_writes": [
                _access_payload(events[write_node], accesses[write_node])
                for write_node in provenance["unknown_writes"]
            ],
            "aliasing_writes": [
                _access_payload(events[write_node], accesses[write_node])
                for write_node in provenance["aliasing_writes"]
            ],
            "issues": copy.deepcopy(detail["issues"]),
        }
    read_payload = [
        {
            "site": events[node_id].site.payload(),
            "dominated_by": (
                {
                    "kind": "launch_image",
                    "address": address,
                }
                if launch_initial_value is not None
                else events[initializer].site.payload()
                if initializer is not None
                else None
            ),
            "incoming": copy.deepcopy(incoming_payloads[node_id]),
        }
        for node_id in selected_reads
    ]
    read_inventory = [
        {
            "site": events[node_id].site.payload(),
            "classification": accesses[node_id].classification,
            "state": _state_payload(flow["in_states"].get(node_id, _FlowState())),
            "dependencies": list(accesses[node_id].dependency_ids),
            "status": read_details[node_id]["status"],
            "reaching_write_inventory": {
                key: copy.deepcopy(incoming_payloads[node_id][key])
                for key in ("writes", "unknown_writes", "aliasing_writes")
            },
        }
        for node_id in selected_reads
    ]
    evidence = {
        "format": GLOBAL_SLOT_REPLAY_EVIDENCE_V2_FORMAT,
        "address": address,
        "width": 4,
        "analysis_status": status,
        "authority_basis": "per_required_read_incoming",
        "launch_initializer": (
            None
            if launch_initial_value is None
            else {
                "kind": "launch_image",
                "address": address,
                "value_origin": launch_alternatives[0],
            }
        ),
        "reachable_write_inventory": {
            "status": (
                "complete"
                if status == "complete" and not process_global_inventory_incomplete
                else "incomplete"
            ),
            "scope": "process_global_diagnostic",
            "writes": writes_payload,
            "unknown_writes": unknown_payload,
            "aliasing_writes": alias_payload,
        },
        "relevant_reads": read_payload,
        "target_dependencies": (
            []
            if relevant_read_dependency is None
            else copy.deepcopy(
                list(relevant_read_dependency.get("target_dependencies", ()))
            )
        ),
        "read_inventory": read_inventory,
        "alternatives": alternatives,
        "dependencies": dependencies,
        "inductive_control_frontiers": [
            copy.deepcopy(dict(issue)) for issue in inductive_graph_frontiers
        ],
        "final_authorization_condition": (
            "every required read must have complete incoming evidence, and "
            "the unseeded joint fixed point must close the rooted control graph"
        ),
        "diagnostic_inventory": {
            "truncated": diagnostic_only and any(
                len(values) > _DIAGNOSTIC_SITE_LIMIT
                for values in (
                    exact_writes,
                    unknown_writes,
                    aliasing_writes,
                )
            ),
            "limit": _DIAGNOSTIC_SITE_LIMIT,
            "process_global_tainted": bool(unknown_writes or aliasing_writes),
            "process_global_overflow": bool(overflow_writes or flow["overflow"]),
            "counts": {
                "exact_writes": len(exact_writes),
                "unknown_writes": len(unknown_writes),
                "aliasing_writes": len(aliasing_writes),
                "relevant_reads": len(relevant_reads),
                "read_reaching_exact_writes": len(reaching_exact_writes),
                "read_reaching_unknown_writes": len(reaching_unknown_writes),
                "read_reaching_aliasing_writes": len(reaching_aliasing_writes),
            },
        },
    }
    return {
        "address": address,
        "status": status,
        "tainted": any(detail["state"].tainted for detail in read_details.values()),
        "evidence": evidence,
        "issues": issues,
    }


def _normalize_units(
    units: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Mapping[str, Any]], list[dict[str, Any]]]:
    result: dict[str, Mapping[str, Any]] = {}
    issues: list[dict[str, Any]] = []
    for index, raw in enumerate(units):
        if not isinstance(raw, Mapping):
            issues.append(_issue("violated", "machine_ir_unit_malformed", index=index))
            continue
        unit = copy.deepcopy(dict(raw))
        unit_id = unit.get("id")
        source_value = unit.get("source")
        source = source_value if isinstance(source_value, Mapping) else None
        original = source.get("original") if source is not None else None
        semantics = unit.get("semantics")
        if not isinstance(unit_id, str) or not unit_id:
            issues.append(_issue("violated", "machine_ir_unit_id_invalid", index=index))
            continue
        if unit_id in result:
            issues.append(_issue("violated", "machine_ir_unit_id_duplicated", unit_id=unit_id))
            continue
        if (
            not isinstance(original, Mapping)
            or not _u32(original.get("rva_start"))
            or not isinstance(original.get("rva_end"), int)
            or isinstance(original.get("rva_end"), bool)
            or not original["rva_start"] < original["rva_end"] <= _UINT32_LIMIT
            or source is None
            or not _digest(source.get("contract_sha256"))
            or not _digest(source.get("instruction_bytes_sha256"))
            or not isinstance(semantics, Mapping)
            or not isinstance(semantics.get("memory_events"), list)
        ):
            issues.append(_issue("violated", "machine_ir_unit_binding_invalid", unit_id=unit_id))
            continue
        for event_index, event in enumerate(semantics["memory_events"]):
            if (
                not isinstance(event, Mapping)
                or event.get("kind") not in _MEMORY_KINDS
                or not isinstance(event.get("width"), int)
                or isinstance(event.get("width"), bool)
                or event["width"] <= 0
                or "address" not in event
            ):
                issues.append(
                    _issue(
                        "violated",
                        "machine_ir_memory_event_invalid",
                        unit_id=unit_id,
                        event_index=event_index,
                    )
                )
        result[unit_id] = unit
    return dict(sorted(result.items())), _deduplicate_issues(issues)


def _normalize_call_site_effects(
    rows: Sequence[Mapping[str, Any]],
    *,
    units: Mapping[str, Mapping[str, Any]],
    finite_value_budget: int,
    interprocedural_authority_sha256: str | None,
) -> tuple[dict[CallSiteId, CallSiteEffect], list[dict[str, Any]]]:
    if not rows:
        return {}, []
    if not _digest(interprocedural_authority_sha256):
        return {}, [_issue("violated", "call_site_effect_authority_binding_missing")]
    try:
        parsed = parse_call_site_effects(
            rows,
            finite_value_budget=finite_value_budget,
        )
    except (TypeError, ValueError) as exc:
        return {}, [_issue(
            "violated",
            "call_site_effect_inventory_invalid",
            reason=str(exc),
        )]

    issues: list[dict[str, Any]] = []
    accepted: dict[CallSiteId, CallSiteEffect] = {}
    for site, effect in sorted(
        parsed.items(), key=lambda item: (item[0].unit_id, item[0].event_index)
    ):
        unit = units.get(site.unit_id)
        semantics = unit.get("semantics") if isinstance(unit, Mapping) else None
        external_events = (
            semantics.get("external_events")
            if isinstance(semantics, Mapping)
            else None
        )
        if (
            not isinstance(external_events, list)
            or not 0 <= site.event_index < len(external_events)
            or not isinstance(external_events[site.event_index], Mapping)
            or external_events[site.event_index].get("kind")
            != effect.transfer_kind
        ):
            issues.append(_issue(
                "violated",
                "call_site_effect_event_binding_invalid",
                unit_id=site.unit_id,
                event_index=site.event_index,
            ))
            continue
        accepted[site] = effect
    return accepted, _deduplicate_issues(issues)


def _normalize_launch_initial_values(
    values: Mapping[int, int] | None,
    *,
    candidate_addresses: frozenset[int],
) -> tuple[dict[int, int], list[dict[str, Any]]]:
    if values is None:
        return {}, []
    if not isinstance(values, Mapping):
        return {}, [_issue("violated", "launch_slot_inventory_corrupt")]
    result: dict[int, int] = {}
    issues: list[dict[str, Any]] = []
    for address, value in values.items():
        if (
            not _u32(address)
            or address not in candidate_addresses
            or not _u32(value)
        ):
            issues.append(
                _issue(
                    "violated",
                    "launch_slot_value_invalid",
                    address=address,
                )
            )
            continue
        result[int(address)] = int(value)
    return dict(sorted(result.items())), _deduplicate_issues(issues)


def _normalize_relevant_reads(
    rows: Sequence[Mapping[str, Any]] | None,
    *,
    units: Mapping[str, Mapping[str, Any]],
    image_base: int,
    candidate_addresses: frozenset[int],
    access_facts: Mapping[str, CheckedMemoryAccessFact],
    address_domain_facts: Mapping[str, CheckedMemoryAddressDomain],
) -> tuple[dict[int, Mapping[str, Any]] | None, list[dict[str, Any]]]:
    """Check target-to-slot read dependencies against exact memory events."""

    if rows is None:
        return None, []
    grouped: dict[int, dict[str, Any]] = {}
    issues: list[dict[str, Any]] = []
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            issues.append(
                _issue("violated", "relevant_slot_read_dependency_malformed", index=index)
            )
            continue
        slot_rva = raw.get("slot_rva")
        unit_id = raw.get("unit_id")
        event_index = raw.get("event_index")
        exit_id = raw.get("exit_id")
        witness_only = raw.get("witness_only") is True
        if (
            not isinstance(slot_rva, int)
            or isinstance(slot_rva, bool)
            or slot_rva < 0
            or image_base + slot_rva not in candidate_addresses
        ):
            issues.append(
                _issue("violated", "relevant_slot_read_dependency_invalid", index=index)
            )
            continue
        address = image_base + slot_rva
        if not isinstance(exit_id, str) or not exit_id:
            issues.append(_issue(
                "violated",
                "relevant_slot_read_dependency_invalid",
                index=index,
                slot_address=address,
            ))
            continue
        entry = grouped.setdefault(
            address,
            {"node_ids": set(), "target_dependencies": {}},
        )
        if witness_only:
            entry["target_dependencies"][(exit_id, "", -1, True)] = {
                "exit_id": exit_id,
                "witness_only": True,
            }
            continue
        if (
            not isinstance(unit_id, str)
            or unit_id not in units
            or not isinstance(event_index, int)
            or isinstance(event_index, bool)
            or event_index < 0
        ):
            issues.append(
                _issue(
                    "violated",
                    "relevant_slot_read_dependency_invalid",
                    index=index,
                    slot_address=address,
                )
            )
            continue
        events = units[unit_id]["semantics"]["memory_events"]
        event = events[event_index] if event_index < len(events) else None
        expected_address = address
        node_id = _event_node(unit_id, event_index)
        domain_access = (
            _checked_domain_classification(
                address_domain_facts[node_id], slot_address=expected_address
            )
            if node_id in address_domain_facts
            else None
        )
        if (
            not isinstance(event, Mapping)
            or event.get("kind") not in {"read", "read_write"}
            or event.get("width") not in {4, 32}
        ):
            issues.append(
                _issue(
                    "violated",
                    "relevant_slot_read_dependency_mismatch",
                    index=index,
                    unit_id=unit_id,
                    event_index=event_index,
                    slot_address=expected_address,
                )
            )
            continue
        constant_address = _constant(event.get("address"))
        if constant_address is not None and constant_address != expected_address:
            issues.append(
                _issue(
                    "violated",
                    "relevant_slot_read_dependency_mismatch",
                    index=index,
                    unit_id=unit_id,
                    event_index=event_index,
                    slot_address=expected_address,
                )
            )
            continue
        if (
            constant_address is None
            and (
                domain_access is None
                or domain_access.classification
                not in {"exact", "conditional_exact"}
            )
        ):
            issues.append(_issue(
                "incomplete",
                "relevant_slot_read_dependency_unproved",
                index=index,
                unit_id=unit_id,
                event_index=event_index,
                slot_address=expected_address,
            ))
        entry["node_ids"].add(node_id)
        entry["target_dependencies"][(exit_id, unit_id, event_index, False)] = {
            "exit_id": exit_id,
            "unit_id": unit_id,
            "event_index": event_index,
        }
    return {
        address: {
            "node_ids": sorted(value["node_ids"]),
            "target_dependencies": [
                value["target_dependencies"][identity]
                for identity in sorted(value["target_dependencies"])
            ],
        }
        for address, value in sorted(grouped.items())
    }, _deduplicate_issues(issues)


def _issues_for_slot(
    issues: Sequence[Mapping[str, Any]], *, address: int
) -> list[dict[str, Any]]:
    """Keep global issues and issues explicitly bound to one candidate slot."""

    result: list[Mapping[str, Any]] = []
    for issue in issues:
        details = issue.get("details")
        if not isinstance(details, Mapping) or "slot_address" not in details:
            result.append(issue)
            continue
        slot_address = details.get("slot_address")
        # A malformed scope must fail globally rather than disappearing from
        # every per-slot replay.
        if not _u32(slot_address) or int(slot_address) == address:
            result.append(issue)
    return _deduplicate_issues(result)


def _normalize_graph(
    graph: Mapping[str, Any], units: Mapping[str, Mapping[str, Any]]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    if not isinstance(graph, Mapping):
        graph = {}
        issues.append(_issue("violated", "rooted_control_graph_malformed"))
    if graph.get("status") != "complete":
        issues.append(
            _issue(
                "violated" if graph.get("status") == "violated" else "incomplete",
                "rooted_control_graph_incomplete",
            )
        )
    if graph.get("format") != ROOTED_CONTROL_GRAPH_V2_FORMAT:
        issues.append(_issue("violated", "rooted_control_graph_format_invalid"))
    graph_id = graph.get("id", "rooted-control-graph-v2")
    if not isinstance(graph_id, str) or not graph_id:
        issues.append(_issue("violated", "rooted_control_graph_id_invalid"))
        graph_id = "invalid-rooted-control-graph"

    roots: list[str] = []
    root_kinds: dict[str, str] = {}
    raw_roots = graph.get("roots")
    if not isinstance(raw_roots, list) or not raw_roots:
        issues.append(_issue("incomplete", "rooted_control_roots_missing"))
        raw_roots = []
    for index, raw in enumerate(raw_roots):
        if isinstance(raw, str):
            unit_id, kind = raw, "pe"
        elif isinstance(raw, Mapping):
            unit_id = raw.get("unit_id")
            kind = raw.get("kind", "pe")
        else:
            unit_id, kind = None, None
        if unit_id not in units or not isinstance(kind, str) or not kind:
            issues.append(_issue("violated", "rooted_control_root_invalid", index=index))
            continue
        roots.append(str(unit_id))
        root_kinds[str(unit_id)] = str(kind)
    roots = sorted(set(roots))

    successors: dict[str, set[str]] = {unit_id: set() for unit_id in units}
    supplied_direct: set[tuple[str, str]] = set()
    raw_edges = graph.get("direct_edges")
    if not isinstance(raw_edges, list):
        issues.append(_issue("incomplete", "direct_edge_inventory_missing"))
        raw_edges = []
    for index, raw in enumerate(raw_edges):
        edge = _edge(raw)
        if edge is None or edge[0] not in units or edge[1] not in units:
            issues.append(_issue("violated", "direct_edge_invalid", index=index))
            continue
        supplied_direct.add(edge)
        successors[edge[0]].add(edge[1])

    indirect_sources: set[str] = set()
    incomplete_indirect_sources: set[str] = set()
    raw_indirect = graph.get("indirect_exits")
    if not isinstance(raw_indirect, list):
        issues.append(_issue("incomplete", "indirect_exit_inventory_missing"))
        raw_indirect = []
    for index, raw in enumerate(raw_indirect):
        if not isinstance(raw, Mapping):
            issues.append(_issue("violated", "indirect_exit_certificate_invalid", index=index))
            continue
        source = raw.get("source_unit_id")
        targets = raw.get("target_unit_ids")
        external_targets = raw.get("external_targets")
        if external_targets is None:
            external_targets = []
        if source not in units:
            issues.append(_issue("violated", "indirect_exit_source_invalid", index=index))
            continue
        indirect_sources.add(str(source))
        if (
            raw.get("status") != "complete"
            or not isinstance(targets, list)
            or not isinstance(external_targets, list)
            or not (targets or external_targets)
        ):
            incomplete_indirect_sources.add(str(source))
            continue
        for target in targets:
            if target not in units:
                issues.append(
                    _issue("violated", "indirect_exit_target_invalid", source_unit_id=source)
                )
                continue
            successors[str(source)].add(str(target))

    reachable: set[str] = set()
    pending = list(reversed(roots))
    while pending:
        unit_id = pending.pop()
        if unit_id in reachable:
            continue
        reachable.add(unit_id)
        pending.extend(
            reversed(sorted(successors.get(unit_id, ()), reverse=False))
        )

    # Completeness is a rooted property.  Unreachable decoded units remain in
    # the exact machine-IR inventory but do not require product edges until a
    # checked transfer reaches them.  A missing edge on a reached unit still
    # fails closed and prevents any slot fact from being promoted.
    rva_index = {
        int(unit["source"]["original"]["rva_start"]): unit_id
        for unit_id, unit in units.items()
    }
    for source in sorted(incomplete_indirect_sources & reachable):
        issues.append(_issue(
            "incomplete",
            "indirect_exit_certificate_incomplete",
            source_unit_id=source,
        ))
    for unit_id in sorted(reachable):
        control = units[unit_id].get("control")
        if not isinstance(control, Mapping):
            continue
        direct_targets = control.get("direct_targets", [])
        if isinstance(direct_targets, list):
            for target_rva in direct_targets:
                if isinstance(target_rva, int) and target_rva in rva_index:
                    edge = (unit_id, rva_index[target_rva])
                    if edge not in supplied_direct:
                        issues.append(_issue(
                            "incomplete",
                            "decoded_direct_edge_omitted",
                            source_unit_id=unit_id,
                            target_unit_id=edge[1],
                        ))
        if control.get("has_indirect_target") is True and unit_id not in indirect_sources:
            issues.append(_issue(
                "incomplete",
                "indirect_exit_certificate_missing",
                source_unit_id=unit_id,
            ))
    normalized_graph = {
        "format": graph.get("format", ROOTED_CONTROL_GRAPH_V2_FORMAT),
        "id": graph_id,
        "status": graph.get("status"),
        "roots": [
            {"unit_id": unit_id, "kind": root_kinds[unit_id]} for unit_id in roots
        ],
        "direct_edges": [
            {"source_unit_id": source, "target_unit_id": target}
            for source, target in sorted(supplied_direct)
        ],
        "indirect_exits": copy.deepcopy(raw_indirect),
    }
    return {
        "graph_id": graph_id,
        "graph_sha256": canonical_sha256(normalized_graph),
        "roots": roots,
        "root_kinds": root_kinds,
        "successors": {key: sorted(value) for key, value in successors.items()},
        "reachable_units": sorted(reachable),
    }, _deduplicate_issues(issues)


def _normalize_range_facts(
    facts: Iterable[tuple[str, Mapping[str, Any]]],
    *,
    image_base: int,
    size_of_image: int,
    known_units: frozenset[str],
    authority_binding: Mapping[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    result: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    seen: set[str] = set()
    for source_kind, raw in facts:
        if not isinstance(raw, Mapping):
            issues.append(_issue("violated", "checked_range_fact_malformed"))
            continue
        identity = raw.get("id")
        if raw.get("status") != "complete":
            issues.append(
                _issue(
                    "violated" if raw.get("status") == "violated" else "incomplete",
                    "checked_range_fact_not_complete",
                    fact_id=identity,
                )
            )
            continue
        base = raw.get("base_expression")
        units = raw.get("applies_to_unit_ids")
        offset_start = raw.get("offset_start")
        offset_end = raw.get("offset_end")
        image = raw.get("disjoint_from_image")
        observed_binding = raw.get("authority_binding")
        if (
            raw.get("format") != CHECKED_MEMORY_RANGE_FACT_V2_FORMAT
            or not isinstance(identity, str)
            or not identity
            or identity in seen
            or not isinstance(base, Mapping)
            or not isinstance(units, list)
            or not units
            or any(unit not in known_units for unit in units)
            or not isinstance(offset_start, int)
            or isinstance(offset_start, bool)
            or not isinstance(offset_end, int)
            or isinstance(offset_end, bool)
            or offset_start >= offset_end
            or raw.get("range_kind")
            != ("stack" if source_kind == "entry" else "dynamic")
            or not isinstance(image, Mapping)
            or image != {"image_base": image_base, "size_of_image": size_of_image}
            or authority_binding is None
            or not isinstance(observed_binding, Mapping)
            or dict(observed_binding) != dict(authority_binding)
        ):
            issues.append(
                _issue(
                    "violated",
                    "checked_range_fact_invalid",
                    fact_id=identity,
                )
            )
            continue
        seen.add(identity)
        assert isinstance(image, Mapping)
        normalized = {
            "format": CHECKED_MEMORY_RANGE_FACT_V2_FORMAT,
            "id": identity,
            "status": "complete",
            "source_kind": source_kind,
            "range_kind": raw.get("range_kind"),
            "base_expression": copy.deepcopy(dict(base)),
            "offset_start": offset_start,
            "offset_end": offset_end,
            "applies_to_unit_ids": sorted(set(str(unit) for unit in units)),
            "disjoint_from_image": copy.deepcopy(dict(image)),
            "authority_binding": copy.deepcopy(dict(observed_binding)),
        }
        normalized["fact_sha256"] = canonical_sha256(normalized)
        result.append(normalized)
    return sorted(result, key=lambda row: str(row["id"])), _deduplicate_issues(issues)


def _normalize_spatial_facts(
    facts: Sequence[Mapping[str, Any]],
    *,
    units: Mapping[str, Mapping[str, Any]],
    access_facts: Mapping[str, CheckedMemoryAccessFact],
    image_base: int,
    size_of_image: int,
    authority_binding: Mapping[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    result: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_events: set[tuple[str, int]] = set()
    esp_fields = {
        "format",
        "status",
        "unit_id",
        "event_index",
        "memory_kind",
        "width_bytes",
        "address_expression",
        "entry_esp_offsets",
        "address_esp_offset",
        "minimum_start_offset",
        "maximum_start_offset",
        "stack_contract",
        "disjoint_from_image",
        "authority_binding",
        "id",
        "fact_sha256",
    }
    origin_fields = {
        "format",
        "status",
        "unit_id",
        "event_index",
        "memory_kind",
        "width_bytes",
        "address_expression",
        "memory_access_fact_id",
        "memory_access_fact_sha256",
        "address_origins",
        "frame_base_offsets",
        "minimum_start_offset",
        "maximum_start_offset",
        "stack_contract",
        "disjoint_from_image",
        "authority_binding",
        "id",
        "fact_sha256",
    }
    for index, raw in enumerate(facts):
        try:
            if not isinstance(raw, Mapping):
                raise ValueError("spatial fact has noncanonical fields")
            fields = frozenset(raw)
            if fields not in {frozenset(esp_fields), frozenset(origin_fields)}:
                raise ValueError("spatial fact has noncanonical fields")
            identity = raw.get("id")
            unit_id = raw.get("unit_id")
            event_index = raw.get("event_index")
            fact_format = raw.get("format")
            if (
                fact_format not in {
                    CHECKED_STACK_SPATIAL_FACT_V2_FORMAT,
                    CHECKED_STACK_ORIGIN_SPATIAL_FACT_V2_FORMAT,
                }
                or raw.get("status") != "complete"
                or not isinstance(identity, str)
                or not identity
                or identity in seen_ids
                or not isinstance(unit_id, str)
                or unit_id not in units
                or not isinstance(event_index, int)
                or isinstance(event_index, bool)
                or event_index < 0
                or (unit_id, event_index) in seen_events
            ):
                raise ValueError("spatial fact identity or event binding is invalid")
            events = units[unit_id]["semantics"].get("memory_events")
            if not isinstance(events, list) or event_index >= len(events):
                raise ValueError("spatial fact references an unknown event")
            event = events[event_index]
            width = raw.get("width_bytes")
            if (
                not isinstance(event, Mapping)
                or raw.get("memory_kind") != event.get("kind")
                or width != event.get("width")
                or raw.get("address_expression") != event.get("address")
                or not isinstance(width, int)
                or isinstance(width, bool)
                or not 0 < width <= 4096
            ):
                raise ValueError("spatial fact contradicts its exact memory event")
            if fact_format == CHECKED_STACK_SPATIAL_FACT_V2_FORMAT:
                if set(raw) != esp_fields:
                    raise ValueError("ESP spatial fact has noncanonical fields")
                starts = _esp_spatial_starts(raw)
                id_prefix = "checked-stack-spatial-v2:"
            else:
                if set(raw) != origin_fields:
                    raise ValueError("origin spatial fact has noncanonical fields")
                starts = _origin_spatial_starts(
                    raw,
                    event_node=f"event:{unit_id}:{event_index}",
                    access_facts=access_facts,
                )
                id_prefix = "checked-stack-origin-spatial-v2:"
            contract = raw.get("stack_contract")
            if not isinstance(contract, Mapping) or set(contract) != {
                "lower_bound", "upper_bound_exclusive"
            }:
                raise ValueError("spatial fact stack contract is malformed")
            lower = contract.get("lower_bound")
            upper = contract.get("upper_bound_exclusive")
            if (
                not isinstance(lower, int)
                or isinstance(lower, bool)
                or not isinstance(upper, int)
                or isinstance(upper, bool)
                or lower >= upper
            ):
                raise ValueError("spatial fact stack bounds are invalid")
            if (
                raw.get("minimum_start_offset") != min(starts)
                or raw.get("maximum_start_offset") != max(starts)
                or any(start < lower or start + width > upper for start in starts)
            ):
                raise ValueError("spatial fact is outside its stack contract")
            if raw.get("disjoint_from_image") != {
                "image_base": image_base,
                "size_of_image": size_of_image,
            }:
                raise ValueError("spatial fact has a stale image separation binding")
            if (
                authority_binding is None
                or not isinstance(raw.get("authority_binding"), Mapping)
                or dict(raw["authority_binding"]) != dict(authority_binding)
            ):
                raise ValueError("spatial fact authority binding is stale")
            core = {
                key: copy.deepcopy(value)
                for key, value in raw.items()
                if key not in {"id", "fact_sha256"}
            }
            expected_id = id_prefix + canonical_sha256(core)
            payload = {**core, "id": expected_id}
            if (
                identity != expected_id
                or raw.get("fact_sha256") != canonical_sha256(payload)
            ):
                raise ValueError("spatial fact digest is stale")
            seen_ids.add(identity)
            seen_events.add((unit_id, event_index))
            result.append(copy.deepcopy(dict(raw)))
        except (TypeError, ValueError) as exc:
            issues.append(_issue(
                "violated",
                "checked_memory_spatial_fact_invalid",
                index=index,
                reason=str(exc),
            ))
    return sorted(
        result,
        key=lambda row: (
            str(row["unit_id"]), int(row["event_index"]), str(row["id"])
        ),
    ), _deduplicate_issues(issues)


def _esp_spatial_starts(raw: Mapping[str, Any]) -> list[int]:
    address_offset = affine_register_offset(
        raw.get("address_expression"), "esp"
    )
    offsets = raw.get("entry_esp_offsets")
    if (
        address_offset is None
        or raw.get("address_esp_offset") != address_offset
        or not isinstance(offsets, list)
        or not offsets
        or any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in offsets
        )
        or offsets != sorted(set(offsets))
    ):
        raise ValueError(
            "spatial fact entry offsets are not finite canonical data"
        )
    return [int(value) + address_offset for value in offsets]


def _origin_spatial_starts(
    raw: Mapping[str, Any],
    *,
    event_node: str,
    access_facts: Mapping[str, CheckedMemoryAccessFact],
) -> list[int]:
    access_fact = access_facts.get(event_node)
    if access_fact is None:
        raise ValueError("origin spatial fact lacks a checked memory-access fact")
    payload = access_fact.to_payload()
    if (
        raw.get("memory_access_fact_id") != access_fact.fact_id
        or raw.get("memory_access_fact_sha256") != payload["fact_sha256"]
        or raw.get("address_origins")
        != [origin.to_value() for origin in access_fact.address_origins]
    ):
        raise ValueError("origin spatial fact has a stale access-fact binding")
    origin_offsets: list[int] = []
    for origin in access_fact.address_origins:
        value = origin.to_value()
        key = value.get("key") if isinstance(value, Mapping) else None
        if (
            not isinstance(value, Mapping)
            or value.get("kind") != "stack_location"
            or not isinstance(key, list)
            or len(key) != 1
            or not isinstance(key[0], int)
            or isinstance(key[0], bool)
        ):
            raise ValueError("origin spatial fact has a non-stack origin")
        origin_offsets.append(int(key[0]))
    frame_offsets = raw.get("frame_base_offsets")
    if (
        not isinstance(frame_offsets, list)
        or not frame_offsets
        or any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in frame_offsets
        )
        or frame_offsets != sorted(set(frame_offsets))
    ):
        raise ValueError("origin spatial fact frame bases are not canonical")
    return [
        int(frame_base) + origin_offset
        for frame_base in frame_offsets
        for origin_offset in sorted(set(origin_offsets))
    ]


def _events(
    units: Mapping[str, Mapping[str, Any]],
    reachable: frozenset[str],
    *,
    call_site_effects: Mapping[CallSiteId, CallSiteEffect],
    interprocedural_authority_sha256: str | None,
) -> dict[str, _Event]:
    result: dict[str, _Event] = {}
    for unit_id in sorted(reachable):
        semantics = units[unit_id]["semantics"]
        for event_index, raw in enumerate(semantics["memory_events"]):
            if not isinstance(raw, Mapping):
                raw = {}
            instruction_rva = raw.get("instruction_rva")
            if not _u32(instruction_rva):
                instruction_rva = units[unit_id]["source"]["original"]["rva_start"]
            assert isinstance(instruction_rva, int)
            node_id = _event_node(unit_id, event_index)
            result[node_id] = _Event(
                node_id=node_id,
                site=_Site(unit_id, event_index, int(instruction_rva)),
                kind=str(raw.get("kind", "unknown")),
                width=(
                    int(raw["width"])
                    if isinstance(raw.get("width"), int)
                    and not isinstance(raw.get("width"), bool)
                    and raw["width"] > 0
                    else None
                ),
                address=copy.deepcopy(raw.get("address")),
                value=copy.deepcopy(raw.get("value")),
                raw=copy.deepcopy(dict(raw)),
                order_key=(int(instruction_rva), 0, event_index),
            )
    covered_call_sites: set[CallSiteId] = set()
    for site, effect in sorted(
        call_site_effects.items(),
        key=lambda item: (item[0].unit_id, item[0].event_index),
    ):
        if site.unit_id not in reachable:
            continue
        unit = units[site.unit_id]
        external_event = unit["semantics"]["external_events"][site.event_index]
        covered_call_sites.add(site)
        instruction_rva = external_event.get("instruction_rva")
        if not _u32(instruction_rva):
            instruction_rva = unit["source"]["original"]["rva_start"]
        assert isinstance(instruction_rva, int)

        output_addresses = {
            int(output.location.key[0]) & 0xFFFFFFFF
            for output in effect.outputs
            if output.location.kind == "exact"
            and len(output.location.key) == 1
            and _u32(output.location.key[0])
        }
        if effect.memory_frame_status != "complete":
            node_id = _call_unknown_memory_write_node(
                site.unit_id, site.event_index
            )
            raw = {
                "kind": "write",
                "width": None,
                "address": None,
                "value": None,
                "instruction_rva": instruction_rva,
                "source": "incomplete_interprocedural_call_memory_frame",
                "call_site_unit_id": site.unit_id,
                "call_event_index": site.event_index,
                "transfer_kind": effect.transfer_kind,
                "interprocedural_authority_sha256": (
                    interprocedural_authority_sha256
                ),
            }
            result[node_id] = _Event(
                node_id=node_id,
                site=_Site(site.unit_id, site.event_index, instruction_rva),
                kind="write",
                width=None,
                address=None,
                value=None,
                raw=raw,
                order_key=(instruction_rva, 1, 0),
            )
        else:
            for write_index, span in enumerate(effect.memory_writes):
                address = (
                    int(span.base.key[0]) & 0xFFFFFFFF
                    if span.base.kind == "exact"
                    and len(span.base.key) == 1
                    and _u32(span.base.key[0])
                    else span.base.as_json()
                )
                if (
                    isinstance(address, int)
                    and span.size == 4
                    and address in output_addresses
                ):
                    continue
                node_id = _call_memory_write_node(
                    site.unit_id, site.event_index, write_index
                )
                raw = {
                    "kind": "write",
                    "width": span.size,
                    "address": copy.deepcopy(address),
                    "value": None,
                    "instruction_rva": instruction_rva,
                    "source": "interprocedural_call_memory_frame",
                    "call_site_unit_id": site.unit_id,
                    "call_event_index": site.event_index,
                    "transfer_kind": effect.transfer_kind,
                    "interprocedural_authority_sha256": (
                        interprocedural_authority_sha256
                    ),
                }
                result[node_id] = _Event(
                    node_id=node_id,
                    site=_Site(
                        site.unit_id, site.event_index, instruction_rva
                    ),
                    kind="write",
                    width=span.size,
                    address=copy.deepcopy(address),
                    value=None,
                    raw=raw,
                    order_key=(instruction_rva, 1, write_index),
                )

        for output_index, output in enumerate(effect.outputs):
            if (
                output.location.kind != "exact"
                or len(output.location.key) != 1
                or not _u32(output.location.key[0])
            ):
                continue
            address = int(output.location.key[0]) & 0xFFFFFFFF
            origins = [origin.as_json() for origin in sorted(output.value)]
            node_id = _call_output_write_node(
                site.unit_id, site.event_index, output_index
            )
            raw = {
                "kind": "write",
                "width": 4,
                "address": {"op": "const", "value": address, "width": 32},
                "value": None,
                "value_origins": origins,
                "instruction_rva": instruction_rva,
                "source": "interprocedural_call_result_frame",
                "call_site_unit_id": site.unit_id,
                "call_event_index": site.event_index,
                "transfer_kind": effect.transfer_kind,
                "interprocedural_authority_sha256": (
                    interprocedural_authority_sha256
                ),
            }
            result[node_id] = _Event(
                node_id=node_id,
                site=_Site(site.unit_id, site.event_index, instruction_rva),
                kind="write",
                width=4,
                address=copy.deepcopy(raw["address"]),
                value=None,
                raw=raw,
                order_key=(instruction_rva, 2, output_index),
            )

    # A missing call-site effect is an unknown post-call memory transition.
    # Omitting it would silently treat an uncontracted call as preserving all
    # mutable state.
    for unit_id in sorted(reachable):
        external_events = units[unit_id]["semantics"].get("external_events", ())
        if not isinstance(external_events, Sequence) or isinstance(
            external_events, (str, bytes)
        ):
            continue
        for event_index, raw_event in enumerate(external_events):
            if (
                not isinstance(raw_event, Mapping)
                or raw_event.get("kind")
                not in {"external_call", "indirect_call", "internal_call"}
            ):
                continue
            site = CallSiteId(unit_id, event_index)
            if site in covered_call_sites:
                continue
            instruction_rva = raw_event.get("instruction_rva")
            if not _u32(instruction_rva):
                instruction_rva = units[unit_id]["source"]["original"][
                    "rva_start"
                ]
            assert isinstance(instruction_rva, int)
            node_id = _call_unknown_memory_write_node(unit_id, event_index)
            raw = {
                "kind": "write",
                "width": None,
                "address": None,
                "value": None,
                "instruction_rva": instruction_rva,
                "source": "missing_interprocedural_call_memory_frame",
                "call_site_unit_id": unit_id,
                "call_event_index": event_index,
                "transfer_kind": str(raw_event.get("kind")),
                "interprocedural_authority_sha256": (
                    interprocedural_authority_sha256
                ),
            }
            result[node_id] = _Event(
                node_id=node_id,
                site=_Site(unit_id, event_index, instruction_rva),
                kind="write",
                width=None,
                address=None,
                value=None,
                raw=raw,
                order_key=(instruction_rva, 1, 0),
            )
    return result


def _event_graph(
    *,
    units: Mapping[str, Mapping[str, Any]],
    reachable: frozenset[str],
    roots: Sequence[str],
    successors: Mapping[str, Sequence[str]],
    events: Mapping[str, _Event],
) -> dict[str, Any]:
    edges: dict[str, set[str]] = {"super": set()}
    predecessors: dict[str, set[str]] = {"super": set()}
    by_rva = {
        int(unit["source"]["original"]["rva_start"]): unit_id
        for unit_id, unit in units.items()
    }
    call_routing: dict[str, tuple[tuple[str, ...], str]] = {}
    for unit_id in sorted(reachable):
        entry = _entry_node(unit_id)
        exit_node = _exit_node(unit_id)
        unit_events = sorted(
            (
                event
                for event in events.values()
                if event.site.unit_id == unit_id
            ),
            key=lambda event: (event.order_key, event.node_id),
        )
        ordinary_nodes = [
            event.node_id
            for event in unit_events
            if not _is_call_summary_event(event)
        ]
        summary_nodes = [
            event.node_id
            for event in unit_events
            if _is_call_summary_event(event)
        ]
        routing = _internal_call_routing(
            unit=units[unit_id],
            successor_ids=successors.get(unit_id, ()),
            by_rva=by_rva,
            reachable=reachable,
        )
        chain = [entry, *ordinary_nodes, *summary_nodes, exit_node]
        for node in chain:
            edges.setdefault(node, set())
            predecessors.setdefault(node, set())
        if routing is None:
            pairs = zip(chain, chain[1:])
        else:
            pre_call = ordinary_nodes[-1] if ordinary_nodes else entry
            summary_chain = [pre_call, *summary_nodes, exit_node]
            pairs = zip(summary_chain, summary_chain[1:])
            target_ids, continuation_id = routing
            call_routing[unit_id] = (target_ids, continuation_id)
            for target_id in target_ids:
                target = _entry_node(target_id)
                edges[pre_call].add(target)
                predecessors.setdefault(target, set()).add(pre_call)
            # Ordinary events still execute in sequence before the call edge.
            ordinary_chain = [entry, *ordinary_nodes]
            for source, target in zip(ordinary_chain, ordinary_chain[1:]):
                edges[source].add(target)
                predecessors[target].add(source)
        for source, target in pairs:
            edges[source].add(target)
            predecessors[target].add(source)
    for root in roots:
        if root in reachable:
            edges["super"].add(_entry_node(root))
            predecessors[_entry_node(root)].add("super")
    for source in sorted(reachable):
        routing = call_routing.get(source)
        if routing is not None:
            _target_ids, continuation_id = routing
            if continuation_id in reachable:
                edges[_exit_node(source)].add(_entry_node(continuation_id))
                predecessors[_entry_node(continuation_id)].add(
                    _exit_node(source)
                )
            continue
        for target in successors.get(source, ()):
            if target in reachable:
                edges[_exit_node(source)].add(_entry_node(target))
                predecessors[_entry_node(target)].add(_exit_node(source))

    seen: set[str] = set()
    pending = ["super"]
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        seen.add(node)
        pending.extend(sorted(edges.get(node, ()), reverse=True))
    return {
        "nodes": sorted(seen),
        "edges": {node: sorted(edges.get(node, ())) for node in sorted(seen)},
        "predecessors": {
            node: sorted(value for value in predecessors.get(node, ()) if value in seen)
            for node in sorted(seen)
        },
    }


def _is_call_summary_event(event: _Event) -> bool:
    return event.raw.get("source") in {
        "incomplete_interprocedural_call_memory_frame",
        "interprocedural_call_memory_frame",
        "interprocedural_call_result_frame",
        "missing_interprocedural_call_memory_frame",
    }


def _internal_call_routing(
    *,
    unit: Mapping[str, Any],
    successor_ids: Sequence[str],
    by_rva: Mapping[int, str],
    reachable: frozenset[str],
) -> tuple[tuple[str, ...], str] | None:
    """Split a call edge from its post-call summary/continuation edge."""

    external_events = unit["semantics"].get("external_events", ())
    if not isinstance(external_events, Sequence) or isinstance(
        external_events, (str, bytes)
    ):
        return None
    call_events = [
        event
        for event in external_events
        if isinstance(event, Mapping)
        and event.get("kind") in {"internal_call", "indirect_call"}
    ]
    if len(call_events) != 1:
        return None
    event = call_events[0]
    continuation = by_rva.get(event.get("return_rva"))
    if continuation is None or continuation not in successor_ids:
        return None
    if event.get("kind") == "internal_call":
        target = by_rva.get(event.get("target_rva"))
        targets = () if target is None else (target,)
    else:
        targets = tuple(sorted(
            target
            for target in successor_ids
            if target != continuation and target in reachable
        ))
    if not targets or any(target not in successor_ids for target in targets):
        return None
    return tuple(sorted(set(targets))), continuation


def _common_dominating_write(
    *,
    event_graph: Mapping[str, Any],
    candidate_writes: Sequence[str],
    relevant_reads: Sequence[str],
) -> str | None:
    """Select a finite write that lies on every path to every relevant read.

    Computing every node's complete dominator set is quadratic in the event
    graph and consumed gigabytes on large binaries.  A slot has only a finite
    set of exact writes, so test those candidates directly: a candidate
    dominates the reads exactly when no read remains reachable from the
    synthetic root after removing that candidate.
    """

    candidates = sorted(set(candidate_writes))
    reads = frozenset(relevant_reads)
    if not candidates:
        return None
    if not reads:
        return candidates[0]
    edges = event_graph["edges"]
    for candidate in candidates:
        seen: set[str] = set()
        pending = ["super"]
        while pending:
            node = pending.pop()
            if node == candidate or node in seen:
                continue
            seen.add(node)
            pending.extend(
                target
                for target in reversed(edges.get(node, ()))
                if target != candidate and target not in seen
            )
        if reads.isdisjoint(seen):
            return candidate
    return None


def _reaching_write_provenance(
    *,
    node_id: str,
    event_graph: Mapping[str, Any],
    events: Mapping[str, _Event],
    accesses: Mapping[str, _Access],
    exact_write_values: Mapping[str, Sequence[Any]],
) -> dict[str, Any]:
    """Collect definitions on paths into one read, stopping at strong writes."""

    pending = list(reversed(event_graph["predecessors"].get(node_id, ())))
    seen: set[str] = set()
    writes: set[str] = set()
    unknown_writes: set[str] = set()
    aliasing_writes: set[str] = set()
    launch_reaches = False
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if current == "super":
            launch_reaches = True
            continue
        event = events.get(current)
        access = accesses.get(current)
        if (
            event is not None
            and access is not None
            and event.kind in {"write", "read_write"}
            and access.classification != "disjoint"
        ):
            if (
                access.classification == "exact"
                and current in exact_write_values
            ):
                writes.add(current)
                continue
            if access.classification == "alias":
                aliasing_writes.add(current)
            else:
                unknown_writes.add(current)
        pending.extend(
            reversed(event_graph["predecessors"].get(current, ()))
        )
    return {
        "launch_reaches": launch_reaches,
        "writes": sorted(writes),
        "unknown_writes": sorted(unknown_writes),
        "aliasing_writes": sorted(aliasing_writes),
    }


def _flow_replay(
    *,
    event_graph: Mapping[str, Any],
    events: Mapping[str, _Event],
    accesses: Mapping[str, _Access],
    exact_write_values: Mapping[str, Sequence[Any]],
    alternative_budget: int,
    initial_alternatives: Sequence[Any] = (),
) -> dict[str, Any]:
    nodes = [str(value) for value in event_graph["nodes"]]
    in_states = {node: _FlowState() for node in nodes}
    out_states = {node: _FlowState() for node in nodes}
    encoded_initial = tuple(
        sorted(_canonical_json(value) for value in initial_alternatives)
    )
    out_states["super"] = _FlowState(
        reachable=True,
        initialized=bool(encoded_initial),
        overflow=len(encoded_initial) > alternative_budget,
        alternatives=encoded_initial[:alternative_budget],
    )
    pending = deque(str(node) for node in event_graph["edges"].get("super", ()))
    queued = set(pending)
    maximum_steps = max(8, len(nodes) * (alternative_budget + 4))
    steps = 0
    while pending and steps < maximum_steps:
        node = pending.popleft()
        queued.discard(node)
        steps += 1
        inputs = [
            out_states[pred]
            for pred in event_graph["predecessors"].get(node, [])
            if out_states[pred].reachable
        ]
        incoming = _join_states(inputs, alternative_budget)
        outgoing = _transfer_state(
            incoming,
            event=events.get(node),
            access=accesses.get(node),
            alternatives=exact_write_values.get(node),
            alternative_budget=alternative_budget,
        )
        if incoming == in_states[node] and outgoing == out_states[node]:
            continue
        in_states[node] = incoming
        out_states[node] = outgoing
        for successor in event_graph["edges"].get(node, ()):
            if successor not in queued:
                pending.append(successor)
                queued.add(successor)
    converged = not pending
    return {
        "converged": converged,
        "overflow": any(state.overflow for state in (*in_states.values(), *out_states.values())),
        "in_states": in_states,
        "out_states": out_states,
    }


def _join_states(states: Sequence[_FlowState], budget: int) -> _FlowState:
    if not states:
        return _FlowState()
    alternatives = sorted({value for state in states for value in state.alternatives})
    overflow = any(state.overflow for state in states) or len(alternatives) > budget
    return _FlowState(
        reachable=True,
        initialized=all(state.initialized for state in states),
        tainted=any(state.tainted for state in states),
        overflow=overflow,
        alternatives=tuple(alternatives[:budget]),
    )


def _transfer_state(
    state: _FlowState,
    *,
    event: _Event | None,
    access: _Access | None,
    alternatives: Sequence[Any] | None,
    alternative_budget: int,
) -> _FlowState:
    if not state.reachable or event is None or access is None:
        return state
    if event.kind not in {"write", "read_write"}:
        return state
    if access.classification == "disjoint":
        return state
    if access.classification == "exact" and alternatives is not None:
        encoded = tuple(sorted(_canonical_json(value) for value in alternatives))
        return _FlowState(
            reachable=True,
            initialized=True,
            tainted=False,
            overflow=len(encoded) > alternative_budget,
            alternatives=encoded[:alternative_budget],
        )
    return _FlowState(
        reachable=True,
        initialized=state.initialized,
        tainted=True,
        overflow=state.overflow,
        alternatives=state.alternatives,
    )


def _classify_access(
    event: _Event,
    *,
    slot_address: int,
    checked_domain: CheckedMemoryAddressDomain | None = None,
    checked_fact: CheckedMemoryAccessFact | None = None,
    checked_range: Mapping[str, Any] | None = None,
    checked_spatial: Mapping[str, Any] | None = None,
) -> _Access:
    if event.kind not in _MEMORY_KINDS or event.width is None:
        return _Access("unknown", reason="memory_event_shape_unknown")
    # A literal address in the exact machine IR is already a complete address
    # evaluation.  Contextual origin/domain facts are useful for symbolic
    # expressions, but consulting them first can weaken a constant access back
    # to a conservative alias merely because the proposal checker does not
    # authorize coverage.  Classify the authoritative literal directly.
    constant = _constant(event.address)
    if constant is not None:
        if event.width == 4 and constant == slot_address:
            return _Access("exact")
        if event.width > 4096:
            return _Access("alias", reason="access_span_too_large_to_exclude")
        if _spans_overlap32(constant, event.width, slot_address, 4):
            return _Access("alias", reason="constant_partial_or_overlapping_access")
        return _Access("disjoint")
    if checked_spatial is not None:
        return _Access("disjoint", (str(checked_spatial["id"]),))
    if checked_domain is not None:
        return _checked_domain_classification(
            checked_domain, slot_address=slot_address
        )
    if checked_fact is not None:
        checked = _checked_access_classification(
            checked_fact,
            slot_address=slot_address,
        )
        if checked is not None:
            return checked
    if checked_range is not None:
        minimum = int(checked_range["minimum_address"])
        maximum = int(checked_range["maximum_address"])
        identity = str(checked_range["id"])
        if maximum + event.width > _UINT32_LIMIT:
            return _Access("alias", (identity,), "checked_address_range_wraps")
        if (
            maximum + event.width <= slot_address
            or slot_address + 4 <= minimum
        ):
            return _Access("disjoint", (identity,))
        return _Access(
            "alias", (identity,), "checked_address_range_may_overlap_slot"
        )
    if isinstance(event.address, Mapping):
        return _Access("alias", reason="symbolic_address_may_alias_slot")
    return _Access("unknown", reason="memory_address_unknown")


def _checked_domain_classification(
    domain: CheckedMemoryAddressDomain,
    *,
    slot_address: int,
) -> _Access:
    classifications = {
        "exact"
        if domain.width_bytes == 4 and value == slot_address
        else "alias"
        if _spans_overlap32(value, domain.width_bytes, slot_address, 4)
        else "disjoint"
        for value in domain.addresses
    }
    if len(classifications) == 1:
        return _Access(next(iter(classifications)), (domain.domain_id,))
    if classifications == {"exact", "disjoint"}:
        return _Access("conditional_exact", (domain.domain_id,))
    return _Access(
        "alias",
        (domain.domain_id,),
        "checked_address_domain_has_mixed_alias_classes",
    )


def _checked_access_classification(
    fact: CheckedMemoryAccessFact,
    *,
    slot_address: int,
) -> _Access | None:
    origins = [value.to_value() for value in fact.address_origins]
    kinds = {str(origin.get("kind")) for origin in origins}
    if kinds != {"exact"}:
        # A value-origin fact proves where the analyzer derived an address, but
        # does not by itself prove that the underlying stack/allocation range
        # is in bounds, non-wrapping, and disjoint from this PE image.  Only a
        # separately checked spatial range may authorize that exclusion.
        if kinds & {"stack_location", "dynamic_range", "dynamic_location"}:
            return _Access(
                "alias",
                (fact.fact_id,),
                "checked_non_image_origin_lacks_spatial_witness",
            )
        return None
    concrete: list[int] = []
    for origin in origins:
        key = origin.get("key") if isinstance(origin, Mapping) else None
        if (
            not isinstance(key, list)
            or len(key) != 1
            or not _u32(key[0])
        ):
            return None
        concrete.append(int(key[0]))
    classifications = {
        "exact"
        if fact.width_bytes == 4 and value == slot_address
        else "alias"
        if _spans_overlap32(value, fact.width_bytes, slot_address, 4)
        else "disjoint"
        for value in concrete
    }
    return _Access(
        "alias",
        (fact.fact_id,),
        (
            "checked_address_origins_are_not_coverage_authority"
            if classifications <= {"exact", "disjoint"}
            else "checked_address_alternatives_have_mixed_alias_classes"
        ),
    )


def _event_alternatives(value: Any, raw: Mapping[str, Any]) -> list[Any] | None:
    for key in ("value_origins", "value_alternatives", "alternatives"):
        explicit = raw.get(key)
        if isinstance(explicit, list) and explicit:
            normalized = [_origin(item) for item in explicit]
            if all(item is not None for item in normalized):
                return _deduplicate_json(item for item in normalized if item is not None)
            return None
    return _value_alternatives(value)


def _value_alternatives(value: Any) -> list[Any] | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < _UINT32_LIMIT:
        return [{"kind": "exact_bits", "value": value, "width_bits": 32}]
    if not isinstance(value, Mapping):
        return None
    if isinstance(value.get("kind"), str) and value.get("kind"):
        normalized = _origin(value)
        return None if normalized is None else [normalized]
    op = value.get("op")
    if op == "const" and _u32(value.get("value")):
        width = value.get("width", 32)
        if isinstance(width, int) and not isinstance(width, bool) and 0 < width <= 32:
            return [
                {
                    "kind": "exact_bits",
                    "value": int(value["value"]),
                    "width_bits": width,
                }
            ]
    if op == "ite":
        args = value.get("args")
        if isinstance(args, list) and len(args) == 3:
            left = _value_alternatives(args[1])
            right = _value_alternatives(args[2])
            if left is not None and right is not None:
                return _deduplicate_json([*left, *right])
    if op == "finite":
        raw = value.get("alternatives")
        if isinstance(raw, list) and raw:
            rows = [_origin(item) for item in raw]
            if all(row is not None for row in rows):
                return _deduplicate_json(row for row in rows if row is not None)
    return None


def _origin(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    if isinstance(value.get("kind"), str) and value.get("kind"):
        try:
            return json.loads(_canonical_json(value))
        except (TypeError, ValueError):
            return None
    alternatives = _value_alternatives(value)
    return alternatives[0] if alternatives is not None and len(alternatives) == 1 else None


def _constant(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < _UINT32_LIMIT:
        return value
    if isinstance(value, Mapping) and value.get("op") == "const" and _u32(value.get("value")):
        return int(value["value"])
    return None


def _spans_overlap32(left: int, left_width: int, right: int, right_width: int) -> bool:
    return bool(set(_span_bytes(left, left_width)) & set(_span_bytes(right, right_width)))


def _span_bytes(start: int, width: int) -> Iterable[int]:
    return ((start + offset) & 0xFFFFFFFF for offset in range(width))


def _access_payload(event: _Event, access: _Access) -> dict[str, Any]:
    return {
        "site": event.site.payload(),
        "reason": access.reason,
        "address": copy.deepcopy(event.address),
        "width": event.width,
        "dependencies": list(access.dependency_ids),
    }


def _state_payload(state: _FlowState) -> dict[str, Any]:
    return {
        "reachable": state.reachable,
        "initialized": state.initialized,
        "tainted": state.tainted,
        "overflow": state.overflow,
        "alternatives": [json.loads(value) for value in state.alternatives],
    }


def _uninitialized_callback_root_kind(
    *,
    node_id: str,
    event_graph: Mapping[str, Any],
    root_kinds: Mapping[str, str],
) -> str | None:
    # A callback root is authoritative only at its own independent entry.  This
    # lightweight reverse closure is diagnostic and cannot establish facts.
    pending = [node_id]
    seen: set[str] = set()
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        seen.add(node)
        if node.startswith("entry:"):
            unit_id = node.removeprefix("entry:")
            if root_kinds.get(unit_id) == "callback":
                return "callback"
        pending.extend(event_graph["predecessors"].get(node, []))
    return None


def _edge(value: Any) -> tuple[str, str] | None:
    if not isinstance(value, Mapping):
        return None
    source = value.get("source_unit_id")
    target = value.get("target_unit_id")
    if not isinstance(source, str) or not source or not isinstance(target, str) or not target:
        return None
    return source, target


def _event_node(unit_id: str, index: int) -> str:
    return f"event:{unit_id}:{index}"


def _call_memory_write_node(
    unit_id: str, event_index: int, write_index: int
) -> str:
    return f"call-memory-write:{unit_id}:{event_index}:{write_index}"


def _call_unknown_memory_write_node(unit_id: str, event_index: int) -> str:
    return f"call-unknown-memory-write:{unit_id}:{event_index}"


def _call_output_write_node(
    unit_id: str, event_index: int, output_index: int
) -> str:
    return f"call-output-write:{unit_id}:{event_index}:{output_index}"


def _entry_node(unit_id: str) -> str:
    return f"entry:{unit_id}"


def _exit_node(unit_id: str) -> str:
    return f"exit:{unit_id}"


def _u32(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < _UINT32_LIMIT


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _DIGEST_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _deduplicate_json(values: Iterable[Any]) -> list[Any]:
    encoded = sorted({_canonical_json(value) for value in values})
    return [json.loads(value) for value in encoded]


def _issue(status: str, code: str, **details: Any) -> dict[str, Any]:
    return {
        "status": status,
        "code": code,
        "details": copy.deepcopy(details),
    }


def _deduplicate_issues(values: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    encoded = sorted({_canonical_json(dict(value)) for value in values})
    return [json.loads(value) for value in encoded]


def _aggregate_status(values: Iterable[str]) -> str:
    statuses = set(values)
    if "violated" in statuses:
        return "violated"
    if "incomplete" in statuses:
        return "incomplete"
    return "complete"


__all__ = [
    "CHECKED_MEMORY_RANGE_FACT_V2_FORMAT",
    "GLOBAL_SLOT_ANALYSIS_V2_FORMAT",
    "GLOBAL_SLOT_REPLAY_EVIDENCE_V2_FORMAT",
    "ROOTED_CONTROL_GRAPH_V2_FORMAT",
    "GlobalSlotAnalysisV2Error",
    "analyze_global_slots_v2",
    "canonical_sha256",
]
