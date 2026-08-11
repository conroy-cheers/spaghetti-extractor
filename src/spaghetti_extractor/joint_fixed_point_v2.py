"""Dependency-aware orchestration for v2 interprocedural authority.

The individual analyzers remain responsible for checking their own evidence.
This module owns the finite assume/guarantee iteration between call summaries,
stack ranges, mutable slots, and indirect targets.  Proposal-seeded results are
never exported as authority: the final interprocedural result is replayed with
no static target seed before the product graph can close.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .analysis_schema_v2 import CHECKED_MEMORY_RANGE_FACT_V2_FORMAT
from .artifact_identity_v2 import canonical_sha256
from .global_slot_hypotheses_v2 import (
    GlobalSlotHypothesisV2Error,
    GlobalSlotInductionHypothesisV2,
)
from .joint_interprocedural_analysis_v2 import validate_joint_replay_v2


JOINT_FIXED_POINT_V2_FORMAT = (
    "spaghetti-extractor-joint-interprocedural-fixed-point-v2"
)
JOINT_AUTHORITY_SEMANTIC_STATE_V2_FORMAT = (
    "spaghetti-extractor-joint-authority-semantic-state-v2"
)


@dataclass(frozen=True)
class JointFixedPointCallbacks:
    """Typed phase boundaries used by the joint fixed-point driver."""

    derive_interprocedural: Callable[
        [
            Sequence[Mapping[str, Any]],
            Mapping[str, Sequence[int]],
            Sequence[Mapping[str, Any]],
            Sequence[Mapping[str, Any]] | None,
        ],
        Mapping[str, Any],
    ]
    derive_stack_ranges: Callable[
        [
            Mapping[str, Any],
            Mapping[str, Any],
        ],
        Mapping[str, Any],
    ]
    derive_global_slots: Callable[
        [Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]
    ]
    derive_global_slot_authority: Callable[
        [
            Mapping[str, Any],
            Mapping[str, Any],
            Mapping[str, Any],
            Mapping[str, Any],
        ],
        Mapping[str, Any],
    ]
    derive_graph: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    derive_inductive_interprocedural: Callable[
        [
            Sequence[Mapping[str, Any]],
            Mapping[str, Sequence[int]],
            Sequence[Mapping[str, Any]],
            Sequence[Mapping[str, Any]],
            Sequence[Mapping[str, Any]],
        ],
        Mapping[str, Any],
    ] | None = None
    derive_dependency_scoped_global_slots: Callable[
        [Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]],
        Mapping[str, Any],
    ] | None = None


def derive_joint_fixed_point_v2(
    *,
    proposal_graph: Mapping[str, Any],
    proposal_recoveries: Sequence[Mapping[str, Any]],
    proposal_interprocedural: Mapping[str, Any] | None = None,
    proposal_call_frame_hypotheses: Sequence[Mapping[str, Any]] = (),
    proposal_slot_dependencies: Sequence[Mapping[str, Any]] = (),
    proposal_global_slot_hypotheses: Sequence[
        Mapping[str, Any] | GlobalSlotInductionHypothesisV2
    ] = (),
    callbacks: JointFixedPointCallbacks,
    finite_round_budget: int = 32,
    progress: Callable[[str, Mapping[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Close one graph-bound finite lattice and replay it without seeds.

    Proposal recoveries accelerate only the bootstrap.  Exact launch-value
    slot hypotheses may additionally seed the first authority round, but they
    are discarded immediately unless point-sensitive replay emits the
    identical typed invariant.  Acceptance depends on an unseeded
    interprocedural pass whose derived graph, stack facts, and mutable-slot
    invariants reproduce the exact facts supplied to that pass.
    """

    if (
        not isinstance(finite_round_budget, int)
        or isinstance(finite_round_budget, bool)
        or not 1 <= finite_round_budget <= 1024
    ):
        raise ValueError("joint fixed-point round budget must be between 1 and 1024")

    # Proposal discovery is already a separately cached, non-authorizing Nix
    # phase.  Re-running it inside this derivation multiplied the expensive
    # whole-program transfer cost without adding evidence.  Its checked effect
    # proposals may be used once to expose mutually recursive slot/target
    # invariants.  Every subsequent round is unseeded and must reproduce those
    # invariants and targets before they can enter the returned authority.
    bootstrap_rounds: list[dict[str, Any]] = []
    slot_hypotheses = _normalize_global_slot_hypotheses(
        proposal_global_slot_hypotheses
    )
    bootstrap: Mapping[str, Any] = (
        copy.deepcopy(dict(proposal_interprocedural))
        if proposal_interprocedural is not None
        else {
            "status": "prepared",
            "proposal_artifacts": {
                "proof_authority": False,
                "recoveries": [
                    copy.deepcopy(dict(row)) for row in proposal_recoveries
                ],
                "call_frame_hypotheses": [
                    copy.deepcopy(dict(row))
                    for row in proposal_call_frame_hypotheses
                ],
                "slot_dependencies": [
                    copy.deepcopy(dict(row))
                    for row in proposal_slot_dependencies
                ],
                "signature": canonical_sha256({
                    "recoveries": list(proposal_recoveries),
                    "call_frame_hypotheses": list(
                        proposal_call_frame_hypotheses
                    ),
                    "slot_dependencies": list(proposal_slot_dependencies),
                }),
            },
        }
    )
    bootstrap_graph: Mapping[str, Any] = proposal_graph
    bootstrap_converged = True
    invariants: tuple[Mapping[str, Any], ...] = ()
    stack_entry_offsets: Mapping[str, Sequence[int]] = {}
    stack_range_facts: tuple[Mapping[str, Any], ...] = ()
    authoritative_rounds: list[dict[str, Any]] = []
    authoritative_converged = False
    interprocedural: Mapping[str, Any] = {}
    cold_graph: Mapping[str, Any] = {}
    stack_ranges: Mapping[str, Any] = {}
    slot_analysis: Mapping[str, Any] = {}
    slot_authority: Mapping[str, Any] = {}
    final_signature: str | None = None
    final_evidence_stable = False
    bootstrap_authority_invariants: tuple[Mapping[str, Any], ...] = ()

    if proposal_interprocedural is not None:
        fixed = _mapping(bootstrap.get("fixed_point"))
        if (
            fixed.get("proposal_only") is not True
            or fixed.get("cold_initial_recoveries_empty") is not False
            or fixed.get("static_recovery_authority_seeded") is True
        ):
            raise ValueError(
                "proposal interprocedural bootstrap is not a non-authorizing "
                "proposal-only artifact"
            )
        bootstrap_graph = callbacks.derive_graph(bootstrap)
        bootstrap_stack, bootstrap_slots, bootstrap_authority = (
            _derive_graph_evidence(
                graph=bootstrap_graph,
                interprocedural=bootstrap,
                callbacks=callbacks,
                progress=progress,
                round_index=0,
            )
        )
        bootstrap_authority_invariants = _global_slot_invariants(
            bootstrap_authority
        )
        invariants = bootstrap_authority_invariants
        stack_entry_offsets = _stack_entry_offsets(bootstrap_stack)
        stack_range_facts = _mapping_rows(
            bootstrap_stack.get("checked_range_facts")
        )
        bootstrap_converged = not any(
            row.get("status") == "violated"
            for artifact in (
                bootstrap_graph,
                bootstrap_stack,
                bootstrap_slots,
                bootstrap_authority,
            )
            for row in _mapping_rows(artifact.get("issues"))
        )
        bootstrap_rounds.append({
            "round": 0,
            "proof_authority": False,
            "graph_id": bootstrap_graph.get("id"),
            "graph_status": bootstrap_graph.get("status"),
            "interprocedural_status": bootstrap.get("status"),
            "global_slot_invariants": len(invariants),
            "checked_stack_ranges": len(stack_range_facts),
            "stack_entry_units": len(stack_entry_offsets),
            "signature": _iteration_signature(
                bootstrap=bootstrap,
                stack_ranges=bootstrap_stack,
                slot_analysis=bootstrap_slots,
                slot_authority=bootstrap_authority,
            ),
        })

    invariants, introduced_slot_hypothesis_ids, shadowed_slot_hypothesis_ids = (
        _merge_initial_global_slot_hypotheses(
            invariants,
            slot_hypotheses,
        )
    )

    for round_index in range(1, finite_round_budget + 1):
        input_semantic_state = _authority_semantic_state(
            invariants, stack_entry_offsets, stack_range_facts
        )
        input_signature = canonical_sha256(input_semantic_state)
        input_evidence_signature = _authority_evidence_signature(
            invariants, stack_entry_offsets, stack_range_facts
        )
        input_family_signatures = _authority_family_signatures(
            input_semantic_state
        )
        _progress(progress, "round_started", {
            "round": round_index,
            "global_slot_invariants": len(invariants),
            "stack_entry_units": len(stack_entry_offsets),
            "checked_stack_ranges": len(stack_range_facts),
            "input_authority_signature": input_signature,
            "input_authority_evidence_signature": input_evidence_signature,
        })
        target_hypotheses = tuple(
            copy.deepcopy(dict(row)) for row in proposal_recoveries
        )
        interprocedural = (
            callbacks.derive_interprocedural(
                invariants,
                stack_entry_offsets,
                stack_range_facts,
                None,
            )
            if callbacks.derive_inductive_interprocedural is None
            else callbacks.derive_inductive_interprocedural(
                invariants,
                stack_entry_offsets,
                stack_range_facts,
                target_hypotheses,
                proposal_call_frame_hypotheses,
            )
        )
        _progress(progress, "interprocedural_derived", {
            "round": round_index,
            "status": interprocedural.get("status"),
            "recovered_targets": len(
                _mapping_rows(interprocedural.get("recovered_targets"))
            ),
            "call_summaries": len(_mapping_rows(
                _mapping(interprocedural.get("call_summaries")).get("summaries")
            )),
            "analysis_rounds": _mapping(
                interprocedural.get("fixed_point")
            ).get("rounds"),
        })
        cold_graph = callbacks.derive_graph(interprocedural)
        _progress(progress, "graph_derived", {
            "round": round_index,
            "status": cold_graph.get("status"),
            "graph_id": cold_graph.get("id"),
            "reachable_units": _sequence_len(cold_graph.get("reachable_units")),
            "frontiers": len(_mapping_rows(cold_graph.get("frontiers"))),
        })
        stack_ranges, slot_analysis, slot_authority = _derive_graph_evidence(
            graph=cold_graph,
            interprocedural=interprocedural,
            callbacks=callbacks,
            progress=progress,
            round_index=round_index,
        )
        next_invariants = _global_slot_invariants(slot_authority)
        next_stack_entry_offsets = _stack_entry_offsets(stack_ranges)
        next_stack_range_facts = _mapping_rows(
            stack_ranges.get("checked_range_facts")
        )
        output_semantic_state = _authority_semantic_state(
            next_invariants,
            next_stack_entry_offsets,
            next_stack_range_facts,
        )
        output_signature = canonical_sha256(output_semantic_state)
        output_evidence_signature = _authority_evidence_signature(
            next_invariants,
            next_stack_entry_offsets,
            next_stack_range_facts,
        )
        output_family_signatures = _authority_family_signatures(
            output_semantic_state
        )
        changed_semantic_families = sorted(
            family
            for family in input_family_signatures
            if input_family_signatures[family]
            != output_family_signatures[family]
        )
        semantic_state_stable = output_signature == input_signature
        evidence_stable = (
            output_evidence_signature == input_evidence_signature
        )
        final_signature = _iteration_signature(
            bootstrap=interprocedural,
            stack_ranges=stack_ranges,
            slot_analysis=slot_analysis,
            slot_authority=slot_authority,
        )
        authoritative_rounds.append({
            "round": round_index,
            "signature": final_signature,
            "graph_id": cold_graph.get("id"),
            "graph_status": cold_graph.get("status"),
            "interprocedural_status": interprocedural.get("status"),
            "global_slot_invariants": len(next_invariants),
            "checked_stack_ranges": len(
                stack_ranges.get("checked_range_facts", ())
            ),
            "stack_entry_units": len(next_stack_entry_offsets),
            "input_authority_signature": input_signature,
            "output_authority_signature": output_signature,
            "input_authority_evidence_signature": (
                input_evidence_signature
            ),
            "output_authority_evidence_signature": (
                output_evidence_signature
            ),
            "semantic_state_stable": semantic_state_stable,
            "evidence_identity_stable": evidence_stable,
            "changed_semantic_families": changed_semantic_families,
        })
        _progress(progress, "round_finished", {
            **authoritative_rounds[-1],
            "converged": semantic_state_stable,
        })
        invariants = next_invariants
        stack_entry_offsets = next_stack_entry_offsets
        stack_range_facts = next_stack_range_facts
        final_evidence_stable = evidence_stable
        if semantic_state_stable:
            authoritative_converged = True
            break

    _progress(progress, "joint_replay_started", {
        "authoritative_converged": authoritative_converged,
        "authoritative_rounds": len(authoritative_rounds),
    })
    payload = validate_joint_replay_v2(
        proposal_graph=proposal_graph,
        proposal_recoveries=proposal_recoveries,
        stack_range_analysis=stack_ranges,
        global_slot_analysis=slot_analysis,
        global_slot_authority=slot_authority,
        interprocedural=interprocedural,
        cold_graph=cold_graph,
        authoritative_semantics_stable=authoritative_converged,
        proposal_slot_dependencies=proposal_slot_dependencies,
    )
    _progress(progress, "joint_replay_finished", {
        "status": payload.get("status"),
        "issues": len(_mapping_rows(payload.get("issues"))),
    })
    issues = [
        copy.deepcopy(dict(issue))
        for issue in payload.get("issues", ())
        if isinstance(issue, Mapping)
    ]
    if not authoritative_converged:
        issues.append({
            "status": "incomplete",
            "code": "authoritative_joint_lattice_round_budget_exceeded",
            "round_budget": finite_round_budget,
        })
    authoritative_unseeded = (
        _mapping(interprocedural.get("fixed_point")).get(
            "cold_initial_recoveries_empty"
        )
        is True
        and _mapping(interprocedural.get("fixed_point")).get("proposal_only")
        is False
        and _mapping(interprocedural.get("fixed_point")).get(
            "static_recovery_authority_seeded"
        )
        is False
    )
    if not authoritative_unseeded:
        issues.append({
            "status": "violated",
            "code": "authoritative_interprocedural_replay_seeded",
        })
    fixed_point = {
        "format": JOINT_FIXED_POINT_V2_FORMAT,
        "status": "complete" if authoritative_converged else "incomplete",
        "converged": authoritative_converged,
        "bootstrap_converged": bootstrap_converged,
        "authoritative_converged": authoritative_converged,
        "convergence_basis": JOINT_AUTHORITY_SEMANTIC_STATE_V2_FORMAT,
        "final_evidence_identity_stable": final_evidence_stable,
        "round_budget": finite_round_budget,
        "rounds": bootstrap_rounds,
        "authoritative_rounds": authoritative_rounds,
        "proposal_bootstrap_only": True,
        "prepared_proposal_reused": True,
        "authoritative_interprocedural_unseeded": authoritative_unseeded,
        "global_slot_induction": {
            "proof_authority": False,
            "hypothesis_ids": [hypothesis.id for hypothesis in slot_hypotheses],
            "invariant_content_ids": [
                hypothesis.invariant.content_id for hypothesis in slot_hypotheses
            ],
            "introduced_content_ids": sorted(introduced_slot_hypothesis_ids),
            "shadowed_by_bootstrap_authority_content_ids": sorted(
                shadowed_slot_hypothesis_ids
            ),
            "reproduced_content_ids": sorted(
                introduced_slot_hypothesis_ids
                & _global_slot_content_ids(invariants)
            ),
            "not_reproduced_content_ids": sorted(
                introduced_slot_hypothesis_ids
                - _global_slot_content_ids(invariants)
            ),
            "first_authority_round_only": True,
        },
        "final_signature": final_signature,
        "dependency_signature": canonical_sha256({
            "cold_graph_id": cold_graph.get("id"),
            "global_slot_content_ids": sorted(
                str(row.get("content_id")) for row in invariants
            ),
            "stack_entry_offsets_sha256": canonical_sha256(stack_entry_offsets),
            "interprocedural_signature": _mapping(
                interprocedural.get("fixed_point")
            ).get("cold_replay_signature"),
        }),
    }
    status = (
        "violated"
        if any(row.get("status") == "violated" for row in issues)
        else "complete"
        if payload.get("status") == "complete" and authoritative_converged
        else "incomplete"
    )
    return {
        **payload,
        "status": status,
        "issues": sorted(
            _deduplicate(issues),
            key=lambda row: (
                str(row.get("status")),
                str(row.get("code")),
                str(row.get("exit_id", "")),
            ),
        ),
        "joint_fixed_point": fixed_point,
        "bootstrap_diagnostics": {
            "proof_authority": False,
            "status": bootstrap.get("status"),
            "fixed_point": copy.deepcopy(bootstrap.get("fixed_point")),
            "proposal_graph": copy.deepcopy(dict(proposal_graph)),
            "derived_graph": copy.deepcopy(dict(bootstrap_graph)),
            "proposal_slot_dependencies": [
                copy.deepcopy(dict(row)) for row in proposal_slot_dependencies
            ],
            "proposal_global_slot_hypotheses": [
                hypothesis.to_payload() for hypothesis in slot_hypotheses
            ],
            "bootstrap_authority_global_slot_content_ids": sorted(
                _global_slot_content_ids(bootstrap_authority_invariants)
            ),
            "converged": bootstrap_converged,
        },
    }


def _derive_graph_evidence(
    *,
    graph: Mapping[str, Any],
    interprocedural: Mapping[str, Any],
    callbacks: JointFixedPointCallbacks,
    progress: Callable[[str, Mapping[str, Any]], None] | None,
    round_index: int,
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    stack_ranges = callbacks.derive_stack_ranges(
        graph,
        interprocedural,
    )
    _progress(progress, "stack_ranges_derived", {
        "round": round_index,
        "status": stack_ranges.get("status"),
        "entry_units": len(_mapping(stack_ranges.get("entry_offsets"))),
        "checked_ranges": len(
            _mapping_rows(stack_ranges.get("checked_range_facts"))
        ),
        "checked_spatial_facts": len(
            _mapping_rows(stack_ranges.get("checked_spatial_facts"))
        ),
        "frontiers": len(_mapping_rows(stack_ranges.get("frontiers"))),
    })
    slot_analysis = (
        callbacks.derive_global_slots(graph, stack_ranges)
        if callbacks.derive_dependency_scoped_global_slots is None
        else callbacks.derive_dependency_scoped_global_slots(
            graph,
            stack_ranges,
            interprocedural,
        )
    )
    _progress(progress, "global_slots_derived", {
        "round": round_index,
        "status": slot_analysis.get("status"),
        "complete_slots": _mapping(slot_analysis.get("counts")).get(
            "complete_slots"
        ),
        "incomplete_slots": _mapping(slot_analysis.get("counts")).get(
            "incomplete_slots"
        ),
        "issues": len(_mapping_rows(slot_analysis.get("issues"))),
    })
    slot_authority = callbacks.derive_global_slot_authority(
        slot_analysis,
        stack_ranges,
        graph,
        interprocedural,
    )
    _progress(progress, "global_slot_authority_derived", {
        "round": round_index,
        "status": slot_authority.get("status"),
        "global_slot_invariants": len(
            _mapping_rows(slot_authority.get("global_slot_invariants"))
        ),
        "issues": len(_mapping_rows(slot_authority.get("issues"))),
    })
    return stack_ranges, slot_analysis, slot_authority


def _progress(
    callback: Callable[[str, Mapping[str, Any]], None] | None,
    phase: str,
    details: Mapping[str, Any],
) -> None:
    if callback is not None:
        callback(phase, details)


def _global_slot_invariants(
    authority: Mapping[str, Any],
) -> tuple[Mapping[str, Any], ...]:
    return tuple(
        copy.deepcopy(dict(row))
        for row in authority.get("global_slot_invariants", ())
        if isinstance(row, Mapping)
    )


def _normalize_global_slot_hypotheses(
    values: Sequence[Mapping[str, Any] | GlobalSlotInductionHypothesisV2],
) -> tuple[GlobalSlotInductionHypothesisV2, ...]:
    result: list[GlobalSlotInductionHypothesisV2] = []
    try:
        for value in values:
            result.append(
                value
                if isinstance(value, GlobalSlotInductionHypothesisV2)
                else GlobalSlotInductionHypothesisV2.parse(value)
            )
    except (GlobalSlotHypothesisV2Error, TypeError, ValueError) as exc:
        raise ValueError(f"global-slot induction hypothesis is invalid: {exc}") from exc
    result.sort(key=lambda item: item.id)
    if len({item.id for item in result}) != len(result):
        raise ValueError("global-slot induction hypothesis IDs must be unique")
    slot_rvas = [item.invariant.slot_rva for item in result]
    if len(set(slot_rvas)) != len(slot_rvas):
        raise ValueError(
            "global-slot induction hypotheses must contain one record per slot"
        )
    return tuple(result)


def _merge_initial_global_slot_hypotheses(
    authoritative: Sequence[Mapping[str, Any]],
    hypotheses: Sequence[GlobalSlotInductionHypothesisV2],
) -> tuple[tuple[Mapping[str, Any], ...], frozenset[str], frozenset[str]]:
    """Add proposals once, with independently replayed authority taking priority."""

    rows = [copy.deepcopy(dict(row)) for row in authoritative]
    content_ids = set(_global_slot_content_ids(rows))
    occupied_slots = {
        int(row["slot_rva"])
        for row in rows
        if isinstance(row.get("slot_rva"), int)
        and not isinstance(row.get("slot_rva"), bool)
    }
    introduced: set[str] = set()
    shadowed: set[str] = set()
    for hypothesis in hypotheses:
        content_id = hypothesis.invariant.content_id
        if (
            content_id in content_ids
            or hypothesis.invariant.slot_rva in occupied_slots
        ):
            shadowed.add(content_id)
            continue
        rows.append(hypothesis.invariant.to_payload())
        content_ids.add(content_id)
        occupied_slots.add(hypothesis.invariant.slot_rva)
        introduced.add(content_id)
    rows.sort(key=lambda row: str(row.get("content_id", "")))
    return tuple(rows), frozenset(introduced), frozenset(shadowed)


def _global_slot_content_ids(
    values: Sequence[Mapping[str, Any]],
) -> frozenset[str]:
    return frozenset(
        str(row["content_id"])
        for row in values
        if isinstance(row.get("content_id"), str) and row.get("content_id")
    )


def _iteration_signature(
    *,
    bootstrap: Mapping[str, Any],
    stack_ranges: Mapping[str, Any],
    slot_analysis: Mapping[str, Any],
    slot_authority: Mapping[str, Any],
) -> str:
    fixed = _mapping(bootstrap.get("fixed_point"))
    return canonical_sha256(
        {
            "bootstrap_cold_signature": fixed.get("cold_replay_signature"),
            "bootstrap_dependency_inventory": fixed.get("dependencies", []),
            "bootstrap_recoveries": bootstrap.get("recovered_targets", []),
            "stack_binding": stack_ranges.get("binding"),
            "stack_range_facts": stack_ranges.get("checked_range_facts", []),
            "slot_evidence": slot_analysis.get("global_slot_evidence", []),
            "slot_invariants": slot_authority.get("global_slot_invariants", []),
        }
    )


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _mapping_rows(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(row for row in value if isinstance(row, Mapping))


def _sequence_len(value: Any) -> int:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return 0
    return len(value)


def _authority_evidence_signature(
    invariants: Sequence[Mapping[str, Any]],
    stack_entry_offsets: Mapping[str, Sequence[int]],
    stack_range_facts: Sequence[Mapping[str, Any]],
) -> str:
    return canonical_sha256({
        "global_slot_invariants": list(invariants),
        "stack_entry_offsets": stack_entry_offsets,
        "stack_range_facts": list(stack_range_facts),
    })


def _authority_semantic_state(
    invariants: Sequence[Mapping[str, Any]],
    stack_entry_offsets: Mapping[str, Sequence[int]],
    stack_range_facts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Project exactly the authority facts consumed by the next pass.

    Global-slot record identities remain significant because target and call
    evidence names those records directly.  Checked stack-range identities do
    not: ``derive_interprocedural_result_v2`` validates each record and passes
    only the accepted unit set plus ``stack_entry_offsets`` to the typed
    analyzer.  Their graph/effect hashes therefore record evidence lineage,
    not another abstract-state coordinate.  Comparing those hashes here forms
    an artificial ``H(previous evidence)`` chain even after the stack facts
    have reached a post-fixed point.

    Malformed or unknown stack records retain their complete payload so this
    projection cannot hide corruption.  The final joint replay still checks
    the exact current stack binding against the current graph and call-effect
    inventory.
    """

    return {
        "format": JOINT_AUTHORITY_SEMANTIC_STATE_V2_FORMAT,
        "global_slot_invariants": [
            copy.deepcopy(dict(row)) for row in invariants
        ],
        "stack_entry_offsets": {
            unit_id: list(offsets)
            for unit_id, offsets in sorted(stack_entry_offsets.items())
        },
        "checked_stack_ranges": sorted(
            (_stack_range_semantic_projection(row) for row in stack_range_facts),
            key=canonical_sha256,
        ),
    }


def _stack_range_semantic_projection(
    row: Mapping[str, Any],
) -> dict[str, Any]:
    expected = {
        "format",
        "status",
        "source_kind",
        "range_kind",
        "base_expression",
        "offset_start",
        "offset_end",
        "applies_to_unit_ids",
        "disjoint_from_image",
        "authority_binding",
        "id",
    }
    binding = row.get("authority_binding")
    if (
        set(row) != expected
        or row.get("format") != CHECKED_MEMORY_RANGE_FACT_V2_FORMAT
        or not isinstance(binding, Mapping)
    ):
        return {
            "malformed_or_unknown_record": copy.deepcopy(dict(row)),
        }
    return {
        "format": row["format"],
        "status": row["status"],
        "source_kind": row["source_kind"],
        "range_kind": row["range_kind"],
        "base_expression": copy.deepcopy(row["base_expression"]),
        "offset_start": row["offset_start"],
        "offset_end": row["offset_end"],
        "applies_to_unit_ids": copy.deepcopy(row["applies_to_unit_ids"]),
        "disjoint_from_image": copy.deepcopy(row["disjoint_from_image"]),
        "binary_and_launch_binding": {
            field: copy.deepcopy(binding.get(field))
            for field in (
                "pe_sha256",
                "machine_ir_sha256",
                "launch_assumptions_sha256",
                "image_base",
                "size_of_image",
            )
        },
    }


def _authority_family_signatures(
    semantic_state: Mapping[str, Any],
) -> dict[str, str]:
    return {
        family: canonical_sha256(semantic_state.get(family))
        for family in (
            "global_slot_invariants",
            "stack_entry_offsets",
            "checked_stack_ranges",
        )
    }


def _stack_entry_offsets(
    analysis: Mapping[str, Any],
) -> dict[str, tuple[int, ...]]:
    raw = analysis.get("entry_offsets")
    if not isinstance(raw, Mapping):
        return {}
    result: dict[str, tuple[int, ...]] = {}
    for unit_id, values in raw.items():
        if (
            isinstance(unit_id, str)
            and isinstance(values, Sequence)
            and not isinstance(values, (str, bytes))
            and values
            and all(
                isinstance(value, int) and not isinstance(value, bool)
                for value in values
            )
        ):
            result[unit_id] = tuple(sorted(set(int(value) for value in values)))
    return dict(sorted(result.items()))


def _deduplicate(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        copied = copy.deepcopy(dict(row))
        result[canonical_sha256(copied)] = copied
    return list(result.values())


__all__ = [
    "JOINT_AUTHORITY_SEMANTIC_STATE_V2_FORMAT",
    "JOINT_FIXED_POINT_V2_FORMAT",
    "JointFixedPointCallbacks",
    "derive_joint_fixed_point_v2",
]
