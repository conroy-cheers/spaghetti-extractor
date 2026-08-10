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

from .artifact_identity_v2 import canonical_sha256
from .joint_interprocedural_analysis_v2 import validate_joint_replay_v2


JOINT_FIXED_POINT_V2_FORMAT = (
    "spaghetti-extractor-joint-interprocedural-fixed-point-v2"
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
    proposal_call_frame_hypotheses: Sequence[Mapping[str, Any]] = (),
    callbacks: JointFixedPointCallbacks,
    finite_round_budget: int = 32,
) -> dict[str, Any]:
    """Close one graph-bound finite lattice and replay it without seeds.

    Proposal recoveries accelerate only the bootstrap.  Acceptance depends on
    an unseeded interprocedural pass whose derived graph, stack facts, and
    mutable-slot invariants reproduce the exact facts supplied to that pass.
    """

    if (
        not isinstance(finite_round_budget, int)
        or isinstance(finite_round_budget, bool)
        or not 1 <= finite_round_budget <= 1024
    ):
        raise ValueError("joint fixed-point round budget must be between 1 and 1024")

    # Proposal discovery is already a separately cached, non-authorizing Nix
    # phase.  Re-running it inside this derivation multiplied the expensive
    # whole-program transfer cost without adding evidence.  Keep only its
    # finite recoveries as optional hypotheses; authority still starts from
    # the launch-only bottom state and uses them solely for genuinely recursive
    # SCC replay.
    bootstrap_rounds: list[dict[str, Any]] = []
    bootstrap: Mapping[str, Any] = {
        "status": "prepared",
        "proposal_artifacts": {
            "proof_authority": False,
            "recoveries": [copy.deepcopy(dict(row)) for row in proposal_recoveries],
            "call_frame_hypotheses": [
                copy.deepcopy(dict(row))
                for row in proposal_call_frame_hypotheses
            ],
            "signature": canonical_sha256(proposal_recoveries),
        },
    }
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

    for round_index in range(1, finite_round_budget + 1):
        input_signature = _authority_state_signature(
            invariants, stack_entry_offsets, stack_range_facts
        )
        hypotheses = tuple(
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
                hypotheses,
                proposal_call_frame_hypotheses,
            )
        )
        cold_graph = callbacks.derive_graph(interprocedural)
        stack_ranges, slot_analysis, slot_authority = _derive_graph_evidence(
            graph=cold_graph,
            interprocedural=interprocedural,
            callbacks=callbacks,
        )
        next_invariants = _global_slot_invariants(slot_authority)
        next_stack_entry_offsets = _stack_entry_offsets(stack_ranges)
        next_stack_range_facts = _mapping_rows(
            stack_ranges.get("checked_range_facts")
        )
        output_signature = _authority_state_signature(
            next_invariants,
            next_stack_entry_offsets,
            next_stack_range_facts,
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
        })
        invariants = next_invariants
        stack_entry_offsets = next_stack_entry_offsets
        stack_range_facts = next_stack_range_facts
        if output_signature == input_signature:
            authoritative_converged = True
            break

    payload = validate_joint_replay_v2(
        proposal_graph=proposal_graph,
        proposal_recoveries=proposal_recoveries,
        stack_range_analysis=stack_ranges,
        global_slot_analysis=slot_analysis,
        global_slot_authority=slot_authority,
        interprocedural=interprocedural,
        cold_graph=cold_graph,
        authoritative_evidence_stable=authoritative_converged,
    )
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
        "round_budget": finite_round_budget,
        "rounds": bootstrap_rounds,
        "authoritative_rounds": authoritative_rounds,
        "proposal_bootstrap_only": True,
        "prepared_proposal_reused": True,
        "authoritative_interprocedural_unseeded": authoritative_unseeded,
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
            "converged": bootstrap_converged,
        },
    }


def _derive_graph_evidence(
    *,
    graph: Mapping[str, Any],
    interprocedural: Mapping[str, Any],
    callbacks: JointFixedPointCallbacks,
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    stack_ranges = callbacks.derive_stack_ranges(
        graph,
        interprocedural,
    )
    slot_analysis = (
        callbacks.derive_global_slots(graph, stack_ranges)
        if callbacks.derive_dependency_scoped_global_slots is None
        else callbacks.derive_dependency_scoped_global_slots(
            graph,
            stack_ranges,
            interprocedural,
        )
    )
    slot_authority = callbacks.derive_global_slot_authority(
        slot_analysis,
        stack_ranges,
        graph,
        interprocedural,
    )
    return stack_ranges, slot_analysis, slot_authority


def _global_slot_invariants(
    authority: Mapping[str, Any],
) -> tuple[Mapping[str, Any], ...]:
    return tuple(
        copy.deepcopy(dict(row))
        for row in authority.get("global_slot_invariants", ())
        if isinstance(row, Mapping)
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


def _authority_state_signature(
    invariants: Sequence[Mapping[str, Any]],
    stack_entry_offsets: Mapping[str, Sequence[int]],
    stack_range_facts: Sequence[Mapping[str, Any]],
) -> str:
    return canonical_sha256({
        "global_slot_invariants": list(invariants),
        "stack_entry_offsets": stack_entry_offsets,
        "stack_range_facts": list(stack_range_facts),
    })


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
    "JOINT_FIXED_POINT_V2_FORMAT",
    "JointFixedPointCallbacks",
    "derive_joint_fixed_point_v2",
]
