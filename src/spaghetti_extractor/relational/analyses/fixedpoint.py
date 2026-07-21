from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Callable, Generic, Sequence, TypeVar

from .dataflow import strongly_connected_components


StateT = TypeVar("StateT")
ReasonT = TypeVar("ReasonT")


@dataclass(frozen=True)
class MonotoneFixedPointResult(Generic[StateT, ReasonT]):
    input_states: tuple[StateT | None, ...]
    output_states: tuple[StateT | None, ...]
    output_reason_states: tuple[ReasonT | None, ...]
    converged: bool
    iterations: int
    transfer_evaluations: int


def solve_monotone_fixed_point(
    *,
    initial_input_states: Sequence[StateT | None],
    initial_output_states: Sequence[StateT | None],
    initial_output_reason_states: Sequence[ReasonT | None],
    successors: Sequence[Sequence[int]],
    evaluate_output: Callable[
        [int, StateT, StateT | None], tuple[StateT, ReasonT]
    ],
    recompute_input: Callable[
        [int, Sequence[StateT | None]], StateT | None
    ],
    max_iterations: int,
) -> MonotoneFixedPointResult[StateT, ReasonT]:
    """Solve a finite monotone proposal while preserving synchronous rounds.

    The callback owns the semantic transfer and monotone output join. This
    engine owns only deterministic scheduling. It is deliberately independent
    of the register lattice so the same implementation can be replayed for a
    whole graph, an SCC, or a Nix pack.
    """
    region_count = len(successors)
    if not (
        len(initial_input_states) == region_count
        and len(initial_output_states) == region_count
        and len(initial_output_reason_states) == region_count
    ):
        raise ValueError("fixed-point state inventories do not match the graph")
    if max_iterations <= 0:
        raise ValueError("fixed-point iteration bound must be positive")
    if any(
        target < 0 or target >= region_count
        for targets in successors
        for target in targets
    ):
        raise ValueError("fixed-point successor is outside the state inventory")

    input_states = copy.deepcopy(list(initial_input_states))
    output_states = copy.deepcopy(list(initial_output_states))
    output_reason_states = copy.deepcopy(
        list(initial_output_reason_states)
    )
    dirty_regions = {
        region_index
        for region_index, state in enumerate(input_states)
        if state is not None
    }
    transfer_evaluations = 0
    converged = False
    iterations = 0

    for iteration in range(max_iterations):
        iterations = iteration + 1
        next_outputs = copy.deepcopy(output_states)
        next_reasons = copy.deepcopy(output_reason_states)
        changed_output_regions: set[int] = set()
        for region_index in sorted(dirty_regions):
            input_state = input_states[region_index]
            if input_state is None:
                continue
            transfer_evaluations += 1
            output_state, output_reasons = evaluate_output(
                region_index,
                input_state,
                output_states[region_index],
            )
            if output_state != output_states[region_index]:
                changed_output_regions.add(region_index)
            next_outputs[region_index] = output_state
            next_reasons[region_index] = output_reasons

        affected_inputs = {
            target_index
            for source_index in changed_output_regions
            for target_index in successors[source_index]
        }
        next_inputs = copy.deepcopy(input_states)
        changed_input_regions: set[int] = set()
        for region_index in sorted(affected_inputs):
            input_state = recompute_input(region_index, next_outputs)
            if input_state != input_states[region_index]:
                changed_input_regions.add(region_index)
            next_inputs[region_index] = input_state

        if not changed_input_regions and not changed_output_regions:
            output_reason_states = next_reasons
            converged = True
            break
        input_states = next_inputs
        output_states = next_outputs
        output_reason_states = next_reasons
        dirty_regions = changed_input_regions

    return MonotoneFixedPointResult(
        input_states=tuple(input_states),
        output_states=tuple(output_states),
        output_reason_states=tuple(output_reason_states),
        converged=converged,
        iterations=iterations,
        transfer_evaluations=transfer_evaluations,
    )


def solve_monotone_fixed_point_by_scc(
    *,
    initial_input_states: Sequence[StateT | None],
    initial_output_states: Sequence[StateT | None],
    initial_output_reason_states: Sequence[ReasonT | None],
    successors: Sequence[Sequence[int]],
    evaluate_output: Callable[
        [int, StateT, StateT | None], tuple[StateT, ReasonT]
    ],
    recompute_input: Callable[
        [int, Sequence[StateT | None]], StateT | None
    ],
    max_iterations: int,
) -> MonotoneFixedPointResult[StateT, ReasonT]:
    """Solve SCCs in condensation order using only predecessor summaries.

    Cross-SCC outputs are immutable once a component starts. This is the
    execution model used by pack-local Nix derivations; the global arrays here
    are only an in-process compatibility representation.
    """
    region_count = len(successors)
    if not (
        len(initial_input_states) == region_count
        and len(initial_output_states) == region_count
        and len(initial_output_reason_states) == region_count
    ):
        raise ValueError("fixed-point state inventories do not match the graph")
    if max_iterations <= 0:
        raise ValueError("fixed-point iteration bound must be positive")

    partition = strongly_connected_components(successors)
    input_states = copy.deepcopy(list(initial_input_states))
    output_states = copy.deepcopy(list(initial_output_states))
    output_reason_states = copy.deepcopy(
        list(initial_output_reason_states)
    )
    transfer_evaluations = 0
    iterations = 0
    converged = True

    for component_id in partition.topological_component_ids:
        component = partition.components[component_id]
        component_members = set(component)
        for region_index in component:
            recomputed = recompute_input(region_index, output_states)
            if recomputed is not None:
                input_states[region_index] = recomputed
        dirty_regions = {
            region_index
            for region_index in component
            if input_states[region_index] is not None
        }

        while dirty_regions:
            if iterations >= max_iterations:
                converged = False
                break
            iterations += 1
            changed_output_regions: set[int] = set()
            for region_index in sorted(dirty_regions):
                input_state = input_states[region_index]
                if input_state is None:
                    continue
                transfer_evaluations += 1
                output_state, output_reasons = evaluate_output(
                    region_index,
                    input_state,
                    output_states[region_index],
                )
                if output_state != output_states[region_index]:
                    changed_output_regions.add(region_index)
                output_states[region_index] = output_state
                output_reason_states[region_index] = output_reasons

            affected_inputs = {
                target_index
                for source_index in changed_output_regions
                for target_index in successors[source_index]
                if target_index in component_members
            }
            changed_input_regions: set[int] = set()
            for region_index in sorted(affected_inputs):
                input_state = recompute_input(region_index, output_states)
                if input_state != input_states[region_index]:
                    changed_input_regions.add(region_index)
                input_states[region_index] = input_state
            dirty_regions = changed_input_regions

        if not converged:
            break

    return MonotoneFixedPointResult(
        input_states=tuple(input_states),
        output_states=tuple(output_states),
        output_reason_states=tuple(output_reason_states),
        converged=converged,
        iterations=iterations,
        transfer_evaluations=transfer_evaluations,
    )


__all__ = [
    "MonotoneFixedPointResult",
    "solve_monotone_fixed_point",
    "solve_monotone_fixed_point_by_scc",
]
