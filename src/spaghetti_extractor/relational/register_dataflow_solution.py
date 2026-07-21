from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from ..errors import StageAInputError
from .analyses.register_lattice import (
    RegisterRelation,
    _register_relation_join,
    _register_relation_key,
    _register_relation_payload,
)
from .register_dataflow_aggregate import parse_register_dataflow_aggregate
from .register_transfer_core import (
    REGISTER_ORDER,
    evaluate_register_transfer_program,
    parse_register_transfer_context,
    parse_register_transfer_programs,
)


@dataclass(frozen=True)
class RegisterDataflowSolution:
    original_sha256: str
    candidate_sha256: str
    graph_sha256: str
    aggregate_sha256: str
    region_ids: tuple[str, ...]
    input_states: tuple[dict[str, RegisterRelation], ...]
    output_states: tuple[dict[str, RegisterRelation], ...]
    output_reasons: tuple[dict[str, str], ...]


def _state(
    relations: Sequence[Mapping[str, Any]],
) -> dict[str, RegisterRelation]:
    return {
        str(relation["register"]): _register_relation_payload(dict(relation))
        for relation in relations
    }


def _same_state(
    left: Mapping[str, RegisterRelation],
    right: Mapping[str, RegisterRelation],
) -> bool:
    return all(
        _register_relation_key(left[register])
        == _register_relation_key(right[register])
        for register in REGISTER_ORDER
    )


def validate_register_dataflow_solution(
    *,
    aggregate_payload: object,
    transfer_programs_payload: object,
    expected_original_sha256: str,
    expected_candidate_sha256: str,
    expected_graph_sha256: str,
) -> RegisterDataflowSolution:
    """Check a distributed proposal without rerunning its iterative solver.

    The result remains untrusted proof guidance. This checker establishes exact
    artifact identity, graph closure, and a post-fixed local transfer condition;
    generated Lean must still replay every accepted relation claim.
    """
    programs_artifact = parse_register_transfer_programs(
        transfer_programs_payload,
        expected_original_sha256=expected_original_sha256,
        expected_candidate_sha256=expected_candidate_sha256,
        expected_graph_sha256=expected_graph_sha256,
    )
    aggregate = parse_register_dataflow_aggregate(
        aggregate_payload,
        expected_original_sha256=expected_original_sha256,
        expected_candidate_sha256=expected_candidate_sha256,
        expected_graph_sha256=expected_graph_sha256,
        require_complete=True,
    )
    programs = list(programs_artifact["programs"])
    region_ids = tuple(str(program["region_id"]) for program in programs)
    aggregate_by_id = {
        str(region["id"]): region for region in aggregate["regions"]
    }
    if set(aggregate_by_id) != set(region_ids):
        raise StageAInputError(
            "register dataflow solution region inventory does not match programs"
        )
    input_states = tuple(
        _state(aggregate_by_id[region_id]["input_relations"])
        for region_id in region_ids
    )
    output_states = tuple(
        _state(aggregate_by_id[region_id]["output_relations"])
        for region_id in region_ids
    )
    output_reasons = tuple(
        dict(aggregate_by_id[region_id]["reasons"])
        for region_id in region_ids
    )
    region_index = {region_id: index for index, region_id in enumerate(region_ids)}
    propagation = programs_artifact["propagation"]
    propagation_regions = {
        str(region["id"]): region for region in propagation["regions"]
    }
    if set(propagation_regions) != set(region_ids):
        raise StageAInputError(
            "register dataflow solution propagation inventory differs"
        )
    incoming: dict[str, list[dict[str, Any]]] = {
        region_id: [] for region_id in region_ids
    }
    for edge in propagation["edges"]:
        incoming[str(edge["target_id"])].append(edge)

    for target_id in region_ids:
        target = propagation_regions[target_id]
        expected_input: dict[str, RegisterRelation] = {}
        for register in REGISTER_ORDER:
            candidates: list[RegisterRelation] = []
            seed = target["seed_relation"]
            if seed is not None:
                candidates.append(str(seed))
            for edge in incoming[target_id]:
                source_output = output_states[region_index[str(edge["source_id"])]]
                result_relations = {
                    str(relation["register"]): _register_relation_payload(relation)
                    for relation in edge["result_relations"]
                }
                preserved = set(edge["preserved_registers"])
                if edge["kind"] == "internal_callsite_preservation_summary":
                    contribution: RegisterRelation = (
                        source_output[register]
                        if register in preserved
                        and register in result_relations
                        and _register_relation_key(source_output[register])
                            == _register_relation_key(result_relations[register])
                        else "related_word"
                    )
                elif not edge["environment_barrier"]:
                    contribution = source_output[register]
                elif register in result_relations:
                    contribution = result_relations[register]
                elif register in preserved:
                    contribution = source_output[register]
                else:
                    contribution = "related_word"
                candidates.append(contribution)
            if not candidates:
                raise StageAInputError(
                    f"register dataflow solution region {target_id} has no input seed"
                )
            expected_input[register] = _register_relation_join(candidates)
            if register in target["stack_window_registers"]:
                expected_input[register] = "related_word"
        submitted_input = input_states[region_index[target_id]]
        if not _same_state(expected_input, submitted_input):
            raise StageAInputError(
                f"register dataflow solution input for {target_id} is not graph-closed"
            )

    # The programs artifact deliberately preserves the canonical JSON form.
    # Normalize it once before replay so immutable-memory ranges carry the
    # derived bounds and decoded bytes required by the evaluator.
    context = parse_register_transfer_context(programs_artifact["context"])
    for index, program in enumerate(programs):
        evaluated = evaluate_register_transfer_program(
            program,
            input_states[index],
            context_payload=context,
            validate=False,
            validate_context=False,
        )
        submitted = output_states[index]
        reasons = output_reasons[index]
        for register in REGISTER_ORDER:
            proposed = evaluated.relations[register]
            if reasons[register] == "monotone_transfer_widening":
                stable = _register_relation_join([submitted[register], proposed])
                if _register_relation_key(stable) != _register_relation_key(
                    submitted[register]
                ):
                    raise StageAInputError(
                        "register dataflow solution widened output is not stable"
                    )
            elif (
                _register_relation_key(submitted[register])
                != _register_relation_key(proposed)
                or reasons[register] != evaluated.reasons[register]
            ):
                raise StageAInputError(
                    "register dataflow solution output does not match transfer program"
                )

    return RegisterDataflowSolution(
        original_sha256=expected_original_sha256,
        candidate_sha256=expected_candidate_sha256,
        graph_sha256=expected_graph_sha256,
        aggregate_sha256=str(aggregate["aggregate_sha256"]),
        region_ids=region_ids,
        input_states=input_states,
        output_states=output_states,
        output_reasons=output_reasons,
    )


__all__ = [
    "RegisterDataflowSolution",
    "validate_register_dataflow_solution",
]
