from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

from ..errors import StageAInputError
from .analyses.fixedpoint import solve_monotone_fixed_point_by_scc
from .analyses.register_lattice import (
    RegisterRelation,
    _register_relation_join,
    _register_relation_key,
    _register_relation_payload,
)
from .register_dataflow_artifact import REGISTER_ORDER
from .register_dataflow_formats import parse_register_dataflow_pack_input
from .register_dataflow_summary_format import (
    parse_register_dataflow_pack_summary,
)
from .register_transfer_core import (
    RegisterTransferIncomplete,
    evaluate_register_transfer_program,
    parse_register_transfer_context,
    parse_register_transfer_program,
)


REGISTER_DATAFLOW_PACK_RESULT_FORMAT = "stage-a-register-dataflow-pack-result-v1"


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _state_from_relations(
    relations: Sequence[Mapping[str, Any]],
) -> dict[str, RegisterRelation]:
    state: dict[str, RegisterRelation] = {}
    for relation in relations:
        register = str(relation["register"])
        state[register] = _register_relation_payload(dict(relation))
    if tuple(state) != REGISTER_ORDER:
        raise StageAInputError(
            "register dataflow state does not cover canonical registers"
        )
    return state


def _relations_from_state(
    state: Mapping[str, RegisterRelation],
) -> list[dict[str, Any]]:
    return [
        {"register": register, **_register_relation_payload(state[register])}
        for register in REGISTER_ORDER
    ]


def _input_key(
    state: Mapping[str, RegisterRelation],
) -> tuple[tuple[str, int | None], ...]:
    return tuple(_register_relation_key(state[register]) for register in REGISTER_ORDER)


def _result_payload(body: dict[str, Any]) -> dict[str, Any]:
    return {**body, "result_sha256": _canonical_sha256(body)}


def parse_register_dataflow_pack_result(
    payload: object,
    *,
    expected_pack_id: str | None = None,
    expected_input_sha256: str | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise StageAInputError("register dataflow pack result must be an object")
    expected_fields = {
        "format",
        "status",
        "acceptance_authority",
        "pack_id",
        "input_sha256",
        "predecessor_results",
        "converged",
        "iterations",
        "transfer_evaluations",
        "regions",
        "missing_observations",
        "result_sha256",
    }
    if set(payload) != expected_fields:
        raise StageAInputError("register dataflow pack result fields do not match")
    body = {key: value for key, value in payload.items() if key != "result_sha256"}
    if payload["result_sha256"] != _canonical_sha256(body):
        raise StageAInputError("register dataflow pack result digest does not match")
    if payload["format"] != REGISTER_DATAFLOW_PACK_RESULT_FORMAT:
        raise StageAInputError("register dataflow pack result format is invalid")
    if payload["status"] not in {"complete", "incomplete"}:
        raise StageAInputError("register dataflow pack result status is invalid")
    if payload["acceptance_authority"] is not False:
        raise StageAInputError("register dataflow pack result claims authority")
    if expected_pack_id is not None and payload["pack_id"] != expected_pack_id:
        raise StageAInputError("register dataflow pack result ID does not match")
    if (
        expected_input_sha256 is not None
        and payload["input_sha256"] != expected_input_sha256
    ):
        raise StageAInputError("register dataflow pack result input does not match")
    if not isinstance(payload["regions"], list):
        raise StageAInputError("register dataflow pack result regions are invalid")
    return json.loads(json.dumps(payload))


class _MissingTransferObservation(Exception):
    def __init__(self, region_id: str, input_relations: list[dict[str, Any]]):
        self.region_id = region_id
        self.input_relations = input_relations
        super().__init__(region_id)


def solve_register_dataflow_pack(
    *,
    pack_payload: object,
    predecessor_payloads: Sequence[object],
    transfer_context_payload: object | None = None,
) -> dict[str, Any]:
    pack = parse_register_dataflow_pack_input(pack_payload)
    transfer_context = (
        parse_register_transfer_context(transfer_context_payload)
        if transfer_context_payload is not None else None
    )
    if (
        pack["transfer_context_sha256"] is not None
        and (
            transfer_context is None
            or transfer_context["context_sha256"]
                != pack["transfer_context_sha256"]
        )
    ):
        raise StageAInputError(
            "register dataflow transfer context does not match its pack"
        )
    expected_predecessors = list(pack["predecessor_ids"])
    predecessor_summaries = [
        parse_register_dataflow_pack_summary(payload)
        for payload in predecessor_payloads
    ]
    if sorted(summary["pack_id"] for summary in predecessor_summaries) != (
        expected_predecessors
    ):
        raise StageAInputError(
            "register dataflow predecessor result inventory does not match"
        )
    if any(
        summary["status"] != "complete"
        for summary in predecessor_summaries
    ):
        body = {
            "format": REGISTER_DATAFLOW_PACK_RESULT_FORMAT,
            "status": "incomplete",
            "acceptance_authority": False,
            "pack_id": pack["id"],
            "input_sha256": pack["input_sha256"],
            "predecessor_results": [
                {
                    "id": summary["pack_id"],
                    "sha256": summary["summary_sha256"],
                }
                for summary in sorted(
                    predecessor_summaries,
                    key=lambda summary: summary["pack_id"],
                )
            ],
            "converged": False,
            "iterations": 0,
            "transfer_evaluations": 0,
            "regions": [],
            "missing_observations": [{
                "code": "predecessor_incomplete",
                "predecessor_ids": sorted(
                    summary["pack_id"]
                    for summary in predecessor_summaries
                    if summary["status"] != "complete"
                ),
            }],
        }
        return _result_payload(body)

    external_outputs = {
        region["id"]: _state_from_relations(region["output_relations"])
        for summary in predecessor_summaries
        for region in summary["regions"]
    }
    regions = list(pack["regions"])
    region_index = {region["id"]: index for index, region in enumerate(regions)}
    if len(region_index) != len(regions):
        raise StageAInputError("register dataflow pack region IDs are ambiguous")
    local_region_ids = set(region_index)
    incoming: list[list[dict[str, Any]]] = [[] for _ in regions]
    successors: list[set[int]] = [set() for _ in regions]
    for edge in pack["edges"]:
        target_id = edge["target_id"]
        source_id = edge["source_id"]
        if target_id not in local_region_ids:
            raise StageAInputError("register dataflow edge target is not local")
        if source_id not in local_region_ids and source_id not in external_outputs:
            raise StageAInputError(
                "register dataflow edge source has no predecessor summary"
            )
        incoming[region_index[target_id]].append(edge)
        if source_id in local_region_ids:
            successors[region_index[source_id]].add(region_index[target_id])

    initial_inputs: list[dict[str, RegisterRelation] | None] = []
    observations: list[dict[tuple[tuple[str, int | None], ...], dict[str, Any]]] = []
    programs: list[dict[str, Any] | None] = []
    for region in regions:
        seed = region["seed_relation"]
        initial_inputs.append(
            {register: seed for register in REGISTER_ORDER}
            if seed is not None else None
        )
        program = region.get("program")
        if program is not None:
            parsed_program = parse_register_transfer_program(program)
            if parsed_program["region_id"] != region["id"]:
                raise StageAInputError(
                    "register transfer program region does not match"
                )
            by_input = {}
            programs.append(parsed_program)
        else:
            if "observations" not in region:
                raise StageAInputError(
                    "register dataflow region has no transfer semantics"
                )
            by_input = {}
            for observation in region["observations"]:
                key = _input_key(
                    _state_from_relations(observation["input_relations"])
                )
                if key in by_input:
                    raise StageAInputError(
                        "register transfer table has ambiguous input observations"
                    )
                by_input[key] = observation
            programs.append(None)
        observations.append(by_input)

    def source_output(
        source_id: str,
        outputs: Sequence[dict[str, RegisterRelation] | None],
    ) -> dict[str, RegisterRelation] | None:
        if source_id in region_index:
            return outputs[region_index[source_id]]
        return external_outputs.get(source_id)

    def recompute_input(
        target_index: int,
        outputs: Sequence[dict[str, RegisterRelation] | None],
    ) -> dict[str, RegisterRelation] | None:
        region = regions[target_index]
        seed = region["seed_relation"]
        state: dict[str, RegisterRelation] | None = None
        result: dict[str, RegisterRelation] = {}
        for register in REGISTER_ORDER:
            candidates: list[RegisterRelation] = []
            if seed is not None:
                candidates.append(seed)
            for edge in incoming[target_index]:
                output = source_output(edge["source_id"], outputs)
                if output is None:
                    continue
                results = {
                    relation["register"]: _register_relation_payload(relation)
                    for relation in edge["result_relations"]
                }
                preserved = set(edge["preserved_registers"])
                kind = edge["kind"]
                if kind == "internal_callsite_preservation_summary":
                    contribution: RegisterRelation = (
                        output[register]
                        if register in preserved
                        and register in results
                        and _register_relation_key(output[register])
                            == _register_relation_key(results[register])
                        else "related_word"
                    )
                elif not edge["environment_barrier"]:
                    contribution = output[register]
                elif register in results:
                    contribution = results[register]
                elif register in preserved:
                    contribution = output[register]
                else:
                    contribution = "related_word"
                candidates.append(contribution)
            if not candidates:
                continue
            state = result
            result[register] = _register_relation_join(candidates)
            if register in region["stack_window_registers"]:
                result[register] = "related_word"
        if state is not None and set(result) != set(REGISTER_ORDER):
            raise StageAInputError("register dataflow input state is incomplete")
        return state

    def evaluate_output(
        index: int,
        input_state: dict[str, RegisterRelation],
        previous_output: dict[str, RegisterRelation] | None,
    ) -> tuple[dict[str, RegisterRelation], dict[str, str]]:
        program = programs[index]
        if program is not None:
            if transfer_context is None:
                raise RegisterTransferIncomplete("transfer_context_missing")
            evaluated = evaluate_register_transfer_program(
                program,
                input_state,
                context_payload=transfer_context,
                validate=False,
                validate_context=False,
            )
            proposed = evaluated.relations
            reasons = evaluated.reasons
        else:
            observation = observations[index].get(_input_key(input_state))
            if observation is None:
                raise _MissingTransferObservation(
                    str(regions[index]["id"]),
                    _relations_from_state(input_state),
                )
            proposed = _state_from_relations(observation["output_relations"])
            reasons = dict(observation["reasons"])
        if previous_output is None:
            return proposed, reasons
        joined = {
            register: _register_relation_join([
                previous_output[register], proposed[register]
            ])
            for register in REGISTER_ORDER
        }
        for register in REGISTER_ORDER:
            if joined[register] != proposed[register]:
                reasons[register] = "monotone_transfer_widening"
        return joined, reasons

    missing: list[dict[str, Any]] = []
    try:
        result = solve_monotone_fixed_point_by_scc(
            initial_input_states=initial_inputs,
            initial_output_states=[None for _ in regions],
            initial_output_reason_states=[None for _ in regions],
            successors=[tuple(sorted(items)) for items in successors],
            evaluate_output=evaluate_output,
            recompute_input=recompute_input,
            max_iterations=max(1, len(regions) * len(REGISTER_ORDER) + 1),
        )
    except _MissingTransferObservation as exc:
        result = None
        missing.append({
            "code": "transfer_observation_missing",
            "region_id": exc.region_id,
            "input_relations": exc.input_relations,
        })
    except RegisterTransferIncomplete as exc:
        result = None
        missing.append({
            "code": "transfer_program_incomplete",
            "reason_code": exc.code,
        })

    complete = result is not None and result.converged and all(
        state is not None for state in result.input_states
    ) and all(state is not None for state in result.output_states)
    region_results = []
    if complete and result is not None:
        for index, region in enumerate(regions):
            input_state = result.input_states[index]
            output_state = result.output_states[index]
            reasons = result.output_reason_states[index]
            assert input_state is not None and output_state is not None
            assert reasons is not None
            region_results.append({
                "id": region["id"],
                "input_relations": _relations_from_state(input_state),
                "output_relations": _relations_from_state(output_state),
                "reasons": reasons,
            })
    if result is not None and not result.converged:
        missing.append({"code": "fixed_point_iteration_budget_exhausted"})
    body = {
        "format": REGISTER_DATAFLOW_PACK_RESULT_FORMAT,
        "status": "complete" if complete else "incomplete",
        "acceptance_authority": False,
        "pack_id": pack["id"],
        "input_sha256": pack["input_sha256"],
        "predecessor_results": [
            {"id": item["pack_id"], "sha256": item["summary_sha256"]}
            for item in sorted(
                predecessor_summaries, key=lambda item: item["pack_id"]
            )
        ],
        "converged": bool(result is not None and result.converged),
        "iterations": 0 if result is None else result.iterations,
        "transfer_evaluations": (
            0 if result is None else result.transfer_evaluations
        ),
        "regions": region_results,
        "missing_observations": missing,
    }
    return _result_payload(body)


__all__ = [
    "REGISTER_DATAFLOW_PACK_RESULT_FORMAT",
    "parse_register_dataflow_pack_result",
    "solve_register_dataflow_pack",
]
