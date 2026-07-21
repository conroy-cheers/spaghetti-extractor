"""Validate a distributed register solution and emit its immutable replay.

This phase owns aggregate checking only; it cannot regenerate proposal or SCC
products and it emits no final composition claims.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from ..errors import StageAInputError
from ..stage_binary import _parse_stage_a_pe
from ..util import sha256_file, write_json
from .analysis_artifact import parse_decoded_behaviors
from .artifacts import read_json_object as _read_json
from .contract import _load_contract
from .proposal_artifact import validate_relational_proposal
from .region_facts import _canonical_json_sha256
from .register_dataflow_seed import parse_register_dataflow_problem_seed
from .register_replay_artifact import (
    REGISTER_REPLAY_RELATIONS,
    validate_register_replay,
    write_register_replay_manifest,
)
from .analyses.registers import _synthesize_register_relations
from .analyses.segments import (
    _attach_stack_register_output_claims,
    _attach_static_word_register_output_claims,
    _lower_stack_register_relations,
)


def stage_a_replay_register_dataflow(
    *,
    proposal: Path,
    register_dataflow_aggregate: Path,
    out: Path,
) -> dict[str, Any]:
    proposal = Path(proposal)
    aggregate_path = Path(register_dataflow_aggregate)
    out = Path(out)
    proposal_manifest = validate_relational_proposal(proposal)
    original_bin = _parse_stage_a_pe(proposal / "artifacts" / "original.pe")
    candidate_bin = _parse_stage_a_pe(proposal / "artifacts" / "candidate.pe")
    if original_bin.sha256 != proposal_manifest.original_sha256:
        raise StageAInputError("proposal original PE identity changed")
    if candidate_bin.sha256 != proposal_manifest.candidate_sha256:
        raise StageAInputError("proposal candidate PE identity changed")

    normalized = _load_contract(proposal / "relation-contract.json")
    behaviors = parse_decoded_behaviors(
        _read_json(proposal / "relational-decoded-behaviors.json"),
        expected_original_sha256=original_bin.sha256,
        expected_candidate_sha256=candidate_bin.sha256,
        expected_relation_contract_sha256=sha256_file(
            proposal / "relation-contract.json"
        ),
        expected_region_count=len(normalized.get("regions", [])),
    )
    seed = parse_register_dataflow_problem_seed(
        _read_json(proposal / "relational-register-dataflow-problem-seed.json"),
        expected_original_sha256=original_bin.sha256,
        expected_candidate_sha256=candidate_bin.sha256,
        expected_contract_sha256=_canonical_json_sha256(normalized),
        expected_behaviors_sha256=_canonical_json_sha256(behaviors),
    )
    aggregate = _read_json(aggregate_path)
    proposal_register_relations = _read_json(
        proposal / "relational-register-relations.json"
    )
    recomputed_contract, register_relations = _synthesize_register_relations(
        normalized,
        behaviors,
        original_image_base=original_bin.image_base,
        candidate_image_base=candidate_bin.image_base,
        indirect_call_candidates=seed["indirect_call_candidates"],
        import_call_candidates=seed["import_call_candidates"],
        callsite_summary_predecessors=seed["callsite_summary_predecessors"],
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        _dataflow_aggregate=aggregate,
    )
    recomputed_contract, register_relations = _lower_stack_register_relations(
        recomputed_contract, register_relations
    )
    register_relations = _attach_stack_register_output_claims(
        recomputed_contract, behaviors, register_relations
    )
    register_relations = _attach_static_word_register_output_claims(
        recomputed_contract, behaviors, register_relations
    )
    for field in (
        "fixed_code_pointer_call_fixed_point",
        "callsite_register_relation_fixed_point",
    ):
        if field in proposal_register_relations:
            register_relations[field] = json.loads(json.dumps(
                proposal_register_relations[field]
            ))
    if recomputed_contract != normalized:
        raise StageAInputError(
            "aggregate register replay changed the proposal relation contract"
        )
    if register_relations != proposal_register_relations:
        raise StageAInputError(
            "aggregate register replay differs from proposal discovery"
        )
    aggregate_sha256 = aggregate.get("aggregate_sha256")
    if not isinstance(aggregate_sha256, str):
        raise StageAInputError("register aggregate digest is missing")

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    write_json(out / REGISTER_REPLAY_RELATIONS, register_relations)
    manifest = write_register_replay_manifest(
        out,
        original_sha256=original_bin.sha256,
        candidate_sha256=candidate_bin.sha256,
        proposal_closure_sha256=proposal_manifest.closure_sha256,
        aggregate_sha256=aggregate_sha256,
        aggregate_file_sha256=sha256_file(aggregate_path),
    )
    validate_register_replay(
        out,
        expected_proposal_closure_sha256=proposal_manifest.closure_sha256,
        expected_original_sha256=original_bin.sha256,
        expected_candidate_sha256=candidate_bin.sha256,
    )
    return manifest


__all__ = ["stage_a_replay_register_dataflow"]
