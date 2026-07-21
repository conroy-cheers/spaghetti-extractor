from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..stage_binary import _parse_stage_a_pe
from ..util import sha256_file, write_json
from .analysis_artifact import parse_decoded_behaviors
from .register_dataflow_compile import compile_register_dataflow_problem
from .register_dataflow_seed import (
    parse_register_dataflow_problem_seed,
)
from .register_transfer_core import canonical_sha256


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="spaghetti-extractor-register-dataflow-problem"
    )
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--seed", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--decoded-behaviors", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args(argv)

    original = _parse_stage_a_pe(arguments.original)
    candidate = _parse_stage_a_pe(arguments.candidate)
    contract = json.loads(arguments.contract.read_text(encoding="utf-8"))
    if not isinstance(contract, dict) or not isinstance(
        contract.get("regions"), list
    ):
        parser.error("--contract must contain a relational contract")
    behaviors = parse_decoded_behaviors(
        json.loads(arguments.decoded_behaviors.read_text(encoding="utf-8")),
        expected_original_sha256=original.sha256,
        expected_candidate_sha256=candidate.sha256,
        expected_relation_contract_sha256=sha256_file(arguments.contract),
        expected_region_count=len(contract["regions"]),
    )
    contract_sha256 = canonical_sha256(contract)
    behaviors_sha256 = canonical_sha256(behaviors)
    seed = parse_register_dataflow_problem_seed(
        json.loads(arguments.seed.read_text(encoding="utf-8")),
        expected_original_sha256=original.sha256,
        expected_candidate_sha256=candidate.sha256,
        expected_contract_sha256=contract_sha256,
        expected_behaviors_sha256=behaviors_sha256,
    )
    problem = compile_register_dataflow_problem(
        contract,
        behaviors,
        original_image_base=original.image_base,
        candidate_image_base=candidate.image_base,
        indirect_call_candidates=seed["indirect_call_candidates"],
        import_call_candidates=seed["import_call_candidates"],
        callsite_summary_predecessors=seed["callsite_summary_predecessors"],
        original_bin=original,
        candidate_bin=candidate,
    )
    write_json(arguments.out, problem)
    print(json.dumps({
        "status": "compiled",
        "problem_sha256": problem["problem_sha256"],
        "graph_sha256": problem["graph"]["graph_sha256"],
        "region_count": problem["transfer_programs"]["region_count"],
        "out": str(arguments.out),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
