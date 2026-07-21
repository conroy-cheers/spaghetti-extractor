"""Produce proposal-bound semantic IR and invariant products.

This branch is independent of register propagation and can execute in parallel
with transfer-problem compilation and SCC solving.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ..errors import StageAInputError
from ..stage_binary import _parse_stage_a_pe
from ..util import sha256_file, write_json
from .analysis_artifact import parse_decoded_behaviors
from .artifacts import read_json_object as _read_json
from .contract import _load_contract
from .extraction import _relational_semantic_ir
from .proposal_artifact import validate_relational_proposal
from .semantic_products_artifact import (
    INVARIANTS_FILE,
    SEMANTIC_IR_FILE,
    validate_semantic_products,
    write_semantic_products_manifest,
)
from .analyses.invariants import _synthesize_relational_invariants


def stage_a_produce_semantic_products(
    *, proposal: Path, out: Path,
) -> dict[str, Any]:
    proposal = Path(proposal)
    out = Path(out)
    proposal_manifest = validate_relational_proposal(proposal)
    original_bin = _parse_stage_a_pe(proposal / "artifacts" / "original.pe")
    candidate_bin = _parse_stage_a_pe(proposal / "artifacts" / "candidate.pe")
    if original_bin.sha256 != proposal_manifest.original_sha256:
        raise StageAInputError("proposal original PE identity changed")
    if candidate_bin.sha256 != proposal_manifest.candidate_sha256:
        raise StageAInputError("proposal candidate PE identity changed")
    contract_path = proposal / "relation-contract.json"
    behaviors_path = proposal / "relational-decoded-behaviors.json"
    normalized = _load_contract(contract_path)
    behaviors = parse_decoded_behaviors(
        _read_json(behaviors_path),
        expected_original_sha256=original_bin.sha256,
        expected_candidate_sha256=candidate_bin.sha256,
        expected_relation_contract_sha256=sha256_file(contract_path),
        expected_region_count=len(normalized.get("regions", [])),
    )
    semantic_ir = _relational_semantic_ir(
        original_bin, candidate_bin, normalized, behaviors
    )
    invariants = _synthesize_relational_invariants(normalized, behaviors)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    write_json(out / SEMANTIC_IR_FILE, semantic_ir)
    write_json(out / INVARIANTS_FILE, invariants)
    manifest = write_semantic_products_manifest(
        out,
        original_sha256=original_bin.sha256,
        candidate_sha256=candidate_bin.sha256,
        proposal_closure_sha256=proposal_manifest.closure_sha256,
        relation_contract_sha256=sha256_file(contract_path),
        decoded_behaviors_sha256=sha256_file(behaviors_path),
    )
    validate_semantic_products(
        out,
        expected_proposal_closure_sha256=proposal_manifest.closure_sha256,
        expected_original_sha256=original_bin.sha256,
        expected_candidate_sha256=candidate_bin.sha256,
        expected_relation_contract_sha256=sha256_file(contract_path),
        expected_decoded_behaviors_sha256=sha256_file(behaviors_path),
    )
    return manifest


__all__ = ["stage_a_produce_semantic_products"]
