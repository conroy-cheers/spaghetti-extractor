"""Produce register-replay-bound memory and external-call products."""

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
from .extraction import _relational_memory_contracts
from .memory_products_artifact import (
    EXTERNAL_CALL_SITES_FILE,
    MEMORY_CONTRACTS_FILE,
    validate_memory_products,
    write_memory_products_manifest,
)
from .proposal_artifact import validate_relational_proposal
from .register_replay_artifact import (
    REGISTER_REPLAY_RELATIONS,
    validate_register_replay,
)
from .analyses.external import _external_call_site_candidates


def stage_a_produce_memory_products(
    *, proposal: Path, register_replay: Path, out: Path,
) -> dict[str, Any]:
    proposal = Path(proposal)
    register_replay = Path(register_replay)
    out = Path(out)
    proposal_manifest = validate_relational_proposal(proposal)
    replay_manifest = validate_register_replay(
        register_replay,
        expected_proposal_closure_sha256=proposal_manifest.closure_sha256,
        expected_original_sha256=proposal_manifest.original_sha256,
        expected_candidate_sha256=proposal_manifest.candidate_sha256,
    )
    original_bin = _parse_stage_a_pe(proposal / "artifacts" / "original.pe")
    candidate_bin = _parse_stage_a_pe(proposal / "artifacts" / "candidate.pe")
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
    register_relations = _read_json(
        register_replay / REGISTER_REPLAY_RELATIONS
    )
    if register_relations != _read_json(
        proposal / "relational-register-relations.json"
    ):
        raise StageAInputError("register replay differs from proposal discovery")
    import_register_analysis = _read_json(
        proposal / "relational-import-register-invariants.json"
    )
    external_call_sites = _external_call_site_candidates(
        normalized,
        behaviors,
        register_relations,
        import_register_analysis["indirect_import_calls"],
    )
    memory_contracts = _relational_memory_contracts(
        original_bin,
        candidate_bin,
        normalized,
        behaviors,
        register_relations,
    )
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    write_json(out / EXTERNAL_CALL_SITES_FILE, external_call_sites)
    write_json(out / MEMORY_CONTRACTS_FILE, memory_contracts)
    manifest = write_memory_products_manifest(
        out,
        original_sha256=original_bin.sha256,
        candidate_sha256=candidate_bin.sha256,
        proposal_closure_sha256=proposal_manifest.closure_sha256,
        register_replay_sha256=replay_manifest.replay_sha256,
        register_relations_sha256=replay_manifest.register_relations_sha256,
        relation_contract_sha256=sha256_file(contract_path),
        decoded_behaviors_sha256=sha256_file(behaviors_path),
    )
    validate_memory_products(
        out,
        expected_proposal_closure_sha256=proposal_manifest.closure_sha256,
        expected_register_replay_sha256=replay_manifest.replay_sha256,
        expected_original_sha256=original_bin.sha256,
        expected_candidate_sha256=candidate_bin.sha256,
        expected_relation_contract_sha256=sha256_file(contract_path),
        expected_decoded_behaviors_sha256=sha256_file(behaviors_path),
    )
    return manifest


__all__ = ["stage_a_produce_memory_products"]
