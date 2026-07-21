"""Merge validated immutable phase products without rerunning their producers."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ..errors import StageAInputError
from ..util import sha256_file
from .analysis_artifact import (
    write_relational_analysis_manifest,
)
from .analysis_reference import (
    immutable_nix_store_file,
    validate_relational_analysis_view,
)
from .composition_products_artifact import (
    COMPOSITION_PRODUCTS_REQUIRED_FILES,
    validate_composition_products,
)
from .memory_products_artifact import (
    EXTERNAL_CALL_SITES_FILE,
    MEMORY_CONTRACTS_FILE,
    validate_memory_products,
)
from .proposal_artifact import (
    validate_relational_proposal,
)
from .register_replay_artifact import (
    REGISTER_REPLAY_RELATIONS,
    validate_register_replay,
)
from .semantic_products_artifact import (
    INVARIANTS_FILE,
    SEMANTIC_IR_FILE,
    validate_semantic_products,
)


def _copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        destination.unlink()
    immutable_source = immutable_nix_store_file(source)
    if immutable_source is not None:
        destination.symlink_to(immutable_source)
    else:
        shutil.copyfile(source, destination)


def stage_a_assemble_relational_analysis(
    *,
    proposal: Path,
    register_replay: Path,
    semantic_products: Path,
    memory_products: Path,
    composition_products: Path,
    out: Path,
) -> dict[str, Any]:
    proposal = Path(proposal)
    register_replay = Path(register_replay)
    semantic_products = Path(semantic_products)
    memory_products = Path(memory_products)
    composition_products = Path(composition_products)
    out = Path(out)

    proposal_manifest = validate_relational_proposal(proposal)
    replay_manifest = validate_register_replay(
        register_replay,
        expected_proposal_closure_sha256=proposal_manifest.closure_sha256,
        expected_original_sha256=proposal_manifest.original_sha256,
        expected_candidate_sha256=proposal_manifest.candidate_sha256,
    )
    if replay_manifest.register_relations_sha256 != sha256_file(
        proposal / "relational-register-relations.json"
    ):
        raise StageAInputError("register replay differs from proposal discovery")
    contract_sha256 = sha256_file(proposal / "relation-contract.json")
    behaviors_sha256 = sha256_file(
        proposal / "relational-decoded-behaviors.json"
    )
    semantic_manifest = validate_semantic_products(
        semantic_products,
        expected_proposal_closure_sha256=proposal_manifest.closure_sha256,
        expected_original_sha256=proposal_manifest.original_sha256,
        expected_candidate_sha256=proposal_manifest.candidate_sha256,
        expected_relation_contract_sha256=contract_sha256,
        expected_decoded_behaviors_sha256=behaviors_sha256,
    )
    memory_manifest = validate_memory_products(
        memory_products,
        expected_proposal_closure_sha256=proposal_manifest.closure_sha256,
        expected_register_replay_sha256=replay_manifest.replay_sha256,
        expected_original_sha256=proposal_manifest.original_sha256,
        expected_candidate_sha256=proposal_manifest.candidate_sha256,
        expected_relation_contract_sha256=contract_sha256,
        expected_decoded_behaviors_sha256=behaviors_sha256,
    )
    validate_composition_products(
        composition_products,
        expected_proposal_closure_sha256=proposal_manifest.closure_sha256,
        expected_register_replay_sha256=replay_manifest.replay_sha256,
        expected_semantic_products_sha256=semantic_manifest.products_sha256,
        expected_memory_products_sha256=memory_manifest.products_sha256,
        expected_original_sha256=proposal_manifest.original_sha256,
        expected_candidate_sha256=proposal_manifest.candidate_sha256,
    )

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for relative, _digest in proposal_manifest.files:
        _copy_file(proposal / relative, out / relative)
    _copy_file(
        register_replay / REGISTER_REPLAY_RELATIONS,
        out / REGISTER_REPLAY_RELATIONS,
    )
    for relative in (SEMANTIC_IR_FILE, INVARIANTS_FILE):
        _copy_file(semantic_products / relative, out / relative)
    for relative in (MEMORY_CONTRACTS_FILE, EXTERNAL_CALL_SITES_FILE):
        _copy_file(memory_products / relative, out / relative)
    for relative in sorted(COMPOSITION_PRODUCTS_REQUIRED_FILES):
        _copy_file(composition_products / relative, out / relative)

    manifest = write_relational_analysis_manifest(
        out,
        original_sha256=proposal_manifest.original_sha256,
        candidate_sha256=proposal_manifest.candidate_sha256,
    )
    validate_relational_analysis_view(out)
    return manifest


__all__ = ["stage_a_assemble_relational_analysis"]
