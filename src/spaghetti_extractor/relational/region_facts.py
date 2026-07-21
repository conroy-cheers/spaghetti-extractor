from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe
from ..util import sha256_bytes, sha256_file, write_json
from .analyses.control import (
    _attach_reverse_sentinel_table_source_invariants,
    _attach_reverse_sentinel_table_value_targets,
    _dynamic_range_indirect_call_candidates,
    _immutable_code_pointer_table_call_candidates,
    _immutable_indirect_call_candidates,
)
from .analyses.external import _machine_import_call_contract_analysis
from .analyses.memory import _attach_initial_static_code_pointer_slots
from .analyses.region_local import (
    _attach_assembled_immutable_read_address_separations,
    _attach_import_seed_address_separations,
    _iat_import_register_seed_candidates,
    _refine_contract_bounds,
)
from .analyses.stack import _attach_return_write_address_separations
from .contract import _load_contract, _normalize_contract
from .pair_normalization import load_pair_normalization
from .region_facts_artifact import (
    RegionFactsArtifact,
    region_facts_payload,
)


_REGION_FACTS_SEMANTICS_FILES = (
    "../pe.py",
    "../stage_binary.py",
    "contract.py",
    "extraction.py",
    "model.py",
    "pair_normalization.py",
    "pair_normalization_artifact.py",
    "region_facts.py",
    "region_facts_artifact.py",
    "schema.py",
    "analyses/control.py",
    "analyses/external.py",
    "analyses/memory.py",
    "analyses/region_local.py",
    "analyses/register_static.py",
    "analyses/semantic_control.py",
    "analyses/segments.py",
    "analyses/stack.py",
)


def _canonical_json_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def region_facts_semantics_sha256() -> str:
    root = Path(__file__).resolve().parent
    payload = {
        "format": "stage-a-relational-region-facts-semantics-v1",
        "files": {
            relative: sha256_file(root / relative)
            for relative in _REGION_FACTS_SEMANTICS_FILES
        },
    }
    return _canonical_json_sha256(payload)


def analyze_relational_region_facts(
    *,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    normalized_contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
) -> dict[str, Any]:
    contract = _refine_contract_bounds(normalized_contract, behaviors)
    contract, initial_static_code_pointer_analysis = (
        _attach_initial_static_code_pointer_slots(
            contract, behaviors, original_bin, candidate_bin
        )
    )
    indirect_call_candidates = _immutable_indirect_call_candidates(
        original_bin, candidate_bin, contract, behaviors
    )
    table_call_proposals = _immutable_code_pointer_table_call_candidates(
        original_bin, candidate_bin, contract, behaviors
    )
    contract = _attach_reverse_sentinel_table_value_targets(
        original_bin, candidate_bin, contract, table_call_proposals
    )
    contract = _attach_reverse_sentinel_table_source_invariants(
        contract, table_call_proposals
    )
    dynamic_call_candidates = _dynamic_range_indirect_call_candidates(
        contract, behaviors
    )
    import_register_seeds = _iat_import_register_seed_candidates(
        original_bin, candidate_bin, behaviors
    )
    contract = _attach_import_seed_address_separations(
        contract, import_register_seeds
    )
    contract = _attach_assembled_immutable_read_address_separations(
        contract, behaviors, original_bin, candidate_bin
    )
    contract = _attach_return_write_address_separations(
        contract, behaviors, original_bin, candidate_bin
    )
    machine_call_analysis = _machine_import_call_contract_analysis(
        contract, behaviors
    )
    return {
        "contract": contract,
        "initial_static_code_pointer_analysis": (
            initial_static_code_pointer_analysis
        ),
        "indirect_call_candidates": indirect_call_candidates,
        "table_call_proposals": table_call_proposals,
        "dynamic_call_candidates": dynamic_call_candidates,
        "import_register_seeds": import_register_seeds,
        "machine_call_analysis": machine_call_analysis,
    }


def stage_a_analyze_region_facts(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
    original_extraction: Path,
    candidate_extraction: Path,
    normalized_behaviors: Path,
    out: Path,
) -> dict[str, Any]:
    original_bin = _parse_stage_a_pe(Path(original))
    candidate_bin = _parse_stage_a_pe(Path(candidate))
    normalized, issues = _normalize_contract(
        _load_contract(Path(relation_contract)), original_bin, candidate_bin
    )
    if issues:
        raise StageAInputError(
            "relational contract failed structural validation before region-fact "
            f"analysis: {issues[:3]}"
        )
    behaviors = load_pair_normalization(
        path=Path(normalized_behaviors),
        normalized_contract=normalized,
        original_sha256=original_bin.sha256,
        candidate_sha256=candidate_bin.sha256,
        original_extraction=Path(original_extraction),
        candidate_extraction=Path(candidate_extraction),
    )
    facts = analyze_relational_region_facts(
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        normalized_contract=normalized,
        behaviors=behaviors,
    )
    payload = region_facts_payload(
        original_sha256=original_bin.sha256,
        candidate_sha256=candidate_bin.sha256,
        input_relation_contract_sha256=_canonical_json_sha256(normalized),
        normalized_behaviors_sha256=sha256_file(Path(normalized_behaviors)),
        region_facts_semantics_sha256=region_facts_semantics_sha256(),
        region_count=len(behaviors),
        **facts,
    )
    RegionFactsArtifact.parse(payload)
    write_json(Path(out), payload)
    return {
        "format": "stage-a-relational-region-facts-result-v1",
        "status": "analyzed",
        "original_sha256": original_bin.sha256,
        "candidate_sha256": candidate_bin.sha256,
        "regions": len(behaviors),
        "out": str(out),
        "sha256": sha256_file(Path(out)),
    }


__all__ = [
    "analyze_relational_region_facts",
    "region_facts_semantics_sha256",
    "stage_a_analyze_region_facts",
]
