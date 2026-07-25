"""Produce final composition products from immutable analysis artifacts.

This module is intentionally downstream of register replay, semantic products,
and memory products. Its Nix source closure mirrors that boundary: composition
changes cannot invalidate those branches, transfer compilation, or discovery.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ..stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe
from ..util import sha256_file, write_json
from .analysis_artifact import (
    parse_decoded_behaviors,
    segment_candidates_payload,
)
from .artifacts import read_json_object as _read_json
from .contract import _load_contract
from .extraction import (
    _relational_memory_contracts,
    _relational_semantic_ir,
)
from .ir import RelationalProofIR
from .isa_requirements import (
    ISARequirementInventory,
    _lean_form_source_hashes,
    build_isa_requirement_inventory,
    extract_lean_instruction_forms,
)
from .memory_products_artifact import (
    EXTERNAL_CALL_SITES_FILE,
    MEMORY_CONTRACTS_FILE,
    validate_memory_products,
)
from .composition_products_artifact import (
    validate_composition_products,
    write_composition_products_manifest,
)
from .phases import CompositionProducts, ExtractedProgramPair, StateAnalysisProducts
from .proposal_artifact import (
    validate_relational_proposal,
)
from .register_replay_artifact import (
    REGISTER_REPLAY_RELATIONS,
    validate_register_replay,
)
from .runtime_frame_artifact import (
    RUNTIME_FRAME_AFFINE_VIABILITY_FILE,
    runtime_frame_affine_viability_payload,
)
from .semantic_products_artifact import (
    INVARIANTS_FILE,
    SEMANTIC_IR_FILE,
    validate_semantic_products,
)
from .side_extraction import load_side_isa
from .analyses.control import (
    _attach_dynamic_indirect_call_analysis,
    _attach_import_register_analysis,
    _attach_product_graph_analysis,
    _attach_stack_window_analysis,
    _bounded_immutable_code_pointer_table_call_inputs,
    _bounded_immutable_relocation_table_jump_candidates,
    _checked_product_reachability_inventories,
    _relational_product_graph,
)
from .analyses.external import (
    _attach_external_call_site_analysis,
    _attach_machine_import_call_contract_analysis,
    _external_call_site_candidates,
)
from .analyses.invariants import (
    _attach_invariant_synthesis,
    _synthesize_relational_invariants,
)
from .analyses.segments import (
    _attach_memory_transition_analysis,
    _attach_register_relation_analysis,
    _attach_segment_refinement_analysis,
    _segment_refinement_candidates,
    _segment_refinement_diagnostic_report,
)


def _composition_product_graph(
    *,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    normalized: dict[str, Any],
    behaviors: list[dict[str, Any]],
    register_relations: dict[str, Any],
    segment_candidates: list[dict[str, Any]],
    indirect_call_candidates: list[dict[str, Any]],
    bounded_table_call_candidates: list[dict[str, Any]],
    dynamic_call_candidates: list[dict[str, Any]],
    import_register_seeds: list[dict[str, Any]],
    import_call_candidates: list[dict[str, Any]],
    external_call_candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    bounded_table_candidates = (
        _bounded_immutable_relocation_table_jump_candidates(
            original_bin,
            candidate_bin,
            normalized,
            behaviors,
        )
    )
    return _relational_product_graph(
        normalized,
        behaviors,
        register_relations,
        segment_candidates,
        original_image_base=original_bin.image_base,
        candidate_image_base=candidate_bin.image_base,
        indirect_call_candidates=indirect_call_candidates,
        bounded_table_candidates=bounded_table_candidates,
        bounded_table_call_candidates=bounded_table_call_candidates,
        dynamic_call_candidates=dynamic_call_candidates,
        import_register_seeds=import_register_seeds,
        import_call_candidates=import_call_candidates,
        external_call_candidates=external_call_candidates,
    )


def _produce_composition_outputs(
    *,
    out: Path,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    original_artifact: Path,
    candidate_artifact: Path,
    normalized: dict[str, Any],
    behaviors: list[dict[str, Any]],
    extraction: dict[str, Any],
    proof_ir: dict[str, Any],
    register_relations: dict[str, Any],
    stack_window_analysis: dict[str, Any],
    machine_call_analysis: dict[str, Any],
    import_register_seeds: list[dict[str, Any]],
    import_register_analysis: dict[str, Any],
    table_call_proposals: list[dict[str, Any]],
    dynamic_call_candidates: list[dict[str, Any]],
    combined_indirect_call_candidates: list[dict[str, Any]],
    original_isa: Path | None,
    candidate_isa: Path | None,
    semantic_ir: dict[str, Any] | None = None,
    invariant_synthesis: dict[str, Any] | None = None,
    memory_contracts: dict[str, Any] | None = None,
    external_call_sites: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if external_call_sites is None:
        external_call_sites = _external_call_site_candidates(
            normalized, behaviors, register_relations,
            import_register_analysis["indirect_import_calls"],
        )
    write_json(out / "relational-external-call-sites.json", external_call_sites)
    proof_ir = _attach_machine_import_call_contract_analysis(
        proof_ir, machine_call_analysis
    )
    proof_ir = _attach_external_call_site_analysis(proof_ir, external_call_sites)
    RelationalProofIR.parse(proof_ir)
    write_json(out / "relational-proof-ir.json", proof_ir)
    if semantic_ir is None:
        semantic_ir = _relational_semantic_ir(
            original_bin, candidate_bin, normalized, behaviors
        )
    write_json(out / "relational-semantic-ir.json", semantic_ir)
    if memory_contracts is None:
        memory_contracts = _relational_memory_contracts(
            original_bin,
            candidate_bin,
            normalized,
            behaviors,
            register_relations,
        )
    write_json(out / "relational-memory-contracts.json", memory_contracts)
    if invariant_synthesis is None:
        invariant_synthesis = _synthesize_relational_invariants(
            normalized, behaviors
        )
    write_json(out / "relational-invariants.json", invariant_synthesis)
    state_analysis = StateAnalysisProducts.create(
        extracted=ExtractedProgramPair.create(
            contract=normalized,
            behaviors=behaviors,
            extraction=extraction,
        ),
        register_relations=register_relations,
        stack_windows=stack_window_analysis,
        machine_import_calls=machine_call_analysis,
        external_call_sites=external_call_sites,
        semantic_ir=semantic_ir,
        memory_contracts=memory_contracts,
        invariants=invariant_synthesis,
    )
    proof_ir = _attach_invariant_synthesis(proof_ir, invariant_synthesis)
    proof_ir = _attach_register_relation_analysis(proof_ir, register_relations)
    proof_ir = _attach_memory_transition_analysis(
        proof_ir, normalized, behaviors, memory_contracts, register_relations
    )
    bounded_table_call_inputs = (
        _bounded_immutable_code_pointer_table_call_inputs(
            normalized,
            behaviors,
            table_call_proposals,
            original_bin=original_bin,
            candidate_bin=candidate_bin,
            original_image_base=original_bin.image_base,
            candidate_image_base=candidate_bin.image_base,
        )
    )
    write_json(
        out / "relational-bounded-table-call-inputs.json",
        bounded_table_call_inputs,
    )
    segment_diagnostics: list[dict[str, Any]] = []
    segment_candidates = _segment_refinement_candidates(
        normalized, behaviors, memory_contracts, register_relations,
        import_register_seeds, diagnostics=segment_diagnostics,
        original_bin=original_bin, candidate_bin=candidate_bin,
        bounded_table_call_candidates=bounded_table_call_inputs["candidates"],
    )
    write_json(
        out / "relational-segment-diagnostics.json",
        _segment_refinement_diagnostic_report(segment_diagnostics),
    )
    proof_ir = _attach_segment_refinement_analysis(
        proof_ir, normalized, behaviors, memory_contracts, register_relations,
        import_register_seeds, segment_candidates=segment_candidates,
        segment_diagnostics=segment_diagnostics,
    )
    product_graph = _composition_product_graph(
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        normalized=normalized,
        behaviors=behaviors,
        register_relations=register_relations,
        segment_candidates=segment_candidates,
        indirect_call_candidates=combined_indirect_call_candidates,
        bounded_table_call_candidates=bounded_table_call_inputs["candidates"],
        dynamic_call_candidates=dynamic_call_candidates,
        import_register_seeds=import_register_seeds,
        import_call_candidates=import_register_analysis["indirect_import_calls"],
        external_call_candidates=external_call_sites["candidates"],
    )
    composition = CompositionProducts.create(
        state=state_analysis,
        product_graph=product_graph,
        segment_candidates=segment_candidates,
    )
    product_graph = dict(composition.product_graph.raw)
    _checked_product_reachability_inventories(product_graph)
    write_json(out / "relational-product-graph.json", product_graph)
    if (original_isa is None) != (candidate_isa is None):
        raise StageAInputError(
            "both original and candidate side ISA artifacts are required"
        )
    if original_isa is not None and candidate_isa is not None:
        lean_instruction_forms = {}
        for side, path, binary in (
            ("original", original_isa, original_bin),
            ("candidate", candidate_isa, candidate_bin),
        ):
            lean_instruction_forms.update(
                load_side_isa(
                    path=Path(path),
                    contract=normalized,
                    side=side,
                    binary_sha256=binary.sha256,
                )
            )
        lean_instruction_form_evidence = {
            "status": "lean_extracted_untrusted",
            "cache": "manifest_bound_side_artifacts",
            **_lean_form_source_hashes(),
            "row_count": len(lean_instruction_forms),
            "side_artifacts": {
                "original": sha256_file(Path(original_isa)),
                "candidate": sha256_file(Path(candidate_isa)),
            },
        }
    else:
        lean_instruction_forms, lean_instruction_form_evidence = (
            extract_lean_instruction_forms(
                original=original_artifact,
                candidate=candidate_artifact,
                relation_contract=normalized,
            )
        )
    isa_requirements = build_isa_requirement_inventory(
        original=original_bin,
        candidate=candidate_bin,
        relation_contract=normalized,
        product_graph=product_graph,
        lean_forms=lean_instruction_forms,
        lean_form_source_sha256=str(
            lean_instruction_form_evidence["classifier_sha256"]
        ),
        lean_form_extractor_sha256=str(
            lean_instruction_form_evidence["extractor_sha256"]
        ),
    )
    isa_requirements_path = out / "isa-requirements.json"
    write_json(isa_requirements_path, isa_requirements.to_payload())
    isa_requirements = ISARequirementInventory.parse(
        _read_json(isa_requirements_path)
    )
    proof_ir = _attach_product_graph_analysis(proof_ir, product_graph)
    proof_ir = _attach_dynamic_indirect_call_analysis(
        proof_ir, normalized, behaviors, dynamic_call_candidates, product_graph
    )
    proof_ir = _attach_import_register_analysis(
        proof_ir, import_register_seeds, import_register_analysis,
        segment_candidates, memory_contracts,
    )
    proof_ir = _attach_stack_window_analysis(
        proof_ir, normalized, stack_window_analysis
    )
    RelationalProofIR.parse(proof_ir)
    write_json(out / "relational-proof-ir.json", proof_ir)
    write_json(
        out / "relational-segment-candidates.json",
        segment_candidates_payload(
            candidates=segment_candidates,
            diagnostics_sha256=sha256_file(
                out / "relational-segment-diagnostics.json"
            ),
            product_graph_sha256=sha256_file(
                out / "relational-product-graph.json"
            ),
        ),
    )
    return {
        "proof_ir": proof_ir,
        "invariant_synthesis": invariant_synthesis,
        "memory_contracts": memory_contracts,
        "product_graph": product_graph,
        "external_call_sites": external_call_sites,
        "segment_candidates": segment_candidates,
        "isa_requirements": isa_requirements,
    }


def stage_a_produce_composition_products(
    *,
    proposal: Path,
    register_replay: Path,
    semantic_products: Path,
    memory_products: Path,
    out: Path,
    original_isa: Path | None = None,
    candidate_isa: Path | None = None,
) -> dict[str, Any]:
    proposal = Path(proposal)
    out = Path(out)
    source_manifest = validate_relational_proposal(proposal)
    original_artifact = proposal / "artifacts" / "original.pe"
    candidate_artifact = proposal / "artifacts" / "candidate.pe"
    original_bin = _parse_stage_a_pe(original_artifact)
    candidate_bin = _parse_stage_a_pe(candidate_artifact)
    if original_bin.sha256 != source_manifest.original_sha256:
        raise StageAInputError("proposal original PE identity changed")
    if candidate_bin.sha256 != source_manifest.candidate_sha256:
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
    register_replay = Path(register_replay)
    replay_manifest = validate_register_replay(
        register_replay,
        expected_proposal_closure_sha256=source_manifest.closure_sha256,
        expected_original_sha256=original_bin.sha256,
        expected_candidate_sha256=candidate_bin.sha256,
    )
    proposal_register_relations = _read_json(
        proposal / "relational-register-relations.json"
    )
    register_relations = _read_json(
        register_replay / REGISTER_REPLAY_RELATIONS
    )
    if register_relations != proposal_register_relations:
        raise StageAInputError(
            "register replay differs from proposal discovery"
        )
    semantic_products = Path(semantic_products)
    semantic_manifest = validate_semantic_products(
        semantic_products,
        expected_proposal_closure_sha256=source_manifest.closure_sha256,
        expected_original_sha256=original_bin.sha256,
        expected_candidate_sha256=candidate_bin.sha256,
        expected_relation_contract_sha256=sha256_file(
            proposal / "relation-contract.json"
        ),
        expected_decoded_behaviors_sha256=sha256_file(
            proposal / "relational-decoded-behaviors.json"
        ),
    )
    semantic_ir = _read_json(semantic_products / SEMANTIC_IR_FILE)
    invariant_synthesis = _read_json(semantic_products / INVARIANTS_FILE)

    memory_products = Path(memory_products)
    memory_manifest = validate_memory_products(
        memory_products,
        expected_proposal_closure_sha256=source_manifest.closure_sha256,
        expected_register_replay_sha256=replay_manifest.replay_sha256,
        expected_original_sha256=original_bin.sha256,
        expected_candidate_sha256=candidate_bin.sha256,
        expected_relation_contract_sha256=sha256_file(
            proposal / "relation-contract.json"
        ),
        expected_decoded_behaviors_sha256=sha256_file(
            proposal / "relational-decoded-behaviors.json"
        ),
    )
    memory_contracts = _read_json(memory_products / MEMORY_CONTRACTS_FILE)
    external_call_sites = _read_json(
        memory_products / EXTERNAL_CALL_SITES_FILE
    )

    import_seed_artifact = _read_json(
        proposal / "relational-import-register-seeds.json"
    )
    import_register_seeds = import_seed_artifact.get("candidates")
    if not isinstance(import_register_seeds, list):
        raise StageAInputError("proposal import register seeds are malformed")
    import_register_analysis = _read_json(
        proposal / "relational-import-register-invariants.json"
    )
    indirect_targets = _read_json(
        proposal / "relational-indirect-call-targets.json"
    )
    table_call_proposals = indirect_targets.get("table_call_proposals")
    dynamic_call_candidates = indirect_targets.get("dynamic_range_candidates")
    indirect_call_candidates = indirect_targets.get("candidates")
    fixed_register_candidates = indirect_targets.get("fixed_register_candidates")
    if not all(isinstance(value, list) for value in (
        table_call_proposals,
        dynamic_call_candidates,
        indirect_call_candidates,
        fixed_register_candidates,
    )):
        raise StageAInputError("proposal indirect-call inventory is malformed")
    combined_indirect_call_candidates = [
        *indirect_call_candidates,
        *fixed_register_candidates,
    ]
    machine_call_analysis = _read_json(
        proposal / "relational-machine-import-calls.json"
    )
    stack_window_analysis = _read_json(
        proposal / "relational-stack-windows.json"
    )
    proof_ir = _read_json(proposal / "relational-proof-ir.json")
    RelationalProofIR.parse(proof_ir)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    assembled = _produce_composition_outputs(
        out=out,
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        original_artifact=original_artifact,
        candidate_artifact=candidate_artifact,
        normalized=normalized,
        behaviors=behaviors,
        extraction={"source": "manifest_bound_relational_proposal_closure"},
        proof_ir=proof_ir,
        register_relations=register_relations,
        stack_window_analysis=stack_window_analysis,
        machine_call_analysis=machine_call_analysis,
        import_register_seeds=import_register_seeds,
        import_register_analysis=import_register_analysis,
        table_call_proposals=table_call_proposals,
        dynamic_call_candidates=dynamic_call_candidates,
        combined_indirect_call_candidates=combined_indirect_call_candidates,
        original_isa=original_isa,
        candidate_isa=candidate_isa,
        semantic_ir=semantic_ir,
        invariant_synthesis=invariant_synthesis,
        memory_contracts=memory_contracts,
        external_call_sites=external_call_sites,
    )
    if not assembled["product_graph"]:
        raise StageAInputError("relational composition produced no graph")
    runtime_frame_affine_seed = _read_json(
        proposal / RUNTIME_FRAME_AFFINE_VIABILITY_FILE
    )
    runtime_frame_affine_budgets = runtime_frame_affine_seed.get("budgets")
    if not isinstance(runtime_frame_affine_budgets, dict):
        raise StageAInputError("runtime frame affine budgets are malformed")
    runtime_frame_affine = runtime_frame_affine_viability_payload(
        original_sha256=original_bin.sha256,
        candidate_sha256=candidate_bin.sha256,
        relation_contract_sha256=sha256_file(
            proposal / "relation-contract.json"
        ),
        decoded_behaviors_sha256=sha256_file(
            proposal / "relational-decoded-behaviors.json"
        ),
        register_relations_sha256=sha256_file(
            register_replay / REGISTER_REPLAY_RELATIONS
        ),
        behaviors=behaviors,
        register_relations=register_relations,
        product_graph=assembled["product_graph"],
        max_shapes=int(runtime_frame_affine_budgets.get("max_shapes", 0)),
        max_families=int(runtime_frame_affine_budgets.get("max_families", 0)),
    )
    write_json(
        out / RUNTIME_FRAME_AFFINE_VIABILITY_FILE,
        runtime_frame_affine,
    )
    for upstream_file in (
        EXTERNAL_CALL_SITES_FILE,
        SEMANTIC_IR_FILE,
        MEMORY_CONTRACTS_FILE,
        INVARIANTS_FILE,
    ):
        (out / upstream_file).unlink()
    original_isa_sha256 = (
        sha256_file(Path(original_isa)) if original_isa is not None else None
    )
    candidate_isa_sha256 = (
        sha256_file(Path(candidate_isa)) if candidate_isa is not None else None
    )
    manifest = write_composition_products_manifest(
        out,
        original_sha256=original_bin.sha256,
        candidate_sha256=candidate_bin.sha256,
        proposal_closure_sha256=source_manifest.closure_sha256,
        register_replay_sha256=replay_manifest.replay_sha256,
        semantic_products_sha256=semantic_manifest.products_sha256,
        memory_products_sha256=memory_manifest.products_sha256,
        original_isa_sha256=original_isa_sha256,
        candidate_isa_sha256=candidate_isa_sha256,
    )
    validate_composition_products(
        out,
        expected_proposal_closure_sha256=source_manifest.closure_sha256,
        expected_register_replay_sha256=replay_manifest.replay_sha256,
        expected_semantic_products_sha256=semantic_manifest.products_sha256,
        expected_memory_products_sha256=memory_manifest.products_sha256,
        expected_original_sha256=original_bin.sha256,
        expected_candidate_sha256=candidate_bin.sha256,
        expected_original_isa_sha256=original_isa_sha256,
        expected_candidate_isa_sha256=candidate_isa_sha256,
    )
    return manifest


__all__ = [
    "_produce_composition_outputs",
    "stage_a_produce_composition_products",
]
