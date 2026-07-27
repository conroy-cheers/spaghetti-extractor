from __future__ import annotations

import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
import time
from collections import Counter, defaultdict, deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from pathlib import Path
from threading import Event
from typing import Any

import capstone
import z3

from ..stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe
from ..util import sha256_bytes, sha256_file, utc_now, write_json
from .analysis_artifact import (
    decoded_behaviors_payload,
    parse_decoded_behaviors,
    parse_segment_candidates,
    segment_candidates_payload,
    validate_relational_analysis,
    write_relational_analysis_manifest,
)
from .artifacts import (
    read_json_object as _read_json,
    write_text_if_changed as _write_text_if_changed,
)
from .callsite_preservation import (
    parse_callsite_preservation_artifact,
    serialize_callsite_preservation_artifact,
)
from .ir import (
    CompositionProgressIR,
    ProductGraphIR,
    RelationalProofIR,
    WholeProgramAcceptanceIR,
)
from .analyses.control import (
    _attach_reverse_sentinel_table_source_invariants,
    _attach_reverse_sentinel_table_value_targets,
    _attach_dynamic_indirect_call_analysis,
    _attach_import_register_analysis,
    _attach_product_graph_analysis,
    _attach_stack_window_analysis,
    _bounded_immutable_code_pointer_table_call_inputs,
    _checked_product_reachability_inventories,
    _composition_progress,
    _constant_read32_address,
    _dynamic_range_indirect_call_candidates,
    _dynamic_range_indirect_call_shape,
    _immutable_code_pointer_table_call_candidates,
    _immutable_image_u32,
    _immutable_indirect_call_candidates,
    _register_writes_have_address_separations,
    _relational_product_graph,
)
from .analyses.external import (
    _attach_external_result_dynamic_invariants,
    _attach_external_call_site_analysis,
    _attach_machine_import_call_contract_analysis,
    _machine_import_call_contract_analysis,
    _semantic_affine_base_offset,
    _external_argument_relation_claims,
    _external_call_site_candidates,
    _register_offset_witness,
    _semantic_add_word_offset,
    _semantic_affine_word_read,
    _semantic_call_push_base,
    _semantic_exact_stack_argument,
    _semantic_external_target_identity,
    _semantic_externalize_register_import_call,
    _semantic_input_register_offset,
    _semantic_word_read,
    _semantic_word_writes_disjoint,
)
from .model import _semantic_constant_word
from .phases import CompositionProducts, ExtractedProgramPair, StateAnalysisProducts
from .region_facts import (
    _canonical_json_sha256,
    analyze_relational_region_facts,
    region_facts_semantics_sha256,
)
from .region_facts_artifact import RegionFactsArtifact
from .analyses.memory import (
    _attach_dynamic_range_flow_invariants,
    _attach_initial_static_code_pointer_slots,
    _attach_static_dynamic_pointer_slots,
    _attach_static_word_relation_slots,
)
from .analyses.segments import (
    _attach_memory_transition_analysis,
    _attach_branch_exact_memory_requirements,
    _attach_register_relation_analysis,
    _attach_segment_refinement_analysis,
    _attach_static_word_register_output_claims,
    _attach_stack_register_output_claims,
    _direct_call_stack_amount,
    _dynamic_range_register_output_claims,
    _dynamic_range_transfer_claims,
    _import_register_transfer_claims,
    _lower_stack_register_relations,
    _mapped_relocation_image_obligations,
    _paired_stack_guard_claim,
    _paired_stack_word_value_claim,
    _paired_stack_word_write_claim,
    _paired_stack_word_writes_claim,
    _proof_ir,
    _related_word_zero_guard_claim,
    _segment_refinement_candidates,
    _segment_refinement_diagnostic_report,
    _semantic_expr_has_exact_inputs,
    _semantic_expr_registers,
    _stack_read32_sub_output_claim,
    _static_dynamic_pointer_slot_guard_claim,
)
from .analyses.x87 import attach_x87_exact_stack_read_invariants
from .analyses.predicates import (
    attach_no_write_bound_edge_pullbacks,
    attach_no_write_state_predicate_pullbacks,
)
from .analyses.registers import (
    _attach_assembled_immutable_read_address_separations,
    _attach_import_register_invariants,
    _attach_import_seed_address_separations,
    _closed_internal_return_predecessors,
    _exact_index_expression,
    _iat_import_register_seed_candidates,
    _iat_seed_read,
    _infer_import_register_invariants,
    _infer_register_output_relation,
    _paired_constant_relation,
    _propose_internal_callsite_preservation_summaries,
    _refine_contract_bounds,
    _register_relation_implies,
    _register_relation_join,
    _returning_external_thunk_predecessors,
    _semantic_index_from_address,
    _semantic_read_addresses,
    _synthesize_register_relations,
)
from .analyses.stack import (
    _attach_return_slot_contracts,
    _attach_return_write_address_separations,
    _attach_stack_window_invariants,
    _constant_return_write_requirements,
    _direct_call_push_claim,
    _discover_static_call_return_summaries,
    _reachable_weighted_nonzero_cycle_nodes,
    _return_pop_claim,
    _return_write_separations_cover,
    _semantic_read32_after_writes,
    _semantic_read32_after_writes_address,
    _semantic_read8_after_writes,
    _stack_window_transfer_claims,
)
from .contract import (
    _annotate_flag_liveness,
    _assign_region_targets,
    _check_coverage,
    _check_span_overlap,
    _dynamic_range_relations,
    _import_identity,
    _infer_region_address_separations,
    _inside_executable,
    _load_contract,
    _machine_import_call_contracts,
    _mapped_relocation_offsets,
    _normalize_contract,
    _normalize_padding,
    _padding_bridge_valid,
    _padding_bytes,
    _raw_base_relocations,
    _register_pairs,
    _semantic_cutpoint_spans,
    _semantic_expr_is_pure,
    _span,
    _static_dynamic_pointer_slots,
    _static_word_relation_slots,
    stage_a_generate_relation_contract,
)


from .extraction import (
    _assembled_iat_read_candidates,
    _assembled_u32_after_register_writes,
    _behavior_cache_key,
    _behavior_rows,
    _cached_behavior_affected_by_machine_contracts,
    _extract_relational_behaviors,
    _normalize_raw_relational_behaviors,
    _iat_read_classification,
    _read8_after_register_writes,
    _read_behavior_cache,
    _register_offset_write,
    _relational_extraction_semantics_sha256,
    _relational_loader_facts,
    _relational_memory_contracts,
    _relational_semantic_ir,
    _relational_semantic_preflight,
    _run_lean_extractor,
    _semantic_exact_memory_inputs,
    _semantic_memory_expression_pullback_supported,
    _semantic_memory_pullback_support,
    _semantic_memory_reads,
    _semantic_pullback_exact_memory_inputs,
    _semantic_successors,
    _semantic_value_at_path,
    _semantic_x87_load_pullback_supported,
    _unique_import_at_absolute_address,
)
from .report import NixBuildReport
from .worker_diagnostics import WorkerPhase, write_worker_diagnostic
from .model import (
    PURE_SEMANTIC_EXPR_OPERATIONS,
    _semantic_constant_bool,
    _semantic_hash,
)
from .interfaces import stage_a_interface_manifest
from .isa_requirements import (
    ISARequirementInventory,
    build_isa_requirement_inventory,
    extract_lean_instruction_forms,
    _lean_form_source_hashes,
)
from .lean.analysis_source import (
    _copy_relational_analysis_kernel_sources,
    _copy_relational_kernel_sources,
)
from .pair_normalization import load_pair_normalization
from .proposal_artifact import write_relational_proposal_manifest
from .report_schema import RELATIONAL_PREPARED_REPORT_FILES
from .runtime_frame_artifact import (
    RUNTIME_FRAME_AFFINE_VIABILITY_FILE,
    runtime_frame_affine_viability_payload,
    validate_runtime_frame_affine_viability_payload,
)
from .register_dataflow_artifact import register_transfer_table_payload
from .register_dataflow_seed import register_dataflow_problem_seed_payload
from .register_transfer_ir import register_transfer_programs_payload
from .side_extraction import load_side_extraction, load_side_isa
from .schema import (
    FLAG_BITS,
    MACHINE_CALL_ABI_REGISTERS,
    MACHINE_CALL_ABI_TEMPLATES,
    MACHINE_CALL_MAX_ARGUMENT_WORDS,
    MACHINE_CALL_MEMORY_EFFECTS,
    MACHINE_CALL_WORLD_EFFECTS,
    REGISTERS,
    RELATION_CONTRACT_FORMAT,
    RELATIONAL_APPROVED_AXIOMS,
    RELATIONAL_ENVIRONMENT_ID,
    RELATIONAL_KERNEL_MODULES,
    RELATIONAL_OBSERVATIONS,
    RELATIONAL_PROOF_IR_FORMAT,
    RELATIONAL_SEGMENT_CERTIFICATE_FORMAT,
    STAGE_A_RELATIONAL_MODEL_ID,
    STAGE_A_RELATIONAL_PROFILE_ID,
    integer as _integer,
)

_LEAN_SOURCE_ROOT = Path(__file__).resolve().parent.parent / "lean" / "StageA"


def _extraction_failure_blocker(extraction: dict[str, Any]) -> str:
    output = str(extraction.get("stderr") or "") + "\n" + str(
        extraction.get("stdout") or ""
    )
    if " did not normalize" in output:
        return (
            "Lean decoded the exact region bytes but could not normalize every "
            "control-flow target into the canonical relation map"
        )
    if " did not decode" in output:
        return "Lean could not decode every relational region from the exact PE bytes"
    return "Lean could not extract normalized semantics for every relational region"


def _stabilize_fixed_code_pointer_register_calls(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    *,
    original_image_base: int,
    candidate_image_base: int,
    indirect_call_candidates: list[dict[str, Any]],
    import_call_candidates: list[dict[str, Any]],
    callsite_summary_predecessors: list[dict[str, Any]] | None = None,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    register_transfer_cache: dict[str, Any] | None = None,
    register_transfer_table_out: dict[str, Any] | None = None,
    register_transfer_programs_out: dict[str, Any] | None = None,
    register_transfer_program_cache: dict[str, Any] | None = None,
) -> tuple[
    dict[str, Any], dict[str, Any], list[dict[str, Any]], dict[str, Any]
]:
    fixed_candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    converged = False
    round_budget = max(1, len(contract.get("regions", [])) + 1)
    normalized = contract
    register_relations: dict[str, Any] = {}
    for _round in range(round_budget):
        combined = [*indirect_call_candidates, *fixed_candidates]
        source_ids = [
            int(candidate["source_region_index"])
            for candidate in combined
        ]
        if len(source_ids) != len(set(source_ids)):
            fixed_candidates = []
            break
        normalized, register_relations = _synthesize_register_relations(
            normalized,
            behaviors,
            original_image_base=original_image_base,
            candidate_image_base=candidate_image_base,
            indirect_call_candidates=combined,
            import_call_candidates=import_call_candidates,
            callsite_summary_predecessors=callsite_summary_predecessors,
            original_bin=original_bin,
            candidate_bin=candidate_bin,
            _transfer_cache=register_transfer_cache,
            _transfer_table_out=register_transfer_table_out,
            _transfer_programs_out=register_transfer_programs_out,
            _transfer_program_cache=register_transfer_program_cache,
        )
        proposed = register_relations.get(
            "indirect_fixed_code_pointer_calls", []
        )
        proposal_key = json.dumps(proposed, sort_keys=True, separators=(",", ":"))
        if proposed == fixed_candidates:
            converged = True
            break
        if proposal_key in seen:
            fixed_candidates = []
            break
        seen.add(proposal_key)
        fixed_candidates = proposed

    if not converged:
        fixed_candidates = []
        normalized, register_relations = _synthesize_register_relations(
            normalized,
            behaviors,
            original_image_base=original_image_base,
            candidate_image_base=candidate_image_base,
            indirect_call_candidates=indirect_call_candidates,
            import_call_candidates=import_call_candidates,
            callsite_summary_predecessors=callsite_summary_predecessors,
            original_bin=original_bin,
            candidate_bin=candidate_bin,
            _transfer_cache=register_transfer_cache,
            _transfer_table_out=register_transfer_table_out,
            _transfer_programs_out=register_transfer_programs_out,
            _transfer_program_cache=register_transfer_program_cache,
        )
    fixed_point = {
        "status": (
            "proposal_requires_generated_lean_replay" if converged else "incomplete"
        ),
        "converged": converged,
        "candidate_count": len(fixed_candidates),
        "round_budget": round_budget,
    }
    register_relations["fixed_code_pointer_call_fixed_point"] = fixed_point
    return (
        normalized,
        register_relations,
        [*indirect_call_candidates, *fixed_candidates],
        fixed_point,
    )


def _indirect_call_target_artifact(
    *,
    status: str,
    candidates: list[dict[str, Any]],
    table_call_proposals: list[dict[str, Any]],
    dynamic_range_candidates: list[dict[str, Any]],
    fixed_register_candidates: list[dict[str, Any]] | None = None,
    fixed_register_call_fixed_point: dict[str, Any] | None = None,
) -> dict[str, Any]:
    artifact = {
        "format": "stage-a-relational-indirect-call-targets-v1",
        "status": status,
        "candidates": candidates,
        "table_call_proposals": table_call_proposals,
        "dynamic_range_candidates": dynamic_range_candidates,
    }
    if fixed_register_candidates is not None:
        artifact["fixed_register_candidates"] = fixed_register_candidates
    if fixed_register_call_fixed_point is not None:
        artifact["fixed_register_call_fixed_point"] = (
            fixed_register_call_fixed_point
        )
    return artifact


def _prepared_relational_payload(
    out: Path,
    *,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    graph: dict[str, Any],
    composition_progress: dict[str, Any],
) -> dict[str, Any]:
    return {
        "format": "stage-a-prepared-relational-v2",
        "status": "prepared",
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "original_sha256": original_bin.sha256,
        "candidate_sha256": candidate_bin.sha256,
        "analysis_manifest_sha256": sha256_file(
            out / "relational-analysis-manifest.json"
        ),
        "interface_manifest_sha256": sha256_file(
            out / "stage-a-interface-manifest.json"
        ),
        "relation_contract_sha256": sha256_file(out / "relation-contract.json"),
        "proof_ir_sha256": sha256_file(out / "relational-proof-ir.json"),
        "semantic_ir_sha256": sha256_file(out / "relational-semantic-ir.json"),
        "memory_contracts_sha256": sha256_file(
            out / "relational-memory-contracts.json"
        ),
        "static_word_relations_sha256": sha256_file(
            out / "relational-static-word-relations.json"
        ),
        "register_relations_sha256": sha256_file(
            out / "relational-register-relations.json"
        ),
        "runtime_frame_affine_sha256": sha256_file(
            out / RUNTIME_FRAME_AFFINE_VIABILITY_FILE
        ),
        "stack_windows_sha256": sha256_file(
            out / "relational-stack-windows.json"
        ),
        "segment_diagnostics_sha256": sha256_file(
            out / "relational-segment-diagnostics.json"
        ),
        "product_graph_sha256": sha256_file(
            out / "relational-product-graph.json"
        ),
        "isa_requirements_sha256": sha256_file(out / "isa-requirements.json"),
        "invariants_sha256": sha256_file(out / "relational-invariants.json"),
        "whole_program_acceptance_sha256": sha256_file(
            out / "whole-program-acceptance.json"
        ),
        "composition_progress_sha256": sha256_file(
            out / "composition-progress.json"
        ),
        "artifact_manifest_sha256": sha256_file(
            out / "artifact-manifest.json"
        ),
        "module_graph_sha256": sha256_file(out / "module-graph.json"),
        "expected_final_theorem": graph["expected_final_theorem"],
        "acceptance": graph["acceptance"],
        "composition_progress": composition_progress,
        "approved_axioms": graph["approved_axioms"],
        "counts": graph["counts"],
    }


def _write_prepared_relational_graph(
    out: Path,
    *,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    normalized: dict[str, Any],
    behaviors: list[dict[str, Any]],
    invariant_synthesis: dict[str, Any],
    memory_contracts: dict[str, Any],
    register_relations: dict[str, Any],
    product_graph: dict[str, Any],
    runtime_frame_affine: dict[str, Any],
    import_register_seeds: list[dict[str, Any]],
    import_register_analysis: dict[str, Any],
    segment_candidates: list[dict[str, Any]],
    isa_requirements: dict[str, Any],
    semantic_preflight: dict[str, Any],
    external_call_sites: dict[str, Any],
    stack_window_analysis: dict[str, Any],
    trusted_base: dict[str, Any],
) -> dict[str, Any]:
    from .build import _write_relational_module_graph
    from .lean.generation import _write_sharded_relational_proof

    original_artifact = out / "artifacts" / "original.pe"
    candidate_artifact = out / "artifacts" / "candidate.pe"
    shard_modules, _ = _write_sharded_relational_proof(
        out / "lean",
        original_bin,
        candidate_bin,
        original_artifact.read_bytes(),
        candidate_artifact.read_bytes(),
        normalized,
        behaviors,
        invariant_synthesis=invariant_synthesis,
        memory_contracts=memory_contracts,
        register_relations=register_relations,
        product_graph=product_graph,
        runtime_frame_affine=runtime_frame_affine,
        import_register_seeds=import_register_seeds,
        import_register_analysis=import_register_analysis,
        external_call_sites=external_call_sites,
        segment_candidates=segment_candidates,
        isa_requirements=isa_requirements,
        replay=False,
    )
    acceptance = _read_json(out / "whole-program-acceptance.json")
    WholeProgramAcceptanceIR.parse(acceptance)
    composition_progress = _composition_progress(
        product_graph,
        semantic_preflight,
        external_call_sites,
        acceptance,
        stack_window_analysis,
    )
    CompositionProgressIR.parse(composition_progress)
    write_json(out / "composition-progress.json", composition_progress)
    graph = _write_relational_module_graph(
        out,
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        trusted_base=trusted_base,
    )
    for olean in (out / "lean").rglob("*.olean"):
        olean.unlink()
    prepared = _prepared_relational_payload(
        out,
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        graph=graph,
        composition_progress=composition_progress,
    )
    write_json(out / "prepared-proof.json", prepared)
    return prepared


def _run_relational_worker(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
    out: Path,
    original_extraction: Path | None = None,
    candidate_extraction: Path | None = None,
    normalized_behaviors: Path | None = None,
    original_isa: Path | None = None,
    candidate_isa: Path | None = None,
    region_facts: Path | None = None,
    phase: WorkerPhase,
) -> dict[str, Any]:
    _proposal_only = phase == "proposal"
    _analyze_only = phase in {"analysis", "proposal"}
    started_at = utc_now()
    out = Path(out)
    if out.exists():
        shutil.rmtree(out)
    (out / "artifacts").mkdir(parents=True)
    (out / "lean" / "StageA").mkdir(parents=True)
    (out / "certificates").mkdir(parents=True)

    try:
        original_bin = _parse_stage_a_pe(Path(original))
        candidate_bin = _parse_stage_a_pe(Path(candidate))
        contract = _load_contract(Path(relation_contract))
        normalized, issues = _normalize_contract(contract, original_bin, candidate_bin)
    except (OSError, StageAInputError, ValueError) as exc:
        return write_worker_diagnostic(
            out=out,
            phase=phase,
            started_at=started_at,
            original=Path(original),
            candidate=Path(candidate),
            reason_code="structural_validation_failed",
            message=str(exc),
        )

    if issues:
        return write_worker_diagnostic(
            out=out,
            phase=phase,
            started_at=started_at,
            original=Path(original),
            candidate=Path(candidate),
            reason_code="contract_structural_validation_failed",
            message="relational contract failed structural validation",
            issues=issues,
        )

    original_artifact = out / "artifacts" / "original.pe"
    candidate_artifact = out / "artifacts" / "candidate.pe"
    shutil.copyfile(original, original_artifact)
    shutil.copyfile(candidate, candidate_artifact)
    write_json(out / "relation-contract.json", normalized)
    write_json(
        out / "stage-a-interface-manifest.json",
        stage_a_interface_manifest(),
    )

    proof_ir = _proof_ir(original_bin, candidate_bin, normalized)
    RelationalProofIR.parse(proof_ir)
    write_json(out / "relational-proof-ir.json", proof_ir)
    trusted_base = {
        "format": "stage-a-relational-trusted-base-v1",
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "logical_trusted_base": [
            "lean_kernel",
            "lean_std_bv_decide_bitblaster",
            "lean_std_lrat_checker",
            "reviewed_stage_a_x86_pe32_relational_specification",
        ],
        "untrusted_producers": ["python", "capstone", "pefile", "z3", "sat_solver", "mapping_inference"],
        "approved_axioms": ["propext", "Classical.choice", "Quot.sound"],
        "claim_scope": {
            "kind": "relational_region_certificate",
            "whole_program_observational_equivalence": False,
        },
        "hard_boundaries": [
            "pe32_i386_only",
            "identity_address_memory_relation",
            "explicit_register_and_code_target_relations",
            "mapped_object_images_are_checked_at_relocation_word_granularity",
            "dynamic_memory_transition_preservation_requires_separate_closure",
            "external_equivalence_is_conditional_on_checked_lockstep_environment_refinement",
            "external_results_must_preserve_admitted_runtime_control_frames",
        ],
    }
    write_json(out / "trusted-base.json", trusted_base)

    semantic_preflight = _relational_semantic_preflight(original_artifact, candidate_artifact, normalized)
    write_json(out / "semantic-gaps.json", semantic_preflight)
    if semantic_preflight["status"] != "supported":
        return write_worker_diagnostic(
            out=out,
            phase=phase,
            started_at=started_at,
            original=Path(original),
            candidate=Path(candidate),
            reason_code="semantic_preflight_incomplete",
            message=(
                "x86 semantic preflight found regions outside the reviewed "
                "Lean decoder"
            ),
            issues=semantic_preflight["issues"],
        )

    if (original_extraction is None) != (candidate_extraction is None):
        raise StageAInputError(
            "both original and candidate side extractions are required"
        )
    if normalized_behaviors is not None and (
        original_extraction is None or candidate_extraction is None
    ):
        raise StageAInputError(
            "pair normalization requires both bound side extractions"
        )
    if region_facts is not None and normalized_behaviors is None:
        raise StageAInputError(
            "cached region facts require a bound pair normalization artifact"
        )
    if normalized_behaviors is not None:
        assert original_extraction is not None
        assert candidate_extraction is not None
        if not _analyze_only:
            _copy_relational_kernel_sources(out / "lean" / "StageA")
        behaviors = load_pair_normalization(
            path=Path(normalized_behaviors),
            normalized_contract=normalized,
            original_sha256=original_bin.sha256,
            candidate_sha256=candidate_bin.sha256,
            original_extraction=Path(original_extraction),
            candidate_extraction=Path(candidate_extraction),
        )
        extraction = {
            "status": "checked",
            "source": "manifest_bound_pair_normalization_artifact",
            "pair_normalization_artifact": sha256_file(
                Path(normalized_behaviors)
            ),
            "raw_side_artifacts": {
                "original": sha256_file(Path(original_extraction)),
                "candidate": sha256_file(Path(candidate_extraction)),
            },
        }
    elif original_extraction is not None and candidate_extraction is not None:
        _copy_relational_analysis_kernel_sources(out / "lean" / "StageA")
        raw_behaviors = {
            (side, index): term
            for side, path, binary in (
                ("original", original_extraction, original_bin),
                ("candidate", candidate_extraction, candidate_bin),
            )
            for index, term in enumerate(
                load_side_extraction(
                    path=Path(path),
                    contract=normalized,
                    side=side,
                    binary_sha256=binary.sha256,
                )
            )
        }
        behaviors, extraction = _normalize_raw_relational_behaviors(
            out / "lean", normalized, raw_behaviors
        )
        extraction = {
            **extraction,
            "raw_side_artifacts": {
                "original": sha256_file(Path(original_extraction)),
                "candidate": sha256_file(Path(candidate_extraction)),
            },
        }
    else:
        copy_kernel_sources = (
            _copy_relational_analysis_kernel_sources
            if _analyze_only
            else _copy_relational_kernel_sources
        )
        copy_kernel_sources(out / "lean" / "StageA")
        behaviors, extraction = _extract_relational_behaviors(
            out / "lean",
            original_bin,
            candidate_bin,
            original_artifact.read_bytes(),
            candidate_artifact.read_bytes(),
            normalized,
            use_cache=True,
        )
    if behaviors is None:
        extraction_issues = extraction.get("issues", [])
        return write_worker_diagnostic(
            out=out,
            phase=phase,
            started_at=started_at,
            original=Path(original),
            candidate=Path(candidate),
            reason_code="semantic_extraction_incomplete",
            message=_extraction_failure_blocker(extraction),
            issues=(
                extraction_issues
                if isinstance(extraction_issues, list)
                else []
            ),
        )
    extracted = ExtractedProgramPair.create(
        contract=normalized,
        behaviors=behaviors,
        extraction=extraction,
    )
    behaviors = extracted.behavior_rows()
    input_contract = extracted.mutable_contract()
    if region_facts is None:
        local_facts = analyze_relational_region_facts(
            original_bin=original_bin,
            candidate_bin=candidate_bin,
            normalized_contract=input_contract,
            behaviors=behaviors,
        )
    else:
        assert normalized_behaviors is not None
        payload = _read_json(Path(region_facts))
        artifact = RegionFactsArtifact.parse(
            payload,
            expected_original_sha256=original_bin.sha256,
            expected_candidate_sha256=candidate_bin.sha256,
            expected_input_relation_contract_sha256=(
                _canonical_json_sha256(input_contract)
            ),
            expected_normalized_behaviors_sha256=(
                sha256_file(Path(normalized_behaviors))
            ),
            expected_region_facts_semantics_sha256=(
                region_facts_semantics_sha256()
            ),
        )
        local_facts = artifact.mutable_payload()
    normalized = local_facts["contract"]
    initial_static_code_pointer_analysis = local_facts[
        "initial_static_code_pointer_analysis"
    ]
    indirect_call_candidates = local_facts["indirect_call_candidates"]
    table_call_proposals = local_facts["table_call_proposals"]
    dynamic_call_candidates = local_facts["dynamic_call_candidates"]
    import_register_seeds = local_facts["import_register_seeds"]
    machine_call_analysis = local_facts["machine_call_analysis"]
    register_transfer_cache: dict[str, Any] = {}
    import_register_analysis = _infer_import_register_invariants(
        normalized, behaviors, import_register_seeds
    )
    write_json(
        out / "relational-indirect-call-targets.json",
        _indirect_call_target_artifact(
            status="proposal_requires_generated_lean_replay",
            candidates=indirect_call_candidates,
            table_call_proposals=table_call_proposals,
            dynamic_range_candidates=dynamic_call_candidates,
        ),
    )
    write_json(
        out / "relational-import-register-seeds.json",
        {
            "format": "stage-a-relational-import-register-seeds-v1",
            "status": "proposal_requires_generated_lean_replay",
            "candidates": import_register_seeds,
        },
    )
    normalized = _attach_import_register_invariants(
        normalized, import_register_analysis
    )
    normalized, register_relations = _synthesize_register_relations(
        normalized,
        behaviors,
        original_image_base=original_bin.image_base,
        candidate_image_base=candidate_bin.image_base,
        indirect_call_candidates=indirect_call_candidates,
        import_call_candidates=import_register_analysis["indirect_import_calls"],
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        _transfer_cache=register_transfer_cache,
    )
    callsite_preservation_analysis: dict[str, Any] = {}
    max_callsite_rounds = max(1, len(normalized.get("regions", [])) + 1)
    for _ in range(max_callsite_rounds):
        callsite_preservation_analysis = (
            _propose_internal_callsite_preservation_summaries(
                normalized,
                behaviors,
                import_register_analysis,
                register_relations,
            )
        )
        callsite_summary_edges = callsite_preservation_analysis[
            "proposal_edges"
        ]
        return_predecessors = _closed_internal_return_predecessors(
            register_relations,
        )
        returning_external_thunk_predecessors = (
            _returning_external_thunk_predecessors(
                normalized, behaviors, register_relations,
            )
        )
        composed_import_register_analysis = _infer_import_register_invariants(
            normalized,
            behaviors,
            import_register_seeds,
            internal_return_predecessors=return_predecessors,
            callsite_summary_predecessors=callsite_summary_edges,
            returning_external_thunk_predecessors=(
                returning_external_thunk_predecessors
            ),
        )
        if (
            composed_import_register_analysis.get("relations")
            == import_register_analysis.get("relations")
            and composed_import_register_analysis.get("indirect_import_calls")
            == import_register_analysis.get("indirect_import_calls")
        ):
            import_register_analysis = composed_import_register_analysis
            break
        import_register_analysis = composed_import_register_analysis
        normalized = _attach_import_register_invariants(
            normalized, import_register_analysis
        )
        normalized, register_relations = _synthesize_register_relations(
            normalized,
            behaviors,
            original_image_base=original_bin.image_base,
            candidate_image_base=candidate_bin.image_base,
            indirect_call_candidates=indirect_call_candidates,
            import_call_candidates=import_register_analysis[
                "indirect_import_calls"
            ],
            original_bin=original_bin,
            candidate_bin=candidate_bin,
            _transfer_cache=register_transfer_cache,
        )
    else:
        callsite_preservation_analysis = {
            **callsite_preservation_analysis,
            "status": "incomplete_fixed_point_budget_exhausted",
        }
    callsite_preservation_artifact = parse_callsite_preservation_artifact(
        callsite_preservation_analysis,
        region_count=len(normalized.get("regions", [])),
    )
    write_json(
        out / "relational-callsite-preservation.json",
        serialize_callsite_preservation_artifact(
            callsite_preservation_artifact
        ),
    )
    write_json(
        out / "relational-import-register-invariants.json",
        import_register_analysis,
    )
    normalized, stack_window_analysis = _attach_stack_window_invariants(
        normalized, behaviors, register_relations, original_bin, candidate_bin
    )
    normalized, x87_stack_read_analysis = attach_x87_exact_stack_read_invariants(
        normalized, behaviors
    )
    stack_window_analysis["x87_exact_stack_reads"] = x87_stack_read_analysis
    # Stack provenance is discovered from decoded memory accesses and runtime
    # frames after the initial edge analysis. Replay register synthesis so
    # stack-derived pointers flow forward as related words instead of exact
    # values before redundant register atoms are lowered into stack windows.
    normalized, register_relations = _synthesize_register_relations(
        normalized,
        behaviors,
        original_image_base=original_bin.image_base,
        candidate_image_base=candidate_bin.image_base,
        indirect_call_candidates=indirect_call_candidates,
        import_call_candidates=import_register_analysis["indirect_import_calls"],
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        _transfer_cache=register_transfer_cache,
    )
    normalized, register_relations = _lower_stack_register_relations(
        normalized, register_relations
    )
    register_relations = _attach_stack_register_output_claims(
        normalized, behaviors, register_relations
    )
    normalized, static_word_analysis = _attach_static_word_relation_slots(
        normalized, behaviors, original_bin, candidate_bin
    )
    static_word_analysis["initial_code_pointers"] = (
        initial_static_code_pointer_analysis
    )
    register_transfer_table: dict[str, Any] = {}
    register_transfer_programs: dict[str, Any] = {}
    register_transfer_program_cache: dict[str, Any] = {}
    # Static slots are inferred from paired writes after the first register
    # fixed point. Replay synthesis so equal-address loads do not retain an
    # unsoundly strong exact relation when their checked slot is only related.
    normalized, register_relations = _synthesize_register_relations(
        normalized,
        behaviors,
        original_image_base=original_bin.image_base,
        candidate_image_base=candidate_bin.image_base,
        indirect_call_candidates=indirect_call_candidates,
        import_call_candidates=import_register_analysis["indirect_import_calls"],
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        _transfer_cache=register_transfer_cache,
    )
    normalized, register_relations = _lower_stack_register_relations(
        normalized, register_relations
    )
    register_relations = _attach_stack_register_output_claims(
        normalized, behaviors, register_relations
    )
    register_relations = _attach_static_word_register_output_claims(
        normalized, behaviors, register_relations
    )
    write_json(out / "relational-stack-windows.json", stack_window_analysis)
    write_json(out / "relational-static-word-relations.json", static_word_analysis)
    write_json(out / "relation-contract.json", normalized)
    write_json(out / "relational-register-relations.json", register_relations)
    proof_ir = _proof_ir(original_bin, candidate_bin, normalized)
    write_json(out / "relational-machine-import-calls.json", machine_call_analysis)
    external_call_sites = _external_call_site_candidates(
        normalized, behaviors, register_relations,
        import_register_analysis["indirect_import_calls"],
    )
    normalized, external_result_invariants = (
        _attach_external_result_dynamic_invariants(normalized, external_call_sites)
    )
    write_json(
        out / "relational-external-result-invariants.json",
        external_result_invariants,
    )
    dynamic_flow_passes: list[dict[str, Any]] = []
    static_pointer_passes: list[dict[str, Any]] = []
    lifecycle_converged = False
    for _lifecycle_iteration in range(max(1, len(normalized.get("regions", [])) + 1)):
        before = (
            sum(
                len(region.get("input_dynamic_range_relations", []))
                for region in normalized.get("regions", [])
            ),
            len(normalized.get("static_dynamic_pointer_slots", [])),
        )
        normalized, dynamic_flow_pass = _attach_dynamic_range_flow_invariants(
            normalized, behaviors, register_relations,
        )
        dynamic_flow_passes.append(dynamic_flow_pass)
        normalized, static_pointer_pass = _attach_static_dynamic_pointer_slots(
            normalized, behaviors, original_bin, candidate_bin,
        )
        static_pointer_passes.append(static_pointer_pass)
        after = (
            sum(
                len(region.get("input_dynamic_range_relations", []))
                for region in normalized.get("regions", [])
            ),
            len(normalized.get("static_dynamic_pointer_slots", [])),
        )
        if after == before:
            lifecycle_converged = True
            break
    dynamic_flow_analysis = {
        "format": "spaghetti-extractor-dynamic-range-lifecycle-v1",
        "status": (
            "proposal_requires_generated_lean_replay"
            if lifecycle_converged
            and all(item["status"] != "incomplete" for item in dynamic_flow_passes)
            else "incomplete"
        ),
        "converged": lifecycle_converged,
        "passes": dynamic_flow_passes,
    }
    static_dynamic_pointer_analysis = {
        "format": "spaghetti-extractor-static-dynamic-pointer-lifecycle-v1",
        "status": (
            "proposal_requires_generated_lean_replay"
            if lifecycle_converged
            and all(item["status"] != "incomplete" for item in static_pointer_passes)
            else "incomplete"
        ),
        "converged": lifecycle_converged,
        "passes": static_pointer_passes,
    }
    # Exact-memory predicates are a fallback for otherwise-unclassified branch
    # reads. Infer dynamic/static pointer slots first so their stronger checked
    # relation can discharge zero/nonzero guards without leaving a stale exact
    # memory requirement in the cutpoint invariant.
    normalized, branch_exact_memory_analysis = (
        _attach_branch_exact_memory_requirements(
            normalized, behaviors, original_bin, candidate_bin
        )
    )
    stack_window_analysis["branch_exact_memory_requirements"] = (
        branch_exact_memory_analysis
    )
    normalized, bound_pullback_analysis = attach_no_write_bound_edge_pullbacks(
        normalized, behaviors
    )
    stack_window_analysis["bound_edge_pullbacks"] = bound_pullback_analysis
    normalized, predicate_pullback_analysis = attach_no_write_state_predicate_pullbacks(
        normalized, behaviors
    )
    stack_window_analysis["state_predicate_pullbacks"] = predicate_pullback_analysis
    write_json(
        out / "relational-dynamic-range-flow.json",
        dynamic_flow_analysis,
    )
    write_json(
        out / "relational-static-dynamic-pointer-slots.json",
        static_dynamic_pointer_analysis,
    )
    normalized, static_word_analysis = _attach_static_word_relation_slots(
        normalized, behaviors, original_bin, candidate_bin,
    )
    static_word_analysis["initial_code_pointers"] = (
        initial_static_code_pointer_analysis
    )
    (
        normalized,
        register_relations,
        combined_indirect_call_candidates,
        fixed_register_call_fixed_point,
    ) = _stabilize_fixed_code_pointer_register_calls(
        normalized,
        behaviors,
        original_image_base=original_bin.image_base,
        candidate_image_base=candidate_bin.image_base,
        indirect_call_candidates=indirect_call_candidates,
        import_call_candidates=import_register_analysis["indirect_import_calls"],
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        register_transfer_cache=register_transfer_cache,
        register_transfer_table_out=register_transfer_table,
        register_transfer_programs_out=register_transfer_programs,
        register_transfer_program_cache=register_transfer_program_cache,
    )
    fixed_register_call_candidates = combined_indirect_call_candidates[
        len(indirect_call_candidates):
    ]
    normalized, register_relations = _lower_stack_register_relations(
        normalized, register_relations
    )
    register_relations = _attach_stack_register_output_claims(
        normalized, behaviors, register_relations
    )
    register_relations = _attach_static_word_register_output_claims(
        normalized, behaviors, register_relations
    )
    # Caller-produced relations such as fixed code pointers are scoped to the
    # runtime frame, not the shared callee invariant.  Jointly stabilize those
    # callsite summaries with register dataflow and indirect-call discovery.
    callsite_relation_fixed_point = {
        "status": "incomplete",
        "converged": False,
        "rounds": 0,
        "round_budget": 8,
    }
    previous_summary_key: str | None = None
    for callsite_round in range(callsite_relation_fixed_point["round_budget"]):
        callsite_preservation_analysis = (
            _propose_internal_callsite_preservation_summaries(
                normalized,
                behaviors,
                import_register_analysis,
                register_relations,
            )
        )
        summary_predecessors = callsite_preservation_analysis.get(
            "proposal_edges", []
        )
        summary_key = json.dumps(
            summary_predecessors, sort_keys=True, separators=(",", ":")
        )
        callsite_relation_fixed_point["rounds"] = callsite_round + 1
        if summary_key == previous_summary_key:
            callsite_relation_fixed_point.update({
                "status": "proposal_requires_generated_lean_replay",
                "converged": True,
            })
            break
        previous_summary_key = summary_key
        (
            normalized,
            register_relations,
            combined_indirect_call_candidates,
            fixed_register_call_fixed_point,
        ) = _stabilize_fixed_code_pointer_register_calls(
            normalized,
            behaviors,
            original_image_base=original_bin.image_base,
            candidate_image_base=candidate_bin.image_base,
            indirect_call_candidates=indirect_call_candidates,
            import_call_candidates=import_register_analysis[
                "indirect_import_calls"
            ],
            callsite_summary_predecessors=summary_predecessors,
            original_bin=original_bin,
            candidate_bin=candidate_bin,
            register_transfer_cache=register_transfer_cache,
            register_transfer_table_out=register_transfer_table,
            register_transfer_programs_out=register_transfer_programs,
            register_transfer_program_cache=register_transfer_program_cache,
        )
        normalized, register_relations = _lower_stack_register_relations(
            normalized, register_relations
        )
        register_relations = _attach_stack_register_output_claims(
            normalized, behaviors, register_relations
        )
        register_relations = _attach_static_word_register_output_claims(
            normalized, behaviors, register_relations
        )
    callsite_preservation_analysis = (
        _propose_internal_callsite_preservation_summaries(
            normalized,
            behaviors,
            import_register_analysis,
            register_relations,
        )
    )
    callsite_preservation_artifact = parse_callsite_preservation_artifact(
        callsite_preservation_analysis,
        region_count=len(normalized.get("regions", [])),
    )
    write_json(
        out / "relational-callsite-preservation.json",
        serialize_callsite_preservation_artifact(callsite_preservation_artifact),
    )
    register_relations["callsite_register_relation_fixed_point"] = (
        callsite_relation_fixed_point
    )
    fixed_register_call_candidates = combined_indirect_call_candidates[
        len(indirect_call_candidates):
    ]
    write_json(
        out / "relational-indirect-call-targets.json",
        _indirect_call_target_artifact(
            status=fixed_register_call_fixed_point["status"],
            candidates=indirect_call_candidates,
            table_call_proposals=table_call_proposals,
            dynamic_range_candidates=dynamic_call_candidates,
            fixed_register_candidates=fixed_register_call_candidates,
            fixed_register_call_fixed_point=fixed_register_call_fixed_point,
        ),
    )
    fixed_flow_facts = [
        {
            "id": f"{direction}:{region_index}:{relation_index}",
            "kind": direction,
            "region_index": region_index,
            "original_register": relation["original"],
            "candidate_register": relation["candidate"],
            "target_id": int(relation["target_id"]),
        }
        for region_index, row in enumerate(register_relations.get("regions", []))
        for direction, relations in (
            ("input", row.get("inputs", [])),
            ("output", row.get("outputs", [])),
        )
        for relation_index, relation in enumerate(relations)
        if relation.get("relation") == "fixed_code_pointer"
        and isinstance(relation.get("target_id"), int)
        and not isinstance(relation.get("target_id"), bool)
    ]
    write_json(
        out / "relational-fixed-code-pointer-flow.json",
        {
            "format": "stage-a-fixed-code-pointer-register-flow-v1",
            "status": fixed_register_call_fixed_point["status"],
            "acceptance_authority": False,
            "facts": fixed_flow_facts,
            "edge_proposals": fixed_register_call_candidates,
            "fixed_point": fixed_register_call_fixed_point,
            "activation": {
                "state": "pending_generated_lean_replay",
                "activated_edges": [],
            },
        },
    )
    write_json(out / "relational-static-word-relations.json", static_word_analysis)
    write_json(out / "relational-register-relations.json", register_relations)
    write_json(
        out / "relational-register-dataflow-graph.json",
        register_transfer_table["graph"],
    )
    write_json(
        out / "relational-register-transfer-table.json",
        register_transfer_table_payload(
            original_sha256=original_bin.sha256,
            candidate_sha256=candidate_bin.sha256,
            graph_sha256=str(register_transfer_table["graph_sha256"]),
            regions=register_transfer_table["regions"],
            propagation=register_transfer_table["propagation"],
        ),
    )
    register_transfer_program_artifact = register_transfer_programs_payload(
        original_sha256=original_bin.sha256,
        candidate_sha256=candidate_bin.sha256,
        graph_sha256=str(register_transfer_programs["graph_sha256"]),
        context=register_transfer_programs["context"],
        programs=register_transfer_programs["programs"],
        propagation=register_transfer_programs["propagation"],
    )
    write_json(
        out / "relational-register-transfer-programs.json",
        register_transfer_program_artifact,
    )
    write_json(
        out / "relational-register-program-dataflow-graph.json",
        register_transfer_programs["graph"],
    )
    write_json(out / "relation-contract.json", normalized)
    write_json(
        out / "relational-decoded-behaviors.json",
        decoded_behaviors_payload(
            original_sha256=original_bin.sha256,
            candidate_sha256=candidate_bin.sha256,
            relation_contract_sha256=sha256_file(out / "relation-contract.json"),
            behaviors=behaviors,
        ),
    )
    try:
        frame_max_shapes = int(os.environ.get(
            "SPAGHETTI_EXTRACTOR_STAGE_A_FRAME_AFFINE_SHAPES", "65536"
        ))
        frame_max_families = int(os.environ.get(
            "SPAGHETTI_EXTRACTOR_STAGE_A_FRAME_AFFINE_FAMILIES", "65536"
        ))
    except ValueError:
        frame_max_shapes = 0
        frame_max_families = 0
    runtime_frame_affine = runtime_frame_affine_viability_payload(
            original_sha256=original_bin.sha256,
            candidate_sha256=candidate_bin.sha256,
            relation_contract_sha256=sha256_file(
                out / "relation-contract.json"
            ),
            decoded_behaviors_sha256=sha256_file(
                out / "relational-decoded-behaviors.json"
            ),
            register_relations_sha256=sha256_file(
                out / "relational-register-relations.json"
            ),
            behaviors=behaviors,
            register_relations=register_relations,
            max_shapes=frame_max_shapes,
            max_families=frame_max_families,
        )
    write_json(
        out / RUNTIME_FRAME_AFFINE_VIABILITY_FILE,
        runtime_frame_affine,
    )
    register_dataflow_problem_seed = register_dataflow_problem_seed_payload(
        original_sha256=original_bin.sha256,
        candidate_sha256=candidate_bin.sha256,
        contract_sha256=_canonical_json_sha256(normalized),
        behaviors_sha256=_canonical_json_sha256(behaviors),
        indirect_call_candidates=combined_indirect_call_candidates,
        import_call_candidates=import_register_analysis[
            "indirect_import_calls"
        ],
        callsite_summary_predecessors=callsite_preservation_analysis.get(
            "proposal_edges", []
        ),
    )
    write_json(
        out / "relational-register-dataflow-problem-seed.json",
        register_dataflow_problem_seed,
    )
    if _proposal_only:
        RelationalProofIR.parse(proof_ir)
        write_json(out / "relational-proof-ir.json", proof_ir)
        shutil.rmtree(out / "lean")
        shutil.rmtree(out / "certificates")
        return write_relational_proposal_manifest(
            out,
            original_sha256=original_bin.sha256,
            candidate_sha256=candidate_bin.sha256,
        )
    # Composition is a downstream phase with its own source and cache boundary.
    # Import it only after proposal discovery has reached its terminal artifact.
    from .composition_products import _produce_composition_outputs

    assembled = _produce_composition_outputs(
        out=out,
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        original_artifact=original_artifact,
        candidate_artifact=candidate_artifact,
        normalized=normalized,
        behaviors=behaviors,
        extraction=extraction,
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
    )
    proof_ir = assembled["proof_ir"]
    invariant_synthesis = assembled["invariant_synthesis"]
    memory_contracts = assembled["memory_contracts"]
    product_graph = assembled["product_graph"]
    external_call_sites = assembled["external_call_sites"]
    segment_candidates = assembled["segment_candidates"]
    isa_requirements = assembled["isa_requirements"]
    runtime_frame_affine = runtime_frame_affine_viability_payload(
        original_sha256=original_bin.sha256,
        candidate_sha256=candidate_bin.sha256,
        relation_contract_sha256=sha256_file(out / "relation-contract.json"),
        decoded_behaviors_sha256=sha256_file(
            out / "relational-decoded-behaviors.json"
        ),
        register_relations_sha256=sha256_file(
            out / "relational-register-relations.json"
        ),
        behaviors=behaviors,
        register_relations=register_relations,
        product_graph=product_graph,
        max_shapes=frame_max_shapes,
        max_families=frame_max_families,
    )
    write_json(
        out / RUNTIME_FRAME_AFFINE_VIABILITY_FILE,
        runtime_frame_affine,
    )
    analysis_manifest = write_relational_analysis_manifest(
        out,
        original_sha256=original_bin.sha256,
        candidate_sha256=candidate_bin.sha256,
    )
    if _analyze_only:
        shutil.rmtree(out / "lean")
        shutil.rmtree(out / "certificates")
        return analysis_manifest
    return _write_prepared_relational_graph(
        out,
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        normalized=normalized,
        behaviors=behaviors,
        invariant_synthesis=invariant_synthesis,
        memory_contracts=memory_contracts,
        register_relations=register_relations,
        product_graph=product_graph,
        runtime_frame_affine=runtime_frame_affine,
        import_register_seeds=import_register_seeds,
        import_register_analysis=import_register_analysis,
        segment_candidates=segment_candidates,
        isa_requirements=isa_requirements.to_payload(),
        semantic_preflight=semantic_preflight,
        external_call_sites=external_call_sites,
        stack_window_analysis=stack_window_analysis,
        trusted_base=trusted_base,
    )

def stage_a_prepare_relational(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
    out: Path,
) -> dict[str, Any]:
    return _run_relational_worker(
        original=original,
        candidate=candidate,
        relation_contract=relation_contract,
        out=out,
        phase="preparation",
    )


def stage_a_preflight_relational(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
) -> dict[str, Any]:
    """Run the cheap, fail-closed structural and ISA eligibility checks.

    This deliberately stops before extraction, invariant synthesis, proof
    source generation, or Lean.  It has no acceptance authority; its output is
    suitable only for deciding whether an expensive proof preparation is worth
    starting.
    """

    started = time.monotonic()
    try:
        original_bin = _parse_stage_a_pe(Path(original))
        candidate_bin = _parse_stage_a_pe(Path(candidate))
        contract = _load_contract(Path(relation_contract))
        normalized, structural_issues = _normalize_contract(
            contract, original_bin, candidate_bin
        )
    except (OSError, StageAInputError, ValueError) as exc:
        return {
            "format": "stage-a-relational-static-preflight-v1",
            "status": "incomplete",
            "acceptance_authority": False,
            "reason_code": "structural_validation_failed",
            "issues": [{
                "category": "structural_validation_failed",
                "message": str(exc),
            }],
            "elapsed_seconds": round(time.monotonic() - started, 6),
        }
    if structural_issues:
        return {
            "format": "stage-a-relational-static-preflight-v1",
            "status": "incomplete",
            "acceptance_authority": False,
            "reason_code": "contract_structural_validation_failed",
            "issues": structural_issues,
            "original_sha256": original_bin.sha256,
            "candidate_sha256": candidate_bin.sha256,
            "elapsed_seconds": round(time.monotonic() - started, 6),
        }
    semantic = _relational_semantic_preflight(
        Path(original), Path(candidate), normalized
    )
    return {
        "format": "stage-a-relational-static-preflight-v1",
        "status": "ready" if semantic["status"] == "supported" else "incomplete",
        "acceptance_authority": False,
        "reason_code": (
            None if semantic["status"] == "supported"
            else "semantic_preflight_incomplete"
        ),
        "issues": semantic["issues"],
        "counts": {
            "regions": len(normalized.get("regions", [])),
            "issues": len(semantic["issues"]),
        },
        "original_sha256": original_bin.sha256,
        "candidate_sha256": candidate_bin.sha256,
        "relation_contract_sha256": sha256_file(Path(relation_contract)),
        "elapsed_seconds": round(time.monotonic() - started, 6),
    }


def stage_a_analyze_relational(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
    out: Path,
    original_extraction: Path | None = None,
    candidate_extraction: Path | None = None,
    normalized_behaviors: Path | None = None,
    original_isa: Path | None = None,
    candidate_isa: Path | None = None,
    region_facts: Path | None = None,
) -> dict[str, Any]:
    return _run_relational_worker(
        original=original,
        candidate=candidate,
        relation_contract=relation_contract,
        out=out,
        original_extraction=original_extraction,
        candidate_extraction=candidate_extraction,
        normalized_behaviors=normalized_behaviors,
        original_isa=original_isa,
        candidate_isa=candidate_isa,
        region_facts=region_facts,
        phase="analysis",
    )


def stage_a_discover_relational_proposals(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
    out: Path,
    original_extraction: Path | None = None,
    candidate_extraction: Path | None = None,
    normalized_behaviors: Path | None = None,
    region_facts: Path | None = None,
) -> dict[str, Any]:
    return _run_relational_worker(
        original=original,
        candidate=candidate,
        relation_contract=relation_contract,
        out=out,
        original_extraction=original_extraction,
        candidate_extraction=candidate_extraction,
        normalized_behaviors=normalized_behaviors,
        region_facts=region_facts,
        phase="proposal",
    )


def stage_a_generate_relational(
    *, analysis: Path, out: Path
) -> dict[str, Any]:
    from .analysis_reference import (
        materialize_relational_analysis_view,
        validate_relational_analysis_view,
    )

    analysis = Path(analysis)
    out = Path(out)
    source_manifest = validate_relational_analysis_view(analysis)
    materialize_relational_analysis_view(analysis, out)
    copied_manifest = validate_relational_analysis(out)
    if copied_manifest != source_manifest:
        raise StageAInputError("copied relational analysis manifest changed")

    original_artifact = out / "artifacts" / "original.pe"
    candidate_artifact = out / "artifacts" / "candidate.pe"
    original_bin = _parse_stage_a_pe(original_artifact)
    candidate_bin = _parse_stage_a_pe(candidate_artifact)
    if original_bin.sha256 != source_manifest.original_sha256:
        raise StageAInputError("analyzed original PE identity changed")
    if candidate_bin.sha256 != source_manifest.candidate_sha256:
        raise StageAInputError("analyzed candidate PE identity changed")

    normalized = _load_contract(out / "relation-contract.json")
    decoded = _read_json(out / "relational-decoded-behaviors.json")
    behaviors_raw = parse_decoded_behaviors(
        decoded,
        expected_original_sha256=original_bin.sha256,
        expected_candidate_sha256=candidate_bin.sha256,
        expected_relation_contract_sha256=sha256_file(
            out / "relation-contract.json"
        ),
        expected_region_count=len(normalized.get("regions", [])),
    )
    extracted = ExtractedProgramPair.create(
        contract=normalized,
        behaviors=behaviors_raw,
        extraction={"source": "manifest_bound_lossless_behavior_inventory"},
    )
    behaviors = extracted.behavior_rows()

    segment_artifact = _read_json(out / "relational-segment-candidates.json")
    segment_candidates = parse_segment_candidates(
        segment_artifact,
        expected_diagnostics_sha256=sha256_file(
            out / "relational-segment-diagnostics.json"
        ),
        expected_product_graph_sha256=sha256_file(
            out / "relational-product-graph.json"
        ),
    )

    proof_ir = _read_json(out / "relational-proof-ir.json")
    RelationalProofIR.parse(proof_ir)
    invariant_synthesis = _read_json(out / "relational-invariants.json")
    memory_contracts = _read_json(out / "relational-memory-contracts.json")
    register_relations = _read_json(out / "relational-register-relations.json")
    product_graph = _read_json(out / "relational-product-graph.json")
    ProductGraphIR.parse(product_graph)
    runtime_frame_affine = _read_json(
        out / RUNTIME_FRAME_AFFINE_VIABILITY_FILE
    )
    validate_runtime_frame_affine_viability_payload(
        runtime_frame_affine,
        original_sha256=original_bin.sha256,
        candidate_sha256=candidate_bin.sha256,
        relation_contract_sha256=sha256_file(out / "relation-contract.json"),
        decoded_behaviors_sha256=sha256_file(
            out / "relational-decoded-behaviors.json"
        ),
        register_relations_sha256=sha256_file(
            out / "relational-register-relations.json"
        ),
        behaviors=behaviors,
        register_relations=register_relations,
        product_graph=product_graph,
    )
    import_seed_artifact = _read_json(
        out / "relational-import-register-seeds.json"
    )
    import_register_seeds = import_seed_artifact.get("candidates")
    if not isinstance(import_register_seeds, list):
        raise StageAInputError("import register seed artifact is malformed")
    import_register_analysis = _read_json(
        out / "relational-import-register-invariants.json"
    )
    isa_requirements = ISARequirementInventory.parse(
        _read_json(out / "isa-requirements.json")
    )
    semantic_preflight = _read_json(out / "semantic-gaps.json")
    if semantic_preflight.get("status") != "supported":
        raise StageAInputError(
            "cannot generate proof sources from incomplete semantic analysis"
        )
    external_call_sites = _read_json(out / "relational-external-call-sites.json")
    stack_window_analysis = _read_json(out / "relational-stack-windows.json")
    trusted_base = _read_json(out / "trusted-base.json")

    (out / "lean" / "StageA").mkdir(parents=True)
    (out / "certificates").mkdir(parents=True)
    _copy_relational_kernel_sources(out / "lean" / "StageA")
    prepared = _write_prepared_relational_graph(
        out,
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        normalized=normalized,
        behaviors=behaviors,
        invariant_synthesis=invariant_synthesis,
        memory_contracts=memory_contracts,
        register_relations=register_relations,
        product_graph=product_graph,
        runtime_frame_affine=runtime_frame_affine,
        import_register_seeds=import_register_seeds,
        import_register_analysis=import_register_analysis,
        segment_candidates=segment_candidates,
        isa_requirements=isa_requirements.to_payload(),
        semantic_preflight=semantic_preflight,
        external_call_sites=external_call_sites,
        stack_window_analysis=stack_window_analysis,
        trusted_base=trusted_base,
    )
    validate_relational_analysis(out)
    return prepared

def stage_a_check_relational_proof(
    *, report: Path, out: Path | None = None
) -> dict[str, Any]:
    report = Path(report)
    verdict = _read_json(report / "verdict.json")
    NixBuildReport.parse(verdict)

    from .build import _check_nix_relational_report

    return _check_nix_relational_report(report=report, verdict=verdict, out=out)
