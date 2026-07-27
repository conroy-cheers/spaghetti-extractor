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


from .verdict import (
    _write_incomplete,
    _write_relational_verdict,
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
    RELATIONAL_ACCEPTANCE_THEOREMS,
    RELATIONAL_APPROVED_AXIOMS,
    RELATIONAL_ENVIRONMENT_ID,
    RELATIONAL_KERNEL_MODULES,
    RELATIONAL_OBSERVATIONS,
    RELATIONAL_PROOF_IR_FORMAT,
    RELATIONAL_SEGMENT_CERTIFICATE_FORMAT,
    STAGE_A_RELATIONAL_MODEL_ID,
    STAGE_A_RELATIONAL_PROFILE_ID,
    SchemaError,
    integer as _integer,
    selected_relational_acceptance_theorem,
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
    prepare_only: bool,
) -> tuple[list[str], dict[str, Any] | None]:
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
    if not prepare_only:
        return shard_modules, None
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
    return shard_modules, prepared


def stage_a_prove_relational(
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
    _prepare_only: bool = False,
    _analyze_only: bool = False,
    _proposal_only: bool = False,
) -> dict[str, Any]:
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
        return _write_incomplete(out, started_at, original, candidate, str(exc))

    if issues:
        return _write_incomplete(
            out,
            started_at,
            original,
            candidate,
            "relational contract failed structural validation",
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
        return _write_relational_verdict(
            out,
            started_at,
            original_bin,
            candidate_bin,
            normalized,
            proof_ir,
            trusted_base,
            "incomplete",
            {
                "status": "semantic_preflight_incomplete",
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "issues": semantic_preflight["issues"],
            },
            certificates=[],
            blocker="x86 semantic preflight found regions outside the reviewed Lean decoder",
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
        return _write_relational_verdict(
            out,
            started_at,
            original_bin,
            candidate_bin,
            normalized,
            proof_ir,
            trusted_base,
            "incomplete",
            extraction,
            certificates=[],
            blocker=_extraction_failure_blocker(extraction),
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
    shard_modules, prepared = _write_prepared_relational_graph(
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
        prepare_only=_prepare_only,
    )
    if prepared is not None:
        return prepared
    production = _run_sharded_relational(out / "lean", shard_modules)
    if production["status"] != "checked":
        from .proof_diagnostics import check_relational_counterexample

        counterexample = check_relational_counterexample(
            out / "lean",
            original_bin,
            candidate_bin,
            original_artifact.read_bytes(),
            candidate_artifact.read_bytes(),
            normalized,
            behaviors,
            production,
        )
        if counterexample is not None:
            return _write_relational_verdict(
                out,
                started_at,
                original_bin,
                candidate_bin,
                normalized,
                proof_ir,
                trusted_base,
                "fail",
                counterexample,
                certificates=[],
                blocker="Lean checked a concrete relational counterexample",
            )
        return _write_relational_verdict(
            out,
            started_at,
            original_bin,
            candidate_bin,
            normalized,
            proof_ir,
            trusted_base,
            "incomplete",
            production,
            certificates=[],
            blocker="Lean did not close every relational obligation",
        )

    from .build import _finalize_local_proof_ir
    from .executor import _collect_certificates
    from .lean.generation import _write_sharded_relational_proof

    certificates = _collect_certificates(out / "lean", out / "certificates")
    covered_indices = {entry["region_index"] for entry in certificates}
    certificates.extend(
        {"region_index": index, "kind": "lean_normalization"}
        for index in range(len(normalized["regions"]))
        if index not in covered_indices
    )
    certificates.sort(key=lambda entry: entry["region_index"])
    for entry in certificates:
        index = entry.get("region_index")
        if isinstance(index, int) and 0 <= index < len(normalized["regions"]):
            entry["region_id"] = normalized["regions"][index]["id"]
    if len(certificates) != len(normalized["regions"]):
        return _write_relational_verdict(
            out,
            started_at,
            original_bin,
            candidate_bin,
            normalized,
            proof_ir,
            trusted_base,
            "incomplete",
            production,
            certificates=certificates,
            blocker="Lean proof production did not emit one LRAT certificate per region",
        )

    shard_modules, _ = _write_sharded_relational_proof(
        out / "lean", original_bin, candidate_bin,
        original_artifact.read_bytes(), candidate_artifact.read_bytes(),
        normalized, behaviors, invariant_synthesis=invariant_synthesis,
        memory_contracts=memory_contracts, register_relations=register_relations,
        product_graph=product_graph,
        runtime_frame_affine=runtime_frame_affine,
        import_register_seeds=import_register_seeds,
        import_register_analysis=import_register_analysis,
        external_call_sites=external_call_sites,
        segment_candidates=segment_candidates,
        isa_requirements=isa_requirements.to_payload(),
        replay=True, certificates=certificates,
    )
    replay = _run_sharded_relational(out / "lean", shard_modules)
    theorem = str(replay.get("theorem") or "")
    acceptance = _read_json(out / "whole-program-acceptance.json")
    try:
        expected_theorem = selected_relational_acceptance_theorem(acceptance)
    except SchemaError:
        expected_theorem = None
    theorem_checked = (
        replay["status"] == "checked"
        and expected_theorem is not None
        and theorem == expected_theorem
    )
    finalized_proof_ir = _finalize_local_proof_ir(
        proof_ir,
        theorem_checked=theorem_checked,
        theorem=theorem,
    )
    assumption_obligations = [
        obligation for obligation in finalized_proof_ir["obligations"]
        if obligation["kind"] != "relational_region_equivalence"
        and obligation.get("status") != "proved"
    ]
    verdict = (
        "pass" if theorem_checked and not assumption_obligations
        else "incomplete"
    )
    return _write_relational_verdict(
        out,
        started_at,
        original_bin,
        candidate_bin,
        normalized,
        finalized_proof_ir,
        trusted_base,
        verdict,
        replay,
        certificates=certificates,
        blocker=(
            None if verdict == "pass"
            else "whole-program relational obligations remain open"
            if replay["status"] == "checked"
            else "independent LRAT replay did not check"
        ),
    )

def stage_a_prepare_relational(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
    out: Path,
) -> dict[str, Any]:
    return stage_a_prove_relational(
        original=original,
        candidate=candidate,
        relation_contract=relation_contract,
        out=out,
        _prepare_only=True,
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
    return stage_a_prove_relational(
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
        _analyze_only=True,
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
    return stage_a_prove_relational(
        original=original,
        candidate=candidate,
        relation_contract=relation_contract,
        out=out,
        original_extraction=original_extraction,
        candidate_extraction=candidate_extraction,
        normalized_behaviors=normalized_behaviors,
        region_facts=region_facts,
        _analyze_only=True,
        _proposal_only=True,
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
    _shards, prepared = _write_prepared_relational_graph(
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
        prepare_only=True,
    )
    if prepared is None:
        raise AssertionError("relational generation did not emit a prepared proof")
    validate_relational_analysis(out)
    return prepared

def stage_a_check_relational_proof(
    *, report: Path, out: Path | None = None
) -> dict[str, Any]:
    report = Path(report)
    verdict = _read_json(report / "verdict.json")
    report_format = verdict.get("format")
    if report_format != "stage-a-relational-nix-build-v1":
        raise StageAInputError(
            "stage_a_check_relational_proof accepts only "
            "stage-a-relational-nix-build-v1 reports; "
            f"got {report_format!r}"
        )

    from .build import _check_nix_relational_report

    return _check_nix_relational_report(report=report, verdict=verdict, out=out)


def _run_sharded_relational(lean_dir: Path, shard_modules: list[str]) -> dict[str, Any]:
    from .executor import (
        _compile_formal_kernel,
        _compile_relational_kernel,
        _failed_shard_hint_path,
        _relational_proof_jobs,
        _run_lean_relational,
        _run_lean_relational_cached,
    )

    started = time.monotonic()
    formal = _compile_formal_kernel(lean_dir)
    if formal.get("status") != "checked":
        formal["pipeline_elapsed_seconds"] = round(time.monotonic() - started, 3)
        return formal
    relational_kernel = _compile_relational_kernel(lean_dir)
    prerequisites: dict[str, dict[str, Any]] = {
        "relational_kernel": relational_kernel,
    }
    if relational_kernel.get("status") != "checked":
        return {
            **relational_kernel,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    segment_kernel = _run_lean_relational_cached(
        lean_dir, bundle="RelationalSegment"
    )
    prerequisites["relational_segment"] = segment_kernel
    if segment_kernel.get("status") != "checked":
        return {
            **segment_kernel,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    composition_kernel = _run_lean_relational_cached(
        lean_dir, bundle="RelationalComposition"
    )
    prerequisites["relational_composition"] = composition_kernel
    if composition_kernel.get("status") != "checked":
        return {
            **composition_kernel,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    environment_kernel = _run_lean_relational_cached(
        lean_dir, bundle="RelationalEnvironment"
    )
    prerequisites["relational_environment"] = environment_kernel
    if environment_kernel.get("status") != "checked":
        return {
            **environment_kernel,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    global_mapping = _run_lean_relational_cached(
        lean_dir, bundle="RelationalGlobalMappingContext"
    )
    prerequisites["global_mapping_context"] = global_mapping
    if global_mapping.get("status") != "checked":
        return {
            **global_mapping,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    jobs = min(len(shard_modules), _relational_proof_jobs())
    definition_modules = sorted(
        path.stem
        for path in (lean_dir / "StageA").glob("RelationalDefinitionsShard*.lean")
    )
    definition_results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(jobs, len(definition_modules) or 1)) as executor:
        futures = {
            executor.submit(
                _run_lean_relational_cached,
                lean_dir,
                bundle=module,
            ): module
            for module in definition_modules
        }
        for future in as_completed(futures):
            result = future.result()
            result["module"] = futures[future]
            definition_results.append(result)
            if result.get("status") != "checked":
                return {
                    **result,
                    "phase": "region_definitions",
                    "definition_results": definition_results,
                    "prerequisites": prerequisites,
                    "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
                }
    prerequisites["region_definitions"] = {
        "status": "checked",
        "modules": len(definition_results),
    }
    pe_attestation_jobs = {
        "original": lambda: _run_lean_relational_cached(
            lean_dir, bundle="RelationalProofOriginal"
        ),
        "candidate": lambda: _run_lean_relational_cached(
            lean_dir, bundle="RelationalProofCandidate"
        ),
    }
    with ThreadPoolExecutor(max_workers=len(pe_attestation_jobs)) as executor:
        futures = {
            executor.submit(run): name for name, run in pe_attestation_jobs.items()
        }
        for future in as_completed(futures):
            prerequisites[futures[future]] = future.result()
    failed_attestation = next(
        (
            prerequisites[name]
            for name in pe_attestation_jobs
            if prerequisites[name].get("status") != "checked"
        ),
        None,
    )
    if failed_attestation is not None:
        return {
            **failed_attestation,
            "phase": "pe_attestations",
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    machine_call_contracts = _run_lean_relational_cached(
        lean_dir, bundle="RelationalMachineImportCallContracts"
    )
    prerequisites["machine_import_call_contracts"] = machine_call_contracts
    if machine_call_contracts.get("status") != "checked":
        return {
            **machine_call_contracts,
            "phase": "machine_import_call_contracts",
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    base = _run_lean_relational_cached(lean_dir, bundle="RelationalProofBase")
    prerequisites["relational_proof_base"] = base
    if base.get("status") != "checked":
        return {
            **base,
            "phase": "relational_proof_base",
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    heavy_threshold = max(
        1,
        int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_HEAVY_SHARD_BYTES", "500000")),
    )
    heavy_jobs = min(
        jobs,
        max(1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_HEAVY_JOBS", "1"))),
    )
    source_sizes = {
        module: (lean_dir / "StageA" / f"{module}.lean").stat().st_size
        for module in shard_modules
    }
    static_context_shards = sorted(
        module for module in shard_modules
        if "import StageA.RelationalStaticContext" in
        (lean_dir / "StageA" / f"{module}.lean").read_text(encoding="utf-8")
    )
    pending_modules = sorted(
        set(shard_modules) - set(static_context_shards),
        key=lambda module: source_sizes[module], reverse=True,
    )
    failure_hint_path = _failed_shard_hint_path(lean_dir)
    prioritized_module: str | None = None
    if failure_hint_path is not None:
        try:
            hint = json.loads(failure_hint_path.read_text(encoding="utf-8"))
            hinted_module = hint.get("module")
        except (OSError, json.JSONDecodeError):
            hinted_module = None
        if hinted_module in pending_modules:
            pending_modules.remove(hinted_module)
            pending_modules.insert(0, hinted_module)
            prioritized_module = hinted_module
    cancellation = Event()
    results: list[dict[str, Any]] = []
    running_heavy = 0

    with ThreadPoolExecutor(max_workers=jobs) as executor:
        future_modules: dict[Any, str] = {}

        def submit_available() -> None:
            nonlocal running_heavy
            while pending_modules and len(future_modules) < jobs:
                selected = next(
                    (
                        index for index, module in enumerate(pending_modules)
                        if source_sizes[module] <= heavy_threshold or running_heavy < heavy_jobs
                    ),
                    None,
                )
                if selected is None:
                    return
                module = pending_modules.pop(selected)
                if source_sizes[module] > heavy_threshold:
                    running_heavy += 1
                future = executor.submit(
                    _run_lean_relational_cached,
                    lean_dir,
                    bundle=module,
                    cancel_event=cancellation,
                )
                future_modules[future] = module

        submit_available()
        while future_modules:
            completed, _ = wait(future_modules, return_when=FIRST_COMPLETED)
            for future in completed:
                module = future_modules.pop(future)
                if source_sizes[module] > heavy_threshold:
                    running_heavy -= 1
                result = future.result()
                result["module"] = module
                result["source_bytes"] = source_sizes[module]
                results.append(result)
                if result.get("status") != "checked":
                    cancellation.set()
                    if failure_hint_path is not None:
                        failure_hint_path.parent.mkdir(parents=True, exist_ok=True)
                        write_json(
                            failure_hint_path,
                            {
                                "format": "stage-a-relational-failed-shard-hint-v1",
                                "module": module,
                            },
                        )
                    for pending in future_modules:
                        pending.cancel()
                    result["completed_shards"] = len(results)
                    result["total_shards"] = len(shard_modules)
                    result["shard_results"] = results[:-1]
                    result["scheduler"] = {
                        "jobs": jobs,
                        "heavy_jobs": heavy_jobs,
                        "heavy_threshold_bytes": heavy_threshold,
                        "max_shard_source_bytes": max(source_sizes.values(), default=0),
                        "prerequisites": prerequisites,
                        "prioritized_failure_hint": prioritized_module,
                    }
                    result["pipeline_elapsed_seconds"] = round(time.monotonic() - started, 3)
                    return result
            submit_available()
    static_tree_kernel = _run_lean_relational_cached(
        lean_dir, bundle="RelationalStaticTree"
    )
    prerequisites["relational_static_tree"] = static_tree_kernel
    if static_tree_kernel.get("status") != "checked":
        return {
            **static_tree_kernel,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    static_context_base = _run_lean_relational_cached(
        lean_dir, bundle="RelationalStaticContextBase"
    )
    prerequisites["static_context_base"] = static_context_base
    if static_context_base.get("status") != "checked":
        return {
            **static_context_base,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    static_data_context = _run_lean_relational_cached(
        lean_dir, bundle="RelationalStaticDataContext"
    )
    prerequisites["static_data_context"] = static_data_context
    if static_data_context.get("status") != "checked":
        return {
            **static_data_context,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    static_map_modules = sorted(
        path.stem
        for path in (lean_dir / "StageA").glob(
            "RelationalStaticCodeMapChunk*.lean"
        )
    )
    static_map_results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(
        max_workers=min(jobs, len(static_map_modules) or 1)
    ) as executor:
        futures = {
            executor.submit(
                _run_lean_relational_cached, lean_dir, bundle=module
            ): module
            for module in static_map_modules
        }
        for future in as_completed(futures):
            result = future.result()
            result["module"] = futures[future]
            static_map_results.append(result)
            if result.get("status") != "checked":
                return {
                    **result,
                    "phase": "static_code_map_chunks",
                    "static_map_results": static_map_results,
                    "prerequisites": prerequisites,
                    "pipeline_elapsed_seconds": round(
                        time.monotonic() - started, 3
                    ),
                }
    prerequisites["static_code_map_chunks"] = {
        "status": "checked",
        "modules": len(static_map_results),
    }
    static_tree_modules: dict[int, list[str]] = {}
    for path in (lean_dir / "StageA").glob("RelationalStatic*Tree*Node*.lean"):
        match = re.search(r"Tree(\d+)Node\d+$", path.stem)
        if match is not None:
            static_tree_modules.setdefault(int(match.group(1)), []).append(path.stem)
    static_tree_results: list[dict[str, Any]] = []
    for level in sorted(static_tree_modules):
        level_modules = sorted(static_tree_modules[level])
        with ThreadPoolExecutor(
            max_workers=min(jobs, len(level_modules) or 1)
        ) as executor:
            futures = {
                executor.submit(
                    _run_lean_relational_cached, lean_dir, bundle=module
                ): module
                for module in level_modules
            }
            for future in as_completed(futures):
                result = future.result()
                result["module"] = futures[future]
                static_tree_results.append(result)
                if result.get("status") != "checked":
                    return {
                        **result,
                        "phase": "static_code_map_tree",
                        "static_tree_results": static_tree_results,
                        "prerequisites": prerequisites,
                        "pipeline_elapsed_seconds": round(
                            time.monotonic() - started, 3
                        ),
                    }
    prerequisites["static_code_map_tree"] = {
        "status": "checked",
        "modules": len(static_tree_results),
        "levels": len(static_tree_modules),
    }
    static_context = _run_lean_relational_cached(
        lean_dir, bundle="RelationalStaticContext"
    )
    prerequisites["static_context"] = static_context
    if static_context.get("status") != "checked":
        return {
            **static_context,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    deferred_results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(
        max_workers=min(jobs, len(static_context_shards) or 1)
    ) as executor:
        futures = {
            executor.submit(
                _run_lean_relational_cached, lean_dir, bundle=module
            ): module
            for module in static_context_shards
        }
        for future in as_completed(futures):
            result = future.result()
            module = futures[future]
            result["module"] = module
            result["source_bytes"] = source_sizes[module]
            deferred_results.append(result)
            results.append(result)
            if result.get("status") != "checked":
                return {
                    **result,
                    "phase": "static_context_shards",
                    "completed_shards": len(results),
                    "total_shards": len(shard_modules),
                    "shard_results": results[:-1],
                    "prerequisites": prerequisites,
                    "pipeline_elapsed_seconds": round(
                        time.monotonic() - started, 3
                    ),
                }
    prerequisites["static_context_shards"] = {
        "status": "checked",
        "modules": len(deferred_results),
    }
    product_graph_context = _run_lean_relational_cached(
        lean_dir, bundle="RelationalProductGraphContext"
    )
    prerequisites["product_graph_context"] = product_graph_context
    if product_graph_context.get("status") != "checked":
        return {
            **product_graph_context,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    reachable_product_local_evidence = _run_lean_relational_cached(
        lean_dir, bundle="RelationalReachableProductLocalEvidence"
    )
    prerequisites["reachable_product_local_evidence"] = (
        reachable_product_local_evidence
    )
    if reachable_product_local_evidence.get("status") != "checked":
        return {
            **reachable_product_local_evidence,
            "phase": "reachable_product_local_evidence",
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }

    def generated_modules(pattern: str | tuple[str, ...]) -> list[str]:
        def sort_key(module: str) -> tuple[int, str]:
            match = re.search(r"Chunk(\d+)$", module)
            return (int(match.group(1)) if match else -1, module)

        patterns = (pattern,) if isinstance(pattern, str) else pattern
        return sorted(
            {
                path.stem
                for item in patterns
                for path in (lean_dir / "StageA").glob(item)
            },
            key=sort_key,
        )

    def run_generated_phase(
        modules: list[str],
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        phase_results: list[dict[str, Any]] = []
        phase_cancellation = Event()
        with ThreadPoolExecutor(max_workers=jobs) as executor:
            phase_futures = {
                executor.submit(
                    _run_lean_relational_cached,
                    lean_dir,
                    bundle=module,
                    cancel_event=phase_cancellation,
                ): module
                for module in modules
            }
            for future in as_completed(phase_futures):
                module = phase_futures[future]
                result = future.result()
                result["module"] = module
                result["source_bytes"] = (
                    lean_dir / "StageA" / f"{module}.lean"
                ).stat().st_size
                phase_results.append(result)
                if result.get("status") != "checked":
                    phase_cancellation.set()
                    for pending in phase_futures:
                        pending.cancel()
                    return phase_results, result
        return phase_results, None

    region_chunk_modules = generated_modules("RelationalRegionChunk[0-9]*.lean")
    region_chunk_results, failed = run_generated_phase(region_chunk_modules)
    if failed is not None:
        return {
            **failed,
            "phase": "region_chunk_modules",
            "region_chunk_results": region_chunk_results[:-1],
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    prerequisites["region_chunk_modules"] = {
        "status": "checked",
        "modules": len(region_chunk_results),
    }
    region_chunks = _run_lean_relational_cached(
        lean_dir, bundle="RelationalRegionChunks"
    )
    prerequisites["region_chunks"] = region_chunks
    if region_chunks.get("status") != "checked":
        return {
            **region_chunks,
            "phase": "region_chunks",
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }

    phase_results: dict[str, list[dict[str, Any]]] = {}
    for phase, pattern in (
        ("exact_decode_chunks", "RelationalProof*DecodeChunk*.lean"),
        (
            "instruction_adequacy_chunks",
            "RelationalProof*InstructionAdequacyChunk*.lean",
        ),
        (
            "segment_refinement_chunks",
            (
                "RelationalSegmentRefinementChunk*.lean",
                "RelationalSegmentRefinementEdge*.lean",
            ),
        ),
        (
            "external_call_refinement_edges",
            "RelationalExternalCallRefinementEdge*.lean",
        ),
        ("product_graph_chunks", "RelationalProductGraphChunk*.lean"),
        ("import_register_seed_chunks", "RelationalImportRegisterSeedChunk*.lean"),
        (
            "dynamic_range_indirect_call_chunks",
            "RelationalDynamicRangeIndirectCallChunk*.lean",
        ),
        ("stack_separation_regions", "RelationalStackSeparationRegion*.lean"),
        ("product_decoded_control_chunks", "RelationalProductDecodedControlChunk*.lean"),
        ("product_reachability_chunks", "RelationalProductReachabilityChunk*.lean"),
        (
            "product_edge_refinement_chunks",
            "RelationalProductEdgeRefinementChunk*.lean",
        ),
        ("product_node_coverage_chunks", "RelationalProductNodeCoverageChunk*.lean"),
        (
            "reachable_product_node_chunks",
            "RelationalReachableProductNodeChunk*.lean",
        ),
        (
            "reachable_product_edge_chunks",
            "RelationalReachableProductEdgeChunk*.lean",
        ),
    ):
        modules = generated_modules(pattern)
        phase_results[phase], failed = run_generated_phase(modules)
        if failed is not None:
            return {
                **failed,
                "phase": phase,
                "completed_phase_modules": len(phase_results[phase]),
                "total_phase_modules": len(modules),
                "phase_results": phase_results,
                "shard_results": results,
                "prerequisites": prerequisites,
                "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
            }

    instruction_adequacy_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalInstructionAdequacyCertificate",
    )
    phase_results["instruction_adequacy_certificate"] = [
        instruction_adequacy_certificate
    ]
    if instruction_adequacy_certificate.get("status") != "checked":
        return {
            **instruction_adequacy_certificate,
            "phase": "instruction_adequacy_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }

    segment_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalSegmentRefinementCertificate",
    )
    phase_results["segment_refinement_certificate"] = [segment_certificate]
    if segment_certificate.get("status") != "checked":
        return {
            **segment_certificate,
            "phase": "segment_refinement_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    external_call_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalExternalCallRefinementCertificate",
    )
    phase_results["external_call_refinement_certificate"] = [
        external_call_certificate
    ]
    if external_call_certificate.get("status") != "checked":
        return {
            **external_call_certificate,
            "phase": "external_call_refinement_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    stack_separation_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalStackSeparationCertificate",
    )
    phase_results["stack_separation_certificate"] = [stack_separation_certificate]
    if stack_separation_certificate.get("status") != "checked":
        return {
            **stack_separation_certificate,
            "phase": "stack_separation_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    product_graph_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalProductGraphCertificate",
    )
    phase_results["product_graph_certificate"] = [product_graph_certificate]
    if product_graph_certificate.get("status") != "checked":
        return {
            **product_graph_certificate,
            "phase": "product_graph_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    import_register_seed_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalImportRegisterSeedCertificate",
    )
    phase_results["import_register_seed_certificate"] = [
        import_register_seed_certificate
    ]
    if import_register_seed_certificate.get("status") != "checked":
        return {
            **import_register_seed_certificate,
            "phase": "import_register_seed_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    dynamic_range_indirect_call_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalDynamicRangeIndirectCallCertificate",
    )
    phase_results["dynamic_range_indirect_call_certificate"] = [
        dynamic_range_indirect_call_certificate
    ]
    if dynamic_range_indirect_call_certificate.get("status") != "checked":
        return {
            **dynamic_range_indirect_call_certificate,
            "phase": "dynamic_range_indirect_call_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    product_decoded_control_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalProductDecodedControlCertificate",
    )
    phase_results["product_decoded_control_certificate"] = [
        product_decoded_control_certificate
    ]
    if product_decoded_control_certificate.get("status") != "checked":
        return {
            **product_decoded_control_certificate,
            "phase": "product_decoded_control_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    product_reachability_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalProductReachabilityCertificate",
    )
    phase_results["product_reachability_certificate"] = [
        product_reachability_certificate
    ]
    if product_reachability_certificate.get("status") != "checked":
        return {
            **product_reachability_certificate,
            "phase": "product_reachability_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    product_edge_refinement_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalProductEdgeRefinementCertificate",
    )
    phase_results["product_edge_refinement_certificate"] = [
        product_edge_refinement_certificate
    ]
    if product_edge_refinement_certificate.get("status") != "checked":
        return {
            **product_edge_refinement_certificate,
            "phase": "product_edge_refinement_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    product_node_coverage_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalProductNodeCoverageCertificate",
    )
    phase_results["product_node_coverage_certificate"] = [
        product_node_coverage_certificate
    ]
    if product_node_coverage_certificate.get("status") != "checked":
        return {
            **product_node_coverage_certificate,
            "phase": "product_node_coverage_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    reachable_product_node_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalReachableProductNodeCertificate",
    )
    phase_results["reachable_product_node_certificate"] = [
        reachable_product_node_certificate
    ]
    if reachable_product_node_certificate.get("status") != "checked":
        return {
            **reachable_product_node_certificate,
            "phase": "reachable_product_node_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    reachable_product_edge_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalReachableProductEdgeCertificate",
    )
    phase_results["reachable_product_edge_certificate"] = [
        reachable_product_edge_certificate
    ]
    if reachable_product_edge_certificate.get("status") != "checked":
        return {
            **reachable_product_edge_certificate,
            "phase": "reachable_product_edge_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    reachable_product_local_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalReachableProductLocalCertificate",
    )
    phase_results["reachable_product_local_certificate"] = [
        reachable_product_local_certificate
    ]
    if reachable_product_local_certificate.get("status") != "checked":
        return {
            **reachable_product_local_certificate,
            "phase": "reachable_product_local_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }

    closure_data_leaves = sorted(set(
        [
            "RelationalExternalCallSites",
            "RelationalProofRequiredInputsData",
            "RelationalProofPaddingData",
            "RelationalProofRegionInventoryData",
            "RelationalProofOriginalCoverageData",
            "RelationalProofCandidateCoverageData",
        ]
        + generated_modules("RelationalProofRegionIndexChunk*.lean")
        + generated_modules("RelationalProofStaticUsageLeaf*.lean")
    ))
    phase_results["structural_data_leaves"], failed = run_generated_phase(
        closure_data_leaves
    )
    if failed is not None:
        return {
            **failed,
            "phase": "structural_data_leaves",
            "completed_phase_modules": len(
                phase_results["structural_data_leaves"]
            ),
            "total_phase_modules": len(closure_data_leaves),
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    closure_data_aggregates = [
        "RelationalProofRegionIndexData",
        *generated_modules("RelationalProofStaticUsageChunk*.lean"),
    ]
    phase_results["structural_data_aggregates"], failed = run_generated_phase(
        closure_data_aggregates
    )
    if failed is not None:
        return {
            **failed,
            "phase": "structural_data_aggregates",
            "completed_phase_modules": len(
                phase_results["structural_data_aggregates"]
            ),
            "total_phase_modules": len(closure_data_aggregates),
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    static_usage_certificate = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalProofStaticUsageCertificate",
    )
    phase_results["structural_static_usage_certificate"] = [
        static_usage_certificate
    ]
    if static_usage_certificate.get("status") != "checked":
        return {
            **static_usage_certificate,
            "phase": "structural_static_usage_certificate",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    closure_data = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalProofClosureData",
    )
    phase_results["structural_data"] = [closure_data]
    if closure_data.get("status") != "checked":
        return {
            **closure_data,
            "phase": "structural_data",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }

    structural_fact_modules = sorted(set(
        generated_modules("RelationalProofStructuralRegionChunk*.lean")
        + generated_modules("RelationalProofStructuralPadding*Chunk*.lean")
        + generated_modules("RelationalProofStructuralCoverage*.lean")
        + ["RelationalProofStructuralIndependent"]
    ))
    phase_results["structural_facts"], failed = run_generated_phase(
        structural_fact_modules
    )
    if failed is not None:
        return {
            **failed,
            "phase": "structural_facts",
            "completed_phase_modules": len(phase_results["structural_facts"]),
            "total_phase_modules": len(structural_fact_modules),
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }

    structural_aggregates = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalProofStructuralAggregates",
    )
    phase_results["structural_aggregates"] = [structural_aggregates]
    if structural_aggregates.get("status") != "checked":
        return {
            **structural_aggregates,
            "phase": "structural_aggregates",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }

    closure = _run_lean_relational_cached(
        lean_dir,
        bundle="RelationalProofClosureBase",
    )
    phase_results["structural_closure"] = [closure]
    if closure.get("status") != "checked":
        return {
            **closure,
            "phase": "structural_closure",
            "phase_results": phase_results,
            "shard_results": results,
            "prerequisites": prerequisites,
            "pipeline_elapsed_seconds": round(time.monotonic() - started, 3),
        }

    acceptance_path = lean_dir.parent / "whole-program-acceptance.json"
    acceptance = (
        _read_json(acceptance_path) if acceptance_path.is_file() else {}
    )
    try:
        expected_theorem = selected_relational_acceptance_theorem(acceptance)
    except SchemaError:
        expected_theorem = None
    acceptance_ready = expected_theorem in RELATIONAL_ACCEPTANCE_THEOREMS
    final_bundle = "RelationalAcceptance" if acceptance_ready else "RelationalBundle"
    final = _run_lean_relational(lean_dir, bundle=final_bundle)
    if final.get("status") == "checked":
        final["theorem"] = (
            expected_theorem
            if acceptance_ready
            else "StageA.GeneratedRelational.candidateRelationalEvidenceBundle"
        )
    if final.get("status") == "checked" and failure_hint_path is not None:
        failure_hint_path.unlink(missing_ok=True)
    final["shards"] = len(shard_modules)
    final["shard_results"] = results
    final["phase_results"] = phase_results
    final["scheduler"] = {
        "jobs": jobs,
        "heavy_jobs": heavy_jobs,
        "heavy_threshold_bytes": heavy_threshold,
        "max_shard_source_bytes": max(source_sizes.values(), default=0),
        "total_shard_source_bytes": sum(source_sizes.values()),
        "prerequisites": prerequisites,
        "prioritized_failure_hint": prioritized_module,
    }
    final["pipeline_elapsed_seconds"] = round(time.monotonic() - started, 3)
    return final
