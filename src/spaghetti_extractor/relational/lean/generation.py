from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

from ...stage_binary import StageABinary, StageAInputError
from ...util import sha256_bytes, write_json
from ..analyses.external import _semantic_external_target_identity
from ..analyses.segments import _segment_refinement_candidates
from ..analyses.stack import _stack_window_transfer_claims
from ..artifacts import write_text_if_changed as _write_text_if_changed
from ..checked_artifacts import (
    CheckedArtifactIdentity,
    CheckedArtifactKind,
    checked_image_identity,
)
from ..contract import _raw_base_relocations
from ..model import _semantic_hash, _target_shaped_register_output_claims
from ..schema import (
    FLAG_BITS,
    RELATIONAL_ACCEPTANCE_THEOREM,
    RELATIONAL_KERNEL_MODULES,
)
from ..isa_requirements import isa_requirement_replay_projection


_LEAN_SOURCE_ROOT = Path(__file__).resolve().parents[2] / "lean" / "StageA"
from .common import (
    _lean_all_append_proof,
    _lean_byte_tree_definitions,
    _lean_direct_append_proof,
    _lean_import_certificate,
    _lean_index_tree,
    _lean_index_tree_join,
    _lean_padding_alias_certificate,
    _lean_pe,
    _lean_register_pair,
    _lean_relocations,
    _lean_right_append,
    _lean_sorted_span_certificate,
    _lean_span,
    _required_input_pairs,
    _required_input_pairs_from,
    _side_coverage_spans,
    _side_padding,
)
from .expressions import (
    _lean_machine_import_call_contract,
    _lean_region_bound_setup,
    _lean_region_flag_setup,
    _lean_region_index_masks,
    _lean_region_indexed_memory_fact_names,
    _lean_region_indexed_memory_lemma_specs,
    _lean_region_indexed_relocation_word_specs,
    _lean_region_memory_lemma_names,
    _lean_region_memory_lemmas,
    _lean_region_memory_setup,
    _lean_region_relocation_memory_setup,
    _lean_region_separation_setup,
    _lean_region_static_relocation_word_specs,
    _lean_state_invariant,
)
from .definitions import (
    _has_compositional_normalized_support,
    _lean_behavior_field,
    _lean_behavior_fields_memory_free,
    _lean_global_mapping_context_source,
    _lean_identical_state_only_writes_component,
    _lean_normalized_branch_parts,
    _lean_normalized_indirect_call_parts,
    _lean_normalized_static_outcome,
    _lean_region_definition,
    _lean_x87_state_only_pair,
    _normalized_behavior_fast_path,
    _normalized_behavior_structure_matches,
    _write_relational_static_context_modules,
)
from .segments import (
    _write_relational_external_call_refinement_modules,
    _write_relational_external_jump_refinement_modules,
    _write_relational_invariant_modules,
    _write_relational_memory_pullback_modules,
    _write_relational_register_relation_modules,
    _write_relational_segment_refinement_modules,
)
from .composition import (
    _write_reachable_product_local_certificate,
    _write_relational_product_graph_modules,
    _write_stack_separation_modules,
)
from .acceptance import (
    _write_relational_acceptance_modules,
)
from .affine_frames import (
    write_relational_affine_frame_profile_module,
    write_relational_affine_frame_semantic_modules,
)
from .common import (
    _lean_bool,
    _lean_bytes,
    _lean_code_aliases,
    _lean_register_relation_pair,
    _lean_relation_constructor,
    _sorted_span_certificate,
)


def _checked_region_semantic_identity(
    *,
    side: str,
    binary: StageABinary,
    region: Mapping[str, Any],
    behavior: Mapping[str, Any],
    machine_call_contracts: list[dict[str, Any]],
) -> CheckedArtifactIdentity:
    span = region[side]
    start = int(span["rva_start"])
    size = int(span["size"])
    data = bytes(binary.pe.get_data(start, size))
    if len(data) != size:
        raise StageAInputError(
            f"{side} checked semantic region 0x{start:x} is not file-backed"
        )
    normalized = {
        "behavior": behavior[side],
        "image_base": binary.image_base,
        "imports": _lean_import_certificate(binary),
        "semantic_ir": behavior[f"{side}_ir"],
        "machine_call_contracts": machine_call_contracts,
        "span": {"rva_start": start, "size": size},
    }
    return CheckedArtifactIdentity.create(
        kind=CheckedArtifactKind.REGION_SEMANTICS,
        semantic_key=f"pe32-region:{side}:{start:08x}:{size}",
        dependency_ids=(),
        relevant_input_sha256=sha256_bytes(data),
        normalized_data_sha256=sha256_bytes(
            json.dumps(
                normalized, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ),
    )


def _checked_region_binding_identity(
    *,
    side: str,
    binary: StageABinary,
    region: Mapping[str, Any],
    semantics: CheckedArtifactIdentity,
) -> CheckedArtifactIdentity:
    span = region[side]
    normalized = {
        "side": side,
        "span": {
            "rva_start": int(span["rva_start"]),
            "size": int(span["size"]),
        },
        "semantic_artifact_id": semantics.artifact_id,
    }
    image = checked_image_identity(side=side, binary_sha256=binary.sha256)
    return CheckedArtifactIdentity.create(
        kind=CheckedArtifactKind.REGION_DECODE,
        semantic_key=(
            f"pe32-region-binding:{side}:"
            f"{int(span['rva_start']):08x}:{int(span['size'])}"
        ),
        dependency_ids=(image.artifact_id, semantics.artifact_id),
        relevant_input_sha256=binary.sha256,
        normalized_data_sha256=sha256_bytes(
            json.dumps(
                normalized, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ),
    )


def _checked_semantic_pack_index(
    identity: CheckedArtifactIdentity, *, pack_count: int
) -> int:
    """Assign semantic artifacts without order-dependent pack reshuffling."""
    if pack_count < 1:
        raise StageAInputError("checked semantic pack count must be positive")
    semantic_digest = sha256_bytes(identity.semantic_key.encode("utf-8"))
    return int(semantic_digest[:16], 16) % pack_count


from .expressions import (
    _lean_acceptance_outcome,
    _lean_address_separation,
    _lean_bound_index_value,
    _lean_dynamic_range_argument_claim,
    _lean_dynamic_range_relation,
    _lean_external_target,
    _lean_immutable_indirect_jump_claim,
    _lean_import_register_seed_claim,
    _lean_machine_call_memory_footprint,
    _lean_machine_call_memory_size,
    _lean_masked_successor_tautology_proof,
    _lean_paired_stack_word_value_claim,
    _lean_paired_stack_word_write_claim,
    _lean_paired_stack_word_writes_claim,
    _lean_region_static_memory_lemma_specs,
    _lean_region_value_targets,
    _lean_register_argument_claim,
    _lean_register_offset_witness,
    _lean_register_offset_write,
    _lean_register_output_claim,
    _lean_return_slot_offset_pair,
    _lean_semantic_bool_expr,
    _lean_semantic_expr,
    _lean_semantic_x87_expr,
    _lean_stack_address_separation_claim,
    _lean_stack_window,
    _lean_stack_window_argument_claim,
    _lean_stack_window_transfer_claim,
    _lean_static_dynamic_pointer_slot,
    _lean_successor_tautology_proof,
    _lean_symbolic_x87_state,
    _lean_value_target,
    _semantic_masked_successor_shape,
    _semantic_successor_shape,
)
from .definitions import (
    _copy_relational_kernel_sources,
    _lean_bundle_source,
    _lean_counterexample_source,
    _lean_extraction_source,
    _lean_identical_state_only_write_registers,
    _lean_static_proof_context_base_source,
    _lean_static_range,
    _lean_targets_definition,
    _static_index_ranges,
)
from .segments import (
    _external_register_policy_replay_candidate,
)
from .acceptance import (
    _compact_acceptance_blockers,
    _lean_acceptance_empty_stack,
    _lean_acceptance_execution_edge,
    _lean_acceptance_running_node,
    _lean_acceptance_running_target,
    _lean_all_listed_proof,
    _lean_appended_list,
    _lean_appended_proof,
    _whole_program_acceptance_plan,
)


def _lean_region_instruction_adequacy_append_proof(
    *,
    pe: str,
    imports: str,
    candidate: bool,
    chunks: list[str],
    facts: list[str],
) -> str:
    if len(chunks) != len(facts) or not chunks:
        raise ValueError("instruction-adequacy chunks and facts must be non-empty")
    if len(chunks) == 1:
        return facts[0]
    candidate_literal = _lean_bool(candidate)
    return (
        f"allRegionInstructionAdequate_append {pe} {imports} "
        f"{candidate_literal} {chunks[0]} ({_lean_right_append(chunks[1:])}) "
        f"{facts[0]} ("
        + _lean_region_instruction_adequacy_append_proof(
            pe=pe,
            imports=imports,
            candidate=candidate,
            chunks=chunks[1:],
            facts=facts[1:],
        )
        + ")"
    )


def _lean_isa_requirement_replay_append_proof(
    *,
    pe: str,
    candidate: bool,
    region_chunks: list[str],
    requirement_chunks: list[str],
    facts: list[str],
) -> str:
    if (
        len(region_chunks) != len(requirement_chunks)
        or len(region_chunks) != len(facts)
        or not region_chunks
    ):
        raise ValueError("ISA replay chunks and facts must be non-empty and aligned")
    if len(region_chunks) == 1:
        return facts[0]
    candidate_literal = _lean_bool(candidate)
    return (
        f"allISARequirementRegionsReplay_append {pe} {candidate_literal} "
        f"{region_chunks[0]} ({_lean_right_append(region_chunks[1:])}) "
        f"{requirement_chunks[0]} "
        f"({_lean_right_append(requirement_chunks[1:])}) {facts[0]} ("
        + _lean_isa_requirement_replay_append_proof(
            pe=pe,
            candidate=candidate,
            region_chunks=region_chunks[1:],
            requirement_chunks=requirement_chunks[1:],
            facts=facts[1:],
        )
        + ")"
    )


def _write_relational_isa_requirement_replay_modules(
    lean_dir: Path,
    contract: Mapping[str, Any],
    isa_requirements: Mapping[str, Any],
    decode_chunk_regions: list[list[int]],
) -> list[str]:
    projection = isa_requirement_replay_projection(isa_requirements, contract)
    stage_a = lean_dir / "StageA"
    semantic_forms = {
        occurrence.form_id: occurrence.semantic_form
        for side in ("original", "candidate")
        for region in projection[side]
        for occurrence in region.occurrences
    }
    ordered_form_ids = sorted(semantic_forms)
    form_name_by_id = {
        form_id: f"isaRequirementSemanticForm{index}"
        for index, form_id in enumerate(ordered_form_ids)
    }
    form_definitions = "\n\n".join(
        f"def {form_name_by_id[form_id]} : InstructionSemanticForm :=\n"
        f"  {semantic_forms[form_id]}"
        for form_id in ordered_form_ids
    )
    forms_source = (
        "import StageA.RelationalISAQualification\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        + form_definitions
        + "\n\nend StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalISARequirementForms.lean", forms_source
    )

    generated_modules = ["RelationalISARequirementForms"]
    side_chunk_modules: dict[str, list[str]] = {
        "original": [],
        "candidate": [],
    }
    side_chunk_names: dict[str, list[str]] = {
        "original": [],
        "candidate": [],
    }
    side_chunk_theorems: dict[str, list[str]] = {
        "original": [],
        "candidate": [],
    }
    for side in ("original", "candidate"):
        module_side = side.capitalize()
        candidate_literal = _lean_bool(side == "candidate")
        projected_by_index = {
            region.region_index: region for region in projection[side]
        }
        for chunk_index, region_indices in enumerate(decode_chunk_regions):
            module = f"RelationalISARequirementReplay{module_side}Chunk{chunk_index}"
            chunk_name = f"{side}ISARequirementChunk{chunk_index}"
            chunk_theorem = f"{side}ISARequirementChunk{chunk_index}Replays"
            side_chunk_modules[side].append(module)
            side_chunk_names[side].append(chunk_name)
            side_chunk_theorems[side].append(chunk_theorem)
            definitions: list[str] = []
            theorem_names: list[str] = []
            requirement_names: list[str] = []
            for region_index in region_indices:
                projected = projected_by_index[region_index]
                requirement_name = f"{side}ISARequirementRegion{region_index}"
                theorem_name = f"{requirement_name}Replays"
                requirement_names.append(requirement_name)
                theorem_names.append(theorem_name)
                occurrence_literals = []
                for occurrence in projected.occurrences:
                    occurrence_literals.append(
                        "(⟨"
                        f"{occurrence.rva}, {occurrence.size}, "
                        f"{_lean_bytes(occurrence.encoded)}, "
                        f"{form_name_by_id[occurrence.form_id]}"
                        "⟩ : InstructionFormOccurrence)"
                    )
                definitions.append(
                    f"def {requirement_name} : ISARequirementRegion := {{\n"
                    f"  nodeId := {projected.target_id}\n"
                    "  occurrences := ["
                    + ", ".join(occurrence_literals)
                    + "]\n}"
                )
                definitions.append(
                    f"theorem {theorem_name} :\n"
                    f"    {requirement_name}.Replays {side}Pe "
                    f"{candidate_literal} region{region_index} := by\n"
                    "  unfold ISARequirementRegion.Replays\n"
                    "  decide"
                )
            definitions.append(
                f"def {chunk_name} : List ISARequirementRegion := ["
                + ", ".join(requirement_names)
                + "]"
            )
            chunk_goal = " ∧ ".join(
                [
                    f"{name}.Replays {side}Pe {candidate_literal} region{region_index}"
                    for name, region_index in zip(
                        requirement_names, region_indices, strict=True
                    )
                ]
                + ["True"]
            )
            chunk_proof = (
                "".join(f"And.intro {name} (" for name in theorem_names)
                + "True.intro"
                + ")" * len(theorem_names)
            )
            definitions.append(
                f"theorem {chunk_theorem} :\n"
                f"    AllISARequirementRegionsReplay {side}Pe "
                f"{candidate_literal} regionChunk{chunk_index} {chunk_name} := by\n"
                f"  change {chunk_goal}\n"
                f"  exact {chunk_proof}"
            )
            source = (
                "import StageA.RelationalISARequirementForms\n"
                f"import StageA.RelationalProof{module_side}\n"
                f"import StageA.RelationalRegionChunk{chunk_index}\n\n"
                "namespace StageA.GeneratedRelational\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
                + "\n\n".join(definitions)
                + "\n\nend StageA.GeneratedRelational\n"
            )
            _write_text_if_changed(stage_a / f"{module}.lean", source)
            generated_modules.append(module)

    aggregate_theorems: dict[str, str] = {}
    for side in ("original", "candidate"):
        aggregate_theorems[side] = _lean_isa_requirement_replay_append_proof(
            pe=f"{side}Pe",
            candidate=side == "candidate",
            region_chunks=[
                f"regionChunk{index}" for index in range(len(decode_chunk_regions))
            ],
            requirement_chunks=side_chunk_names[side],
            facts=side_chunk_theorems[side],
        )
    original_requirements = _lean_right_append(side_chunk_names["original"])
    candidate_requirements = _lean_right_append(side_chunk_names["candidate"])
    aggregate_source = (
        "import StageA.RelationalProofRegionInventoryData\n"
        + "".join(
            f"import StageA.{module}\n"
            for side in ("original", "candidate")
            for module in side_chunk_modules[side]
        )
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        f"def originalISARequirements : List ISARequirementRegion := "
        f"{original_requirements}\n\n"
        f"def candidateISARequirements : List ISARequirementRegion := "
        f"{candidate_requirements}\n\n"
        "theorem allOriginalISARequirementsReplay :\n"
        "    AllISARequirementRegionsReplay originalPe false allRegions "
        "originalISARequirements := by\n"
        "  unfold allRegions originalISARequirements\n"
        f"  exact {aggregate_theorems['original']}\n\n"
        "theorem allCandidateISARequirementsReplay :\n"
        "    AllISARequirementRegionsReplay candidatePe true allRegions "
        "candidateISARequirements := by\n"
        "  unfold allRegions candidateISARequirements\n"
        f"  exact {aggregate_theorems['candidate']}\n\n"
        "def isaRequirementReplayCertificate :\n"
        "    ISARequirementReplayCertificate originalPe candidatePe allRegions := {\n"
        "  originalRequirements := originalISARequirements\n"
        "  candidateRequirements := candidateISARequirements\n"
        "  originalReplayed := allOriginalISARequirementsReplay\n"
        "  candidateReplayed := allCandidateISARequirementsReplay\n"
        "}\n\n"
        "end StageA.GeneratedRelational\n"
    )
    aggregate_module = "RelationalISARequirementReplayCertificate"
    _write_text_if_changed(stage_a / f"{aggregate_module}.lean", aggregate_source)
    generated_modules.append(aggregate_module)
    return generated_modules


def _write_sharded_relational_proof(
    lean_dir: Path,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    original: bytes,
    candidate: bytes,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    *,
    invariant_synthesis: dict[str, Any],
    memory_contracts: dict[str, Any],
    register_relations: dict[str, Any],
    product_graph: dict[str, Any],
    runtime_frame_affine: dict[str, Any],
    import_register_seeds: list[dict[str, Any]],
    import_register_analysis: dict[str, Any],
    external_call_sites: dict[str, Any],
    segment_candidates: list[dict[str, Any]],
    isa_requirements: Mapping[str, Any],
    replay: bool,
    certificates: list[dict[str, Any]] | None = None,
) -> tuple[list[str], int]:
    certificate_by_region = {entry.get("region_id"): entry for entry in certificates or []}
    checked_region_artifacts: list[dict[str, Any]] = []
    x87_region_indices = {
        int(candidate["source_region_index"])
        for candidate in segment_candidates
        if str(candidate.get("certificate_profile", "")).startswith(
            "composable_x87_"
        )
    }
    legacy_full_image_regions = {
        side: x87_region_indices
        | {
            index
            for index, behavior in enumerate(behaviors)
            if any(
                marker in str(behavior[side])
                for marker in (
                    "X87Expr.imageLoad",
                    "X87Expr.load",
                    "X87Expr.store",
                )
            )
        }
        for side in ("original", "candidate")
    }
    standalone_fwait_regions = {
        side: {
            index
            for index in x87_region_indices
            if binary.pe.get_data(
                int(contract["regions"][index][side]["rva_start"]),
                int(contract["regions"][index][side]["size"]),
            )
            == b"\x9b"
        }
        for side, binary in (
            ("original", original_bin),
            ("candidate", candidate_bin),
        )
    }

    regions_literal = ", ".join(f"region{index}" for index in range(len(contract["regions"])))
    region_index_literal = _lean_index_tree(
        [f"region{index}" for index in range(len(contract["regions"]))]
    )
    required_inputs_literal = ", ".join(
        _lean_register_pair(pair) for pair in _required_input_pairs(contract["regions"])
    )
    original_padding_items = _side_padding(contract, "original")
    candidate_padding_items = _side_padding(contract, "candidate")
    original_padding = ", ".join(_lean_span(item) for item in original_padding_items)
    candidate_padding = ", ".join(_lean_span(item) for item in candidate_padding_items)
    original_coverage = _lean_sorted_span_certificate(
        _side_coverage_spans(contract, "original")
    )
    candidate_coverage = _lean_sorted_span_certificate(
        _side_coverage_spans(contract, "candidate")
    )
    original_alias_coverage = _lean_padding_alias_certificate(
        original_padding_items
    )
    candidate_alias_coverage = _lean_padding_alias_certificate(
        candidate_padding_items
    )
    machine_call_contract_rows = ", ".join(
        _lean_machine_import_call_contract(item)
        for item in contract.get("machine_import_call_contracts", [])
    )
    machine_call_contract_source = (
        "import StageA.RelationalDecode\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "def machineImportCallContracts : List MachineImportCallContract := "
        f"[{machine_call_contract_rows}]\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalMachineImportCallContracts.lean",
        machine_call_contract_source,
    )
    for side, binary, data in (
        ("original", original_bin, original),
        ("candidate", candidate_bin, candidate),
    ):
        module_side = side.capitalize()
        _write_text_if_changed(
            lean_dir / "StageA" / f"RelationalProof{module_side}Imports.lean",
            _lean_pe_import_source(side, binary),
        )
        _write_pe_side_modules(lean_dir, side, binary, data)
    base = (
        "import StageA.RelationalProofOriginal\n"
        "import StageA.RelationalProofCandidate\n"
        "import StageA.RelationalMachineImportCallContracts\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal\n\nset_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(lean_dir / "StageA" / "RelationalProofBase.lean", base)
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalGlobalMappingContext.lean",
        _lean_global_mapping_context_source(contract),
    )
    static_map_modules = _write_relational_static_context_modules(
        lean_dir,
        contract,
        original_entrypoint_rva=original_bin.entrypoint_rva,
        candidate_entrypoint_rva=candidate_bin.entrypoint_rva,
    )

    shard_size = max(1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PROOF_SHARD", "4")))
    shard_byte_target = max(
        1,
        int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PROOF_SHARD_BYTES", "49152")),
    )
    estimated_region_bytes: list[int] = []
    for index, region in enumerate(contract["regions"]):
        estimated_region_bytes.append(
            len(behaviors[index]["original"])
            + len(behaviors[index]["candidate"])
            + len(_lean_region_definition(index, region))
            + len(_lean_region_memory_lemmas(index, region, behaviors[index]))
            + 16_384
        )
    shard_groups = _partition_proof_shards(
        estimated_region_bytes,
        max_regions=shard_size,
        target_bytes=shard_byte_target,
    )

    definition_modules: list[str] = []
    shard_modules: list[str] = []
    for shard_index, indices in enumerate(shard_groups):
        definition_module = f"RelationalDefinitionsShard{shard_index}"
        definition_modules.append(definition_module)
        module = f"RelationalProofShard{shard_index}"
        shard_modules.append(module)
        definitions = []
        theorems = []
        for index in indices:
            definitions.append(_lean_region_definition(index, contract["regions"][index]))
            definitions.append(
                _lean_region_memory_lemmas(
                    index, contract["regions"][index], behaviors[index]
                )
            )
            definitions.append(f"def originalBehavior{index} : SymbolicBehavior := {behaviors[index]['original']}")
            definitions.append(f"def candidateBehavior{index} : SymbolicBehavior := {behaviors[index]['candidate']}")
            outcome_condition_support = _lean_outcome_condition_support_source(
                index, contract["regions"][index], behaviors[index]
            )
            if outcome_condition_support:
                definitions.append(outcome_condition_support)
            normalized_support = (
                _lean_compositional_normalized_support_source(
                    index, contract["regions"][index], behaviors[index]
                )
                if _has_compositional_normalized_support(
                    contract["regions"][index], behaviors[index]
                ) else ""
            )
            if normalized_support:
                definitions.append(normalized_support)
            theorems.append(_lean_region_theorem_source(
                index,
                contract["regions"][index],
                behaviors[index],
                original_image_base=original_bin.image_base,
                candidate_image_base=candidate_bin.image_base,
                replay=replay,
                certificate=certificate_by_region.get(contract["regions"][index]["id"]),
            ))
        definition_source = (
            "import StageA.Relational\n\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\nset_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(
            lean_dir / "StageA" / f"{definition_module}.lean", definition_source
        )
        proof_source = (
            f"import StageA.{definition_module}\n\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\nset_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n\n"
            + "\n\n".join(theorems)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", proof_source)

    stack_separation_modules = _write_stack_separation_modules(
        lean_dir, contract, definition_modules, shard_groups
    )
    invariant_modules = _write_relational_invariant_modules(
        lean_dir,
        contract,
        invariant_synthesis,
        definition_modules,
        shard_groups,
    )

    decode_chunk_count = min(
        len(shard_groups),
        max(1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_DECODE_CHUNKS", "64"))),
    )
    shards_per_decode_chunk = (
        len(shard_groups) + decode_chunk_count - 1
    ) // decode_chunk_count
    decode_chunk_regions: list[list[int]] = []
    decode_chunk_shards: list[list[int]] = []
    for chunk_index, shard_offset in enumerate(
        range(0, len(shard_groups), shards_per_decode_chunk)
    ):
        selected_shard_indices = list(range(
            shard_offset,
            min(len(shard_groups), shard_offset + shards_per_decode_chunk),
        ))
        selected_region_indices = [
            region_index
            for shard_index in selected_shard_indices
            for region_index in shard_groups[shard_index]
        ]
        decode_chunk_shards.append(selected_shard_indices)
        decode_chunk_regions.append(selected_region_indices)

    semantic_pack_count = max(
        1,
        int(
            os.environ.get(
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_SEMANTIC_PACKS",
                "64",
            )
        ),
    )
    semantic_entries: dict[tuple[str, int], dict[str, Any]] = {}
    semantic_pack_declarations: dict[
        tuple[str, int], list[tuple[str, tuple[str, ...]]]
    ] = {}
    for side, binary in (
        ("original", original_bin),
        ("candidate", candidate_bin),
    ):
        module_side = side.capitalize()
        for index, region in enumerate(contract["regions"]):
            if index in standalone_fwait_regions[side]:
                continue
            identity = _checked_region_semantic_identity(
                side=side,
                binary=binary,
                region=region,
                behavior=behaviors[index],
                machine_call_contracts=contract.get(
                    "machine_import_call_contracts", []
                ),
            )
            entry: dict[str, Any] = {"identity": identity}
            semantic_entries[(side, index)] = entry
            if index in legacy_full_image_regions[side]:
                continue

            pack_index = _checked_semantic_pack_index(
                identity, pack_count=semantic_pack_count
            )
            pack_suffix = f"{pack_index:02x}"
            semantic_module = (
                f"RelationalProof{module_side}SemanticPack{pack_suffix}"
            )
            contracts_name = (
                f"{side}MachineImportCallContractsPack{pack_suffix}"
            )
            stable_suffix = sha256_bytes(identity.semantic_key.encode("utf-8"))
            expected_name = f"{side}RegionSemantic{stable_suffix}Expected"
            input_name = f"{side}RegionSemantic{stable_suffix}Input"
            replay_name = f"{side}RegionSemantic{stable_suffix}ReplayChecked"
            semantic_name = f"{side}RegionSemantic{stable_suffix}Checked"
            span = region[side]
            start = int(span["rva_start"])
            size = int(span["size"])
            region_bytes = bytes(binary.pe.get_data(start, size))
            binding_identity = _checked_region_binding_identity(
                side=side,
                binary=binary,
                region=region,
                semantics=identity,
            )
            declarations = (
                f"def {expected_name} : SymbolicBehavior := "
                f"{behaviors[index][side]}",
                f"def {input_name} : RegionSemanticInput := {{\n"
                f"  imageBase := {binary.image_base}\n"
                f"  span := {_lean_span(span)}\n"
                f"  bytes := {_lean_bytes(region_bytes)}\n"
                "}",
                f"theorem {replay_name} :\n"
                f"    {input_name}.evaluate {side}Imports "
                f"{contracts_name} = some {expected_name} := by\n"
                "  decide",
                f"def {semantic_name} :\n"
                f"    CheckedLocalRegionSemantics {input_name} "
                f"{side}Imports {contracts_name} :=\n"
                "  CheckedLocalRegionSemantics.ofReplay "
                f"{input_name} {side}Imports {contracts_name}\n"
                f"    {{ value := \"{identity.artifact_id}\" }} "
                f"{expected_name} {replay_name}",
                f"theorem {semantic_name}EffectsExact :\n"
                f"    {semantic_name}.effects =\n"
                "      TransitionEffects.ofBehavior "
                f"{semantic_name}.behavior :=\n"
                f"  {semantic_name}.effectsExact",
            )
            semantic_pack_declarations.setdefault(
                (side, pack_index), []
            ).append((identity.semantic_key, declarations))
            entry.update({
                "binding_identity": binding_identity,
                "contracts_name": contracts_name,
                "input_name": input_name,
                "module": semantic_module,
                "replay_name": replay_name,
                "semantic_name": semantic_name,
            })

    for (side, pack_index), packed in sorted(
        semantic_pack_declarations.items()
    ):
        module_side = side.capitalize()
        pack_suffix = f"{pack_index:02x}"
        semantic_module = (
            f"RelationalProof{module_side}SemanticPack{pack_suffix}"
        )
        contracts_name = f"{side}MachineImportCallContractsPack{pack_suffix}"
        semantic_source = (
            f"import StageA.RelationalProof{module_side}Imports\n"
            "import StageA.RelationalMachineImportCallContracts\n"
            "import StageA.RelationalCheckedArtifacts\n"
            + "\n\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n"
            "open StageA.Relational.CheckedArtifacts\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n\n"
            f"def {contracts_name} : List MachineImportCallContract := "
            "machineImportCallContracts\n\n"
            + "\n\n".join(
                declaration
                for _, declarations in sorted(packed)
                for declaration in declarations
            )
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(
            lean_dir / "StageA" / f"{semantic_module}.lean",
            semantic_source,
        )

    for chunk_index, selected_region_indices in enumerate(decode_chunk_regions):
        selected_shard_indices = decode_chunk_shards[chunk_index]
        definition_imports = "\n".join(
            f"import StageA.{definition_modules[shard_index]}"
            for shard_index in selected_shard_indices
        )
        for side in ("original", "candidate"):
            module_side = side.capitalize()
            module = f"RelationalProof{module_side}DecodeChunk{chunk_index}"
            binding_declarations: list[str] = []
            semantic_imports: set[str] = set()
            for index in selected_region_indices:
                if index in standalone_fwait_regions[side]:
                    continue
                entry = semantic_entries[(side, index)]
                identity = entry["identity"]
                theorem = f"{side}Behavior{index}CheckedDecoded"
                artifact_row: dict[str, Any] = {
                    "identity": identity.payload(),
                    "side": side,
                    "region_index": index,
                    "region_id": contract["regions"][index]["id"],
                    "span": dict(contract["regions"][index][side]),
                    "decoded_theorem": theorem,
                }
                if index not in legacy_full_image_regions[side]:
                    semantic_module = entry["module"]
                    semantic_imports.add(semantic_module)
                    contracts_name = entry["contracts_name"]
                    semantic_name = entry["semantic_name"]
                    replay_name = entry["replay_name"]
                    binding_name = f"{side}Region{index}ImageBinding"
                    binding_identity = entry["binding_identity"]
                    binding_declarations.extend((
                        f"def {binding_name} :\n"
                        f"    CheckedRegionImageBinding {side}Pe {side}Imports "
                        f"{contracts_name} {semantic_name} := {{\n"
                        f"  artifactId := {{ value := "
                        f"\"{binding_identity.artifact_id}\" }}\n"
                        "  spanBytesExact := by decide\n"
                        "  imageBaseExact := rfl\n"
                        "  imageContextIndependent := by decide\n"
                        "}",
                        f"theorem {theorem} : "
                        f"regionBehaviorWithMachineCallContracts {side}Pe "
                        f"{side}Imports machineImportCallContracts "
                        f"region{index}.{side} = "
                        f"some {side}Behavior{index} := by\n"
                        f"  simpa [{contracts_name}] using "
                        f"{binding_name}.behavior_exact",
                    ))
                    artifact_row.update({
                        "binding_identity": binding_identity.payload(),
                        "binding_module": module,
                        "image_binding_definition": binding_name,
                        "legacy_full_image_replay": False,
                        "module": semantic_module,
                        "semantic_replay_theorem": replay_name,
                        "semantic_definition": semantic_name,
                    })
                else:
                    semantic_name = f"{side}Region{index}CheckedSemantics"
                    binding_declarations.extend((
                        f"theorem {theorem} : "
                        f"regionBehaviorWithMachineCallContracts {side}Pe "
                        f"{side}Imports machineImportCallContracts "
                        f"region{index}.{side} = "
                        f"some {side}Behavior{index} := by decide",
                        f"def {semantic_name} :\n"
                        "    CheckedContractedRegionSemantics "
                        f"{side}Pe {side}Imports machineImportCallContracts :=\n"
                        "  CheckedContractedRegionSemantics.ofDecoded "
                        f"{side}Pe {side}Imports machineImportCallContracts\n"
                        f"    {{ value := \"{identity.artifact_id}\" }} "
                        f"region{index}.{side} {side}Behavior{index}\n"
                        f"    {theorem}",
                        f"theorem {semantic_name}EffectsExact :\n"
                        f"    {semantic_name}.effects =\n"
                        "      TransitionEffects.ofBehavior "
                        f"{semantic_name}.behavior :=\n"
                        f"  {semantic_name}.effectsExact",
                    ))
                    artifact_row.update({
                        "legacy_full_image_replay": True,
                        "module": module,
                        "semantic_definition": semantic_name,
                    })
                checked_region_artifacts.append(artifact_row)

            binding_source = (
                f"import StageA.RelationalProof{module_side}Image\n"
                + "".join(
                    f"import StageA.{semantic_module}\n"
                    for semantic_module in sorted(semantic_imports)
                )
                + "import StageA.RelationalMachineImportCallContracts\n"
                + definition_imports
                + "\n\nnamespace StageA.GeneratedRelational\n\n"
                "open StageA.Formal StageA.Relational\n"
                "open StageA.Relational.CheckedArtifacts\n\n"
                "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
                "set_option linter.unusedSimpArgs false\n\n"
                + "\n\n".join(binding_declarations)
                + "\n\nend StageA.GeneratedRelational\n"
            )
            _write_text_if_changed(
                lean_dir / "StageA" / f"{module}.lean",
                binding_source,
            )

    region_chunk_names = [
        f"regionChunk{index}" for index in range(len(decode_chunk_regions))
    ]
    region_chunk_modules: list[str] = []
    for chunk_index, (name, indices) in enumerate(zip(
        region_chunk_names, decode_chunk_regions, strict=True
    )):
        module = f"RelationalRegionChunk{chunk_index}"
        region_chunk_modules.append(module)
        source = (
            "\n".join(
                f"import StageA.{definition_modules[shard_index]}"
                for shard_index in decode_chunk_shards[chunk_index]
            )
            + "\n\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            f"def {name} : List RegionRelation := ["
            + ", ".join(f"region{index}" for index in indices)
            + "]\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(
            lean_dir / "StageA" / f"{module}.lean", source
        )
    region_chunks_source = (
        "\n".join(f"import StageA.{module}" for module in region_chunk_modules)
        + "\n\nnamespace StageA.GeneratedRelational\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalRegionChunks.lean", region_chunks_source
    )

    _write_relational_isa_requirement_replay_modules(
        lean_dir,
        contract,
        isa_requirements,
        decode_chunk_regions,
    )

    instruction_adequacy_modules: dict[str, list[str]] = {
        "original": [],
        "candidate": [],
    }
    instruction_adequacy_theorems: dict[str, list[str]] = {
        "original": [],
        "candidate": [],
    }
    for side in ("original", "candidate"):
        module_side = side.capitalize()
        candidate = side == "candidate"
        candidate_literal = _lean_bool(candidate)
        for chunk_index, region_indices in enumerate(decode_chunk_regions):
            module = (
                f"RelationalProof{module_side}InstructionAdequacyChunk{chunk_index}"
            )
            chunk_theorem = f"{side}InstructionAdequacyChunk{chunk_index}Checked"
            instruction_adequacy_modules[side].append(module)
            instruction_adequacy_theorems[side].append(chunk_theorem)
            region_theorems = "\n\n".join(
                f"theorem {side}Region{index}InstructionAdequate :\n"
                f"    RegionInstructionAdequateWithX87 {side}Pe {side}Imports "
                f"region{index}.{side} :=\n"
                f"  regionInstructionAdequateWithX87_of_checked {side}Pe {side}Imports "
                f"region{index}.{side} (by decide)"
                for index in region_indices
            )
            chunk_goal = " ∧ ".join(
                [
                    f"RegionInstructionAdequateWithX87 {side}Pe {side}Imports "
                    f"region{index}.{side}"
                    for index in region_indices
                ]
                + ["True"]
            )
            chunk_proof = (
                "".join(
                    f"And.intro {side}Region{index}InstructionAdequate ("
                    for index in region_indices
                )
                + "True.intro"
                + ")" * len(region_indices)
            )
            source = (
                "import StageA.RelationalPEExecution\n"
                f"import StageA.RelationalProof{module_side}\n"
                f"import StageA.RelationalRegionChunk{chunk_index}\n\n"
                "namespace StageA.GeneratedRelational\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
                + region_theorems
                + f"\n\ntheorem {chunk_theorem} :\n"
                f"    AllRegionInstructionAdequate {side}Pe {side}Imports "
                f"{candidate_literal} regionChunk{chunk_index} := by\n"
                f"  change {chunk_goal}\n"
                f"  exact {chunk_proof}\n\n"
                "end StageA.GeneratedRelational\n"
            )
            _write_text_if_changed(
                lean_dir / "StageA" / f"{module}.lean",
                source,
            )

    original_instruction_adequacy_proof = (
        _lean_region_instruction_adequacy_append_proof(
            pe="originalPe",
            imports="originalImports",
            candidate=False,
            chunks=region_chunk_names,
            facts=instruction_adequacy_theorems["original"],
        )
    )
    candidate_instruction_adequacy_proof = (
        _lean_region_instruction_adequacy_append_proof(
            pe="candidatePe",
            imports="candidateImports",
            candidate=True,
            chunks=region_chunk_names,
            facts=instruction_adequacy_theorems["candidate"],
        )
    )
    instruction_adequacy_source = (
        "import StageA.RelationalPEExecution\n"
        + "".join(
            f"import StageA.{module}\n"
            for side in ("original", "candidate")
            for module in instruction_adequacy_modules[side]
        )
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "theorem allOriginalRegionsInstructionAdequate :\n"
        "    AllRegionInstructionAdequate originalPe originalImports false "
        f"({_lean_right_append(region_chunk_names)}) := by\n"
        f"  exact {original_instruction_adequacy_proof}\n\n"
        "theorem allCandidateRegionsInstructionAdequate :\n"
        "    AllRegionInstructionAdequate candidatePe candidateImports true "
        f"({_lean_right_append(region_chunk_names)}) := by\n"
        f"  exact {candidate_instruction_adequacy_proof}\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalInstructionAdequacyCertificate.lean",
        instruction_adequacy_source,
    )

    external_site_candidates = external_call_sites["candidates"]
    external_site_region_chunks = sorted({
        chunk_by_region
        for site in external_site_candidates
        for chunk_by_region in (
            next(
                index for index, region_indices in enumerate(decode_chunk_regions)
                if int(site["source_region_index"]) in region_indices
            ),
            next(
                index for index, region_indices in enumerate(decode_chunk_regions)
                if int(site["target_region_index"]) in region_indices
            ),
        )
    })
    external_site_definitions = "\n\n".join(
        (
            f"def externalCallSite{int(site['id'])} : ExternalCallSiteContract := {{\n"
            + f"  id := {int(site['id'])}\n"
            + f"  sourceTargetId := {int(site['source_target_id'])}\n"
            + f"  continuationTargetId := {int(site['continuation_target_id'])}\n"
            + f"  machineContractId := {int(site['machine_contract_id'])}\n"
            + "  boundaryInvariant := "
            + f"{_lean_state_invariant(site['boundary_invariant'])}\n"
            + "  targetInvariant := "
            + (
                "{ region"
                f"{int(site['target_region_index'])}.inputInvariant with "
                "importRegisterRelations := [] }\n"
                if site.get("site_kind") == "direct_import_thunk"
                else f"region{int(site['target_region_index'])}.inputInvariant\n"
            )
            + "}"
        )
        for site in external_site_candidates
    )
    external_site_names = [
        f"externalCallSite{int(site['id'])}" for site in external_site_candidates
    ]
    external_site_source = (
        "import StageA.RelationalEnvironment\n"
        "import StageA.RelationalStaticContextBase\n"
        + "".join(
            f"import StageA.RelationalRegionChunk{chunk_index}\n"
            for chunk_index in external_site_region_chunks
        )
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        + external_site_definitions
        + ("\n\n" if external_site_definitions else "")
        + "def externalCallSites : List ExternalCallSiteContract := ["
        + ", ".join(external_site_names)
        + "]\n\n"
        "theorem externalCallSitesStructurallyValid :\n"
        "    externalCallSiteIdsUnique externalCallSites = true ∧\n"
        "      externalCallSites.all "
        "(ExternalCallSiteContract.staticValid staticProofContext) = true := by\n"
        "  decide\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalExternalCallSites.lean",
        external_site_source,
    )

    memory_pullback_modules = _write_relational_memory_pullback_modules(
        lean_dir,
        contract,
        memory_contracts,
        definition_modules,
        shard_groups,
        decode_chunk_regions,
        original_image_base=original_bin.image_base,
        candidate_image_base=candidate_bin.image_base,
    )
    register_relation_modules = _write_relational_register_relation_modules(
        lean_dir,
        contract,
        register_relations,
        definition_modules,
        shard_groups,
        decode_chunk_regions,
        original_image_base=original_bin.image_base,
        candidate_image_base=candidate_bin.image_base,
    )

    direct_modules: list[str] = []
    for chunk_index, region_indices in enumerate(decode_chunk_regions):
        direct_region_indices = [
            index for index in region_indices if index not in x87_region_indices
        ]
        direct_module = f"RelationalProofDirectChunk{chunk_index}"
        direct_modules.append(direct_module)
        direct_region_chunk = f"strictDirectRegionChunk{chunk_index}"
        direct_theorems = "\n\n".join(
            f"theorem region{index}CheckedDirect : regionEquivalentWithImports originalPe candidatePe "
            f"originalImports candidateImports machineImportCallContracts region{index} :=\n"
            f"  regionEquivalentWithImports_of_decoded originalPe candidatePe originalImports candidateImports machineImportCallContracts "
            f"region{index} originalBehavior{index} candidateBehavior{index}\n"
            f"    originalBehavior{index}CheckedDecoded candidateBehavior{index}CheckedDecoded "
            f"region{index}CheckedDirectBehavior"
            for index in direct_region_indices
        )
        direct_chunk_goal = " ∧ ".join(
            [
                f"regionEquivalentWithImports originalPe candidatePe originalImports candidateImports machineImportCallContracts region{index}"
                for index in direct_region_indices
            ]
            + ["True"]
        )
        direct_chunk_proof = (
            "".join(
                f"And.intro region{index}CheckedDirect ("
                for index in direct_region_indices
            )
            + "True.intro"
            + ")" * len(direct_region_indices)
        )
        direct_source = (
            "import StageA.RelationalImage\n"
            f"import StageA.RelationalProofOriginalDecodeChunk{chunk_index}\n"
            f"import StageA.RelationalProofCandidateDecodeChunk{chunk_index}\n\n"
            f"import StageA.RelationalRegionChunk{chunk_index}\n"
            + "\n".join(
                f"import StageA.{shard_modules[shard_index]}"
                for shard_index in decode_chunk_shards[chunk_index]
            )
            + "\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n\n"
            f"def {direct_region_chunk} : List RegionRelation := ["
            + ", ".join(f"region{index}" for index in direct_region_indices)
            + "]\n\n"
            + direct_theorems
            + f"\n\ntheorem directRegionChunk{chunk_index}Checked :\n"
            f"    allDirectRegionGoals originalPe candidatePe originalImports candidateImports machineImportCallContracts {direct_region_chunk} := by\n"
            f"  change {direct_chunk_goal}\n"
            f"  exact {direct_chunk_proof}"
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(
            lean_dir / "StageA" / f"{direct_module}.lean",
            direct_source,
        )

    deferred_guard_segment_candidates = [
        candidate
        for candidate in _segment_refinement_candidates(
            contract,
            behaviors,
            memory_contracts,
            register_relations,
            import_register_seeds,
            original_bin=original_bin,
            candidate_bin=candidate_bin,
            allow_deferred_guards=True,
        )
        if candidate.get("certificate_profile")
            == "composable_local_no_write_deferred_guard_v1"
    ]
    segment_refinement_modules = _write_relational_segment_refinement_modules(
        lean_dir,
        contract,
        behaviors,
        memory_contracts,
        register_relations,
        product_graph,
        decode_chunk_regions,
        import_register_seeds,
        segment_candidates,
        deferred_guard_candidates=deferred_guard_segment_candidates,
    )
    product_graph_modules = _write_relational_product_graph_modules(
        lean_dir,
        product_graph,
        segment_candidates,
        segment_refinement_modules,
        decode_chunk_regions,
        contract=contract,
    )
    write_relational_affine_frame_profile_module(
        lean_dir, runtime_frame_affine
    )
    write_relational_affine_frame_semantic_modules(
        lean_dir,
        runtime_frame_affine,
        contract=contract,
        product_graph=product_graph,
        decode_chunk_regions=decode_chunk_regions,
        physical_state_only_region_indices=(
            standalone_fwait_regions["original"] |
            standalone_fwait_regions["candidate"]
        ),
    )
    external_call_refinement_modules = (
        _write_relational_external_call_refinement_modules(
            lean_dir,
            contract,
            behaviors,
            register_relations,
            product_graph,
            decode_chunk_regions,
            external_call_sites,
        )
    )
    _write_relational_external_jump_refinement_modules(
        lean_dir,
        contract,
        behaviors,
        register_relations,
        decode_chunk_regions,
        external_call_sites,
    )
    _write_reachable_product_local_certificate(
        lean_dir,
        product_graph,
        segment_candidates,
        external_call_refinement_modules,
    )

    required_input_states: list[list[dict[str, str]]] = [[]]
    for indices in decode_chunk_regions:
        required_input_states.append(
            _required_input_pairs_from(
                required_input_states[-1],
                [contract["regions"][index] for index in indices],
            )
        )
    required_state_definitions = "\n\n".join(
        f"def requiredInputsState{index} : List RegisterPair := ["
        + ", ".join(_lean_register_pair(pair) for pair in state)
        + "]"
        for index, state in enumerate(required_input_states)
    )
    padding_chunk_size = max(
        1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PADDING_CHUNK", "128"))
    )
    padding_groups = {
        "original": [
            original_padding_items[offset : offset + padding_chunk_size]
            for offset in range(0, len(original_padding_items), padding_chunk_size)
        ] or [[]],
        "candidate": [
            candidate_padding_items[offset : offset + padding_chunk_size]
            for offset in range(0, len(candidate_padding_items), padding_chunk_size)
        ] or [[]],
    }
    padding_chunk_names = {
        side: [f"{side}PaddingChunk{index}" for index in range(len(groups))]
        for side, groups in padding_groups.items()
    }
    padding_definitions = "\n\n".join(
        f"def {name} : List Span := ["
        + ", ".join(_lean_span(span) for span in group)
        + "]"
        for side in ("original", "candidate")
        for name, group in zip(
            padding_chunk_names[side], padding_groups[side], strict=True
        )
    )
    data_usage_regions: list[int] = []
    for target in contract.get("value_targets", []):
        region_index = next((
            index for index, region in enumerate(contract["regions"])
            if target in region.get("values", [])
        ), None)
        if region_index is None:
            raise StageAInputError(
                f"global data target {target['id']} has no region usage witness"
            )
        data_usage_regions.append(region_index)
    def write_closure_data_module(
        module: str,
        imports: list[str],
        body: str,
    ) -> None:
        source = (
            "".join(f"import StageA.{item}\n" for item in imports)
            + "\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n\n"
            + body
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)

    write_closure_data_module(
        "RelationalProofRequiredInputsData",
        ["Relational"],
        required_state_definitions
        + "\n\n"
        + f"def requiredInputsCertificate : List RegisterPair := "
        f"requiredInputsState{len(region_chunk_names)}",
    )
    write_closure_data_module(
        "RelationalProofPaddingData",
        ["RelationalStaticContext"],
        padding_definitions
        + "\n\n"
        + f"def originalPadding : List Span := "
        f"{_lean_right_append(padding_chunk_names['original'])}\n\n"
        + f"def candidatePadding : List Span := "
        f"{_lean_right_append(padding_chunk_names['candidate'])}",
    )

    region_index_chunk_names: list[str] = []
    region_index_chunks: list[tuple[str, int]] = []
    for chunk_index, region_indices in enumerate(decode_chunk_regions):
        module = f"RelationalProofRegionIndexChunk{chunk_index}"
        name = f"regionIndexChunk{chunk_index}"
        region_index_chunk_names.append(module)
        region_index_chunks.append((name, len(region_indices)))
        write_closure_data_module(
            module,
            ["RelationalImage", f"RelationalRegionChunk{chunk_index}"],
            f"def {name} : IndexTree RegionRelation := "
            + _lean_index_tree([f"region{index}" for index in region_indices]),
        )
    write_closure_data_module(
        "RelationalProofRegionIndexData",
        region_index_chunk_names,
        "def allRegionIndex : IndexTree RegionRelation := "
        + _lean_index_tree_join(region_index_chunks),
    )

    write_closure_data_module(
        "RelationalProofRegionInventoryData",
        ["RelationalStaticContext", "RelationalRegionChunks"],
        f"def allRegions : List RegionRelation := "
        f"{_lean_right_append(region_chunk_names)}\n\n"
        + "def staticDataUsageRegions : Array Nat := #["
        + ", ".join(str(index) for index in data_usage_regions)
        + "]",
    )

    static_usage_leaf_size = max(
        1,
        int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_STATIC_USAGE_CHUNK", "16")),
    )
    static_usage_leaf_modules: list[str] = []
    static_usage_chunk_modules: list[str] = []
    static_usage_chunk_theorems: list[str] = []
    static_usage_leaf_index = 0
    for chunk_index, (chunk_name, region_indices) in enumerate(
        zip(region_chunk_names, decode_chunk_regions, strict=True)
    ):
        leaf_names: list[str] = []
        leaf_theorems: list[str] = []
        chunk_leaf_modules: list[str] = []
        for offset in range(0, len(region_indices), static_usage_leaf_size):
            leaf_region_indices = region_indices[
                offset : offset + static_usage_leaf_size
            ]
            leaf_module = f"RelationalProofStaticUsageLeaf{static_usage_leaf_index}"
            leaf_name = f"staticUsageLeaf{static_usage_leaf_index}"
            leaf_theorem = f"staticUsageLeaf{static_usage_leaf_index}Checked"
            static_usage_leaf_index += 1
            static_usage_leaf_modules.append(leaf_module)
            chunk_leaf_modules.append(leaf_module)
            leaf_names.append(leaf_name)
            leaf_theorems.append(leaf_theorem)
            write_closure_data_module(
                leaf_module,
                ["RelationalStaticContext", f"RelationalRegionChunk{chunk_index}"],
                f"def {leaf_name} : List RegionRelation := ["
                + ", ".join(f"region{index}" for index in leaf_region_indices)
                + "]\n\n"
                + f"theorem {leaf_theorem} :\n"
                f"    {leaf_name}.all "
                "(regionUsesStaticContext staticProofContext) = true := by decide",
            )
        module = f"RelationalProofStaticUsageChunk{chunk_index}"
        theorem = f"regionChunk{chunk_index}UsesStaticContextChecked"
        static_usage_chunk_modules.append(module)
        static_usage_chunk_theorems.append(theorem)
        leaf_partition = _lean_right_append(leaf_names)
        leaf_proof = _lean_all_append_proof(
            "regionUsesStaticContext staticProofContext",
            leaf_names,
            leaf_theorems,
        )
        write_closure_data_module(
            module,
            [
                "RelationalStaticContext",
                f"RelationalRegionChunk{chunk_index}",
                *chunk_leaf_modules,
            ],
            f"theorem regionChunk{chunk_index}StaticUsagePartition :\n"
            f"    {chunk_name} = {leaf_partition} := by rfl\n\n"
            f"theorem {theorem} :\n"
            f"    {chunk_name}.all "
            "(regionUsesStaticContext staticProofContext) = true := by\n"
            f"  rw [regionChunk{chunk_index}StaticUsagePartition]\n"
            f"  exact {leaf_proof}",
        )
    static_usage_proof = _lean_all_append_proof(
        "regionUsesStaticContext staticProofContext",
        region_chunk_names,
        static_usage_chunk_theorems,
    )
    write_closure_data_module(
        "RelationalProofStaticUsageCertificate",
        [
            "RelationalImage",
            "RelationalProofRegionInventoryData",
            *static_usage_chunk_modules,
        ],
        "theorem allRegionsUseStaticContextChecked :\n"
        "    RegionsUseStaticContext staticProofContext allRegions := by\n"
        "  unfold RegionsUseStaticContext regionsUseStaticContext allRegions\n"
        f"  exact {static_usage_proof}\n\n"
        "theorem staticDataUsageChecked :\n"
        "    StaticDataUsageWitnessValid staticProofContext allRegions.toArray\n"
        "      staticDataUsageRegions :=\n"
        "  staticDataUsageWitnessValid_of_checked staticProofContext allRegions.toArray\n"
        "    staticDataUsageRegions (by decide)",
    )

    write_closure_data_module(
        "RelationalProofOriginalCoverageData",
        ["RelationalImage", "RelationalStaticContext"],
        f"def originalCoverage : SortedSpanCertificate := {original_coverage}\n\n"
        f"def originalAliasCoverage : PaddingAliasCertificate := "
        f"{original_alias_coverage}",
    )
    write_closure_data_module(
        "RelationalProofCandidateCoverageData",
        ["RelationalImage", "RelationalStaticContext"],
        f"def candidateCoverage : SortedSpanCertificate := {candidate_coverage}\n\n"
        f"def candidateAliasCoverage : PaddingAliasCertificate := "
        f"{candidate_alias_coverage}",
    )

    closure_data_imports = [
        "RelationalMachineImportCallContracts",
        "RelationalExternalCallSites",
        "RelationalProofRequiredInputsData",
        "RelationalProofPaddingData",
        "RelationalProofRegionIndexData",
        "RelationalProofRegionInventoryData",
        "RelationalProofStaticUsageCertificate",
        "RelationalProofOriginalCoverageData",
        "RelationalProofCandidateCoverageData",
    ]
    write_closure_data_module(
        "RelationalProofClosureData",
        closure_data_imports,
        "def proofBundle : StageA.Relational.ProofBundle := { originalBytes, candidateBytes, "
        "originalImports := originalImportCertificate, candidateImports := candidateImportCertificate, "
        "machineImportCallContracts, "
        "regions := allRegions, regionIndex := allRegionIndex, originalPadding, candidatePadding, "
        "originalCoverage, candidateCoverage, originalAliasCoverage, candidateAliasCoverage }",
    )

    structural_region_modules: list[str] = []
    for chunk_index, chunk_name in enumerate(region_chunk_names):
        module = f"RelationalProofStructuralRegionChunk{chunk_index}"
        structural_region_modules.append(module)
        source = (
            "import StageA.RelationalStaticContext\n"
            "import StageA.RelationalProofRegionIndexData\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            f"theorem regionStructureItemsChunk{chunk_index}Checked :\n"
            f"    {chunk_name}.all (fun region =>\n"
            "      spanInExecutableSection originalPe region.original &&\n"
            "      spanInExecutableSection candidatePe region.candidate &&\n"
            "      region.inputs.length > 0 && region.outputs.length > 0) = true := by decide\n\n"
            f"theorem valueRegionsChunk{chunk_index}Checked :\n"
            f"    valueRegionsClosed originalPe candidatePe originalRelocations candidateRelocations {chunk_name} = true := by decide\n\n"
            f"theorem flagRelationChunk{chunk_index}Checked :\n"
            f"    {chunk_name}.all (fun source => source.targets.all "
            f"(targetFlagRelationClosed allRegionIndex source)) = true := by decide\n\n"
            "end StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)

    structural_padding_modules: list[str] = []
    for side in ("original", "candidate"):
        for chunk_index, chunk_name in enumerate(padding_chunk_names[side]):
            module = f"RelationalProofStructuralPadding{side.capitalize()}Chunk{chunk_index}"
            structural_padding_modules.append(module)
            source = (
                "import StageA.RelationalProofPaddingData\n\n"
                "namespace StageA.GeneratedRelational\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
                f"theorem {side}PaddingChunk{chunk_index}Checked :\n"
                f"    {chunk_name}.all (paddingSpanValid {side}Pe) = true := by decide\n\n"
                "end StageA.GeneratedRelational\n"
            )
            _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)

    coverage_modules: list[str] = []
    for side in ("original", "candidate"):
        module = f"RelationalProofStructuralCoverage{side.capitalize()}"
        coverage_modules.append(module)
        source = (
            "import StageA.RelationalProofRegionInventoryData\n"
            "import StageA.RelationalProofPaddingData\n"
            f"import StageA.RelationalProof{side.capitalize()}CoverageData\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            f"theorem {side}CoverageChecked : executableCoverageCertified {side}Pe\n"
            f"    (allRegions.map (fun region => region.{side}) ++ {side}Padding)\n"
            f"    {side}Coverage = true := by decide\n\n"
            f"theorem {side}AliasCoverageChecked :\n"
            f"    paddingAliasCertificateValid {side}Padding {side}AliasCoverage = true := by decide\n\n"
            "end StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)

    independent_source = (
        "import StageA.RelationalProofClosureData\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "theorem imagesChecked : imageStructureClosed originalPe candidatePe = true := by decide\n\n"
        "theorem indexChecked : regionIndexClosed allRegions allRegionIndex = true := by decide\n\n"
        "theorem entryChecked : entryRootClosed originalPe candidatePe allRegions = true := by decide\n\n"
        "theorem targetsChecked : targetCoverageClosed allRegionIndex allRegions = true := by decide\n\n"
        "theorem targetAliasesChecked : targetAliasesCertified allRegions originalAliasCoverage candidateAliasCoverage = true := by decide\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalProofStructuralIndependent.lean",
        independent_source,
    )

    region_structure_proof = _lean_all_append_proof(
        "fun region => spanInExecutableSection originalPe region.original && "
        "spanInExecutableSection candidatePe region.candidate && "
        "region.inputs.length > 0 && region.outputs.length > 0",
        region_chunk_names,
        [f"regionStructureItemsChunk{index}Checked" for index in range(len(region_chunk_names))],
    )
    value_regions_proof = _lean_all_append_proof(
        "valueRegionClosed originalPe candidatePe originalRelocations candidateRelocations",
        region_chunk_names,
        [f"valueRegionsChunk{index}Checked" for index in range(len(region_chunk_names))],
    )
    flag_relation_proof = _lean_all_append_proof(
        "fun source => source.targets.all (targetFlagRelationClosed allRegionIndex source)",
        region_chunk_names,
        [f"flagRelationChunk{index}Checked" for index in range(len(region_chunk_names))],
    )
    padding_proofs = {
        side: _lean_all_append_proof(
            f"paddingSpanValid {side}Pe",
            padding_chunk_names[side],
            [f"{side}PaddingChunk{index}Checked" for index in range(len(padding_chunk_names[side]))],
        )
        for side in ("original", "candidate")
    }
    aggregate_source = (
        "import StageA.RelationalProofStructuralIndependent\n"
        + "\n".join(
            f"import StageA.{module}"
            for module in structural_region_modules + structural_padding_modules
        )
        + "\n\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "theorem allRegionsNonempty : allRegions.length > 0 := by decide\n\n"
        "theorem regionStructureItemsChecked : regionStructureItemsClosed originalPe candidatePe allRegions = true := by\n"
        "  unfold regionStructureItemsClosed allRegions\n"
        f"  exact {region_structure_proof}\n\n"
        "theorem regionStructureChecked : regionStructureClosed originalPe candidatePe allRegions = true := by\n"
        "  simp [regionStructureClosed, allRegionsNonempty, regionStructureItemsChecked]\n\n"
        "theorem valueRegionsChecked : valueRegionsClosed originalPe candidatePe originalRelocations candidateRelocations allRegions = true := by\n"
        "  unfold valueRegionsClosed allRegions\n"
        f"  exact {value_regions_proof}\n\n"
        "theorem valuesChecked : valueTargetsClosed originalPe candidatePe allRegions = true :=\n"
        "  valueTargetsClosed_of_parsed originalPe candidatePe originalRelocations candidateRelocations allRegions originalRelocationsParsed candidateRelocationsParsed valueRegionsChecked\n\n"
        "theorem mappedRelocationImageRelationsChecked :\n"
        "    AllMappedRelocationImageRelations originalPe candidatePe originalRelocations "
        "candidateRelocations allRegions :=\n"
        "  allMappedRelocationImageRelations_of_valueRegionsClosed originalPe candidatePe "
        "originalRelocations candidateRelocations allRegions valueRegionsChecked\n\n"
        "theorem flagRelationCompositionChecked : flagRelationCompositionClosed allRegionIndex allRegions = true := by\n"
        "  unfold flagRelationCompositionClosed allRegions\n"
        f"  exact {flag_relation_proof}\n\n"
        "theorem originalPaddingChecked : paddingBytesClosed originalPe originalPadding = true := by\n"
        "  unfold paddingBytesClosed originalPadding\n"
        f"  exact {padding_proofs['original']}\n\n"
        "theorem candidatePaddingChecked : paddingBytesClosed candidatePe candidatePadding = true := by\n"
        "  unfold paddingBytesClosed candidatePadding\n"
        f"  exact {padding_proofs['candidate']}\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalProofStructuralAggregates.lean",
        aggregate_source,
    )

    closure_source = (
        "import StageA.RelationalProofStructuralAggregates\n"
        + "\n".join(f"import StageA.{module}" for module in coverage_modules)
        + "\n\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "theorem structuralChecked : structuralEligible proofBundle = true :=\n"
        "  structuralEligible_of_checks proofBundle originalPe candidatePe originalParsed candidateParsed\n"
        "    imagesChecked indexChecked regionStructureChecked originalCoverageChecked candidateCoverageChecked\n"
        "    originalPaddingChecked candidatePaddingChecked entryChecked targetsChecked\n"
        "    originalAliasCoverageChecked candidateAliasCoverageChecked targetAliasesChecked\n"
        "    valuesChecked flagRelationCompositionChecked\n\n"
        "theorem importsChecked : importTablesCertified proofBundle := by\n"
        "  unfold importTablesCertified parsedImages proofBundle\n"
        "  rw [originalParsed, candidateParsed]\n"
        "  exact ⟨originalImportsChecked, candidateImportsChecked⟩\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalProofClosureBase.lean",
        closure_source,
    )

    invariant_certificate_type = " ∧ ".join(
        [f"AllInvariantClaims {item['claims']}" for item in invariant_modules] + ["True"]
    )
    invariant_certificate_proof = (
        "".join(f"And.intro {item['theorem']} (" for item in invariant_modules)
        + "True.intro"
        + ")" * len(invariant_modules)
    )
    memory_pullback_certificate_type = " ∧ ".join(
        [
            f"AllInvariantClaims {item['ordinary_claims']}"
            for item in memory_pullback_modules
        ]
        + ["True"]
    )
    memory_pullback_certificate_proof = (
        "".join(
            f"And.intro {item['ordinary_theorem']} ("
            for item in memory_pullback_modules
        )
        + "True.intro"
        + ")" * len(memory_pullback_modules)
    )
    x87_pullback_certificate_type = " ∧ ".join(
        [
            f"AllInvariantClaims {item['x87_claims']}"
            for item in memory_pullback_modules
        ]
        + ["True"]
    )
    x87_pullback_certificate_proof = (
        "".join(
            f"And.intro {item['x87_theorem']} ("
            for item in memory_pullback_modules
        )
        + "True.intro"
        + ")" * len(memory_pullback_modules)
    )
    register_relation_certificate_type = " ∧ ".join(
        [
            f"AllInvariantClaims {item['claims']}"
            for item in register_relation_modules
        ]
        + ["True"]
    )
    register_relation_certificate_proof = (
        "".join(
            f"And.intro {item['theorem']} ("
            for item in register_relation_modules
        )
        + "True.intro"
        + ")" * len(register_relation_modules)
    )
    segment_refinement_certificate_type = " ∧ ".join(
        [
            f"AllInvariantClaims {item['claims']}"
            for item in segment_refinement_modules
        ]
        + ["True"]
    )
    segment_refinement_certificate_proof = (
        "".join(
            f"And.intro {item['theorem']} ("
            for item in segment_refinement_modules
        )
        + "True.intro"
        + ")" * len(segment_refinement_modules)
    )
    segment_refinement_certificate_source = (
        "import StageA.RelationalSegment\n"
        + "".join(
            f"import StageA.{item['module']}\n"
            for item in segment_refinement_modules
        )
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        f"def GeneratedSegmentRefinementCertificate : Prop := "
        f"{segment_refinement_certificate_type}\n\n"
        "theorem generatedSegmentRefinementCertificateChecked :\n"
        "    GeneratedSegmentRefinementCertificate := by\n"
        f"  exact {segment_refinement_certificate_proof}\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalSegmentRefinementCertificate.lean",
        segment_refinement_certificate_source,
    )
    stack_separation_certificate_type = " ∧ ".join(
        [item["proposition"] for item in stack_separation_modules] + ["True"]
    )
    stack_separation_certificate_proof = (
        "".join(
            f"And.intro {item['theorem']} (" for item in stack_separation_modules
        )
        + "True.intro"
        + ")" * len(stack_separation_modules)
    )
    stack_separation_certificate_source = (
        "import StageA.Relational\n"
        + "".join(
            f"import StageA.{item['module']}\n" for item in stack_separation_modules
        )
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        f"def GeneratedStackSeparationCertificate : Prop := "
        f"{stack_separation_certificate_type}\n\n"
        "theorem generatedStackSeparationCertificateChecked :\n"
        "    GeneratedStackSeparationCertificate := by\n"
        f"  exact {stack_separation_certificate_proof}\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalStackSeparationCertificate.lean",
        stack_separation_certificate_source,
    )
    final = (
        "import StageA.RelationalCertificates\n"
        "import StageA.RelationalInstructionAdequacyCertificate\n"
        "import StageA.RelationalISARequirementReplayCertificate\n"
        "import StageA.RelationalProofClosureBase\n"
        "import StageA.RelationalSegmentRefinementCertificate\n"
        "import StageA.RelationalStackSeparationCertificate\n"
        "import StageA.RelationalAffineFrameSemanticProfile\n"
        "import StageA.RelationalProductNodeCoverageCertificate\n"
        "import StageA.RelationalProductReachabilityCertificate\n"
        "import StageA.RelationalProductDecodedControlCertificate\n"
        "import StageA.RelationalReachableProductLocalCertificate\n"
        "import StageA.RelationalImportRegisterSeedCertificate\n"
        "import StageA.RelationalDynamicRangeIndirectCallCertificate\n"
        "import StageA.RelationalExternalCallRefinementCertificate\n"
        "import StageA.RelationalExternalJumpRefinementCertificate\n"
        + "".join(
            f"import StageA.{item['module']}\n" for item in invariant_modules
        )
        + "".join(
            f"import StageA.{item['module']}\n" for item in memory_pullback_modules
        )
        + "".join(
            f"import StageA.{item['module']}\n" for item in register_relation_modules
        )
        + "\n\nnamespace StageA.GeneratedRelational\n\nopen StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        f"def GeneratedInvariantCertificate : Prop := {invariant_certificate_type}\n\n"
        "theorem generatedInvariantCertificateChecked : GeneratedInvariantCertificate := by\n"
        f"  exact {invariant_certificate_proof}\n\n"
        "def GeneratedMappedRelocationImageCertificate : Prop :=\n"
        "  AllMappedRelocationImageRelations originalPe candidatePe originalRelocations "
        "candidateRelocations allRegions\n\n"
        "theorem generatedMappedRelocationImageCertificateChecked :\n"
        "    GeneratedMappedRelocationImageCertificate :=\n"
        "  mappedRelocationImageRelationsChecked\n\n"
        f"def GeneratedOrdinaryMemoryReadPullbackCertificate : Prop := "
        f"{memory_pullback_certificate_type}\n\n"
        "theorem generatedOrdinaryMemoryReadPullbackCertificateChecked :\n"
        "    GeneratedOrdinaryMemoryReadPullbackCertificate := by\n"
        f"  exact {memory_pullback_certificate_proof}\n\n"
        f"def GeneratedX87LoadPullbackCertificate : Prop := "
        f"{x87_pullback_certificate_type}\n\n"
        "theorem generatedX87LoadPullbackCertificateChecked :\n"
        "    GeneratedX87LoadPullbackCertificate := by\n"
        f"  exact {x87_pullback_certificate_proof}\n\n"
        f"def GeneratedExactRegisterRelationCertificate : Prop := "
        f"{register_relation_certificate_type}\n\n"
        "theorem generatedExactRegisterRelationCertificateChecked :\n"
        "    GeneratedExactRegisterRelationCertificate := by\n"
        f"  exact {register_relation_certificate_proof}\n\n"
        "theorem candidateRelationalEvidenceBundle :\n"
        "    StaticProofContext.StructurallyValid staticProofContext ∧\n"
        "      relationalProductGraph.IndexedValid staticProofContext ∧\n"
        "      relationalProductEvidence.valid relationalProductGraph = true ∧\n"
        "      GeneratedImportRegisterSeedCertificate ∧\n"
        "      GeneratedDynamicRangeIndirectCallCertificate ∧\n"
        "      GeneratedExternalCallRefinementCertificate ∧\n"
        "      GeneratedPartialDecodedControlCompletenessCertificate ∧\n"
        "      GeneratedPartialReachableProductLocalCertificate ∧\n"
        "      GeneratedDeclaredGraphReachabilityCertificate ∧\n"
        "      GeneratedPartialProductEdgeRefinementCertificate ∧\n"
        "      GeneratedPartialProductNodeCoverageCertificate ∧\n"
        "      RegionsUseStaticContext staticProofContext allRegions ∧\n"
        "      StaticDataUsageWitnessValid staticProofContext allRegions.toArray\n"
        "        staticDataUsageRegions ∧\n"
        "      valueRegionsClosed originalPe candidatePe originalRelocations\n"
        "        candidateRelocations allRegions = true ∧\n"
        "      GeneratedInvariantCertificate ∧\n"
        "      GeneratedMappedRelocationImageCertificate ∧\n"
        "      GeneratedStackSeparationCertificate ∧\n"
        "      GeneratedOrdinaryMemoryReadPullbackCertificate ∧\n"
        "      GeneratedX87LoadPullbackCertificate ∧\n"
        "      GeneratedExactRegisterRelationCertificate ∧\n"
        "      GeneratedSegmentRefinementCertificate :=\n"
        "  ⟨staticProofContextChecked, relationalProductGraphIndexedValidChecked,\n"
        "    relationalProductEvidenceValidChecked,\n"
        "    generatedImportRegisterSeedCertificateChecked,\n"
        "    generatedDynamicRangeIndirectCallCertificateChecked,\n"
        "    generatedExternalCallRefinementCertificateChecked,\n"
        "    generatedPartialDecodedControlCompletenessCertificateChecked,\n"
        "    generatedPartialReachableProductLocalCertificateChecked,\n"
        "    generatedDeclaredGraphReachabilityCertificateChecked,\n"
        "    generatedPartialProductEdgeRefinementCertificateChecked,\n"
        "    generatedPartialProductNodeCoverageCertificateChecked,\n"
        "    allRegionsUseStaticContextChecked,\n"
        "    staticDataUsageChecked, valueRegionsChecked,\n"
        "    generatedInvariantCertificateChecked,\n"
        "    generatedMappedRelocationImageCertificateChecked,\n"
        "    generatedStackSeparationCertificateChecked,\n"
        "    generatedOrdinaryMemoryReadPullbackCertificateChecked,\n"
        "    generatedX87LoadPullbackCertificateChecked,\n"
        "    generatedExactRegisterRelationCertificateChecked,\n"
        "    generatedSegmentRefinementCertificateChecked⟩\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(lean_dir / "StageA" / "RelationalBundle.lean", final)
    _write_relational_acceptance_modules(
        lean_dir,
        original_bin,
        candidate_bin,
        contract,
        behaviors,
        product_graph,
        register_relations,
        segment_candidates,
        decode_chunk_regions,
        external_site_candidates,
        runtime_frame_affine=runtime_frame_affine,
        deferred_guard_segment_candidates=deferred_guard_segment_candidates,
        segment_refinement_modules=segment_refinement_modules,
    )
    write_json(
        lean_dir.parent / "checked-region-artifacts.json",
        {
            "format": "stage-a-checked-region-artifacts-v1",
            "artifacts": sorted(
                checked_region_artifacts,
                key=lambda row: (row["side"], row["region_index"]),
            ),
        },
    )
    return (
        shard_modules
        + [item["module"] for item in stack_separation_modules]
        + [item["module"] for item in invariant_modules]
        + [item["module"] for item in memory_pullback_modules]
        + [item["module"] for item in register_relation_modules],
        shard_size,
    )

def _lean_named_byte_tree(packs: list[tuple[str, int]]) -> str:
    if not packs:
        return ".empty"
    if len(packs) == 1:
        return packs[0][0]
    midpoint = len(packs) // 2
    left = packs[:midpoint]
    right = packs[midpoint:]
    left_size = sum(size for _, size in left)
    total_size = left_size + sum(size for _, size in right)
    return (
        f".node {total_size} {left_size} "
        f"({_lean_named_byte_tree(left)}) ({_lean_named_byte_tree(right)})"
    )


def _lean_pe_image_pack_source(name: str, data: bytes) -> str:
    return (
        "import StageA.Formal\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal\n\n"
        "set_option maxRecDepth 1000000\n\n"
        + _lean_byte_tree_definitions(name, data)
        + "\n\nend StageA.GeneratedRelational\n"
    )


def _write_pe_side_modules(
    lean_dir: Path,
    side: str,
    binary: StageABinary,
    data: bytes,
) -> list[str]:
    pack_size = max(
        1024,
        int(
            os.environ.get(
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_IMAGE_PACK_BYTES",
                str(32 * 1024),
            )
        ),
    )
    module_side = side.capitalize()
    packs: list[tuple[str, str, int]] = []
    for index, offset in enumerate(range(0, len(data), pack_size)):
        pack_data = data[offset : offset + pack_size]
        module = f"RelationalProof{module_side}ImagePack{index:04d}"
        name = f"{side}ImagePack{index:04d}"
        _write_text_if_changed(
            lean_dir / "StageA" / f"{module}.lean",
            _lean_pe_image_pack_source(name, pack_data),
        )
        packs.append((module, name, len(pack_data)))
    image_module = f"RelationalProof{module_side}Image"
    _write_text_if_changed(
        lean_dir / "StageA" / f"{image_module}.lean",
        _lean_pe_side_source(side, binary, data, image_packs=packs),
    )
    imports_attestation = f"RelationalProof{module_side}ImportsAttestation"
    relocations_attestation = (
        f"RelationalProof{module_side}RelocationsAttestation"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / f"{imports_attestation}.lean",
        _lean_pe_import_attestation_source(side),
    )
    _write_text_if_changed(
        lean_dir / "StageA" / f"{relocations_attestation}.lean",
        _lean_pe_relocation_attestation_source(side, binary),
    )
    facade = f"RelationalProof{module_side}"
    _write_text_if_changed(
        lean_dir / "StageA" / f"{facade}.lean",
        (
            f"import StageA.{image_module}\n"
            f"import StageA.{imports_attestation}\n"
            f"import StageA.{relocations_attestation}\n"
        ),
    )
    return [
        *(module for module, _, _ in packs),
        image_module,
        imports_attestation,
        relocations_attestation,
        facade,
    ]


def _lean_pe_side_source(
    side: str,
    binary: StageABinary,
    data: bytes,
    *,
    image_packs: list[tuple[str, str, int]] | None = None,
) -> str:
    module_side = side.capitalize()
    pack_imports = ""
    byte_definitions = _lean_byte_tree_definitions(f"{side}Bytes", data)
    if image_packs is not None:
        pack_imports = "".join(
            f"import StageA.{module}\n" for module, _, _ in image_packs
        )
        byte_definitions = (
            f"def {side}Bytes : ByteTree := "
            + _lean_named_byte_tree(
                [(name, size) for _, name, size in image_packs]
            )
        )
    return (
        "import StageA.Formal\n"
        + pack_imports
        + "\n"
        + "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal\n\nset_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        + byte_definitions
        + "\n\n"
        + f"def {side}Pe : PE32 := {_lean_pe(binary, f'{side}Bytes')}\n\n"
        + f"theorem {side}MetadataParsed : parsePEMetadataTree {side}Bytes = some {side}Pe.metadata := by decide\n\n"
        + f"theorem {side}Parsed : parsePE32Tree {side}Bytes = some {side}Pe := by\n"
        + f"  simp [parsePE32Tree, {side}MetadataParsed, PE32.metadata, PEMetadata.toPE32, {side}Pe]\n\n"
        + "end StageA.GeneratedRelational\n"
    )


def _lean_pe_import_attestation_source(side: str) -> str:
    module_side = side.capitalize()
    return (
        f"import StageA.RelationalProof{module_side}Image\n"
        f"import StageA.RelationalProof{module_side}Imports\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        + f"theorem {side}ImportsChecked : "
        f"importTableValid {side}Pe {side}ImportCertificate = true := by\n"
        "  decide\n\n"
        "end StageA.GeneratedRelational\n"
    )


def _lean_pe_relocation_attestation_source(
    side: str,
    binary: StageABinary,
) -> str:
    module_side = side.capitalize()
    return (
        f"import StageA.RelationalProof{module_side}Image\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        + f"def {side}Relocations : List BaseRelocation := "
        + _lean_relocations(binary)
        + "\n\n"
        + f"theorem {side}RelocationsParsed : "
        f"parseRelocations {side}Pe = some {side}Relocations := by\n"
        "  decide\n\n"
        "end StageA.GeneratedRelational\n"
    )


def _lean_pe_import_source(side: str, binary: StageABinary) -> str:
    return (
        "import StageA.Formal\n\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        + f"def {side}ImportCertificate : ImportTableCertificate := "
        + _lean_import_certificate(binary)
        + "\n\n"
        + f"def {side}Imports : List PEImport := "
        + f"{side}ImportCertificate.imports\n\n"
        + "end StageA.GeneratedRelational\n"
    )


def _partition_proof_shards(
    region_costs: list[int],
    *,
    max_regions: int,
    target_bytes: int,
) -> list[list[int]]:
    groups: list[list[int]] = []
    current: list[int] = []
    current_bytes = 0
    for index, cost in enumerate(region_costs):
        if current and (
            len(current) >= max_regions
            or current_bytes + cost > target_bytes
        ):
            groups.append(current)
            current = []
            current_bytes = 0
        current.append(index)
        current_bytes += cost
    if current:
        groups.append(current)
    return groups

def _lean_normalized_component_setup(
    index: int,
    region: dict[str, Any],
    *,
    original_image_base: int,
    candidate_image_base: int,
    preserve_flags: bool = False,
    preserve_states: bool = False,
) -> tuple[str, str]:
    name = f"region{index}"
    input_hypotheses = [f"inputRelated{pair_index}" for pair_index in range(len(region["inputs"]))]
    relation_destructure = (
        "  rcases related with ⟨" + ", ".join(input_hypotheses) + "⟩\n"
        if len(input_hypotheses) > 1 else ""
    )
    substitutions = "".join(
        f"  subst c{pair['candidate']}\n" for pair in region["inputs"]
    )
    flag_setup, flag_hypotheses = _lean_region_flag_setup(index, region)
    aliases = (
        "  let originalInput := originalState\n"
        "  let candidateInput := candidateState\n"
        if preserve_states else ""
    )
    flags_copy = "  have flagsRelatedAll := flagsRelated\n" if preserve_flags else ""
    identity_memory_setup = (
        f"  have {name}ValueTargetsIdentity : forall target, target ∈ {name}.values ->\n"
        "      target.originalValue = target.candidateValue := by\n"
        "    intro target member\n"
        f"    simp_all [{name}]\n"
        f"  have {name}NormalizedMemoryIdentity :\n"
        f"      (fun address => originalMemory (normalizeDataAddress {name}.values address)) =\n"
        "        originalMemory := by\n"
        "    funext address\n"
        f"    exact congrArg originalMemory\n"
        f"      (normalizeDataAddress_eq_self_of_identity_targets {name}.values address\n"
        f"        {name}ValueTargetsIdentity)\n"
        f"  rw [{name}NormalizedMemoryIdentity]\n"
        if region.get("values") else ""
    )
    return (
        aliases
        + "  unfold statesRelated StateRelCore at related\n"
        "  simp only [registerRelationsHold_exactRegisterRelations] at related\n"
        "  rcases originalState with ⟨⟨oeax, oebx, oecx, oedx, oesi, oedi, oebp, oesp⟩, originalMemory, originalUndefined, originalX87, originalX87Physical, originalX87Semantics, originalFlags, originalFsBase⟩\n"
        "  rcases candidateState with ⟨⟨ceax, cebx, cecx, cedx, cesi, cedi, cebp, cesp⟩, candidateMemory, candidateUndefined, candidateX87, candidateX87Physical, candidateX87Semantics, candidateFlags, candidateFsBase⟩\n"
        "  rcases related with ⟨related, boundsSatisfied, separationsSatisfied, memoryRelated, undefinedRelated, x87Related, flagsRelated, fsBaseRelated⟩\n"
        f"  have exactMemory := memoryRelated_without_relocations {original_image_base} {candidate_image_base} "
        f"{name}.targets {name}.values originalMemory candidateMemory (by decide) memoryRelated\n"
        f"  change candidateMemory = fun address => originalMemory (normalizeDataAddress {name}.values address) at exactMemory\n"
        "  subst candidateMemory\n"
        + identity_memory_setup
        + "  change originalUndefined = candidateUndefined at undefinedRelated\n"
        "  subst candidateUndefined\n"
        "  change originalX87 = candidateX87 ∧ originalX87Physical = candidateX87Physical ∧ originalX87Semantics = candidateX87Semantics at x87Related\n"
        "  rcases x87Related with ⟨rfl, rfl, rfl⟩\n"
        + flags_copy
        + flag_setup
        + "  change originalFsBase = candidateFsBase at fsBaseRelated\n"
        "  subst candidateFsBase\n"
        f"  simp [registersRelated, StageA.Formal.Registers.get, {name}] at related\n"
        + relation_destructure
        + substitutions
        + f"  simp [StageA.Relational.boundsRelated, StageA.Relational.boundValue, evalExprPure, StageA.Formal.Registers.get, {name}] at boundsSatisfied\n"
        f"  simp [addressSeparationsRelated, StageA.Formal.Registers.get, {name}] at separationsSatisfied\n",
        flag_hypotheses,
    )

def _lean_outcome_condition_support_source(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> str:
    outcome = _lean_normalized_static_outcome(region, behaviors)
    if outcome is None:
        return ""
    name = f"region{index}"
    branch_parts = _lean_normalized_branch_parts(outcome)
    if branch_parts is None:
        return ""
    condition, _, _ = branch_parts
    return (
        f"def {name}OutcomeCondition : BoolExpr := {condition}\n\n"
        f"theorem {name}OutcomeConditionWithin :\n"
        f"    {name}OutcomeCondition.flagsWithin {name}.flagInputs = true := by decide\n"
    )


def _lean_compositional_normalized_support_source(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> str:
    outcome = _lean_normalized_static_outcome(region, behaviors)
    if outcome is None or "flags := some" not in behaviors["original"]:
        return ""
    name = f"region{index}"
    branch_parts = _lean_normalized_branch_parts(outcome)
    indirect_call_parts = _lean_normalized_indirect_call_parts(outcome)
    if branch_parts is None:
        if indirect_call_parts is None:
            normalized_outcome = outcome
        else:
            target, continuation = indirect_call_parts
            normalized_outcome = (
                "StageA.Relational.NormalizedOutcomeExpr.indirectCall "
                f"{name}OutcomeTarget {continuation}"
            )
    else:
        _, taken, fallthrough = branch_parts
        normalized_outcome = (
            "StageA.Relational.NormalizedOutcomeExpr.branch "
            f"{name}OutcomeCondition {taken} {fallthrough}"
        )
    empty_writes = all(
        _lean_behavior_field(behaviors.get(side, ""), "writes", "comparison") == "[]"
        for side in ("original", "candidate")
    )
    empty_writes_fact = (
        f"theorem {name}OriginalWritesEmpty : "
        f"originalBehavior{index}.writes = [] := by rfl\n\n"
        if empty_writes else ""
    )
    register_names = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    original_ir = behaviors.get("original_ir")
    compact_ir = isinstance(original_ir, dict)
    register_ir = original_ir.get("registers", {}) if compact_ir else {}
    flags_ir = original_ir.get("flags", {}) if compact_ir else {}
    compact_ir = (
        compact_ir
        and all(isinstance(register_ir.get(register), dict) for register in register_names)
        and isinstance(flags_ir, dict)
    )
    compact_definitions = ""
    normalized_registers_rhs = f"originalBehavior{index}.registers"
    normalized_x87_rhs = f"originalBehavior{index}.x87"
    normalized_writes_rhs = f"originalBehavior{index}.writes"
    normalized_behavior_value = (
        f"(normalizeSymbolicBehavior false {name}.targets "
        f"originalBehavior{index}).get (by decide)"
    )
    empty_writes_subject = f"originalBehavior{index}.writes"
    common_flags_definition = (
        f"def {name}CommonFlags : FlagsExpr := "
        f"originalBehavior{index}.flags.get (by decide)\n\n"
    )
    outcome_definitions = ""
    if indirect_call_parts is not None:
        target, _ = indirect_call_parts
        outcome_definitions = (
            f"def {name}OutcomeTarget : Expr := {target}\n\n"
            f"theorem {name}OutcomeTargetWithin :\n"
            f"    {name}OutcomeTarget.flagsWithin {name}.flagInputs = true := by decide\n\n"
        )
    if compact_ir:
        register_definitions = "".join(
            f"def {name}Register{register.capitalize()} : Expr := "
            f"{_lean_semantic_expr(register_ir[register])}\n\n"
            f"theorem {name}Register{register.capitalize()}Within : "
            f"{name}Register{register.capitalize()}.flagsWithin {name}.flagInputs = true := "
            "by decide\n\n"
            for register in register_names
        )
        common_register_fields = ", ".join(
            f"{register} := {name}Register{register.capitalize()}"
            for register in register_names
        )
        flag_fields = (
            ("zero", "Zero"),
            ("carry", "Carry"),
            ("auxiliary", "Auxiliary"),
            ("sign", "Sign"),
            ("overflow", "Overflow"),
            ("parity", "Parity"),
        )
        flag_definitions = ""
        common_flag_fields: list[str] = []
        for field, lean_name in flag_fields:
            expression = flags_ir.get(field)
            value = (
                "none" if expression is None else
                f"some ({_lean_semantic_bool_expr(expression)})"
            )
            flag_definitions += (
                f"def {name}Flag{lean_name} : Option BoolExpr := {value}\n\n"
            )
            common_flag_fields.append(f"{field} := {name}Flag{lean_name}")
        compact_definitions = (
            register_definitions
            + f"def {name}CommonRegisters : Registers Expr := "
            + "{ " + common_register_fields + " }\n\n"
            + flag_definitions
            + f"def {name}CommonFlags : FlagsExpr := "
            + "{ " + ", ".join(common_flag_fields) + " }\n\n"
            + f"def {name}CommonX87 : SymbolicX87State := "
            + _lean_symbolic_x87_state(original_ir["x87"])
            + "\n\n"
            + f"def {name}CommonWrites : List (Expr × Expr) := ["
            + ", ".join(
                f"({_lean_semantic_expr(write['address'])}, "
                f"{_lean_semantic_expr(write['value'])})"
                for write in original_ir.get("writes", [])
            )
            + "]\n\n"
            + f"theorem {name}OutputsIdentity :\n"
            + f"    {name}.outputs.all (fun pair => pair.original == pair.candidate) = true := "
            + "by decide\n\n"
            + f"theorem {name}FlagOutputs : {name}.flagOutputs = "
            + "[" + ", ".join(str(bit) for bit in region.get("flag_outputs", []))
            + "] := by decide\n\n"
            + f"theorem {name}RegistersRelatedValuesSelf "
            + "(originalImageBase candidateImageBase : Nat)\n"
            + "    (targets : List CodeTargetPair) (values : List ValueTargetPair) "
            + "(state : PureState) :\n"
            + f"    registersRelatedValues originalImageBase candidateImageBase targets values "
            + f"{name}.outputs state state = true :=\n"
            + f"  registersRelatedValues_self_of_identity originalImageBase candidateImageBase "
            + f"targets values {name}.outputs state "
            + f"{name}OutputsIdentity\n\n"
            + f"theorem {name}OriginalRegisters : originalBehavior{index}.registers = "
            + f"{name}CommonRegisters := by decide\n\n"
            + f"theorem {name}CandidateRegisters : candidateBehavior{index}.registers = "
            + f"{name}CommonRegisters := by decide\n\n"
            + f"theorem {name}OriginalFlags : originalBehavior{index}.flags = "
            + f"some {name}CommonFlags := by decide\n\n"
            + f"theorem {name}CandidateFlags : candidateBehavior{index}.flags = "
            + f"some {name}CommonFlags := by decide\n\n"
        )
        normalized_registers_rhs = f"{name}CommonRegisters"
        normalized_x87_rhs = f"{name}CommonX87"
        normalized_writes_rhs = f"{name}CommonWrites"
        normalized_behavior_value = (
            "{ registers := " + f"{name}CommonRegisters"
            + ", x87 := " + f"{name}CommonX87"
            + ", writes := " + f"{name}CommonWrites"
            + ", flags := some " + f"{name}CommonFlags"
            + ", outcome := " + normalized_outcome + " }"
        )
        empty_writes_subject = f"{name}CommonWrites"
        common_flags_definition = ""
    empty_writes_fact = (
        f"theorem {name}OriginalWritesEmpty : "
        f"{empty_writes_subject} = [] := by rfl\n\n"
        if empty_writes else ""
    )
    return (
        outcome_definitions
        + compact_definitions
        +
        f"def {name}NormalizedBehavior : NormalizedSymbolicBehavior :=\n"
        f"  {normalized_behavior_value}\n\n"
        f"theorem {name}NormalizedRegisters : {name}NormalizedBehavior.registers = "
        f"{normalized_registers_rhs} := by decide\n\n"
        f"theorem {name}NormalizedX87 : {name}NormalizedBehavior.x87 = "
        f"{normalized_x87_rhs} := by decide\n\n"
        f"theorem {name}NormalizedWrites : {name}NormalizedBehavior.writes = "
        f"{normalized_writes_rhs} := by decide\n\n"
        + common_flags_definition
        +
        f"theorem {name}NormalizedFlags : {name}NormalizedBehavior.flags = "
        f"some {name}CommonFlags := by decide\n\n"
        f"theorem {name}NormalizedOutcome : {name}NormalizedBehavior.outcome = "
        f"{normalized_outcome} := by decide\n\n"
        f"theorem {name}OriginalNormalized : normalizeSymbolicBehavior false "
        f"{name}.targets originalBehavior{index} = some {name}NormalizedBehavior := "
        "by decide\n\n"
        f"theorem {name}CandidateNormalized : normalizeSymbolicBehavior true "
        f"{name}.targets candidateBehavior{index} = some {name}NormalizedBehavior := "
        "by decide\n\n"
        f"theorem {name}OriginalNormalizedRegisters : "
        f"{name}NormalizedBehavior.registers = originalBehavior{index}.registers := "
        "by decide\n\n"
        f"theorem {name}CandidateNormalizedRegisters : "
        f"{name}NormalizedBehavior.registers = candidateBehavior{index}.registers := "
        "by decide\n\n"
        f"theorem {name}OriginalNormalizedX87 : "
        f"{name}NormalizedBehavior.x87 = originalBehavior{index}.x87 := by decide\n\n"
        f"theorem {name}CandidateNormalizedX87 : "
        f"{name}NormalizedBehavior.x87 = candidateBehavior{index}.x87 := by decide\n\n"
        f"theorem {name}OriginalNormalizedWrites : "
        f"{name}NormalizedBehavior.writes = originalBehavior{index}.writes := by decide\n\n"
        f"theorem {name}CandidateNormalizedWrites : "
        f"{name}NormalizedBehavior.writes = candidateBehavior{index}.writes := by decide\n\n"
        + empty_writes_fact
    )


def _lean_compositional_normalized_theorem_source(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
    *,
    original_image_base: int,
    candidate_image_base: int,
) -> str | None:
    outcome = _lean_normalized_static_outcome(region, behaviors)
    if outcome is None or "flags := some" not in behaviors["original"]:
        return None

    name = f"region{index}"
    compact_registers = isinstance(behaviors.get("original_ir"), dict)
    theorem_name = f"{name}Checked"
    state_relation = (
        f"statesRelated {original_image_base} {candidate_image_base} {name}.targets {name}.flagInputs "
        f"{name}.bounds {name}.addressSeparations {name}.values {name}.inputs "
        "originalState candidateState"
    )
    setup, flag_hypotheses = _lean_normalized_component_setup(
        index,
        region,
        original_image_base=original_image_base,
        candidate_image_base=candidate_image_base,
    )
    state_preserving_setup, _ = _lean_normalized_component_setup(
        index,
        region,
        original_image_base=original_image_base,
        candidate_image_base=candidate_image_base,
        preserve_states=True,
    )
    agreement_setup, _ = _lean_normalized_component_setup(
        index,
        region,
        original_image_base=original_image_base,
        candidate_image_base=candidate_image_base,
        preserve_flags=True,
        preserve_states=True,
    )
    flag_lemma_line = f"    {flag_hypotheses},\n" if flag_hypotheses else ""
    common_simplifiers = (
        "StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval, "
        "StageA.Formal.MachineState.read32, Memory.read32, "
        "StageA.Formal.MachineState.readX87Word, StageA.Formal.read8AfterWriteValue, "
        "StageA.Formal.X87LoadFormat.byteWidth, StageA.Formal.Registers.get, "
        "normalizeDataAddress, normalizeCodeTarget, normalizeImport, wordsRelated, wordRelated_self, "
        "codePointerRelated, codeAddressMatches, mappedValueRelated"
    )
    if compact_registers:
        common_simplifiers += (
            f", {name}CommonRegisters, {name}CommonX87, {name}CommonWrites"
        )
    empty_writes = all(
        _lean_behavior_field(behaviors.get(side, ""), "writes", "comparison") == "[]"
        for side in ("original", "candidate")
    )
    memory_agreement_proof = (
        f"    · simpa [originalInput, candidateInput] using "
        f"Eq.symm {name}NormalizedMemoryIdentity\n"
        if region.get("values") else
        "    · rfl\n"
    )
    state_agreement_proof = (
        f"  have stateAgreement : MachineStateAgreement {name}.flagInputs "
        "originalInput candidateInput := by\n"
        "    constructor\n"
        "    · rfl\n"
        + memory_agreement_proof
        + "    · rfl\n    · rfl\n    · rfl\n"
        "    · intro bit contains\n"
        f"      exact flagsRelated_of_contains {name}.flagInputs originalFlags "
        "candidateFlags flagsRelatedAll contains\n"
    )
    direct_agreement_setup, _ = _lean_normalized_component_setup(
        index,
        region,
        original_image_base=original_image_base,
        candidate_image_base=candidate_image_base,
        preserve_flags=True,
    )
    state_agreement_theorem = (
        f"theorem {name}MachineStateAgreement (originalState candidateState : MachineState)\n"
        f"    (related : {state_relation}) :\n"
        f"    MachineStateAgreement {name}.flagInputs originalState candidateState := by\n"
        + direct_agreement_setup
        + "  constructor\n"
        + "  · rfl\n  · rfl\n  · rfl\n  · rfl\n  · rfl\n"
        + "  · intro bit contains\n"
        + f"    exact flagsRelated_of_contains {name}.flagInputs originalFlags "
        + "candidateFlags flagsRelatedAll contains\n\n"
    )
    empty_writes_fact = (
        f"theorem {name}OriginalWritesEmpty : "
        f"originalBehavior{index}.writes = [] := by rfl\n\n"
        if empty_writes else ""
    )
    writes_component_proof = (
        f"  simp only [NormalizedSymbolicBehavior.eval_writes, {name}NormalizedWrites]\n"
        f"  rw [{name}OriginalWritesEmpty]\n"
        "  rfl\n"
        if empty_writes else
        (
            f"  have writesEqual : ({name}NormalizedBehavior.eval originalInput).writes =\n"
            f"      ({name}NormalizedBehavior.eval candidateInput).writes := by\n"
            f"    simp only [NormalizedSymbolicBehavior.eval_writes, {name}NormalizedWrites]\n"
            "    first\n"
            "    | rfl\n"
            f"    | simp [evalNormalizedWrites, {common_simplifiers},\n"
            + flag_lemma_line
            + f"        originalInput, candidateInput, originalBehavior{index}, {name}]\n"
            "      all_goals first | rfl | bv_normalize\n"
            "  rw [writesEqual]\n"
            "  apply writesRelated_self\n"
        )
    )
    branch_parts = _lean_normalized_branch_parts(outcome)
    indirect_call_parts = _lean_normalized_indirect_call_parts(outcome)
    if branch_parts is None and indirect_call_parts is None:
        normalized_outcome = outcome
        outcome_facts = ""
        outcome_component_setup = ""
        outcome_component_proof = (
            f"  simp [NormalizedSymbolicBehavior.eval_outcome, {name}NormalizedOutcome,\n"
            "    NormalizedOutcomeExpr.eval, outcomesRelated]\n"
        )
    elif branch_parts is not None:
        condition, taken, fallthrough = branch_parts
        normalized_outcome = (
            f"StageA.Relational.NormalizedOutcomeExpr.branch "
            f"{name}OutcomeCondition {taken} {fallthrough}"
        )
        outcome_facts = (
            f"def {name}OutcomeCondition : BoolExpr := {condition}\n\n"
            f"theorem {name}OutcomeConditionWithin :\n"
            f"    {name}OutcomeCondition.flagsWithin {name}.flagInputs = true := by decide\n\n"
        )
        outcome_component_setup = agreement_setup
        outcome_component_proof = (
            state_agreement_proof
            +
            f"  have outcomeRelated := outcomesRelated_normalized_branch_of_agreement\n"
            f"    {original_image_base} {candidate_image_base} {name}.targets {name}.values\n"
            f"    {name}.flagInputs {name}OutcomeCondition {taken} {fallthrough}\n"
            f"    originalInput candidateInput {name}OutcomeConditionWithin stateAgreement\n"
            f"  rw [NormalizedSymbolicBehavior.eval_outcome, "
            f"NormalizedSymbolicBehavior.eval_outcome, {name}NormalizedOutcome]\n"
            f"  exact outcomeRelated\n"
        )
    else:
        assert indirect_call_parts is not None
        _, continuation = indirect_call_parts
        normalized_outcome = (
            f"StageA.Relational.NormalizedOutcomeExpr.indirectCall "
            f"{name}OutcomeTarget {continuation}"
        )
        outcome_facts = ""
        outcome_component_setup = ""
        outcome_component_proof = (
            f"  exact normalizedBehaviorOutcomeRelated_indirectCall_of_agreement\n"
            f"    {original_image_base} {candidate_image_base} {name}.targets {name}.values\n"
            f"    {name}.flagInputs {name}NormalizedBehavior {name}OutcomeTarget {continuation}\n"
            f"    originalState candidateState {name}NormalizedOutcome\n"
            f"    {name}OutcomeTargetWithin\n"
            f"    ({name}MachineStateAgreement originalState candidateState related)\n"
        )

    definitions = state_agreement_theorem if compact_registers else ""
    register_names = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    compact_register_proof = ""
    if compact_registers:
        compact_register_proof = (
            "  intro originalState candidateState related\n"
            + f"  have stateAgreement := {name}MachineStateAgreement originalState "
            + "candidateState related\n"
            + f"  simp only [NormalizedSymbolicBehavior.eval_registers, "
            + f"{name}NormalizedRegisters, evalNormalizedRegisters]\n"
            + "  apply Registers.eq_of_fields\n"
            + "".join(
                f"  · exact Expr.eval_eq_of_flagsWithin {name}.flagInputs originalState candidateState\n"
                f"        {name}Register{register.capitalize()} {name}Register{register.capitalize()}Within stateAgreement\n"
                for register in register_names
            )
        )

    component_specs = (
        (
            "Registers",
            f"registersRelatedValues {original_image_base} {candidate_image_base} {name}.targets {name}.values "
            f"{name}.outputs ({name}NormalizedBehavior.eval originalState).registers "
            f"({name}NormalizedBehavior.eval candidateState).registers = true",
            compact_register_proof or (
            f"  have registersEqual : ({name}NormalizedBehavior.eval originalInput).registers =\n"
            f"      ({name}NormalizedBehavior.eval candidateInput).registers := by\n"
            f"    simp only [NormalizedSymbolicBehavior.eval_registers, {name}NormalizedRegisters]\n"
            "    first\n"
            "    | rfl\n"
            f"    | simp [evalNormalizedRegisters, {common_simplifiers},\n"
            + flag_lemma_line
            + f"        originalInput, candidateInput, originalBehavior{index}, {name}]\n"
            "      all_goals first | rfl | bv_normalize\n"
            "  rw [registersEqual]\n"
            "  apply registersRelatedValues_self_of_identity\n"
            "  decide\n"),
        ),
        (
            "X87",
            f"({name}NormalizedBehavior.eval originalState).x87 = "
            f"({name}NormalizedBehavior.eval candidateState).x87",
            f"  simp only [NormalizedSymbolicBehavior.eval_x87, {name}NormalizedX87]\n"
            f"  simp [evalNormalizedX87, {common_simplifiers},\n"
            + flag_lemma_line
            + f"    originalBehavior{index}, {name}]\n"
            "  all_goals first | rfl | bv_normalize\n",
        ),
        (
            "Writes",
            f"writesRelated {original_image_base} {candidate_image_base} {name}.targets {name}.values "
            f"({name}NormalizedBehavior.eval originalState).writes "
            f"({name}NormalizedBehavior.eval candidateState).writes = true",
            writes_component_proof,
        ),
        (
            "Outcome",
            f"outcomesRelated {original_image_base} {candidate_image_base} {name}.targets {name}.values "
            f"({name}NormalizedBehavior.eval originalState).outcome "
            f"({name}NormalizedBehavior.eval candidateState).outcome = true",
            outcome_component_proof,
        ),
    )
    component_theorems: list[str] = []
    for label, goal, proof in component_specs:
        component_theorems.append(
            (
                f"theorem {name}{label}Component (originalState candidateState : MachineState)\n"
                f"    (related : {state_relation}) :\n    {goal} :=\n"
                f"  normalizedBehaviorRegistersRelated_of_eval_eq {original_image_base} "
                f"{candidate_image_base} {name}NormalizedBehavior {name} "
                f"{name}OutputsIdentity (by\n{compact_register_proof}) "
                f"originalState candidateState related\n"
                if label == "Registers" and compact_registers else
                f"theorem {name}{label}Component (originalState candidateState : MachineState)\n"
                f"    (related : {state_relation}) :\n    {goal} := by\n"
                + (
                    "" if label == "Writes" and empty_writes else
                    outcome_component_setup if label == "Outcome" else
                    state_preserving_setup if label in {"Registers", "Writes"} else
                    setup
                )
                + proof
            )
        )

    bit_metadata = {
        0: ("carry", "cf"),
        2: ("parity", "pf"),
        4: ("auxiliary", "af"),
        6: ("zero", "zf"),
        7: ("sign", "sf"),
        10: (None, "df"),
        11: ("overflow", "of"),
    }
    bit_facts: list[str] = []
    bit_components: list[str] = []
    for bit in region.get("flag_outputs", []):
        field, suffix = bit_metadata[bit]
        if compact_registers and field is not None:
            flag_value = f"{name}Flag{field.capitalize()}"
            within_goal = (
                f"flagValueWithin {name}.flagInputs {bit} {flag_value} = true"
            )
            bit_facts.append(
                f"theorem {name}Flag{bit}Within : {within_goal} := by decide\n\n"
                f"theorem {name}CommonFlag{bit}Agreement (original candidate : MachineState)\n"
                f"    (agreement : MachineStateAgreement {name}.flagInputs original candidate) :\n"
                f"    evalFlagBit original {bit} {flag_value} =\n"
                f"      evalFlagBit candidate {bit} {flag_value} :=\n"
                f"  evalFlagBit_eq_of_flagsWithin {name}.flagInputs {bit} original candidate\n"
                f"    {flag_value} {name}Flag{bit}Within agreement\n\n"
                f"theorem {name}NormalizedFlag{bit}Agreement (original candidate : MachineState)\n"
                f"    (agreement : MachineStateAgreement {name}.flagInputs original candidate) :\n"
                f"    ({name}NormalizedBehavior.eval original).eflags.extractLsb' {bit} 1 =\n"
                f"      ({name}NormalizedBehavior.eval candidate).eflags.extractLsb' {bit} 1 := by\n"
                f"  apply NormalizedSymbolicBehavior.eval_flag_eq_of_some_field\n"
                f"    {name}NormalizedBehavior {name}CommonFlags {flag_value} original candidate {bit}\n"
                f"    {name}NormalizedFlags\n"
                f"  · intro state\n"
                f"    rw [FlagsExpr.eval_extract_{suffix}]\n"
                f"    rfl\n"
                f"  · exact {name}CommonFlag{bit}Agreement original candidate agreement\n\n"
            )
        else:
            within_goal = (
                f"{name}.flagInputs.contains 10 = true"
                if field is None else
                f"flagValueWithin {name}.flagInputs {bit} {name}CommonFlags.{field} = true"
            )
            bit_facts.append(
                f"theorem {name}Flag{bit}Within : {within_goal} := by decide\n\n"
                f"theorem {name}CommonFlag{bit}Agreement (original candidate : MachineState)\n"
                f"    (agreement : MachineStateAgreement {name}.flagInputs original candidate) :\n"
                f"    ({name}CommonFlags.eval original).extractLsb' {bit} 1 =\n"
                f"      ({name}CommonFlags.eval candidate).extractLsb' {bit} 1 :=\n"
                f"  FlagsExpr.eval_{suffix}_eq_of_flagsWithin {name}.flagInputs original candidate\n"
                f"    {name}CommonFlags {name}Flag{bit}Within agreement\n\n"
                f"theorem {name}NormalizedFlag{bit}Agreement (original candidate : MachineState)\n"
                f"    (agreement : MachineStateAgreement {name}.flagInputs original candidate) :\n"
                f"    ({name}NormalizedBehavior.eval original).eflags.extractLsb' {bit} 1 =\n"
                f"      ({name}NormalizedBehavior.eval candidate).eflags.extractLsb' {bit} 1 :=\n"
                f"  NormalizedSymbolicBehavior.eval_flag_eq_of_some {name}NormalizedBehavior {name}CommonFlags\n"
                f"    original candidate {bit} {name}NormalizedFlags\n"
                f"    ({name}CommonFlag{bit}Agreement original candidate agreement)\n\n"
            )
        bit_setup, _ = _lean_normalized_component_setup(
            index,
            region,
            original_image_base=original_image_base,
            candidate_image_base=candidate_image_base,
            preserve_flags=True,
            preserve_states=True,
        )
        if not compact_registers:
            bit_components.append(
                f"theorem {name}Flag{bit}Component (originalState candidateState : MachineState)\n"
                f"    (related : {state_relation}) :\n"
                f"    ({name}NormalizedBehavior.eval originalState).eflags.extractLsb' {bit} 1 =\n"
                f"      ({name}NormalizedBehavior.eval candidateState).eflags.extractLsb' {bit} 1 := by\n"
                + bit_setup
                + state_agreement_proof
                +
                f"  simpa only [originalInput, candidateInput] using\n"
                f"    {name}NormalizedFlag{bit}Agreement originalInput candidateInput stateAgreement\n\n"
            )

    bit_component_names = [
        f"{name}Flag{bit}Component originalState candidateState related"
        for bit in region.get("flag_outputs", [])
    ]
    output_bits = list(region.get("flag_outputs", []))
    original_flags = f"({name}NormalizedBehavior.eval originalState).eflags"
    candidate_flags = f"({name}NormalizedBehavior.eval candidateState).eflags"
    flags_proof = f"flagsRelated_nil {original_flags} {candidate_flags}"
    for bit_index in range(len(output_bits) - 1, -1, -1):
        bit = output_bits[bit_index]
        tail = ", ".join(str(value) for value in output_bits[bit_index + 1:])
        flags_proof = (
            f"flagsRelated_cons_of_eq {bit} [{tail}] {original_flags} {candidate_flags} "
            f"({bit_component_names[bit_index]}) ({flags_proof})"
        )
    if compact_registers:
        if output_bits:
            member_cases = (
                f"    rw [{name}FlagOutputs] at member\n"
                "    simp only [List.mem_cons, List.not_mem_nil, or_false] at member\n"
            )
            if len(output_bits) == 1:
                member_cases += (
                    "    subst bit\n"
                    f"    exact {name}NormalizedFlag{output_bits[0]}Agreement "
                    "originalState candidateState stateAgreement\n"
                )
            else:
                member_cases += (
                    "    rcases member with "
                    + " | ".join("rfl" for _ in output_bits)
                    + "\n"
                    + "".join(
                        f"    · exact {name}NormalizedFlag{bit}Agreement "
                        "originalState candidateState stateAgreement\n"
                        for bit in output_bits
                    )
                )
        else:
            member_cases = (
                f"    rw [{name}FlagOutputs] at member\n"
                "    simp at member\n"
            )
        flags_component = (
            f"theorem {name}FlagsComponent (originalState candidateState : MachineState)\n"
            f"    (related : {state_relation}) :\n"
            f"    StageA.Relational.flagsRelated {name}.flagOutputs\n"
            f"      ({name}NormalizedBehavior.eval originalState).eflags\n"
            f"      ({name}NormalizedBehavior.eval candidateState).eflags = true :=\n"
            f"  normalizedBehaviorFlagsRelated_of_output_bits {original_image_base} "
            f"{candidate_image_base} {name}NormalizedBehavior {name} (by\n"
            "    intro originalState candidateState related bit member\n"
            f"    have stateAgreement := {name}MachineStateAgreement originalState "
            "candidateState related\n"
            + member_cases
            + "  ) originalState candidateState related\n\n"
        )
    else:
        flags_component = (
            f"theorem {name}FlagsComponent (originalState candidateState : MachineState)\n"
            f"    (related : {state_relation}) :\n"
            f"    StageA.Relational.flagsRelated {name}.flagOutputs\n"
            f"      ({name}NormalizedBehavior.eval originalState).eflags\n"
            f"      ({name}NormalizedBehavior.eval candidateState).eflags = true := by\n"
            f"  change StageA.Relational.flagsRelated [{', '.join(str(bit) for bit in output_bits)}] "
            f"{original_flags} {candidate_flags} = true\n"
            f"  exact {flags_proof}\n\n"
        )

    direct = (
        f"theorem {theorem_name}DirectBehavior : behaviorsEquivalent {original_image_base} {candidate_image_base} "
        f"originalBehavior{index} candidateBehavior{index} {name} :=\n"
        f"  behaviorsEquivalent_of_normalized_components {original_image_base} {candidate_image_base} "
        f"originalBehavior{index} candidateBehavior{index} {name}NormalizedBehavior {name}\n"
        f"    {name}OriginalNormalized {name}CandidateNormalized {name}RegistersComponent\n"
        f"    {name}X87Component {name}WritesComponent {name}FlagsComponent {name}OutcomeComponent\n"
    )
    return (
        definitions
        + "".join(bit_facts)
        + "\n".join(component_theorems)
        + "\n"
        + "".join(bit_components)
        + flags_component
        + direct
    )

def _lean_region_theorem_source(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
    *,
    original_image_base: int,
    candidate_image_base: int,
    replay: bool,
    certificate: dict[str, Any] | None,
) -> str:
    name = f"region{index}"
    theorem_name = f"{name}Checked"
    if _has_compositional_normalized_support(region, behaviors):
        compositional = _lean_compositional_normalized_theorem_source(
            index,
            region,
            behaviors,
            original_image_base=original_image_base,
            candidate_image_base=candidate_image_base,
        )
        if compositional is not None:
            return compositional
    memory_lemmas = ", ".join(
        _lean_region_memory_lemma_names(index, region, behaviors)
    )
    memory_lemma_line = f"    {memory_lemmas},\n" if memory_lemmas else ""
    memory_normalizer_line = (
        "    normalizeDataAddress, valueTargetContainsCandidate,\n"
        if region.get("values") and not _lean_region_indexed_memory_lemma_specs(region) else ""
    )
    bound_setup = _lean_region_bound_setup(index, region, behaviors)
    flag_setup, flag_hypotheses = _lean_region_flag_setup(index, region)
    flag_lemma_line = f"    {flag_hypotheses},\n" if flag_hypotheses else ""
    normalized_flag_simplifiers = f", {flag_hypotheses}" if flag_hypotheses else ""
    relocation_memory_setup = _lean_region_relocation_memory_setup(
        index, region, behaviors
    )
    separation_setup, separation_hypotheses = _lean_region_separation_setup(index, region)
    separation_lemma_line = (
        f"    {separation_hypotheses},\n" if separation_hypotheses else ""
    )
    indexed_memory_facts = _lean_region_indexed_memory_fact_names(index, region)
    index_mask_facts = [
        f"region{index}IndexMaskFact{mask_index}"
        for mask_index in range(len(_lean_region_index_masks(region, behaviors)))
    ]
    indexed_memory_rewrite = (
        (
            f"  all_goals try simp only [{', '.join(index_mask_facts)}]\n"
            if index_mask_facts else ""
        )
        + f"  all_goals try simp only [{', '.join(indexed_memory_facts)}]\n"
        + "  all_goals try simp\n"
        if indexed_memory_facts else ""
    )
    has_relocation_word_facts = bool(
        _lean_region_static_relocation_word_specs(region, behaviors)
        or _lean_region_indexed_relocation_word_specs(region)
    )
    word_relation_simplifiers = (
        "wordRelated_self"
        if has_relocation_word_facts else
        "wordRelated, codePointerRelated, codeAddressMatches, mappedValueRelated"
    )
    memory_read_simplifiers = (
        "machineStateRead32_eq_memoryRead32, assembledMemoryRead32_eq, "
        "assembledMemoryRead32OfNat_eq"
        if has_relocation_word_facts else
        "StageA.Formal.MachineState.read32, Memory.read32"
    )
    flag_eval_simplifiers = (
        "StageA.Formal.FlagsExpr.eval_extract_cf, "
        "StageA.Formal.FlagsExpr.eval_extract_pf, "
        "StageA.Formal.FlagsExpr.eval_extract_af, "
        "StageA.Formal.FlagsExpr.eval_extract_zf, "
        "StageA.Formal.FlagsExpr.eval_extract_sf, "
        "StageA.Formal.FlagsExpr.eval_extract_df, "
        "StageA.Formal.FlagsExpr.eval_extract_of, StageA.Formal.evalFlagBit"
    )
    if replay:
        if certificate and certificate.get("kind") == "lrat":
            tactic = f"bv_check \"../../certificates/{certificate['path']}\""
        elif certificate and certificate.get("kind") == "lean_normalization":
            tactic = "bv_normalize"
        else:
            tactic = "fail_if_success trivial"
    else:
        tactic = "bv_decide? (config := { timeout := 120, trimProofs := false })"
    relocation_bridge_tactics = "".join(
        f" | (rw [← {name}RelocationOriginalRead32Static{relocation_index}, "
        f"← {name}RelocationCandidateRead32Static{relocation_index}] at "
        f"{name}RelocationWordRelatedStatic{relocation_index}; exact "
        f"{name}RelocationWordRelatedStatic{relocation_index})"
        for relocation_index, _ in enumerate(
            _lean_region_static_relocation_word_specs(region, behaviors)
        )
    )
    input_hypotheses = [f"inputRelated{pair_index}" for pair_index in range(len(region["inputs"]))]
    relation_destructure = (
        "  rcases related with ⟨" + ", ".join(input_hypotheses) + "⟩\n"
        if len(input_hypotheses) > 1 else ""
    )
    substitutions = "".join(f"  subst c{pair['candidate']}\n" for pair in region["inputs"])
    normalized_fast_path = _normalized_behavior_fast_path(region, behaviors)
    normalized_theorem = (
        f"theorem {name}NormalizedBehavior : "
        f"normalizeSymbolicBehavior false {name}.targets originalBehavior{index} = "
        f"normalizeSymbolicBehavior true {name}.targets candidateBehavior{index} := by decide\n\n"
        f"theorem {name}NormalizedBehaviorExists : "
        f"(normalizeSymbolicBehavior false {name}.targets originalBehavior{index}).isSome := by decide\n\n"
        if normalized_fast_path else ""
    )
    proof_steps = (
        "  unfold evalBehavior\n"
        f"  rw [← {name}NormalizedBehavior]\n"
        f"  cases normalized : normalizeSymbolicBehavior false {name}.targets originalBehavior{index} with\n"
        f"  | none => simpa [normalized] using {name}NormalizedBehaviorExists\n"
        "  | some behavior =>\n"
        "    simp [normalized, NormalizedSymbolicBehavior.eval, NormalizedOutcomeExpr.eval, "
        f"registersRelatedValues, writesRelated_self, outcomesRelated_self, "
        f"StageA.Relational.flagsRelated, "
        f"wordRelated{normalized_flag_simplifiers}, {name}]\n"
        if normalized_fast_path else (
            "  simp [evalBehavior, evalBehaviorRegisters, evalBehaviorX87, evalBehaviorWrites, "
            "evalBehaviorFlags, evalBehaviorOutcome, normalizeSymbolicBehavior, normalizeOutcomeExpr, "
            "NormalizedSymbolicBehavior.eval, NormalizedOutcomeExpr.eval, "
            "evalNormalizedRegisters, evalNormalizedX87, evalNormalizedWrites, evalNormalizedFlags, "
            "StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval, "
            f"{flag_eval_simplifiers},\n"
            f"    {memory_read_simplifiers}, StageA.Formal.MachineState.readX87Word,\n"
            "    StageA.Formal.read8AfterWriteValue, BitVec.add_assoc,\n"
            "    StageA.Formal.X87LoadFormat.byteWidth, registersRelated, registersRelatedValues,\n"
            "    StageA.Formal.Registers.get, StageA.Formal.Registers.set, normalizeCodeTarget, normalizeImport,\n"
            f"    writesRelated, wordsRelated, outcomesRelated, "
            f"StageA.Relational.flagsRelated, "
            f"{word_relation_simplifiers},\n"
            + memory_normalizer_line
            + memory_lemma_line
            + separation_lemma_line
            + flag_lemma_line
            + f"    originalBehavior{index}, candidateBehavior{index}, {name}]\n"
            + indexed_memory_rewrite
            + f"  all_goals first | rfl{relocation_bridge_tactics} "
            f"| (split <;> simp_all) | {tactic}\n"
        )
    )
    direct_state_setup = (
        "  unfold statesRelated StateRelCore at related\n"
        "  simp only [registerRelationsHold_exactRegisterRelations] at related\n"
        "  rcases originalState with ⟨⟨oeax, oebx, oecx, oedx, oesi, oedi, oebp, oesp⟩, originalMemory, originalUndefined, originalX87, originalX87Physical, originalX87Semantics, originalFlags, originalFsBase⟩\n"
        "  rcases candidateState with ⟨⟨ceax, cebx, cecx, cedx, cesi, cedi, cebp, cesp⟩, candidateMemory, candidateUndefined, candidateX87, candidateX87Physical, candidateX87Semantics, candidateFlags, candidateFsBase⟩\n"
        "  rcases related with ⟨related, boundsSatisfied, separationsSatisfied, memoryRelated, undefinedRelated, x87Related, flagsRelated, fsBaseRelated⟩\n"
    )
    direct_state_equalities = (
        "  change originalUndefined = candidateUndefined at undefinedRelated\n  subst candidateUndefined\n"
        "  change originalX87 = candidateX87 ∧ originalX87Physical = candidateX87Physical ∧ originalX87Semantics = candidateX87Semantics at x87Related\n  rcases x87Related with ⟨rfl, rfl, rfl⟩\n"
        + flag_setup
        + "  change originalFsBase = candidateFsBase at fsBaseRelated\n  subst candidateFsBase\n"
        f"  simp [registersRelated, StageA.Formal.Registers.get, {name}] at related\n"
        + relation_destructure
        + substitutions
        + f"  simp [StageA.Relational.boundsRelated, StageA.Relational.boundValue, evalExprPure, StageA.Formal.Registers.get, {name}] at boundsSatisfied\n"
    )
    direct_setup_base_without_memory = direct_state_setup + direct_state_equalities
    direct_setup_base = (
        direct_state_setup
        + _lean_region_memory_setup(
            index, region, str(original_image_base), str(candidate_image_base),
        )
        + direct_state_equalities
    )
    direct_setup = (
        direct_setup_base
        + bound_setup
        + relocation_memory_setup
        + separation_setup
    )
    if not normalized_fast_path and not replay:
        components = (
            ("Registers", "behaviorRegistersEquivalent"),
            ("X87", "behaviorX87Equivalent"),
            ("Writes", "behaviorWritesEquivalent"),
            ("Flags", "behaviorFlagsEquivalent"),
            ("Outcome", "behaviorOutcomeEquivalent"),
        )
        x87_proof_steps = proof_steps
        for omitted in (memory_lemma_line, separation_lemma_line, indexed_memory_rewrite):
            if omitted:
                x87_proof_steps = x87_proof_steps.replace(omitted, "")
        x87_state_only = _lean_x87_state_only_pair(behaviors)
        memory_free_fields = {
            "Registers": ("registers", "x87"),
            "Writes": ("writes", "comparison"),
            "Flags": ("flags", "outcome"),
        }
        memory_free_component_proofs = {
            "Registers": (
                "  simp [evalNormalizedRegisters, StageA.Formal.Expr.eval, "
                "registersRelatedValues, StageA.Formal.Registers.get, "
                "wordRelated, codePointerRelated, codeAddressMatches, "
                "mappedValueRelated, normalizeDataAddress, valueTargetContainsCandidate,\n"
                + flag_lemma_line
                + f"    originalBehavior{index}, candidateBehavior{index}, {name}]\n"
                f"  all_goals first | rfl | (split <;> simp_all) | {tactic}\n"
            ),
            "Writes": (
                "  simp [evalNormalizedWrites, StageA.Formal.Expr.eval, "
                "StageA.Formal.X87Expr.eval, "
                "writesRelated, wordsRelated, StageA.Formal.Registers.get, "
                "wordRelated, codePointerRelated, codeAddressMatches, "
                "mappedValueRelated, normalizeDataAddress, valueTargetContainsCandidate,\n"
                + flag_lemma_line
                + f"    originalBehavior{index}, candidateBehavior{index}, {name}]\n"
                f"  all_goals first | rfl | (split <;> simp_all) | {tactic}\n"
            ),
            "Flags": (
                "  simp [evalNormalizedFlags, StageA.Formal.Expr.eval, "
                "StageA.Formal.BoolExpr.eval, "
                f"{flag_eval_simplifiers}, StageA.Relational.flagsRelated, "
                "StageA.Formal.Registers.get,\n"
                + flag_lemma_line
                + f"    originalBehavior{index}, candidateBehavior{index}, {name}]\n"
                f"  all_goals first | rfl | (split <;> simp_all) | {tactic}\n"
            ),
        }
        identical_writes_component = _lean_identical_state_only_writes_component(
            index, region, behaviors
        )
        component_sources: list[str] = []
        for label, predicate in components:
            if (
                label == "Flags"
                and region.get("flag_outputs") == [10]
                and 10 in region.get("flag_inputs", [])
            ):
                component_sources.append(
                    f"theorem {name}{label}DirectComponent : {predicate} "
                    f"{original_image_base} {candidate_image_base} "
                    f"originalBehavior{index} candidateBehavior{index} {name} :=\n"
                    f"  behaviorFlagsEquivalent_df {original_image_base} "
                    f"{candidate_image_base} originalBehavior{index} "
                    f"candidateBehavior{index} {name} (by decide) (by decide)\n\n"
                )
                continue
            source = (
                f"theorem {name}{label}DirectComponent : {predicate} "
                f"{original_image_base} {candidate_image_base} "
                f"originalBehavior{index} candidateBehavior{index} {name} := by\n"
                f"  unfold {predicate}\n"
                "  intro originalState candidateState related\n"
            )
            if label == "X87" and x87_state_only:
                source += (
                    "  unfold statesRelated StateRelCore at related\n"
                    "  simp only [registerRelationsHold_exactRegisterRelations] at related\n"
                    "  rcases originalState with ⟨⟨oeax, oebx, oecx, oedx, oesi, oedi, "
                    "oebp, oesp⟩, originalMemory, "
                    "originalUndefined, originalX87, originalX87Physical, "
                    "originalX87Semantics, originalFlags, originalFsBase⟩\n"
                    "  rcases candidateState with ⟨⟨ceax, cebx, cecx, cedx, cesi, cedi, "
                    "cebp, cesp⟩, candidateMemory, "
                    "candidateUndefined, candidateX87, candidateX87Physical, "
                    "candidateX87Semantics, candidateFlags, candidateFsBase⟩\n"
                    "  rcases related with ⟨registersRelated, boundsRelated, "
                    "separationsRelated, memoryRelated, undefinedRelated, x87Related, "
                    "flagsRelated, fsBaseRelated⟩\n"
                    "  change originalX87 = candidateX87 ∧ "
                    "originalX87Physical = candidateX87Physical ∧ "
                    "originalX87Semantics = candidateX87Semantics at x87Related\n"
                    "  rcases x87Related with ⟨rfl, rfl, rfl⟩\n"
                    f"  simp [originalBehavior{index}, candidateBehavior{index}, "
                    "evalNormalizedX87, StageA.Formal.X87Expr.eval, "
                    "StageA.Formal.Expr.eval]\n"
                )
            elif label == "Writes" and identical_writes_component is not None:
                source += identical_writes_component
            else:
                field_spec = memory_free_fields.get(label)
                memory_free = bool(
                    field_spec
                    and _lean_behavior_fields_memory_free(
                        behaviors, field_spec[0], field_spec[1]
                    )
                )
                component_setup = (
                    direct_setup_base_without_memory + bound_setup
                    if memory_free else
                    (direct_setup_base if label == "X87" else direct_setup)
                )
                component_proof = x87_proof_steps if label == "X87" else proof_steps
                if memory_free:
                    component_proof = memory_free_component_proofs[label]
                source += component_setup + component_proof
            component_sources.append(source + "\n")
        component_theorems = "".join(component_sources)
        return (
            component_theorems
            + f"theorem {theorem_name}DirectBehavior : behaviorsEquivalent {original_image_base} {candidate_image_base} "
            f"originalBehavior{index} candidateBehavior{index} {name} :=\n"
            f"  behaviorsEquivalent_of_components {original_image_base} {candidate_image_base} "
            f"originalBehavior{index} candidateBehavior{index} {name}\n"
            f"    {name}RegistersDirectComponent {name}X87DirectComponent {name}WritesDirectComponent\n"
            f"    {name}FlagsDirectComponent {name}OutcomeDirectComponent\n"
        )
    return (
        normalized_theorem
        + f"theorem {theorem_name}DirectBehavior : behaviorsEquivalent {original_image_base} {candidate_image_base} originalBehavior{index} candidateBehavior{index} {name} := by\n"
        "  unfold behaviorsEquivalent\n"
        "  intro originalState candidateState related\n"
        + direct_setup
        + proof_steps
    )
