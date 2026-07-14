from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from ...stage_binary import StageABinary, StageAInputError
from ...util import sha256_bytes, write_json
from ..analyses.external import (
    _external_call_site_candidates,
    _semantic_external_target_identity,
)
from ..analyses.registers import _target_shaped_register_output_claims
from ..analyses.stack import _stack_window_transfer_claims
from ..artifacts import write_text_if_changed as _write_text_if_changed
from ..contract import _raw_base_relocations
from ..model import _semantic_hash
from ..schema import (
    FLAG_BITS,
    RELATIONAL_ACCEPTANCE_THEOREM,
    RELATIONAL_KERNEL_MODULES,
)


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
    _lean_region_definition,
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
    _lean_behavior_field,
    _lean_behavior_fields_memory_free,
    _lean_global_mapping_context_source,
    _lean_identical_state_only_writes_component,
    _lean_normalized_branch_parts,
    _lean_normalized_static_outcome,
    _lean_x87_state_only_pair,
    _normalized_behavior_fast_path,
    _normalized_behavior_structure_matches,
    _write_relational_static_context_modules,
)
from .segments import (
    _write_relational_external_call_refinement_modules,
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
from .common import (
    _lean_bool,
    _lean_bytes,
    _lean_code_aliases,
    _lean_register_relation_pair,
    _lean_relation_constructor,
    _sorted_span_certificate,
)
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


def _write_sharded_relational_proof(
    lean_dir: Path,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    original: bytes,
    candidate: bytes,
    contract: dict[str, Any],
    behaviors: list[dict[str, str]],
    *,
    invariant_synthesis: dict[str, Any],
    memory_contracts: dict[str, Any],
    register_relations: dict[str, Any],
    product_graph: dict[str, Any],
    import_register_seeds: list[dict[str, Any]],
    import_register_analysis: dict[str, Any],
    segment_candidates: list[dict[str, Any]],
    replay: bool,
    certificates: list[dict[str, Any]] | None = None,
) -> tuple[list[str], int]:
    certificate_by_region = {entry.get("region_id"): entry for entry in certificates or []}

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
            lean_dir / "StageA" / f"RelationalProof{module_side}.lean",
            _lean_pe_side_source(side, binary, data),
        )
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
    decode_modules: list[str] = []
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
        definition_imports = "\n".join(
            f"import StageA.{definition_modules[shard_index]}"
            for shard_index in selected_shard_indices
        )
        for side in ("original", "candidate"):
            module_side = side.capitalize()
            module = f"RelationalProof{module_side}DecodeChunk{chunk_index}"
            decode_modules.append(module)
            contracts_name = f"{side}MachineImportCallContractsChunk{chunk_index}"
            decode_theorems = "\n\n".join(
                f"theorem {side}Behavior{index}CheckedDecoded : "
                f"regionBehaviorWithMachineCallContracts {side}Pe {side}Imports "
                f"{contracts_name} region{index}.{side} = "
                f"some {side}Behavior{index} := by decide"
                for index in selected_region_indices
            )
            source = (
                f"import StageA.RelationalProof{module_side}\n"
                "import StageA.RelationalMachineImportCallContracts\n"
                + definition_imports
                + "\n\nnamespace StageA.GeneratedRelational\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
                "set_option linter.unusedSimpArgs false\n\n"
                f"def {contracts_name} : List MachineImportCallContract := "
                "machineImportCallContracts\n\n"
                + decode_theorems
                + "\n\nend StageA.GeneratedRelational\n"
            )
            _write_text_if_changed(
                lean_dir / "StageA" / f"{module}.lean",
                source,
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

    external_call_sites = _external_call_site_candidates(
        contract, behaviors, register_relations,
        import_register_analysis["indirect_import_calls"],
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
        f"def externalCallSite{int(site['id'])} : ExternalCallSiteContract := {{\n"
        f"  id := {int(site['id'])}\n"
        f"  sourceTargetId := {int(site['source_target_id'])}\n"
        f"  continuationTargetId := {int(site['continuation_target_id'])}\n"
        f"  machineContractId := {int(site['machine_contract_id'])}\n"
        f"  boundaryInvariant := "
        f"{_lean_state_invariant(site['boundary_invariant'])}\n"
        f"  targetInvariant := "
        f"region{int(site['target_region_index'])}.inputInvariant\n"
        "}"
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
        direct_module = f"RelationalProofDirectChunk{chunk_index}"
        direct_modules.append(direct_module)
        direct_region_chunk = region_chunk_names[chunk_index]
        direct_theorems = "\n\n".join(
            f"theorem region{index}CheckedDirect : regionEquivalentWithImports originalPe candidatePe "
            f"originalImports candidateImports machineImportCallContracts region{index} :=\n"
            f"  regionEquivalentWithImports_of_decoded originalPe candidatePe originalImports candidateImports machineImportCallContracts "
            f"region{index} originalBehavior{index} candidateBehavior{index}\n"
            f"    originalBehavior{index}CheckedDecoded candidateBehavior{index}CheckedDecoded "
            f"region{index}CheckedDirectBehavior"
            for index in region_indices
        )
        direct_chunk_goal = " ∧ ".join(
            [
                f"regionEquivalentWithImports originalPe candidatePe originalImports candidateImports machineImportCallContracts region{index}"
                for index in region_indices
            ]
            + ["True"]
        )
        direct_chunk_proof = (
            "".join(
                f"And.intro region{index}CheckedDirect (" for index in region_indices
            )
            + "True.intro"
            + ")" * len(region_indices)
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
    )
    product_graph_modules = _write_relational_product_graph_modules(
        lean_dir,
        product_graph,
        segment_candidates,
        segment_refinement_modules,
        decode_chunk_regions,
    )
    external_call_refinement_modules = (
        _write_relational_external_call_refinement_modules(
            lean_dir,
            contract,
            behaviors,
            register_relations,
            product_graph,
            decode_chunk_regions,
            import_register_analysis["indirect_import_calls"],
        )
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
            "import StageA.RelationalProofRequiredInputsData\n"
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
            f"theorem relationOutputsChunk{chunk_index}Checked :\n"
            f"    {chunk_name}.all (fun source => requiredInputsCertificate.all source.outputs.contains) = true := by decide\n\n"
            f"theorem flagRelationChunk{chunk_index}Checked :\n"
            f"    {chunk_name}.all (fun source => source.targets.all "
            f"(targetFlagRelationClosed allRegionIndex source)) = true := by decide\n\n"
            f"theorem requiredInputsChunk{chunk_index}Checked :\n"
            f"    requiredInputPairsFrom requiredInputsState{chunk_index} {chunk_name} = "
            f"requiredInputsState{chunk_index + 1} := by decide\n\n"
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
    relation_outputs_proof = _lean_all_append_proof(
        "fun source => requiredInputsCertificate.all source.outputs.contains",
        region_chunk_names,
        [f"relationOutputsChunk{index}Checked" for index in range(len(region_chunk_names))],
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
    required_input_rewrites = ", ".join(
        [
            item
            for index in range(len(region_chunk_names))
            for item in (
                (["requiredInputPairsFrom_append"] if index + 1 < len(region_chunk_names) else [])
                + [f"requiredInputsChunk{index}Checked"]
            )
        ]
    )
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
        "theorem relationOutputsChecked : allRegions.all (fun source => requiredInputsCertificate.all source.outputs.contains) = true := by\n"
        "  unfold allRegions\n"
        f"  exact {relation_outputs_proof}\n\n"
        "theorem requiredInputsChecked : requiredInputPairs allRegions = requiredInputsCertificate := by\n"
        "  unfold requiredInputPairs\n"
        "  change requiredInputPairsFrom requiredInputsState0 allRegions = requiredInputsCertificate\n"
        "  unfold allRegions\n"
        f"  rw [{required_input_rewrites}]\n"
        "  rfl\n\n"
        "theorem relationCompositionChecked : relationCompositionClosed allRegions = true :=\n"
        "  relationCompositionClosed_of_certificate allRegions requiredInputsCertificate requiredInputsChecked relationOutputsChecked\n\n"
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
        "    valuesChecked relationCompositionChecked flagRelationCompositionChecked\n\n"
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

    direct_regions_proof = _lean_direct_append_proof(
        region_chunk_names,
        [f"directRegionChunk{index}Checked" for index in range(len(region_chunk_names))],
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
        "import StageA.RelationalProofClosureBase\n"
        "import StageA.RelationalSegmentRefinementCertificate\n"
        "import StageA.RelationalStackSeparationCertificate\n"
        "import StageA.RelationalProductNodeCoverageCertificate\n"
        "import StageA.RelationalProductReachabilityCertificate\n"
        "import StageA.RelationalProductDecodedControlCertificate\n"
        "import StageA.RelationalReachableProductLocalCertificate\n"
        "import StageA.RelationalImportRegisterSeedCertificate\n"
        "import StageA.RelationalDynamicRangeIndirectCallCertificate\n"
        "import StageA.RelationalExternalCallRefinementCertificate\n"
        + "".join(f"import StageA.{module}\n" for module in direct_modules)
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
        "theorem allDirectRegionsChecked : allDirectRegionGoals originalPe candidatePe originalImports candidateImports machineImportCallContracts allRegions := by\n"
        "  unfold allRegions\n"
        f"  exact {direct_regions_proof}\n\n"
        "theorem allRegionsChecked : allRegionGoals proofBundle proofBundle.regions := by\n"
        "  apply allRegionGoals_of_direct proofBundle originalPe candidatePe originalParsed candidateParsed\n"
        "  exact allDirectRegionsChecked\n\n"
        "theorem regionalRelationalCertificate : RelationalImageCertificate proofBundle :=\n"
        "  relationalImageCertificate_intro proofBundle structuralChecked importsChecked allRegionsChecked\n\n"
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
        "theorem candidateRelationalImageCertificate :\n"
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
        "      RelationalImageCertificate proofBundle ∧ GeneratedInvariantCertificate ∧\n"
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
        "    regionalRelationalCertificate, generatedInvariantCertificateChecked,\n"
        "    generatedMappedRelocationImageCertificateChecked,\n"
        "    generatedStackSeparationCertificateChecked,\n"
        "    generatedOrdinaryMemoryReadPullbackCertificateChecked,\n"
        "    generatedX87LoadPullbackCertificateChecked,\n"
        "    generatedExactRegisterRelationCertificateChecked,\n"
        "    generatedSegmentRefinementCertificateChecked⟩\n\n"
        "#print axioms candidateRelationalImageCertificate\n\nend StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(lean_dir / "StageA" / "RelationalBundle.lean", final)
    _write_relational_acceptance_modules(
        lean_dir,
        contract,
        behaviors,
        product_graph,
        register_relations,
        segment_candidates,
        decode_chunk_regions,
        external_site_candidates,
    )
    return (
        shard_modules
        + [item["module"] for item in stack_separation_modules]
        + [item["module"] for item in invariant_modules]
        + [item["module"] for item in memory_pullback_modules]
        + [item["module"] for item in register_relation_modules],
        shard_size,
    )

def _lean_pe_side_source(side: str, binary: StageABinary, data: bytes) -> str:
    return (
        "import StageA.Formal\n\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal\n\nset_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        + _lean_byte_tree_definitions(f"{side}Bytes", data)
        + "\n\n"
        + f"def {side}Pe : PE32 := {_lean_pe(binary, f'{side}Bytes')}\n\n"
        + f"def {side}ImportCertificate : ImportTableCertificate := {_lean_import_certificate(binary)}\n\n"
        + f"def {side}Imports : List PEImport := {side}ImportCertificate.imports\n\n"
        + f"def {side}Relocations : List BaseRelocation := {_lean_relocations(binary)}\n\n"
        + f"theorem {side}MetadataParsed : parsePEMetadataTree {side}Bytes = some {side}Pe.metadata := by decide\n\n"
        + f"theorem {side}Parsed : parsePE32Tree {side}Bytes = some {side}Pe := by\n"
        + f"  simp [parsePE32Tree, {side}MetadataParsed, PE32.metadata, PEMetadata.toPE32, {side}Pe]\n\n"
        + f"theorem {side}ImportsChecked : importTableValid {side}Pe {side}ImportCertificate = true := by decide\n\n"
        + f"theorem {side}RelocationsParsed : parseRelocations {side}Pe = some {side}Relocations := by decide\n\n"
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
    return (
        aliases
        + "  unfold statesRelated StateRelCore at related\n"
        "  simp only [registerRelationsHold_exactRegisterRelations] at related\n"
        "  rcases originalState with ⟨⟨oeax, oebx, oecx, oedx, oesi, oedi, oebp, oesp⟩, originalMemory, originalUndefined, originalX87, originalFlags, originalFsBase⟩\n"
        "  rcases candidateState with ⟨⟨ceax, cebx, cecx, cedx, cesi, cedi, cebp, cesp⟩, candidateMemory, candidateUndefined, candidateX87, candidateFlags, candidateFsBase⟩\n"
        "  rcases related with ⟨related, boundsSatisfied, separationsSatisfied, memoryRelated, undefinedRelated, x87Related, flagsRelated, fsBaseRelated⟩\n"
        f"  have exactMemory := memoryRelated_without_relocations {original_image_base} {candidate_image_base} "
        f"{name}.targets {name}.values originalMemory candidateMemory (by decide) memoryRelated\n"
        f"  change candidateMemory = fun address => originalMemory (normalizeDataAddress {name}.values address) at exactMemory\n"
        "  subst candidateMemory\n"
        "  change originalUndefined = candidateUndefined at undefinedRelated\n"
        "  subst candidateUndefined\n"
        "  change originalX87 = candidateX87 at x87Related\n"
        "  subst candidateX87\n"
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
    empty_writes = all(
        _lean_behavior_field(behaviors.get(side, ""), "writes", "comparison") == "[]"
        for side in ("original", "candidate")
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
    if branch_parts is None:
        normalized_outcome = outcome
        outcome_facts = ""
        outcome_component_setup = ""
        outcome_component_proof = (
            f"  simp [NormalizedSymbolicBehavior.eval_outcome, {name}NormalizedOutcome,\n"
            "    NormalizedOutcomeExpr.eval, outcomesRelated]\n"
        )
    else:
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
            f"  have stateAgreement : MachineStateAgreement {name}.flagInputs "
            "originalInput candidateInput := by\n"
            "    constructor\n"
            "    · rfl\n    · rfl\n    · rfl\n    · rfl\n    · rfl\n"
            "    · intro bit contains\n"
            f"      exact flagsRelated_of_contains {name}.flagInputs originalFlags "
            "candidateFlags flagsRelatedAll contains\n"
            f"  have outcomeRelated := outcomesRelated_normalized_branch_of_agreement\n"
            f"    {original_image_base} {candidate_image_base} {name}.targets {name}.values\n"
            f"    {name}.flagInputs {name}OutcomeCondition {taken} {fallthrough}\n"
            f"    originalInput candidateInput {name}OutcomeConditionWithin stateAgreement\n"
            f"  simpa only [NormalizedSymbolicBehavior.eval_outcome, "
            f"{name}NormalizedOutcome] using outcomeRelated\n"
        )

    definitions = (
        f"def {name}NormalizedBehavior : NormalizedSymbolicBehavior :=\n"
        f"  (normalizeSymbolicBehavior false {name}.targets originalBehavior{index}).get (by decide)\n\n"
        f"theorem {name}NormalizedRegisters : {name}NormalizedBehavior.registers = originalBehavior{index}.registers := by decide\n\n"
        f"theorem {name}NormalizedX87 : {name}NormalizedBehavior.x87 = originalBehavior{index}.x87 := by decide\n\n"
        f"theorem {name}NormalizedWrites : {name}NormalizedBehavior.writes = originalBehavior{index}.writes := by decide\n\n"
        f"def {name}CommonFlags : FlagsExpr := originalBehavior{index}.flags.get (by decide)\n\n"
        f"theorem {name}NormalizedFlags : {name}NormalizedBehavior.flags = some {name}CommonFlags := by decide\n\n"
        + outcome_facts
        + f"theorem {name}NormalizedOutcome : {name}NormalizedBehavior.outcome = {normalized_outcome} := by decide\n\n"
        f"theorem {name}OriginalNormalized : normalizeSymbolicBehavior false {name}.targets originalBehavior{index} = some {name}NormalizedBehavior := by decide\n\n"
        f"theorem {name}CandidateNormalized : normalizeSymbolicBehavior true {name}.targets candidateBehavior{index} = some {name}NormalizedBehavior := by decide\n\n"
        + empty_writes_fact
    )

    component_specs = (
        (
            "Registers",
            f"registersRelatedValues {original_image_base} {candidate_image_base} {name}.targets {name}.values "
            f"{name}.outputs ({name}NormalizedBehavior.eval originalState).registers "
            f"({name}NormalizedBehavior.eval candidateState).registers = true",
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
            "  decide\n",
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

    bit_metadata = {
        0: ("carry", "cf"),
        2: ("parity", "pf"),
        6: ("zero", "zf"),
        7: ("sign", "sf"),
        10: (None, "df"),
        11: ("overflow", "of"),
    }
    bit_facts: list[str] = []
    bit_components: list[str] = []
    for bit in region.get("flag_outputs", []):
        field, suffix = bit_metadata[bit]
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
        bit_components.append(
            f"theorem {name}Flag{bit}Component (originalState candidateState : MachineState)\n"
            f"    (related : {state_relation}) :\n"
            f"    ({name}NormalizedBehavior.eval originalState).eflags.extractLsb' {bit} 1 =\n"
            f"      ({name}NormalizedBehavior.eval candidateState).eflags.extractLsb' {bit} 1 := by\n"
            + bit_setup
            + f"  have stateAgreement : MachineStateAgreement {name}.flagInputs originalInput candidateInput := by\n"
            "    constructor\n"
            "    · rfl\n    · rfl\n    · rfl\n    · rfl\n    · rfl\n"
            "    · intro bit contains\n"
            f"      exact flagsRelated_of_contains {name}.flagInputs originalFlags candidateFlags flagsRelatedAll contains\n"
            f"  exact {name}NormalizedFlag{bit}Agreement originalInput candidateInput stateAgreement\n\n"
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
    if _normalized_behavior_structure_matches(region, behaviors):
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
        "  rcases originalState with ⟨⟨oeax, oebx, oecx, oedx, oesi, oedi, oebp, oesp⟩, originalMemory, originalUndefined, originalX87, originalFlags, originalFsBase⟩\n"
        "  rcases candidateState with ⟨⟨ceax, cebx, cecx, cedx, cesi, cedi, cebp, cesp⟩, candidateMemory, candidateUndefined, candidateX87, candidateFlags, candidateFsBase⟩\n"
        "  rcases related with ⟨related, boundsSatisfied, separationsSatisfied, memoryRelated, undefinedRelated, x87Related, flagsRelated, fsBaseRelated⟩\n"
    )
    direct_state_equalities = (
        "  change originalUndefined = candidateUndefined at undefinedRelated\n  subst candidateUndefined\n"
        "  change originalX87 = candidateX87 at x87Related\n  subst candidateX87\n"
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
                    "originalUndefined, originalX87, originalFlags, originalFsBase⟩\n"
                    "  rcases candidateState with ⟨⟨ceax, cebx, cecx, cedx, cesi, cedi, "
                    "cebp, cesp⟩, candidateMemory, "
                    "candidateUndefined, candidateX87, candidateFlags, candidateFsBase⟩\n"
                    "  rcases related with ⟨registersRelated, boundsRelated, "
                    "separationsRelated, memoryRelated, undefinedRelated, x87Related, "
                    "flagsRelated, fsBaseRelated⟩\n"
                    "  change originalX87 = candidateX87 at x87Related\n"
                    "  subst candidateX87\n"
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
