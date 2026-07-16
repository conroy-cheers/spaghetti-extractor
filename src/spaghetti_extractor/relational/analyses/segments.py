from __future__ import annotations

import json
from collections import Counter
from typing import Any

from ...stage_binary import StageABinary
from ...util import sha256_bytes
from ..contract import _raw_base_relocations, _semantic_expr_is_pure
from ..diagnostics import (
    _dynamic_pointer_traversal_diagnostic,
    _nonzero_word_guard,
    _static_dynamic_pointer_seed_diagnostic,
)
from ..extraction import _relational_loader_facts
from ..lean.definitions import _lean_x87_state_only_pair
from ..schema import (
    FLAG_BITS,
    RELATIONAL_PROOF_IR_FORMAT,
    RELATIONAL_SEGMENT_CERTIFICATE_FORMAT,
    STAGE_A_RELATIONAL_MODEL_ID,
    STAGE_A_RELATIONAL_PROFILE_ID,
    integer as _integer,
)
from .external import (
    _register_offset_witness,
    _semantic_external_target_identity,
    _semantic_input_register_offset,
)
from .control import _immutable_image_u32
from ..model import (
    _semantic_constant_word,
    _stack_window_transfer_claims,
    _target_shaped_register_output_claims,
)


def _proof_ir(original: StageABinary, candidate: StageABinary, contract: dict[str, Any]) -> dict[str, Any]:
    obligations = [
        {"id": f"relational:{region['id']}", "kind": "relational_region_equivalence", "status": "pending_lrat"}
        for region in contract["regions"]
    ]
    obligations.extend(
        {
            "id": f"invariant:{region['id']}:{bound_index}",
            "kind": "cfg_bound_invariant",
            "status": "incomplete",
            "region_id": region["id"],
            "original_register": bound["original"],
            "candidate_register": bound["candidate"],
            "original_expression": bound.get("original_expression"),
            "candidate_expression": bound.get("candidate_expression"),
            "expression_source": bound.get("expression_source", "entry_register"),
            "unsigned_upper_exclusive": bound["unsigned_lt"],
            "blocker": "bound is a local region precondition and has not been proved inductive on incoming CFG edges",
            "next_action": "prove the bound at roots and preserve it across every reachable predecessor edge",
        }
        for region in contract["regions"]
        for bound_index, bound in enumerate(region.get("bounds", []))
    )
    obligations.extend(
        {
            "id": f"address-separation:{region['id']}",
            "kind": "cfg_address_separation_invariant",
            "status": "incomplete",
            "region_id": region["id"],
            "comparisons": len(region["address_separations"]),
            "blocker": "stack-derived writes are assumed disjoint from relocated image reads but the predicate has not been proved on incoming CFG edges",
            "next_action": "prove image/stack disjointness at roots and preserve each required address separation across reachable predecessor edges",
        }
        for region in contract["regions"]
        if region.get("address_separations")
    )
    obligations.extend(_mapped_relocation_image_obligations(original, candidate, contract))
    obligations.append({
        "id": "static-context:canonical-pe32",
        "kind": "static_proof_context",
        "status": "pending_lean",
        "blocker": (
            "the canonical PE, import, relocation, code/data map, root, and observation "
            "context has not yet been checked by Lean"
        ),
        "next_action": (
            "replay StaticProofContext.valid_of_checked over the exact bundled PE bytes and "
            "the indexed mapping inventories"
        ),
    })
    obligations.append({
        "id": "composition:rooted-product-graph",
        "kind": "product_graph_composition",
        "status": "incomplete",
        "blocker": (
            "the checked regional certificate has not yet been composed through the "
            "complete rooted product graph into the concrete PE execution theorem"
        ),
        "next_action": (
            "close every reachable product edge, invariant, and environment refinement, "
            "then check candidatePE32ProgramsEquivalent"
        ),
    })
    families = [
        {"family": "exact_pe_decode", "status": "incomplete"},
        {"family": "x86_semantics", "status": "incomplete"},
        {"family": "executable_coverage", "status": "incomplete"},
        {"family": "roots_and_targets", "status": "incomplete"},
        {"family": "static_proof_context", "status": "incomplete"},
        {"family": "relational_regions", "status": "incomplete"},
        {"family": "whole_program_composition", "status": "incomplete"},
        {
            "family": "cfg_invariants",
            "status": "incomplete" if any(
                obligation["kind"] in {
                    "cfg_bound_invariant", "cfg_address_separation_invariant",
                }
                for obligation in obligations
            ) else "not_applicable",
        },
        {"family": "memory_relation", "status": "incomplete"},
        {"family": "adversarial_environment", "status": "incomplete"},
    ]
    return {
        "format": RELATIONAL_PROOF_IR_FORMAT,
        "status": "incomplete",
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "claim_scope": {
            "kind": "relational_region_certificate",
            "whole_program_observational_equivalence": False,
        },
        "original": _relational_loader_facts(original),
        "candidate": _relational_loader_facts(candidate),
        "environment": contract["environment"],
        "observations": contract["observations"],
        "memory_relation": contract["memory_relation"],
        "relation_contract_sha256": sha256_bytes(json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()),
        "counts": {"regions": len(contract["regions"]), "code_targets": len(contract["code_targets"]), "padding": len(contract["padding"])},
        "families": families,
        "obligations": obligations,
    }

def _mapped_relocation_image_obligations(
    original: StageABinary,
    candidate: StageABinary,
    contract: dict[str, Any],
) -> list[dict[str, Any]]:
    relocation_rvas: dict[str, set[int]] = {}
    for side, binary in (("original", original), ("candidate", candidate)):
        relocation_rvas[side] = {
            relocation["rva"]
            for relocation in _raw_base_relocations(binary)
            if relocation["type"] == 3
        }
    obligations: list[dict[str, Any]] = []
    for region in contract["regions"]:
        for target in region.get("values", []):
            if target["mapped_size"] < 4:
                continue
            original_base = target["original_value"] - original.image_base
            candidate_base = target["candidate_value"] - candidate.image_base
            differing_cells = []
            for offset in range(0, target["mapped_size"] - 3):
                original_rva = original_base + offset
                candidate_rva = candidate_base + offset
                if (
                    original_rva not in relocation_rvas["original"]
                    or candidate_rva not in relocation_rvas["candidate"]
                ):
                    continue
                original_word = int(original.pe.get_dword_at_rva(original_rva) or 0)
                candidate_word = int(candidate.pe.get_dword_at_rva(candidate_rva) or 0)
                if original_word != candidate_word:
                    differing_cells.append({
                        "offset": offset,
                        "original_rva": original_rva,
                        "candidate_rva": candidate_rva,
                        "original_word": original_word,
                        "candidate_word": candidate_word,
                    })
            if not differing_cells:
                continue
            obligations.append({
                "id": f"memory:{region['id']}:{target['id']}",
                "kind": "mapped_relocation_image_relation",
                "status": "pending_lean",
                "region_id": region["id"],
                "value_target_id": target["id"],
                "differing_relocation_cells": differing_cells,
                "claim": (
                    "the exact original and candidate PE section images have matching HIGHLOW "
                    "relocation cells whose dword contents satisfy wordRelated"
                ),
                "next_action": (
                    "check valueTargetValid from both exact PE images and expose the result as "
                    "AllMappedRelocationImageRelations"
                ),
            })
    return obligations

def _attach_register_relation_analysis(
    proof_ir: dict[str, Any], register_relations: dict[str, Any]
) -> dict[str, Any]:
    counts = register_relations["counts"]
    total_register_outputs = sum(
        len(region.get("outputs", []))
        for region in register_relations.get("regions", [])
    )
    unclaimed_outputs = total_register_outputs - counts["register_output_claims"]
    obligation = {
        "id": "cfg-register-relation-preservation",
        "kind": "cfg_register_relation_preservation",
        "status": "incomplete",
        "analysis": {
            **counts,
            "total_register_outputs": total_register_outputs,
            "unclaimed_register_outputs": unclaimed_outputs,
            "checked_claim_types": [
                "exact_memory_free_expression",
                "exact_identity_memory_expression_when_global_value_map_empty",
                "identity_register_transfer",
                "paired_constant_relation",
                "exact_register_edge_pair",
                "win32_external_register_policy_edge",
            ],
            "generated_certificate": (
                "StageA.GeneratedRelational."
                "GeneratedExactRegisterRelationCertificate"
            ),
        },
        "blocker": (
            f"{unclaimed_outputs} register outputs, mixed-relation direct edges, and explicit "
            "external-environment result compatibility remain open"
        ),
        "next_action": (
            "add generic checked mapped-memory and pointer-arithmetic transfer rules, then "
            "instantiate the checked Win32 register policy with a relational environment contract"
        ),
    }
    call_return_obligations = [
        {
            "id": (
                "call-return:"
                f"{edge['callsite_region_index']}:"
                f"{edge['source_region_index']}:"
                f"{edge['target_region_index']}"
            ),
            "kind": "call_return_stack_composition",
            "status": "incomplete",
            "callsite_region_index": edge["callsite_region_index"],
            "callee_entry_region_index": edge["callee_entry_region_index"],
            "return_region_index": edge["source_region_index"],
            "continuation_region_index": edge["target_region_index"],
            "function_id": edge["function_id"],
            "blocker": (
                "function metadata proposes a return-to-continuation edge, but Lean has not "
                "proved call-stack membership and mapped return-address resolution"
            ),
            "next_action": (
                "check the caller/callee/return decoded outcomes, prove the return target "
                "resolves to the pushed continuation, and preserve the global state relation"
            ),
        }
        for edge in register_relations["edges"]
        if edge.get("requires_call_stack_proof")
    ]
    direct_call_push_obligations = [
        {
            "id": (
                "direct-call-push:"
                f"{edge['source_region_index']}:{edge['target_region_index']}"
            ),
            "kind": "direct_call_push",
            "status": (
                "candidate_requires_lean_replay"
                if edge.get("direct_call_push_claim") is not None
                else "incomplete"
            ),
            "source_region_index": edge["source_region_index"],
            "callee_region_index": edge["target_region_index"],
            "claim": edge.get("direct_call_push_claim"),
            "blocker": (
                None if edge.get("direct_call_push_claim") is not None else
                "decoded call does not have one unique mapped continuation and final "
                "ESP-relative mapped return-address write"
            ),
            "next_action": (
                "replay DirectCallPushClosed in Lean"
                if edge.get("direct_call_push_claim") is not None else
                "inspect the decoded call target, continuation map, final ESP expression, "
                "and last stack write"
            ),
        }
        for edge in register_relations["edges"]
        if edge["kind"] == "call" and not edge.get("indirect_target_profile")
    ]
    indirect_call_push_obligations = [
        {
            "id": (
                "indirect-call-push:"
                f"{edge['source_region_index']}:{edge['target_region_index']}"
            ),
            "kind": "indirect_call_push",
            "status": (
                "candidate_requires_lean_replay"
                if edge.get("indirect_call_push_claim") is not None
                else "incomplete"
            ),
            "source_region_index": edge["source_region_index"],
            "callee_region_index": edge["target_region_index"],
            "claim": edge.get("indirect_call_push_claim"),
            "blocker": (
                None if edge.get("indirect_call_push_claim") is not None else
                "decoded indirect call lacks one mapped continuation and final "
                "ESP-relative mapped return-address write"
            ),
            "next_action": (
                "replay IndirectCallPushClaim.checked in Lean"
                if edge.get("indirect_call_push_claim") is not None else
                "inspect the continuation map, final ESP expression, and last stack write"
            ),
        }
        for edge in register_relations["edges"]
        if edge.get("indirect_target_profile") ==
            "immutable_relocated_function_pointer_call_v1"
    ]
    return_pop_obligations = [
        {
            "id": f"return-pop:{region['region_index']}",
            "kind": "return_pop",
            "status": (
                "candidate_requires_lean_replay"
                if region.get("return_pop_claim") is not None
                else "incomplete"
            ),
            "region_index": region["region_index"],
            "claim": region.get("return_pop_claim"),
            "profile": (
                (region.get("return_pop_claim") or {}).get("profile")
            ),
            "blocker": (
                None if region.get("return_pop_claim") is not None else
                "return target is neither one direct ESP-relative read nor an exact "
                "post-write read whose constant image writes have complete byte-level "
                "stack-separation witnesses, or the stack-pop deltas differ"
            ),
            "next_action": (
                "replay ReturnPopAfterWritesClosed and its runtime-frame target theorem "
                "in Lean"
                if (region.get("return_pop_claim") or {}).get("profile")
                    == "esp_relative_return_after_static_writes_v1" else
                "replay ReturnPopClosed in Lean"
                if region.get("return_pop_claim") is not None else
                "classify preceding stack writes and reduce the return target to a checked "
                "ESP-relative slot; constant PE-image writes require all 16 byte-pair "
                "separations per written dword"
            ),
        }
        for region in register_relations["regions"]
        if region.get("is_return")
    ]
    return_slot_transfer_obligations = [
        {
            "id": (
                f"return-slot-transfer:{edge['source_region_index']}:"
                f"{edge['target_region_index']}:{claim_index}"
            ),
            "kind": "return_slot_affine_transfer",
            "status": "candidate_requires_lean_replay",
            "source_region_index": edge["source_region_index"],
            "target_region_index": edge["target_region_index"],
            "claim": claim,
            "blocker": None,
            "next_action": "replay ReturnSlotTransferClosed in Lean",
        }
        for edge in register_relations["edges"]
        for claim_index, claim in enumerate(
            edge.get("return_slot_transfer_claims", [])
        )
    ]
    return_slot_return_transfer_obligations = [
        {
            "id": (
                f"return-slot-return-transfer:{region['region_index']}:"
                f"{claim_index}"
            ),
            "kind": "return_slot_return_affine_transfer",
            "status": "candidate_requires_lean_replay",
            "source_region_index": region["region_index"],
            "claim": claim,
            "blocker": None,
            "next_action": "replay ReturnSlotTransferClosed in Lean",
        }
        for region in register_relations["regions"]
        for claim_index, claim in enumerate(
            region.get("return_slot_return_transfer_claims", [])
        )
    ]
    return_slot_frame_obligations = [
        {
            "id": f"return-slot-frame:{region['region_index']}",
            "kind": "return_slot_runtime_frame",
            "status": (
                "candidate_requires_lean_replay"
                if region.get("return_slot_status") == "satisfied"
                else "incomplete"
            ),
            "region_index": region["region_index"],
            "offsets": region.get("return_slot_offsets", []),
            "claims": region.get("return_pop_frame_claims", []),
            "blocker": (
                None
                if region.get("return_slot_status") == "satisfied"
                else region.get("return_slot_status")
            ),
            "next_action": (
                "replay the checked return-pop runtime-frame theorem and compose the "
                "active frame"
                if region.get("return_slot_status") == "satisfied"
                else "close the reported call-path, affine-offset, or finite-join frontier"
            ),
        }
        for region in register_relations["regions"]
        if region.get("is_return")
    ]
    return_slot_call_summary_obligations = [
        {
            "id": (
                f"return-slot-call-summary:{edge['source_region_index']}:"
                f"{claim['return_region_index']}:{claim_index}"
            ),
            "kind": "return_slot_call_summary",
            "status": "candidate_requires_lean_replay",
            "callsite_region_index": edge["source_region_index"],
            "callee_region_index": edge["target_region_index"],
            "return_region_index": claim["return_region_index"],
            "claim": claim,
            "blocker": None,
            "next_action": "replay ReturnSlotCallSummaryClosed in Lean",
        }
        for edge in register_relations["edges"]
        for claim_index, claim in enumerate(
            edge.get("return_slot_call_summary_claims", [])
        )
    ]
    attached = dict(proof_ir)
    attached["register_relation_summary"] = {
        **counts,
        "total_register_outputs": total_register_outputs,
        "unclaimed_register_outputs": unclaimed_outputs,
        "call_return_obligations": len(call_return_obligations),
        "direct_call_push_obligations": len(direct_call_push_obligations),
        "indirect_call_push_obligations": len(indirect_call_push_obligations),
        "return_pop_obligations": len(return_pop_obligations),
        "return_slot_transfer_obligations": len(return_slot_transfer_obligations),
        "return_slot_return_transfer_obligations": len(
            return_slot_return_transfer_obligations
        ),
        "return_slot_frame_obligations": len(return_slot_frame_obligations),
        "return_slot_call_summary_obligations": len(
            return_slot_call_summary_obligations
        ),
    }
    attached["obligations"] = [
        *proof_ir["obligations"],
        obligation,
        *call_return_obligations,
        *direct_call_push_obligations,
        *indirect_call_push_obligations,
        *return_pop_obligations,
        *return_slot_transfer_obligations,
        *return_slot_return_transfer_obligations,
        *return_slot_frame_obligations,
        *return_slot_call_summary_obligations,
    ]
    attached["status"] = "incomplete"
    return attached

def _attach_memory_transition_analysis(
    proof_ir: dict[str, Any],
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    memory_contracts: dict[str, Any],
    register_relations: dict[str, Any],
) -> dict[str, Any]:
    regions_with_writes = 0
    write_pairs = 0
    identical_write_regions = 0
    differing_write_regions = 0
    bulk_copy_regions = 0
    atomic_compare_exchange_regions = 0
    transition_obligations: list[dict[str, Any]] = []
    for region_index, (region, behavior) in enumerate(
        zip(contract["regions"], behaviors, strict=True)
    ):
        original = behavior.get("original_ir") or {}
        candidate = behavior.get("candidate_ir") or {}
        original_writes = original.get("writes") or []
        candidate_writes = candidate.get("writes") or []
        has_writes = bool(original_writes or candidate_writes)
        if has_writes:
            regions_with_writes += 1
            write_pairs += max(len(original_writes), len(candidate_writes))
            if original_writes == candidate_writes:
                identical_write_regions += 1
            else:
                differing_write_regions += 1
        original_outcome = original.get("outcome") or {}
        candidate_outcome = candidate.get("outcome") or {}
        has_bulk_copy = (
            original_outcome.get("op") == "bulk_copy"
            or candidate_outcome.get("op") == "bulk_copy"
        )
        has_atomic_compare_exchange = (
            original_outcome.get("op") == "atomic_compare_exchange"
            or candidate_outcome.get("op") == "atomic_compare_exchange"
        )
        if has_bulk_copy:
            bulk_copy_regions += 1
        if has_atomic_compare_exchange:
            atomic_compare_exchange_regions += 1

        if not (has_writes or has_bulk_copy or has_atomic_compare_exchange):
            continue
        if has_atomic_compare_exchange:
            repair_class = "atomic_read_modify_write_relation"
            next_action = (
                "prove the compared words and replacement words are related, both sides take the "
                "same success branch, and the conditional paired write preserves successor reads"
            )
        elif has_bulk_copy:
            repair_class = "bulk_copy_range_relation"
            next_action = (
                "prove count and direction agree, source ranges satisfy the required read relation, "
                "destination ranges correspond, and overlap semantics preserve successor reads"
            )
        elif original_writes == candidate_writes:
            repair_class = "identical_symbolic_write_pullback"
            next_action = (
                "evaluate the shared write expressions under the entry relation and pull each "
                "successor memory-read predicate backward through Memory.write32"
            )
        else:
            repair_class = "related_word_write_pullback"
            next_action = (
                "pair write addresses, prove written code/data pointers with wordRelated, and add "
                "the resulting dword cells to the successor memory-relation witness"
            )
        successor_requirements = memory_contracts["regions"][region_index][
            "successor_read_requirements"
        ]
        supported_successor_pullbacks = sum(
            requirement["ordinary_pullback_pair_supported"]
            for requirement in successor_requirements
        )
        exact_transition_supported = bool(successor_requirements) and all(
            requirement["exact_memory_transition_proposed"]
            for requirement in successor_requirements
        ) and not has_bulk_copy and not has_atomic_compare_exchange
        transition_obligations.append({
            "id": f"memory-transition:{region['id']}",
            "kind": "memory_transition_preservation",
            "status": (
                "candidate_requires_lean_replay"
                if exact_transition_supported else "incomplete"
            ),
            "region_id": region["id"],
            "region_index": region_index,
            "semantic_ir_region_index": region_index,
            "memory_contract_region_index": region_index,
            "repair_class": repair_class,
            "analysis": {
                "status": (
                    "candidate_requires_lean_replay"
                    if exact_transition_supported else "incomplete"
                ),
                "original_writes": len(original_writes),
                "candidate_writes": len(candidate_writes),
                "symbolic_writes_identical": original_writes == candidate_writes,
                "bulk_copy": has_bulk_copy,
                "atomic_compare_exchange": has_atomic_compare_exchange,
                "mapped_value_targets": len(region.get("values", [])),
                "available_lean_lemma": (
                    "StageA.Relational.memoryRelated_without_values_after_identical_writes"
                    if (
                        has_writes
                        and not has_bulk_copy
                        and not has_atomic_compare_exchange
                        and original_writes == candidate_writes
                        and not region.get("values")
                    ) else None
                ),
                "entry_read_observations": len(
                    memory_contracts["regions"][region_index]["reads"]
                ),
                "successor_read_requirements": successor_requirements,
                "ordinary_pullback_pair_supported_edges": (
                    supported_successor_pullbacks
                ),
                "ordinary_pullback_pair_total_edges": len(successor_requirements),
                "checked_pullback_claim": (
                    "StageA.Relational.InvariantWP.MemoryReadPullbackEdgeClosed"
                    if supported_successor_pullbacks else None
                ),
                "exact_memory_transition_supported": exact_transition_supported,
                "exact_memory_transition_edges": sum(
                    requirement["exact_memory_transition_proposed"]
                    for requirement in successor_requirements
                ),
                "register_relation": {
                    "exact_inputs": sum(
                        relation["relation"] == "exact"
                        for relation in register_relations["regions"][region_index]["inputs"]
                    ),
                    "checked_output_claims": len(
                        register_relations["regions"][region_index]["output_claims"]
                    ),
                    "fully_supported_output_transfer": register_relations["regions"][
                        region_index
                    ]["fully_supported_output_transfer"],
                    "checked_successor_pair_claims": sum(
                        len(edge["exact_output_pair_claims"])
                        for edge in register_relations["edges"]
                        if edge["source_region_index"] == region_index
                    ),
                },
            },
            "blocker": (
                None if exact_transition_supported else
                "the region's mutation has not been proved to preserve the live memory observations "
                "required at each reachable successor"
            ),
            "next_action": (
                "replay the generated exact pullback transition certificate in Lean"
                if exact_transition_supported else next_action
            ),
        })

    if not (regions_with_writes or bulk_copy_regions or atomic_compare_exchange_regions):
        return proof_ir

    summary = {
        "regions": len(contract["regions"]),
        "regions_with_writes": regions_with_writes,
        "write_pairs": write_pairs,
        "syntactically_identical_write_regions": identical_write_regions,
        "relational_write_regions": differing_write_regions,
        "bulk_copy_regions": bulk_copy_regions,
        "atomic_compare_exchange_regions": atomic_compare_exchange_regions,
        "transition_obligations": len(transition_obligations),
    }
    return {
        **proof_ir,
        "memory_transition_summary": summary,
        "obligations": [*proof_ir["obligations"], *transition_obligations],
    }

def _semantic_expr_has_exact_inputs(
    source: dict[str, Any], expression: dict[str, Any],
) -> bool:
    exact_identity_registers = {
        str(relation["original"])
        for relation in source.get("input_relations", [])
        if relation.get("relation") == "exact"
        and relation.get("original") == relation.get("candidate")
    }
    return (
        _semantic_expr_is_pure(expression)
        and _semantic_expr_registers(expression) <= exact_identity_registers
    )

def _paired_stack_word_value_claim(
    source: dict[str, Any],
    original_value: dict[str, Any],
    candidate_value: dict[str, Any],
    original_image_base: int | None = None,
    candidate_image_base: int | None = None,
) -> dict[str, Any] | None:
    dynamic_matches = [
        relation
        for relation in source.get("input_dynamic_range_relations", [])
        if int(relation.get("original_offset", 0)) == 0
        and int(relation.get("candidate_offset", 0)) == 0
        and original_value == {
            "op": "input_reg", "reg": str(relation.get("original")),
        }
        and candidate_value == {
            "op": "input_reg", "reg": str(relation.get("candidate")),
        }
    ]
    if len(dynamic_matches) == 1:
        return {
            "profile": "dynamic_range_v1",
            "original": original_value,
            "candidate": candidate_value,
            "relation": dynamic_matches[0],
        }
    if len(dynamic_matches) > 1:
        return None

    if (
        original_value == candidate_value
        and _semantic_expr_has_exact_inputs(source, original_value)
    ):
        return {
            "profile": "exact_inputs_v1",
            "original": original_value,
            "candidate": candidate_value,
        }

    original_constant = (
        _integer(original_value.get("value"))
        if original_value.get("op") == "constant" else None
    )
    candidate_constant = (
        _integer(candidate_value.get("value"))
        if candidate_value.get("op") == "constant" else None
    )
    if original_constant is not None and candidate_constant is not None:
        code_matches = []
        if original_image_base is not None and candidate_image_base is not None:
            for target in source.get("code_targets", []):
                original_addresses = {
                    original_image_base + int(target["original_rva"]),
                    *(
                        original_image_base
                        + int(alias["rva"] if isinstance(alias, dict) else alias)
                        for alias in target.get("original_aliases", [])
                    ),
                }
                candidate_addresses = {
                    candidate_image_base + int(target["candidate_rva"]),
                    *(
                        candidate_image_base
                        + int(alias["rva"] if isinstance(alias, dict) else alias)
                        for alias in target.get("candidate_aliases", [])
                    ),
                }
                if (
                    original_constant in original_addresses
                    and candidate_constant in candidate_addresses
                ):
                    code_matches.append(int(target["id"]))
        if len(code_matches) == 1:
            return {
                "profile": "mapped_code_target_v1",
                "original": original_value,
                "candidate": candidate_value,
                "target_id": code_matches[0],
            }

        data_matches = [
            int(target["id"])
            for target in source.get("values", [])
            if int(target["original_value"]) == original_constant
            and int(target["candidate_value"]) == candidate_constant
        ]
        if len(data_matches) == 1:
            return {
                "profile": "mapped_data_target_v1",
                "original": original_value,
                "candidate": candidate_value,
                "target_id": data_matches[0],
            }

    original_argument = _semantic_input_register_offset(original_value)
    candidate_argument = _semantic_input_register_offset(candidate_value)
    if original_argument is None or candidate_argument is None:
        return None
    original_register, original_offset = original_argument
    candidate_register, candidate_offset = candidate_argument
    if original_offset != candidate_offset:
        return None

    def canonical_argument(register: str, offset: int) -> dict[str, Any]:
        register_expression = {"op": "input_reg", "reg": register}
        if offset == 0:
            return register_expression
        return {
            "op": "add",
            "left": register_expression,
            "right": {"op": "constant", "value": offset},
        }

    if (
        original_value != canonical_argument(original_register, original_offset)
        or candidate_value
            != canonical_argument(candidate_register, candidate_offset)
    ):
        return None
    matching_relations = [
        relation for relation in source.get("input_relations", [])
        if relation.get("original") == original_register
        and relation.get("candidate") == candidate_register
        and (
            relation.get("relation") == "exact"
            or (
                relation.get("relation") == "related_word"
                and original_offset == 0
            )
        )
    ]
    if len(matching_relations) != 1:
        return None
    return {
        "profile": "register_argument_v1",
        "original": original_value,
        "candidate": candidate_value,
        "claim": {
            "relation": matching_relations[0],
            "offset": original_offset,
        },
    }

def _paired_stack_word_write_claim(
    source: dict[str, Any], behavior_pair: dict[str, Any],
    original_image_base: int | None = None,
    candidate_image_base: int | None = None,
) -> dict[str, Any] | None:
    original_writes = (behavior_pair.get("original_ir") or {}).get("writes") or []
    candidate_writes = (behavior_pair.get("candidate_ir") or {}).get("writes") or []
    if len(original_writes) != 1 or len(candidate_writes) != 1:
        return None
    original_write = original_writes[0]
    candidate_write = candidate_writes[0]
    original_value = original_write.get("value") or {}
    candidate_value = candidate_write.get("value") or {}
    value_claim = _paired_stack_word_value_claim(
        source, original_value, candidate_value,
        original_image_base, candidate_image_base,
    )
    if value_claim is None:
        return None

    def positive_register_offset(
        expression: Any, register: str,
    ) -> int | None:
        if not isinstance(expression, dict) or expression.get("op") != "add":
            return None
        left = expression.get("left") or {}
        right = expression.get("right") or {}
        if left.get("op") == "constant":
            left, right = right, left
        if (
            left != {"op": "input_reg", "reg": register}
            or right.get("op") != "constant"
        ):
            return None
        amount = _integer(right.get("value"))
        if amount is None or not 0 <= amount < 2**31:
            return None
        return amount

    matches = []
    for window in source.get("stack_windows", []):
        original_register = str(window.get("original_register"))
        candidate_register = str(window.get("candidate_register"))
        original_amount = positive_register_offset(
            original_write.get("address"), original_register
        )
        candidate_amount = positive_register_offset(
            candidate_write.get("address"), candidate_register
        )
        if (
            original_amount is not None
            and original_amount == candidate_amount
            and original_amount % 4 == 0
            and original_amount + 4 <= int(window.get("bytes_above", -1))
        ):
            matches.append((window, original_amount))
    if len(matches) != 1:
        return None
    window, amount = matches[0]
    return {
        "profile": "paired_stack_word_write_v1",
        "window": window,
        "amount": amount,
        "value": value_claim,
    }

def _paired_stack_word_writes_claim(
    source: dict[str, Any], behavior_pair: dict[str, Any],
    original_image_base: int | None = None,
    candidate_image_base: int | None = None,
    minimum_writes: int = 2,
) -> dict[str, Any] | None:
    original_writes = (behavior_pair.get("original_ir") or {}).get("writes") or []
    candidate_writes = (behavior_pair.get("candidate_ir") or {}).get("writes") or []
    if (
        len(original_writes) < minimum_writes
        or len(original_writes) != len(candidate_writes)
    ):
        return None
    value_claims = [
        _paired_stack_word_value_claim(
            source, original.get("value") or {}, candidate.get("value") or {},
            original_image_base, candidate_image_base,
        )
        for original, candidate in zip(
            original_writes, candidate_writes, strict=True
        )
    ]
    if any(claim is None for claim in value_claims):
        return None

    def register_offset(expression: Any, register: str) -> int | None:
        if expression == {"op": "input_reg", "reg": register}:
            return 0
        if not isinstance(expression, dict) or expression.get("op") != "add":
            return None
        left = expression.get("left") or {}
        right = expression.get("right") or {}
        if left.get("op") == "constant":
            left, right = right, left
        if (
            left != {"op": "input_reg", "reg": register}
            or right.get("op") != "constant"
        ):
            return None
        amount = _integer(right.get("value"))
        return amount if amount is not None and 0 < amount < 2**31 else None

    matches: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    for window in source.get("stack_windows", []):
        original_register = str(window.get("original_register"))
        candidate_register = str(window.get("candidate_register"))
        writes: list[dict[str, Any]] = []
        for original, candidate, value_claim in zip(
            original_writes, candidate_writes, value_claims, strict=True
        ):
            original_amount = register_offset(
                original.get("address"), original_register
            )
            candidate_amount = register_offset(
                candidate.get("address"), candidate_register
            )
            if (
                original_amount is None
                or original_amount != candidate_amount
                or original_amount % 4 != 0
                or original_amount + 4 > int(window.get("bytes_above", -1))
            ):
                break
            writes.append({
                "amount": original_amount,
                "value": value_claim,
            })
        else:
            matches.append((window, writes))
    if len(matches) != 1:
        return None
    window, writes = matches[0]
    return {
        "profile": "paired_stack_word_writes_v1",
        "window": window,
        "writes": writes,
    }

def _direct_call_stack_writes_claim(
    source: dict[str, Any], behavior_pair: dict[str, Any],
    call_claim: dict[str, Any] | None,
    original_image_base: int | None = None,
    candidate_image_base: int | None = None,
) -> dict[str, Any] | None:
    if not isinstance(call_claim, dict):
        return None
    original_ir = behavior_pair.get("original_ir") or {}
    candidate_ir = behavior_pair.get("candidate_ir") or {}
    original_writes = original_ir.get("writes") or []
    candidate_writes = candidate_ir.get("writes") or []
    if len(original_writes) < 2 or len(original_writes) != len(candidate_writes):
        return None
    prefix_pair = {
        "original_ir": {**original_ir, "writes": original_writes[:-1]},
        "candidate_ir": {**candidate_ir, "writes": candidate_writes[:-1]},
    }
    stack_writes = _paired_stack_word_writes_claim(
        source, prefix_pair, original_image_base, candidate_image_base,
        minimum_writes=1,
    )
    if stack_writes is None:
        return None
    stack_amount = _direct_call_stack_amount(call_claim)
    if stack_amount is None:
        return None
    window = stack_writes["window"]
    if (
        str(window.get("original_register")) != "esp"
        or str(window.get("candidate_register")) != "esp"
        or int(window.get("bytes_below", 0)) < stack_amount
    ):
        return None
    return {
        "profile": "direct_call_stack_writes_v1",
        "stack_writes": stack_writes,
        "stack_amount": stack_amount,
        "callee_target_id": int(call_claim["callee_target_id"]),
        "continuation_target_id": int(call_claim["continuation_target_id"]),
        "original_return_address": int(call_claim["original_return_address"]),
        "candidate_return_address": int(call_claim["candidate_return_address"]),
    }


def _static_word_value_claim_compatible(
    relation: str, value_claim: dict[str, Any],
) -> bool:
    profile = value_claim.get("profile")
    if relation == "related_word":
        return profile in {
            "exact_inputs_v1", "register_argument_v1",
            "mapped_code_target_v1", "mapped_data_target_v1",
            "dynamic_range_v1",
        }
    if relation == "exact":
        return profile == "exact_inputs_v1" or (
            profile == "register_argument_v1"
            and ((value_claim.get("claim") or {}).get("relation") or {}).get(
                "relation"
            ) == "exact"
        )
    if relation == "code_pointer":
        return profile == "mapped_code_target_v1"
    if relation == "data_pointer":
        return profile == "mapped_data_target_v1"
    return False


def _dynamic_word_value_claim_compatible(
    relation: str, value_claim: dict[str, Any],
) -> bool:
    profile = value_claim.get("profile")
    if relation == "relatedWord":
        return profile in {
            "exact_inputs_v1", "register_argument_v1",
            "mapped_code_target_v1", "mapped_data_target_v1",
        }
    if relation == "codePointer":
        return profile == "mapped_code_target_v1"
    if relation == "dataPointer":
        return profile == "mapped_data_target_v1"
    return False


def _paired_prepared_word_writes_claim(
    source: dict[str, Any], behavior_pair: dict[str, Any],
    static_word_relation_slots: list[dict[str, Any]],
    original_image_base: int | None = None,
    candidate_image_base: int | None = None,
    static_dynamic_pointer_slots: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    original_writes = (behavior_pair.get("original_ir") or {}).get("writes") or []
    candidate_writes = (behavior_pair.get("candidate_ir") or {}).get("writes") or []
    if not original_writes or len(original_writes) != len(candidate_writes):
        return None

    def register_offset(expression: Any, register: str) -> int | None:
        if expression == {"op": "input_reg", "reg": register}:
            return 0
        if not isinstance(expression, dict) or expression.get("op") != "add":
            return None
        left = expression.get("left") or {}
        right = expression.get("right") or {}
        if left.get("op") == "constant":
            left, right = right, left
        if (
            left != {"op": "input_reg", "reg": register}
            or right.get("op") != "constant"
        ):
            return None
        amount = _integer(right.get("value"))
        return amount if amount is not None and 0 <= amount < 2**31 else None

    items: list[dict[str, Any]] = []
    for original_write, candidate_write in zip(
        original_writes, candidate_writes, strict=True
    ):
        value_claim = _paired_stack_word_value_claim(
            source,
            original_write.get("value") or {},
            candidate_write.get("value") or {},
            original_image_base,
            candidate_image_base,
        )
        if value_claim is None:
            return None

        location_claims: list[dict[str, Any]] = []
        for window in source.get("stack_windows", []):
            original_amount = register_offset(
                original_write.get("address"), str(window.get("original_register"))
            )
            candidate_amount = register_offset(
                candidate_write.get("address"), str(window.get("candidate_register"))
            )
            if (
                original_amount is not None
                and original_amount == candidate_amount
                and original_amount % 4 == 0
                and original_amount + 4 <= int(window.get("bytes_above", -1))
            ):
                location_claims.append({
                    "kind": "stack",
                    "window": window,
                    "amount": original_amount,
                })

        original_address = _semantic_constant_word(
            original_write.get("address") or {}
        )
        candidate_address = _semantic_constant_word(
            candidate_write.get("address") or {}
        )
        if original_address is not None and candidate_address is not None:
            for slot in static_dynamic_pointer_slots or []:
                source_relation = value_claim.get("relation") or {}
                source_words = {
                    (int(word["offset"]), str(word["kind"]))
                    for word in source_relation.get("required_words", [])
                }
                slot_words = {
                    (int(word["offset"]), str(word["kind"]))
                    for word in slot.get("required_words", [])
                }
                if (
                    int(slot["original_address"]) == original_address
                    and int(slot["candidate_address"]) == candidate_address
                    and value_claim.get("profile") == "dynamic_range_v1"
                    and int(source_relation.get("original_offset", -1)) == 0
                    and int(source_relation.get("candidate_offset", -1)) == 0
                    and bool(slot_words)
                    and slot_words <= source_words
                ):
                    location_claims.append({
                        "kind": "static_dynamic_pointer",
                        "slot_id": int(slot["id"]),
                        "original_address": original_address,
                        "candidate_address": candidate_address,
                        "source_relation": source_relation,
                    })
            for slot in static_word_relation_slots:
                if (
                    int(slot["original_address"]) == original_address
                    and int(slot["candidate_address"]) == candidate_address
                    and _static_word_value_claim_compatible(
                        str(slot["relation"]), value_claim
                    )
                ):
                    location_claims.append({
                        "kind": "static_word",
                        "slot_id": int(slot["id"]),
                        "original_address": original_address,
                        "candidate_address": candidate_address,
                    })

        for source_relation in source.get("input_dynamic_range_relations", []):
            original_amount = register_offset(
                original_write.get("address"), str(source_relation.get("original"))
            )
            candidate_amount = register_offset(
                candidate_write.get("address"), str(source_relation.get("candidate"))
            )
            if original_amount is None or candidate_amount is None:
                continue
            for relation in source_relation.get("required_words", []):
                relation_offset = int(relation.get("offset", -1))
                if (
                    int(source_relation.get("original_offset", 0)) + original_amount
                        == relation_offset
                    and int(source_relation.get("candidate_offset", 0)) + candidate_amount
                        == relation_offset
                    and _dynamic_word_value_claim_compatible(
                        str(relation.get("kind")), value_claim
                    )
                ):
                    location_claims.append({
                        "kind": "dynamic_word",
                        "source_relation": source_relation,
                        "relation": relation,
                        "original_amount": original_amount,
                        "candidate_amount": candidate_amount,
                    })

        if len(location_claims) != 1:
            return None
        items.append({**location_claims[0], "value": value_claim})

    return {
        "profile": "paired_prepared_word_writes_v1",
        "writes": items,
    }


def _prepared_dynamic_stack_spill_claim(
    source: dict[str, Any], target: dict[str, Any],
    prepared_writes: dict[str, Any] | None,
) -> dict[str, Any] | None:
    def stack_window_identity(window: Any) -> tuple[Any, ...] | None:
        if not isinstance(window, dict):
            return None
        return (
            _integer(window.get("range_id")),
            str(window.get("original_register")),
            str(window.get("candidate_register")),
            _integer(window.get("bytes_below")),
            _integer(window.get("bytes_above")),
        )

    if not isinstance(prepared_writes, dict):
        return None
    writes = prepared_writes.get("writes") or []
    if not writes or writes[0].get("kind") != "stack":
        return None
    spill = writes[0]
    value = spill.get("value") or {}
    if value.get("profile") != "dynamic_range_v1":
        return None
    if any(item.get("kind") == "stack" for item in writes[1:]):
        return None
    source_relation = value.get("relation")
    if not isinstance(source_relation, dict):
        return None
    target_relations = target.get("input_dynamic_stack_range_relations") or []
    if len(target_relations) != 1:
        return None
    target_relation = target_relations[0]
    window = spill.get("window")
    if (
        stack_window_identity(target_relation.get("window"))
            != stack_window_identity(window)
        or stack_window_identity(window) is None
        or int(target_relation.get("stack_offset", -1))
            != int(spill.get("amount", -2))
        or int(target_relation.get("original_offset", 0))
            != int(source_relation.get("original_offset", 0))
        or int(target_relation.get("candidate_offset", 0))
            != int(source_relation.get("candidate_offset", 0))
    ):
        return None
    source_words = {
        (int(word["offset"]), str(word["kind"]))
        for word in source_relation.get("required_words", [])
    }
    target_words = {
        (int(word["offset"]), str(word["kind"]))
        for word in target_relation.get("required_words", [])
    }
    source_active_words = {
        (int(word["offset"]), str(word["kind"]))
        for word in source_relation.get("active_words", [])
    }
    target_active_words = {
        (int(word["offset"]), str(word["kind"]))
        for word in target_relation.get("active_words", [])
    }
    if not target_words <= source_words or not target_active_words <= source_active_words:
        return None
    return {
        "profile": "prepared_dynamic_stack_spill_v1",
        "source_relation": source_relation,
        "target_relation": target_relation,
        "window": window,
        "amount": int(spill["amount"]),
        "suffix": writes[1:],
    }


def _direct_call_prepared_writes_claim(
    source: dict[str, Any], behavior_pair: dict[str, Any],
    call_claim: dict[str, Any] | None,
    static_word_relation_slots: list[dict[str, Any]],
    original_image_base: int | None = None,
    candidate_image_base: int | None = None,
    static_dynamic_pointer_slots: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    if not isinstance(call_claim, dict):
        return None
    original_ir = behavior_pair.get("original_ir") or {}
    candidate_ir = behavior_pair.get("candidate_ir") or {}
    original_writes = original_ir.get("writes") or []
    candidate_writes = candidate_ir.get("writes") or []
    if len(original_writes) < 2 or len(original_writes) != len(candidate_writes):
        return None
    stack_amount = _direct_call_stack_amount(call_claim)
    if stack_amount is None:
        return None
    return_windows = [
        window for window in source.get("stack_windows", [])
        if str(window.get("original_register")) == "esp"
        and str(window.get("candidate_register")) == "esp"
        and int(window.get("bytes_below", 0)) >= stack_amount
    ]
    if len(return_windows) != 1:
        return None
    prefix_pair = {
        "original_ir": {**original_ir, "writes": original_writes[:-1]},
        "candidate_ir": {**candidate_ir, "writes": candidate_writes[:-1]},
    }
    prepared_writes = _paired_prepared_word_writes_claim(
        source, prefix_pair, static_word_relation_slots,
        original_image_base, candidate_image_base,
        static_dynamic_pointer_slots,
    )
    if prepared_writes is None or not any(
        item["kind"] == "static_word" for item in prepared_writes["writes"]
    ):
        return None
    return {
        "profile": "direct_call_prepared_writes_v1",
        "prepared_writes": prepared_writes,
        "return_window": return_windows[0],
        "stack_amount": stack_amount,
        "callee_target_id": int(call_claim["callee_target_id"]),
        "continuation_target_id": int(call_claim["continuation_target_id"]),
        "original_return_address": int(call_claim["original_return_address"]),
        "candidate_return_address": int(call_claim["candidate_return_address"]),
    }

def _segment_refinement_candidates(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    memory_contracts: dict[str, Any],
    register_relations: dict[str, Any],
    import_register_seeds: list[dict[str, Any]] | None = None,
    diagnostics: list[dict[str, Any]] | None = None,
    original_bin: StageABinary | None = None,
    candidate_bin: StageABinary | None = None,
) -> list[dict[str, Any]]:
    by_edge: dict[int, dict[str, Any]] = {}
    memory_regions = memory_contracts.get("regions", [])
    register_regions = register_relations.get("regions", [])
    for edge_index, edge in enumerate(register_relations.get("edges", [])):
        if edge_index in by_edge:
            continue
        source_index = int(edge["source_region_index"])
        target_index = int(edge["target_region_index"])
        if (
            source_index >= len(memory_regions)
            or source_index >= len(register_regions)
            or source_index >= len(behaviors)
        ):
            continue
        source = contract["regions"][source_index]
        target = contract["regions"][target_index]
        source_target = next((
            code_target for code_target in contract.get("code_targets", [])
            if int(code_target.get("region_index", -1)) == source_index
            and int(code_target["original_rva"])
                == int(source["original"]["rva_start"])
            and int(code_target["candidate_rva"])
                == int(source["candidate"]["rva_start"])
        ), None)
        memory = memory_regions[source_index]
        successors = memory.get("successors", {})
        candidate_successors = memory.get("candidate_successors", {})
        direct_targets = successors.get("direct", [])
        candidate_direct_targets = candidate_successors.get("direct", [])
        target_flags = target.get("flag_inputs", list(FLAG_BITS))
        import_transfer_claims = _import_register_transfer_claims(
            contract, behaviors, source_index, target_index,
            import_register_seeds or [],
        )
        dynamic_transfer_claims = _dynamic_range_transfer_claims(
            contract, behaviors, source_index, target_index,
            edge.get("original_guard") or {},
            edge.get("candidate_guard") or {},
        )
        guard_relation_claim = _related_word_zero_guard_claim(
            source,
            edge.get("original_guard") or {},
            edge.get("candidate_guard") or {},
        ) or _input_flags_guard_claim(
            source,
            edge.get("original_guard") or {},
            edge.get("candidate_guard") or {},
        ) or _exact_pure_guard_claim(
            source,
            edge.get("original_guard") or {},
            edge.get("candidate_guard") or {},
            original_bin,
            candidate_bin,
        ) or _paired_exact_guard_claim(
            contract,
            source,
            edge.get("original_guard") or {},
            edge.get("candidate_guard") or {},
            original_bin,
            candidate_bin,
        ) or _paired_stack_guard_claim(
            source,
            edge.get("original_guard") or {},
            edge.get("candidate_guard") or {},
        ) or _paired_stack_relative_guard_claim(
            source,
            edge.get("original_guard") or {},
            edge.get("candidate_guard") or {},
        ) or _static_dynamic_pointer_slot_guard_claim(
            contract,
            edge.get("original_guard") or {},
            edge.get("candidate_guard") or {},
        )
        if guard_relation_claim is None and dynamic_transfer_claims is not None:
            next_claim_index = next((
                index for index, claim in enumerate(dynamic_transfer_claims)
                if claim.get("kind") == "nullable_pointer"
            ), None)
            if next_claim_index is not None:
                guard_relation_claim = {
                    "profile": "dynamic_range_next_guard_v1",
                    "claim_index": next_claim_index,
                }
        branch_edge = edge.get("kind") in {"branch_taken", "branch_fallthrough"}
        stack_transfer_claims = _stack_window_transfer_claims(
            source, target, behaviors[source_index]
        )
        dynamic_register_output_claims = _dynamic_range_register_output_claims(
            register_regions[source_index], dynamic_transfer_claims,
            behaviors[source_index], guard_relation_claim,
        )
        target_shaped_register_output_claims = (
            _target_shaped_register_output_claims(
                register_regions[source_index], register_regions[target_index]
            )
            if not dynamic_register_output_claims else None
        )
        register_inventory_supported = (
            target_shaped_register_output_claims is not None
            if not dynamic_register_output_claims
            else source.get("output_relations", [])
                == target.get("input_relations", [])
        )
        register_transfer_supported = register_inventory_supported
        flag_transfer_claim = _preserved_input_flags_claim(
            source, target_flags, behaviors[source_index]
        )
        flag_transfer_supported = (
            target_flags == []
            or flag_transfer_claim is not None
        )
        common_transfer_supported = (
            edge.get("relation_preservation_proposed")
            and register_transfer_supported
            and all(
                claim.get("kind") != "exact_memory"
                for claim in register_regions[source_index].get("output_claims", [])
            )
            and not edge.get("environment_barrier")
            and not edge.get("requires_call_stack_proof")
            and register_inventory_supported
            and not source.get("output_import_relations")
            and import_transfer_claims is not None
            and dynamic_transfer_claims is not None
            and stack_transfer_claims is not None
            and flag_transfer_supported
            and not target.get("bounds")
            and (
                not target.get("address_separations")
                or bool(target.get("stack_address_separation_claims"))
            )
            and _lean_x87_state_only_pair(behaviors[source_index])
        )
        no_write_supported = (
            edge.get("kind") in {"jump", "branch_taken", "branch_fallthrough"}
            and common_transfer_supported
            and memory.get("writes", {}).get("original_count") == 0
            and memory.get("writes", {}).get("candidate_count") == 0
            and (
                (
                    successors.get("outcome") in {"jump", "branch"}
                    and candidate_successors.get("outcome") == successors.get("outcome")
                    and isinstance(direct_targets, list)
                    and direct_targets == candidate_direct_targets
                    and int(target["numeric_id"]) in direct_targets
                )
                or (
                    edge.get("indirect_target_profile") ==
                        "immutable_relocated_function_pointer_jump_v1"
                    and successors.get("outcome") == "indirect_jump"
                    and candidate_successors.get("outcome") == "indirect_jump"
                    and isinstance(edge.get("indirect_target_claim"), dict)
                    and int(edge["indirect_target_claim"].get("target_id", -1))
                        == int(target["numeric_id"])
                )
            )
            and (not branch_edge or guard_relation_claim is not None)
        )
        call_claim = edge.get("direct_call_push_claim")
        call_stack_amount = _direct_call_stack_amount(call_claim)
        call_windows = [
            window for window in source.get("stack_windows", [])
            if str(window.get("original_register")) == "esp"
            and str(window.get("candidate_register")) == "esp"
            and call_stack_amount is not None
            and int(window.get("bytes_below", 0)) >= call_stack_amount
        ]
        original_image_base = original_bin.image_base if original_bin is not None else None
        candidate_image_base = candidate_bin.image_base if candidate_bin is not None else None
        call_stack_writes_claim = _direct_call_stack_writes_claim(
            source, behaviors[source_index], call_claim,
            original_image_base, candidate_image_base,
        )
        call_prepared_writes_claim = _direct_call_prepared_writes_claim(
            source, behaviors[source_index], call_claim,
            contract.get("static_word_relation_slots", []),
            original_image_base, candidate_image_base,
            contract.get("static_dynamic_pointer_slots", []),
        )
        call_prepared_writes_supported = (
            edge.get("kind") == "call"
            and common_transfer_supported
            and isinstance(call_prepared_writes_claim, dict)
            and len(call_windows) == 1
            and successors.get("outcome") == "call"
            and candidate_successors.get("outcome") == "call"
            and isinstance(call_claim, dict)
            and int(call_claim.get("callee_target_id", -1))
                == int(target["numeric_id"])
            and int(call_claim.get("callee_target_id", -1)) in direct_targets
            and direct_targets == candidate_direct_targets
            and not target.get("input_import_relations")
            and not target.get("input_dynamic_range_relations")
            and edge.get("original_guard") == {
                "op": "bool_constant", "value": True,
            }
            and edge.get("candidate_guard") == {
                "op": "bool_constant", "value": True,
            }
        )
        call_stack_writes_supported = (
            edge.get("kind") == "call"
            and common_transfer_supported
            and isinstance(call_stack_writes_claim, dict)
            and len(call_windows) == 1
            and successors.get("outcome") == "call"
            and candidate_successors.get("outcome") == "call"
            and isinstance(call_claim, dict)
            and int(call_claim.get("callee_target_id", -1))
                == int(target["numeric_id"])
            and int(call_claim.get("callee_target_id", -1)) in direct_targets
            and direct_targets == candidate_direct_targets
            and not target.get("input_import_relations")
            and not target.get("input_dynamic_range_relations")
            and edge.get("original_guard") == {
                "op": "bool_constant", "value": True,
            }
            and edge.get("candidate_guard") == {
                "op": "bool_constant", "value": True,
            }
        )
        call_supported = (
            edge.get("kind") == "call"
            and common_transfer_supported
            and isinstance(call_claim, dict)
            and call_claim.get("profile") == "mapped_direct_call_push_v1"
            and call_stack_amount is not None
            and len(call_windows) == 1
            and memory.get("writes", {}).get("original_count") == 1
            and memory.get("writes", {}).get("candidate_count") == 1
            and successors.get("outcome") == "call"
            and candidate_successors.get("outcome") == "call"
            and int(call_claim.get("callee_target_id", -1))
                == int(target["numeric_id"])
            and int(call_claim.get("callee_target_id", -1)) in direct_targets
            and direct_targets == candidate_direct_targets
            and not target.get("input_import_relations")
            and not target.get("input_dynamic_range_relations")
            and edge.get("original_guard") == {
                "op": "bool_constant", "value": True,
            }
            and edge.get("candidate_guard") == {
                "op": "bool_constant", "value": True,
            }
        )
        stack_write_claim = _paired_stack_word_write_claim(
            source, behaviors[source_index],
            original_image_base, candidate_image_base,
        )
        stack_writes_claim = _paired_stack_word_writes_claim(
            source, behaviors[source_index],
            original_image_base, candidate_image_base,
        )
        prepared_writes_claim = _paired_prepared_word_writes_claim(
            source, behaviors[source_index],
            contract.get("static_word_relation_slots", []),
            original_image_base, candidate_image_base,
            contract.get("static_dynamic_pointer_slots", []),
        )
        prepared_dynamic_stack_spill_claim = (
            _prepared_dynamic_stack_spill_claim(
                source, target, prepared_writes_claim,
            )
        )
        prepared_writes_supported = (
            edge.get("kind") in {"jump", "branch_taken", "branch_fallthrough"}
            and common_transfer_supported
            and isinstance(prepared_writes_claim, dict)
            and any(
                item.get("kind") != "stack"
                for item in prepared_writes_claim["writes"]
            )
            and memory.get("writes", {}).get("original_count")
                == len(prepared_writes_claim["writes"])
            and memory.get("writes", {}).get("candidate_count")
                == len(prepared_writes_claim["writes"])
            and successors.get("outcome") in {"jump", "branch"}
            and candidate_successors.get("outcome") == successors.get("outcome")
            and isinstance(direct_targets, list)
            and direct_targets == candidate_direct_targets
            and int(target["numeric_id"]) in direct_targets
            and not target.get("input_import_relations")
            and (
                not target.get("input_dynamic_stack_range_relations")
                or isinstance(prepared_dynamic_stack_spill_claim, dict)
            )
            and (not branch_edge or guard_relation_claim is not None)
        )
        stack_write_supported = (
            edge.get("kind") in {"jump", "branch_taken", "branch_fallthrough"}
            and common_transfer_supported
            and isinstance(stack_write_claim, dict)
            and memory.get("writes", {}).get("original_count") == 1
            and memory.get("writes", {}).get("candidate_count") == 1
            and successors.get("outcome") in {"jump", "branch"}
            and candidate_successors.get("outcome") == successors.get("outcome")
            and isinstance(direct_targets, list)
            and direct_targets == candidate_direct_targets
            and int(target["numeric_id"]) in direct_targets
            and not target.get("input_import_relations")
            and not target.get("input_dynamic_range_relations")
            and (not branch_edge or guard_relation_claim is not None)
        )
        stack_writes_supported = (
            edge.get("kind") in {"jump", "branch_taken", "branch_fallthrough"}
            and common_transfer_supported
            and isinstance(stack_writes_claim, dict)
            and memory.get("writes", {}).get("original_count")
                == len(stack_writes_claim["writes"])
            and memory.get("writes", {}).get("candidate_count")
                == len(stack_writes_claim["writes"])
            and successors.get("outcome") in {"jump", "branch"}
            and candidate_successors.get("outcome") == successors.get("outcome")
            and isinstance(direct_targets, list)
            and direct_targets == candidate_direct_targets
            and int(target["numeric_id"]) in direct_targets
            and not target.get("input_import_relations")
            and not target.get("input_dynamic_range_relations")
            and (not branch_edge or guard_relation_claim is not None)
        )
        segment_supported = (
            no_write_supported or call_supported or call_prepared_writes_supported
            or call_stack_writes_supported
            or prepared_writes_supported
            or stack_write_supported or stack_writes_supported
        )
        certificate_eligible = segment_supported and source_target is not None
        if diagnostics is not None:
            failed_checks: list[str] = []

            def require(code: str, supported: bool) -> None:
                if not supported:
                    failed_checks.append(code)

            require(
                "relation_preservation_not_proposed",
                bool(edge.get("relation_preservation_proposed")),
            )
            require(
                "register_output_transfer_unsupported",
                register_transfer_supported,
            )
            require(
                "exact_memory_output_claim_present",
                all(
                    claim.get("kind") != "exact_memory"
                    for claim in register_regions[source_index].get(
                        "output_claims", []
                    )
                ),
            )
            require(
                "external_environment_barrier",
                not bool(edge.get("environment_barrier")),
            )
            require(
                "call_stack_refinement_required",
                not bool(edge.get("requires_call_stack_proof")),
            )
            require(
                "successor_state_relation_mismatch",
                register_inventory_supported,
            )
            require(
                "source_import_relation_transfer_required",
                not source.get("output_import_relations"),
            )
            require(
                "import_register_transfer_unsupported",
                import_transfer_claims is not None,
            )
            require(
                "dynamic_range_transfer_unsupported",
                dynamic_transfer_claims is not None,
            )
            require(
                "stack_window_transfer_unsupported",
                stack_transfer_claims is not None,
            )
            require(
                "flag_relation_mismatch",
                flag_transfer_supported,
            )
            require(
                "target_flag_profile_unsupported",
                all(bit in FLAG_BITS for bit in target_flags),
            )
            require(
                "target_bound_invariant_required",
                not target.get("bounds"),
            )
            require(
                "target_address_separation_invariant_required",
                not target.get("address_separations")
                or bool(target.get("stack_address_separation_claims")),
            )
            require(
                "x87_state_transfer_unsupported",
                _lean_x87_state_only_pair(behaviors[source_index]),
            )

            original_write_count = int(
                memory.get("writes", {}).get("original_count", -1)
            )
            candidate_write_count = int(
                memory.get("writes", {}).get("candidate_count", -1)
            )
            if edge.get("kind") == "call":
                attempted_profile = (
                    "composable_direct_call_prepared_writes_v1"
                    if isinstance(call_prepared_writes_claim, dict)
                    else "composable_direct_call_stack_writes_v1"
                    if max(original_write_count, candidate_write_count) > 1
                    else "composable_direct_call_v1"
                )
                require(
                    "direct_call_push_missing",
                    isinstance(call_claim, dict)
                    and call_claim.get("profile") == "mapped_direct_call_push_v1"
                    and call_stack_amount is not None,
                )
                require(
                    "direct_call_stack_window_ambiguous",
                    len(call_windows) == 1,
                )
                require(
                    "direct_call_write_shape_mismatch",
                    original_write_count == candidate_write_count == 1
                    or call_prepared_writes_supported
                    or call_stack_writes_supported,
                )
                if max(original_write_count, candidate_write_count) > 1:
                    require(
                        "direct_call_prepared_writes_witness_missing",
                        call_prepared_writes_supported or call_stack_writes_supported,
                    )
                require(
                    "direct_call_successor_shape_mismatch",
                    successors.get("outcome") == "call"
                    and candidate_successors.get("outcome") == "call"
                    and isinstance(call_claim, dict)
                    and int(call_claim.get("callee_target_id", -1))
                        == int(target["numeric_id"])
                    and int(call_claim.get("callee_target_id", -1))
                        in direct_targets
                    and direct_targets == candidate_direct_targets,
                )
                require(
                    "callee_input_import_relation_unsupported",
                    not target.get("input_import_relations"),
                )
                require(
                    "callee_input_dynamic_range_relation_unsupported",
                    not target.get("input_dynamic_range_relations"),
                )
                require(
                    "unconditional_call_guard_required",
                    edge.get("original_guard")
                        == {"op": "bool_constant", "value": True}
                    and edge.get("candidate_guard")
                        == {"op": "bool_constant", "value": True},
                )
            elif edge.get("kind") in {
                "jump", "branch_taken", "branch_fallthrough"
            }:
                if original_write_count == candidate_write_count == 0:
                    attempted_profile = "composable_local_no_write_v1"
                    write_claim_supported = True
                elif original_write_count == candidate_write_count == 1:
                    attempted_profile = (
                        "composable_paired_prepared_word_writes_v1"
                        if isinstance(prepared_writes_claim, dict)
                        and any(
                            item.get("kind") != "stack"
                            for item in prepared_writes_claim["writes"]
                        )
                        else "composable_paired_stack_word_write_v1"
                    )
                    write_claim_supported = (
                        prepared_writes_supported
                        or isinstance(stack_write_claim, dict)
                    )
                    require(
                        "paired_word_write_witness_missing",
                        write_claim_supported,
                    )
                else:
                    attempted_profile = (
                        "composable_paired_prepared_word_writes_v1"
                        if isinstance(prepared_writes_claim, dict)
                        and any(
                            item.get("kind") != "stack"
                            for item in prepared_writes_claim["writes"]
                        )
                        else "composable_paired_stack_word_writes_v1"
                    )
                    write_claim_supported = (
                        prepared_writes_supported
                        or isinstance(stack_writes_claim, dict)
                    )
                    require(
                        "paired_word_writes_witness_missing",
                        write_claim_supported,
                    )
                require(
                    "paired_memory_write_count_mismatch",
                    original_write_count == candidate_write_count,
                )
                require(
                    "direct_successor_shape_mismatch",
                    successors.get("outcome") in {"jump", "branch"}
                    and candidate_successors.get("outcome")
                        == successors.get("outcome")
                    and isinstance(direct_targets, list)
                    and direct_targets == candidate_direct_targets
                    and int(target["numeric_id"]) in direct_targets,
                )
                require(
                    "successor_import_relation_unsupported",
                    original_write_count == 0
                    or prepared_writes_supported
                    or not target.get("input_import_relations"),
                )
                require(
                    "successor_dynamic_range_relation_unsupported",
                    original_write_count == 0
                    or prepared_writes_supported
                    or not target.get("input_dynamic_range_relations"),
                )
                require(
                    "successor_dynamic_stack_relation_unsupported",
                    original_write_count == 0
                    or not target.get("input_dynamic_stack_range_relations")
                    or isinstance(prepared_dynamic_stack_spill_claim, dict),
                )
                require(
                    "branch_guard_relation_unsupported",
                    not branch_edge or guard_relation_claim is not None,
                )
            else:
                attempted_profile = "unsupported_control_or_memory_profile"
                require("control_kind_unsupported", False)

            require(
                "canonical_source_target_missing",
                source_target is not None,
            )

            diagnostics.append({
                "edge_index": edge_index,
                "source_region_index": source_index,
                "target_region_index": target_index,
                "edge_kind": str(edge.get("kind")),
                "attempted_profile": attempted_profile,
                "eligible": certificate_eligible,
                "failed_checks": failed_checks if not certificate_eligible else [],
            })
        if not certificate_eligible:
            continue
        by_edge[edge_index] = {
            "format": RELATIONAL_SEGMENT_CERTIFICATE_FORMAT,
            "edge_index": edge_index,
            "source_region_index": source_index,
            "target_region_index": target_index,
            "source_target_id": int(source_target["id"]),
            "target_id": int(target["numeric_id"]),
            "local_code_target_ids": [
                int(target["id"]) for target in source.get("code_targets", [])
            ],
            "local_value_target_ids": [
                int(target["id"]) for target in source.get("values", [])
            ],
            "certificate_profile": (
                "composable_direct_call_prepared_writes_v1"
                if call_prepared_writes_supported
                else "composable_direct_call_stack_writes_v1"
                if call_stack_writes_supported
                else "composable_direct_call_v1" if call_supported
                else "composable_paired_prepared_word_writes_v1"
                if prepared_writes_supported
                else "composable_paired_stack_word_write_v1"
                if stack_write_supported
                else "composable_paired_stack_word_writes_v1"
                if stack_writes_supported
                else "composable_immutable_indirect_jump_v1"
                if edge.get("indirect_target_profile") ==
                    "immutable_relocated_function_pointer_jump_v1"
                else "composable_local_no_write_v1"
            ),
            "indirect_target_claim": edge.get("indirect_target_claim"),
            "import_transfer_claims": import_transfer_claims,
            "dynamic_transfer_claims": dynamic_transfer_claims,
            "dynamic_register_output_claims": dynamic_register_output_claims or [],
            "register_output_claims": (
                target_shaped_register_output_claims or []
            ),
            "original_guard": edge["original_guard"],
            "candidate_guard": edge["candidate_guard"],
            **({
                "source_stack_window": (
                    call_prepared_writes_claim["return_window"]
                    if call_prepared_writes_supported
                    else call_stack_writes_claim["stack_writes"]["window"]
                    if call_stack_writes_supported else call_windows[0]
                ),
                "callee_target_id": int(call_claim["callee_target_id"]),
                "continuation_target_id": int(call_claim["continuation_target_id"]),
                "original_return_address": int(call_claim["original_return_address"]),
                "candidate_return_address": int(call_claim["candidate_return_address"]),
                "stack_amount": call_stack_amount,
            } if call_supported or call_stack_writes_supported
                or call_prepared_writes_supported else {}),
            "direct_call_prepared_writes_claim": (
                call_prepared_writes_claim
                if call_prepared_writes_supported else None
            ),
            "direct_call_stack_writes_claim": (
                call_stack_writes_claim if call_stack_writes_supported else None
            ),
            "paired_stack_write_claim": (
                stack_write_claim if stack_write_supported else None
            ),
            "paired_stack_writes_claim": (
                stack_writes_claim if stack_writes_supported else None
            ),
            "paired_prepared_writes_claim": (
                prepared_writes_claim if prepared_writes_supported else None
            ),
            "prepared_dynamic_stack_spill_claim": (
                prepared_dynamic_stack_spill_claim
                if prepared_writes_supported else None
            ),
            "guard_relation_claim": guard_relation_claim,
            "flag_transfer_claim": flag_transfer_claim,
            "stack_transfer_claims": stack_transfer_claims,
        }
    return [by_edge[index] for index in sorted(by_edge)]


def _segment_refinement_diagnostic_report(
    diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
    failed_check_counts = Counter(
        str(code)
        for row in diagnostics
        if not bool(row.get("eligible"))
        for code in row.get("failed_checks", [])
    )
    return {
        "format": "stage-a-segment-refinement-diagnostics-v1",
        "status": "analysis_only",
        "counts": {
            "edges": len(diagnostics),
            "eligible": sum(bool(row.get("eligible")) for row in diagnostics),
            "incomplete": sum(
                not bool(row.get("eligible")) for row in diagnostics
            ),
            "failed_checks": dict(sorted(failed_check_counts.items())),
        },
        "edges": diagnostics,
        "trust": {
            "role": "untrusted_explanation_of_certificate_eligibility",
            "acceptance_authority": False,
            "final_pass_requires": "pe32ProgramsEquivalent",
        },
    }

def _import_register_transfer_claims(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    source_index: int,
    target_index: int,
    seeds: list[dict[str, Any]],
) -> list[dict[str, Any]] | None:
    target_relations = contract["regions"][target_index].get(
        "input_import_relations", []
    )
    if not target_relations:
        return []

    def import_key(imported: dict[str, Any]) -> tuple[str, str, str | int]:
        if "symbol" in imported:
            return (str(imported["dll"]).lower(), "symbol", str(imported["symbol"]))
        return (str(imported["dll"]).lower(), "ordinal", int(imported["ordinal"]))

    source_relations = contract["regions"][source_index].get(
        "input_import_relations", []
    )
    original_registers = behaviors[source_index]["original_ir"].get("registers") or {}
    candidate_registers = behaviors[source_index]["candidate_ir"].get("registers") or {}
    claims: list[dict[str, Any]] = []
    for target_relation in target_relations:
        target_key = import_key(target_relation["import"])
        matches: list[dict[str, Any]] = []
        for seed_index, seed in enumerate(seeds):
            if (
                int(seed["region_index"]) == source_index
                and str(seed["original_register"]) == str(target_relation["original"])
                and str(seed["candidate_register"]) == str(target_relation["candidate"])
                and import_key(seed["import"]) == target_key
            ):
                matches.append({"kind": "seed", "seed_index": seed_index, **seed})
        for source_relation in source_relations:
            if import_key(source_relation["import"]) != target_key:
                continue
            original_expression = original_registers.get(
                str(target_relation["original"])
            ) or {}
            candidate_expression = candidate_registers.get(
                str(target_relation["candidate"])
            ) or {}
            if (
                original_expression.get("op") == "input_reg"
                and candidate_expression.get("op") == "input_reg"
                and str(original_expression.get("reg"))
                    == str(source_relation["original"])
                and str(candidate_expression.get("reg"))
                    == str(source_relation["candidate"])
            ):
                matches.append({
                    "kind": "preserve",
                    "import": target_relation["import"],
                    "source_original_register": source_relation["original"],
                    "source_candidate_register": source_relation["candidate"],
                    "target_original_register": target_relation["original"],
                    "target_candidate_register": target_relation["candidate"],
                })
        if len(matches) != 1:
            return None
        claims.append(matches[0])
    return claims

def _dynamic_range_transfer_claims(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    source_index: int,
    target_index: int,
    original_guard: dict[str, Any],
    candidate_guard: dict[str, Any],
) -> list[dict[str, Any]] | None:
    target_relations = contract["regions"][target_index].get(
        "input_dynamic_range_relations", []
    )
    if not target_relations:
        return []
    source_relations = contract["regions"][source_index].get(
        "input_dynamic_range_relations", []
    )
    source_stack_relations = contract["regions"][source_index].get(
        "input_dynamic_stack_range_relations", []
    )
    original_registers = behaviors[source_index]["original_ir"].get("registers") or {}
    candidate_registers = behaviors[source_index]["candidate_ir"].get("registers") or {}
    prepared_writes = _paired_prepared_word_writes_claim(
        contract["regions"][source_index],
        behaviors[source_index],
        contract.get("static_word_relation_slots", []),
        static_dynamic_pointer_slots=contract.get(
            "static_dynamic_pointer_slots", []
        ),
    )
    single_dynamic_write = None
    if isinstance(prepared_writes, dict):
        writes = prepared_writes.get("writes", [])
        if len(writes) == 1 and writes[0].get("kind") == "dynamic_word":
            single_dynamic_write = writes[0]
    claims: list[dict[str, Any]] = []
    for target_relation in target_relations:
        target_words = {
            (int(word["offset"]), str(word["kind"]))
            for word in target_relation.get("required_words", [])
        }
        target_active_words = {
            (int(word["offset"]), str(word["kind"]))
            for word in target_relation.get("active_words", [])
        }
        matches: list[dict[str, Any]] = []
        original_expression = original_registers.get(
            str(target_relation["original"])
        ) or {}
        candidate_expression = candidate_registers.get(
            str(target_relation["candidate"])
        ) or {}
        for source_relation in source_relations:
            source_words = {
                (int(word["offset"]), str(word["kind"]))
                for word in source_relation.get("required_words", [])
            }
            source_active_words = {
                (int(word["offset"]), str(word["kind"]))
                for word in source_relation.get("active_words", [])
            }
            if (
                int(source_relation.get("original_offset", -1))
                    == int(target_relation.get("original_offset", -2))
                and int(source_relation.get("candidate_offset", -1))
                    == int(target_relation.get("candidate_offset", -2))
                and target_words <= source_words
                and target_active_words <= source_active_words
                and original_expression == {
                    "op": "input_reg", "reg": source_relation["original"]
                }
                and candidate_expression == {
                    "op": "input_reg", "reg": source_relation["candidate"]
                }
            ):
                matches.append({
                    "kind": (
                        "prepared_preserve"
                        if isinstance(prepared_writes, dict)
                        else "preserve"
                    ),
                    "source_relation": source_relation,
                    "target_relation": target_relation,
                })
            if (
                single_dynamic_write is not None
                and single_dynamic_write.get("source_relation") == source_relation
                and int(source_relation.get("original_offset", -1))
                    == int(target_relation.get("original_offset", -2))
                and int(source_relation.get("candidate_offset", -1))
                    == int(target_relation.get("candidate_offset", -2))
                and target_words <= source_words
                and target_active_words == source_active_words | {
                    (
                        int(single_dynamic_write["relation"]["offset"]),
                        str(single_dynamic_write["relation"]["kind"]),
                    )
                }
                and (
                    int(single_dynamic_write["relation"]["offset"]),
                    str(single_dynamic_write["relation"]["kind"]),
                ) not in source_active_words
                and original_expression == {
                    "op": "input_reg", "reg": source_relation["original"]
                }
                and candidate_expression == {
                    "op": "input_reg", "reg": source_relation["candidate"]
                }
            ):
                matches.append({
                    "kind": "activate",
                    "source_relation": source_relation,
                    "target_relation": target_relation,
                    "relation": single_dynamic_write["relation"],
                    "original_amount": int(single_dynamic_write["original_amount"]),
                    "candidate_amount": int(single_dynamic_write["candidate_amount"]),
                    "value": single_dynamic_write["value"],
                })
            pointer_words = [
                word for word in source_relation.get("active_words", [])
                if word.get("kind") == "nullableDynamicPointer"
            ]
            for pointer_word in pointer_words:
                pointer_offset = int(pointer_word["offset"])
                original_read = {
                    "op": "read32",
                    "address": {
                        "op": "add",
                        "left": {
                            "op": "input_reg",
                            "reg": source_relation["original"],
                        },
                        "right": {"op": "constant", "value": pointer_offset},
                    },
                }
                candidate_read = {
                    "op": "read32",
                    "address": {
                        "op": "add",
                        "left": {
                            "op": "input_reg",
                            "reg": source_relation["candidate"],
                        },
                        "right": {"op": "constant", "value": pointer_offset},
                    },
                }

                if (
                    int(source_relation.get("original_offset", -1)) == 0
                    and int(source_relation.get("candidate_offset", -1)) == 0
                    and int(target_relation.get("original_offset", -1)) == 0
                    and int(target_relation.get("candidate_offset", -1)) == 0
                    and target_words <= source_words
                    and not target_active_words
                    and original_expression == original_read
                    and candidate_expression == candidate_read
                    and original_guard == _nonzero_word_guard(original_read)
                    and candidate_guard == _nonzero_word_guard(candidate_read)
                ):
                    matches.append({
                        "kind": "nullable_pointer",
                        "source_relation": source_relation,
                        "target_relation": target_relation,
                        "pointer_offset": pointer_offset,
                    })
        for source_relation in source_stack_relations:
            source_words = {
                (int(word["offset"]), str(word["kind"]))
                for word in source_relation.get("required_words", [])
            }
            source_active_words = {
                (int(word["offset"]), str(word["kind"]))
                for word in source_relation.get("active_words", [])
            }
            window = source_relation.get("window") or {}
            stack_offset = int(source_relation.get("stack_offset", -1))

            def stack_read(register: str) -> dict[str, Any]:
                address: dict[str, Any] = {
                    "op": "input_reg", "reg": register,
                }
                if stack_offset != 0:
                    address = {
                        "op": "add",
                        "left": address,
                        "right": {"op": "constant", "value": stack_offset},
                    }
                return {"op": "read32", "address": address}

            if (
                stack_offset >= 0
                and int(source_relation.get("original_offset", -1))
                    == int(target_relation.get("original_offset", -2))
                and int(source_relation.get("candidate_offset", -1))
                    == int(target_relation.get("candidate_offset", -2))
                and target_words <= source_words
                and target_active_words <= source_active_words
                and original_expression == stack_read(
                    str(window.get("original_register"))
                )
                and candidate_expression == stack_read(
                    str(window.get("candidate_register"))
                )
            ):
                matches.append({
                    "kind": "stack_reload",
                    "source_relation": source_relation,
                    "target_relation": target_relation,
                })
        for slot in contract.get("static_dynamic_pointer_slots", []):
            slot_words = {
                (int(word["offset"]), str(word["kind"]))
                for word in slot.get("required_words", [])
            }
            original_read = {
                "op": "read32",
                "address": {
                    "op": "constant",
                    "value": int(slot["original_address"]),
                },
            }
            candidate_read = {
                "op": "read32",
                "address": {
                    "op": "constant",
                    "value": int(slot["candidate_address"]),
                },
            }
            if (
                int(target_relation.get("original_offset", -1)) == 0
                and int(target_relation.get("candidate_offset", -1)) == 0
                and target_words <= slot_words
                and not target_active_words
                and original_expression == original_read
                and candidate_expression == candidate_read
                and original_guard == _nonzero_word_guard(original_read)
                and candidate_guard == _nonzero_word_guard(candidate_read)
            ):
                matches.append({
                    "kind": "static_pointer_seed",
                    "slot": slot,
                    "target_relation": target_relation,
                })
        if len(matches) != 1:
            return None
        claims.append(matches[0])
    return claims

def _dynamic_range_register_output_claims(
    register_region: dict[str, Any],
    dynamic_transfer_claims: list[dict[str, Any]] | None,
    behavior: dict[str, Any] | None = None,
    guard_relation_claim: dict[str, Any] | None = None,
) -> list[dict[str, Any]] | None:
    if dynamic_transfer_claims is None:
        return None
    ordinary_outputs = {
        (
            claim["output"]["original"],
            claim["output"]["candidate"],
            claim["output"]["relation"],
        )
        for claim in register_region.get("output_claims", [])
        if isinstance(claim.get("output"), dict)
    }
    missing = [
        output for output in register_region.get("outputs", [])
        if (output["original"], output["candidate"], output["relation"])
            not in ordinary_outputs
    ]
    if not missing:
        return []
    result: list[dict[str, Any]] = []
    for output in missing:
        matches = [
            claim for claim in dynamic_transfer_claims
            if claim.get("kind") in {
                "nullable_pointer", "static_pointer_seed", "stack_reload",
            }
            and claim["target_relation"]["original"] == output["original"]
            and claim["target_relation"]["candidate"] == output["candidate"]
            and int(claim["target_relation"].get("original_offset", -1)) == 0
            and int(claim["target_relation"].get("candidate_offset", -1)) == 0
            and output["relation"] == "related_word"
        ]
        if (
            behavior is not None
            and guard_relation_claim is not None
            and guard_relation_claim.get("profile")
                == "static_dynamic_pointer_guard_v1"
            and guard_relation_claim.get("kind") == "zero"
            and output["relation"] == "related_word"
        ):
            slot = guard_relation_claim["slot"]
            original_expression = (
                behavior.get("original_ir", {}).get("registers") or {}
            ).get(output["original"])
            candidate_expression = (
                behavior.get("candidate_ir", {}).get("registers") or {}
            ).get(output["candidate"])
            if (
                original_expression == {
                    "op": "read32",
                    "address": {
                        "op": "constant", "value": int(slot["original_address"]),
                    },
                }
                and candidate_expression == {
                    "op": "read32",
                    "address": {
                        "op": "constant", "value": int(slot["candidate_address"]),
                    },
                }
            ):
                matches.append({
                    "kind": "static_pointer_zero",
                    "slot": slot,
                    "output": output,
                })
        if len(matches) != 1:
            return None
        result.append({"output": output, "claim": matches[0]})
    return result

def _static_dynamic_pointer_slot_guard_claim(
    contract: dict[str, Any],
    original_guard: dict[str, Any],
    candidate_guard: dict[str, Any],
) -> dict[str, Any] | None:
    matches: list[dict[str, Any]] = []
    for slot in contract.get("static_dynamic_pointer_slots", []):
        original_read = {
            "op": "read32",
            "address": {
                "op": "constant", "value": int(slot["original_address"]),
            },
        }
        candidate_read = {
            "op": "read32",
            "address": {
                "op": "constant", "value": int(slot["candidate_address"]),
            },
        }
        original_zero = _nonzero_word_guard(original_read)["value"]
        candidate_zero = _nonzero_word_guard(candidate_read)["value"]
        for kind, expected_original, expected_candidate in (
            ("zero", original_zero, candidate_zero),
            ("nonzero", _nonzero_word_guard(original_read),
             _nonzero_word_guard(candidate_read)),
        ):
            if original_guard == expected_original and candidate_guard == expected_candidate:
                matches.append({
                    "profile": "static_dynamic_pointer_guard_v1",
                    "kind": kind,
                    "slot": slot,
                })
    return matches[0] if len(matches) == 1 else None


def _input_flags_guard_claim(
    source: dict[str, Any],
    original_guard: dict[str, Any],
    candidate_guard: dict[str, Any],
) -> dict[str, Any] | None:
    if original_guard != candidate_guard:
        return None
    allowed = {
        int(index) for index in source.get("flag_inputs", list(FLAG_BITS))
    }

    def supported(expression: Any) -> bool:
        if not isinstance(expression, dict):
            return False
        operation = expression.get("op")
        if operation == "input_flag":
            return _integer(expression.get("index")) in allowed
        if operation == "not":
            return supported(expression.get("value"))
        if operation in {"and", "or", "xor"}:
            return supported(expression.get("left")) and supported(
                expression.get("right")
            )
        return False

    if not supported(original_guard):
        return None
    return {
        "profile": "input_flags_guard_v1",
        "guard": original_guard,
    }


def _exact_pure_guard_claim(
    source: dict[str, Any],
    original_guard: dict[str, Any],
    candidate_guard: dict[str, Any],
    original_bin: StageABinary | None = None,
    candidate_bin: StageABinary | None = None,
) -> dict[str, Any] | None:
    if original_guard != candidate_guard:
        return None
    exact_registers = {
        str(relation["original"])
        for relation in source.get("input_relations", [])
        if relation.get("relation") == "exact"
        and relation.get("original") == relation.get("candidate")
    }
    allowed_flags = {
        int(index) for index in source.get("flag_inputs", list(FLAG_BITS))
    }

    def exact_expression(expression: Any) -> bool:
        if not isinstance(expression, dict):
            return False
        operation = expression.get("op")
        if operation == "input_reg":
            return str(expression.get("reg")) in exact_registers
        if operation == "input_flag_value":
            return _integer(expression.get("bit")) in allowed_flags
        if operation in {
            "input_fs_base", "input_x87_control", "input_x87_status",
            "constant", "undefined",
        }:
            return True
        if operation == "read32":
            address = expression.get("address") or {}
            if (
                original_bin is None
                or candidate_bin is None
                or address.get("op") != "constant"
            ):
                return False
            absolute = int(address.get("value", -1))
            original_value = _immutable_image_u32(original_bin, absolute)
            candidate_value = _immutable_image_u32(candidate_bin, absolute)
            return original_value is not None and original_value == candidate_value
        if operation == "read8":
            address = expression.get("address") or {}
            if (
                original_bin is None
                or candidate_bin is None
                or address.get("op") != "constant"
            ):
                return False
            absolute = int(address.get("value", -1))
            original_value = _immutable_image_u32(original_bin, absolute)
            candidate_value = _immutable_image_u32(candidate_bin, absolute)
            return original_value is not None and original_value == candidate_value
        if operation in {
            "add", "sub", "bit_and", "bit_xor", "shift_left_by",
            "shift_right_by", "shift_arithmetic_right_by", "bit_or",
            "unsigned_less_value", "multiply", "multiply_high_unsigned",
            "multiply_high_signed",
        }:
            return exact_expression(expression.get("left")) and exact_expression(
                expression.get("right")
            )
        if operation in {
            "bit_not", "extract_byte", "shift_left", "shift_right",
            "bit_value", "lowest_set_bit", "highest_set_bit",
        }:
            return exact_expression(expression.get("value"))
        if operation == "if_equal":
            return all(exact_expression(expression.get(field)) for field in (
                "left", "right", "then", "else",
            ))
        if operation in {
            "divide_quotient", "divide_remainder", "division_valid_value",
        }:
            return all(exact_expression(expression.get(field)) for field in (
                "high", "low", "divisor",
            ))
        return False

    def exact_boolean(expression: Any) -> bool:
        if not isinstance(expression, dict):
            return False
        operation = expression.get("op")
        if operation in {"equal", "unsigned_less"}:
            return exact_expression(expression.get("left")) and exact_expression(
                expression.get("right")
            )
        if operation == "not":
            return exact_boolean(expression.get("value"))
        if operation in {"and", "or", "xor"}:
            return exact_boolean(expression.get("left")) and exact_boolean(
                expression.get("right")
            )
        if operation in {"msb", "bit"}:
            return exact_expression(expression.get("value"))
        if operation == "input_flag":
            return _integer(expression.get("index")) in allowed_flags
        if operation == "division_valid":
            return all(exact_expression(expression.get(field)) for field in (
                "high", "low", "divisor",
            ))
        return False

    if not exact_boolean(original_guard):
        return None
    return {
        "profile": "exact_pure_guard_v1",
        "guard": original_guard,
    }


def _paired_exact_guard_claim(
    contract: dict[str, Any],
    source: dict[str, Any],
    original_guard: dict[str, Any],
    candidate_guard: dict[str, Any],
    original_bin: StageABinary | None = None,
    candidate_bin: StageABinary | None = None,
) -> dict[str, Any] | None:
    exact_registers = {
        (str(relation["original"]), str(relation["candidate"]))
        for relation in source.get("input_relations", [])
        if relation.get("relation") == "exact"
    }
    allowed_flags = {
        int(index) for index in source.get("flag_inputs", list(FLAG_BITS))
    }
    static_slots = contract.get("static_word_relation_slots", [])

    def paired_static_expression(
        original: Any, candidate: Any,
    ) -> tuple[dict[str, Any], int, int] | None:
        """Recover a side-specific expression using only immutable PE facts."""
        if not isinstance(original, dict) or not isinstance(candidate, dict):
            return None
        operation = original.get("op")
        if operation != candidate.get("op"):
            return None
        if operation == "constant":
            original_value = _integer(original.get("value")) & 0xFFFFFFFF
            candidate_value = _integer(candidate.get("value")) & 0xFFFFFFFF
            return ({
                "kind": "constant",
                "original": original_value,
                "candidate": candidate_value,
            }, original_value, candidate_value)
        if operation == "read32":
            original_address = original.get("address") or {}
            candidate_address = candidate.get("address") or {}
            if (
                original_bin is None
                or candidate_bin is None
                or original_address.get("op") != "constant"
                or candidate_address.get("op") != "constant"
            ):
                return None
            original_absolute = _integer(original_address.get("value"))
            candidate_absolute = _integer(candidate_address.get("value"))
            original_value = _immutable_image_u32(original_bin, original_absolute)
            candidate_value = _immutable_image_u32(candidate_bin, candidate_absolute)
            if original_value is None or candidate_value is None:
                return None
            return ({
                "kind": "read32",
                "original_address": original_absolute,
                "candidate_address": candidate_absolute,
            }, original_value, candidate_value)
        if operation in {
            "add", "sub", "bit_and", "bit_xor", "shift_left_by",
            "shift_right_by", "shift_arithmetic_right_by", "bit_or",
            "unsigned_less_value", "multiply", "multiply_high_unsigned",
            "multiply_high_signed",
        }:
            left = paired_static_expression(
                original.get("left"), candidate.get("left")
            )
            right = paired_static_expression(
                original.get("right"), candidate.get("right")
            )
            if left is None or right is None:
                return None

            def evaluate(left_value: int, right_value: int) -> int:
                mask = 0xFFFFFFFF
                if operation == "add":
                    return (left_value + right_value) & mask
                if operation == "sub":
                    return (left_value - right_value) & mask
                if operation == "bit_and":
                    return left_value & right_value
                if operation == "bit_xor":
                    return left_value ^ right_value
                if operation == "bit_or":
                    return left_value | right_value
                if operation == "shift_left_by":
                    return (left_value << (right_value % 32)) & mask
                if operation == "shift_right_by":
                    return left_value >> (right_value % 32)
                if operation == "shift_arithmetic_right_by":
                    signed = (
                        left_value if left_value < 0x80000000
                        else left_value - 0x100000000
                    )
                    return (signed >> (right_value % 32)) & mask
                if operation == "unsigned_less_value":
                    return int(left_value < right_value)
                product = left_value * right_value
                if operation == "multiply":
                    return product & mask
                if operation == "multiply_high_unsigned":
                    return (product >> 32) & mask
                signed_left = (
                    left_value if left_value < 0x80000000
                    else left_value - 0x100000000
                )
                signed_right = (
                    right_value if right_value < 0x80000000
                    else right_value - 0x100000000
                )
                return ((signed_left * signed_right) >> 32) & mask

            original_value = evaluate(left[1], right[1])
            candidate_value = evaluate(left[2], right[2])
            return ({
                "kind": "binary",
                "operation": operation,
                "left": left[0],
                "right": right[0],
            }, original_value, candidate_value)
        return None

    def paired_constant_read(
        original_expression: dict[str, Any],
        candidate_expression: dict[str, Any],
        kind: str,
    ) -> dict[str, Any] | None:
        original_address = original_expression.get("address") or {}
        candidate_address = candidate_expression.get("address") or {}
        if (
            original_address.get("op") != "constant"
            or candidate_address.get("op") != "constant"
        ):
            return None
        original_absolute = int(original_address.get("value", -1))
        candidate_absolute = int(candidate_address.get("value", -1))
        if original_bin is not None and candidate_bin is not None:
            original_value = _immutable_image_u32(original_bin, original_absolute)
            candidate_value = _immutable_image_u32(candidate_bin, candidate_absolute)
            if original_value is not None and original_value == candidate_value:
                return {
                    "kind": kind,
                    "original_address": original_absolute,
                    "candidate_address": candidate_absolute,
                }
        matching_slots = [
            slot for slot in static_slots
            if slot.get("relation") == "exact"
            and int(slot.get("original_address", -1)) == original_absolute
            and int(slot.get("candidate_address", -1)) == candidate_absolute
        ]
        if len(matching_slots) != 1:
            return None
        return {
            "kind": kind,
            "original_address": original_absolute,
            "candidate_address": candidate_absolute,
        }

    def paired_expression(
        original: Any, candidate: Any,
    ) -> dict[str, Any] | None:
        if not isinstance(original, dict) or not isinstance(candidate, dict):
            return None
        operation = original.get("op")
        if operation != candidate.get("op"):
            return None
        if operation == "input_reg":
            original_register = str(original.get("reg"))
            candidate_register = str(candidate.get("reg"))
            if (original_register, candidate_register) not in exact_registers:
                return None
            return {
                "kind": "input_reg",
                "original": original_register,
                "candidate": candidate_register,
            }
        if operation == "input_flag_value":
            original_bit = _integer(original.get("bit"))
            candidate_bit = _integer(candidate.get("bit"))
            if original_bit != candidate_bit or original_bit not in allowed_flags:
                return None
            return {"kind": "input_flag_value", "bit": original_bit}
        if operation in {
            "input_fs_base", "input_x87_control", "input_x87_status",
        }:
            return {"kind": operation}
        if operation == "constant":
            original_value = _integer(original.get("value"))
            if original_value != _integer(candidate.get("value")):
                return None
            return {"kind": "constant", "value": original_value}
        if operation == "undefined":
            original_slot = _integer(original.get("slot"))
            if original_slot != _integer(candidate.get("slot")):
                return None
            return {"kind": "undefined", "slot": original_slot}
        if operation in {"read8", "read32"}:
            direct = paired_constant_read(original, candidate, operation)
            if direct is not None:
                return direct
            address = paired_static_expression(
                original.get("address"), candidate.get("address")
            )
            if address is None or original_bin is None or candidate_bin is None:
                return None
            original_value = _immutable_image_u32(original_bin, address[1])
            candidate_value = _immutable_image_u32(candidate_bin, address[2])
            if original_value is None or original_value != candidate_value:
                return None
            return {
                "kind": f"{operation}_at",
                "address": address[0],
            }
        if operation in {
            "add", "sub", "bit_and", "bit_xor", "shift_left_by",
            "shift_right_by", "shift_arithmetic_right_by", "bit_or",
            "unsigned_less_value", "multiply", "multiply_high_unsigned",
            "multiply_high_signed",
        }:
            left = paired_expression(original.get("left"), candidate.get("left"))
            right = paired_expression(original.get("right"), candidate.get("right"))
            if left is None or right is None:
                return None
            return {
                "kind": "binary", "operation": operation,
                "left": left, "right": right,
            }
        if operation in {"bit_not", "lowest_set_bit", "highest_set_bit"}:
            value = paired_expression(original.get("value"), candidate.get("value"))
            if value is None:
                return None
            return {"kind": "unary", "operation": operation, "value": value}
        if operation in {
            "extract_byte", "shift_left", "shift_right", "bit_value",
        }:
            metadata_key = "index" if operation in {
                "extract_byte", "bit_value",
            } else "amount"
            index = _integer(original.get(metadata_key))
            if index != _integer(candidate.get(metadata_key)):
                return None
            value = paired_expression(original.get("value"), candidate.get("value"))
            if value is None:
                return None
            return {
                "kind": "indexed", "operation": operation,
                "index": index, "value": value,
            }
        if operation == "if_equal":
            children = {
                field: paired_expression(original.get(field), candidate.get(field))
                for field in ("left", "right", "then", "else")
            }
            if any(value is None for value in children.values()):
                return None
            return {"kind": "if_equal", **children}
        if operation in {
            "divide_quotient", "divide_remainder", "division_valid_value",
        }:
            children = {
                field: paired_expression(original.get(field), candidate.get(field))
                for field in ("high", "low", "divisor")
            }
            if any(value is None for value in children.values()):
                return None
            return {"kind": "ternary", "operation": operation, **children}
        return None

    def constant(value: int) -> dict[str, Any]:
        return {"kind": "constant", "value": value}

    def paired_boolean(
        original: Any, candidate: Any,
    ) -> dict[str, Any] | None:
        if not isinstance(original, dict) or not isinstance(candidate, dict):
            return None
        operation = original.get("op")
        if operation != candidate.get("op"):
            return None
        if operation == "equal":
            left = paired_expression(original.get("left"), candidate.get("left"))
            right = paired_expression(original.get("right"), candidate.get("right"))
            if left is None or right is None:
                return None
            return {
                "kind": "if_equal", "left": left, "right": right,
                "then": constant(1), "else": constant(0),
            }
        if operation == "unsigned_less":
            left = paired_expression(original.get("left"), candidate.get("left"))
            right = paired_expression(original.get("right"), candidate.get("right"))
            if left is None or right is None:
                return None
            return {
                "kind": "binary", "operation": "unsigned_less_value",
                "left": left, "right": right,
            }
        if operation == "not":
            value = paired_boolean(original.get("value"), candidate.get("value"))
            if value is None:
                return None
            return {
                "kind": "if_equal", "left": value, "right": constant(0),
                "then": constant(1), "else": constant(0),
            }
        if operation in {"and", "or", "xor"}:
            left = paired_boolean(original.get("left"), candidate.get("left"))
            right = paired_boolean(original.get("right"), candidate.get("right"))
            if left is None or right is None:
                return None
            return {
                "kind": "binary",
                "operation": {"and": "bit_and", "or": "bit_or",
                              "xor": "bit_xor"}[operation],
                "left": left, "right": right,
            }
        if operation == "msb":
            value = paired_expression(original.get("value"), candidate.get("value"))
            if value is None:
                return None
            return {
                "kind": "indexed", "operation": "bit_value",
                "index": 31, "value": value,
            }
        if operation == "bit":
            index = _integer(original.get("index"))
            if index != _integer(candidate.get("index")):
                return None
            value = paired_expression(original.get("value"), candidate.get("value"))
            if value is None:
                return None
            return {
                "kind": "indexed", "operation": "bit_value",
                "index": index, "value": value,
            }
        if operation == "input_flag":
            original_index = _integer(original.get("index"))
            candidate_index = _integer(candidate.get("index"))
            if original_index != candidate_index or original_index not in allowed_flags:
                return None
            return {"kind": "input_flag_value", "bit": original_index}
        if operation == "division_valid":
            children = {
                field: paired_expression(original.get(field), candidate.get(field))
                for field in ("high", "low", "divisor")
            }
            if any(value is None for value in children.values()):
                return None
            return {
                "kind": "ternary", "operation": "division_valid_value",
                **children,
            }
        return None

    witness = paired_boolean(original_guard, candidate_guard)
    if witness is None:
        return None
    return {
        "profile": "paired_exact_guard_v1",
        "original_guard": original_guard,
        "candidate_guard": candidate_guard,
        "witness": witness,
    }


def _preserved_input_flags_claim(
    source: dict[str, Any],
    target_flags: list[int],
    behavior: dict[str, Any],
) -> dict[str, Any] | None:
    if not target_flags:
        return None
    source_flags = {
        int(index) for index in source.get("flag_inputs", list(FLAG_BITS))
    }
    if any(bit not in source_flags for bit in target_flags):
        return None
    fields = {
        0: "carry",
        2: "parity",
        6: "zero",
        7: "sign",
        11: "overflow",
    }

    def preserves(side: str, bit: int) -> bool:
        if bit == 10:
            return True
        field = fields.get(bit)
        if field is None:
            return False
        flags = (behavior.get(side) or {}).get("flags") or {}
        return flags.get(field) == {"op": "input_flag", "index": bit}

    if not all(
        preserves(side, bit)
        for side in ("original_ir", "candidate_ir")
        for bit in target_flags
    ):
        return None
    return {
        "profile": "preserved_input_flags_v1",
        "bits": list(target_flags),
    }


def _related_word_zero_guard_claim(
    source: dict[str, Any],
    original_guard: dict[str, Any],
    candidate_guard: dict[str, Any],
) -> dict[str, Any] | None:
    def parse(expression: dict[str, Any]) -> tuple[str, int] | None:
        not_count = 0
        while expression.get("op") == "not":
            not_count += 1
            expression = expression.get("value") or {}
        if expression.get("op") != "equal":
            return None
        left = expression.get("left") or {}
        right = expression.get("right") or {}
        if right.get("op") == "constant" and int(right.get("value", -1)) == 0:
            word = left
        elif left.get("op") == "constant" and int(left.get("value", -1)) == 0:
            word = right
        else:
            return None
        if word.get("op") != "bit_and" or word.get("left") != word.get("right"):
            return None
        register = word.get("left") or {}
        if register.get("op") != "input_reg":
            return None
        return str(register["reg"]), not_count

    original = parse(original_guard)
    candidate = parse(candidate_guard)
    if original is None or candidate is None or original[1] != candidate[1]:
        return None
    relation = next((
        relation for relation in source.get("input_relations", [])
        if str(relation["original"]) == original[0]
        and str(relation["candidate"]) == candidate[0]
        and relation["relation"] in {"exact", "related_word"}
    ), None)
    if relation is None:
        return None
    return {
        "profile": "related_word_zero_guard_v1",
        "original_register": original[0],
        "candidate_register": candidate[0],
        "value_relation": relation["relation"],
        "not_count": original[1],
    }

def _paired_stack_guard_claim(
    source: dict[str, Any],
    original_guard: dict[str, Any],
    candidate_guard: dict[str, Any],
) -> dict[str, Any] | None:
    windows = source.get("stack_windows", [])
    if not windows:
        return None

    def register_offset(address: Any) -> tuple[str, int] | None:
        if not isinstance(address, dict) or address.get("op") != "add":
            return None
        register = address.get("left")
        constant = address.get("right")
        if (
            not isinstance(register, dict)
            or register.get("op") != "input_reg"
            or not isinstance(constant, dict)
            or constant.get("op") != "constant"
        ):
            return None
        offset = int(constant.get("value", -1))
        if offset < 0 or offset >= 2**31:
            return None
        return str(register.get("reg")), offset

    def parse(expression: dict[str, Any]) -> tuple[str, int, int] | None:
        not_count = 0
        while expression.get("op") == "not":
            not_count += 1
            expression = expression.get("value") or {}
        if expression.get("op") != "equal":
            return None
        left = expression.get("left") or {}
        right = expression.get("right") or {}
        if right.get("op") == "constant" and int(right.get("value", -1)) == 0:
            word = left
        elif left.get("op") == "constant" and int(left.get("value", -1)) == 0:
            word = right
        else:
            return None
        if word.get("op") != "bit_and" or word.get("left") != word.get("right"):
            return None
        read = word.get("left") or {}
        if read.get("op") != "read32":
            return None
        address = register_offset(read.get("address"))
        if address is None or address[1] % 4 != 0:
            return None
        return address[0], address[1], not_count

    original = parse(original_guard)
    candidate = parse(candidate_guard)
    if (
        original is None
        or candidate is None
        or original[1:] != candidate[1:]
    ):
        return None
    matches = [
        window for window in windows
        if str(window.get("original_register")) == original[0]
        and str(window.get("candidate_register")) == candidate[0]
        and original[1] + 4 <= int(window.get("bytes_above", -1))
    ]
    if len(matches) != 1:
        return None
    return {
        "profile": "paired_stack_read_guard_v1",
        "window": matches[0],
        "offset": original[1],
        "not_count": original[2],
    }


def _paired_stack_relative_guard_claim(
    source: dict[str, Any],
    original_guard: dict[str, Any],
    candidate_guard: dict[str, Any],
) -> dict[str, Any] | None:
    windows = source.get("stack_windows", [])
    if not windows:
        return None

    def register_adjustment(
        address: Any,
    ) -> tuple[str, dict[str, Any]] | None:
        if not isinstance(address, dict):
            return None
        if address.get("op") == "input_reg":
            return str(address.get("reg")), {"kind": "identity"}
        operation = str(address.get("op"))
        register = address.get("left") or {}
        constant = address.get("right") or {}
        if (
            operation not in {"add", "sub"}
            or register.get("op") != "input_reg"
            or constant.get("op") != "constant"
        ):
            return None
        value = int(constant.get("value", -1))
        if value < 0 or value >= 2**32:
            return None
        if operation == "sub":
            adjustment = {"kind": "subtract", "amount": value}
        elif value >= 2**31:
            adjustment = {"kind": "subtract", "amount": 2**32 - value}
        else:
            adjustment = {"kind": "add", "amount": value}
        return str(register.get("reg")), adjustment

    def parse(
        expression: dict[str, Any],
    ) -> tuple[str, dict[str, Any], dict[str, Any], bool, int] | None:
        not_count = 0
        while expression.get("op") == "not":
            not_count += 1
            expression = expression.get("value") or {}
        if expression.get("op") != "equal":
            return None
        left = expression.get("left") or {}
        right = expression.get("right") or {}
        if right.get("op") == "constant" and int(right.get("value", -1)) == 0:
            word = left
        elif left.get("op") == "constant" and int(left.get("value", -1)) == 0:
            word = right
        else:
            return None
        masked = word.get("op") == "bit_and" and word.get("left") == word.get("right")
        if masked:
            word = word.get("left") or {}
        read = word
        address = read.get("address") or {}
        if read.get("op") != "read32":
            return None
        parsed = register_adjustment(address)
        if parsed is None:
            return None
        return parsed[0], parsed[1], address, masked, not_count

    original = parse(original_guard)
    candidate = parse(candidate_guard)
    if (
        original is None
        or candidate is None
        or original[1] != candidate[1]
        or original[3:] != candidate[3:]
    ):
        return None
    adjustment = original[1]

    def covered(window: dict[str, Any]) -> bool:
        kind = adjustment["kind"]
        amount = int(adjustment.get("amount", 0))
        if kind == "identity":
            return 4 <= int(window.get("bytes_above", -1))
        if amount % 4 != 0:
            return False
        if kind == "add":
            return amount + 4 <= int(window.get("bytes_above", -1))
        return 4 <= amount <= int(window.get("bytes_below", -1))

    matches = [
        window for window in windows
        if str(window.get("original_register")) == original[0]
        and str(window.get("candidate_register")) == candidate[0]
        and covered(window)
    ]
    if len(matches) != 1:
        return None
    return {
        "profile": "paired_stack_read_relative_guard_v1",
        "window": matches[0],
        "adjustment": adjustment,
        "original_address": original[2],
        "candidate_address": candidate[2],
        "masked": original[3],
        "not_count": original[4],
    }

def _stack_read32_sub_output_claim(
    region: dict[str, Any],
    output: dict[str, Any],
    original_expression: dict[str, Any],
    candidate_expression: dict[str, Any],
) -> dict[str, Any] | None:
    def parse(
        expression: dict[str, Any],
    ) -> tuple[str, int, int, bool, bool] | None:
        direct_read = expression.get("op") == "read32"
        if direct_read:
            read = expression
            subtract_value = 0
        elif expression.get("op") == "sub":
            read = expression.get("left") or {}
            subtract = expression.get("right") or {}
            if subtract.get("op") != "constant":
                return None
            subtract_value = int(subtract.get("value", -1))
        else:
            return None
        address = read.get("address") or {}
        direct_address = address.get("op") == "input_reg"
        if direct_address:
            register = address
            offset_value = 0
        elif address.get("op") == "add":
            register = address.get("left") or {}
            offset = address.get("right") or {}
            if register.get("op") == "constant":
                register, offset = offset, register
            if offset.get("op") != "constant":
                return None
            offset_value = int(offset.get("value", -1))
        else:
            return None
        if (
            read.get("op") != "read32"
            or register.get("op") != "input_reg"
        ):
            return None
        if not (0 <= offset_value < 2**31 and 0 <= subtract_value < 2**32):
            return None
        return (
            str(register.get("reg")), offset_value, subtract_value, direct_read,
            direct_address,
        )

    original = parse(original_expression)
    candidate = parse(candidate_expression)
    if (
        original is None
        or candidate is None
        or original[1] != candidate[1]
        or original[2] != candidate[2]
        or output.get("relation") != "related_word"
        or original[1] % 4 != 0
        or original[2] != 0
    ):
        return None
    matches = [
        window for window in region.get("stack_windows", [])
        if str(window.get("original_register")) == original[0]
        and str(window.get("candidate_register")) == candidate[0]
        and original[1] + 4 <= int(window.get("bytes_above", -1))
    ]
    if len(matches) != 1:
        return None
    return {
        "kind": "stack_read32_sub",
        "output": output,
        "window": matches[0],
        "offset": original[1],
        "subtract": original[2],
        "original_direct_read": original[3],
        "candidate_direct_read": candidate[3],
        "original_direct_address": original[4],
        "candidate_direct_address": candidate[4],
    }


def _stack_read32_relative_output_claim(
    region: dict[str, Any],
    output: dict[str, Any],
    original_expression: dict[str, Any],
    candidate_expression: dict[str, Any],
) -> dict[str, Any] | None:
    def parse(expression: dict[str, Any]) -> tuple[str, str, int] | None:
        if expression.get("op") != "read32":
            return None
        address = expression.get("address") or {}
        if address.get("op") == "input_reg":
            return str(address.get("reg")), "identity", 0
        if address.get("op") not in {"add", "sub"}:
            return None
        register = address.get("left") or {}
        constant = address.get("right") or {}
        if address.get("op") == "add" and register.get("op") == "constant":
            register, constant = constant, register
        if register.get("op") != "input_reg" or constant.get("op") != "constant":
            return None
        value = int(constant.get("value", -1))
        if not 0 <= value < 2**32:
            return None
        if address.get("op") == "sub":
            return str(register.get("reg")), "subtract", value
        if value < 2**31:
            return str(register.get("reg")), "add", value
        return str(register.get("reg")), "subtract", 2**32 - value

    original = parse(original_expression)
    candidate = parse(candidate_expression)
    if (
        original is None
        or candidate is None
        or original[1:] != candidate[1:]
        or output.get("relation") != "related_word"
    ):
        return None
    adjustment, amount = original[1], original[2]
    matches = []
    for window in region.get("stack_windows", []):
        if (
            str(window.get("original_register")) != original[0]
            or str(window.get("candidate_register")) != candidate[0]
        ):
            continue
        if adjustment == "identity":
            valid = 4 <= int(window.get("bytes_above", -1))
        elif adjustment == "add":
            valid = amount % 4 == 0 and amount + 4 <= int(
                window.get("bytes_above", -1)
            )
        else:
            valid = (
                4 <= amount
                and amount % 4 == 0
                and amount <= int(window.get("bytes_below", -1))
            )
        if valid:
            matches.append(window)
    if len(matches) != 1:
        return None
    return {
        "kind": "stack_read32_relative",
        "output": output,
        "window": matches[0],
        "adjustment": {"kind": adjustment, "amount": amount},
    }

def _attach_stack_register_output_claims(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    register_relations: dict[str, Any],
) -> dict[str, Any]:
    for region_index, row in enumerate(register_relations.get("regions", [])):
        region = contract["regions"][region_index]
        existing = {
            (str(claim["output"]["original"]), str(claim["output"]["candidate"])):
                claim
            for claim in row.get("output_claims", [])
        }
        for output in row.get("outputs", []):
            key = (str(output["original"]), str(output["candidate"]))
            original_expression = behaviors[region_index]["original_ir"]["registers"][
                output["original"]
            ]
            candidate_expression = behaviors[region_index]["candidate_ir"]["registers"][
                output["candidate"]
            ]
            claim = _stack_read32_sub_output_claim(
                region, output, original_expression, candidate_expression
            )
            if claim is None:
                claim = _stack_read32_relative_output_claim(
                    region, output, original_expression, candidate_expression
                )
            if claim is not None:
                # A checked stack-window read is composable under StateRel. It
                # therefore supersedes a local exact-memory claim synthesized
                # before stack provenance was available.
                existing[key] = claim
                continue
            if (
                output.get("relation") == "related_word"
                and original_expression.get("op") == "input_reg"
                and candidate_expression.get("op") == "input_reg"
            ):
                matching_windows = [
                    window for window in region.get("stack_windows", [])
                    if str(window.get("original_register")) ==
                        str(original_expression.get("reg"))
                    and str(window.get("candidate_register")) ==
                        str(candidate_expression.get("reg"))
                    and int(window.get("bytes_above", 0)) > 0
                ]
                if len(matching_windows) == 1:
                    existing[key] = {
                        "kind": "stack_window_identity",
                        "output": output,
                        "window": matching_windows[0],
                    }
        row["output_claims"] = [
            existing[(str(output["original"]), str(output["candidate"]))]
            for output in row.get("outputs", [])
            if (str(output["original"]), str(output["candidate"])) in existing
        ]
        row["fully_supported_output_transfer"] = (
            len(row["output_claims"]) == len(row["outputs"])
        )
    return register_relations


def _static_word_relation_supports_register_output(
    static_relation: str, register_relation: str,
) -> bool:
    return (static_relation, register_relation) in {
        ("exact", "exact"),
        ("exact", "related_word"),
        ("related_word", "related_word"),
        ("code_pointer", "code_pointer"),
        ("data_pointer", "data_pointer"),
    }


def _attach_static_word_register_output_claims(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    register_relations: dict[str, Any],
) -> dict[str, Any]:
    slots = contract.get("static_word_relation_slots", [])
    for region_index, row in enumerate(register_relations.get("regions", [])):
        existing = {
            (str(claim["output"]["original"]), str(claim["output"]["candidate"])):
                claim
            for claim in row.get("output_claims", [])
        }
        for output in row.get("outputs", []):
            key = (str(output["original"]), str(output["candidate"]))
            if (
                key in existing
                and existing[key].get("kind") != "exact_memory"
            ):
                continue
            original_expression = behaviors[region_index]["original_ir"]["registers"][
                output["original"]
            ]
            candidate_expression = behaviors[region_index]["candidate_ir"]["registers"][
                output["candidate"]
            ]
            if (
                original_expression.get("op") != "read32"
                or candidate_expression.get("op") != "read32"
                or (original_expression.get("address") or {}).get("op") != "constant"
                or (candidate_expression.get("address") or {}).get("op") != "constant"
            ):
                continue
            original_address = int(original_expression["address"]["value"])
            candidate_address = int(candidate_expression["address"]["value"])
            matching_slots = [
                slot for slot in slots
                if int(slot["original_address"]) == original_address
                and int(slot["candidate_address"]) == candidate_address
                and _static_word_relation_supports_register_output(
                    str(slot["relation"]), str(output["relation"])
                )
            ]
            if len(matching_slots) != 1:
                continue
            existing[key] = {
                "kind": "static_word_slot",
                "output": output,
                "slot": matching_slots[0],
                "original_address": original_address,
                "candidate_address": candidate_address,
            }
        row["output_claims"] = [
            existing[(str(output["original"]), str(output["candidate"]))]
            for output in row.get("outputs", [])
            if (str(output["original"]), str(output["candidate"])) in existing
        ]
        row["fully_supported_output_transfer"] = (
            len(row["output_claims"]) == len(row["outputs"])
        )
    counts = register_relations.get("counts", {})
    counts["register_output_claims"] = sum(
        len(row.get("output_claims", []))
        for row in register_relations.get("regions", [])
    )
    counts["static_word_slot_output_claims"] = sum(
        claim.get("kind") == "static_word_slot"
        for row in register_relations.get("regions", [])
        for claim in row.get("output_claims", [])
    )
    counts["fully_supported_output_regions"] = sum(
        bool(row.get("fully_supported_output_transfer"))
        for row in register_relations.get("regions", [])
    )
    return register_relations

def _lower_stack_register_relations(
    contract: dict[str, Any],
    register_relations: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    regions = contract.get("regions", [])
    rows = register_relations.get("regions", [])

    def covered_pairs(region: dict[str, Any]) -> set[tuple[str, str]]:
        return {
            (str(window["original_register"]), str(window["candidate_register"]))
            for window in region.get("stack_windows", [])
        }

    input_covered = [covered_pairs(region) for region in regions]
    outgoing: dict[int, list[dict[str, Any]]] = {}
    for edge in register_relations.get("edges", []):
        outgoing.setdefault(int(edge["source_region_index"]), []).append(edge)

    for index, (region, row) in enumerate(zip(regions, rows, strict=True)):
        removed_inputs = input_covered[index]
        if removed_inputs:
            region["input_relations"] = [
                relation for relation in region.get("input_relations", [])
                if (str(relation["original"]), str(relation["candidate"]))
                    not in removed_inputs
            ]
            row["inputs"] = [
                relation for relation in row.get("inputs", [])
                if (str(relation["original"]), str(relation["candidate"]))
                    not in removed_inputs
            ]
            removed_originals = {pair[0] for pair in removed_inputs}
            row["exact_output_claims"] = [
                claim for claim in row.get("exact_output_claims", [])
                if not (
                    _semantic_expr_registers(claim.get("expression") or {})
                    & removed_originals
                )
            ]
            row["output_claims"] = [
                claim for claim in row.get("output_claims", [])
                if not (
                    (
                        claim.get("kind") == "identity"
                        and str(claim.get("input", {}).get("original"))
                            in removed_originals
                    )
                    or (
                        claim.get("kind") in {"exact_expression", "exact_memory"}
                        and bool(
                            _semantic_expr_registers(claim.get("expression") or {})
                            & removed_originals
                        )
                    )
                )
            ]

        edges = outgoing.get(index, [])
        removable_outputs = {
            pair for pair in covered_pairs(region)
            if edges and all(
                not edge.get("environment_barrier")
                and not edge.get("requires_call_stack_proof")
                and pair in input_covered[int(edge["target_region_index"])]
                for edge in edges
            )
        }
        if not removable_outputs:
            row["fully_exact_output_transfer"] = bool(row.get("outputs")) and (
                len(row.get("exact_output_claims", [])) == len(row.get("outputs", []))
            )
            row["fully_supported_output_transfer"] = (
                len(row.get("output_claims", [])) == len(row.get("outputs", []))
            )
            continue
        region["output_relations"] = [
            relation for relation in region.get("output_relations", [])
            if (str(relation["original"]), str(relation["candidate"]))
                not in removable_outputs
        ]
        row["outputs"] = [
            relation for relation in row.get("outputs", [])
            if (str(relation["original"]), str(relation["candidate"]))
                not in removable_outputs
        ]
        row["exact_output_claims"] = [
            claim for claim in row.get("exact_output_claims", [])
            if (str(claim["register"]), str(claim["register"]))
                not in removable_outputs
        ]
        row["output_claims"] = [
            claim for claim in row.get("output_claims", [])
            if (str(claim["output"]["original"]), str(claim["output"]["candidate"]))
                not in removable_outputs
        ]
        row["fully_exact_output_transfer"] = bool(row["outputs"]) and (
            len(row["exact_output_claims"]) == len(row["outputs"])
        )
        row["fully_supported_output_transfer"] = (
            len(row["output_claims"]) == len(row["outputs"])
        )
    return contract, register_relations

def _attach_segment_refinement_analysis(
    proof_ir: dict[str, Any],
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    memory_contracts: dict[str, Any],
    register_relations: dict[str, Any],
    import_register_seeds: list[dict[str, Any]] | None = None,
    *,
    segment_candidates: list[dict[str, Any]] | None = None,
    segment_diagnostics: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    candidates = {
        item["edge_index"]: item
        for item in (
            segment_candidates
            if segment_candidates is not None
            else _segment_refinement_candidates(
                contract, behaviors, memory_contracts, register_relations,
                import_register_seeds,
            )
        )
    }
    diagnostics = {
        int(item["edge_index"]): item
        for item in (segment_diagnostics or [])
    }
    obligations: list[dict[str, Any]] = []
    for edge_index, edge in enumerate(register_relations["edges"]):
        source_index = int(edge["source_region_index"])
        target_index = int(edge["target_region_index"])
        source = contract["regions"][source_index]
        target = contract["regions"][target_index]
        dynamic_pointer = _dynamic_pointer_traversal_diagnostic(
            contract, behaviors, register_relations, edge, source_index, target_index
        )
        static_pointer = _static_dynamic_pointer_seed_diagnostic(
            contract, behaviors, register_relations, edge, source_index, target_index
        )
        if edge.get("requires_call_stack_proof"):
            repair_class = "call_stack_and_return_address"
            next_action = (
                "prove the pushed return address, abstract call-stack membership, and mapped "
                "return exit before checking the successor StateRel"
            )
        elif edge.get("environment_barrier"):
            repair_class = "external_environment_refinement"
            next_action = (
                "instantiate paired external environments for the machine-level call event, "
                "world update, memory effects, and continuation StateRel"
            )
        elif dynamic_pointer is not None and dynamic_pointer["status"] == "incomplete":
            repair_class = "dynamic_pointer_traversal_relation"
            next_action = dynamic_pointer["next_action"]
        elif static_pointer is not None and static_pointer["status"] == "incomplete":
            repair_class = "static_dynamic_pointer_seed_relation"
            next_action = static_pointer["next_action"]
        elif not edge.get("relation_preservation_proposed"):
            repair_class = "register_state_relation"
            next_action = (
                "strengthen the source invariant or add checked relation witnesses for every "
                "target input register"
            )
        else:
            repair_class = "successor_state_composition"
            next_action = (
                "combine exact decode, register transfer, flags, x87, memory writes, and the "
                "edge guard into RelationalSegmentRefinement under the canonical StateRel"
            )
        candidate = candidates.get(edge_index)
        diagnostic = diagnostics.get(edge_index)
        failed_checks = (
            list(diagnostic.get("failed_checks", []))
            if diagnostic is not None else []
        )
        obligations.append({
            "id": (
                f"segment:{source['id']}:{target['id']}:{edge_index}"
            ),
            "kind": "relational_segment_refinement",
            "status": "proved" if candidate is not None else "incomplete",
            "source_region_id": source["id"],
            "target_region_id": target["id"],
            "source_region_index": source_index,
            "target_region_index": target_index,
            "edge_kind": edge.get("kind"),
            "original_span": source["original"],
            "candidate_span": source["candidate"],
            "repair_class": repair_class,
            "blocker": (
                None if candidate is not None else
                (
                    "the paired dynamic-pointer traversal lacks a unique checked source "
                    "range, successor range shape, or exact nonzero edge guard"
                    if dynamic_pointer is not None
                    and dynamic_pointer["status"] == "incomplete" else
                    "the paired writable-PE pointer load lacks one checked static slot, "
                    "successor shape, or exact nonzero guard"
                    if static_pointer is not None
                    and static_pointer["status"] == "incomplete" else
                    "segment certificate eligibility checks failed: "
                    + ", ".join(failed_checks)
                    if failed_checks else
                    "no Lean RelationalSegmentRefinement theorem connects this decoded edge "
                    "to the canonical global StateRel"
                )
            ),
            "next_action": (
                f"replay the generated {candidate['certificate_profile']} segment theorem in Lean"
                if candidate is not None else next_action
            ),
            "analysis": {
                "register_relation_preservation_proposed": bool(
                    edge.get("relation_preservation_proposed")
                ),
                "environment_barrier": bool(edge.get("environment_barrier")),
                "requires_call_stack_proof": bool(
                    edge.get("requires_call_stack_proof")
                ),
                "certificate_profile": (
                    candidate["certificate_profile"] if candidate is not None else None
                ),
                "certificate": candidate,
                "eligibility_diagnostic": diagnostic,
                "dynamic_pointer_traversal": dynamic_pointer,
                "static_dynamic_pointer_seed": static_pointer,
            },
        })
    attached = dict(proof_ir)
    attached["segment_refinement_summary"] = {
        "edges": len(obligations),
        "proved": len(candidates),
        "incomplete": len(obligations) - len(candidates),
        "interface": "StageA.Relational.RelationalSegmentRefinement",
        "certificate_format": RELATIONAL_SEGMENT_CERTIFICATE_FORMAT,
        "incomplete_reason_counts": dict(sorted(Counter(
            str(code)
            for diagnostic in diagnostics.values()
            if not bool(diagnostic.get("eligible"))
            for code in diagnostic.get("failed_checks", [])
        ).items())),
    }
    attached["obligations"] = [*proof_ir["obligations"], *obligations]
    attached["families"] = [
        *proof_ir["families"],
        {
            "family": "segment_refinement",
            "status": (
                "not_applicable" if not obligations else
                "satisfied" if len(candidates) == len(obligations) else
                "incomplete"
            ),
        },
    ]
    attached["status"] = "incomplete"
    return attached

def _semantic_expr_registers(expression: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    if expression.get("op") == "input_reg":
        result.add(str(expression["reg"]))
    for key, value in expression.items():
        if key == "op":
            continue
        if isinstance(value, dict) and "op" in value:
            result.update(_semantic_expr_registers(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and "op" in item:
                    result.update(_semantic_expr_registers(item))
    return result

def _direct_call_stack_amount(claim: Any) -> int | None:
    if not isinstance(claim, dict):
        return None
    original = _register_offset_witness(claim.get("original_stack_address"))
    candidate = _register_offset_witness(claim.get("candidate_stack_address"))
    if original is None or candidate is None or original[1] != candidate[1]:
        return None
    amount = (-int(original[1])) % 2**32
    if not (4 <= amount < 2**31) or amount % 4 != 0:
        return None
    return amount
