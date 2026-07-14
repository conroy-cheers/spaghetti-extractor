from __future__ import annotations

import json
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
from ..model import _stack_window_transfer_claims


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
        "return_pop_obligations": len(return_pop_obligations),
        "return_slot_transfer_obligations": len(return_slot_transfer_obligations),
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
        *return_pop_obligations,
        *return_slot_transfer_obligations,
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
) -> dict[str, Any] | None:
    if (
        original_value == candidate_value
        and _semantic_expr_has_exact_inputs(source, original_value)
    ):
        return {
            "profile": "exact_inputs_v1",
            "original": original_value,
            "candidate": candidate_value,
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
        source, original_value, candidate_value
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
) -> dict[str, Any] | None:
    original_writes = (behavior_pair.get("original_ir") or {}).get("writes") or []
    candidate_writes = (behavior_pair.get("candidate_ir") or {}).get("writes") or []
    if len(original_writes) < 2 or len(original_writes) != len(candidate_writes):
        return None
    value_claims = [
        _paired_stack_word_value_claim(
            source, original.get("value") or {}, candidate.get("value") or {}
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

def _segment_refinement_candidates(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    memory_contracts: dict[str, Any],
    register_relations: dict[str, Any],
    import_register_seeds: list[dict[str, Any]] | None = None,
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
        ) or _paired_stack_guard_claim(
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
        register_transfer_supported = (
            bool(register_regions[source_index].get("fully_supported_output_transfer"))
            or dynamic_register_output_claims is not None
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
            and source.get("output_relations", []) == target.get("input_relations", [])
            and not source.get("output_import_relations")
            and import_transfer_claims is not None
            and dynamic_transfer_claims is not None
            and stack_transfer_claims is not None
            and source.get("flag_outputs", []) == target_flags
            and target_flags in ([], [10])
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
            source, behaviors[source_index]
        )
        stack_writes_claim = _paired_stack_word_writes_claim(
            source, behaviors[source_index]
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
        if not (
            no_write_supported or call_supported or stack_write_supported
            or stack_writes_supported
        ):
            continue
        source_target = next((
            code_target for code_target in contract.get("code_targets", [])
            if int(code_target.get("region_index", -1)) == source_index
            and int(code_target["original_rva"]) == int(source["original"]["rva_start"])
            and int(code_target["candidate_rva"]) == int(source["candidate"]["rva_start"])
        ), None)
        if source_target is None:
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
                "composable_direct_call_v1" if call_supported
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
            "original_guard": edge["original_guard"],
            "candidate_guard": edge["candidate_guard"],
            **({
                "source_stack_window": call_windows[0],
                "callee_target_id": int(call_claim["callee_target_id"]),
                "continuation_target_id": int(call_claim["continuation_target_id"]),
                "original_return_address": int(call_claim["original_return_address"]),
                "candidate_return_address": int(call_claim["candidate_return_address"]),
                "stack_amount": call_stack_amount,
            } if call_supported else {}),
            "paired_stack_write_claim": (
                stack_write_claim if stack_write_supported else None
            ),
            "paired_stack_writes_claim": (
                stack_writes_claim if stack_writes_supported else None
            ),
            "guard_relation_claim": guard_relation_claim,
            "stack_transfer_claims": stack_transfer_claims,
        }
    return [by_edge[index] for index in sorted(by_edge)]

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
    original_registers = behaviors[source_index]["original_ir"].get("registers") or {}
    candidate_registers = behaviors[source_index]["candidate_ir"].get("registers") or {}
    claims: list[dict[str, Any]] = []
    for target_relation in target_relations:
        target_words = {
            (int(word["offset"]), str(word["kind"]))
            for word in target_relation.get("required_words", [])
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
            if (
                int(source_relation.get("original_offset", -1))
                    == int(target_relation.get("original_offset", -2))
                and int(source_relation.get("candidate_offset", -1))
                    == int(target_relation.get("candidate_offset", -2))
                and target_words <= source_words
                and original_expression == {
                    "op": "input_reg", "reg": source_relation["original"]
                }
                and candidate_expression == {
                    "op": "input_reg", "reg": source_relation["candidate"]
                }
            ):
                matches.append({
                    "kind": "preserve",
                    "source_relation": source_relation,
                    "target_relation": target_relation,
                })
            pointer_words = [
                word for word in source_relation.get("required_words", [])
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
            if claim.get("kind") in {"nullable_pointer", "static_pointer_seed"}
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

def _stack_read32_sub_output_claim(
    region: dict[str, Any],
    output: dict[str, Any],
    original_expression: dict[str, Any],
    candidate_expression: dict[str, Any],
) -> dict[str, Any] | None:
    def parse(expression: dict[str, Any]) -> tuple[str, int, int] | None:
        if expression.get("op") != "sub":
            return None
        read = expression.get("left") or {}
        subtract = expression.get("right") or {}
        address = read.get("address") or {}
        register = address.get("left") or {}
        offset = address.get("right") or {}
        if (
            read.get("op") != "read32"
            or address.get("op") != "add"
            or register.get("op") != "input_reg"
            or offset.get("op") != "constant"
            or subtract.get("op") != "constant"
        ):
            return None
        offset_value = int(offset.get("value", -1))
        subtract_value = int(subtract.get("value", -1))
        if not (0 <= offset_value < 2**31 and 0 <= subtract_value < 2**32):
            return None
        return str(register.get("reg")), offset_value, subtract_value

    original = parse(original_expression)
    candidate = parse(candidate_expression)
    if (
        original is None
        or candidate is None
        or original[1:] != candidate[1:]
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
            if key in existing:
                continue
            original_expression = behaviors[region_index]["original_ir"]["registers"][
                output["original"]
            ]
            candidate_expression = behaviors[region_index]["candidate_ir"]["registers"][
                output["candidate"]
            ]
            claim = _stack_read32_sub_output_claim(
                region, output, original_expression, candidate_expression
            )
            if claim is not None:
                existing[key] = claim
        row["output_claims"] = [
            existing[(str(output["original"]), str(output["candidate"]))]
            for output in row.get("outputs", [])
            if (str(output["original"]), str(output["candidate"])) in existing
        ]
        row["fully_supported_output_transfer"] = (
            len(row["output_claims"]) == len(row["outputs"])
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
