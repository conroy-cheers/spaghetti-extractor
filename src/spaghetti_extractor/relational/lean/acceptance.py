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
from .expressions import (
    _lean_acceptance_outcome,
    _lean_external_target,
    _lean_register_offset_witness,
    _lean_register_output_claim,
    _lean_return_slot_offset_pair,
    _lean_semantic_expr,
    _lean_stack_window,
    _lean_stack_window_transfer_claim,
    _lean_state_invariant,
)
from .definitions import (
    _normalized_behavior_fast_path,
)


def _compact_acceptance_blockers(
    blockers: list[dict[str, str]], *, example_limit: int = 10
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for blocker in blockers:
        code = str(blocker["code"])
        group = grouped.setdefault(code, {
            "code": code,
            "count": 0,
            "message": str(blocker["message"]),
            "next_action": str(blocker["next_action"]),
            "examples": [],
        })
        group["count"] += 1
        message = str(blocker["message"])
        if message not in group["examples"] and len(group["examples"]) < example_limit:
            group["examples"].append(message)
    for group in grouped.values():
        group["omitted_examples"] = max(
            int(group["count"]) - len(group["examples"]), 0
        )
        if int(group["count"]) > 1:
            group["message"] = (
                f"{group['count']} whole-program acceptance blockers have code "
                f"{group['code']}"
            )
    return list(grouped.values())

def _whole_program_acceptance_plan(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    product_graph: dict[str, Any],
    register_relations: dict[str, Any],
    segment_candidates: list[dict[str, Any]],
    external_site_candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    """Recognize the first fully compositional profile without weakening acceptance."""
    blockers: list[dict[str, str]] = []

    def block(code: str, message: str, next_action: str) -> None:
        blockers.append({
            "code": code,
            "message": message,
            "next_action": next_action,
        })

    nodes = product_graph["nodes"]
    edges = product_graph["edges"]
    evidence = product_graph["evidence"]
    decoded_control_by_node = {
        int(candidate["node_id"]): candidate
        for candidate in evidence.get("decoded_control_candidates", [])
    }
    regions = contract["regions"]
    if not evidence.get("reachable_product_local_complete"):
        block(
            "reachable_product_local_incomplete",
            "reachable decoded-control or local edge-refinement evidence is incomplete",
            "close every reachable decoded-control and local-refinement frontier",
        )
    if len(nodes) != len(regions) or len(behaviors) != len(regions):
        block(
            "product_region_inventory_mismatch",
            "the product-node, region, and decoded-behavior inventories differ in size",
            "regenerate a canonical one-node-per-region product inventory",
        )
    roots = [int(node_id) for node_id in product_graph["root_node_ids"]]
    if len(roots) != 1:
        block(
            "console_launch_root_unsupported",
            "pe32-console-launch-v1 currently requires exactly one checked entry root",
            "select the PE console entry root and model additional roots separately",
        )
    control_states: list[dict[str, Any]] = []
    control_states_by_node: dict[int, list[dict[str, Any]]] = {}
    if len(roots) == 1 and len(nodes) == len(behaviors):
        node_by_target = {
            int(node["target_id"]): node_id for node_id, node in enumerate(nodes)
        }
        pending: list[tuple[int, tuple[int, ...]]] = [(roots[0], ())]
        seen: set[tuple[int, tuple[int, ...]]] = set()
        control_incomplete = False
        while pending and not control_incomplete:
            node_id, calls = pending.pop(0)
            key = (node_id, calls)
            if key in seen:
                continue
            if len(seen) >= 512 or len(calls) > 32:
                block(
                    "finite_control_profile_exceeded",
                    "the rooted call-stack control profile is recursive or exceeds its finite bound",
                    "add an inductive checked control-stack profile for recursion",
                )
                control_incomplete = True
                break
            seen.add(key)
            relation_row = register_relations.get("regions", [])[node_id]
            offsets = list(relation_row.get("return_slot_offsets", []))
            if len(offsets) != len(calls):
                block(
                    "runtime_frame_offset_inventory_incomplete",
                    f"product node {node_id} has {len(calls)} runtime frames but "
                    f"{len(offsets)} checked return-slot offsets",
                    "propagate a checked return-slot offset for every live runtime frame",
                )
                control_incomplete = True
                break
            state = {
                "node_id": node_id,
                "calls": list(calls),
                "frame_offsets": offsets,
            }
            control_states.append(state)
            control_states_by_node.setdefault(node_id, []).append(state)
            original_outcome = behaviors[node_id].get("original_ir", {}).get("outcome", {})
            candidate_outcome = behaviors[node_id].get("candidate_ir", {}).get("outcome", {})
            operation = original_outcome.get("op")
            if operation != candidate_outcome.get("op"):
                block(
                    "control_profile_outcome_mismatch",
                    f"product node {node_id} has different original and candidate control outcomes",
                    "add a paired finite-path normalization certificate",
                )
                control_incomplete = True
                break
            successor_targets: list[tuple[int, tuple[int, ...]]] = []
            if operation == "jump":
                if original_outcome.get("target") != candidate_outcome.get("target"):
                    control_incomplete = True
                else:
                    successor_targets.append((int(original_outcome["target"]), calls))
            elif operation == "branch":
                for field in ("taken", "fallthrough"):
                    if original_outcome.get(field) != candidate_outcome.get(field):
                        control_incomplete = True
                        break
                    successor_targets.append((int(original_outcome[field]), calls))
            elif operation == "call":
                if any(
                    original_outcome.get(field) != candidate_outcome.get(field)
                    for field in ("target", "continuation")
                ):
                    control_incomplete = True
                else:
                    successor_targets.append((
                        int(original_outcome["target"]),
                        (int(original_outcome["continuation"]), *calls),
                    ))
            elif operation == "external_call":
                if any(
                    original_outcome.get(field) != candidate_outcome.get(field)
                    for field in ("import", "continuation")
                ):
                    control_incomplete = True
                else:
                    successor_targets.append((
                        int(original_outcome["continuation"]), calls,
                    ))
            elif operation == "indirect_jump":
                decoded_control = decoded_control_by_node.get(node_id, {})
                if decoded_control.get("profile") != (
                    "immutable_relocated_function_pointer_jump_v1"
                ):
                    block(
                        "bounded_indirect_control_profile_unmet",
                        f"product node {node_id} has no checked finite indirect-jump target",
                        "classify the target by provenance and emit a checked finite target set",
                    )
                    control_incomplete = True
                else:
                    successor_targets.append((
                        int(decoded_control["target_id"]), calls,
                    ))
            elif operation == "returned":
                if calls:
                    successor_targets.append((calls[0], calls[1:]))
            else:
                block(
                    "control_profile_outcome_unsupported",
                    f"product node {node_id} uses unsupported control outcome {operation!r}",
                    "add the corresponding checked control-state transition",
                )
                control_incomplete = True
            if control_incomplete:
                if not any(
                    item["code"] == "control_profile_outcome_mismatch"
                    for item in blockers
                ):
                    block(
                        "control_profile_outcome_mismatch",
                        f"product node {node_id} has mismatched control destinations",
                        "repair the mapping or add a paired finite-path normalization certificate",
                    )
                break
            for target_id, successor_calls in successor_targets:
                target_node_id = node_by_target.get(target_id)
                if target_node_id is None:
                    block(
                        "control_profile_target_unmapped",
                        f"control target {target_id} from product node {node_id} has no product node",
                        "close the rooted decoded-control mapping frontier",
                    )
                    control_incomplete = True
                    break
                pending.append((target_node_id, successor_calls))

    candidate_by_edge = {
        int(candidate["edge_index"]): candidate for candidate in segment_candidates
    }
    external_by_edge = {
        int(candidate["edge_index"]): candidate
        for candidate in external_site_candidates
    }
    register_edge_by_source_target = {
        (int(edge["source_region_index"]), int(edge["target_region_index"])): edge
        for edge in register_relations.get("edges", [])
    }
    all_node_ids = list(range(len(nodes)))
    reachable_node_ids = [
        int(node_id) for node_id in evidence.get("declared_reachable_node_ids", [])
    ]
    if reachable_node_ids != all_node_ids:
        block(
            "unreachable_region_composition_pending",
            "the initial acceptance profile requires every canonical product node to be root-reachable",
            "add checked unreachable-region exclusion or retain all nodes in the rooted simulation",
        )

    node_steps: list[dict[str, Any]] = []
    has_guarded_branch = False
    has_internal_call = False
    has_internal_return = False
    has_external_call = False
    has_bounded_indirect = False
    has_paired_stack_write = False
    termination_region_indices: list[int] = []
    for node_id, node in enumerate(nodes):
        if int(node.get("id", -1)) != node_id or node_id >= len(regions):
            block(
                "noncanonical_product_node_index",
                f"product node {node_id} is not canonically indexed",
                "regenerate the indexed product graph",
            )
            continue
        region = regions[node_id]
        target_id = int(node["target_id"])
        if int(region.get("numeric_id", -1)) != target_id or target_id != node_id:
            block(
                "noncanonical_region_target_index",
                f"product node {node_id} does not use its canonical region-entry target",
                "emit an indexed region-to-code-target binding certificate",
            )
            continue
        outgoing = [int(edge_id) for edge_id in node["outgoing_edge_ids"]]
        if len(outgoing) not in {0, 1, 2}:
            block(
                "multi_exit_node_composition_pending",
                f"reachable product node {node_id} has {len(outgoing)} outgoing edges",
                "derive guard-exhaustive node steps from all decoded outgoing edges",
            )
            continue
        if any(edge_id >= len(edges) for edge_id in outgoing):
            block(
                "product_edge_index_invalid",
                f"product node {node_id} references a missing outgoing edge",
                "regenerate the indexed product graph",
            )
            continue
        true_guard = {"op": "bool_constant", "value": True}
        outcomes = [
            behaviors[node_id].get("original_ir", {}).get("outcome", {}),
            behaviors[node_id].get("candidate_ir", {}).get("outcome", {}),
        ]
        if not outgoing:
            relation_row = register_relations.get("regions", [])[node_id]
            control_rows = control_states_by_node.get(node_id, [])
            if (
                any(outcome.get("op") != "returned" for outcome in outcomes)
                or relation_row.get("return_pop_claim") is None
                or relation_row.get("return_pop_claim", {}).get("profile")
                    != "esp_relative_return_pop_v1"
                or len(control_rows) != 1
            ):
                block(
                    "return_node_profile_unmet",
                    f"product node {node_id} is not a checked finite-control return",
                    "emit a return-pop claim, runtime-frame offsets, and one checked control state",
                )
                continue
            calls = list(control_rows[0]["calls"])
            if calls:
                if not relation_row.get("return_pop_frame_claims"):
                    block(
                        "return_runtime_frame_claim_missing",
                        f"return node {node_id} lacks a checked live-frame return-slot claim",
                        "emit a return-pop frame claim for the active continuation",
                    )
                    continue
                continuation_target_id = int(calls[0])
                target_node_id = next(
                    (
                        candidate_id for candidate_id, candidate_node in enumerate(nodes)
                        if int(candidate_node["target_id"]) == continuation_target_id
                    ),
                    -1,
                )
                if target_node_id < 0:
                    block(
                        "return_continuation_unmapped",
                        f"return node {node_id} continuation {continuation_target_id} is unmapped",
                        "add the continuation to the checked product graph",
                    )
                    continue
                stack_transfers = _stack_window_transfer_claims(
                    region, regions[target_node_id], behaviors[node_id]
                )
                if stack_transfers is None:
                    block(
                        "return_stack_window_transfer_incomplete",
                        f"return node {node_id} cannot establish continuation "
                        f"{target_node_id}'s stack windows",
                        "strengthen the checked stack windows or support the decoded ESP transfer",
                    )
                    continue
                target_region = regions[target_node_id]
                target_relation_row = register_relations.get("regions", [
                ])[target_node_id]
                target_output_claims = _target_shaped_register_output_claims(
                    relation_row, target_relation_row
                )
                if target_output_claims is None:
                    block(
                        "return_register_relation_transfer_incomplete",
                        f"return node {node_id} cannot establish continuation "
                        f"{target_node_id}'s register relations",
                        "emit checked target-shaped register output claims for the continuation",
                    )
                    continue
                unsupported_target_families = [
                    field for field in (
                        "bounds",
                        "address_separations",
                        "flag_inputs",
                        "input_import_relations",
                        "input_dynamic_range_relations",
                    )
                    if target_region.get(field)
                ]
                if unsupported_target_families:
                    block(
                        "return_continuation_invariant_transfer_incomplete",
                        f"return node {node_id} needs unsupported continuation invariant "
                        f"families {unsupported_target_families}",
                        "add checked return transfer claims for these invariant families",
                    )
                    continue
                node_steps.append({
                    "kind": "return",
                    "node_id": node_id,
                    "region_index": node_id,
                    "target_id": target_id,
                    "control_state": control_rows[0],
                    "target_node_id": target_node_id,
                    "target_region_index": target_node_id,
                    "target_target_id": continuation_target_id,
                    "return_pop_claim": relation_row["return_pop_claim"],
                    "return_frame_claim": relation_row["return_pop_frame_claims"][0],
                    "output_claims": target_output_claims,
                    "return_frame_claim_index": 0,
                    "stack_window_transfers": stack_transfers,
                    "edges": [],
                })
                has_internal_return = True
            else:
                unsupported_terminal_families = [
                    field for field in (
                        "output_import_relations",
                        "output_dynamic_range_relations",
                    )
                    if region.get(field)
                ]
                if unsupported_terminal_families:
                    block(
                        "terminal_invariant_family_pending",
                        f"termination node {node_id} has unsupported terminal families "
                        f"{unsupported_terminal_families}",
                        "emit checked terminal transfer witnesses for these relation families",
                    )
                    continue
                node_steps.append({
                    "kind": "terminate",
                    "node_id": node_id,
                    "region_index": node_id,
                    "target_id": target_id,
                    "control_state": control_rows[0],
                    "return_pop_claim": relation_row["return_pop_claim"],
                    "output_claims": relation_row["output_claims"],
                    "return_frame_claim_index": 0,
                    "edges": [],
                })
                termination_region_indices.append(node_id)
            continue
        if len(outgoing) == 1:
            edge_id = outgoing[0]
            edge = edges[edge_id]
            segment = candidate_by_edge.get(edge_id)
            jump_profile = (
                bool(edge.get("infeasible"))
                or edge.get("kind") != "jump"
                or edge.get("original_guard") != true_guard
                or edge.get("candidate_guard") != true_guard
                or segment is None
                or segment.get("certificate_profile") not in {
                    "composable_local_no_write_v1",
                    "composable_paired_stack_word_write_v1",
                    "composable_paired_stack_word_writes_v1",
                }
            ) is False
            call_profile = (
                not bool(edge.get("infeasible"))
                and edge.get("kind") == "call"
                and edge.get("original_guard") == true_guard
                and edge.get("candidate_guard") == true_guard
                and segment is not None
                and segment.get("certificate_profile") == "composable_direct_call_v1"
            )
            external_site = external_by_edge.get(edge_id)
            external_profile = (
                not bool(edge.get("infeasible"))
                and edge.get("kind") == "externalCall"
                and edge.get("original_guard") == true_guard
                and edge.get("candidate_guard") == true_guard
                and external_site is not None
            )
            decoded_control = decoded_control_by_node.get(node_id, {})
            indirect_jump_profile = (
                not bool(edge.get("infeasible"))
                and edge.get("kind") == "jump"
                and edge.get("original_guard") == true_guard
                and edge.get("candidate_guard") == true_guard
                and segment is not None
                and segment.get("certificate_profile")
                    == "composable_immutable_indirect_jump_v1"
                and decoded_control.get("profile")
                    == "immutable_relocated_function_pointer_jump_v1"
                and int(decoded_control.get("target_id", -1))
                    == int(edge.get("target_target_id", -2))
            )
            if (
                not jump_profile and not call_profile and not external_profile
                and not indirect_jump_profile
            ):
                block(
                    "direct_jump_node_profile_unmet",
                    f"product node {node_id} is not a checked unconditional jump, call, or external call",
                    "add the corresponding return, write, indirect-control, or environment composition rule",
                )
                continue
            target_node_id = int(edge["target_node_id"])
            if not (0 <= target_node_id < len(regions)):
                block(
                    "product_target_node_invalid",
                    f"edge {edge_id} has invalid target node {target_node_id}",
                    "regenerate the indexed product graph",
                )
                continue
            expected_target = int(regions[target_node_id]["numeric_id"])
            expected_operation = (
                "external_call" if external_profile
                else "call" if call_profile
                else "indirect_jump" if indirect_jump_profile
                else "jump"
            )
            target_field = "continuation" if external_profile else "target"
            decoded_outcome_mismatch = (
                any(outcome.get("op") != expected_operation for outcome in outcomes)
                if indirect_jump_profile else
                any(
                    outcome.get("op") != expected_operation
                    or int(outcome.get(target_field, -1)) != expected_target
                    for outcome in outcomes
                )
            )
            if decoded_outcome_mismatch:
                block(
                    "decoded_jump_outcome_mismatch",
                    f"node {node_id} does not decode to the submitted {expected_operation} target on both sides",
                    "repair the mapping or add a paired finite-path normalization certificate",
                )
                continue
            step = {
                "kind": expected_operation,
                "node_id": node_id,
                "region_index": node_id,
                "target_id": target_id,
                "edges": [{
                    "edge_id": edge_id,
                    "target_node_id": target_node_id,
                    "target_region_index": target_node_id,
                    "target_target_id": int(edge["target_target_id"]),
                }],
            }
            if call_profile:
                register_edge = register_edge_by_source_target.get(
                    (node_id, target_node_id), {}
                )
                direct_call_claim = register_edge.get("direct_call_push_claim")
                continuation = int(outcomes[0].get("continuation", -1))
                control_rows = control_states_by_node.get(node_id, [])
                if (
                    direct_call_claim is None
                    or any(int(outcome.get("continuation", -1)) != continuation for outcome in outcomes)
                    or len(control_rows) != 1
                    or control_rows[0]["calls"]
                    or control_rows[0]["frame_offsets"]
                ):
                    block(
                        "direct_call_control_profile_unmet",
                        f"call node {node_id} lacks a top-level checked runtime-frame seed",
                        "close the call push and finite control-state evidence",
                    )
                    continue
                step["control_state"] = control_rows[0]
                step["continuation_target_id"] = continuation
                step["direct_call_push_claim"] = direct_call_claim
                step["source_stack_window"] = segment["source_stack_window"]
                step["stack_amount"] = int(segment["stack_amount"])
                has_internal_call = True
            elif external_profile:
                control_rows = control_states_by_node.get(node_id, [])
                if (
                    len(control_rows) != 1
                    or control_rows[0]["calls"]
                    or control_rows[0]["frame_offsets"]
                ):
                    block(
                        "nested_external_runtime_frame_preservation_pending",
                        f"external-call node {node_id} is reached with live internal runtime frames",
                        "prove the import write footprint disjoint from every live return slot and transfer frame offsets across the call",
                    )
                    continue
                step["kind"] = "external_call"
                step["control_state"] = control_rows[0]
                step["external_site"] = external_site
                step["decoded_import"] = outcomes[0].get("import")
                has_external_call = True
            elif indirect_jump_profile:
                step["decoded_control"] = {
                    **decoded_control,
                    "original_target_expression": outcomes[0]["target"],
                    "candidate_target_expression": outcomes[1]["target"],
                }
                has_bounded_indirect = True
            if (
                segment is not None
                and segment.get("certificate_profile")
                    in {
                        "composable_paired_stack_word_write_v1",
                        "composable_paired_stack_word_writes_v1",
                    }
            ):
                has_paired_stack_write = True
            node_steps.append(step)
            continue

        edge_rows = [edges[edge_id] for edge_id in outgoing]
        edge_by_kind = {edge.get("kind"): edge for edge in edge_rows}
        taken_edge = edge_by_kind.get("branchTaken")
        fallthrough_edge = edge_by_kind.get("branchFallthrough")
        if (
            len(edge_by_kind) != 2
            or taken_edge is None
            or fallthrough_edge is None
            or any(bool(edge.get("infeasible")) for edge in edge_rows)
            or any(
                candidate_by_edge.get(int(edge["id"]), {}).get("certificate_profile")
                    not in {
                        "composable_local_no_write_v1",
                        "composable_paired_stack_word_write_v1",
                        "composable_paired_stack_word_writes_v1",
                    }
                for edge in edge_rows
            )
        ):
            block(
                "guarded_branch_profile_unmet",
                f"product node {node_id} is not a complete checked two-way branch",
                "supply taken and fallthrough no-write refinements with exhaustive guards",
            )
            continue
        target_node_ids = [int(edge["target_node_id"]) for edge in edge_rows]
        if any(not (0 <= target < len(regions)) for target in target_node_ids):
            block(
                "product_target_node_invalid",
                f"branch node {node_id} has an invalid target node",
                "regenerate the indexed product graph",
            )
            continue
        expected_taken = int(taken_edge["target_target_id"])
        expected_fallthrough = int(fallthrough_edge["target_target_id"])
        if any(
            outcome.get("op") != "branch"
            or int(outcome.get("taken", -1)) != expected_taken
            or int(outcome.get("fallthrough", -1)) != expected_fallthrough
            for outcome in outcomes
        ):
            block(
                "decoded_branch_outcome_mismatch",
                f"node {node_id} branch destinations do not match its submitted edges",
                "repair the mapping or add a paired finite-path normalization certificate",
            )
            continue
        original_condition = outcomes[0].get("condition")
        candidate_condition = outcomes[1].get("condition")
        if (
            taken_edge.get("original_guard") != original_condition
            or taken_edge.get("candidate_guard") != candidate_condition
            or fallthrough_edge.get("original_guard")
                != {"op": "not", "value": original_condition}
            or fallthrough_edge.get("candidate_guard")
                != {"op": "not", "value": candidate_condition}
        ):
            block(
                "branch_guard_inventory_mismatch",
                f"node {node_id} guards do not exhaust its decoded branch condition",
                "regenerate direct decoded-control guards from the exact branch outcome",
            )
            continue
        has_guarded_branch = True
        has_paired_stack_write = has_paired_stack_write or any(
            candidate_by_edge.get(int(edge["id"]), {}).get("certificate_profile")
                in {
                    "composable_paired_stack_word_write_v1",
                    "composable_paired_stack_word_writes_v1",
                }
            for edge in edge_rows
        )
        ordered_edges = [taken_edge, fallthrough_edge]
        node_steps.append({
            "kind": "branch",
            "node_id": node_id,
            "region_index": node_id,
            "target_id": target_id,
            "edges": [{
                "edge_id": int(edge["id"]),
                "branch_value": edge.get("kind") == "branchTaken",
                "target_node_id": int(edge["target_node_id"]),
                "target_region_index": int(edge["target_node_id"]),
                "target_target_id": int(edge["target_target_id"]),
            } for edge in ordered_edges],
        })

    for step in node_steps:
        step["control_states"] = control_states_by_node.get(
            int(step["node_id"]), []
        )

    if len(termination_region_indices) > 1:
        block(
            "multiple_terminal_invariants_pending",
            "the first terminal profile requires one canonical returned-state invariant",
            "prove a common terminal invariant or retain distinct terminal execution states",
        )

    profile = (
        "representative-compositional-control-v1"
        if (
            has_internal_call and has_internal_return and has_external_call
            and has_guarded_branch and has_bounded_indirect
        )
        else "finite-call-return-with-external-v1"
        if has_internal_call and has_internal_return and has_external_call
        else "bounded-indirect-control-v1"
        if has_bounded_indirect
        else "paired-external-call-v1"
        if has_external_call
        else "finite-call-return-v1"
        if has_internal_call and has_internal_return
        else "paired-stack-write-control-v1"
        if has_paired_stack_write
        else "guarded-no-write-control-v1"
        if has_guarded_branch
        else "direct-no-write-jump-v1"
    )
    if blockers:
        compact_blockers = _compact_acceptance_blockers(blockers)
        return {
            "format": "stage-a-whole-program-acceptance-v1",
            "status": "incomplete",
            "required_theorem": RELATIONAL_ACCEPTANCE_THEOREM,
            "theorem": None,
            "profile": profile,
            "control_states": control_states,
            "blockers": compact_blockers,
        }
    return {
        "format": "stage-a-whole-program-acceptance-v1",
        "status": "ready",
        "required_theorem": RELATIONAL_ACCEPTANCE_THEOREM,
        "theorem": RELATIONAL_ACCEPTANCE_THEOREM,
        "profile": profile,
        "root_node_id": roots[0],
        "terminal_region_index": (
            termination_region_indices[0]
            if termination_region_indices else roots[0]
        ),
        "terminal_invariant": (
            {
                "register_relations": [
                    claim["output"]
                    for step in node_steps if step["kind"] == "terminate"
                    for claim in step["output_claims"]
                ],
                "import_register_relations": [],
                "dynamic_register_range_relations": [],
                "bounds": [],
                "flag_bits": (
                    regions[termination_region_indices[0]].get("flag_outputs", [])
                    if termination_region_indices else []
                ),
                "address_separations": [],
                "stack_windows": [],
            }
            if termination_region_indices else {
                "register_relations": [],
                "import_register_relations": [],
                "dynamic_register_range_relations": [],
                "bounds": [],
                "flag_bits": [],
                "address_separations": [],
                "stack_windows": [],
            }
        ),
        "control_states": control_states,
        "node_steps": node_steps,
        "blockers": [],
    }

def _lean_all_listed_proof(theorems: list[str]) -> str:
    return (
        "".join(f"⟨{theorem}, " for theorem in theorems)
        + "True.intro"
        + "⟩" * len(theorems)
    )

def _lean_appended_list(names: list[str]) -> str:
    if not names:
        return "[]"
    result = names[-1]
    for name in reversed(names[:-1]):
        result = f"{name} ++ ({result})"
    return result

def _lean_appended_proof(
    chunks: list[dict[str, str]], theorem: str, arguments: str, proof_key: str
) -> str:
    if not chunks:
        return "True.intro"
    proof = chunks[-1][proof_key]
    ids = chunks[-1]["ids"]
    for chunk in reversed(chunks[:-1]):
        proof = (
            f"{theorem} {arguments} {chunk['ids']} ({ids}) "
            f"{chunk[proof_key]} ({proof})"
        )
        ids = f"{chunk['ids']} ++ ({ids})"
    return proof

def _lean_acceptance_empty_stack(node_id: int) -> str:
    return (
        "  have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
        f"      ((acceptanceOriginalNormalizedBehavior{node_id}.eval originalState).nextMachineState\n"
        "        originalState)\n"
        f"      ((acceptanceCandidateNormalizedBehavior{node_id}.eval candidateState).nextMachineState\n"
        "        candidateState) [] [] [] := by\n"
        "    simp [RelationalRuntimeCallStackHolds]"
    )

def _lean_acceptance_running_target(
    *, node_id: int, region_index: int, edge: dict[str, Any],
    frames: str = "[]", calls: str = "[]", frame_offsets: str = "[]",
    stack_targets_proof: str = "(by simp [RelationalRuntimeCallTargetsReachable])",
    target_control_proof: str = "(by decide)",
    observation_proof: str = "True.intro",
    world_equal_proof: str = "rfl",
) -> str:
    target_node_id = int(edge["target_node_id"])
    target_region_index = int(edge["target_region_index"])
    target_target_id = int(edge["target_target_id"])
    return (
        f"  have targetInvariant : productInvariantTable.nodeInvariants[{target_node_id}]? =\n"
        f"      some region{target_region_index}.inputInvariant := by decide\n"
        f"  have targetNodeTarget : relationalProductGraph.nodes[{target_node_id}].targetId =\n"
        f"      {target_target_id} := by decide\n"
        f"  refine ⟨{observation_proof}, ?_⟩\n"
        f"  refine ⟨rfl, rfl, rfl, {world_equal_proof}, {target_node_id},\n"
        f"    relationalProductGraph.nodes[{target_node_id}],\n"
        f"    region{target_region_index}.inputInvariant, {frames}, {frame_offsets},\n"
        f"    (by decide), targetNodeTarget, ?_, targetInvariant, {target_control_proof},\n"
        f"    stackHoldsNext, {stack_targets_proof}, "
        "nextStatesRelated⟩\n"
        "  decide"
    )

def _lean_acceptance_running_node(
    step: dict[str, Any], regions: list[dict[str, Any]],
    behaviors: list[dict[str, Any]], *,
    parameterized_environment: bool = False,
) -> str:
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_id = int(step["target_id"])
    original_behavior = f"acceptanceOriginalNormalizedBehavior{node_id}"
    candidate_behavior = f"acceptanceCandidateNormalizedBehavior{node_id}"
    running = f"acceptanceRunningNode{node_id}Refined"
    original_program = (
        "(originalWorldProgram originalEnvironment)"
        if parameterized_environment else "originalWorldProgram"
    )
    candidate_program = (
        "(candidateWorldProgram candidateEnvironment)"
        if parameterized_environment else "candidateWorldProgram"
    )
    environment_binders = (
        "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
        "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
        "      externalCallSites originalEnvironment candidateEnvironment) :\n"
        if parameterized_environment else ""
    )
    behavior_rewrite_arguments = (
        " originalEnvironment" if parameterized_environment else ""
    )
    candidate_behavior_rewrite_arguments = (
        " candidateEnvironment" if parameterized_environment else ""
    )
    prefix = (
        f"theorem {running}\n"
        + environment_binders
        + ("    " if parameterized_environment else "    :\n")
        + "    RunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      productControlProfile\n"
        f"      {original_program} {candidate_program} {node_id} := by\n"
        "  unfold RunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {target_id} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls frameOffsets eventIndex world originalState candidateState\n"
        "    controlAllowed stackHolds stackTargetsReachable statesRelated\n"
        "  unfold DecodedWorldProgram.transitionSystem\n"
        "  simp only [stepWorldExecution]\n"
        f"  rw [originalWorldBehaviorNode{node_id}{behavior_rewrite_arguments}, "
        f"candidateWorldBehaviorNode{node_id}{candidate_behavior_rewrite_arguments}]\n"
        "  simp only [transitionFromWorldOutcome, "
        "NormalizedSymbolicBehavior.eval_outcome,\n"
        f"    acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"    acceptanceCandidateNormalizedOutcome{node_id}, NormalizedOutcomeExpr.eval]\n"
    )
    empty_control = (
        "  have callsEmpty : calls = [] := by\n"
        "    cases calls with\n"
        "    | nil => rfl\n"
        "    | cons call tail =>\n"
        "        simp [productControlProfile, ProductControlProfile.Allows]\n"
        "          at controlAllowed\n"
        "  subst calls\n"
        "  have offsetsEmpty : frameOffsets = [] := by\n"
        "    simpa [productControlProfile, ProductControlProfile.Allows] using controlAllowed\n"
        "  subst frameOffsets\n"
        "  have framesEmpty : frames = [] := by\n"
        "    cases frames with\n"
        "    | nil => rfl\n"
        "    | cons frame tail =>\n"
        "        simp [RelationalRuntimeCallStackHolds] at stackHolds\n"
        "  subst frames\n"
    )
    if step["kind"] == "call":
        edge = step["edges"][0]
        edge_id = int(edge["edge_id"])
        target_region_index = int(edge["target_region_index"])
        continuation = int(step["continuation_target_id"])
        claim = step["direct_call_push_claim"]
        original_return = int(claim["original_return_address"])
        candidate_return = int(claim["candidate_return_address"])
        stack_amount = int(step["stack_amount"])
        stack_amount_twos_complement = 2**32 - stack_amount
        source_window = _lean_stack_window(step["source_stack_window"])
        if _normalized_behavior_fast_path(
            regions[region_index], behaviors[region_index]
        ):
            segment_original_behavior = f"region{region_index}NormalizedBehavior"
            segment_candidate_behavior = f"region{region_index}NormalizedBehavior"
        else:
            segment_original_behavior = (
                f"segmentRefinementEdge{edge_id}OriginalNormalizedBehavior"
            )
            segment_candidate_behavior = (
                f"segmentRefinementEdge{edge_id}CandidateNormalizedBehavior"
            )
        return (
            prefix
            + empty_control
            + f"  let sourceWindow : StackWindowPair := {source_window}\n"
            f"  have stackAddressRewrite (value : Word) :\n"
            f"      value + BitVec.ofNat 32 {stack_amount_twos_complement} =\n"
            f"        value - BitVec.ofNat 32 {stack_amount} := by\n"
            f"    exact word_add_ia32_twos_complement value {stack_amount} "
            "(by decide)\n"
            f"  have originalBehaviorSegment : {original_behavior} =\n"
            f"      {segment_original_behavior} := by decide\n"
            f"  have candidateBehaviorSegment : {candidate_behavior} =\n"
            f"      {segment_candidate_behavior} := by decide\n"
            "  let runtimeFrame : RelationalRuntimeCallFrame := {\n"
            f"    continuationTargetId := {continuation}\n"
            f"    originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
            f"    candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
            "    originalStackAddress := originalState.registers.get\n"
            f"      sourceWindow.originalRegister - BitVec.ofNat 32 {stack_amount}\n"
            "    candidateStackAddress := candidateState.registers.get\n"
            f"      sourceWindow.candidateRegister - BitVec.ofNat 32 {stack_amount}\n"
            "  }\n"
            f"  have transition := segmentRefinementEdge{edge_id}TransitionChecked world\n"
            "    originalState candidateState statesRelated\n"
            f"  have guardTrue : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
            "      originalState = true := by\n"
            f"    simp [segmentRefinementEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
            "  have transitioned := transition.2 guardTrue\n"
            "  have nextStatesRelated : StateRel staticProofContext world\n"
            f"      region{target_region_index}.inputInvariant\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "        candidateState) := by\n"
            "    simpa [originalBehaviorSegment, candidateBehaviorSegment] using\n"
            "      transitioned.2.2.2\n"
            "  have frameMemory : runtimeFrame.memoryHolds\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState).memory\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "        candidateState).memory := by\n"
            "    unfold RelationalRuntimeCallFrame.memoryHolds runtimeFrame\n"
            "    exact pairedStackWordWriteReadsBack_amount staticProofContext world\n"
            f"      region{region_index}.inputInvariant sourceWindow {stack_amount}\n"
            f"      (BitVec.ofNat 32 {original_return}) (BitVec.ofNat 32 {candidate_return})\n"
            "      originalState candidateState\n"
            f"      ({original_behavior}.eval originalState)\n"
            f"      ({candidate_behavior}.eval candidateState) statesRelated\n"
            "      (by decide) (by decide) (by decide) (by decide)\n"
            "      (by simp [sourceWindow,\n"
            f"        acceptanceOriginalNormalizedWrites{node_id},\n"
            f"        originalBehavior{region_index}, evalNormalizedWrites, Expr.eval,\n"
            "        stackAddressRewrite])\n"
            "      (by simp [sourceWindow,\n"
            f"        acceptanceCandidateNormalizedWrites{node_id},\n"
            f"        candidateBehavior{region_index}, evalNormalizedWrites, Expr.eval,\n"
            "        stackAddressRewrite])\n"
            "  have frameOffsetsHold : ReturnSlotOffsetPair.zero.holds runtimeFrame\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers := by\n"
            "    simp [ReturnSlotOffsetPair.zero, ReturnSlotOffsetPair.holds, runtimeFrame,\n"
            "      sourceWindow,\n"
            f"      acceptanceOriginalNormalizedRegisters{node_id},\n"
            f"      acceptanceCandidateNormalizedRegisters{node_id},\n"
            f"      originalBehavior{region_index}, candidateBehavior{region_index},\n"
            "      evalNormalizedRegisters, evalNormalizedRegisters_get,\n"
            "      StageA.Formal.Registers.get, Expr.eval,\n"
            "      stackAddressRewrite]\n"
            "  have frameValid : runtimeFrame.toRelationalCallFrame.valid\n"
            "      staticProofContext = true := by\n"
            "    change RelationalCallFrame.valid staticProofContext {\n"
            f"      continuationTargetId := {continuation}\n"
            f"      originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
            f"      candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
            "    } = true\n"
            "    decide\n"
            "  have frameResolves : runtimeFrame.toRelationalCallFrame.resolves\n"
            "      staticProofContext = true := by\n"
            "    change RelationalCallFrame.resolves staticProofContext {\n"
            f"      continuationTargetId := {continuation}\n"
            f"      originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
            f"      candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
            "    } = true\n"
            "    decide\n"
            "  have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"        candidateState) [runtimeFrame] [{continuation}]\n"
            "      [ReturnSlotOffsetPair.zero] := by\n"
            "    simp only [RelationalRuntimeCallStackHolds]\n"
            "    exact ⟨rfl, frameValid, frameResolves, frameMemory, frameOffsetsHold,\n"
            "      True.intro⟩\n"
            + _lean_acceptance_running_target(
                node_id=node_id,
                region_index=region_index,
                edge=edge,
                frames="[runtimeFrame]",
                calls=f"[{continuation}]",
                frame_offsets="[ReturnSlotOffsetPair.zero]",
                stack_targets_proof=(
                    "(by simp only [RelationalRuntimeCallTargetsReachable]; "
                    f"exact ⟨⟨{continuation}, relationalProductGraph.nodes[{continuation}], "
                    "by decide, by decide, by decide⟩, True.intro⟩)"
                ),
            )
        )
    if step["kind"] == "return":
        continuation = int(step["target_target_id"])
        target_node_id = int(step["target_node_id"])
        target_region_index = int(step["target_region_index"])
        return_claim = step["return_pop_claim"]
        frame_claim = step["return_frame_claim"]
        return_claim_row = (
            "{ originalStackAddress := "
            + _lean_semantic_expr(return_claim["original_stack_address"])
            + ", candidateStackAddress := "
            + _lean_semantic_expr(return_claim["candidate_stack_address"])
            + f", popBytes := {int(return_claim['pop_bytes'])} }}"
        )
        frame_claim_row = (
            "{ offsets := "
            + _lean_return_slot_offset_pair(frame_claim["offsets"])
            + ", originalSlot := "
            + _lean_register_offset_witness(frame_claim["original_slot_witness"])
            + ", candidateSlot := "
            + _lean_register_offset_witness(frame_claim["candidate_slot_witness"])
            + " }"
        )
        frame_offsets = _lean_return_slot_offset_pair(frame_claim["offsets"])
        output_claims = ", ".join(
            _lean_register_output_claim(claim) for claim in step["output_claims"]
        )
        stack_transfers = ", ".join(
            _lean_stack_window_transfer_claim(claim)
            for claim in step["stack_window_transfers"]
        )
        target_edge = {
            "target_node_id": target_node_id,
            "target_region_index": target_region_index,
            "target_target_id": continuation,
        }
        return (
            prefix
            + "  have controlShape : calls = ["
            + str(continuation)
            + "] ∧ frameOffsets = ["
            + frame_offsets
            + "] := by\n"
            "    simpa [productControlProfile, ProductControlProfile.Allows] using\n"
            "      controlAllowed\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
            "  cases frames with\n"
            "  | nil => simp [RelationalRuntimeCallStackHolds] at stackHolds\n"
            "  | cons frame tail =>\n"
            "    have tailEmpty : tail = [] := by\n"
            "      cases tail with\n"
            "      | nil => rfl\n"
            "      | cons next rest =>\n"
            "          simp [RelationalRuntimeCallStackHolds] at stackHolds\n"
            "    subst tail\n"
            "    simp only [RelationalRuntimeCallStackHolds] at stackHolds\n"
            "    have frameContinuation := stackHolds.1\n"
            "    have frameResolves := stackHolds.2.2.1\n"
            "    have frameMemory := stackHolds.2.2.2.1\n"
            "    have frameOffsetsHold := stackHolds.2.2.2.2.1\n"
            f"    let returnClaim : ReturnPopClaim := {return_claim_row}\n"
            f"    let frameClaim : ReturnPopFrameClaim := {frame_claim_row}\n"
            "    have returnTargets := returnPopTargetsRuntimeFrame_of_checked\n"
            f"      {original_behavior} {candidate_behavior} returnClaim frameClaim frame\n"
            "      originalState candidateState (by decide) (by decide)\n"
            "      frameOffsetsHold frameMemory\n"
            f"    simp only [acceptanceOriginalNormalizedOutcome{node_id},\n"
            f"      acceptanceCandidateNormalizedOutcome{node_id},\n"
            "      NormalizedOutcomeExpr.eval, PureOutcome.returned.injEq]\n"
            "      at returnTargets\n"
            "    have relatedForTransfer := statesRelated\n"
            "    rcases statesRelated with\n"
            "      ⟨_worldValid, stackRangesValid, _stackMemory, _importsStatic,\n"
            "        _importsComplete, _importsMemory, _originalImmutable,\n"
            "        _candidateImmutable, relatedCore, _inputImportRegisters⟩\n"
            "    rcases relatedCore with\n"
            "      ⟨_inputRegisters, _inputBounds, _inputSeparations, inputStackWindows,\n"
            "        _inputMemory, _inputDynamicMemory, _inputUndefined, inputX87,\n"
            "        _inputFlags, _inputFsBase⟩\n"
            f"    let outputClaims : List InvariantWP.RegisterOutputClaim := [{output_claims}]\n"
            "    have outputRegisters : registerRelationsHold\n"
            "        staticProofContext.originalPe.imageBase\n"
            "        staticProofContext.candidatePe.imageBase\n"
            "        staticProofContext.codeMap.entries.toList\n"
            "        (staticProofContext.relationalValueTargets world)\n"
            f"        region{target_region_index}.inputInvariant.registerRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            f"      rw [RegionRelation.inputInvariant]\n"
            f"      have inventory : outputClaims.map InvariantWP.RegisterOutputClaim.output =\n"
            f"          region{target_region_index}.inputRelations := by decide\n"
            "      rw [← inventory]\n"
            "      exact InvariantWP.registerRelationsHold_of_nonMemoryOutputClaims\n"
            f"        staticProofContext world region{region_index} {original_behavior}\n"
            f"        {candidate_behavior} outputClaims (by decide)\n"
            "        originalState candidateState relatedForTransfer\n"
            "    have outputBounds : boundsRelated\n"
            f"        region{target_region_index}.inputInvariant.bounds\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index}, boundsRelated]\n"
            "    have outputSeparations : addressSeparationsRelated\n"
            f"        region{target_region_index}.inputInvariant.addressSeparations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        addressSeparationsRelated]\n"
            f"    let stackTransfers : List StackWindowAffineTransferClaim := [{stack_transfers}]\n"
            "    have outputStackWindows := stackWindowsRelated_after_affine_of_checked\n"
            f"      staticProofContext world region{region_index}.inputInvariant\n"
            f"      region{target_region_index}.inputInvariant {original_behavior}\n"
            f"      {candidate_behavior} stackTransfers originalState candidateState\n"
            "      stackRangesValid inputStackWindows (by decide)\n"
            f"    have originalX87Field : {original_behavior}.x87 =\n"
            f"        originalBehavior{region_index}.x87 := by decide\n"
            f"    have candidateX87Field : {candidate_behavior}.x87 =\n"
            f"        candidateBehavior{region_index}.x87 := by decide\n"
            "    have outputX87 :\n"
            f"        (({original_behavior}.eval originalState).nextMachineState\n"
            "          originalState).x87 =\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "          candidateState).x87 := by\n"
            "      rcases originalState with\n"
            "        ⟨originalRegisters, originalMemory, originalUndefined, originalX87,\n"
            "          originalFlags, originalFsBase⟩\n"
            "      rcases candidateState with\n"
            "        ⟨candidateRegisters, candidateMemory, candidateUndefined, candidateX87,\n"
            "          candidateFlags, candidateFsBase⟩\n"
            "      change originalX87 = candidateX87 at inputX87\n"
            "      subst candidateX87\n"
            "      simp [originalX87Field, candidateX87Field,\n"
            f"        originalBehavior{region_index}, candidateBehavior{region_index},\n"
            "        RelationalBehavior.nextMachineState, evalNormalizedX87,\n"
            "        X87Expr.eval, Expr.eval]\n"
            "    have outputFlags : flagsRelated\n"
            f"        region{target_region_index}.inputInvariant.flagBits\n"
            f"        ({original_behavior}.eval originalState).eflags\n"
            f"        ({candidate_behavior}.eval candidateState).eflags = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        flagsRelated]\n"
            f"    have originalWritesField : {original_behavior}.writes = [] := by decide\n"
            f"    have candidateWritesField : {candidate_behavior}.writes = [] := by decide\n"
            f"    have originalWrites : ({original_behavior}.eval originalState).writes = [] := by\n"
            "      simp [originalWritesField, evalNormalizedWrites]\n"
            f"    have candidateWrites : ({candidate_behavior}.eval candidateState).writes = [] := by\n"
            "      simp [candidateWritesField, evalNormalizedWrites]\n"
            "    have outputImports : importRegisterRelationsHold world\n"
            f"        region{target_region_index}.inputInvariant.importRegisterRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        importRegisterRelationsHold]\n"
            "    have outputDynamic : dynamicRegisterRangeRelationsHold world\n"
            f"        region{target_region_index}.inputInvariant.dynamicRegisterRangeRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        dynamicRegisterRangeRelationsHold]\n"
            "    have nextStatesRelated : StateRel staticProofContext world\n"
            f"        region{target_region_index}.inputInvariant\n"
            f"        (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState candidateState) :=\n"
            "      StateRel.afterNoWriteEvaluation staticProofContext world\n"
            f"        region{region_index}.inputInvariant region{target_region_index}.inputInvariant\n"
            f"        originalState candidateState ({original_behavior}.eval originalState)\n"
            f"        ({candidate_behavior}.eval candidateState) relatedForTransfer\n"
            "        originalWrites candidateWrites outputRegisters outputBounds\n"
            "        outputSeparations outputStackWindows outputX87 outputFlags\n"
            "        outputImports outputDynamic\n"
            "    have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
            f"        (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "        [] [] [] := by simp [RelationalRuntimeCallStackHolds]\n"
            "    simp only [RelationalCallFrame.resolves, Bool.and_eq_true, beq_iff_eq]\n"
            "      at frameResolves\n"
            "    rw [frameContinuation] at frameResolves\n"
            "    simp [originalWorldProgram, candidateWorldProgram]\n"
            "    rw [returnTargets.1, returnTargets.2, frameResolves.1, frameResolves.2]\n"
            "    simp\n"
            + "\n".join(
                "  " + line
                for line in _lean_acceptance_running_target(
                    node_id=node_id,
                    region_index=region_index,
                    edge=target_edge,
                ).splitlines()
            )
        )
    if step["kind"] == "external_call":
        edge = step["edges"][0]
        edge_id = int(edge["edge_id"])
        target_region_index = int(edge["target_region_index"])
        site = step["external_site"]
        arguments = ", ".join(
            _lean_semantic_expr(argument)
            for argument in site.get("argument_expressions", [])
        )
        original_arguments = ", ".join(
            f"({_lean_semantic_expr(argument)}).eval originalState"
            for argument in site.get("argument_expressions", [])
        )
        candidate_arguments = ", ".join(
            f"({_lean_semantic_expr(argument)}).eval candidateState"
            for argument in site.get("argument_expressions", [])
        )
        imported_identity = _semantic_external_target_identity(
            step.get("external_site", {}).get("original_import")
            or step.get("external_site", {}).get("import")
            or {}
        )
        if imported_identity is None:
            imported_identity = _semantic_external_target_identity(
                step.get("external_site", {}).get("decoded_import")
                or {}
            )
        if imported_identity is None:
            imported_identity = _semantic_external_target_identity(
                step.get("external_site", {}).get("machine_import")
                or {}
            )
        if imported_identity is None:
            # The candidate carries a contract id, while the exact byte-level target
            # remains in the decoded outcome used to construct this node step.
            decoded_import = step.get("decoded_import")
            imported_identity = _semantic_external_target_identity(decoded_import)
        if imported_identity is None:
            raise StageAInputError(
                f"external acceptance node {node_id} has no decoded import identity"
            )
        imported_literal = _lean_external_target({
            "dll": imported_identity[0], imported_identity[1]: imported_identity[2],
        })
        return (
            prefix
            + empty_control
            + f"  have originalBehaviorCommon : {original_behavior} =\n"
            f"      externalCallEdge{edge_id}OriginalNormalized := by decide\n"
            f"  have candidateBehaviorCommon : {candidate_behavior} =\n"
            f"      externalCallEdge{edge_id}CandidateNormalized := by decide\n"
            f"  have transition := externalCallEdge{edge_id}TransitionChecked world\n"
            "    originalState candidateState statesRelated\n"
            f"  have guardTrue : externalCallEdge{edge_id}Spec.originalGuard.eval\n"
            "      originalState = true := by\n"
            f"    simp [externalCallEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
            "  have closed := transition.2 guardTrue\n"
            f"  simp only [evalBehavior, externalCallEdge{edge_id}OriginalNormalizedChecked,\n"
            f"    externalCallEdge{edge_id}CandidateNormalizedChecked, Option.bind_some]\n"
            "    at closed\n"
            "  rcases closed with\n"
            "    ⟨originalCallArguments, candidateCallArguments, originalOutcome,\n"
            "      candidateOutcome, _edgeExit, _outcomesRelated, boundary⟩\n"
            f"  have originalArgumentsKnown : [{original_arguments}] =\n"
            f"      originalCallArguments := by\n"
            f"    have decomposed := originalOutcome\n"
            f"    simp only [externalCallEdge{edge_id}OriginalOutcomeChecked,\n"
            "      NormalizedSymbolicBehavior.eval_outcome, NormalizedOutcomeExpr.eval,\n"
            "      Expr.eval, PureOutcome.externalCall.injEq] at decomposed\n"
            "    simpa only [List.map] using decomposed.2.1\n"
            f"  have candidateArgumentsKnown : [{candidate_arguments}] =\n"
            f"      candidateCallArguments := by\n"
            f"    have decomposed := candidateOutcome\n"
            f"    simp only [externalCallEdge{edge_id}CandidateOutcomeChecked,\n"
            "      NormalizedSymbolicBehavior.eval_outcome, NormalizedOutcomeExpr.eval,\n"
            "      Expr.eval, PureOutcome.externalCall.injEq] at decomposed\n"
            "    simpa only [List.map] using decomposed.2.1\n"
            "  subst originalCallArguments\n"
            "  subst candidateCallArguments\n"
            "  let originalEvent : WorldExternalEvent := {\n"
            f"    siteId := {edge_id}\n"
            f"    imported := externalCallEdge{edge_id}MachineContract.imported\n"
            f"    arguments := [{original_arguments}]\n"
            f"    state := ({original_behavior}.eval originalState).nextMachineState\n"
            "      originalState\n"
            "    world\n"
            "  }\n"
            "  let candidateEvent : WorldExternalEvent := {\n"
            f"    siteId := {edge_id}\n"
            f"    imported := externalCallEdge{edge_id}MachineContract.imported\n"
            f"    arguments := [{candidate_arguments}]\n"
            f"    state := ({candidate_behavior}.eval candidateState).nextMachineState\n"
            "      candidateState\n"
            "    world\n"
            "  }\n"
            "  have boundaryKnown : ExternalCallBoundaryRelated staticProofContext\n"
            f"      externalCallSite{edge_id} externalCallEdge{edge_id}MachineContract\n"
            "      originalEvent candidateEvent := by\n"
            "    simpa [originalEvent, candidateEvent, originalBehaviorCommon,\n"
            "      candidateBehaviorCommon] using boundary\n"
            "  have environmentAt := ExternalEnvironmentRefines.at staticProofContext\n"
            "    externalCallSites originalEnvironment candidateEnvironment\n"
            f"    environmentRefines externalCallSite{edge_id}\n"
            f"    externalCallEdge{edge_id}MachineContract (by decide)\n"
            f"    externalCallEdge{edge_id}MachineContractResolved\n"
            "  have results := externalCallResultsRelated staticProofContext\n"
            f"    externalCallSite{edge_id} externalCallEdge{edge_id}MachineContract\n"
            "    originalEnvironment candidateEnvironment environmentAt eventIndex\n"
            "    originalEvent candidateEvent boundaryKnown\n"
            "  dsimp only at results\n"
            "  rcases results with\n"
            "    ⟨resultWorldsEqual, _originalConforms, _candidateConforms,\n"
            "      nextStatesRelated⟩\n"
            "  have argumentsRelated := boundaryKnown.2.2.2.2.2.2\n"
            "  have observationRelated : worldRelationalObservationsRelated\n"
            "      staticProofContext\n"
            f"      (some (.external world externalCallEdge{edge_id}MachineContract.imported\n"
            f"        [{original_arguments}]))\n"
            f"      (some (.external world externalCallEdge{edge_id}MachineContract.imported\n"
            f"        [{candidate_arguments}])) := by\n"
            "    exact ⟨rfl, rfl, argumentsRelated⟩\n"
            "  have originalSiteResolved : resolveExternalCallSite staticProofContext\n"
            f"      externalCallSites {target_id}\n"
            f"      externalCallEdge{edge_id}MachineContract.imported = some {edge_id} := by\n"
            "    decide\n"
            "  have candidateSiteResolved : resolveExternalCallSite staticProofContext\n"
            f"      externalCallSites {target_id}\n"
            f"      externalCallEdge{edge_id}MachineContract.imported = some {edge_id} := by\n"
            "    decide\n"
            "  rw [originalBehaviorCommon, candidateBehaviorCommon]\n"
            "  simp only [originalWorldProgram, candidateWorldProgram]\n"
            f"  have importedCommon : ({imported_literal} : ExternalTarget) =\n"
            f"      externalCallEdge{edge_id}MachineContract.imported := by decide\n"
            "  rw [importedCommon]\n"
            "  rw [originalSiteResolved]\n"
            "  simp only [List.map_nil]\n"
            "  have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
            "      (originalEnvironment.result eventIndex originalEvent).state\n"
            "      (candidateEnvironment.result eventIndex candidateEvent).state\n"
            "      [] [] [] := by\n"
            "    simp [RelationalRuntimeCallStackHolds]\n"
            + _lean_acceptance_running_target(
                node_id=node_id,
                region_index=region_index,
                edge=edge,
                observation_proof="observationRelated",
                world_equal_proof="resultWorldsEqual",
            )
        )
    if step["kind"] == "terminate":
        output_claims = ", ".join(
            _lean_register_output_claim(claim) for claim in step["output_claims"]
        )
        return (
            prefix
            + empty_control
            + "  have relatedForTransfer := statesRelated\n"
            "  rcases statesRelated with\n"
            "    ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,\n"
            "      _importsComplete, _importsMemory, _originalImmutable,\n"
            "      _candidateImmutable, relatedCore, _inputImportRegisters⟩\n"
            "  rcases relatedCore with\n"
            "    ⟨_inputRegisters, _inputBounds, _inputSeparations, _inputStackWindows,\n"
            "      _inputMemory, _inputDynamicMemory, _inputUndefined, inputX87,\n"
            "      _inputFlags, _inputFsBase⟩\n"
            f"  let outputClaims : List InvariantWP.RegisterOutputClaim := [{output_claims}]\n"
            "  have outputRegisters : registerRelationsHold\n"
            "      staticProofContext.originalPe.imageBase\n"
            "      staticProofContext.candidatePe.imageBase\n"
            "      staticProofContext.codeMap.entries.toList\n"
            "      (staticProofContext.relationalValueTargets world)\n"
            "      terminalInvariant.registerRelations\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    have inventory : outputClaims.map InvariantWP.RegisterOutputClaim.output =\n"
            "        terminalInvariant.registerRelations := by decide\n"
            "    rw [← inventory]\n"
            "    exact InvariantWP.registerRelationsHold_of_nonMemoryOutputClaims\n"
            f"      staticProofContext world region{region_index} {original_behavior}\n"
            f"      {candidate_behavior} outputClaims (by decide) originalState\n"
            "      candidateState relatedForTransfer\n"
            "  have outputBounds : boundsRelated\n"
            "      terminalInvariant.bounds\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    simp [terminalInvariant, boundsRelated]\n"
            "  have outputSeparations : addressSeparationsRelated\n"
            "      terminalInvariant.addressSeparations\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    simp [terminalInvariant, addressSeparationsRelated]\n"
            "  have outputStackWindows : stackWindowsRelated world\n"
            "      terminalInvariant.stackWindows\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    simp [terminalInvariant, stackWindowsRelated]\n"
            f"  have originalX87Field : {original_behavior}.x87 =\n"
            f"      originalBehavior{region_index}.x87 := by decide\n"
            f"  have candidateX87Field : {candidate_behavior}.x87 =\n"
            f"      candidateBehavior{region_index}.x87 := by decide\n"
            "  have outputX87 :\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState).x87 =\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "        candidateState).x87 := by\n"
            "    rcases originalState with\n"
            "      ⟨originalRegisters, originalMemory, originalUndefined, originalX87,\n"
            "        originalFlags, originalFsBase⟩\n"
            "    rcases candidateState with\n"
            "      ⟨candidateRegisters, candidateMemory, candidateUndefined, candidateX87,\n"
            "        candidateFlags, candidateFsBase⟩\n"
            "    change originalX87 = candidateX87 at inputX87\n"
            "    subst candidateX87\n"
            "    simp [originalX87Field, candidateX87Field,\n"
            f"      originalBehavior{region_index}, candidateBehavior{region_index},\n"
            "      RelationalBehavior.nextMachineState, evalNormalizedX87,\n"
            "      X87Expr.eval, Expr.eval]\n"
            "  have outputFlags : flagsRelated\n"
            "      terminalInvariant.flagBits\n"
            f"      ({original_behavior}.eval originalState).eflags\n"
            f"      ({candidate_behavior}.eval candidateState).eflags = true := by\n"
            f"    simp [terminalInvariant, region{region_index}, flagsRelated]\n"
            f"  have originalWritesField : {original_behavior}.writes = [] := by decide\n"
            f"  have candidateWritesField : {candidate_behavior}.writes = [] := by decide\n"
            f"  have originalWrites : ({original_behavior}.eval originalState).writes = [] := by\n"
            "    simp [originalWritesField, evalNormalizedWrites]\n"
            f"  have candidateWrites : ({candidate_behavior}.eval candidateState).writes = [] := by\n"
            "    simp [candidateWritesField, evalNormalizedWrites]\n"
            "  have outputImports : importRegisterRelationsHold world\n"
            "      terminalInvariant.importRegisterRelations\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    simp [terminalInvariant, importRegisterRelationsHold]\n"
            "  have outputDynamic : dynamicRegisterRangeRelationsHold world\n"
            "      terminalInvariant.dynamicRegisterRangeRelations\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    simp [terminalInvariant, dynamicRegisterRangeRelationsHold]\n"
            "  have nextStatesRelated : StateRel staticProofContext world\n"
            "      terminalInvariant\n"
            f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState) :=\n"
            "    StateRel.afterNoWriteEvaluation staticProofContext world\n"
            f"      region{region_index}.inputInvariant terminalInvariant\n"
            f"      originalState candidateState ({original_behavior}.eval originalState)\n"
            f"      ({candidate_behavior}.eval candidateState) relatedForTransfer\n"
            "      originalWrites candidateWrites outputRegisters outputBounds\n"
            "      outputSeparations outputStackWindows outputX87 outputFlags\n"
            "      outputImports outputDynamic\n"
            "  simp [originalWorldProgram, candidateWorldProgram,\n"
            "    transitionFromWorldOutcome]\n"
            "  constructor\n"
            "  · rfl\n"
            "  · exact ⟨rfl, nextStatesRelated⟩\n"
        )
    if step["kind"] == "indirect_jump":
        edge = step["edges"][0]
        edge_id = int(edge["edge_id"])
        target_region_index = int(edge["target_region_index"])
        target_id = int(edge["target_target_id"])
        original_product_behavior = f"productNode{node_id}OriginalNormalized"
        candidate_product_behavior = f"productNode{node_id}CandidateNormalized"
        claim = f"productNode{node_id}ImmutableIndirectJumpClaim"
        target_closed = f"productNode{node_id}ImmutableIndirectJumpClosed"
        return (
            prefix
            + f"  have originalBehaviorCommon : {original_behavior} =\n"
            f"      {original_product_behavior} := by decide\n"
            f"  have candidateBehaviorCommon : {candidate_behavior} =\n"
            f"      {candidate_product_behavior} := by decide\n"
            f"  have indirectTargets := {target_closed} world originalState\n"
            "    candidateState statesRelated\n"
            "  have originalTargetExpression :\n"
            f"      ({_lean_semantic_expr(step['decoded_control']['original_target_expression'])}).eval "
            "originalState =\n"
            "        BitVec.ofNat 32 (staticProofContext.originalPe.imageBase +\n"
            f"          staticProofContext.codeMap.entries[{claim}.targetId].originalRva) := by\n"
            "    rw [← originalBehaviorCommon] at indirectTargets\n"
            f"    simpa only [acceptanceOriginalNormalizedOutcome{node_id},\n"
            "      NormalizedOutcomeExpr.eval, PureOutcome.indirectJump.injEq] using\n"
            "      indirectTargets.1\n"
            "  have candidateTargetExpression :\n"
            f"      ({_lean_semantic_expr(step['decoded_control']['candidate_target_expression'])}).eval "
            "candidateState =\n"
            "        BitVec.ofNat 32 (staticProofContext.candidatePe.imageBase +\n"
            f"          staticProofContext.codeMap.entries[{claim}.targetId].candidateRva) := by\n"
            "    rw [← candidateBehaviorCommon] at indirectTargets\n"
            f"    simpa only [acceptanceCandidateNormalizedOutcome{node_id},\n"
            "      NormalizedOutcomeExpr.eval, PureOutcome.indirectJump.injEq] using\n"
            "      indirectTargets.2\n"
            "  have originalTargetResolved : resolveMappedCodeTarget false\n"
            "      staticProofContext.originalPe.imageBase\n"
            "      staticProofContext.codeMap.entries.toList\n"
            "      (BitVec.ofNat 32 (staticProofContext.originalPe.imageBase +\n"
            f"        staticProofContext.codeMap.entries[{claim}.targetId].originalRva)) =\n"
            f"        some {target_id} := by decide\n"
            "  have candidateTargetResolved : resolveMappedCodeTarget true\n"
            "      staticProofContext.candidatePe.imageBase\n"
            "      staticProofContext.codeMap.entries.toList\n"
            "      (BitVec.ofNat 32 (staticProofContext.candidatePe.imageBase +\n"
            f"        staticProofContext.codeMap.entries[{claim}.targetId].candidateRva)) =\n"
            f"        some {target_id} := by decide\n"
            f"  have transition := segmentRefinementEdge{edge_id}TransitionChecked world\n"
            "    originalState candidateState statesRelated\n"
            f"  have guardTrue : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
            "      originalState = true := by\n"
            f"    simp [segmentRefinementEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
            "  have transitioned := transition.2 guardTrue\n"
            "  have nextStatesRelated : StateRel staticProofContext world\n"
            f"      region{target_region_index}.inputInvariant\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "        candidateState) := by\n"
            "    simpa [originalBehaviorCommon, candidateBehaviorCommon] using\n"
            "      transitioned.2.2.2\n"
            "  have stackHoldsNext := RelationalRuntimeCallStackHolds.of_memory_eq\n"
            "    staticProofContext originalState candidateState\n"
            f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "    frames calls frameOffsets stackHolds\n"
            "    (by simp [RelationalBehavior.nextMachineState, originalBehaviorCommon,\n"
            f"      {original_product_behavior}WritesEmpty, evalNormalizedWrites,\n"
            "      applyConcreteWrites])\n"
            "    (by simp [RelationalBehavior.nextMachineState, candidateBehaviorCommon,\n"
            f"      {candidate_product_behavior}WritesEmpty, evalNormalizedWrites,\n"
            "      applyConcreteWrites])\n"
            "    (by\n"
            "      change (evalNormalizedRegisters originalState\n"
            f"        {original_product_behavior}.registers).get .esp =\n"
            "          originalState.registers.get .esp\n"
            f"      rw [evalNormalizedRegisters_get, "
            f"{original_product_behavior}EspGet]\n"
            "      rfl)\n"
            "    (by\n"
            "      change (evalNormalizedRegisters candidateState\n"
            f"        {candidate_product_behavior}.registers).get .esp =\n"
            "          candidateState.registers.get .esp\n"
            f"      rw [evalNormalizedRegisters_get, "
            f"{candidate_product_behavior}EspGet]\n"
            "      rfl)\n"
            "  have targetControlAllowed : productControlProfile.Allows\n"
            f"      {int(edge['target_node_id'])} calls frameOffsets = true := by\n"
            "    simpa [productControlProfile, ProductControlProfile.Allows] using\n"
            "      controlAllowed\n"
            "  rw [originalTargetExpression, candidateTargetExpression]\n"
            "  simp only [originalWorldProgram, candidateWorldProgram,\n"
            "    Bool.false_eq_true, if_false, if_true]\n"
            "  rw [originalTargetResolved, candidateTargetResolved]\n"
            "  simp only\n"
            + _lean_acceptance_running_target(
                node_id=node_id,
                region_index=region_index,
                edge=edge,
                frames="frames",
                calls="calls",
                frame_offsets="frameOffsets",
                stack_targets_proof="stackTargetsReachable",
                target_control_proof="targetControlAllowed",
            )
        )
    if step["kind"] == "jump":
        edge = step["edges"][0]
        edge_id = int(edge["edge_id"])
        target_region_index = int(edge["target_region_index"])
        return (
            prefix
            + empty_control
            + f"  have transition := segmentRefinementEdge{edge_id}TransitionChecked world\n"
            "    originalState candidateState statesRelated\n"
            f"  have guardTrue : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
            "      originalState = true := by\n"
            f"    simp [segmentRefinementEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
            "  have transitioned := transition.2 guardTrue\n"
            "  have nextStatesRelated : StateRel staticProofContext world\n"
            f"      region{target_region_index}.inputInvariant\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "        candidateState) := by\n"
            f"    simpa [{original_behavior}, {candidate_behavior},\n"
            f"      region{region_index}NormalizedBehavior] using transitioned.2.2.2\n"
            + _lean_acceptance_empty_stack(node_id)
            + "\n"
            + _lean_acceptance_running_target(
                node_id=node_id, region_index=region_index, edge=edge
            )
        )

    taken, fallthrough = step["edges"]
    taken_id = int(taken["edge_id"])
    fallthrough_id = int(fallthrough["edge_id"])

    def branch_case(edge: dict[str, Any], condition: bool) -> str:
        edge_id = int(edge["edge_id"])
        target_region_index = int(edge["target_region_index"])
        condition_literal = "true" if condition else "false"
        original_guard = (
            f"      change region{region_index}OutcomeCondition.eval originalState = true\n"
            "      exact originalCondition\n"
            if condition else
            f"      change (!region{region_index}OutcomeCondition.eval originalState) = true\n"
            "      simp [originalCondition]\n"
        )
        stack_proof = "\n".join(
            "  " + line
            for line in _lean_acceptance_empty_stack(node_id).splitlines()
        )
        target_proof = "\n".join(
            "  " + line
            for line in _lean_acceptance_running_target(
                node_id=node_id, region_index=region_index, edge=edge
            ).splitlines()
        )
        return (
            f"    have originalGuard : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
            "        originalState = true := by\n"
            + original_guard
            + f"    have candidateGuard : segmentRefinementEdge{edge_id}Spec.candidateGuard.eval\n"
            "        candidateState = true := by\n"
            f"      rw [← transition{edge_id}.1]\n"
            "      exact originalGuard\n"
            f"    have candidateCondition : region{region_index}OutcomeCondition.eval\n"
            f"        candidateState = {condition_literal} := by\n"
            "      exact normalizedBranchCondition_eval_of_guard_true\n"
            f"        region{region_index}OutcomeCondition\n"
            f"        segmentRefinementEdge{edge_id}Spec.candidateGuard\n"
            f"        {condition_literal} candidateState (by decide) candidateGuard\n"
            f"    have transitioned := transition{edge_id}.2 originalGuard\n"
            "    have nextStatesRelated : StateRel staticProofContext world\n"
            f"        region{target_region_index}.inputInvariant\n"
            f"        (({original_behavior}.eval originalState).nextMachineState\n"
            "          originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "          candidateState) := by\n"
            f"      simpa [{original_behavior}, {candidate_behavior},\n"
            f"        region{region_index}NormalizedBehavior] using transitioned.2.2.2\n"
            + stack_proof
            + "\n"
            f"    simp only [region{region_index}OutcomeCondition] at "
            "originalCondition candidateCondition\n"
            "    simp [originalCondition, candidateCondition]\n"
            + target_proof
        )

    return (
        prefix
        + empty_control
        + f"  have transition{taken_id} := segmentRefinementEdge{taken_id}TransitionChecked world\n"
        "    originalState candidateState statesRelated\n"
        f"  have transition{fallthrough_id} := segmentRefinementEdge{fallthrough_id}TransitionChecked world\n"
        "    originalState candidateState statesRelated\n"
        f"  cases originalCondition : region{region_index}OutcomeCondition.eval originalState with\n"
        "  | false =>\n"
        + branch_case(fallthrough, False)
        + "\n  | true =>\n"
        + branch_case(taken, True)
    )

def _lean_acceptance_execution_edge(
    *, step: dict[str, Any], edge: dict[str, Any]
) -> str:
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_id = int(step["target_id"])
    edge_id = int(edge["edge_id"])
    target_node_id = int(edge["target_node_id"])
    target_region_index = int(edge["target_region_index"])
    target_target_id = int(edge["target_target_id"])
    node_resolution_theorems = [
        f"(show relationalProductGraph.getNode? {node_id} = "
        f"some relationalProductGraph.nodes[{node_id}] by decide)"
    ]
    if target_node_id != node_id:
        node_resolution_theorems.append(
            f"(show relationalProductGraph.getNode? {target_node_id} = "
            f"some relationalProductGraph.nodes[{target_node_id}] by decide)"
        )
    invariant_rewrites = ["sourceInvariant"]
    if target_node_id != node_id:
        invariant_rewrites.append("targetInvariant")
    if step["kind"] == "external_call":
        return (
            f"theorem acceptanceExecutionEdge{edge_id}Refined :\n"
            "    RelationalProductExecutionEdgeRefined staticProofContext\n"
            "      relationalProductGraph allRegions productInvariantTable "
            f"{edge_id} := by\n"
            "  apply Or.inr\n"
            "  unfold RelationalExternalExecutionEdgeRefined\n"
            f"  rw [externalCallEdge{edge_id}ProductResolved]\n"
            "  simp only\n"
            f"  have edgeSourceNode : relationalProductGraph.edges[{edge_id}].sourceNodeId =\n"
            f"      {node_id} := by decide\n"
            f"  have edgeTargetNode : relationalProductGraph.edges[{edge_id}].targetNodeId =\n"
            f"      {target_node_id} := by decide\n"
            f"  have edgeSourceTarget : relationalProductGraph.edges[{edge_id}].sourceTargetId =\n"
            f"      {target_id} := by decide\n"
            f"  have edgeTargetTarget : relationalProductGraph.edges[{edge_id}].targetTargetId =\n"
            f"      {target_target_id} := by decide\n"
            "  rw [edgeSourceNode, edgeTargetNode, edgeSourceTarget, edgeTargetTarget,\n"
            f"    {', '.join(node_resolution_theorems)}]\n"
            f"  have regionFound : regionById allRegions {target_id} = "
            f"some region{region_index} := by decide\n"
            f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
            f"      some region{region_index}.inputInvariant := by decide\n"
            f"  have targetInvariant : productInvariantTable.nodeInvariants[{target_node_id}]? =\n"
            f"      some region{target_region_index}.inputInvariant := by decide\n"
            f"  rw [regionFound, {', '.join(invariant_rewrites)}]\n"
            f"  refine ⟨externalCallSite{edge_id}, externalCallEdge{edge_id}Spec,\n"
            f"    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,\n"
            f"    externalCallEdge{edge_id}ProductRefinementChecked⟩\n"
            "  all_goals decide"
        )
    return (
        f"theorem acceptanceExecutionEdge{edge_id}Refined :\n"
        "    RelationalProductExecutionEdgeRefined staticProofContext\n"
        "      relationalProductGraph allRegions productInvariantTable "
        f"{edge_id} := by\n"
        "  apply Or.inl\n"
        "  unfold RelationalInternalExecutionEdgeRefined\n"
        f"  rw [productEdge{edge_id}Resolved]\n"
        "  simp only\n"
        f"  have edgeSourceNode : relationalProductGraph.edges[{edge_id}].sourceNodeId =\n"
        f"      {node_id} := by decide\n"
        f"  have edgeTargetNode : relationalProductGraph.edges[{edge_id}].targetNodeId =\n"
        f"      {target_node_id} := by decide\n"
        f"  have edgeSourceTarget : relationalProductGraph.edges[{edge_id}].sourceTargetId =\n"
        f"      {target_id} := by decide\n"
        f"  have edgeTargetTarget : relationalProductGraph.edges[{edge_id}].targetTargetId =\n"
        f"      {target_target_id} := by decide\n"
        "  rw [edgeSourceNode, edgeTargetNode, edgeSourceTarget, edgeTargetTarget,\n"
        f"    {', '.join(node_resolution_theorems)}]\n"
        f"  have regionFound : regionById allRegions {target_id} = "
        f"some region{region_index} := by decide\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  have targetInvariant : productInvariantTable.nodeInvariants[{target_node_id}]? =\n"
        f"      some region{target_region_index}.inputInvariant := by decide\n"
        f"  rw [regionFound, {', '.join(invariant_rewrites)}]\n"
        f"  refine ⟨segmentRefinementEdge{edge_id}Spec, ?_, ?_, ?_, ?_, ?_, ?_,\n"
        f"    productEdge{edge_id}Refined⟩\n"
        "  all_goals decide"
    )

def _write_relational_acceptance_modules(
    lean_dir: Path,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    product_graph: dict[str, Any],
    register_relations: dict[str, Any],
    segment_candidates: list[dict[str, Any]],
    decode_chunk_regions: list[list[int]],
    external_site_candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    stage_a = lean_dir / "StageA"
    for path in [
        *stage_a.glob("RelationalAcceptance*.lean"),
        *stage_a.glob("RelationalAcceptance*.olean"),
    ]:
        path.unlink()
    plan = _whole_program_acceptance_plan(
        contract, behaviors, product_graph, register_relations, segment_candidates,
        external_site_candidates,
    )
    write_json(lean_dir.parent / "whole-program-acceptance.json", plan)
    if plan["status"] != "ready":
        return plan

    nodes = product_graph["nodes"]
    root_node_id = int(plan["root_node_id"])
    terminal_region_index = int(plan["terminal_region_index"])
    terminal_invariant = _lean_state_invariant(plan["terminal_invariant"])
    parameterized_environment = any(
        step["kind"] == "external_call" for step in plan["node_steps"]
    )
    invariant_rows = ", ".join(
        f"region{node_id}.inputInvariant" for node_id in range(len(nodes))
    )
    control_rows = ", ".join(
        "{ nodeId := " + str(int(state["node_id"]))
        + ", calls := [" + ", ".join(str(int(item)) for item in state["calls"])
        + "], frameOffsets := ["
        + ", ".join(
            _lean_return_slot_offset_pair(offsets)
            for offsets in state["frame_offsets"]
        )
        + "] }"
        for state in plan["control_states"]
    )
    world_program_source = (
        "def originalWorldProgram (environment : WorldExternalEnvironment) : "
        "DecodedWorldProgram := {\n"
        "  candidate := false\n  context := staticProofContext\n"
        "  regions := allRegions\n  externalCallSites\n"
        "  environment\n}\n\n"
        "def candidateWorldProgram (environment : WorldExternalEnvironment) : "
        "DecodedWorldProgram := {\n"
        "  candidate := true\n  context := staticProofContext\n"
        "  regions := allRegions\n  externalCallSites\n"
        "  environment\n}\n\n"
        if parameterized_environment else
        "def inertWorldEnvironment : WorldExternalEnvironment := {\n"
        "  result := fun _ event => { state := event.state, world := event.world }\n"
        "}\n\n"
        "def originalWorldProgram : DecodedWorldProgram := {\n"
        "  candidate := false\n  context := staticProofContext\n"
        "  regions := allRegions\n  externalCallSites\n"
        "  environment := inertWorldEnvironment\n}\n\n"
        "def candidateWorldProgram : DecodedWorldProgram := {\n"
        "  candidate := true\n  context := staticProofContext\n"
        "  regions := allRegions\n  externalCallSites\n"
        "  environment := inertWorldEnvironment\n}\n\n"
    )
    context_source = (
        "import StageA.RelationalBundle\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        f"def terminalInvariant : StateInvariant := {terminal_invariant}\n\n"
        "def productInvariantTable : ProductInvariantTable := {\n"
        f"  nodeInvariants := #[{invariant_rows}]\n"
        "  terminalInvariant\n"
        "}\n\n"
        "def productControlProfile : ProductControlProfile := {\n"
        f"  states := [{control_rows}]\n"
        "}\n\n"
        "def consoleLaunch : PE32ConsoleLaunchV1 := {\n"
        f"  rootNodeId := {root_node_id}\n"
        f"  rootTargetId := {int(nodes[root_node_id]['target_id'])}\n"
        f"  rootInvariant := region{root_node_id}.inputInvariant\n"
        "}\n\n"
        + world_program_source
        + "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalAcceptanceContext.lean", context_source
    )

    decode_chunk_by_region = {
        region_index: chunk_index
        for chunk_index, region_indices in enumerate(decode_chunk_regions)
        for region_index in region_indices
    }
    chunk_size = max(
        1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_ACCEPTANCE_CHUNK", "8"))
    )
    chunks: list[dict[str, str]] = []
    steps = plan["node_steps"]
    for chunk_index, offset in enumerate(range(0, len(steps), chunk_size)):
        selected = steps[offset : offset + chunk_size]
        module = f"RelationalAcceptanceChunk{chunk_index}"
        ids_name = f"acceptanceNodeChunk{chunk_index}Ids"
        edge_ids_name = f"acceptanceEdgeChunk{chunk_index}Ids"
        definitions: list[str] = []
        region_theorems: list[str] = []
        running_theorems: list[str] = []
        edge_theorems: list[str] = []
        for step in selected:
            node_id = int(step["node_id"])
            region_index = int(step["region_index"])
            target_id = int(step["target_id"])
            decode_chunk = decode_chunk_by_region[region_index]
            region_match = f"acceptanceRegionNode{node_id}Matches"
            running = f"acceptanceRunningNode{node_id}Refined"
            region_theorems.append(region_match)
            running_theorems.append(
                f"{running} originalEnvironment candidateEnvironment environmentRefines"
                if parameterized_environment else running
            )
            edge_theorems.extend(
                f"acceptanceExecutionEdge{int(edge['edge_id'])}Refined"
                for edge in step["edges"]
            )
            definitions.append(
                f"theorem {region_match} :\n"
                "    RegionMatchesProductNode staticProofContext relationalProductGraph "
                f"allRegions {node_id} := by\n"
                "  unfold RegionMatchesProductNode\n"
                f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
                f"    some relationalProductGraph.nodes[{node_id}] by decide)]\n"
                "  simp only\n"
                f"  have nodeTarget : relationalProductGraph.nodes[{node_id}].targetId = "
                f"{target_id} := by decide\n"
                "  have codeFound : staticProofContext.codeMap.get? "
                f"{target_id} = some staticProofContext.codeMap.entries[{target_id}] := by decide\n"
                f"  have regionFound : regionById allRegions {target_id} = "
                f"some region{region_index} := by decide\n"
                "  rw [nodeTarget, codeFound, regionFound]\n"
                "  exact ⟨by decide, by decide, by decide, by decide⟩"
            )
            for side in ("original", "candidate"):
                side_title = side.capitalize()
                side_bool = "false" if side == "original" else "true"
                normalized_name = (
                    f"acceptance{side_title}NormalizedBehavior{node_id}"
                )
                normalized_outcome = (
                    f"acceptance{side_title}NormalizedOutcome{node_id}"
                )
                normalized_writes = (
                    f"acceptance{side_title}NormalizedWrites{node_id}"
                )
                normalized_registers = (
                    f"acceptance{side_title}NormalizedRegisters{node_id}"
                )
                normalized_checked = (
                    f"acceptance{side_title}Normalization{node_id}Checked"
                )
                environment_name = f"{side}Environment"
                world_program = (
                    f"({side}WorldProgram {environment_name})"
                    if parameterized_environment else f"{side}WorldProgram"
                )
                world_behavior_binder = (
                    f" ({environment_name} : WorldExternalEnvironment)"
                    if parameterized_environment else ""
                )
                definitions.append(
                    f"def {normalized_name} : NormalizedSymbolicBehavior :=\n"
                    f"  (normalizeSymbolicBehavior {side_bool} region{region_index}.targets "
                    f"{side}Behavior{region_index}).get (by decide)\n\n"
                    f"theorem {normalized_checked} : normalizeSymbolicBehavior {side_bool}\n"
                    f"    region{region_index}.targets {side}Behavior{region_index} =\n"
                    f"      some {normalized_name} := by decide\n\n"
                    f"theorem {normalized_writes} : {normalized_name}.writes =\n"
                    f"    {side}Behavior{region_index}.writes := by decide\n\n"
                    f"theorem {normalized_registers} : {normalized_name}.registers =\n"
                    f"    {side}Behavior{region_index}.registers := by decide\n\n"
                    f"theorem {normalized_outcome} : {normalized_name}.outcome =\n"
                    f"    {_lean_acceptance_outcome(behaviors[region_index][side + '_ir']['outcome'])} "
                    ":= by decide"
                )
                definitions.append(
                    f"theorem {side}WorldBehaviorNode{node_id}{world_behavior_binder} "
                    "(state : MachineState) :\n"
                    f"    decodedWorldRegionBehavior {world_program} {target_id} state =\n"
                    f"      some ({normalized_name}.eval state) := by\n"
                    f"  have regionFound : regionById allRegions {target_id} = "
                    f"some region{region_index} := by decide\n"
                    f"  unfold decodedWorldRegionBehavior {side}WorldProgram\n"
                    "  rw [regionFound]\n"
                    f"  change (regionBehaviorWithMachineCallContracts {side}Pe "
                    f"{side}Imports machineImportCallContracts region{region_index}.{side}).bind\n"
                    f"      (evalBehavior {side_bool} region{region_index}.targets state) = _\n"
                    f"  have decoded : regionBehaviorWithMachineCallContracts {side}Pe "
                    f"{side}Imports machineImportCallContracts region{region_index}.{side} =\n"
                    f"      some {side}Behavior{region_index} := by\n"
                    f"    simpa [{side}MachineImportCallContractsChunk{decode_chunk}] using\n"
                    f"      {side}Behavior{region_index}CheckedDecoded\n"
                    "  rw [decoded]\n"
                    f"  simp [evalBehavior, {normalized_checked}]"
                )
            definitions.append(_lean_acceptance_running_node(
                step, contract["regions"], behaviors,
                parameterized_environment=parameterized_environment,
            ))
            definitions.extend(
                _lean_acceptance_execution_edge(step=step, edge=edge)
                for edge in step["edges"]
            )
        node_ids = [int(step["node_id"]) for step in selected]
        edge_ids = [
            int(edge["edge_id"])
            for step in selected
            for edge in step["edges"]
        ]
        definitions.extend([
            f"def {ids_name} : List Nat := [{', '.join(map(str, node_ids))}]",
            f"def {edge_ids_name} : List Nat := [{', '.join(map(str, edge_ids))}]",
            (
                f"theorem acceptanceRegionChunk{chunk_index}Checked :\n"
                "    AllListedRegionsMatchProductGraph staticProofContext\n"
                f"      relationalProductGraph allRegions {ids_name} := by\n"
                f"  exact {_lean_all_listed_proof(region_theorems)}"
            ),
            (
                f"theorem acceptanceRunningChunk{chunk_index}Checked"
                + (
                    " (originalEnvironment candidateEnvironment : "
                    "WorldExternalEnvironment)\n"
                    "    (environmentRefines : ExternalEnvironmentRefines "
                    "staticProofContext externalCallSites\n"
                    "      originalEnvironment candidateEnvironment)"
                    if parameterized_environment else ""
                )
                + " :\n"
                "    AllListedRunningProductNodesRefined staticProofContext\n"
                "      relationalProductGraph productInvariantTable\n"
                "      relationalProductReachabilityEvidence productControlProfile\n"
                + (
                    "      (originalWorldProgram originalEnvironment)\n"
                    "      (candidateWorldProgram candidateEnvironment) "
                    if parameterized_environment else
                    "      originalWorldProgram\n"
                    "      candidateWorldProgram "
                )
                + f"{ids_name} := by\n"
                f"  exact {_lean_all_listed_proof(running_theorems)}"
            ),
            (
                f"theorem acceptanceExecutionEdgeChunk{chunk_index}Checked :\n"
                "    AllListedProductExecutionEdgesRefined staticProofContext\n"
                "      relationalProductGraph allRegions productInvariantTable\n"
                f"      {edge_ids_name} := by\n"
                f"  exact {_lean_all_listed_proof(edge_theorems)}"
            ),
        ])
        source = (
            "import StageA.RelationalAcceptanceContext\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(stage_a / f"{module}.lean", source)
        chunks.append({
            "module": module,
            "ids": ids_name,
            "edge_ids": edge_ids_name,
            "regions": f"acceptanceRegionChunk{chunk_index}Checked",
            "running": (
                f"acceptanceRunningChunk{chunk_index}Checked originalEnvironment "
                "candidateEnvironment environmentRefines"
                if parameterized_environment else
                f"acceptanceRunningChunk{chunk_index}Checked"
            ),
            "edges": f"acceptanceExecutionEdgeChunk{chunk_index}Checked",
        })

    node_ids_expr = _lean_appended_list([chunk["ids"] for chunk in chunks])
    edge_ids_expr = _lean_appended_list([chunk["edge_ids"] for chunk in chunks])
    region_proof = _lean_appended_proof(
        chunks, "allListedRegionsMatchProductGraph_append",
        "staticProofContext relationalProductGraph allRegions", "regions",
    )
    acceptance_original_program = (
        "(originalWorldProgram originalEnvironment)"
        if parameterized_environment else "originalWorldProgram"
    )
    acceptance_candidate_program = (
        "(candidateWorldProgram candidateEnvironment)"
        if parameterized_environment else "candidateWorldProgram"
    )
    running_proof = _lean_appended_proof(
        chunks, "allListedRunningProductNodesRefined_append",
        "staticProofContext relationalProductGraph productInvariantTable "
        "relationalProductReachabilityEvidence productControlProfile "
        f"{acceptance_original_program} {acceptance_candidate_program}",
        "running",
    )
    edge_proof = _lean_appended_proof(
        [dict(chunk, ids=chunk["edge_ids"]) for chunk in chunks],
        "allListedProductExecutionEdgesRefined_append",
        "staticProofContext relationalProductGraph allRegions productInvariantTable",
        "edges",
    )
    root_target_id = int(nodes[root_node_id]["target_id"])
    if parameterized_environment:
        running_closure_source = (
            "theorem allAcceptanceRunningNodesListed\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    AllListedRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      (originalWorldProgram originalEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment) allAcceptanceNodeIds := by\n"
            f"  simpa [allAcceptanceNodeIds] using ({running_proof})\n\n"
            "theorem allAcceptanceRunningNodesRefined\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    ReachableRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      (originalWorldProgram originalEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment) := by\n"
            "  apply reachableRunningProductNodesRefined_of_complete_evidence\n"
            "    staticProofContext relationalProductGraph productInvariantTable\n"
            "    relationalProductReachabilityEvidence productControlProfile\n"
            "    (originalWorldProgram originalEnvironment)\n"
            "    (candidateWorldProgram candidateEnvironment)\n"
            "    relationalProductLocalEvidence\n"
            "    relationalProductLocalEvidenceCompleteChecked\n"
            "  have ids : allAcceptanceNodeIds =\n"
            "      relationalProductLocalEvidence.decodedNodeIds := by decide\n"
            "  rw [← ids]\n"
            "  exact allAcceptanceRunningNodesListed originalEnvironment\n"
            "    candidateEnvironment environmentRefines\n\n"
        )
        acceptance_certificate_source = (
            "def wholeProgramCertificate\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    WholeProgramCertificate staticProofContext relationalProductGraph\n"
            "      allRegions productInvariantTable relationalProductReachabilityEvidence\n"
            "      productControlProfile externalCallSites consoleLaunch\n"
            "      originalEnvironment candidateEnvironment := {\n"
            "  staticContextValid := staticProofContextChecked\n"
            "  productGraphValid := relationalProductGraphIndexedValidChecked\n"
            "  regionsUseCanonicalContext := allRegionsUseStaticContextChecked\n"
            "  regionsMatchProductGraph := allRegionsMatchProductGraph\n"
            "  invariantTableValid := productInvariantTableValid\n"
            "  reachabilityClosed := generatedDeclaredGraphReachabilityCertificateChecked\n"
            "  decodedControlComplete := reachableProductLocalCertificate.reachableControlComplete\n"
            "  reachableEdgesRefined := reachableProductLocalCertificate.reachableEdgesRefined\n"
            "  reachableExecutionEdgesRefined := allAcceptanceExecutionEdgesRefined\n"
            "  environmentsRefined := environmentRefines\n"
            "  launchValid := consoleLaunchValid\n"
            "  launchControlAllowed := by decide\n"
            "  runningProductNodesRefined := allAcceptanceRunningNodesRefined\n"
            "    originalEnvironment candidateEnvironment environmentRefines\n"
            "}\n\n"
            "theorem candidatePE32ProgramsEquivalent\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    PE32ProgramsObservationallyEquivalent staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile consoleLaunch\n"
            "      (originalWorldProgram originalEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment) := by\n"
            "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "    pe32ProgramsEquivalent staticProofContext relationalProductGraph allRegions\n"
            "      productInvariantTable relationalProductReachabilityEvidence productControlProfile\n"
            "      externalCallSites consoleLaunch originalEnvironment candidateEnvironment\n"
            "      (wholeProgramCertificate originalEnvironment candidateEnvironment\n"
            "        environmentRefines)\n\n"
            "#print axioms candidatePE32ProgramsEquivalent\n\n"
        )
    else:
        running_closure_source = (
            "theorem allAcceptanceRunningNodesListed :\n"
            "    AllListedRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      originalWorldProgram\n"
            "      candidateWorldProgram allAcceptanceNodeIds := by\n"
            f"  simpa [allAcceptanceNodeIds] using ({running_proof})\n\n"
            "theorem allAcceptanceRunningNodesRefined :\n"
            "    ReachableRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      originalWorldProgram\n"
            "      candidateWorldProgram := by\n"
            "  apply reachableRunningProductNodesRefined_of_complete_evidence\n"
            "    staticProofContext relationalProductGraph productInvariantTable\n"
            "    relationalProductReachabilityEvidence productControlProfile\n"
            "    originalWorldProgram\n"
            "    candidateWorldProgram relationalProductLocalEvidence\n"
            "    relationalProductLocalEvidenceCompleteChecked\n"
            "  have ids : allAcceptanceNodeIds =\n"
            "      relationalProductLocalEvidence.decodedNodeIds := by decide\n"
            "  rw [← ids]\n"
            "  exact allAcceptanceRunningNodesListed\n\n"
        )
        acceptance_certificate_source = (
            "theorem inertEnvironmentRefines :\n"
            "    ExternalEnvironmentRefines staticProofContext externalCallSites\n"
            "      inertWorldEnvironment inertWorldEnvironment := by\n"
            "  unfold ExternalEnvironmentRefines\n"
            "  refine ⟨by decide, by decide, ?_⟩\n"
            "  intro site member\n  simp [externalCallSites] at member\n\n"
            "def wholeProgramCertificate : WholeProgramCertificate staticProofContext\n"
            "    relationalProductGraph allRegions productInvariantTable\n"
            "    relationalProductReachabilityEvidence productControlProfile\n"
            "    externalCallSites consoleLaunch\n"
            "    inertWorldEnvironment inertWorldEnvironment := {\n"
            "  staticContextValid := staticProofContextChecked\n"
            "  productGraphValid := relationalProductGraphIndexedValidChecked\n"
            "  regionsUseCanonicalContext := allRegionsUseStaticContextChecked\n"
            "  regionsMatchProductGraph := allRegionsMatchProductGraph\n"
            "  invariantTableValid := productInvariantTableValid\n"
            "  reachabilityClosed := generatedDeclaredGraphReachabilityCertificateChecked\n"
            "  decodedControlComplete := reachableProductLocalCertificate.reachableControlComplete\n"
            "  reachableEdgesRefined := reachableProductLocalCertificate.reachableEdgesRefined\n"
            "  reachableExecutionEdgesRefined := allAcceptanceExecutionEdgesRefined\n"
            "  environmentsRefined := inertEnvironmentRefines\n"
            "  launchValid := consoleLaunchValid\n"
            "  launchControlAllowed := by decide\n"
            "  runningProductNodesRefined := by\n"
            "    simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "      allAcceptanceRunningNodesRefined\n"
            "}\n\n"
            "theorem candidatePE32ProgramsEquivalent :\n"
            "    PE32ProgramsObservationallyEquivalent staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile consoleLaunch\n"
            "      originalWorldProgram candidateWorldProgram := by\n"
            "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "    pe32ProgramsEquivalent staticProofContext relationalProductGraph allRegions\n"
            "      productInvariantTable relationalProductReachabilityEvidence productControlProfile\n"
            "      externalCallSites\n"
            "      consoleLaunch inertWorldEnvironment inertWorldEnvironment\n"
            "      wholeProgramCertificate\n\n"
            "#print axioms candidatePE32ProgramsEquivalent\n\n"
        )
    final_source = (
        "".join(f"import StageA.{chunk['module']}\n" for chunk in chunks)
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        f"def allAcceptanceNodeIds : List Nat := {node_ids_expr}\n\n"
        f"def allAcceptanceEdgeIds : List Nat := {edge_ids_expr}\n\n"
        "theorem allAcceptanceRegionsListed :\n"
        "    AllListedRegionsMatchProductGraph staticProofContext relationalProductGraph\n"
        "      allRegions allAcceptanceNodeIds := by\n"
        f"  simpa [allAcceptanceNodeIds] using ({region_proof})\n\n"
        "theorem allAcceptanceNodeIdsComplete :\n"
        "    allAcceptanceNodeIds = List.range relationalProductGraph.nodes.size := by\n"
        "  decide\n\n"
        "theorem allRegionsMatchProductGraph :\n"
        "    RegionsMatchProductGraph staticProofContext relationalProductGraph allRegions := by\n"
        "  apply regionsMatchProductGraph_of_listed_range\n"
        "  rw [← allAcceptanceNodeIdsComplete]\n"
        "  exact allAcceptanceRegionsListed\n\n"
        + running_closure_source
        + "theorem allAcceptanceExecutionEdgesListed :\n"
        "    AllListedProductExecutionEdgesRefined staticProofContext\n"
        "      relationalProductGraph allRegions productInvariantTable\n"
        "      allAcceptanceEdgeIds := by\n"
        f"  simpa [allAcceptanceEdgeIds] using ({edge_proof})\n\n"
        "theorem allAcceptanceExecutionEdgesRefined :\n"
        "    ReachableProductExecutionEdgesRefined staticProofContext\n"
        "      relationalProductGraph allRegions productInvariantTable\n"
        "      relationalProductReachabilityEvidence := by\n"
        "  apply reachableProductExecutionEdgesRefined_of_complete_evidence\n"
        "    staticProofContext relationalProductGraph allRegions productInvariantTable\n"
        "    relationalProductReachabilityEvidence relationalProductLocalEvidence\n"
        "    relationalProductLocalEvidenceCompleteChecked\n"
        "  have ids : allAcceptanceEdgeIds =\n"
        "      relationalProductLocalEvidence.refinedEdgeIds := by decide\n"
        "  rw [← ids]\n"
        "  exact allAcceptanceExecutionEdgesListed\n\n"
        "theorem productInvariantTableValid :\n"
        "    productInvariantTable.Valid relationalProductGraph := by\n"
        "  unfold ProductInvariantTable.Valid\n  decide\n\n"
        "theorem consoleLaunchValid :\n"
        "    consoleLaunch.Valid relationalProductGraph productInvariantTable := by\n"
        f"  refine ⟨relationalProductGraph.nodes[{root_node_id}],\n"
        "    (by decide), ?_, ?_, ?_, ?_⟩\n"
        "  all_goals decide\n\n"
        + acceptance_certificate_source
        + "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(stage_a / "RelationalAcceptance.lean", final_source)
    return plan
