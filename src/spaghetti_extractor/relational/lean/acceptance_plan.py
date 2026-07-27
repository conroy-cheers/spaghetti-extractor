from __future__ import annotations

import json
import os
from collections import deque
from functools import lru_cache
from typing import Any, Mapping

from ...stage_binary import StageAInputError
from ...util import sha256_bytes
from ..analyses.external import (
    _machine_import_call_contract_identity,
    _register_offset_witness,
    _semantic_external_target_identity,
)
from ..analyses.callbacks import (
    attach_protocol_callback_states,
    protocol_callback_controls_by_node,
)
from ..analyses.frames import (
    RuntimeFrameAliasViability,
    return_frame_claim_for_location,
    runtime_frame_alias_viability,
    runtime_frame_location_key as location_key,
    runtime_frame_location_payload as location_payload,
)
from ..analyses.segments import (
    _import_register_transfer_claims,
    _paired_exact_guard_claim,
    _paired_prepared_word_writes_claim,
    _preserved_input_flags_claim,
    _stack_word_address_adjustment,
    _stack_word_adjustment_covered,
)
from ..analyses.stack import _stack_window_transfer_claims
from ..analyses.semantic_control import _normalized_branch_guard
from ..analyses.registers import _propose_internal_callsite_preservation_summaries
from ..analyses.register_lattice import _register_relation_implies_exact
from ..analyses.linked_control import (
    linked_control_expansion_key,
    linked_control_state_key,
    project_linked_control_profile,
)
from ..analyses.affine_linked_control import affine_linked_control_payload
from ..model import (
    _semantic_constant_bool,
    _target_shaped_register_output_claims_with_stack_windows,
)
from ..schema import RELATIONAL_FINAL_ACCEPTANCE_THEOREM

def _frame_exact_expr_witness(
    inventory: dict[str, Any], original: Any, candidate: Any,
) -> dict[str, Any] | None:
    if not isinstance(original, dict) or not isinstance(candidate, dict):
        return None
    operation = original.get("op")
    if operation != candidate.get("op"):
        return None
    if operation == "constant":
        if int(original.get("value", -1)) != int(candidate.get("value", -2)):
            return None
        return {"kind": "constant", "value": int(original["value"])}
    if operation == "read32":
        matches: list[dict[str, Any]] = []
        for location in inventory.get("locations", []):
            original_result = _register_offset_witness(
                original.get("address"),
                str(location.get("original_register", "esp")),
            )
            candidate_result = _register_offset_witness(
                candidate.get("address"),
                str(location.get("candidate_register", "esp")),
            )
            if original_result is None or candidate_result is None:
                continue
            original_address, original_offset = original_result
            candidate_address, candidate_offset = candidate_result
            for word in inventory.get("exact_words", []):
                if (
                    original_offset
                        == (int(location["original"]) + int(word["original"]))
                            % 2**32
                    and candidate_offset
                        == (int(location["candidate"]) + int(word["candidate"]))
                            % 2**32
                ):
                    matches.append({
                        "kind": "exact_word_read32",
                        "location": location,
                        "word": word,
                        "original_address": original_address,
                        "candidate_address": candidate_address,
                    })
        return matches[0] if len(matches) == 1 else None
    if operation in {
        "add", "sub", "bit_and", "bit_xor", "shift_left_by",
        "shift_right_by", "shift_arithmetic_right_by", "bit_or",
        "unsigned_less_value", "multiply", "multiply_high_unsigned",
        "multiply_high_signed",
    }:
        left = _frame_exact_expr_witness(
            inventory, original.get("left"), candidate.get("left")
        )
        right = _frame_exact_expr_witness(
            inventory, original.get("right"), candidate.get("right")
        )
        if left is None or right is None:
            return None
        return {
            "kind": "binary", "operation": operation,
            "left": left, "right": right,
        }
    return None

def _frame_exact_stack_word_writes_claim(
    source: dict[str, Any], behavior_pair: dict[str, Any],
    inventory: dict[str, Any],
) -> dict[str, Any] | None:
    original_writes = (behavior_pair.get("original_ir") or {}).get("writes") or []
    candidate_writes = (behavior_pair.get("candidate_ir") or {}).get("writes") or []
    if not original_writes or len(original_writes) != len(candidate_writes):
        return None
    items: list[dict[str, Any]] = []
    for original_write, candidate_write in zip(
        original_writes, candidate_writes, strict=True
    ):
        value_witness = _frame_exact_expr_witness(
            inventory,
            original_write.get("value"), candidate_write.get("value"),
        )
        if value_witness is None:
            return None
        location_matches = []
        for window in source.get("stack_windows", []):
            original_adjustment = _stack_word_address_adjustment(
                original_write.get("address"), str(window.get("original_register"))
            )
            candidate_adjustment = _stack_word_address_adjustment(
                candidate_write.get("address"), str(window.get("candidate_register"))
            )
            if (
                original_adjustment is not None
                and original_adjustment == candidate_adjustment
                and _stack_word_adjustment_covered(
                    window, original_adjustment["adjustment"]
                )
            ):
                location_matches.append((window, original_adjustment))
        if len(location_matches) != 1:
            return None
        window, adjustment = location_matches[0]
        items.append({
            "window": window,
            "amount": int(adjustment["amount"]),
            "value": {
                "original": original_write["value"],
                "candidate": candidate_write["value"],
                "witness": value_witness,
            },
        })
    return {"profile": "frame_exact_stack_word_writes_v1", "writes": items}

def _witnessed_linked_call_target_control_state(
    *,
    target_node_id: int,
    continuation: int,
    source_control_state: dict[str, Any],
    seeded_frame_inventory: dict[str, Any],
    transformed_outer_frame_inventories: list[dict[str, Any]],
    expansion_witness_keys: set[str],
) -> dict[str, Any] | None:
    """Construct a call successor while keeping dormant tails parametric."""
    target = {
        "node_id": target_node_id,
        "calls": [continuation, *source_control_state["calls"]],
        "frame_offsets": [
            seeded_frame_inventory,
            *transformed_outer_frame_inventories,
        ],
    }
    if linked_control_expansion_key(target) not in expansion_witness_keys:
        return None
    return target

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

def _retain_checked_linked_control_links(
    linked_control: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Retain links satisfying Lean's depth-one resume-state clause."""
    states = list(linked_control.get("states", []))
    retained_links: list[dict[str, Any]] = []
    rejected_links: list[dict[str, Any]] = []
    for link in linked_control.get("links", []):
        matching_states = [
            state for state in states
            if state.get("node_id") == link.get("resume_node_id")
            and state.get("continuation_target_id")
                == link.get("resume_continuation")
            and state.get("active_frame") == link.get("resume_inventory")
        ]
        if any(
            type(state.get("minimum_depth")) is int
            and int(state["minimum_depth"]) == 1
            for state in matching_states
        ):
            retained_links.append(dict(link))
            continue
        rejected_links.append({
            "reason": "resume_state_depth_one_witness_missing",
            "call_source_target_id": link.get("call_source_target_id"),
            "resume_node_id": link.get("resume_node_id"),
            "resume_target_id": link.get("resume_target_id"),
            "resume_continuation": link.get("resume_continuation"),
            "candidate_minimum_depths": sorted({
                int(state["minimum_depth"])
                for state in matching_states
                if type(state.get("minimum_depth")) is int
            }),
        })

    gaps = [
        *linked_control.get("link_gaps", []),
        *rejected_links,
    ]
    counts = dict(linked_control.get("counts", {}))
    counts["link_candidates"] = len(retained_links)
    counts["link_gaps"] = len(gaps)
    counts["rejected_link_candidates"] = len(rejected_links)
    return (
        {
            **linked_control,
            "links": retained_links,
            "link_gaps": gaps,
            "counts": counts,
        },
        rejected_links,
    )

def _checked_infeasible_branch_edge(edge: Mapping[str, Any]) -> bool:
    """Require both decoded guards to prove an infeasible edge impossible."""
    return (
        edge.get("infeasible") is True
        and _semantic_constant_bool(edge.get("original_guard") or {}) is False
        and _semantic_constant_bool(edge.get("candidate_guard") or {}) is False
    )

def _frame_relations_requiring_internal_preservation(
    frame_relations: tuple[tuple[str, ...], ...], frame_operation: str,
) -> tuple[tuple[str, ...], ...]:
    """Return only register facts that are live across this machine step.

    Register-relative facts belong to the active frame.  Dormant frame
    inventories are continuation metadata and are re-established from the
    continuation invariant after return.
    """
    if frame_operation == "return_pop":
        return ()
    return frame_relations[:1]

def _paired_frame_expression_witness(
    original_expression: Any,
    candidate_expression: Any,
    relations: tuple[dict[str, Any], ...],
) -> dict[str, Any] | None:
    """Build a Lean-replayable equality witness for paired pure expressions."""
    exact_pairs = {
        (str(relation["original"]), str(relation["candidate"]))
        for relation in relations
        if _register_relation_implies_exact(relation.get("relation"))
    }

    def build(original: Any, candidate: Any) -> dict[str, Any] | None:
        if not isinstance(original, dict) or not isinstance(candidate, dict):
            return None
        operation = original.get("op")
        if operation != candidate.get("op"):
            return None
        if operation == "input_reg":
            pair = (str(original.get("reg")), str(candidate.get("reg")))
            if pair not in exact_pairs:
                return None
            return {
                "kind": "input_reg",
                "original": pair[0],
                "candidate": pair[1],
            }
        if operation == "constant":
            original_value = int(original.get("value", -1))
            candidate_value = int(candidate.get("value", -1))
            if original_value != candidate_value:
                return None
            return {"kind": "constant", "value": original_value}
        if operation in {
            "add", "sub", "bit_and", "bit_xor", "shift_left_by",
            "shift_right_by", "shift_arithmetic_right_by", "bit_or",
            "unsigned_less_value", "multiply", "multiply_high_unsigned",
            "multiply_high_signed",
        }:
            left = build(original.get("left"), candidate.get("left"))
            right = build(original.get("right"), candidate.get("right"))
            if left is None or right is None:
                return None
            return {
                "kind": "binary",
                "operation": operation,
                "left": left,
                "right": right,
            }
        if operation in {"bit_not", "lowest_set_bit", "highest_set_bit"}:
            value = build(original.get("value"), candidate.get("value"))
            if value is None:
                return None
            return {"kind": "unary", "operation": operation, "value": value}
        if operation in {
            "extract_byte", "shift_left", "shift_right", "bit_value",
        }:
            metadata = (
                "index" if operation in {"extract_byte", "bit_value"}
                else "amount"
            )
            original_index = int(original.get(metadata, -1))
            candidate_index = int(candidate.get(metadata, -1))
            if original_index != candidate_index:
                return None
            value = build(original.get("value"), candidate.get("value"))
            if value is None:
                return None
            return {
                "kind": "indexed",
                "operation": operation,
                "index": original_index,
                "value": value,
            }
        if operation == "if_equal":
            children = {
                field: build(original.get(field), candidate.get(field))
                for field in ("left", "right", "then", "else")
            }
            if any(value is None for value in children.values()):
                return None
            return {"kind": "if_equal", **children}
        if operation in {
            "divide_quotient", "divide_remainder", "division_valid_value",
        }:
            children = {
                field: build(original.get(field), candidate.get(field))
                for field in ("high", "low", "divisor")
            }
            if any(value is None for value in children.values()):
                return None
            return {"kind": "ternary", "operation": operation, **children}
        return None

    return build(original_expression, candidate_expression)

def _whole_program_acceptance_plan(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    product_graph: dict[str, Any],
    register_relations: dict[str, Any],
    segment_candidates: list[dict[str, Any]],
    external_site_candidates: list[dict[str, Any]],
    launch_profile: dict[str, Any] | None = None,
    *,
    runtime_frame_affine: Mapping[str, Any] | None = None,
    physical_state_only_region_indices: set[int] | frozenset[int] = frozenset(),
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
    external_by_edge = {
        int(candidate["edge_index"]): candidate
        for candidate in external_site_candidates
        if "edge_index" in candidate
    }
    external_thunk_by_source_continuation = {
        (int(candidate["source_region_index"]),
         int(candidate["continuation_target_id"])): candidate
        for candidate in external_site_candidates
        if candidate.get("site_kind") == "direct_import_thunk"
    }
    machine_contract_by_id = {
        int(item["id"]): item
        for item in contract.get("machine_import_call_contracts", [])
    }
    candidate_by_edge = {
        int(candidate["edge_index"]): candidate
        for candidate in segment_candidates
    }
    candidates_by_source_target: dict[
        tuple[int, int], list[dict[str, Any]]
    ] = {}
    for candidate in segment_candidates:
        candidates_by_source_target.setdefault((
            int(candidate["source_region_index"]),
            int(candidate["target_region_index"]),
        ), []).append(candidate)
    machine_contract_by_import: dict[
        tuple[str, str, str | int], dict[str, Any]
    ] = {}
    ambiguous_machine_contract_imports: set[
        tuple[str, str, str | int]
    ] = set()
    for item in contract.get("machine_import_call_contracts", []):
        identity = _machine_import_call_contract_identity(item)
        if identity is None or identity in ambiguous_machine_contract_imports:
            continue
        if identity in machine_contract_by_import:
            machine_contract_by_import.pop(identity, None)
            ambiguous_machine_contract_imports.add(identity)
            continue
        machine_contract_by_import[identity] = item

    def checked_register_external_site(
        node_id: int, continuation_target_id: int,
    ) -> dict[str, Any] | None:
        decoded = decoded_control_by_node.get(node_id, {})
        if decoded.get("profile") not in {
            "inductive_iat_register_call_v1",
            "seeded_iat_register_call_v1",
        }:
            return None
        decoded_identity = _semantic_external_target_identity(
            decoded.get("import") or {}
        )
        matches: list[dict[str, Any]] = []
        for edge_id in nodes[node_id].get("outgoing_edge_ids", []):
            edge = edges[int(edge_id)]
            site = external_by_edge.get(int(edge_id))
            if (
                edge.get("kind") != "externalCall"
                or site is None
                or site.get("dispatch_profile") != "checked_import_register"
                or int(site.get("source_region_index", -1)) != node_id
                or int(site.get("continuation_target_id", -1))
                    != continuation_target_id
            ):
                continue
            dispatch = site.get("dispatch_registers") or {}
            if (
                dispatch.get("original") != decoded.get("original_register")
                or dispatch.get("candidate") != decoded.get("candidate_register")
            ):
                continue
            if (
                decoded.get("profile") == "seeded_iat_register_call_v1"
                and site.get("dispatch_seed") != decoded.get("seed")
            ):
                continue
            machine_contract = machine_contract_by_id.get(
                int(site.get("machine_contract_id", -1))
            )
            if (
                machine_contract is None
                or _semantic_external_target_identity(
                    machine_contract.get("import") or {}
                ) != decoded_identity
            ):
                continue
            matches.append(site)
        return matches[0] if len(matches) == 1 else None
    regions = contract["regions"]
    launch_profile = launch_profile or {}
    original_is_dll = bool(launch_profile.get("original_is_dll", False))
    candidate_is_dll = bool(launch_profile.get("candidate_is_dll", False))
    original_exports = launch_profile.get("original_exports", ())
    candidate_exports = launch_profile.get("candidate_exports", ())
    original_loader_diagnostics = launch_profile.get(
        "original_loader_diagnostics"
    )
    candidate_loader_diagnostics = launch_profile.get(
        "candidate_loader_diagnostics"
    )
    for side, loader_diagnostics in (
        ("original", original_loader_diagnostics),
        ("candidate", candidate_loader_diagnostics),
    ):
        if not isinstance(loader_diagnostics, dict):
            continue
        hard_diagnostics = [
            diagnostic
            for diagnostic in loader_diagnostics.get("diagnostics", [])
            if isinstance(diagnostic, dict)
            and diagnostic.get("severity") == "error"
        ]
        if hard_diagnostics:
            codes = ", ".join(
                str(diagnostic.get("code", "unknown"))
                for diagnostic in hard_diagnostics
            )
            block(
                "loader_image_invalid",
                f"{side} PE32 loader image failed diagnostic policy: {codes}",
                "repair the PE32 loader image and rerun the Lean loader check",
            )
    export_parse_errors = [
        str(error) for error in (
            launch_profile.get("original_export_parse_error"),
            launch_profile.get("candidate_export_parse_error"),
        ) if error
    ]
    if export_parse_errors:
        block(
            "console_launch_export_inventory_unparsed",
            "PE32 export inventory parsing failed: " + "; ".join(
                export_parse_errors
            ),
            "repair or explicitly reject the malformed export directory",
        )
    elif original_exports is None or candidate_exports is None:
        block(
            "console_launch_export_inventory_missing",
            "one or both PE32 export inventories are unavailable",
            "parse both export directories from the exact PE image bytes",
        )
    elif original_exports or candidate_exports:
        block(
            "console_launch_exports_unsupported",
            "the bounded console profile does not admit externally callable PE exports",
            "use an export-aware launch profile that roots executable exports and "
            "classifies data exports and forwarders",
        )
    if original_is_dll or candidate_is_dll:
        block(
            "console_launch_dll_unsupported",
            "the bounded console profile does not admit DLL loader entry events",
            "use a DLL launch profile covering DllMain, TLS events, exports, and "
            "supported loader reasons",
        )
    original_tls_directory = launch_profile.get("original_tls_directory") or {}
    candidate_tls_directory = launch_profile.get("candidate_tls_directory") or {}
    tls_directory_present = any(
        int(directory.get(field, 0)) != 0
        for directory in (original_tls_directory, candidate_tls_directory)
        for field in ("rva", "size")
    )
    tls_callback_target_ids: list[int] = []
    original_tls_callbacks = launch_profile.get("original_tls_callback_rvas")
    candidate_tls_callbacks = launch_profile.get("candidate_tls_callback_rvas")
    original_tls_array_immutable = launch_profile.get(
        "original_tls_callback_array_immutable"
    )
    candidate_tls_array_immutable = launch_profile.get(
        "candidate_tls_callback_array_immutable"
    )
    if not tls_directory_present:
        original_tls_callbacks = original_tls_callbacks or ()
        candidate_tls_callbacks = candidate_tls_callbacks or ()
    tls_parse_errors = [
        str(error) for error in (
            launch_profile.get("original_tls_callback_parse_error"),
            launch_profile.get("candidate_tls_callback_parse_error"),
        ) if error
    ]
    if tls_parse_errors:
        block(
            "pre_entry_tls_inventory_unparsed",
            "PE32 TLS callback inventory parsing failed: " + "; ".join(tls_parse_errors),
            "repair or explicitly reject the malformed TLS directory before proposing launch roots",
        )
    elif (
        original_tls_array_immutable is False
        or candidate_tls_array_immutable is False
    ):
        mutable_sides = ", ".join(
            side for side, immutable in (
                ("original", original_tls_array_immutable),
                ("candidate", candidate_tls_array_immutable),
            )
            if immutable is False
        )
        block(
            "pre_entry_tls_callback_array_mutable",
            f"TLS callback slots are loader-mutable on: {mutable_sides}",
            "place the TLS directory callback pointer, every callback slot, and the "
            "null terminator in non-writable image memory, or provide a launch model "
            "that rereads and resolves the runtime inventory",
        )
    elif original_tls_callbacks is None or candidate_tls_callbacks is None:
        block(
            "pre_entry_tls_inventory_missing",
            "one or both PE32 TLS callback inventories are unavailable",
            "parse both callback arrays from the exact PE image bytes",
        )
    elif len(original_tls_callbacks) != len(candidate_tls_callbacks):
        block(
            "pre_entry_tls_callback_count_mismatch",
            "original and candidate PE32 TLS callback arrays have different lengths",
            "restore a pointwise callback sequence or provide a stronger launch refinement profile",
        )
    elif tls_directory_present and not original_tls_callbacks:
        block(
            "pre_entry_tls_profile_unmet",
            "a present PE32 TLS directory has no callback cutpoints, but its loader state "
            "initialization is not covered by the callback-based launch profile",
            "use a launch profile that checks TLS template/index initialization or remove "
            "the unused TLS directory",
        )
    else:
        tls_mapping_complete = True
        for index, (original_rva, candidate_rva) in enumerate(zip(
            original_tls_callbacks, candidate_tls_callbacks, strict=True
        )):
            matches = [
                target for target in contract.get("code_targets", [])
                if int(original_rva) == int(target["original_rva"])
                and int(candidate_rva) == int(target["candidate_rva"])
            ]
            if len(matches) != 1:
                block(
                    "pre_entry_tls_callback_mapping_unresolved",
                    f"TLS callback {index} at original RVA {int(original_rva)} and "
                    f"candidate RVA {int(candidate_rva)} has {len(matches)} canonical mappings",
                    "add one unambiguous canonical code-target pair for this callback",
                )
                tls_mapping_complete = False
            else:
                tls_callback_target_ids.append(int(matches[0]["id"]))
        if not tls_mapping_complete:
            tls_callback_target_ids = []
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
    node_by_target = {
        int(node["target_id"]): node_id for node_id, node in enumerate(nodes)
    }
    entry_root_node_ids = [
        node_id for node_id, region in enumerate(regions)
        if bool(region.get("root"))
    ]
    if len(entry_root_node_ids) != 1:
        block(
            "console_launch_entry_root_ambiguous",
            f"pe32-console-launch-v2 requires one ordinary entry root, found "
            f"{len(entry_root_node_ids)}",
            "declare exactly one PE entrypoint region; keep TLS callbacks as launch roots",
        )
    entry_root_node_id = (
        entry_root_node_ids[0] if len(entry_root_node_ids) == 1 else None
    )
    entry_target_id = (
        int(nodes[entry_root_node_id]["target_id"])
        if entry_root_node_id is not None else None
    )
    tls_callback_node_ids: list[int] = []
    for callback_index, target_id in enumerate(tls_callback_target_ids):
        node_id = node_by_target.get(int(target_id))
        if node_id is None or node_id not in roots:
            block(
                "pre_entry_tls_callback_root_missing",
                f"TLS callback {callback_index} target {int(target_id)} is not a "
                "canonical product root",
                "map the callback to one canonical region and include it in graph roots",
            )
            tls_callback_node_ids = []
            break
        tls_callback_node_ids.append(node_id)
    launch_root_node_id = (
        tls_callback_node_ids[0]
        if tls_callback_target_ids and len(tls_callback_node_ids) == len(
            tls_callback_target_ids
        )
        else entry_root_node_id if not tls_callback_target_ids else None
    )
    launch_continuation_target_ids = (
        [*tls_callback_target_ids[1:], int(entry_target_id)]
        if tls_callback_target_ids and entry_target_id is not None
        else []
    )
    launch_frame_inventories = tuple(
        (("esp", callback_index * 16, "esp", callback_index * 16),)
        for callback_index in range(len(launch_continuation_target_ids))
    )
    launch_frame_exact_words = tuple(
        ((4, 4), (8, 8), (12, 12))
        for _ in launch_continuation_target_ids
    )
    protocol_callback_contract_by_node = protocol_callback_controls_by_node(
        contract, node_by_target, block
    )
    callsite_import_analysis = {
        "relations": [
            {
                "region_index": region_index,
                "original_register": relation["original"],
                "candidate_register": relation["candidate"],
                "import": relation["import"],
            }
            for region_index, region in enumerate(regions)
            for relation in region.get("input_import_relations", [])
        ],
    }
    callsite_preservation = _propose_internal_callsite_preservation_summaries(
        contract, behaviors, callsite_import_analysis, register_relations
    )
    callsite_rows_by_node: dict[int, list[dict[str, Any]]] = {}
    for row in callsite_preservation.get("summaries", []):
        try:
            callsite_rows_by_node.setdefault(
                int(row["callsite_region_index"]), []
            ).append(row)
        except (KeyError, TypeError, ValueError):
            block(
                "callsite_preservation_certificate_invalid",
                "the callsite-preservation proposal inventory contains an invalid row",
                "regenerate one canonical proposal row per internal callsite",
            )
    proposal_edges_by_node: dict[int, list[dict[str, Any]]] = {}
    for edge in callsite_preservation.get("proposal_edges", []):
        try:
            proposal_edges_by_node.setdefault(
                int(edge["source_region_index"]), []
            ).append(edge)
        except (KeyError, TypeError, ValueError):
            block(
                "callsite_preservation_certificate_invalid",
                "the callsite-preservation proposal edge inventory contains an invalid row",
                "regenerate canonical proposal edges from satisfied certificates",
            )
    control_states: list[dict[str, Any]] = []
    control_states_by_node: dict[int, list[dict[str, Any]]] = {}
    control_witness_states: list[dict[str, Any]] = []
    represented_linked_control_states: set[str] = set()
    expanded_linked_control_states: set[str] = set()
    if launch_root_node_id is not None and len(nodes) == len(behaviors):
        register_edges_by_pair: dict[tuple[int, int], list[dict[str, Any]]] = {}
        for edge in register_relations.get("edges", []):
            register_edges_by_pair.setdefault((
                int(edge["source_region_index"]),
                int(edge["target_region_index"]),
            ), []).append(edge)

        @lru_cache(maxsize=None)
        def location_rank(
            source: tuple[str, int, str, int],
            target: tuple[str, int, str, int],
            target_node_id: int,
        ) -> tuple[Any, ...]:
            return (
                0 if location_memory_transfer_ready(
                    target_node_id, target
                ) else 1,
                0 if location_outgoing_transfer_ready(
                    target_node_id, target
                ) else 1,
                0 if target[0] == source[0] and target[2] == source[2] else 1,
                0 if (
                    source[0] in {"esp", "ebp"}
                    and source[2] in {"esp", "ebp"}
                    and target[0] in {"esp", "ebp"}
                    and target[2] in {"esp", "ebp"}
                    and target[0] != source[0]
                    and target[2] != source[2]
                ) else 1,
                0 if target[0] == "ebp" and target[2] == "ebp" else 1,
                0 if target[0] == "esp" and target[2] == "esp" else 1,
                target,
            )

        max_frame_aliases = 8
        max_frame_preserved_imports = 8

        def terminal_external_jump_target(target_id: int) -> bool:
            target_node_id = node_by_target.get(target_id)
            if target_node_id is None:
                return False
            original = behaviors[target_node_id].get("original_ir", {})
            candidate = behaviors[target_node_id].get("candidate_ir", {})
            original_outcome = original.get("outcome") or {}
            candidate_outcome = candidate.get("outcome") or {}
            original_identity = _semantic_external_target_identity(
                original_outcome.get("import") or {}
            )
            candidate_identity = _semantic_external_target_identity(
                candidate_outcome.get("import") or {}
            )
            return (
                original_outcome.get("op") == "external_jump"
                and candidate_outcome.get("op") == "external_jump"
                and original_identity is not None
                and original_identity == candidate_identity
                and machine_contract_by_import.get(
                    original_identity, {}
                ).get("disposition") == "terminates"
            )

        def import_relation_key(relation: dict[str, Any]) -> str:
            return json.dumps({
                "original": str(relation["original"]),
                "candidate": str(relation["candidate"]),
                "import": relation["import"],
            }, sort_keys=True, separators=(",", ":"))

        def import_relation_payload(key: str) -> dict[str, Any]:
            payload = json.loads(key)
            if not isinstance(payload, dict):
                raise StageAInputError("invalid preserved import relation key")
            return payload

        def register_relation_key(relation: dict[str, Any]) -> str:
            return json.dumps(relation, sort_keys=True, separators=(",", ":"))

        def register_relation_payload(key: str) -> dict[str, Any]:
            payload = json.loads(key)
            if not isinstance(payload, dict):
                raise StageAInputError("invalid preserved register relation key")
            return payload

        def frame_register_relation_payload(key: str) -> dict[str, Any]:
            payload = register_relation_payload(key)
            payload.pop("origin", None)
            return payload

        def register_relation_behavior_preserved(
            relation_key: str,
            original_behavior: dict[str, Any],
            candidate_behavior: dict[str, Any],
        ) -> bool:
            relation = register_relation_payload(relation_key)
            return (
                original_behavior.get("registers", {}).get(
                    relation["original"]
                ) == {
                    "op": "input_reg", "reg": relation["original"],
                }
                and candidate_behavior.get("registers", {}).get(
                    relation["candidate"]
                ) == {
                    "op": "input_reg", "reg": relation["candidate"],
                }
            )

        def paired_frame_expression_witness(
            original_expression: Any,
            candidate_expression: Any,
            relation_keys: tuple[str, ...],
        ) -> dict[str, Any] | None:
            return _paired_frame_expression_witness(
                original_expression,
                candidate_expression,
                tuple(
                    register_relation_payload(relation_key)
                    for relation_key in relation_keys
                ),
            )

        def frame_paired_expression_register_output_claims(
            node_id: int, relation_keys: tuple[str, ...],
        ) -> tuple[dict[str, Any], ...]:
            original = behaviors[node_id].get("original_ir") or {}
            candidate = behaviors[node_id].get("candidate_ir") or {}
            original_registers = original.get("registers") or {}
            candidate_registers = candidate.get("registers") or {}
            claims: list[dict[str, Any]] = []
            for relation_key in relation_keys:
                relation = register_relation_payload(relation_key)
                if relation.get("relation") not in {"exact", "related_word"}:
                    continue
                if register_relation_behavior_preserved(
                    relation_key, original, candidate
                ):
                    continue
                witness = paired_frame_expression_witness(
                    original_registers.get(str(relation["original"])),
                    candidate_registers.get(str(relation["candidate"])),
                    relation_keys,
                )
                if witness is None:
                    continue
                claims.append({
                    "profile": "active_frame_paired_expression_register_output_v1",
                    "output": frame_register_relation_payload(relation_key),
                    "witness": witness,
                })
            return tuple(claims)

        def external_frame_relations_preserved(
            node_id: int,
            imported: dict[str, Any],
            frame_relation_inventories: tuple[tuple[str, ...], ...],
        ) -> bool:
            identity = _semantic_external_target_identity(imported)
            contract_row = machine_contract_by_import.get(identity)
            if contract_row is None:
                block(
                    "runtime_frame_external_contract_missing",
                    f"external transition at node {node_id} has no machine contract "
                    "for carried register relations",
                    "declare the exact ABI-preserved registers and world effects",
                )
                return False
            preserved = {
                str(register) for register in contract_row.get(
                    "preserved_registers", []
                )
            }
            if contract_row.get("disposition") != "returns":
                block(
                    "runtime_frame_register_relation_external_disposition_unsupported",
                    f"external transition at node {node_id} carries register "
                    f"relations through disposition {contract_row.get('disposition')!r}",
                    "add a disposition-specific checked frame-fact continuation theorem",
                )
                return False
            world_independent = {
                "exact", "fixed_word", "code_pointer", "fixed_code_pointer",
            }
            for relation_key in (
                relation_key
                for inventory in frame_relation_inventories
                for relation_key in inventory
            ):
                relation = register_relation_payload(relation_key)
                if (
                    relation.get("relation") not in world_independent
                    or relation.get("original") not in preserved
                    or relation.get("candidate") not in preserved
                ):
                    block(
                        "runtime_frame_register_relation_external_crossing_unsupported",
                        f"external transition at node {node_id} cannot preserve "
                        f"{relation.get('relation')} relation "
                        f"{relation.get('original')}/{relation.get('candidate')}",
                        "use ABI-preserved registers and a world-independent relation, "
                        "or add a checked world-transition theorem for the relation",
                    )
                    return False
                if not register_relation_behavior_preserved(
                    relation_key,
                    behaviors[node_id].get("original_ir") or {},
                    behaviors[node_id].get("candidate_ir") or {},
                ):
                    block(
                        "runtime_frame_register_relation_external_setup_clobbered",
                        f"external transition at node {node_id} clobbers carried "
                        f"register relation {relation.get('original')}/"
                        f"{relation.get('candidate')} before the environment call",
                        "preserve both registers through call setup or add a checked "
                        "register transfer witness",
                    )
                    return False
            return True

        def external_frame_imports_preserved(
            node_id: int,
            imported: dict[str, Any],
            frame_import_inventories: tuple[tuple[str, ...], ...],
        ) -> bool:
            identity = _semantic_external_target_identity(imported)
            contract_row = machine_contract_by_import.get(identity)
            if contract_row is None:
                block(
                    "runtime_frame_import_external_contract_missing",
                    f"external transition at node {node_id} has no machine contract "
                    "for carried import-register facts",
                    "declare the exact ABI-preserved registers and world effects",
                )
                return False
            if contract_row.get("disposition") != "returns":
                block(
                    "runtime_frame_import_external_disposition_unsupported",
                    f"external transition at node {node_id} carries import-register "
                    f"facts through disposition {contract_row.get('disposition')!r}",
                    "add a disposition-specific checked frame-fact continuation theorem",
                )
                return False
            preserved = {
                str(register) for register in contract_row.get(
                    "preserved_registers", []
                )
            }
            original_behavior = behaviors[node_id].get("original_ir") or {}
            candidate_behavior = behaviors[node_id].get("candidate_ir") or {}
            original_registers = original_behavior.get("registers") or {}
            candidate_registers = candidate_behavior.get("registers") or {}
            for relation_key in (
                relation_key
                for inventory in frame_import_inventories
                for relation_key in inventory
            ):
                relation = import_relation_payload(relation_key)
                original_register = str(relation["original"])
                candidate_register = str(relation["candidate"])
                if (
                    original_register == "esp"
                    or candidate_register == "esp"
                    or original_register not in preserved
                    or candidate_register not in preserved
                ):
                    block(
                        "runtime_frame_import_external_crossing_unsupported",
                        f"external transition at node {node_id} cannot ABI-preserve "
                        f"import-register fact {original_register}/{candidate_register}",
                        "carry the fact in non-ESP registers preserved by the exact "
                        "machine import contract",
                    )
                    return False
                if (
                    original_registers.get(original_register) != {
                        "op": "input_reg", "reg": original_register,
                    }
                    or candidate_registers.get(candidate_register) != {
                        "op": "input_reg", "reg": candidate_register,
                    }
                ):
                    block(
                        "runtime_frame_import_external_setup_clobbered",
                        f"external transition at node {node_id} clobbers carried "
                        f"import-register fact {original_register}/{candidate_register} "
                        "before entering the environment",
                        "preserve both registers through call setup or add an exact "
                        "checked transfer witness",
                    )
                    return False
            return True

        def internal_frame_relations_preserved(
            node_id: int,
            frame_relation_inventories: tuple[tuple[str, ...], ...],
            *,
            refreshable_active_relations: frozenset[str] = frozenset(),
        ) -> bool:
            original = behaviors[node_id].get("original_ir") or {}
            candidate = behaviors[node_id].get("candidate_ir") or {}
            for frame_index, inventory in enumerate(
                _frame_relations_requiring_internal_preservation(
                    frame_relation_inventories, "transfer"
                )
            ):
                for relation_key in inventory:
                    if register_relation_behavior_preserved(
                        relation_key, original, candidate
                    ):
                        continue
                    if (
                        frame_index == 0
                        and relation_key in refreshable_active_relations
                    ):
                        continue
                    relation = register_relation_payload(relation_key)
                    block(
                        "runtime_frame_register_relation_behavior_clobbered",
                        f"internal product node {node_id} clobbers carried register "
                        f"relation {relation.get('original')}/"
                        f"{relation.get('candidate')}",
                        "preserve both registers exactly or supply an explicit "
                        "relation-transfer certificate",
                    )
                    return False
            return True

        def active_frame_relation_refreshes(
            node_id: int,
            frame_inventories: tuple[
                tuple[tuple[str, int, str, int], ...], ...
            ],
            frame_relations: tuple[tuple[str, ...], ...],
            frame_exact_words: tuple[tuple[tuple[int, int], ...], ...],
        ) -> dict[tuple[str, str], tuple[str, dict[str, Any]]]:
            if not frame_inventories or not frame_relations:
                return {}
            word_claims, expression_claims = frame_relation_refresh_claims(
                node_id, frame_inventories[0], frame_relations[0],
                frame_exact_words[0],
            )
            return {
                (
                    str(claim["output"]["original"]),
                    str(claim["output"]["candidate"]),
                ): (register_relation_key(claim["output"]), claim)
                for claim in (*word_claims, *expression_claims)
            }

        def region_import_keys(region_index: int) -> tuple[str, ...]:
            return tuple(sorted(
                import_relation_key(relation)
                for relation in regions[region_index].get(
                    "input_import_relations", []
                )
            ))

        def certificate_hash(certificate: dict[str, Any]) -> str:
            unsigned = dict(certificate)
            unsigned.pop("certificate_hash", None)
            return sha256_bytes(json.dumps(
                unsigned, sort_keys=True, separators=(",", ":"),
                allow_nan=False,
            ).encode())

        def callsite_preserved_facts(
            callsite_node_id: int,
            callee_node_id: int,
            continuation_node_id: int,
        ) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
            if terminal_external_jump_target(
                int(nodes[callee_node_id]["target_id"])
            ):
                # A nonreturning import still has a concrete ABI frame, but no
                # facts need to survive through a continuation that cannot run.
                return (), ()
            requested = region_import_keys(callsite_node_id)
            rows = callsite_rows_by_node.get(callsite_node_id, [])
            proposal_edges = proposal_edges_by_node.get(callsite_node_id, [])
            if len(rows) != 1:
                block(
                    "callsite_preservation_certificate_ambiguous",
                    f"internal callsite {callsite_node_id} has {len(rows)} proposal rows",
                    "emit exactly one canonical proposal row for the callsite",
                )
                return None
            row = rows[0]
            try:
                requested_registers = tuple(sorted(
                    register_relation_key(relation)
                    for relation in row["requested_register_relations"]
                ))
            except (KeyError, TypeError, ValueError):
                block(
                    "callsite_preservation_certificate_invalid",
                    f"internal callsite {callsite_node_id} has malformed preserved "
                    "register relations",
                    "regenerate the canonical callsite certificate",
                )
                return None
            if not requested and not requested_registers:
                if (
                    row.get("status") != "not_applicable"
                    or proposal_edges
                ):
                    block(
                        "callsite_preservation_certificate_mismatch",
                        f"internal callsite {callsite_node_id} has an unexpected empty "
                        "preservation proposal",
                        "emit one not-applicable row and no proposal edge",
                    )
                    return None
                return (), ()

            original_behavior = behaviors[callsite_node_id].get(
                "original_ir", {}
            )
            candidate_behavior = behaviors[callsite_node_id].get(
                "candidate_ir", {}
            )
            for relation_key in requested:
                relation = import_relation_payload(relation_key)
                if (
                    original_behavior.get("registers", {}).get(
                        relation["original"]
                    ) != {
                        "op": "input_reg", "reg": relation["original"],
                    }
                    or candidate_behavior.get("registers", {}).get(
                        relation["candidate"]
                    ) != {
                        "op": "input_reg", "reg": relation["candidate"],
                    }
                ):
                    block(
                        "callsite_preservation_seed_behavior_clobbered",
                        f"internal callsite {callsite_node_id} does not preserve "
                        "a requested register while creating its runtime frame",
                        "preserve every requested callsite register exactly",
                    )
                    return None
            output_claims = register_relations.get(
                "regions", []
            )[callsite_node_id].get("output_claims", [])
            for relation_key in requested_registers:
                relation = register_relation_payload(relation_key)
                origin = relation.get("origin")
                claim_index = (
                    int(origin["claim_index"])
                    if isinstance(origin, dict)
                    and isinstance(origin.get("claim_index"), int)
                    else -1
                )
                if (
                    not isinstance(origin, dict)
                    or origin.get("kind") != "region_output_claim"
                    or origin.get("region_index") != callsite_node_id
                    or not 0 <= claim_index < len(output_claims)
                ):
                    block(
                        "callsite_register_relation_origin_invalid",
                        f"internal callsite {callsite_node_id} has an invalid output-"
                        "claim origin",
                        "bind every carried relation to one exact callsite output claim",
                    )
                    return None
                claim = output_claims[claim_index]
                claim_hash = sha256_bytes(json.dumps(
                    claim, sort_keys=True, separators=(",", ":"), allow_nan=False,
                ).encode())
                expected_output = dict(relation)
                expected_output.pop("origin", None)
                if (
                    origin.get("claim_hash") != claim_hash
                    or claim.get("output") != expected_output
                ):
                    block(
                        "callsite_register_relation_origin_mismatch",
                        f"internal callsite {callsite_node_id} relation origin does not "
                        "match its exact output claim",
                        "regenerate the relation from the checked output-claim payload",
                    )
                    return None

            relation_edges = register_edges_by_pair.get((
                callsite_node_id, callee_node_id,
            ), [])
            returning_contract_ids = {
                int(edge["returning_external_thunk_contract_id"])
                for edge in relation_edges
                if isinstance(
                    edge.get("returning_external_thunk_contract_id"), int
                )
                and not isinstance(
                    edge.get("returning_external_thunk_contract_id"), bool
                )
            }
            if len(returning_contract_ids) == 1:
                machine_contract = machine_contract_by_id.get(
                    next(iter(returning_contract_ids))
                )
                preserved = {
                    str(register)
                    for register in (machine_contract or {}).get(
                        "preserved_registers", []
                    )
                }
                required_registers = {
                    import_relation_payload(relation_key)[side]
                    for relation_key in requested
                    for side in ("original", "candidate")
                } | {
                    register_relation_payload(relation_key)[side]
                    for relation_key in requested_registers
                    for side in ("original", "candidate")
                }
                if (
                    machine_contract is None
                    or machine_contract.get("disposition") != "returns"
                    or not required_registers.issubset(preserved)
                ):
                    block(
                        "runtime_frame_register_relation_external_crossing_unsupported",
                        f"returning external thunk at callsite {callsite_node_id} "
                        "does not preserve every seeded runtime-frame register",
                        "declare an exact returning machine contract whose preserved "
                        "register set covers every carried fact",
                    )
                    return None
                return requested, requested_registers
            if len(proposal_edges) != 1:
                block(
                    "callsite_preservation_certificate_ambiguous",
                    f"internal callsite {callsite_node_id} has "
                    f"{len(proposal_edges)} satisfied proposal edges",
                    "emit exactly one satisfied proposal edge for the callsite",
                )
                return None
            analysis = row.get("analysis")
            certificate = (
                analysis.get("certificate")
                if isinstance(analysis, dict) else None
            )
            reason_codes = sorted({
                str(code) for code in row.get("reason_codes", [])
            } | {
                str(code)
                for code in (
                    analysis.get("reason_codes", [])
                    if isinstance(analysis, dict) else []
                )
            })
            if (
                row.get("status") != "satisfied"
                or not isinstance(analysis, dict)
                or analysis.get("status") != "satisfied"
                or not isinstance(certificate, dict)
            ):
                code = (
                    "callsite_preservation_budget_exceeded"
                    if any(item in {
                        "node_budget_overflow", "edge_budget_overflow",
                        "analysis_budget_invalid",
                    } for item in reason_codes)
                    else "callsite_preservation_behavior_unmet"
                )
                block(
                    code,
                    f"internal callsite {callsite_node_id} has no satisfied "
                    f"preservation certificate ({', '.join(reason_codes) or 'missing'})",
                    "bound the callee control graph and preserve every requested "
                    "register on each reachable internal behavior",
                )
                return None
            proposal_edge = proposal_edges[0]
            try:
                certificate_relations = tuple(sorted(
                    import_relation_key(relation)
                    for relation in certificate["requested_relations"]
                ))
                row_relations = tuple(sorted(
                    import_relation_key(relation)
                    for relation in row["requested_relations"]
                ))
                proposal_relations = tuple(sorted(
                    import_relation_key(relation)
                    for relation in proposal_edge["preserved_import_relations"]
                ))
                certificate_register_relations = tuple(sorted(
                    register_relation_key(relation)
                    for relation in certificate["requested_register_relations"]
                ))
                proposal_register_relations = tuple(sorted(
                    register_relation_key(relation)
                    for relation in proposal_edge["preserved_register_relations"]
                ))
                return_inventory = certificate["return_inventory"]
                return_nodes = tuple(sorted({
                    int(item["return_node_id"])
                    for item in return_inventory
                }))
                return_continuations = {
                    int(item["continuation_id"])
                    for item in return_inventory
                }
                supplied_hash = str(certificate["certificate_hash"])
            except (KeyError, TypeError, ValueError):
                block(
                    "callsite_preservation_certificate_invalid",
                    f"internal callsite {callsite_node_id} has a malformed "
                    "preservation certificate",
                    "regenerate the canonical callsite certificate",
                )
                return None
            expected_return_nodes = tuple(sorted({
                int(item) for item in row.get("return_region_indices", [])
            }))
            if (
                int(certificate.get("callsite_id", -1)) != callsite_node_id
                or int(certificate.get("callee_entry", -1)) != callee_node_id
                or int(row.get("callee_region_index", -1)) != callee_node_id
                or int(row.get("continuation_region_index", -1))
                    != continuation_node_id
                or int(proposal_edge.get("target_region_index", -1))
                    != continuation_node_id
                or int(proposal_edge.get("source_region_index", -1))
                    != callsite_node_id
                or return_continuations != {continuation_node_id}
                or return_nodes != expected_return_nodes
                or tuple(sorted(int(item) for item in proposal_edge.get(
                    "return_region_indices", []
                ))) != expected_return_nodes
                or certificate_relations != requested
                or row_relations != requested
                or proposal_relations != requested
                or certificate_register_relations != requested_registers
                or proposal_register_relations != requested_registers
                or proposal_edge.get("certificate_id") != certificate.get("id")
                or proposal_edge.get("certificate_hash") != supplied_hash
                or supplied_hash != certificate_hash(certificate)
            ):
                block(
                    "callsite_preservation_certificate_mismatch",
                    f"internal callsite {callsite_node_id}, callee "
                    f"{callee_node_id}, continuation {continuation_node_id}, and "
                    "its preservation certificate do not match exactly",
                    "regenerate the certificate from the exact paired call, callee, "
                    "return inventory, and continuation",
                )
                return None
            if len(requested) > max_frame_preserved_imports:
                block(
                    "runtime_frame_import_budget_exceeded",
                    f"internal callsite {callsite_node_id} requests "
                    f"{len(requested)} preserved import relations",
                    "reduce the requested inventory or deliberately raise the "
                    "Lean-checked frame budget",
                )
                return None
            if len(requested_registers) > max_frame_preserved_imports:
                block(
                    "runtime_frame_register_relation_budget_exceeded",
                    f"internal callsite {callsite_node_id} requests "
                    f"{len(requested_registers)} preserved register relations",
                    "reduce the requested inventory or deliberately raise the "
                    "Lean-checked frame budget",
                )
                return None
            return requested, requested_registers

        def frame_relation_output_claims(
            callsite_node_id: int, relation_keys: tuple[str, ...],
        ) -> list[dict[str, Any]]:
            output_claims = register_relations.get(
                "regions", []
            )[callsite_node_id].get("output_claims", [])
            selected = []
            for relation_key in relation_keys:
                relation = register_relation_payload(relation_key)
                origin = relation["origin"]
                selected.append(output_claims[int(origin["claim_index"])])
            return selected

        def inventory_key(payload: dict[str, Any]) -> tuple[
            tuple[str, int, str, int], ...
        ]:
            return tuple(location_key(item) for item in payload["locations"])

        def inventory_payload(
            locations: tuple[tuple[str, int, str, int], ...],
            preserved_imports: tuple[str, ...] = (),
            preserved_relations: tuple[str, ...] = (),
            exact_words: tuple[tuple[int, int], ...] = (),
        ) -> dict[str, Any]:
            payload = {
                "locations": [location_payload(location) for location in locations],
            }
            if exact_words:
                payload["exact_words"] = [
                    {"original": original, "candidate": candidate}
                    for original, candidate in exact_words
                ]
            if preserved_imports:
                payload["preserved_imports"] = [
                    import_relation_payload(key) for key in preserved_imports
                ]
            if preserved_relations:
                payload["preserved_relations"] = [
                    register_relation_payload(key)
                    for key in preserved_relations
                ]
            return payload

        def inventory_exact_key(
            payload: dict[str, Any],
        ) -> tuple[tuple[int, int], ...]:
            return tuple(
                (int(word["original"]), int(word["candidate"]))
                for word in payload.get("exact_words", [])
            )

        def inventory_import_key(payload: dict[str, Any]) -> tuple[str, ...]:
            return tuple(sorted(
                import_relation_key(relation)
                for relation in payload.get("preserved_imports", [])
            ))

        def inventory_register_key(payload: dict[str, Any]) -> tuple[str, ...]:
            return tuple(sorted(
                register_relation_key(relation)
                for relation in payload.get("preserved_relations", [])
            ))

        def choose_location_transfers(
            *, source_node_id: int, target_node_id: int,
            target_description: str,
            source_inventories: tuple[
                tuple[tuple[str, int, str, int], ...], ...
            ],
            claims: list[dict[str, Any]],
            rules: list[dict[str, Any]],
        ) -> tuple[tuple[tuple[str, int, str, int], ...], ...] | None:
            transferred_inventories = []
            for source_inventory in source_inventories:
                candidates: dict[
                    tuple[str, int, str, int], tuple[str, int, str, int]
                ] = {}
                for source_location in source_inventory:
                    for claim in claims:
                        if location_key(claim["source"]) == source_location:
                            candidates.setdefault(
                                location_key(claim["target"]), source_location
                            )
                    for rule in rules:
                        if (
                            rule["original_source_register"] != source_location[0]
                            or rule["candidate_source_register"] != source_location[2]
                        ):
                            continue
                        target = (
                            str(rule["original_target_register"]),
                            (source_location[1] - int(rule["original_delta"]))
                                % 2**32,
                            str(rule["candidate_target_register"]),
                            (source_location[3] - int(rule["candidate_delta"]))
                                % 2**32,
                        )
                        candidates.setdefault(target, source_location)
                if not candidates:
                    block(
                        "runtime_frame_location_transfer_incomplete",
                        f"product {target_description} from {source_node_id} has no "
                        f"checked transfer for frame aliases {source_inventory}",
                        "emit an affine register-location witness for at least one "
                        "alias of every live runtime frame",
                    )
                    return None
                ordered = sorted(
                    (
                        target for target in candidates
                        if location_memory_transfer_ready(target_node_id, target)
                    ),
                    key=lambda target: location_rank(
                        candidates[target], target, target_node_id
                    ),
                )
                required_edges = set(
                    location_required_outgoing_edges(target_node_id)
                )
                selected: list[tuple[str, int, str, int]] = []
                remaining_edges = set(required_edges)
                while remaining_edges:
                    ranked = sorted(
                        (
                            target for target in ordered
                            if target not in selected
                        ),
                        key=lambda target: (
                            -len(
                                remaining_edges.intersection(
                                    location_outgoing_transfer_coverage(
                                        target_node_id, target
                                    )
                                )
                            ),
                            location_rank(
                                candidates[target], target, target_node_id
                            ),
                        ),
                    )
                    if not ranked:
                        break
                    chosen = ranked[0]
                    covered = remaining_edges.intersection(
                        location_outgoing_transfer_coverage(
                            target_node_id, chosen
                        )
                    )
                    if not covered:
                        break
                    selected.append(chosen)
                    remaining_edges.difference_update(covered)
                if not required_edges and ordered:
                    selected.append(ordered[0])
                if not selected or remaining_edges:
                    block(
                        "runtime_frame_canonical_alias_incomplete",
                        f"product {target_description} from {source_node_id} "
                        "has no memory-safe alias set covering every feasible "
                        "outgoing internal edge",
                        "emit checked affine location transfers that cover every "
                        "feasible successor",
                    )
                    return None
                canonical = tuple(selected)
                if len(canonical) > max_frame_aliases:
                    block(
                        "runtime_frame_alias_budget_exceeded",
                        f"product {target_description} from {source_node_id} "
                        f"requires {len(canonical)} aliases for one runtime frame",
                        "supply a checked canonical alias policy or raise the Lean-checked "
                        "finite alias profile deliberately",
                    )
                    return None
                transferred_inventories.append(canonical)
            return tuple(transferred_inventories)

        @lru_cache(maxsize=None)
        def transfer_locations(
            source_node_id: int, target_node_id: int,
            source_inventories: tuple[
                tuple[tuple[str, int, str, int], ...], ...
            ],
        ) -> tuple[tuple[tuple[str, int, str, int], ...], ...] | None:
            matching_edges = register_edges_by_pair.get(
                (source_node_id, target_node_id), []
            )
            if len(matching_edges) != 1:
                block(
                    "runtime_frame_transfer_edge_ambiguous",
                    f"product transition {source_node_id}->{target_node_id} has "
                    f"{len(matching_edges)} register-relation edges",
                    "emit one canonical register-relation edge for the decoded transition",
                )
                return None
            return choose_location_transfers(
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                target_description=f"transition {source_node_id}->{target_node_id}",
                source_inventories=source_inventories,
                claims=matching_edges[0].get("return_slot_transfer_claims", []),
                rules=matching_edges[0].get("return_slot_transfer_rules", []),
            )

        @lru_cache(maxsize=None)
        def external_transfer_locations(
            source_node_id: int, target_node_id: int,
            source_inventories: tuple[
                tuple[tuple[str, int, str, int], ...], ...
            ],
        ) -> tuple[tuple[tuple[str, int, str, int], ...], ...] | None:
            matching_edges = register_edges_by_pair.get(
                (source_node_id, target_node_id), []
            )
            if len(matching_edges) != 1:
                block(
                    "runtime_frame_external_edge_ambiguous",
                    f"external transition {source_node_id}->{target_node_id} has "
                    f"{len(matching_edges)} register-relation edges",
                    "emit one canonical external register-relation edge",
                )
                return None
            return choose_location_transfers(
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                target_description=(
                    f"external transition {source_node_id}->{target_node_id}"
                ),
                source_inventories=source_inventories,
                claims=[],
                rules=matching_edges[0].get(
                    "return_slot_external_transfer_rules", []
                ),
            )

        def word_offsets_disjoint(left: int, right: int) -> bool:
            distance = (right - left) % 2**32
            return 4 <= distance <= 2**32 - 4

        write_witness_cache: dict[
            tuple[int, str, int], list[dict[str, Any]] | None
        ] = {}

        def write_witnesses(
            behavior: dict[str, Any], register: str, frame_offset: int,
        ) -> list[dict[str, Any]] | None:
            cache_key = (id(behavior), register, frame_offset)
            if cache_key in write_witness_cache:
                return write_witness_cache[cache_key]
            witnesses = []
            for write in behavior.get("writes") or []:
                result = _register_offset_witness(
                    write.get("address"), register
                )
                if result is None:
                    write_witness_cache[cache_key] = None
                    return None
                witness, write_offset = result
                if not word_offsets_disjoint(frame_offset, int(write_offset)):
                    write_witness_cache[cache_key] = None
                    return None
                witnesses.append(witness)
            write_witness_cache[cache_key] = witnesses
            return witnesses

        def frame_read_address(
            expression: dict[str, Any], writes: list[dict[str, Any]],
            register: str,
        ) -> tuple[dict[str, Any], str] | None:
            if expression.get("op") == "read32":
                address = expression.get("address")
                return (address, "direct") if isinstance(address, dict) else None
            shifted_bytes: dict[int, dict[str, Any]] = {}

            def collect(node: dict[str, Any], shift: int = 0) -> bool:
                operation = node.get("op")
                if operation == "bit_or":
                    left = node.get("left")
                    right = node.get("right")
                    return (
                        isinstance(left, dict)
                        and isinstance(right, dict)
                        and collect(left, shift)
                        and collect(right, shift)
                    )
                if operation == "shift_left":
                    value = node.get("value")
                    amount = int(node.get("amount", -1))
                    return isinstance(value, dict) and collect(
                        value, shift + amount
                    )
                if shift not in {0, 8, 16, 24} or shift in shifted_bytes:
                    return False
                shifted_bytes[shift] = node
                return True

            def decode_byte(
                node: dict[str, Any],
            ) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
                reversed_writes: list[dict[str, Any]] = []
                cursor = node
                while cursor.get("op") == "read8_after_write":
                    address = cursor.get("write_address")
                    value = cursor.get("write_value")
                    prior = cursor.get("prior")
                    if not (
                        isinstance(address, dict)
                        and isinstance(value, dict)
                        and isinstance(prior, dict)
                    ):
                        return None
                    reversed_writes.append({"address": address, "value": value})
                    cursor = prior
                address = cursor.get("address")
                if cursor.get("op") != "read8" or not isinstance(address, dict):
                    return None
                return address, list(reversed(reversed_writes))

            if not collect(expression) or set(shifted_bytes) != {0, 8, 16, 24}:
                return None
            decoded = [
                decode_byte(shifted_bytes[shift])
                for shift in (0, 8, 16, 24)
            ]
            if any(item is None for item in decoded):
                return None
            byte_rows = [item for item in decoded if item is not None]
            offsets = [
                _register_offset_witness(address, register)
                for address, _ in byte_rows
            ]
            if any(item is None for item in offsets):
                return None
            concrete_offsets = [
                item[1] for item in offsets if item is not None
            ]
            base_offset = concrete_offsets[0]
            if concrete_offsets != [
                (base_offset + index) % 2**32 for index in range(4)
            ]:
                return None
            read_write_prefixes = [row_writes for _, row_writes in byte_rows]
            if all(row_writes == writes for row_writes in read_write_prefixes):
                read_profile = "assembled_after_writes"
            elif all(not row_writes for row_writes in read_write_prefixes):
                read_profile = "assembled_input"
            else:
                return None
            return byte_rows[0][0], read_profile

        @lru_cache(maxsize=None)
        def frame_exact_word_register_output_claims(
            node_id: int,
            source_inventory: tuple[tuple[str, int, str, int], ...],
            exact_words: tuple[tuple[int, int], ...],
        ) -> tuple[dict[str, Any], ...]:
            original = behaviors[node_id].get("original_ir") or {}
            candidate = behaviors[node_id].get("candidate_ir") or {}
            original_registers = original.get("registers") or {}
            candidate_registers = candidate.get("registers") or {}
            original_writes = original.get("writes") or []
            candidate_writes = candidate.get("writes") or []
            relation_row = register_relations.get("regions", [])[node_id]
            proposed: dict[str, list[dict[str, Any]]] = {}
            for relation in relation_row.get("outputs", []):
                original_register = str(relation.get("original"))
                candidate_register = str(relation.get("candidate"))
                original_expression = original_registers.get(original_register)
                candidate_expression = candidate_registers.get(candidate_register)
                if not (
                    isinstance(original_expression, dict)
                    and isinstance(candidate_expression, dict)
                ):
                    continue
                for source_location in source_inventory:
                    original_read = frame_read_address(
                        original_expression, original_writes,
                        source_location[0],
                    )
                    candidate_read = frame_read_address(
                        candidate_expression, candidate_writes,
                        source_location[2],
                    )
                    if original_read is None or candidate_read is None:
                        continue
                    original_address, original_read_profile = original_read
                    candidate_address, candidate_read_profile = candidate_read
                    original_result = _register_offset_witness(
                        original_address, source_location[0]
                    )
                    candidate_result = _register_offset_witness(
                        candidate_address, source_location[2]
                    )
                    if original_result is None or candidate_result is None:
                        continue
                    original_address_witness, original_offset = original_result
                    candidate_address_witness, candidate_offset = candidate_result
                    for original_word_offset, candidate_word_offset in exact_words:
                        expected_original = (
                            source_location[1] + original_word_offset
                        ) % 2**32
                        expected_candidate = (
                            source_location[3] + candidate_word_offset
                        ) % 2**32
                        if (
                            original_offset != expected_original
                            or candidate_offset != expected_candidate
                        ):
                            continue
                        original_write_witnesses = (
                            write_witnesses(
                                original, source_location[0], original_offset
                            )
                            if original_read_profile == "assembled_after_writes"
                            else []
                        )
                        candidate_write_witnesses = (
                            write_witnesses(
                                candidate, source_location[2], candidate_offset
                            )
                            if candidate_read_profile == "assembled_after_writes"
                            else []
                        )
                        if (
                            original_write_witnesses is None
                            or candidate_write_witnesses is None
                        ):
                            continue
                        output = {
                            "original": original_register,
                            "candidate": candidate_register,
                            "relation": "exact",
                        }
                        claim = {
                            "profile":
                                "active_frame_exact_word_register_output_v1",
                            "source_location": location_payload(source_location),
                            "word": {
                                "original": original_word_offset,
                                "candidate": candidate_word_offset,
                            },
                            "output": output,
                            "original_address_witness":
                                original_address_witness,
                            "candidate_address_witness":
                                candidate_address_witness,
                            "original_assembled_read":
                                original_read_profile == "assembled_after_writes",
                            "candidate_assembled_read":
                                candidate_read_profile == "assembled_after_writes",
                            "original_input_assembled_read":
                                original_read_profile == "assembled_input",
                            "candidate_input_assembled_read":
                                candidate_read_profile == "assembled_input",
                            "original_write_witnesses":
                                original_write_witnesses,
                            "candidate_write_witnesses":
                                candidate_write_witnesses,
                        }
                        proposed.setdefault(
                            register_relation_key(output), []
                        ).append(claim)
            return tuple(
                rows[0]
                for key, rows in sorted(proposed.items())
                if len({
                    json.dumps(row, sort_keys=True, separators=(",", ":"))
                    for row in rows
                }) == 1
            )

        def frame_relation_refresh_claims(
            node_id: int,
            source_inventory: tuple[tuple[str, int, str, int], ...],
            relation_keys: tuple[str, ...],
            exact_words: tuple[tuple[int, int], ...],
        ) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
            word_claims = frame_exact_word_register_output_claims(
                node_id, source_inventory, exact_words
            )
            expression_claims = frame_paired_expression_register_output_claims(
                node_id, relation_keys
            )
            selected: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
            for kind, claims in (
                ("word", word_claims), ("expression", expression_claims),
            ):
                for claim in claims:
                    key = (
                        str(claim["output"]["original"]),
                        str(claim["output"]["candidate"]),
                    )
                    selected.setdefault(key, (kind, claim))
            ordered = [selected[key] for key in sorted(selected)]
            return (
                tuple(claim for kind, claim in ordered if kind == "word"),
                tuple(
                    claim for kind, claim in ordered if kind == "expression"
                ),
            )

        def frame_relations_after_internal(
            node_id: int,
            frame_inventories: tuple[
                tuple[tuple[str, int, str, int], ...], ...
            ],
            frame_relations: tuple[tuple[str, ...], ...],
            frame_exact_words: tuple[
                tuple[tuple[int, int], ...], ...
            ],
        ) -> tuple[tuple[str, ...], ...]:
            if not frame_inventories:
                return frame_relations
            word_claims, expression_claims = frame_relation_refresh_claims(
                node_id, frame_inventories[0], frame_relations[0],
                frame_exact_words[0],
            )
            existing = frame_relations[0]
            claims_by_registers = {
                (
                    str(claim["output"]["original"]),
                    str(claim["output"]["candidate"]),
                ): claim
                for claim in (*word_claims, *expression_claims)
            }
            carried = tuple(
                key for key in existing
                if (
                    str(register_relation_payload(key)["original"]),
                    str(register_relation_payload(key)["candidate"]),
                ) not in claims_by_registers
            )
            refreshed = tuple(
                register_relation_key(claim["output"])
                for _registers, claim in sorted(claims_by_registers.items())
            )
            active = (*carried, *refreshed)
            if len(active) > max_frame_preserved_imports:
                return frame_relations
            return (active, *frame_relations[1:])

        static_word_slots = list(contract.get("static_word_relation_slots", []))

        @lru_cache(maxsize=None)
        def frame_stack_location_claim(
            source_node_id: int,
            source_location: tuple[str, int, str, int],
        ) -> dict[str, Any] | None:
            original_register, original_offset, candidate_register, \
                candidate_offset = source_location
            if original_offset != candidate_offset:
                return None
            candidates: list[dict[str, Any]] = []
            for window in regions[source_node_id].get("stack_windows", []):
                if (
                    window.get("original_register") != original_register
                    or window.get("candidate_register") != candidate_register
                ):
                    continue
                if (
                    original_offset % 4 == 0
                    and original_offset + 4 <= int(window["bytes_above"])
                ):
                    candidates.append({
                        "window": window,
                        "direction": "above",
                        "amount": original_offset,
                    })
                below_amount = (-original_offset) % 2**32
                if (
                    below_amount >= 4
                    and below_amount % 4 == 0
                    and below_amount <= int(window["bytes_below"])
                ):
                    candidates.append({
                        "window": window,
                        "direction": "below",
                        "amount": below_amount,
                    })
            if not candidates:
                return None
            return sorted(candidates, key=lambda item: (
                0 if item["direction"] == "above" else 1,
                int(item["window"]["bytes_above"])
                    + int(item["window"]["bytes_below"]),
                int(item["window"]["range_id"]),
            ))[0]

        @lru_cache(maxsize=None)
        def paired_frame_write_witnesses(
            source_node_id: int,
            source_location: tuple[str, int, str, int],
        ) -> list[dict[str, Any]] | None:
            original = behaviors[source_node_id].get("original_ir") or {}
            candidate = behaviors[source_node_id].get("candidate_ir") or {}
            original_writes = list(original.get("writes") or [])
            candidate_writes = list(candidate.get("writes") or [])
            if len(original_writes) != len(candidate_writes):
                return None
            witnesses: list[dict[str, Any]] = []
            for original_write, candidate_write in zip(
                original_writes, candidate_writes, strict=True
            ):
                original_affine = _register_offset_witness(
                    original_write.get("address"), source_location[0]
                )
                candidate_affine = _register_offset_witness(
                    candidate_write.get("address"), source_location[2]
                )
                if original_affine is not None and candidate_affine is not None:
                    original_witness, original_write_offset = original_affine
                    candidate_witness, candidate_write_offset = candidate_affine
                    if (
                        word_offsets_disjoint(
                            source_location[1], int(original_write_offset)
                        )
                        and word_offsets_disjoint(
                            source_location[3], int(candidate_write_offset)
                        )
                    ):
                        witnesses.append({
                            "kind": "affine",
                            "original_witness": original_witness,
                            "candidate_witness": candidate_witness,
                        })
                        continue
                original_address = original_write.get("address") or {}
                candidate_address = candidate_write.get("address") or {}
                if (
                    original_address.get("op") != "constant"
                    or candidate_address.get("op") != "constant"
                ):
                    return None
                original_value = int(original_address.get("value", -1))
                candidate_value = int(candidate_address.get("value", -1))
                matching_slots = [
                    slot for slot in static_word_slots
                    if int(slot["original_address"]) == original_value
                    and int(slot["candidate_address"]) == candidate_value
                ]
                if len(matching_slots) != 1:
                    return None
                witnesses.append({
                    "kind": "static_word",
                    "slot_id": int(matching_slots[0]["id"]),
                })
            return witnesses

        @lru_cache(maxsize=None)
        def framed_memory_claim(
            source_node_id: int,
            source_location: tuple[str, int, str, int],
        ) -> dict[str, Any] | None:
            location = frame_stack_location_claim(
                source_node_id, source_location
            )
            witnesses = paired_frame_write_witnesses(
                source_node_id, source_location
            )
            if location is None or witnesses is None:
                return None
            return {
                "profile": "stack_image_separated_v1",
                "offsets": location_payload(source_location),
                "location": location,
                "writes": witnesses,
            }

        @lru_cache(maxsize=None)
        def protected_frame_memory_claim(
            source_node_id: int,
            source_location: tuple[str, int, str, int],
        ) -> dict[str, Any] | None:
            witnesses = paired_frame_write_witnesses(
                source_node_id, source_location
            )
            if witnesses is None:
                return None
            return {
                "profile": "protected_frame_span_v1",
                "offsets": location_payload(source_location),
                "writes": witnesses,
            }

        @lru_cache(maxsize=None)
        def location_memory_transfer_ready(
            source_node_id: int,
            source_location: tuple[str, int, str, int],
        ) -> bool:
            original = behaviors[source_node_id].get("original_ir") or {}
            candidate = behaviors[source_node_id].get("candidate_ir") or {}
            original_writes = write_witnesses(
                original, source_location[0], source_location[1]
            )
            candidate_writes = write_witnesses(
                candidate, source_location[2], source_location[3]
            )
            return (
                original_writes is not None and candidate_writes is not None
            ) or framed_memory_claim(
                source_node_id, source_location
            ) is not None or protected_frame_memory_claim(
                source_node_id, source_location
            ) is not None

        @lru_cache(maxsize=None)
        def location_required_outgoing_edges(
            source_node_id: int,
        ) -> tuple[int, ...]:
            return tuple(
                int(edge_id)
                for edge_id in nodes[source_node_id].get(
                    "outgoing_edge_ids", []
                )
                if not edges[int(edge_id)].get("infeasible")
                and edges[int(edge_id)].get("kind") in {"jump", "call"}
            )

        @lru_cache(maxsize=None)
        def location_edge_transfer_targets(
            source_node_id: int,
            source_location: tuple[str, int, str, int],
            edge_id: int,
        ) -> tuple[tuple[int, tuple[str, int, str, int]], ...]:
            edge = edges[int(edge_id)]
            target_node_id = int(edge["target_node_id"])
            matching_edges = register_edges_by_pair.get(
                (source_node_id, target_node_id), []
            )
            if len(matching_edges) != 1:
                return ()
            relation_edge = matching_edges[0]
            targets: list[tuple[int, tuple[str, int, str, int]]] = []
            for claim in relation_edge.get("return_slot_transfer_claims", []):
                if location_key(claim["source"]) == source_location:
                    targets.append((target_node_id, location_key(claim["target"])))
            for rule in relation_edge.get("return_slot_transfer_rules", []):
                if (
                    rule["original_source_register"] != source_location[0]
                    or rule["candidate_source_register"] != source_location[2]
                ):
                    continue
                targets.append((target_node_id, (
                    str(rule["original_target_register"]),
                    (source_location[1] - int(rule["original_delta"])) % 2**32,
                    str(rule["candidate_target_register"]),
                    (source_location[3] - int(rule["candidate_delta"])) % 2**32,
                )))
            return tuple(dict.fromkeys(targets))

        alias_viability_budget = int(os.environ.get(
            "SPAGHETTI_EXTRACTOR_STAGE_A_FRAME_ALIAS_VIABILITY_STATES", "4096"
        ))
        alias_viability_budget_blockers: set[
            tuple[int, tuple[str, int, str, int]]
        ] = set()

        @lru_cache(maxsize=None)
        def location_successor_viability(
            source_node_id: int,
            source_location: tuple[str, int, str, int],
        ) -> RuntimeFrameAliasViability:
            result = runtime_frame_alias_viability(
                ((source_node_id, source_location),),
                memory_ready=location_memory_transfer_ready,
                required_edges=location_required_outgoing_edges,
                transfer_targets=location_edge_transfer_targets,
                max_states=alias_viability_budget,
            )
            blocker_key = (source_node_id, source_location)
            if (
                result.budget_exceeded
                and blocker_key not in alias_viability_budget_blockers
            ):
                alias_viability_budget_blockers.add(blocker_key)
                block(
                    "runtime_frame_alias_viability_budget_exceeded",
                    f"frame alias {source_location} at product node "
                    f"{source_node_id} exceeds the finite successor-viability "
                    f"budget of {alias_viability_budget} states",
                    "supply a canonical affine alias invariant or deliberately "
                    "raise the checked finite analysis budget",
                )
            return result

        @lru_cache(maxsize=None)
        def location_outgoing_transfer_coverage(
            source_node_id: int,
            source_location: tuple[str, int, str, int],
        ) -> frozenset[int]:
            covered: set[int] = set()
            viability = location_successor_viability(
                source_node_id, source_location
            )
            if viability.budget_exceeded:
                return frozenset()
            for edge_id in location_required_outgoing_edges(source_node_id):
                if any(
                    target in viability.viable
                    for target in location_edge_transfer_targets(
                        source_node_id, source_location, edge_id
                    )
                ):
                    covered.add(int(edge_id))
            return frozenset(covered)

        @lru_cache(maxsize=None)
        def location_outgoing_transfer_ready(
            source_node_id: int,
            source_location: tuple[str, int, str, int],
        ) -> bool:
            return location_outgoing_transfer_coverage(
                source_node_id, source_location
            ) == frozenset(location_required_outgoing_edges(source_node_id))

        def exact_word_transfer_claims(
            source_node_id: int,
            source_inventory: tuple[tuple[str, int, str, int], ...],
            target_bases: tuple[tuple[str, int, str, int], ...],
            source_words: tuple[tuple[int, int], ...],
            target_words: tuple[tuple[int, int], ...],
        ) -> list[dict[str, Any]] | None:
            relation_row = register_relations.get("regions", [])[source_node_id]
            local_rules = relation_row.get(
                "return_slot_local_transfer_rules", []
            )
            original = behaviors[source_node_id].get("original_ir") or {}
            candidate = behaviors[source_node_id].get("candidate_ir") or {}
            exact_transfers = []
            for target_word in target_words:
                if target_word not in source_words:
                    return None
                candidates = []
                for source_base in source_inventory:
                    shifted_source = (
                        source_base[0],
                        (source_base[1] + target_word[0]) % 2**32,
                        source_base[2],
                        (source_base[3] + target_word[1]) % 2**32,
                    )
                    original_writes = write_witnesses(
                        original, shifted_source[0], shifted_source[1]
                    )
                    candidate_writes = write_witnesses(
                        candidate, shifted_source[2], shifted_source[3]
                    )
                    memory_claim = (
                        {
                            "profile": "affine_v1",
                            "offsets": location_payload(shifted_source),
                            "original_write_witnesses": original_writes,
                            "candidate_write_witnesses": candidate_writes,
                        }
                        if original_writes is not None
                        and candidate_writes is not None
                        else framed_memory_claim(source_node_id, shifted_source)
                            or protected_frame_memory_claim(
                                source_node_id, shifted_source
                            )
                    )
                    if memory_claim is None:
                        continue
                    for target_base in target_bases:
                        shifted_target = (
                            target_base[0],
                            (target_base[1] + target_word[0]) % 2**32,
                            target_base[2],
                            (target_base[3] + target_word[1]) % 2**32,
                        )
                        for rule in local_rules:
                            if (
                                rule["original_source_register"]
                                    != shifted_source[0]
                                or rule["candidate_source_register"]
                                    != shifted_source[2]
                            ):
                                continue
                            produced = (
                                str(rule["original_target_register"]),
                                (
                                    shifted_source[1]
                                    - int(rule["original_delta"])
                                ) % 2**32,
                                str(rule["candidate_target_register"]),
                                (
                                    shifted_source[3]
                                    - int(rule["candidate_delta"])
                                ) % 2**32,
                            )
                            if produced != shifted_target:
                                continue
                            candidates.append({
                                "word": {
                                    "original": target_word[0],
                                    "candidate": target_word[1],
                                },
                                "source_base": location_payload(source_base),
                                "target_base": location_payload(target_base),
                                "transfer": {
                                    "profile": "return_slot_frame_transfer_v1",
                                    "transfer": {
                                        "profile": "return_slot_affine_transfer_v2",
                                        "source": location_payload(shifted_source),
                                        "target": location_payload(shifted_target),
                                        "original_output_witness": rule[
                                            "original_output_witness"
                                        ],
                                        "candidate_output_witness": rule[
                                            "candidate_output_witness"
                                        ],
                                    },
                                    "memory": memory_claim,
                                },
                            })
                if not candidates:
                    return None
                exact_transfers.append(sorted(
                    candidates,
                    key=lambda claim: (
                        location_key(claim["source_base"]),
                        location_key(claim["target_base"]),
                    ),
                )[0])
            return exact_transfers

        def internal_transfer_claims(
            source_node_id: int,
            source_inventories: tuple[
                tuple[tuple[str, int, str, int], ...], ...
            ],
            target_inventories: tuple[
                tuple[tuple[str, int, str, int], ...], ...
            ],
            source_imports: tuple[tuple[str, ...], ...] | None = None,
            target_imports: tuple[tuple[str, ...], ...] | None = None,
            source_relations: tuple[tuple[str, ...], ...] | None = None,
            target_relations: tuple[tuple[str, ...], ...] | None = None,
            source_exact_words: tuple[
                tuple[tuple[int, int], ...], ...
            ] | None = None,
            target_exact_words: tuple[
                tuple[tuple[int, int], ...], ...
            ] | None = None,
            *,
            seed_active_frame_words: bool = True,
        ) -> list[dict[str, Any]] | None:
            if len(source_inventories) != len(target_inventories):
                return None
            source_imports = source_imports or tuple(
                () for _ in source_inventories
            )
            target_imports = target_imports or tuple(
                () for _ in target_inventories
            )
            source_relations = source_relations or tuple(
                () for _ in source_inventories
            )
            target_relations = target_relations or tuple(
                () for _ in target_inventories
            )
            source_exact_words = source_exact_words or tuple(
                () for _ in source_inventories
            )
            target_exact_words = target_exact_words or tuple(
                () for _ in target_inventories
            )
            if (
                len(source_imports) != len(source_inventories)
                or len(target_imports) != len(target_inventories)
                or len(source_relations) != len(source_inventories)
                or len(target_relations) != len(target_inventories)
                or len(source_exact_words) != len(source_inventories)
                or len(target_exact_words) != len(target_inventories)
            ):
                return None
            relation_row = register_relations.get("regions", [])[source_node_id]
            local_rules = relation_row.get(
                "return_slot_local_transfer_rules", []
            )
            original = behaviors[source_node_id].get("original_ir") or {}
            candidate = behaviors[source_node_id].get("candidate_ir") or {}
            inventory_claims = []
            for frame_index, (
                    source_inventory, target_inventory, source_frame_imports,
                    target_frame_imports, source_frame_relations,
                    target_frame_relations, source_frame_exact_words,
                    target_frame_exact_words,
                ) in enumerate(zip(
                source_inventories, target_inventories, source_imports,
                target_imports, source_relations, target_relations,
                source_exact_words, target_exact_words, strict=True
            )):
                if source_frame_imports != target_frame_imports:
                    return None
                if frame_index == 0:
                    frame_word_claims, frame_expression_claims = (
                        frame_relation_refresh_claims(
                            node_id, source_inventory,
                            source_frame_relations, source_frame_exact_words,
                        )
                    )
                    if not seed_active_frame_words:
                        frame_word_claims = ()
                else:
                    frame_word_claims = ()
                    frame_expression_claims = ()
                refreshed_registers = {
                    (
                        str(claim["output"]["original"]),
                        str(claim["output"]["candidate"]),
                    )
                    for claim in (
                        *frame_word_claims, *frame_expression_claims,
                    )
                }
                carried_relations = tuple(
                    relation_key for relation_key in source_frame_relations
                    if (
                        str(register_relation_payload(relation_key)["original"]),
                        str(register_relation_payload(relation_key)["candidate"]),
                    ) not in refreshed_registers
                )
                expected_target_relations = (
                    *carried_relations,
                    *(
                        register_relation_key(claim["output"])
                        for claim in (
                            *frame_word_claims, *frame_expression_claims,
                        )
                    ),
                )
                if target_frame_relations != expected_target_relations:
                    return None
                for relation_key in (
                    source_frame_imports if frame_index == 0 else ()
                ):
                    relation = import_relation_payload(relation_key)
                    if (
                        original.get("registers", {}).get(
                            relation["original"]
                        ) != {
                            "op": "input_reg",
                            "reg": relation["original"],
                        }
                        or candidate.get("registers", {}).get(
                            relation["candidate"]
                        ) != {
                            "op": "input_reg",
                            "reg": relation["candidate"],
                        }
                    ):
                        block(
                            "runtime_frame_import_behavior_clobbered",
                            f"internal product node {source_node_id} does not "
                            "preserve a requested runtime-frame import register",
                            "preserve every requested register exactly or remove "
                            "the unsupported callsite summary",
                        )
                        return None
                for relation_key in (
                    carried_relations if frame_index == 0 else ()
                ):
                    if not register_relation_behavior_preserved(
                        relation_key, original, candidate
                    ):
                        block(
                            "runtime_frame_register_relation_behavior_clobbered",
                            f"internal product node {source_node_id} does not "
                            "preserve a requested runtime-frame register relation",
                            "preserve both relation registers exactly or remove "
                            "the unsupported callsite summary",
                        )
                        return None
                transfers = []
                for target_location in target_inventory:
                    candidates = []
                    for source_location in source_inventory:
                        original_writes = write_witnesses(
                            original, source_location[0], source_location[1]
                        )
                        candidate_writes = write_witnesses(
                            candidate, source_location[2], source_location[3]
                        )
                        memory_claim = (
                            {
                                "profile": "affine_v1",
                                "offsets": location_payload(source_location),
                                "original_write_witnesses": original_writes,
                                "candidate_write_witnesses": candidate_writes,
                            }
                            if original_writes is not None
                            and candidate_writes is not None
                            else framed_memory_claim(
                                source_node_id, source_location
                            ) or protected_frame_memory_claim(
                                source_node_id, source_location
                            )
                        )
                        if memory_claim is None:
                            continue
                        for rule in local_rules:
                            if (
                                rule["original_source_register"]
                                    != source_location[0]
                                or rule["candidate_source_register"]
                                    != source_location[2]
                            ):
                                continue
                            produced = (
                                str(rule["original_target_register"]),
                                (
                                    source_location[1]
                                    - int(rule["original_delta"])
                                ) % 2**32,
                                str(rule["candidate_target_register"]),
                                (
                                    source_location[3]
                                    - int(rule["candidate_delta"])
                                ) % 2**32,
                            )
                            if produced != target_location:
                                continue
                            candidates.append({
                                "profile": "return_slot_frame_transfer_v1",
                                "transfer": {
                                    "profile": "return_slot_affine_transfer_v2",
                                    "source": location_payload(source_location),
                                    "target": location_payload(target_location),
                                    "original_output_witness": rule[
                                        "original_output_witness"
                                    ],
                                    "candidate_output_witness": rule[
                                        "candidate_output_witness"
                                    ],
                                },
                                "memory": memory_claim,
                            })
                    if not candidates:
                        return None
                    transfers.append(sorted(
                        candidates,
                        key=lambda claim: location_key(
                            claim["transfer"]["source"]
                        ),
                    )[0])
                exact_word_transfers = exact_word_transfer_claims(
                    source_node_id, source_inventory, target_inventory,
                    source_frame_exact_words, target_frame_exact_words,
                )
                if exact_word_transfers is None:
                    return None
                inventory_claims.append({
                    "profile": "return_slot_frame_inventory_transfer_v1",
                    "source": inventory_payload(
                        source_inventory, source_frame_imports,
                        source_frame_relations, source_frame_exact_words,
                    ),
                    "target": inventory_payload(
                        target_inventory, target_frame_imports,
                        target_frame_relations, target_frame_exact_words,
                    ),
                    "transfers": transfers,
                    "exact_word_transfers": exact_word_transfers,
                    "frame_exact_word_register_outputs":
                        list(frame_word_claims),
                    "frame_paired_expression_register_outputs":
                        list(frame_expression_claims),
                    "carried_relations": [
                        register_relation_payload(relation_key)
                        for relation_key in carried_relations
                    ],
                })
            return inventory_claims

        def external_jump_transfer_claims(
            source_node_id: int, continuation_target_id: int,
            source_locations: tuple[tuple[str, int, str, int], ...],
        ) -> list[dict[str, Any]] | None:
            site = external_thunk_by_source_continuation.get(
                (source_node_id, continuation_target_id)
            )
            if site is None:
                block(
                    "external_jump_runtime_site_missing",
                    f"external jump {source_node_id}->{continuation_target_id} lacks "
                    "a checked continuation-specific machine contract",
                    "add the exact import ABI, argument, memory, and world-effect contract",
                )
                return None
            contract_row = machine_contract_by_id.get(
                int(site["machine_contract_id"])
            )
            if contract_row is None:
                block(
                    "external_jump_machine_contract_missing",
                    f"external jump {source_node_id}->{continuation_target_id} "
                    "references a missing machine contract",
                    "regenerate the canonical machine-contract inventory",
                )
                return None
            relation_row = register_relations.get("regions", [])[source_node_id]
            local_rules = relation_row.get(
                "return_slot_local_transfer_rules", []
            )
            original = behaviors[source_node_id].get("original_ir") or {}
            candidate = behaviors[source_node_id].get("candidate_ir") or {}

            claims = []
            preserved = set(str(item) for item in contract_row[
                "preserved_registers"
            ])
            for source_location in source_locations:
                original_source_register, original_source_offset, \
                    candidate_source_register, candidate_source_offset = \
                    source_location
                original_writes = write_witnesses(
                    original, original_source_register, original_source_offset
                )
                candidate_writes = write_witnesses(
                    candidate, candidate_source_register, candidate_source_offset
                )
                if original_writes is None or candidate_writes is None:
                    return None
                candidates = []
                for rule in local_rules:
                    if (
                        rule["original_source_register"]
                            != original_source_register
                        or rule["candidate_source_register"]
                            != candidate_source_register
                    ):
                        continue
                    internal_location = (
                        str(rule["original_target_register"]),
                        (
                            original_source_offset
                            - int(rule["original_delta"])
                        ) % 2**32,
                        str(rule["candidate_target_register"]),
                        (
                            candidate_source_offset
                            - int(rule["candidate_delta"])
                        ) % 2**32,
                    )
                    boundary_location = (
                        internal_location[0],
                        (
                            internal_location[1]
                            - (4 if internal_location[0] == "esp" else 0)
                        ) % 2**32,
                        internal_location[2],
                        (
                            internal_location[3]
                            - (4 if internal_location[2] == "esp" else 0)
                        ) % 2**32,
                    )
                    if (
                        boundary_location[0] == "esp"
                        and boundary_location[2] == "esp"
                    ):
                        original_environment_delta = int(
                            contract_row["stack_result_delta"]
                        )
                        candidate_environment_delta = int(
                            contract_row["stack_result_delta"]
                        )
                    elif (
                        boundary_location[0] in preserved
                        and boundary_location[2] in preserved
                    ):
                        original_environment_delta = 0
                        candidate_environment_delta = 0
                    else:
                        continue
                    target_location = (
                        boundary_location[0],
                        (
                            boundary_location[1]
                            - original_environment_delta
                        ) % 2**32,
                        boundary_location[2],
                        (
                            boundary_location[3]
                            - candidate_environment_delta
                        ) % 2**32,
                    )
                    candidates.append((target_location, {
                        "profile": "external_jump_return_slot_transfer_claim_v1",
                        "machine_contract_id": int(contract_row["id"]),
                        "source": location_payload(source_location),
                        "internal_target": location_payload(internal_location),
                        "boundary_target": location_payload(boundary_location),
                        "target": location_payload(target_location),
                        "internal_rule": {
                            "original_source_register": original_source_register,
                            "candidate_source_register": candidate_source_register,
                            "original_target_register": internal_location[0],
                            "candidate_target_register": internal_location[2],
                            "original_output_witness": rule[
                                "original_output_witness"
                            ],
                            "candidate_output_witness": rule[
                                "candidate_output_witness"
                            ],
                            "original_delta": int(rule["original_delta"]),
                            "candidate_delta": int(rule["candidate_delta"]),
                        },
                        "result_rule": {
                            "source": location_payload(boundary_location),
                            "target": location_payload(target_location),
                            "original_delta": original_environment_delta,
                            "candidate_delta": candidate_environment_delta,
                        },
                        "memory_claim": {
                            "offsets": location_payload(source_location),
                            "original_write_witnesses": original_writes,
                            "candidate_write_witnesses": candidate_writes,
                        },
                    }))
                if not candidates:
                    return None
                claims.append(sorted(
                    candidates,
                    key=lambda item: location_rank(
                        source_location, item[0], source_node_id
                    ),
                )[0][1])
            return claims

        def direct_call_exact_word_seeds(
            source_node_id: int, target_node_id: int,
        ) -> tuple[tuple[int, int], ...]:
            matches = candidates_by_source_target.get(
                (source_node_id, target_node_id), []
            )
            if len(matches) != 1:
                return ()
            claim = matches[0].get("direct_call_stack_writes_claim")
            if not isinstance(claim, dict):
                claim = matches[0].get("direct_call_prepared_writes_claim")
            if not isinstance(claim, dict):
                return ()
            words: list[tuple[int, int]] = []
            for seed in claim.get("exact_word_seeds", []):
                exact_word = seed.get("exact_word", {})
                words.append((
                    int(exact_word["original_offset"]),
                    int(exact_word["candidate_offset"]),
                ))
            return tuple(words)

        pending: deque[tuple[
            int, tuple[int, ...],
            tuple[tuple[tuple[str, int, str, int], ...], ...],
            tuple[tuple[str, ...], ...],
            tuple[tuple[str, ...], ...],
            tuple[tuple[tuple[int, int], ...], ...],
        ]] = deque([(
            launch_root_node_id,
            tuple(launch_continuation_target_ids),
            launch_frame_inventories,
            tuple(() for _ in launch_continuation_target_ids),
            tuple(() for _ in launch_continuation_target_ids),
            launch_frame_exact_words,
        )])
        while pending:
            (
                node_id, calls, frame_inventories, frame_imports,
                frame_relations, frame_exact_words,
            ) = pending.popleft()
            if (
                len(frame_inventories) != len(calls)
                or len(frame_imports) != len(calls)
                or len(frame_relations) != len(calls)
                or len(frame_exact_words) != len(calls)
            ):
                block(
                    "runtime_frame_offset_inventory_incomplete",
                    f"product node {node_id} has {len(calls)} runtime frames but "
                    f"{len(frame_inventories)} checked return-slot inventories and "
                    f"{len(frame_imports)} preserved-import inventories and "
                    f"{len(frame_relations)} preserved-register inventories",
                    "propagate checked return-slot aliases and preserved facts for "
                    "every live runtime frame",
                )
                continue
            if any(
                not inventory or len(inventory) > max_frame_aliases
                or len(set(inventory)) != len(inventory)
                for inventory in frame_inventories
            ):
                block(
                    "runtime_frame_alias_inventory_invalid",
                    f"product node {node_id} has an empty, duplicate, or oversized "
                    "return-slot alias inventory",
                    "emit one to eight unique checked aliases for every live frame",
                )
                continue
            if any(
                len(words) > 16 or len(set(words)) != len(words)
                or any(
                    original < 0 or original > 65532
                    or candidate < 0 or candidate > 65532
                    for original, candidate in words
                )
                for words in frame_exact_words
            ):
                block(
                    "runtime_frame_exact_word_inventory_invalid",
                    f"product node {node_id} has a duplicate, out-of-range, or "
                    "oversized exact-word inventory",
                    "emit no more than sixteen unique checked frame-relative words",
                )
                continue
            if any(
                len(relations) > max_frame_preserved_imports
                or len(set(relations)) != len(relations)
                for relations in frame_relations
            ):
                block(
                    "runtime_frame_register_relation_inventory_invalid",
                    f"product node {node_id} has a duplicate or oversized "
                    "preserved-register inventory",
                    "emit no more than eight unique checked register relations for "
                    "every live frame",
                )
                continue
            if any(
                len(imports) > max_frame_preserved_imports
                or len(set(imports)) != len(imports)
                for imports in frame_imports
            ):
                block(
                    "runtime_frame_import_inventory_invalid",
                    f"product node {node_id} has a duplicate or oversized "
                    "preserved-import inventory",
                    "emit no more than eight unique checked import-register "
                    "relations for every live frame",
                )
                continue
            state = {
                "node_id": node_id,
                "calls": list(calls),
                "frame_offsets": [
                    inventory_payload(
                        inventory, imports, relations, exact_words,
                    )
                    for inventory, imports, relations, exact_words in zip(
                        frame_inventories, frame_imports, frame_relations,
                        frame_exact_words,
                        strict=True,
                    )
                ],
            }
            profile_state_key = linked_control_state_key(state)
            if profile_state_key not in represented_linked_control_states:
                represented_linked_control_states.add(profile_state_key)
                control_states.append(state)
            expansion_state_key = linked_control_expansion_key(state)
            if expansion_state_key in expanded_linked_control_states:
                continue
            expanded_linked_control_states.add(expansion_state_key)
            # One local witness per finite expansion context is sufficient.
            # Dormant tails are carried by the Lean linked-stack invariant;
            # retaining every concrete tail recreates an exponential call-tree.
            control_witness_states.append(state)
            control_states_by_node.setdefault(node_id, []).append(state)
            original_outcome = behaviors[node_id].get("original_ir", {}).get("outcome", {})
            candidate_outcome = behaviors[node_id].get("candidate_ir", {}).get("outcome", {})
            operation = original_outcome.get("op")
            state_incomplete = False
            if operation != candidate_outcome.get("op"):
                block(
                    "control_profile_outcome_mismatch",
                    f"product node {node_id} has different original and candidate control outcomes",
                    "add a paired finite-path normalization certificate",
                )
                continue
            successor_targets: list[tuple[
                int, tuple[int, ...], str,
            ]] = []
            if operation == "jump":
                if original_outcome.get("target") != candidate_outcome.get("target"):
                    state_incomplete = True
                else:
                    successor_targets.append((
                        int(original_outcome["target"]), calls, "transfer",
                    ))
            elif operation == "branch":
                original_condition = original_outcome.get("condition") or {}
                candidate_condition = candidate_outcome.get("condition") or {}
                original_constant = _semantic_constant_bool(original_condition)
                candidate_constant = _semantic_constant_bool(candidate_condition)
                def active_branch_targets(
                    outcome: dict[str, Any], constant: bool | None,
                ) -> tuple[int, ...]:
                    if constant is True:
                        return (int(outcome["taken"]),)
                    if constant is False:
                        return (int(outcome["fallthrough"]),)
                    return tuple(dict.fromkeys((
                        int(outcome["taken"]),
                        int(outcome["fallthrough"]),
                    )))

                original_targets = active_branch_targets(
                    original_outcome, original_constant
                )
                candidate_targets = active_branch_targets(
                    candidate_outcome, candidate_constant
                )
                if set(original_targets) != set(candidate_targets):
                    state_incomplete = True
                else:
                    successor_targets.extend(
                        (target, calls, "transfer")
                        for target in original_targets
                    )
            elif operation == "call":
                if any(
                    original_outcome.get(field) != candidate_outcome.get(field)
                    for field in ("target", "continuation")
                ):
                    state_incomplete = True
                else:
                    successor_targets.append((
                        int(original_outcome["target"]),
                        (int(original_outcome["continuation"]), *calls),
                        "call",
                    ))
            elif operation == "call_unmapped_return":
                block(
                    "unmapped_return_call_frame_unsupported",
                    f"direct call node {node_id} has return addresses outside the "
                    "canonical code map",
                    "emit a checked must-not-return call-frame token tied to the "
                    "terminal return-address inventory",
                )
                state_incomplete = True
                continue
            elif operation == "external_call":
                if any(frame_imports) and not external_frame_imports_preserved(
                    node_id, original_outcome.get("import") or {}, frame_imports
                ):
                    state_incomplete = True
                    continue
                if any(frame_relations) and not external_frame_relations_preserved(
                    node_id, original_outcome.get("import") or {}, frame_relations
                ):
                    state_incomplete = True
                    continue
                if any(
                    original_outcome.get(field) != candidate_outcome.get(field)
                    for field in ("import", "continuation")
                ):
                    state_incomplete = True
                elif (
                    machine_contract_by_import.get(
                        _semantic_external_target_identity(
                            original_outcome.get("import") or {}
                        ), {}
                    ).get("disposition") == "terminates"
                ):
                    pass
                else:
                    successor_targets.append((
                        int(original_outcome["continuation"]), calls,
                        "external",
                    ))
            elif operation in {"bulk_copy", "atomic_compare_exchange"}:
                if any(frame_imports):
                    block(
                        "runtime_frame_import_external_crossing_unsupported",
                        f"environment operation node {node_id} crosses an active "
                        "preserved-import runtime frame",
                        "supply an environment-aware preservation theorem before "
                        "crossing the external boundary",
                    )
                    state_incomplete = True
                    continue
                if any(frame_relations):
                    block(
                        "runtime_frame_register_relation_environment_crossing_unsupported",
                        f"environment operation node {node_id} crosses an active "
                        "preserved-register runtime frame",
                        "add an operation-specific checked register/world transfer theorem",
                    )
                    state_incomplete = True
                    continue
                if original_outcome.get("continuation") != candidate_outcome.get(
                    "continuation"
                ):
                    state_incomplete = True
                else:
                    successor_targets.append((
                        int(original_outcome["continuation"]), calls,
                        "external",
                    ))
            elif operation == "external_jump":
                if any(frame_imports) and not external_frame_imports_preserved(
                    node_id, original_outcome.get("import") or {}, frame_imports
                ):
                    state_incomplete = True
                    continue
                if any(frame_relations) and not external_frame_relations_preserved(
                    node_id, original_outcome.get("import") or {}, frame_relations
                ):
                    state_incomplete = True
                    continue
                if original_outcome.get("import") != candidate_outcome.get("import"):
                    state_incomplete = True
                elif not calls:
                    block(
                        "top_level_external_jump_unsupported",
                        f"product node {node_id} reaches an import jump without a checked return frame",
                        "map the importing call and propagate its runtime continuation frame",
                    )
                    state_incomplete = True
                elif (
                    machine_contract_by_import.get(
                        _semantic_external_target_identity(
                            original_outcome.get("import") or {}
                        ), {}
                    ).get("disposition") == "terminates"
                ):
                    pass
                else:
                    successor_targets.append((
                        calls[0], calls[1:], "external_pop",
                    ))
            elif operation == "indirect_call":
                decoded_control = decoded_control_by_node.get(node_id, {})
                continuation_matches = (
                    original_outcome.get("continuation") ==
                    candidate_outcome.get("continuation")
                )
                continuation = int(original_outcome.get("continuation", -1))
                register_external_site = (
                    checked_register_external_site(node_id, continuation)
                    if continuation_matches else None
                )
                if register_external_site is not None:
                    machine_contract = machine_contract_by_id[
                        int(register_external_site["machine_contract_id"])
                    ]
                    if any(frame_imports) and not external_frame_imports_preserved(
                        node_id,
                        machine_contract.get("import") or {},
                        frame_imports,
                    ):
                        state_incomplete = True
                    elif (
                        any(frame_relations)
                        and not external_frame_relations_preserved(
                            node_id,
                            machine_contract.get("import") or {},
                            frame_relations,
                        )
                    ):
                        state_incomplete = True
                    elif machine_contract.get("disposition") != "terminates":
                        successor_targets.append((
                            continuation, calls, "external",
                        ))
                elif (
                    decoded_control.get("profile") not in {
                        "immutable_relocated_function_pointer_call_v1",
                        "fixed_static_function_pointer_call_v1",
                        "inductive_fixed_code_pointer_register_call_v1",
                    }
                    or not continuation_matches
                ):
                    block(
                        "bounded_indirect_control_profile_unmet",
                        f"product node {node_id} has no checked finite indirect-call target",
                        "classify the target by provenance and emit a checked finite target set",
                    )
                    state_incomplete = True
                else:
                    successor_targets.append((
                        int(decoded_control["target_id"]),
                        (continuation, *calls),
                        "call",
                    ))
            elif operation == "indirect_jump":
                decoded_control = decoded_control_by_node.get(node_id, {})
                if decoded_control.get("profile") not in {
                    "immutable_relocated_function_pointer_jump_v1",
                    "fixed_static_function_pointer_jump_v1",
                    "fixed_code_address_indirect_jump_v1",
                }:
                    block(
                        "bounded_indirect_control_profile_unmet",
                        f"product node {node_id} has no checked finite indirect-jump target",
                        "classify the target by provenance and emit a checked finite target set",
                    )
                    state_incomplete = True
                else:
                    successor_targets.append((
                        int(decoded_control["target_id"]), calls,
                        "transfer",
                    ))
            elif operation == "returned":
                if calls:
                    successor_targets.append((calls[0], calls[1:], "return_pop"))
            else:
                block(
                    "control_profile_outcome_unsupported",
                    f"product node {node_id} uses unsupported control outcome {operation!r}",
                    "add the corresponding checked control-state transition",
                )
                state_incomplete = True
            if state_incomplete:
                if not any(
                    item["code"] == "control_profile_outcome_mismatch"
                    for item in blockers
                ):
                    block(
                        "control_profile_outcome_mismatch",
                        f"product node {node_id} has mismatched control destinations",
                        "repair the mapping or add a paired finite-path normalization certificate",
                    )
                continue
            post_internal_frame_relations = frame_relations_after_internal(
                node_id, frame_inventories, frame_relations, frame_exact_words
            )
            active_refreshes = active_frame_relation_refreshes(
                node_id, frame_inventories, frame_relations, frame_exact_words
            )
            refreshable_active_relation_keys = frozenset(
                relation_key for relation_key in (
                    frame_relations[0] if frame_relations else ()
                )
                if (
                    str(register_relation_payload(relation_key)["original"]),
                    str(register_relation_payload(relation_key)["candidate"]),
                ) in active_refreshes
            )
            for target_id, successor_calls, frame_operation in successor_targets:
                target_node_id = node_by_target.get(target_id)
                if target_node_id is None:
                    block(
                        "control_profile_target_unmapped",
                        f"control target {target_id} from product node {node_id} has no product node",
                        "close the rooted decoded-control mapping frontier",
                    )
                    state_incomplete = True
                    break
                if frame_operation == "transfer":
                    if not internal_frame_relations_preserved(
                        node_id,
                        _frame_relations_requiring_internal_preservation(
                            frame_relations, frame_operation
                        ),
                        refreshable_active_relations=
                            refreshable_active_relation_keys,
                    ):
                        state_incomplete = True
                        break
                    successor_locations = transfer_locations(
                        node_id, target_node_id, frame_inventories
                    )
                    successor_imports = frame_imports
                    successor_relations = post_internal_frame_relations
                    successor_exact_words = frame_exact_words
                    if successor_locations is None:
                        state_incomplete = True
                        break
                elif frame_operation == "call":
                    if not internal_frame_relations_preserved(
                        node_id,
                        _frame_relations_requiring_internal_preservation(
                            frame_relations, frame_operation
                        ),
                        refreshable_active_relations=
                            refreshable_active_relation_keys,
                    ):
                        state_incomplete = True
                        break
                    transferred_outer = transfer_locations(
                        node_id, target_node_id, frame_inventories
                    )
                    if transferred_outer is None:
                        state_incomplete = True
                        break
                    matching_edges = register_edges_by_pair.get(
                        (node_id, target_node_id), []
                    )
                    seed = (
                        matching_edges[0].get("return_slot_seed")
                        if len(matching_edges) == 1 else None
                    )
                    if seed is None:
                        block(
                            "runtime_frame_call_seed_missing",
                            f"call transition {node_id}->{target_node_id} lacks a "
                            "checked runtime-frame seed",
                            "emit a decoded call-push claim and zero-offset frame location",
                        )
                        state_incomplete = True
                        break
                    continuation_node_id = node_by_target.get(
                        int(successor_calls[0])
                    )
                    if continuation_node_id is None:
                        block(
                            "direct_call_continuation_unmapped",
                            f"call transition {node_id}->{target_node_id} has an "
                            "unmapped continuation",
                            "close the decoded continuation mapping frontier",
                        )
                        state_incomplete = True
                        break
                    seeded_facts = callsite_preserved_facts(
                        node_id, target_node_id, continuation_node_id
                    )
                    if seeded_facts is None:
                        state_incomplete = True
                        break
                    seeded_imports, seeded_relations = seeded_facts
                    successor_locations = (
                        (location_key(seed["offsets"]),), *transferred_outer,
                    )
                    successor_imports = (seeded_imports, *frame_imports)
                    successor_relations = (
                        seeded_relations, *post_internal_frame_relations
                    )
                    successor_exact_words = (
                        direct_call_exact_word_seeds(node_id, target_node_id),
                        *frame_exact_words,
                    )
                elif frame_operation == "return_pop":
                    if not internal_frame_relations_preserved(
                        node_id,
                        _frame_relations_requiring_internal_preservation(
                            frame_relations, frame_operation
                        ),
                    ):
                        state_incomplete = True
                        break
                    return_row = register_relations.get("regions", [])[node_id]
                    active_inventory = frame_inventories[0]
                    active_locations = tuple(
                        location for location in active_inventory
                        if return_frame_claim_for_location(
                            return_row, location
                        ) is not None
                    )
                    if not active_locations:
                        block(
                            "return_active_frame_location_unchecked",
                            f"return node {node_id} does not read the active frame at "
                            f"any checked alias in {active_inventory}",
                            "emit a checked return-pop frame claim for the active location",
                        )
                        state_incomplete = True
                        break
                    successor_locations = choose_location_transfers(
                        source_node_id=node_id,
                        target_node_id=target_node_id,
                        target_description=f"return to {target_node_id}",
                        source_inventories=frame_inventories[1:],
                        claims=return_row.get(
                            "return_slot_return_transfer_claims", []
                        ),
                        rules=return_row.get(
                            "return_slot_return_transfer_rules", []
                        ),
                    )
                    if successor_locations is None:
                        state_incomplete = True
                        break
                    successor_imports = frame_imports[1:]
                    successor_relations = frame_relations[1:]
                    successor_exact_words = frame_exact_words[1:]
                elif frame_operation == "external_pop":
                    active_inventory = frame_inventories[0]
                    if ("esp", 0, "esp", 0) not in active_inventory:
                        block(
                            "external_jump_active_frame_location_unmet",
                            f"external jump {node_id}->{target_node_id} has active "
                            f"runtime frame aliases {active_inventory}",
                            "propagate the decoded direct-call return slot to ESP+0",
                        )
                        state_incomplete = True
                        break
                    outer_claims = external_jump_transfer_claims(
                        node_id, target_id,
                        tuple(
                            inventory[0]
                            for inventory in frame_inventories[1:]
                        ),
                    )
                    if outer_claims is None:
                        block(
                            "external_jump_outer_frame_transfer_incomplete",
                            f"external jump {node_id}->{target_node_id} cannot "
                            f"transfer {len(frame_inventories) - 1} outer runtime frames",
                            "emit decoded thunk, return-slot normalization, write, and ABI witnesses",
                        )
                        state_incomplete = True
                        break
                    successor_locations = tuple(
                        (location_key(claim["target"]),)
                        for claim in outer_claims
                    )
                    successor_imports = frame_imports[1:]
                    successor_relations = frame_relations[1:]
                    successor_exact_words = frame_exact_words[1:]
                else:
                    successor_locations = external_transfer_locations(
                        node_id, target_node_id, frame_inventories
                    )
                    if successor_locations is None:
                        state_incomplete = True
                        break
                    successor_imports = frame_imports
                    successor_relations = frame_relations
                    successor_exact_words = frame_exact_words
                pending.append((
                    target_node_id, successor_calls, successor_locations,
                    successor_imports, successor_relations, successor_exact_words,
                ))

    linked_control, rejected_linked_control_links = (
        _retain_checked_linked_control_links(
            project_linked_control_profile(
                control_witness_states, behaviors=behaviors, nodes=nodes
            )
        )
    )
    for rejected_link in rejected_linked_control_links:
        block(
            "linked_control_resume_state_profile_unmet",
            "linked control link from target "
            f"{rejected_link['call_source_target_id']} to resume node "
            f"{rejected_link['resume_node_id']} has no checked depth-one "
            "resume-state witness",
            "construct a checked depth-one resume state before admitting the link",
        )
    linked_control["fixed_point"] = {
        "status": "reached",
        "profile_state_count": len(represented_linked_control_states),
        "expanded_state_count": len(expanded_linked_control_states),
        "transition_witness_state_count": len(control_witness_states),
        "tail_model": "lean_checked_linked_runtime_call_stack",
    }
    affine_linked_control = (
        affine_linked_control_payload(
            runtime_frame_affine=runtime_frame_affine,
            linked_control=linked_control,
            product_graph=product_graph,
            behaviors=behaviors,
            regions=contract.get("regions"),
            register_relations=register_relations,
            physical_state_only_region_indices=physical_state_only_region_indices,
        )
        if runtime_frame_affine is not None
        else None
    )
    control_witness_expansion_keys = {
        linked_control_expansion_key(state)
        for state in control_witness_states
    }
    control_profile_node_ids = {
        int(state["node_id"]) for state in control_states
    }

    register_edge_by_source_target = {
        (int(edge["source_region_index"]), int(edge["target_region_index"])): edge
        for edge in register_relations.get("edges", [])
    }
    reachable_node_ids = [
        int(node_id) for node_id in evidence.get("declared_reachable_node_ids", [])
    ]
    reachable_node_id_set = set(reachable_node_ids)
    if (
        reachable_node_ids != sorted(reachable_node_id_set)
        or any(node_id < 0 or node_id >= len(nodes) for node_id in reachable_node_ids)
        or any(root not in reachable_node_id_set for root in roots)
    ):
        block(
            "declared_reachability_inventory_invalid",
            "the declared reachable-node inventory is not canonical or omits a root",
            "regenerate one sorted unique in-range reachability inventory containing every root",
        )

    node_steps: list[dict[str, Any]] = []
    has_guarded_branch = False
    has_internal_call = False
    has_internal_return = False
    has_external_call = False
    has_bounded_indirect = False
    has_paired_stack_write = False
    returned_region_indices: list[int] = []
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
        if any(edge_id < 0 or edge_id >= len(edges) for edge_id in outgoing):
            block(
                "product_edge_index_invalid",
                f"product node {node_id} references a missing outgoing edge",
                "regenerate the indexed product graph",
            )
            continue
        # Lean checks that this root-containing inventory is closed under every
        # feasible decoded edge.  Behavioral certificates are therefore needed
        # only for its members; executable-byte and graph-index validation still
        # cover the complete canonical inventory.
        if node_id not in reachable_node_id_set:
            continue
        if len(outgoing) not in {0, 1, 2}:
            block(
                "multi_exit_node_composition_pending",
                f"reachable product node {node_id} has {len(outgoing)} outgoing edges",
                "derive guard-exhaustive node steps from all decoded outgoing edges",
            )
            continue
        true_guard = {"op": "bool_constant", "value": True}
        outcomes = [
            behaviors[node_id].get("original_ir", {}).get("outcome", {}),
            behaviors[node_id].get("candidate_ir", {}).get("outcome", {}),
        ]
        control_rows = control_states_by_node.get(node_id, [])
        if (
            not control_rows
            and node_id not in control_profile_node_ids
            and node_id not in protocol_callback_contract_by_node
        ):
            node_steps.append({
                "kind": "control_unrepresented",
                "profile": "control-state-unrepresented-v1",
                "node_id": node_id,
                "region_index": node_id,
                "target_id": target_id,
                "edges": [
                    {
                        "edge_id": edge_id,
                        "target_node_id": int(edges[edge_id]["target_node_id"]),
                        "target_region_index": int(
                            edges[edge_id]["target_node_id"]
                        ),
                        "target_target_id": int(
                            edges[edge_id]["target_target_id"]
                        ),
                    }
                    for edge_id in outgoing
                ],
            })
            continue
        if not outgoing:
            relation_row = register_relations.get("regions", [])[node_id]
            if all(outcome.get("op") == "external_jump" for outcome in outcomes):
                if not control_rows or any(
                    not control_row["calls"] for control_row in control_rows
                ):
                    block(
                        "external_jump_control_profile_unmet",
                        f"import-thunk node {node_id} lacks a checked active caller frame",
                        "generate continuation-specific external-jump cases for every allowed runtime frame",
                    )
                    continue
                external_jump_cases: list[dict[str, Any]] = []
                external_jump_kind: str | None = None
                external_jump_cases_complete = True
                for control_row in control_rows:
                    calls = control_row["calls"]
                    continuation_target_id = int(calls[0])
                    external_site = external_thunk_by_source_continuation.get(
                        (node_id, continuation_target_id)
                    )
                    if external_site is None:
                        block(
                            "external_jump_site_missing",
                            f"import-thunk node {node_id} control state "
                            f"{calls} lacks one checked site",
                            "close the thunk identity, ABI argument, boundary, and continuation evidence",
                        )
                        external_jump_cases_complete = False
                        break
                    frame_offsets = control_row["frame_offsets"]
                    if (
                        len(frame_offsets) != len(control_row["calls"])
                        or not frame_offsets
                        or ("esp", 0, "esp", 0)
                            not in inventory_key(frame_offsets[0])
                    ):
                        block(
                            "external_jump_frame_offset_missing",
                            f"import-thunk node {node_id} lacks a checked active "
                            "ESP+0 return slot",
                            "propagate every caller return slot into the thunk control state",
                        )
                        external_jump_cases_complete = False
                        break
                    machine_contract = machine_contract_by_id.get(
                        int(external_site["machine_contract_id"])
                    )
                    if machine_contract is None:
                        block(
                            "external_jump_machine_contract_missing",
                            f"import-thunk node {node_id} has no resolved machine contract",
                            "declare one complete machine-level import contract",
                        )
                        external_jump_cases_complete = False
                        break
                    case_kind = (
                        "external_terminate"
                        if machine_contract.get("disposition") == "terminates"
                        else "external_jump"
                    )
                    if (
                        external_jump_kind is not None
                        and external_jump_kind != case_kind
                    ):
                        block(
                            "external_jump_disposition_ambiguous",
                            f"import-thunk node {node_id} has inconsistent call dispositions",
                            "use one machine-level disposition for each imported target",
                        )
                        external_jump_cases_complete = False
                        break
                    external_jump_kind = case_kind
                    case_payload: dict[str, Any] = {
                        "control_state": control_row,
                        "external_site": external_site,
                        "machine_contract": machine_contract,
                        "decoded_import": outcomes[0].get("import"),
                    }
                    if case_kind == "external_jump":
                        target_node_id = node_by_target.get(
                            continuation_target_id, -1
                        )
                        if target_node_id < 0:
                            block(
                                "external_jump_continuation_unmapped",
                                f"import-thunk node {node_id} continuation "
                                f"{continuation_target_id} is unmapped",
                                "add the continuation to the checked product graph",
                            )
                            external_jump_cases_complete = False
                            break
                        active_imports = tuple(sorted(
                            inventory_import_key(frame_offsets[0])
                        ))
                        target_imports = tuple(sorted(
                            import_relation_key(relation)
                            for relation in regions[target_node_id].get(
                                "input_import_relations", []
                            )
                        ))
                        declared_target_imports = tuple(sorted(
                            import_relation_key(relation)
                            for relation in external_site.get(
                                "target_import_relations_from_active_frame", []
                            )
                        ))
                        if (
                            active_imports != target_imports
                            or declared_target_imports != target_imports
                        ):
                            block(
                                "external_jump_target_import_inventory_mismatch",
                                f"import-thunk node {node_id} active frame does not "
                                f"exactly supply continuation {target_node_id}'s "
                                "import-register invariant",
                                "carry every continuation import fact in the active "
                                "runtime frame and declare the same site-local inventory",
                            )
                            external_jump_cases_complete = False
                            break
                        outer_transfers = external_jump_transfer_claims(
                            node_id,
                            continuation_target_id,
                            tuple(
                                inventory_key(item)[0]
                                for item in frame_offsets[1:]
                            ),
                        )
                        if outer_transfers is None:
                            block(
                                "external_jump_outer_frame_transfer_incomplete",
                                f"import-thunk node {node_id} cannot transfer "
                                "every outer runtime frame",
                                "emit decoded thunk, normalization, memory, and ABI transfer claims",
                            )
                            external_jump_cases_complete = False
                            break
                        outer_claims = [
                            {
                                "profile":
                                    "external_jump_return_slot_inventory_transfer_v1",
                                "source": source_inventory,
                                "target": inventory_payload((
                                    location_key(transfer["target"]),
                                ), inventory_import_key(source_inventory),
                                    inventory_register_key(source_inventory),
                                    inventory_exact_key(source_inventory)),
                                "transfers": [transfer],
                                "exact_word_transfers": exact_word_transfer_claims(
                                    node_id,
                                    inventory_key(source_inventory),
                                    (location_key(transfer["internal_target"]),),
                                    inventory_exact_key(source_inventory),
                                    inventory_exact_key(source_inventory),
                                ),
                            }
                            for source_inventory, transfer in zip(
                                frame_offsets[1:], outer_transfers, strict=True
                            )
                        ]
                        if any(
                            claim["exact_word_transfers"] is None
                            for claim in outer_claims
                        ):
                            block(
                                "external_jump_exact_word_transfer_incomplete",
                                f"import-thunk node {node_id} cannot preserve "
                                "every outer frame-relative exact word",
                                "emit checked pre-import write-disjointness witnesses",
                            )
                            external_jump_cases_complete = False
                            break
                        target_offsets = [
                            claim["target"] for claim in outer_claims
                        ]
                        target_control_rows = [
                            row for row in control_states_by_node.get(
                                target_node_id, []
                            )
                            if row["calls"] == control_row["calls"][1:]
                            and row["frame_offsets"] == target_offsets
                        ]
                        if len(target_control_rows) != 1:
                            block(
                                "external_jump_target_control_state_missing",
                                f"import-thunk node {node_id} has no unique "
                                "checked outer-frame successor",
                                "regenerate rooted control closure from the checked thunk transfers",
                            )
                            external_jump_cases_complete = False
                            break
                        case_payload.update({
                            "target_control_state": target_control_rows[0],
                            "return_slot_external_jump_transfer_claims":
                                outer_claims,
                            "target_node_id": target_node_id,
                            "target_region_index": target_node_id,
                            "target_target_id": continuation_target_id,
                        })
                    external_jump_cases.append(case_payload)
                if not external_jump_cases_complete:
                    continue
                external_jump_step = {
                    "kind": external_jump_kind,
                    "node_id": node_id,
                    "region_index": node_id,
                    "target_id": target_id,
                    "edges": [],
                }
                if len(external_jump_cases) == 1:
                    external_jump_step.update(external_jump_cases[0])
                else:
                    external_jump_step["cases"] = external_jump_cases
                node_steps.append(external_jump_step)
                has_external_call = True
                continue
            if (
                any(outcome.get("op") != "returned" for outcome in outcomes)
                or relation_row.get("return_pop_claim") is None
                or relation_row.get("return_pop_claim", {}).get("profile")
                    != "esp_relative_return_pop_v1"
                or not control_rows
            ):
                block(
                    "return_node_profile_unmet",
                    f"product node {node_id} is not a checked finite-control return",
                    "emit a return-pop claim and checked runtime-frame control states",
                )
                continue
            if any(bool(row["calls"]) != bool(control_rows[0]["calls"])
                   for row in control_rows):
                block(
                    "return_control_profile_ambiguous",
                    f"return node {node_id} is both terminal and internally framed",
                    "split terminal and internal return targets into distinct product nodes",
                )
                continue
            if control_rows[0]["calls"]:
                original_return_writes = (
                    behaviors[node_id].get("original_ir", {}).get("writes") or []
                )
                candidate_return_writes = (
                    behaviors[node_id].get("candidate_ir", {}).get("writes") or []
                )
                return_writes_claim = None
                if original_return_writes or candidate_return_writes:
                    return_writes_claim = _paired_prepared_word_writes_claim(
                        region,
                        behaviors[node_id],
                        list(contract.get("static_word_relation_slots", [])),
                        static_dynamic_pointer_slots=list(
                            contract.get("static_dynamic_pointer_slots", [])
                        ),
                    )
                return_cases: list[dict[str, Any]] = []
                return_cases_complete = True
                for control_row in control_rows:
                    calls = list(control_row["calls"])
                    active_inventory_payload = control_row["frame_offsets"][0]
                    frame_exact_return_writes_claim = None
                    if (
                        (original_return_writes or candidate_return_writes)
                        and return_writes_claim is None
                    ):
                        frame_exact_return_writes_claim = (
                            _frame_exact_stack_word_writes_claim(
                                region, behaviors[node_id],
                                active_inventory_payload,
                            )
                        )
                        if frame_exact_return_writes_claim is None:
                            block(
                                "return_paired_memory_update_incomplete",
                                f"return node {node_id} has decoded writes outside "
                                "the checked StateRel and runtime-frame update grammars",
                                "classify each return-side write with a checked stack, "
                                "static, dynamic, pointer-slot, or exact-frame witness",
                            )
                            return_cases_complete = False
                            break
                    active_frame_imports = inventory_import_key(
                        active_inventory_payload
                    )
                    active_frame_relations = inventory_register_key(
                        active_inventory_payload
                    )
                    active_inventory = inventory_key(active_inventory_payload)
                    return_candidates = [
                        (location, return_frame_claim_for_location(
                            relation_row, location
                        ))
                        for location in active_inventory
                    ]
                    return_candidates = [
                        item for item in return_candidates if item[1] is not None
                    ]
                    return_frame_claim = (
                        sorted(return_candidates, key=lambda item: item[0])[0][1]
                        if return_candidates else None
                    )
                    if return_frame_claim is None:
                        block(
                            "return_runtime_frame_claim_missing",
                            f"return node {node_id} lacks a checked live-frame "
                            "return-slot claim",
                            "emit a return-pop frame claim for every active "
                            "continuation shape",
                        )
                        return_cases_complete = False
                        break
                    continuation_target_id = int(calls[0])
                    target_node_id = node_by_target.get(
                        continuation_target_id, -1
                    )
                    if target_node_id < 0:
                        block(
                            "return_continuation_unmapped",
                            f"return node {node_id} continuation "
                            f"{continuation_target_id} is unmapped",
                            "add the continuation to the checked product graph",
                        )
                        return_cases_complete = False
                        break
                    target_control_rows = [
                        row for row in control_states_by_node.get(
                            target_node_id, []
                        )
                        if row["calls"] == calls[1:]
                    ]
                    if len(target_control_rows) != 1:
                        block(
                            "return_target_control_state_missing",
                            f"return node {node_id} has no unique checked successor "
                            "control state for its remaining runtime frames",
                            "regenerate rooted control closure from the checked "
                            "return transfer",
                        )
                        return_cases_complete = False
                        break
                    target_control_row = target_control_rows[0]
                    source_outer_inventories = tuple(
                        inventory_key(item)
                        for item in control_row["frame_offsets"][1:]
                    )
                    target_inventories = tuple(
                        inventory_key(item)
                        for item in target_control_row["frame_offsets"]
                    )
                    outer_frame_claims = internal_transfer_claims(
                        node_id, source_outer_inventories, target_inventories,
                        tuple(
                            inventory_import_key(item)
                            for item in control_row["frame_offsets"][1:]
                        ),
                        tuple(
                            inventory_import_key(item)
                            for item in target_control_row["frame_offsets"]
                        ),
                        tuple(
                            inventory_register_key(item)
                            for item in control_row["frame_offsets"][1:]
                        ),
                        tuple(
                            inventory_register_key(item)
                            for item in target_control_row["frame_offsets"]
                        ),
                        source_exact_words=tuple(
                            inventory_exact_key(item)
                            for item in control_row["frame_offsets"][1:]
                        ),
                        target_exact_words=tuple(
                            inventory_exact_key(item)
                            for item in target_control_row["frame_offsets"]
                        ),
                        seed_active_frame_words=False,
                    )
                    if outer_frame_claims is None:
                        block(
                            "return_outer_frame_transfer_incomplete",
                            f"return node {node_id} cannot preserve every "
                            "remaining runtime frame",
                            "emit checked register, memory, and import transfers "
                            "for each outer frame",
                        )
                        return_cases_complete = False
                        break
                    stack_transfers = _stack_window_transfer_claims(
                        region, regions[target_node_id], behaviors[node_id]
                    )
                    if stack_transfers is None:
                        block(
                            "return_stack_window_transfer_incomplete",
                            f"return node {node_id} cannot establish continuation "
                            f"{target_node_id}'s stack windows",
                            "strengthen the checked stack windows or support the "
                            "decoded ESP transfer",
                        )
                        return_cases_complete = False
                        break
                    target_region = regions[target_node_id]
                    target_relation_row = register_relations.get(
                        "regions", []
                    )[target_node_id]
                    carried_register_relations = [
                        frame_register_relation_payload(key)
                        for key in active_frame_relations
                    ]
                    target_input_relations = list(
                        target_relation_row.get("inputs", [])
                    )
                    if (
                        any(
                            target_input_relations.count(relation) != 1
                            for relation in carried_register_relations
                        )
                        or len({
                            (relation["original"], relation["candidate"])
                            for relation in carried_register_relations
                        }) != len(carried_register_relations)
                    ):
                        block(
                            "return_active_frame_register_relation_mismatch",
                            f"return node {node_id} active frame register relations "
                            f"do not exactly occur in continuation {target_node_id}",
                            "bind each caller-local relation to one exact continuation "
                            "input relation",
                        )
                        return_cases_complete = False
                        break
                    residual_target_inputs = [
                        relation for relation in target_input_relations
                        if relation not in carried_register_relations
                    ]
                    target_output_claims = (
                        _target_shaped_register_output_claims_with_stack_windows(
                            relation_row, {
                                **target_relation_row,
                                "inputs": residual_target_inputs,
                            }, region, behaviors[node_id]
                        )
                    )
                    if target_output_claims is None:
                        block(
                            "return_register_relation_transfer_incomplete",
                            f"return node {node_id} cannot establish continuation "
                            f"{target_node_id}'s register relations",
                            "emit checked target-shaped register output claims "
                            "for the continuation",
                        )
                        return_cases_complete = False
                        break
                    target_imports = region_import_keys(target_node_id)
                    if active_frame_imports:
                        if active_frame_imports != target_imports:
                            block(
                                "return_active_frame_import_mismatch",
                                f"return node {node_id} active frame imports do not "
                                f"exactly match continuation {target_node_id}",
                                "match the callsite certificate to the exact return "
                                "continuation invariant",
                            )
                            return_cases_complete = False
                            break
                        return_import_transfers = (
                            _import_register_transfer_claims(
                                contract, behaviors, node_id, target_node_id, []
                            )
                            or []
                        )
                    else:
                        return_import_transfers = _import_register_transfer_claims(
                            contract, behaviors, node_id, target_node_id, []
                        )
                        if return_import_transfers is None:
                            block(
                                "return_import_register_transfer_incomplete",
                                f"return node {node_id} cannot establish continuation "
                                f"{target_node_id}'s import-register relations",
                                "emit a checked decoded register-preservation claim "
                                "for each continuation import binding",
                            )
                            return_cases_complete = False
                            break
                    target_flag_inputs = [
                        int(bit) for bit in target_region.get("flag_inputs", [])
                    ]
                    flag_transfer_claim = None
                    if target_flag_inputs:
                        flag_transfer_claim = _preserved_input_flags_claim(
                            region, target_flag_inputs, behaviors[node_id]
                        )
                        if flag_transfer_claim is None:
                            block(
                                "return_continuation_flag_transfer_incomplete",
                                f"return node {node_id} cannot establish "
                                f"continuation {target_node_id}'s input flags "
                                f"{target_flag_inputs}",
                                "emit a checked decoded flag-preservation claim "
                                "for every continuation input flag",
                            )
                            return_cases_complete = False
                            break
                    unsupported_target_families = [
                        field for field in (
                            "bounds",
                            "address_separations",
                            "input_dynamic_range_relations",
                        )
                        if target_region.get(field)
                    ]
                    if unsupported_target_families:
                        block(
                            "return_continuation_invariant_transfer_incomplete",
                            f"return node {node_id} needs unsupported continuation "
                            f"invariant families {unsupported_target_families}",
                            "add checked return transfer claims for these invariant "
                            "families",
                        )
                        return_cases_complete = False
                        break
                    return_cases.append({
                        "control_state": control_row,
                        "target_control_state": target_control_row,
                        "target_node_id": target_node_id,
                        "target_region_index": target_node_id,
                        "target_target_id": continuation_target_id,
                        "return_frame_claim": return_frame_claim,
                        "return_frame_inventory": active_inventory_payload,
                        "return_slot_frame_transfer_claims": outer_frame_claims,
                        "output_claims": target_output_claims,
                        "import_transfer_claims": return_import_transfers,
                        "active_frame_imports": [
                            import_relation_payload(key)
                            for key in active_frame_imports
                        ],
                        "active_frame_relations": carried_register_relations,
                        "residual_target_register_relations":
                            residual_target_inputs,
                        "target_register_relations": target_input_relations,
                        "stack_window_transfers": stack_transfers,
                        "flag_transfer_claim": flag_transfer_claim,
                        "paired_prepared_writes_claim": return_writes_claim,
                        "frame_exact_stack_writes_claim":
                            frame_exact_return_writes_claim,
                    })
                if not return_cases_complete:
                    continue
                return_step = {
                    "kind": "return",
                    "node_id": node_id,
                    "region_index": node_id,
                    "target_id": target_id,
                    "return_pop_claim": relation_row["return_pop_claim"],
                    "return_frame_claim_index": 0,
                    "edges": [],
                }
                if len(return_cases) == 1:
                    return_step.update(return_cases[0])
                else:
                    return_step["cases"] = return_cases
                node_steps.append(return_step)
                has_internal_return = True
            else:
                if len(control_rows) != 1:
                    block(
                        "terminal_control_profile_ambiguous",
                        f"terminal return node {node_id} has multiple control states",
                        "retain one canonical empty-stack terminal state",
                    )
                    continue
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
                exact_eax_output = any(
                    isinstance(claim.get("output"), dict)
                    and claim["output"].get("original") == "eax"
                    and claim["output"].get("candidate") == "eax"
                    and _register_relation_implies_exact(claim["output"])
                    for claim in relation_row["output_claims"]
                )
                if not exact_eax_output:
                    block(
                        "terminal_result_relation_unmet",
                        f"termination node {node_id} does not establish exact EAX equality",
                        "emit a checked exact EAX output claim for the console return value",
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
                returned_region_indices.append(node_id)
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
                    "composable_x87_state_only_singleton_v1",
                    "composable_paired_stack_word_write_v1",
                    "composable_paired_stack_word_writes_v1",
                    "composable_paired_prepared_word_writes_v1",
                }
            ) is False
            decoded_control = decoded_control_by_node.get(node_id, {})
            known_indirect_call_profile = (
                segment is not None
                and segment.get("certificate_profile")
                    == "composable_known_indirect_call_v1"
            )
            call_profile = (
                not bool(edge.get("infeasible"))
                and edge.get("kind") == "call"
                and edge.get("original_guard") == true_guard
                and edge.get("candidate_guard") == true_guard
                and segment is not None
                and segment.get("certificate_profile") in {
                    "composable_direct_call_v1",
                    "composable_known_indirect_call_v1",
                    "composable_direct_call_prepared_writes_v1",
                    "composable_direct_call_stack_writes_v1",
                }
                and (
                    not known_indirect_call_profile
                    or decoded_control.get("profile") in {
                        "immutable_relocated_function_pointer_call_v1",
                        "fixed_static_function_pointer_call_v1",
                        "inductive_fixed_code_pointer_register_call_v1",
                    }
                    and int(decoded_control.get("target_id", -1))
                        == int(edge.get("target_target_id", -2))
                )
            )
            external_site = external_by_edge.get(edge_id)
            external_profile = (
                not bool(edge.get("infeasible"))
                and edge.get("kind") == "externalCall"
                and edge.get("original_guard") == true_guard
                and edge.get("candidate_guard") == true_guard
                and external_site is not None
            )
            register_external_profile = (
                external_profile
                and external_site.get("dispatch_profile")
                    == "checked_import_register"
                and checked_register_external_site(
                    node_id,
                    int(external_site.get("continuation_target_id", -1)),
                ) is external_site
            )
            indirect_jump_profile = (
                not bool(edge.get("infeasible"))
                and edge.get("kind") == "jump"
                and edge.get("original_guard") == true_guard
                and edge.get("candidate_guard") == true_guard
                and segment is not None
                and (
                    segment.get("certificate_profile"),
                    decoded_control.get("profile"),
                ) in {
                    (
                        "composable_immutable_indirect_jump_v1",
                        "immutable_relocated_function_pointer_jump_v1",
                    ),
                    (
                        "composable_immutable_indirect_jump_v1",
                        "fixed_static_function_pointer_jump_v1",
                    ),
                    (
                        "composable_fixed_code_address_indirect_jump_v1",
                        "fixed_code_address_indirect_jump_v1",
                    ),
                }
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
                "indirect_call" if register_external_profile
                else "external_call" if external_profile
                else "indirect_call" if known_indirect_call_profile
                else "call" if call_profile
                else "indirect_jump" if indirect_jump_profile
                else "jump"
            )
            target_field = "continuation" if external_profile else "target"
            decoded_outcome_mismatch = (
                any(outcome.get("op") != expected_operation for outcome in outcomes)
                if indirect_jump_profile or known_indirect_call_profile else
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
                "kind": "call" if known_indirect_call_profile else expected_operation,
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
                call_push_claim = (
                    register_edge.get("indirect_call_push_claim")
                    if known_indirect_call_profile else
                    register_edge.get("direct_call_push_claim")
                )
                continuation = int(outcomes[0].get("continuation", -1))
                continuation_node_id = node_by_target.get(continuation)
                control_rows = control_states_by_node.get(node_id, [])
                if (
                    call_push_claim is None
                    or any(int(outcome.get("continuation", -1)) != continuation for outcome in outcomes)
                    or not control_rows
                    or continuation_node_id is None
                ):
                    block(
                        "direct_call_control_profile_unmet",
                        f"call node {node_id} lacks checked runtime-frame seeds",
                        "close the call push and finite rooted control-state evidence",
                    )
                    continue
                seeded_facts = callsite_preserved_facts(
                    node_id, target_node_id, continuation_node_id
                )
                if seeded_facts is None:
                    continue
                seeded_imports, seeded_relations = seeded_facts
                seeded_exact_words = direct_call_exact_word_seeds(
                    node_id, target_node_id
                )
                exact_word_seed_claims = []
                for claim_key in (
                    "direct_call_stack_writes_claim",
                    "direct_call_prepared_writes_claim",
                ):
                    call_write_claim = segment.get(claim_key)
                    if isinstance(call_write_claim, dict):
                        exact_word_seed_claims = list(
                            call_write_claim.get("exact_word_seeds", [])
                        )
                        break
                call_cases: list[dict[str, Any]] = []
                call_cases_complete = True
                for control_row in control_rows:
                    source_locations = tuple(
                        inventory_key(item)
                        for item in control_row["frame_offsets"]
                    )
                    source_imports = tuple(
                        inventory_import_key(item)
                        for item in control_row["frame_offsets"]
                    )
                    source_relations = tuple(
                        inventory_register_key(item)
                        for item in control_row["frame_offsets"]
                    )
                    source_exact_words = tuple(
                        inventory_exact_key(item)
                        for item in control_row["frame_offsets"]
                    )
                    target_locations = transfer_locations(
                        node_id, target_node_id, source_locations,
                    )
                    if target_locations is None:
                        call_cases_complete = False
                        break
                    target_relations = frame_relations_after_internal(
                        node_id, source_locations, source_relations,
                        source_exact_words,
                    )
                    transformed_outer_frames = [
                        inventory_payload(
                            locations, imports, relations, exact_words,
                        )
                        for locations, imports, relations, exact_words in zip(
                            target_locations, source_imports, target_relations,
                            source_exact_words, strict=True,
                        )
                    ]
                    seeded_frame_inventory = inventory_payload(
                        (("esp", 0, "esp", 0),),
                        seeded_imports,
                        seeded_relations,
                        seeded_exact_words,
                    )
                    target_control_row = (
                        _witnessed_linked_call_target_control_state(
                            target_node_id=target_node_id,
                            continuation=continuation,
                            source_control_state=control_row,
                            seeded_frame_inventory=seeded_frame_inventory,
                            transformed_outer_frame_inventories=
                                transformed_outer_frames,
                            expansion_witness_keys=
                                control_witness_expansion_keys,
                        )
                    )
                    if target_control_row is None:
                        block(
                            "direct_call_target_control_state_missing",
                            f"call node {node_id} control state has no unique "
                            "checked successor expansion state",
                            "regenerate rooted control closure from the checked call transfer",
                        )
                        call_cases_complete = False
                        break
                    target_inventories = tuple(
                        inventory_key(item)
                        for item in target_control_row["frame_offsets"][1:]
                    )
                    selected_claims = internal_transfer_claims(
                        node_id, source_locations, target_inventories,
                        source_imports,
                        tuple(
                            inventory_import_key(item)
                            for item in target_control_row["frame_offsets"][1:]
                        ),
                        source_relations,
                        tuple(
                            inventory_register_key(item)
                            for item in target_control_row["frame_offsets"][1:]
                        ),
                        source_exact_words=source_exact_words,
                        target_exact_words=tuple(
                            inventory_exact_key(item)
                            for item in target_control_row["frame_offsets"][1:]
                        ),
                    )
                    if selected_claims is None:
                        block(
                            "direct_call_outer_frame_transfer_incomplete",
                            f"call node {node_id} lacks a checked register/memory "
                            "transfer for every live outer runtime frame",
                            "emit affine register and call-push write-disjointness witnesses",
                        )
                        call_cases_complete = False
                        break
                    call_cases.append({
                        "control_state": control_row,
                        "target_control_state": target_control_row,
                        "seeded_frame_inventory": seeded_frame_inventory,
                        "exact_word_seed_claims": exact_word_seed_claims,
                        "seeded_register_output_claims":
                            frame_relation_output_claims(
                                node_id, seeded_relations
                            ),
                        "return_slot_frame_transfer_claims": selected_claims,
                    })
                if not call_cases_complete:
                    continue
                step["continuation_target_id"] = continuation
                step["continuation_node_id"] = continuation_node_id
                step["call_push_claim"] = call_push_claim
                step["known_indirect_call"] = known_indirect_call_profile
                if known_indirect_call_profile:
                    step["decoded_control"] = {
                        **decoded_control,
                        "original_target_expression": outcomes[0]["target"],
                        "candidate_target_expression": outcomes[1]["target"],
                    }
                step["certificate_profile"] = segment["certificate_profile"]
                step["source_stack_window"] = segment["source_stack_window"]
                step["stack_amount"] = int(segment["stack_amount"])
                if len(call_cases) == 1:
                    step.update(call_cases[0])
                else:
                    step["cases"] = call_cases
                has_internal_call = True
            elif external_profile:
                control_rows = control_states_by_node.get(node_id, [])
                if not control_rows:
                    block(
                        "external_call_control_profile_missing",
                        f"external-call node {node_id} has no rooted control state",
                        "regenerate rooted control closure through this external call",
                    )
                    continue
                register_edge = register_edge_by_source_target.get(
                    (node_id, target_node_id), {}
                )
                transfer_claims = register_edge.get(
                    "return_slot_external_transfer_claims", []
                )
                external_cases: list[dict[str, Any]] = []
                external_cases_complete = True
                for control_row in control_rows:
                    target_control_rows = [
                        row for row in control_states_by_node.get(
                            target_node_id, []
                        )
                        if row["calls"] == control_row["calls"]
                    ]
                    if len(target_control_rows) != 1:
                        block(
                            "external_runtime_frame_target_state_missing",
                            f"external-call node {node_id} control state has no "
                            "unique checked successor state",
                            "regenerate the rooted control profile from the checked transfer claims",
                        )
                        external_cases_complete = False
                        break
                    target_control_row = target_control_rows[0]
                    selected_claims = []
                    for source_payload, target_payload in zip(
                        control_row["frame_offsets"],
                        target_control_row["frame_offsets"],
                        strict=True,
                    ):
                        source_inventory = inventory_key(source_payload)
                        target_inventory = inventory_key(target_payload)
                        transfers = []
                        for target_location in target_inventory:
                            candidates = [
                                claim for claim in transfer_claims
                                if location_key(claim["source"])
                                    in source_inventory
                                and location_key(claim["target"])
                                    == target_location
                            ]
                            if not candidates:
                                break
                            transfers.append(sorted(
                                candidates,
                                key=lambda claim: location_key(claim["source"]),
                            )[0])
                        if len(transfers) != len(target_inventory):
                            break
                        exact_word_transfers = exact_word_transfer_claims(
                            node_id,
                            source_inventory,
                            tuple(
                                location_key(transfer["internal_target"])
                                for transfer in transfers
                            ),
                            inventory_exact_key(source_payload),
                            inventory_exact_key(target_payload),
                        )
                        if exact_word_transfers is None:
                            break
                        selected_claims.append({
                            "profile":
                                "external_return_slot_inventory_transfer_v1",
                            "source": source_payload,
                            "target": target_payload,
                            "transfers": transfers,
                            "exact_word_transfers": exact_word_transfers,
                        })
                    if len(selected_claims) != len(
                        control_row["frame_offsets"]
                    ):
                        block(
                            "external_runtime_frame_transfer_claim_missing",
                            f"external-call node {node_id} lacks a checked "
                            "memory/register transfer claim for every live frame",
                            "emit affine call-setup, write-disjointness, and ABI-result witnesses",
                        )
                        external_cases_complete = False
                        break
                    external_cases.append({
                        "control_state": control_row,
                        "target_control_state": target_control_row,
                        "return_slot_external_transfer_claims": selected_claims,
                    })
                if not external_cases_complete:
                    continue
                step["kind"] = "external_call"
                step["external_site"] = external_site
                machine_contract = machine_contract_by_id.get(
                    int(external_site["machine_contract_id"])
                )
                if machine_contract is None:
                    block(
                        "external_call_machine_contract_missing",
                        f"external-call node {node_id} has no resolved machine contract",
                        "declare one complete machine-level import contract",
                    )
                    continue
                step["machine_contract"] = machine_contract
                step["register_dispatch"] = register_external_profile
                if register_external_profile:
                    step["decoded_control"] = decoded_control
                    step["decoded_import"] = machine_contract["import"]
                else:
                    step["decoded_import"] = outcomes[0].get("import")
                if machine_contract.get("disposition") == "protocol":
                    step["kind"] = "external_protocol"
                if len(external_cases) == 1:
                    step.update(external_cases[0])
                else:
                    step["cases"] = external_cases
                has_external_call = True
            elif jump_profile:
                step["certificate_profile"] = segment["certificate_profile"]
                control_rows = control_states_by_node.get(node_id, [])
                if not control_rows:
                    block(
                        "jump_control_profile_missing",
                        f"jump node {node_id} has no rooted control state",
                        "regenerate rooted control closure through this decoded jump",
                    )
                    continue
                jump_cases: list[dict[str, Any]] = []
                jump_cases_complete = True
                for control_row in control_rows:
                    target_control_rows = [
                        row for row in control_states_by_node.get(
                            target_node_id, []
                        )
                        if row["calls"] == control_row["calls"]
                    ]
                    if len(target_control_rows) != 1:
                        block(
                            "jump_target_control_state_missing",
                            f"jump node {node_id} control state has no unique "
                            "checked successor state",
                            "regenerate rooted control closure from the checked transfer",
                        )
                        jump_cases_complete = False
                        break
                    target_control_row = target_control_rows[0]
                    if (
                        segment.get("certificate_profile")
                        == "composable_x87_state_only_singleton_v1"
                        and target_control_row["frame_offsets"]
                            != control_row["frame_offsets"]
                    ):
                        block(
                            "x87_runtime_frame_inventory_changed",
                            f"x87 singleton node {node_id} changes its runtime "
                            "frame inventory",
                            "retain the identical frame inventory across a "
                            "state-only x87 cutpoint",
                        )
                        jump_cases_complete = False
                        break
                    source_locations = tuple(
                        inventory_key(item)
                        for item in control_row["frame_offsets"]
                    )
                    selected_claims = internal_transfer_claims(
                        node_id,
                        source_locations,
                        tuple(
                            inventory_key(item)
                            for item in target_control_row["frame_offsets"]
                        ),
                        tuple(
                            inventory_import_key(item)
                            for item in control_row["frame_offsets"]
                        ),
                        tuple(
                            inventory_import_key(item)
                            for item in target_control_row["frame_offsets"]
                        ),
                        tuple(
                            inventory_register_key(item)
                            for item in control_row["frame_offsets"]
                        ),
                        tuple(
                            inventory_register_key(item)
                            for item in target_control_row["frame_offsets"]
                        ),
                        source_exact_words=tuple(
                            inventory_exact_key(item)
                            for item in control_row["frame_offsets"]
                        ),
                        target_exact_words=tuple(
                            inventory_exact_key(item)
                            for item in target_control_row["frame_offsets"]
                        ),
                    )
                    if selected_claims is None:
                        block(
                            "jump_runtime_frame_transfer_incomplete",
                            f"jump node {node_id} lacks a checked register/memory "
                            "transfer for every live runtime frame",
                            "emit affine register and write-disjointness witnesses",
                        )
                        jump_cases_complete = False
                        break
                    jump_cases.append({
                        "control_state": control_row,
                        "target_control_state": target_control_row,
                        "return_slot_frame_transfer_claims": selected_claims,
                    })
                if not jump_cases_complete:
                    continue
                if len(jump_cases) == 1:
                    step.update(jump_cases[0])
                else:
                    step["cases"] = jump_cases
            elif indirect_jump_profile:
                control_rows = control_states_by_node.get(node_id, [])
                if not control_rows:
                    block(
                        "indirect_jump_control_profile_missing",
                        f"indirect-jump node {node_id} has no rooted control state",
                        "regenerate rooted control closure through the checked target",
                    )
                    continue
                indirect_jump_cases: list[dict[str, Any]] = []
                indirect_jump_cases_complete = True
                for control_row in control_rows:
                    target_control_rows = [
                        row for row in control_states_by_node.get(
                            target_node_id, []
                        )
                        if row["calls"] == control_row["calls"]
                    ]
                    if len(target_control_rows) != 1:
                        block(
                            "indirect_jump_target_control_state_missing",
                            f"indirect-jump node {node_id} control state has no "
                            "unique checked successor state",
                            "regenerate rooted control closure from the checked target",
                        )
                        indirect_jump_cases_complete = False
                        break
                    target_control_row = target_control_rows[0]
                    selected_claims = internal_transfer_claims(
                        node_id,
                        tuple(
                            inventory_key(item)
                            for item in control_row["frame_offsets"]
                        ),
                        tuple(
                            inventory_key(item)
                            for item in target_control_row["frame_offsets"]
                        ),
                        tuple(
                            inventory_import_key(item)
                            for item in control_row["frame_offsets"]
                        ),
                        tuple(
                            inventory_import_key(item)
                            for item in target_control_row["frame_offsets"]
                        ),
                        tuple(
                            inventory_register_key(item)
                            for item in control_row["frame_offsets"]
                        ),
                        tuple(
                            inventory_register_key(item)
                            for item in target_control_row["frame_offsets"]
                        ),
                        source_exact_words=tuple(
                            inventory_exact_key(item)
                            for item in control_row["frame_offsets"]
                        ),
                        target_exact_words=tuple(
                            inventory_exact_key(item)
                            for item in target_control_row["frame_offsets"]
                        ),
                    )
                    if selected_claims is None:
                        block(
                            "indirect_jump_runtime_frame_transfer_incomplete",
                            f"indirect-jump node {node_id} lacks a checked "
                            "register/memory transfer for every live runtime frame",
                            "emit affine register and write-disjointness witnesses",
                        )
                        indirect_jump_cases_complete = False
                        break
                    indirect_jump_cases.append({
                        "control_state": control_row,
                        "target_control_state": target_control_row,
                        "return_slot_frame_transfer_claims": selected_claims,
                    })
                if not indirect_jump_cases_complete:
                    continue
                step["decoded_control"] = {
                    **decoded_control,
                    "original_target_expression": outcomes[0]["target"],
                    "candidate_target_expression": outcomes[1]["target"],
                }
                if len(indirect_jump_cases) == 1:
                    step.update(indirect_jump_cases[0])
                else:
                    step["cases"] = indirect_jump_cases
                has_bounded_indirect = True
            if (
                segment is not None
                and segment.get("certificate_profile")
                    in {
                        "composable_paired_stack_word_write_v1",
                        "composable_paired_stack_word_writes_v1",
                        "composable_paired_prepared_word_writes_v1",
                        "composable_direct_call_prepared_writes_v1",
                        "composable_direct_call_stack_writes_v1",
                    }
            ):
                has_paired_stack_write = True
            node_steps.append(step)
            continue

        edge_rows = [edges[edge_id] for edge_id in outgoing]
        edge_by_kind = {edge.get("kind"): edge for edge in edge_rows}
        candidate_edge_by_kind = {
            edge.get("candidate_kind", edge.get("kind")): edge
            for edge in edge_rows
        }
        taken_edge = edge_by_kind.get("branchTaken")
        fallthrough_edge = edge_by_kind.get("branchFallthrough")
        if (
            len(edge_by_kind) != 2
            or len(candidate_edge_by_kind) != 2
            or taken_edge is None
            or fallthrough_edge is None
            or candidate_edge_by_kind.get("branchTaken") is None
            or candidate_edge_by_kind.get("branchFallthrough") is None
            or any(
                bool(edge.get("infeasible"))
                and not _checked_infeasible_branch_edge(edge)
                for edge in edge_rows
            )
            or any(
                candidate_by_edge.get(int(edge["id"]), {}).get("certificate_profile")
                    not in {
                        "composable_local_no_write_v1",
                        "composable_local_no_write_deferred_guard_v1",
                        "composable_paired_stack_word_write_v1",
                        "composable_paired_stack_word_writes_v1",
                        "composable_paired_prepared_word_writes_v1",
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
        original_outcome, candidate_outcome = outcomes
        expected_original_taken = int(taken_edge["target_target_id"])
        expected_original_fallthrough = int(
            fallthrough_edge["target_target_id"]
        )
        expected_candidate_taken = int(
            candidate_edge_by_kind["branchTaken"]["target_target_id"]
        )
        expected_candidate_fallthrough = int(
            candidate_edge_by_kind["branchFallthrough"]["target_target_id"]
        )
        if (
            original_outcome.get("op") != "branch"
            or candidate_outcome.get("op") != "branch"
            or int(original_outcome.get("taken", -1))
                != expected_original_taken
            or int(original_outcome.get("fallthrough", -1))
                != expected_original_fallthrough
            or int(candidate_outcome.get("taken", -1))
                != expected_candidate_taken
            or int(candidate_outcome.get("fallthrough", -1))
                != expected_candidate_fallthrough
        ):
            block(
                "decoded_branch_outcome_mismatch",
                f"node {node_id} branch destinations do not match its submitted edges",
                "repair the mapping or add a paired finite-path normalization certificate",
            )
            continue
        original_condition = outcomes[0].get("condition")
        candidate_condition = outcomes[1].get("condition")
        if any(
            edge.get("original_guard")
                != _normalized_branch_guard(
                    original_condition,
                    taken=edge["kind"] == "branchTaken",
                )
            or edge.get("candidate_guard")
                != _normalized_branch_guard(
                    candidate_condition,
                    taken=edge.get("candidate_kind", edge["kind"])
                        == "branchTaken",
                )
            for edge in edge_rows
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
                    "composable_paired_prepared_word_writes_v1",
                    "composable_direct_call_prepared_writes_v1",
                    "composable_direct_call_stack_writes_v1",
                }
            for edge in edge_rows
        )
        ordered_edges = [taken_edge, fallthrough_edge]
        control_rows = control_states_by_node.get(node_id, [])
        if not control_rows:
            block(
                "branch_control_profile_missing",
                f"branch node {node_id} has no rooted control state",
                "regenerate rooted control closure through this decoded branch",
            )
            continue
        branch_cases: list[dict[str, Any]] = []
        branch_cases_complete = True
        for control_row in control_rows:
            source_inventories = tuple(
                inventory_key(item) for item in control_row["frame_offsets"]
            )
            planned_edges = []
            for edge in ordered_edges:
                target_node_id = int(edge["target_node_id"])
                segment_candidate = candidate_by_edge[int(edge["id"])]
                if _checked_infeasible_branch_edge(edge):
                    planned_edges.append({
                        "edge_id": int(edge["id"]),
                        "certificate_profile": segment_candidate[
                            "certificate_profile"
                        ],
                        "frame_guard_claim": None,
                        "infeasible": True,
                        "branch_value": edge.get("kind") == "branchTaken",
                        "candidate_branch_value": edge.get(
                            "candidate_kind", edge.get("kind")
                        ) == "branchTaken",
                        "target_node_id": target_node_id,
                        "target_region_index": target_node_id,
                        "target_target_id": int(edge["target_target_id"]),
                    })
                    continue
                target_rows = [
                    row for row in control_states_by_node.get(
                        target_node_id, []
                    )
                    if row["calls"] == control_row["calls"]
                ]
                if len(target_rows) != 1:
                    block(
                        "branch_target_control_state_missing",
                        f"branch edge {int(edge['id'])} has no unique checked "
                        "target control state",
                        "regenerate rooted control closure through both decoded guards",
                    )
                    branch_cases_complete = False
                    break
                target_row = target_rows[0]
                frame_claims = internal_transfer_claims(
                    node_id,
                    source_inventories,
                    tuple(
                        inventory_key(item)
                        for item in target_row["frame_offsets"]
                    ),
                    tuple(
                        inventory_import_key(item)
                        for item in control_row["frame_offsets"]
                    ),
                    tuple(
                        inventory_import_key(item)
                        for item in target_row["frame_offsets"]
                    ),
                    tuple(
                        inventory_register_key(item)
                        for item in control_row["frame_offsets"]
                    ),
                    tuple(
                        inventory_register_key(item)
                        for item in target_row["frame_offsets"]
                    ),
                    source_exact_words=tuple(
                        inventory_exact_key(item)
                        for item in control_row["frame_offsets"]
                    ),
                    target_exact_words=tuple(
                        inventory_exact_key(item)
                        for item in target_row["frame_offsets"]
                    ),
                )
                if frame_claims is None:
                    block(
                        "branch_runtime_frame_transfer_incomplete",
                        f"branch edge {int(edge['id'])} cannot preserve every live "
                        "runtime frame",
                        "emit checked register and memory-footprint transfers for "
                        "one or more retained aliases",
                    )
                    branch_cases_complete = False
                    break
                frame_guard_claim = None
                if segment_candidate.get("certificate_profile") == (
                    "composable_local_no_write_deferred_guard_v1"
                ):
                    active_inventory = (
                        control_row["frame_offsets"][0]
                        if control_row.get("frame_offsets") else None
                    )
                    if not isinstance(active_inventory, dict):
                        block(
                            "runtime_frame_guard_relation_incomplete",
                            f"branch edge {int(edge['id'])} needs an active "
                            "runtime-frame guard fact",
                            "establish a checked active-frame register relation "
                            "or strengthen the ordinary node invariant",
                        )
                        branch_cases_complete = False
                        break
                    frame_source = {
                        "input_relations": list(
                            active_inventory.get("preserved_relations", [])
                        ),
                        "flag_inputs": [],
                    }
                    frame_guard_claim = _paired_exact_guard_claim(
                        contract,
                        frame_source,
                        edge.get("original_guard") or {},
                        edge.get("candidate_guard") or {},
                        None,
                        None,
                    )
                    if frame_guard_claim is None:
                        block(
                            "runtime_frame_guard_relation_incomplete",
                            f"branch edge {int(edge['id'])} cannot derive its "
                            "guard from checked active-frame register facts",
                            "preserve the guard's exact register inputs in the "
                            "active frame inventory",
                        )
                        branch_cases_complete = False
                        break
                planned_edges.append({
                    "edge_id": int(edge["id"]),
                    "certificate_profile": segment_candidate[
                        "certificate_profile"
                    ],
                    "frame_guard_claim": frame_guard_claim,
                    "branch_value": edge.get("kind") == "branchTaken",
                    "candidate_branch_value": edge.get(
                        "candidate_kind", edge.get("kind")
                    ) == "branchTaken",
                    "target_node_id": target_node_id,
                    "target_region_index": target_node_id,
                    "target_target_id": int(edge["target_target_id"]),
                    "target_control_state": target_row,
                    "return_slot_frame_transfer_claims": frame_claims,
                })
            if not branch_cases_complete:
                break
            branch_cases.append({
                "control_state": control_row,
                "edges": planned_edges,
            })
        if not branch_cases_complete:
            continue
        branch_step = {
            "kind": "branch",
            "node_id": node_id,
            "region_index": node_id,
            "target_id": target_id,
        }
        if len(branch_cases) == 1:
            branch_step.update(branch_cases[0])
        else:
            branch_step["cases"] = branch_cases
            branch_step["edges"] = [
                {
                    "edge_id": int(edge["id"]),
                    "certificate_profile": candidate_by_edge[
                        int(edge["id"])
                    ]["certificate_profile"],
                    "target_node_id": int(edge["target_node_id"]),
                    "target_region_index": int(edge["target_node_id"]),
                    "target_target_id": int(edge["target_target_id"]),
                    "branch_value": edge.get("kind") == "branchTaken",
                    "candidate_branch_value": edge.get(
                        "candidate_kind", edge.get("kind")
                    ) == "branchTaken",
                }
                for edge in ordered_edges
            ]
        node_steps.append(branch_step)

    for step in node_steps:
        step["control_states"] = control_states_by_node.get(
            int(step["node_id"]), []
        )

    protocol_callback_states = attach_protocol_callback_states(
        node_steps,
        protocol_callback_contract_by_node,
        register_relations,
        block,
    )

    if len(returned_region_indices) > 1:
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
            "required_theorem": RELATIONAL_FINAL_ACCEPTANCE_THEOREM,
            "theorem": None,
            "profile": profile,
            "root_node_id": (
                int(launch_root_node_id)
                if launch_root_node_id is not None else None
            ),
            "terminal_region_index": (
                returned_region_indices[0]
                if returned_region_indices else (
                    int(launch_root_node_id)
                    if launch_root_node_id is not None else None
                )
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
                        regions[returned_region_indices[0]].get("flag_outputs", [])
                        if returned_region_indices else []
                    ),
                    "address_separations": [],
                    "stack_windows": [],
                }
                if returned_region_indices else {
                    "register_relations": [{
                        "original": "eax",
                        "candidate": "eax",
                        "relation": "exact",
                    }],
                    "import_register_relations": [],
                    "dynamic_register_range_relations": [],
                    "bounds": [],
                    "flag_bits": [],
                    "address_separations": [],
                    "stack_windows": [],
                }
            ),
            "control_states": control_witness_states,
            "linked_control": linked_control,
            "affine_linked_control": affine_linked_control,
            "protocol_callback_node_ids": sorted(protocol_callback_contract_by_node),
            "protocol_callback_states": protocol_callback_states,
            "launch": {
                "original_is_dll": original_is_dll,
                "candidate_is_dll": candidate_is_dll,
                "original_exports": original_exports,
                "candidate_exports": candidate_exports,
                "original_loader_diagnostics": original_loader_diagnostics,
                "candidate_loader_diagnostics": candidate_loader_diagnostics,
                "entry_root_node_id": entry_root_node_id,
                "entry_target_id": entry_target_id,
                "root_node_id": launch_root_node_id,
                "tls_callback_node_ids": tls_callback_node_ids,
                "tls_callback_target_ids": tls_callback_target_ids,
                "continuation_target_ids": launch_continuation_target_ids,
                "frame_offsets": [
                    inventory_payload(inventory, exact_words=exact_words)
                    for inventory, exact_words in zip(
                        launch_frame_inventories,
                        launch_frame_exact_words,
                        strict=True,
                    )
                ],
                "original_tls_callback_rvas": original_tls_callbacks,
                "candidate_tls_callback_rvas": candidate_tls_callbacks,
            },
            "node_steps": node_steps,
            "blockers": compact_blockers,
        }
    return {
        "format": "stage-a-whole-program-acceptance-v1",
        "status": "ready",
        "required_theorem": RELATIONAL_FINAL_ACCEPTANCE_THEOREM,
        "theorem": RELATIONAL_FINAL_ACCEPTANCE_THEOREM,
        "profile": profile,
        "root_node_id": int(launch_root_node_id),
        "terminal_region_index": (
            returned_region_indices[0]
            if returned_region_indices else int(launch_root_node_id)
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
                    regions[returned_region_indices[0]].get("flag_outputs", [])
                    if returned_region_indices else []
                ),
                "address_separations": [],
                "stack_windows": [],
            }
            if returned_region_indices else {
                "register_relations": [{
                    "original": "eax",
                    "candidate": "eax",
                    "relation": "exact",
                }],
                "import_register_relations": [],
                "dynamic_register_range_relations": [],
                "bounds": [],
                "flag_bits": [],
                "address_separations": [],
                "stack_windows": [],
            }
        ),
        "control_states": control_witness_states,
        "linked_control": linked_control,
        "affine_linked_control": affine_linked_control,
        "protocol_callback_node_ids": sorted(protocol_callback_contract_by_node),
        "protocol_callback_states": protocol_callback_states,
        "launch": {
            "original_is_dll": original_is_dll,
            "candidate_is_dll": candidate_is_dll,
            "original_exports": original_exports,
            "candidate_exports": candidate_exports,
            "original_loader_diagnostics": original_loader_diagnostics,
            "candidate_loader_diagnostics": candidate_loader_diagnostics,
            "entry_root_node_id": int(entry_root_node_id),
            "entry_target_id": int(entry_target_id),
            "root_node_id": int(launch_root_node_id),
            "tls_callback_node_ids": tls_callback_node_ids,
            "tls_callback_target_ids": tls_callback_target_ids,
            "continuation_target_ids": launch_continuation_target_ids,
            "frame_offsets": [
                inventory_payload(inventory, exact_words=exact_words)
                for inventory, exact_words in zip(
                    launch_frame_inventories,
                    launch_frame_exact_words,
                    strict=True,
                )
            ],
            "original_tls_callback_rvas": original_tls_callbacks,
            "candidate_tls_callback_rvas": candidate_tls_callbacks,
        },
        "node_steps": node_steps,
        "blockers": [],
    }
