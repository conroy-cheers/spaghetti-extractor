from __future__ import annotations

import json
import os
import re
from collections import deque
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

from ...stage_binary import StageABinary, StageAInputError
from ...util import sha256_bytes, write_json
from ..analyses.external import (
    _external_call_site_candidates,
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
    _stack_word_address_adjustment,
    _stack_word_adjustment_covered,
    _preserved_input_flags_claim,
)
from ..analyses.stack import _stack_window_transfer_claims
from ..analyses.semantic_control import _normalized_branch_guard
from ..analyses.registers import (
    _propose_internal_callsite_preservation_summaries,
)
from ..analyses.register_lattice import _register_relation_implies_exact
from ..analyses.linked_control import (
    linked_control_expansion_key,
    linked_control_state_key,
    project_linked_control_profile,
)
from ..analyses.affine_linked_control import affine_linked_control_payload
from ..artifacts import write_text_if_changed as _write_text_if_changed
from ..contract import _raw_base_relocations
from ..model import (
    _semantic_constant_bool,
    _semantic_hash,
    _target_shaped_register_output_claims_with_stack_windows,
)
from ..schema import (
    FLAG_BITS,
    RELATIONAL_ACCEPTANCE_THEOREM,
    RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
    RELATIONAL_KERNEL_MODULES,
    choose_relational_acceptance_theorem,
)


_LEAN_SOURCE_ROOT = Path(__file__).resolve().parents[2] / "lean" / "StageA"
from .expressions import (
    _lean_acceptance_outcome,
    _lean_direct_call_prepared_exact_word_seed_claim,
    _lean_external_target,
    _lean_frame_exact_stack_word_writes_claim,
    _lean_paired_exact_expr_witness,
    _lean_paired_prepared_word_writes_claim,
    _lean_register_offset_witness,
    _lean_register_output_claim,
    _lean_return_slot_offset_pair,
    _lean_semantic_bool_expr,
    _lean_semantic_expr,
    _lean_stack_window,
    _lean_stack_window_transfer_claim,
    _lean_state_invariant,
)
from .affine_linked_control import (
    write_relational_affine_linked_call_binding_modules,
    write_relational_affine_linked_control_binding_modules,
    write_relational_affine_linked_external_call_binding_modules,
    write_relational_affine_linked_memory_binding_modules,
    write_relational_affine_linked_control_module,
)
from .definitions import (
    _has_compositional_normalized_support,
    _lean_region_input_invariant,
    _normalized_behavior_fast_path,
)
from .common import _lean_register_relation_pair
from .callbacks import _lean_acceptance_callback_return_node


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


def _lean_frame_exact_guard_claim(claim: dict[str, Any]) -> str:
    if claim.get("profile") != "paired_exact_guard_v1":
        raise StageAInputError(
            f"unsupported active-frame guard claim: {claim.get('profile')!r}"
        )
    return (
        "{ originalGuard := "
        + _lean_semantic_bool_expr(claim["original_guard"])
        + ", candidateGuard := "
        + _lean_semantic_bool_expr(claim["candidate_guard"])
        + ", witness := "
        + _lean_paired_exact_expr_witness(claim["witness"])
        + " }"
    )


def _lean_preserved_input_flags_proof(
    *,
    claim: dict[str, Any],
    source_region_index: int,
    original_behavior: str,
    candidate_behavior: str,
) -> str:
    """Replay a checked preserved-input-flags claim for a linked step."""
    if claim.get("profile") != "preserved_input_flags_v1":
        raise StageAInputError(
            f"unsupported linked flag-transfer claim: {claim.get('profile')!r}"
        )
    bits = [int(bit) for bit in claim.get("bits", [])]
    if not bits:
        return "rfl"
    flag_theorems = {
        0: "evalNormalizedFlags_extract_cf_input_of_checked",
        2: "evalNormalizedFlags_extract_pf_input_of_checked",
        4: "evalNormalizedFlags_extract_af_input_of_checked",
        6: "evalNormalizedFlags_extract_zf_input_of_checked",
        7: "evalNormalizedFlags_extract_sf_input_of_checked",
        11: "evalNormalizedFlags_extract_of_input_of_checked",
    }

    def prove_from(index: int, indent: str) -> list[str]:
        bit = bits[index]
        lines = [f"{indent}apply flagsRelated_cons_of_eq"]
        lines.append(
            f"{indent}· simp only [NormalizedSymbolicBehavior.eval_eflags]"
        )
        proof_indent = indent + "  "
        if bit == 10:
            lines.append(
                f"{proof_indent}rw [evalNormalizedFlags_extract_df, "
                "evalNormalizedFlags_extract_df]"
            )
        else:
            theorem = flag_theorems.get(bit)
            if theorem is None:
                raise StageAInputError(
                    f"unsupported preserved linked flag bit: {bit}"
                )
            lines.append(
                f"{proof_indent}rw [{theorem} originalState "
                f"{original_behavior}.flags (by decide), {theorem} "
                f"candidateState {candidate_behavior}.flags (by decide)]"
            )
        lines.append(
            f"{proof_indent}exact flagsRelated_of_contains "
            f"region{source_region_index}.flagInputs originalState.eflags "
            "candidateState.eflags inputFlags (by decide)"
        )
        if index + 1 == len(bits):
            lines.append(f"{indent}· rfl")
        else:
            nested = prove_from(index + 1, indent + "  ")
            lines.append(f"{indent}· " + nested[0].lstrip())
            lines.extend(nested[1:])
        return lines

    return "\n".join(prove_from(0, ""))


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

    linked_control = project_linked_control_profile(
        control_witness_states, behaviors=behaviors, nodes=nodes
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
        if not outgoing:
            relation_row = register_relations.get("regions", [])[node_id]
            control_rows = control_states_by_node.get(node_id, [])
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
            or any(bool(edge.get("infeasible")) for edge in edge_rows)
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
                segment_candidate = candidate_by_edge[int(edge["id"])]
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
            "required_theorem": RELATIONAL_ACCEPTANCE_THEOREM,
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
        "required_theorem": RELATIONAL_ACCEPTANCE_THEOREM,
        "theorem": RELATIONAL_ACCEPTANCE_THEOREM,
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

def _lean_all_listed_proof(theorems: list[str]) -> str:
    return (
        "".join(f"⟨{theorem}, " for theorem in theorems)
        + "True.intro"
        + "⟩" * len(theorems)
    )


def _lean_return_slot_transfer_rule(rule: dict[str, Any]) -> str:
    return (
        "{ originalSourceRegister := ."
        + str(rule["original_source_register"])
        + ", candidateSourceRegister := ."
        + str(rule["candidate_source_register"])
        + ", originalTargetRegister := ."
        + str(rule["original_target_register"])
        + ", candidateTargetRegister := ."
        + str(rule["candidate_target_register"])
        + ", originalOutput := "
        + _lean_register_offset_witness(rule["original_output_witness"])
        + ", candidateOutput := "
        + _lean_register_offset_witness(rule["candidate_output_witness"])
        + ", originalDelta := BitVec.ofNat 32 "
        + str(int(rule["original_delta"]))
        + ", candidateDelta := BitVec.ofNat 32 "
        + str(int(rule["candidate_delta"]))
        + " }"
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
            f"({chunk[proof_key]}) ({proof})"
        )
        ids = f"{chunk['ids']} ++ ({ids})"
    return proof


def _launch_check_ranges(total: int, chunk_size: int) -> list[tuple[int, int]]:
    """Return an exact, contiguous half-open partition of a launch span."""
    if total < 0:
        raise StageAInputError("launch-check span cannot be negative")
    if chunk_size <= 0:
        raise StageAInputError("launch-check chunk size must be positive")
    return [
        (start, min(chunk_size, total - start))
        for start in range(0, total, chunk_size)
    ]


def _launch_structural_image_ranges(
    *,
    image_base: int,
    span_start: int,
    span_size: int,
    excluded_ranges: list[tuple[int, int]],
    structurally_immutable: bool,
) -> list[tuple[int, int, bool]]:
    """Partition one mapped image span into checked structural/fallback ranges."""
    if span_start < 0 or span_size < 0 or image_base < 0:
        raise StageAInputError("launch image spans cannot be negative")
    span_end = span_start + span_size
    if not structurally_immutable:
        return [(span_start, span_size, False)] if span_size else []

    clipped: list[tuple[int, int]] = []
    for lower, upper in sorted(excluded_ranges):
        if lower < 0 or upper < lower:
            raise StageAInputError("launch image exclusion range is invalid")
        lower = max(span_start, lower)
        upper = min(span_end, upper)
        if lower >= upper:
            continue
        if clipped and lower <= clipped[-1][1]:
            clipped[-1] = (clipped[-1][0], max(clipped[-1][1], upper))
        else:
            clipped.append((lower, upper))

    ranges: list[tuple[int, int, bool]] = []

    def append_range(start: int, stop: int, structural: bool) -> None:
        if start >= stop:
            return
        if (
            ranges
            and ranges[-1][2] == structural
            and ranges[-1][0] + ranges[-1][1] == start
        ):
            previous_start, previous_size, _ = ranges[-1]
            ranges[-1] = (
                previous_start,
                previous_size + stop - start,
                structural,
            )
        else:
            ranges.append((start, stop - start, structural))

    def append_immutable_interval(start: int, stop: int) -> None:
        aligned_start = min(
            start + (-(image_base + start) % 4),
            stop,
        )
        aligned_stop = aligned_start + ((stop - aligned_start) // 4) * 4
        append_range(start, aligned_start, False)
        append_range(aligned_start, aligned_stop, True)
        append_range(aligned_stop, stop, False)

    cursor = span_start
    for lower, upper in clipped:
        append_immutable_interval(cursor, lower)
        append_range(lower, upper, False)
        cursor = upper
    append_immutable_interval(cursor, span_end)
    return ranges


def _lean_acceptance_empty_stack(node_id: int) -> str:
    return (
        "  have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
        f"      ((acceptanceOriginalNormalizedBehavior{node_id}.eval originalState).nextMachineState\n"
        "        originalState)\n"
        f"      ((acceptanceCandidateNormalizedBehavior{node_id}.eval candidateState).nextMachineState\n"
        "        candidateState) [] [] [] := by\n"
        "    simp [RelationalRuntimeCallStackHolds]"
    )


def _runtime_frame_protected_bytes(inventory: dict[str, Any]) -> int:
    protected_bytes = 4
    for word in inventory.get("exact_words", []):
        protected_bytes = max(
            protected_bytes,
            max(int(word["original"]), int(word["candidate"])) + 4,
        )
    return protected_bytes

def _lean_return_slot_offset_inventory(inventory: dict[str, Any]) -> str:
    exact_words = inventory.get("exact_words", [])
    exact_words_field = (
        ", exactWords := ["
        + ", ".join(
            "{ originalOffset := " + str(int(word["original"]))
            + ", candidateOffset := " + str(int(word["candidate"])) + " }"
            for word in exact_words
        )
        + "]"
        if exact_words else ""
    )
    preserved_imports = inventory.get("preserved_imports", [])
    preserved_imports_field = (
        ", preservedImports := ["
        + ", ".join(
            "{ original := ." + str(relation["original"])
            + ", candidate := ." + str(relation["candidate"])
            + ", imported := " + _lean_external_target(relation["import"])
            + " }"
            for relation in preserved_imports
        )
        + "]"
        if preserved_imports else ""
    )
    preserved_relations = inventory.get("preserved_relations", [])
    preserved_relations_field = (
        ", preservedRelations := ["
        + ", ".join(
            _lean_register_relation_pair(relation)
            for relation in preserved_relations
        )
        + "]"
        if preserved_relations else ""
    )
    return (
        "({ locations := ["
        + ", ".join(
            _lean_return_slot_offset_pair(location)
            for location in inventory["locations"]
        )
        + "]"
        + exact_words_field
        + preserved_imports_field
        + preserved_relations_field
        + " } : ReturnSlotOffsetInventory)"
    )

def _lean_return_slot_exact_word_transfer_claim(claim: dict[str, Any]) -> str:
    word = claim["word"]
    return (
        "{ word := { originalOffset := " + str(int(word["original"]))
        + ", candidateOffset := " + str(int(word["candidate"]))
        + " }, sourceBase := "
        + _lean_return_slot_offset_pair(claim["source_base"])
        + ", targetBase := "
        + _lean_return_slot_offset_pair(claim["target_base"])
        + ", transfer := "
        + _lean_return_slot_frame_transfer_claim(claim["transfer"])
        + " }"
    )

def _lean_external_return_slot_transfer_claim(claim: dict[str, Any]) -> str:
    internal = claim["internal_rule"]
    result = claim["result_rule"]
    memory = claim["memory_claim"]
    original_writes = ", ".join(
        _lean_register_offset_witness(witness)
        for witness in memory["original_write_witnesses"]
    )
    candidate_writes = ", ".join(
        _lean_register_offset_witness(witness)
        for witness in memory["candidate_write_witnesses"]
    )
    return (
        "{ source := " + _lean_return_slot_offset_pair(claim["source"])
        + ", internalTarget := "
        + _lean_return_slot_offset_pair(claim["internal_target"])
        + ", internalRule := { originalSourceRegister := ."
        + str(internal["original_source_register"])
        + ", candidateSourceRegister := ."
        + str(internal["candidate_source_register"])
        + ", originalTargetRegister := ."
        + str(internal["original_target_register"])
        + ", candidateTargetRegister := ."
        + str(internal["candidate_target_register"])
        + ", originalOutput := "
        + _lean_register_offset_witness(internal["original_output_witness"])
        + ", candidateOutput := "
        + _lean_register_offset_witness(internal["candidate_output_witness"])
        + ", originalDelta := BitVec.ofNat 32 "
        + str(int(internal["original_delta"]))
        + ", candidateDelta := BitVec.ofNat 32 "
        + str(int(internal["candidate_delta"]))
        + " }, resultRule := { source := "
        + _lean_return_slot_offset_pair(result["source"])
        + ", target := " + _lean_return_slot_offset_pair(result["target"])
        + ", originalDelta := " + str(int(result["original_delta"]))
        + ", candidateDelta := " + str(int(result["candidate_delta"]))
        + " }, memory := { offsets := "
        + _lean_return_slot_offset_pair(memory["offsets"])
        + f", originalWrites := [{original_writes}]"
        + f", candidateWrites := [{candidate_writes}] }} }}"
    )


def _lean_external_return_slot_inventory_transfer_claim(
    claim: dict[str, Any],
) -> str:
    return (
        "{ source := " + _lean_return_slot_offset_inventory(claim["source"])
        + ", target := " + _lean_return_slot_offset_inventory(claim["target"])
        + ", transfers := ["
        + ", ".join(
            _lean_external_return_slot_transfer_claim(transfer)
            for transfer in claim["transfers"]
        )
        + "], exactWordTransfers := ["
        + ", ".join(
            _lean_return_slot_exact_word_transfer_claim(transfer)
            for transfer in claim.get("exact_word_transfers", [])
        )
        + "] }"
    )


def _lean_external_jump_return_slot_transfer_claim(
    claim: dict[str, Any],
) -> str:
    internal = claim["internal_rule"]
    result = claim["result_rule"]
    memory = claim["memory_claim"]
    original_writes = ", ".join(
        _lean_register_offset_witness(witness)
        for witness in memory["original_write_witnesses"]
    )
    candidate_writes = ", ".join(
        _lean_register_offset_witness(witness)
        for witness in memory["candidate_write_witnesses"]
    )
    return (
        "{ source := " + _lean_return_slot_offset_pair(claim["source"])
        + ", internalTarget := "
        + _lean_return_slot_offset_pair(claim["internal_target"])
        + ", boundaryTarget := "
        + _lean_return_slot_offset_pair(claim["boundary_target"])
        + ", internalRule := { originalSourceRegister := ."
        + str(internal["original_source_register"])
        + ", candidateSourceRegister := ."
        + str(internal["candidate_source_register"])
        + ", originalTargetRegister := ."
        + str(internal["original_target_register"])
        + ", candidateTargetRegister := ."
        + str(internal["candidate_target_register"])
        + ", originalOutput := "
        + _lean_register_offset_witness(internal["original_output_witness"])
        + ", candidateOutput := "
        + _lean_register_offset_witness(internal["candidate_output_witness"])
        + ", originalDelta := BitVec.ofNat 32 "
        + str(int(internal["original_delta"]))
        + ", candidateDelta := BitVec.ofNat 32 "
        + str(int(internal["candidate_delta"]))
        + " }, resultRule := { source := "
        + _lean_return_slot_offset_pair(result["source"])
        + ", target := " + _lean_return_slot_offset_pair(result["target"])
        + ", originalDelta := " + str(int(result["original_delta"]))
        + ", candidateDelta := " + str(int(result["candidate_delta"]))
        + " }, memory := { offsets := "
        + _lean_return_slot_offset_pair(memory["offsets"])
        + f", originalWrites := [{original_writes}]"
        + f", candidateWrites := [{candidate_writes}] }} }}"
    )


def _lean_external_jump_return_slot_inventory_transfer_claim(
    claim: dict[str, Any],
) -> str:
    return (
        "{ source := " + _lean_return_slot_offset_inventory(claim["source"])
        + ", target := " + _lean_return_slot_offset_inventory(claim["target"])
        + ", transfers := ["
        + ", ".join(
            _lean_external_jump_return_slot_transfer_claim(transfer)
            for transfer in claim["transfers"]
        )
        + "], exactWordTransfers := ["
        + ", ".join(
            _lean_return_slot_exact_word_transfer_claim(transfer)
            for transfer in claim.get("exact_word_transfers", [])
        )
        + "] }"
    )


def _lean_return_slot_frame_transfer_claim(claim: dict[str, Any]) -> str:
    transfer = claim["transfer"]
    memory = claim["memory"]
    if memory.get("profile", "affine_v1") == "affine_v1":
        original_writes = ", ".join(
            _lean_register_offset_witness(witness)
            for witness in memory["original_write_witnesses"]
        )
        candidate_writes = ", ".join(
            _lean_register_offset_witness(witness)
            for witness in memory["candidate_write_witnesses"]
        )
        memory_literal = (
            ".affine { offsets := "
            + _lean_return_slot_offset_pair(memory["offsets"])
            + f", originalWrites := [{original_writes}]"
            + f", candidateWrites := [{candidate_writes}] }}"
        )
    elif memory.get("profile") in {
        "stack_image_separated_v1", "protected_frame_span_v1",
    }:
        writes = []
        for witness in memory["writes"]:
            if witness["kind"] == "affine":
                writes.append(
                    ".affine "
                    + _lean_register_offset_witness(
                        witness["original_witness"]
                    )
                    + " "
                    + _lean_register_offset_witness(
                        witness["candidate_witness"]
                    )
                )
            elif witness["kind"] == "static_word":
                writes.append(f".staticWord {int(witness['slot_id'])}")
            else:
                raise StageAInputError(
                    "unsupported return-slot write witness "
                    f"{witness['kind']!r}"
                )
        if memory["profile"] == "stack_image_separated_v1":
            location = memory["location"]
            memory_literal = (
                ".framed { offsets := "
                + _lean_return_slot_offset_pair(memory["offsets"])
                + ", location := { window := "
                + _lean_stack_window(location["window"])
                + ", direction := ."
                + str(location["direction"])
                + ", amount := "
                + str(int(location["amount"]))
                + " }, writes := ["
                + ", ".join(writes)
                + "] }"
            )
        else:
            memory_literal = (
                ".protectedSpan { offsets := "
                + _lean_return_slot_offset_pair(memory["offsets"])
                + ", writes := [" + ", ".join(writes) + "] }"
            )
    else:
        raise StageAInputError(
            f"unsupported return-slot memory profile {memory.get('profile')!r}"
        )
    return (
        "{ transfer := { source := "
        + _lean_return_slot_offset_pair(transfer["source"])
        + ", target := " + _lean_return_slot_offset_pair(transfer["target"])
        + ", originalOutput := "
        + _lean_register_offset_witness(transfer["original_output_witness"])
        + ", candidateOutput := "
        + _lean_register_offset_witness(transfer["candidate_output_witness"])
        + " }, memory := " + memory_literal + " }"
    )

def _lean_return_slot_frame_inventory_transfer_claim(
    claim: dict[str, Any],
) -> str:
    return (
        "{ source := " + _lean_return_slot_offset_inventory(claim["source"])
        + ", target := " + _lean_return_slot_offset_inventory(claim["target"])
        + ", transfers := ["
        + ", ".join(
            _lean_return_slot_frame_transfer_claim(transfer)
            for transfer in claim["transfers"]
        )
        + "], exactWordTransfers := ["
        + ", ".join(
            _lean_return_slot_exact_word_transfer_claim(transfer)
            for transfer in claim.get("exact_word_transfers", [])
        )
        + "] }"
    )

def _lean_frame_exact_word_register_output_claim(
    claim: dict[str, Any],
) -> str:
    if claim.get("profile") != "active_frame_exact_word_register_output_v1":
        raise StageAInputError(
            "unsupported active-frame exact-word register output profile"
        )
    word = claim["word"]
    return (
        "{ sourceLocation := "
        + _lean_return_slot_offset_pair(claim["source_location"])
        + ", word := { originalOffset := " + str(int(word["original"]))
        + ", candidateOffset := " + str(int(word["candidate"]))
        + " }, output := "
        + _lean_register_relation_pair(claim["output"])
        + ", originalAddress := "
        + _lean_register_offset_witness(claim["original_address_witness"])
        + ", candidateAddress := "
        + _lean_register_offset_witness(claim["candidate_address_witness"])
        + ", originalAssembledRead := "
        + str(bool(claim.get("original_assembled_read"))).lower()
        + ", candidateAssembledRead := "
        + str(bool(claim.get("candidate_assembled_read"))).lower()
        + ", originalInputAssembledRead := "
        + str(bool(claim.get("original_input_assembled_read"))).lower()
        + ", candidateInputAssembledRead := "
        + str(bool(claim.get("candidate_input_assembled_read"))).lower()
        + ", originalWriteWitnesses := ["
        + ", ".join(
            _lean_register_offset_witness(witness)
            for witness in claim.get("original_write_witnesses", [])
        )
        + "], candidateWriteWitnesses := ["
        + ", ".join(
            _lean_register_offset_witness(witness)
            for witness in claim.get("candidate_write_witnesses", [])
        )
        + "] }"
    )

def _lean_frame_paired_expression_register_output_claim(
    claim: dict[str, Any],
) -> str:
    if claim.get("profile") != (
        "active_frame_paired_expression_register_output_v1"
    ):
        raise StageAInputError(
            "unsupported active-frame paired-expression register output profile"
        )
    return (
        "{ output := "
        + _lean_register_relation_pair(claim["output"])
        + ", witness := "
        + _lean_paired_exact_expr_witness(claim["witness"])
        + " }"
    )

def _lean_runtime_call_import_transfer_claim(
    source: dict[str, Any], target: dict[str, Any],
    carried_relations: list[dict[str, Any]] | None = None,
) -> str:
    carried_field = (
        ", carriedRelations := some ["
        + ", ".join(
            _lean_register_relation_pair(relation)
            for relation in carried_relations
        )
        + "]"
        if carried_relations is not None else ""
    )
    return (
        "{ source := " + _lean_return_slot_offset_inventory(source)
        + ", target := " + _lean_return_slot_offset_inventory(target)
        + carried_field
        + " }"
    )

def _lean_runtime_call_import_transfer_claims(
    claims: list[dict[str, Any]],
) -> str:
    return "[" + ", ".join(
        _lean_runtime_call_import_transfer_claim(
            claim["source"], claim["target"], claim.get("carried_relations")
        )
        for claim in claims
    ) + "]"


def _lean_relational_runtime_call_frame_link(link: dict[str, Any]) -> str:
    return (
        "{ callSourceTargetId := " + str(int(link["call_source_target_id"]))
        + ", resumeNodeId := " + str(int(link["resume_node_id"]))
        + ", resumeTargetId := " + str(int(link["resume_target_id"]))
        + ", resumeContinuation := " + str(int(link["resume_continuation"]))
        + ", innerInventory := "
        + _lean_return_slot_offset_inventory(link["inner_inventory"])
        + ", suspendedInventory := "
        + _lean_return_slot_offset_inventory(link["suspended_inventory"])
        + ", resumeInventory := "
        + _lean_return_slot_offset_inventory(link["resume_inventory"])
        + ", originalGap := " + str(int(link["original_gap"]))
        + ", candidateGap := " + str(int(link["candidate_gap"])) + " }"
    )


def _lean_linked_product_control_state(state: dict[str, Any]) -> str:
    continuation = (
        "none" if state["continuation_target_id"] is None
        else f"some {int(state['continuation_target_id'])}"
    )
    active = (
        "none" if state["active_frame"] is None
        else "some " + _lean_return_slot_offset_inventory(state["active_frame"])
    )
    return (
        "{ nodeId := " + str(int(state["node_id"]))
        + f", continuation := {continuation}, active := {active}"
        + f", minimumDepth := {int(state['minimum_depth'])} }}"
    )

def _lean_acceptance_running_target(
    *, node_id: int, region_index: int, edge: dict[str, Any],
    frames: str = "[]", calls: str = "[]", frame_offsets: str = "[]",
    stack_targets_proof: str = "(by simp [RelationalRuntimeCallTargetsMapped])",
    target_control_proof: str = "(by decide)",
    frame_imports_proof: str = (
        "(by simp [RelationalRuntimeCallFactsHold, "
        "RelationalRuntimeCallImportsHold, RelationalRuntimeCallRelationsHold, "
        "ReturnSlotOffsetInventory.zero, ReturnSlotOffsetInventory.singleton, "
        "ReturnSlotOffsetInventory.preservedImportsHold, "
        "ReturnSlotOffsetInventory.preservedRelationsHold, "
        "importRegisterRelationsHold, registerRelationsHold])"
    ),
    observation_proof: str = "True.intro",
    world_equal_proof: str = "rfl",
    states_related_proof: str = "nextStatesRelated",
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
        f"    stackHoldsNext, {frame_imports_proof}, {stack_targets_proof}, "
        f"{states_related_proof}⟩\n"
        "  decide"
    )


def _lean_acceptance_linked_running_target(
    *, node_id: int, edge: dict[str, Any], frames: str = "[]",
    calls: str = "[]", active: str = "none", links: str = "[]",
    stack_targets_proof: str = "(by simp [RelationalRuntimeCallTargetsMapped])",
    target_control_proof: str = "(by decide)",
    links_allowed_proof: str = "linksAllowedNext",
    frame_facts_proof: str = "frameFactsNext",
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
        f"    region{target_region_index}.inputInvariant, {frames}, {active}, {links},\n"
        f"    (by decide), targetNodeTarget, ?_, targetInvariant, {target_control_proof},\n"
        f"    stackHoldsNext, {links_allowed_proof}, {frame_facts_proof},\n"
        f"    {stack_targets_proof}, nextStatesRelated⟩\n"
        "  decide"
    )


def _linked_empty_jump_supported(step: dict[str, Any]) -> bool:
    if step.get("kind") != "jump" or step.get("cases") is not None:
        return False
    if step.get("certificate_profile") == "composable_x87_state_only_singleton_v1":
        return False
    control = step.get("control_state")
    if not isinstance(control, dict):
        return False
    if control.get("calls") != [] or control.get("frame_offsets") != []:
        return False
    return step.get("return_slot_frame_transfer_claims") == []


def _linked_shallow_profiles_supported(
    control_states: list[dict[str, Any]], linked_control: dict[str, Any]
) -> bool:
    """Check whether the finite old and linked profiles are the same at depth <= 1.

    This is only a generation preflight.  The emitted Lean theorem rechecks the
    complete finite profiles before an old local proof may be lifted.
    """

    if linked_control.get("links") != []:
        return False
    projected: list[dict[str, Any]] = []
    for state in control_states:
        calls = state.get("calls")
        frame_offsets = state.get("frame_offsets")
        if not isinstance(calls, list) or not isinstance(frame_offsets, list):
            return False
        if len(calls) != len(frame_offsets) or len(calls) > 1:
            return False
        projected.append({
            "node_id": int(state["node_id"]),
            "continuation_target_id": int(calls[0]) if calls else None,
            "active_frame": frame_offsets[0] if frame_offsets else None,
        })
    linked_states = [
        {
            "node_id": int(state["node_id"]),
            "continuation_target_id": state.get("continuation_target_id"),
            "active_frame": state.get("active_frame"),
        }
        for state in linked_control.get("states", [])
    ]
    return sorted(projected, key=lambda item: json.dumps(item, sort_keys=True)) == sorted(
        linked_states, key=lambda item: json.dumps(item, sort_keys=True)
    )


def _lean_acceptance_linked_shallow_node(
    step: dict[str, Any], *, parameterized_environment: bool = False,
    parameterized_protocol_environment: bool = False,
) -> str:
    """Lift an existing depth-zero/one node proof through a Lean-checked bridge."""

    if parameterized_protocol_environment:
        raise StageAInputError(
            "shallow linked acceptance does not yet support protocol environments"
        )
    node_id = int(step["node_id"])
    environment_binders = (
        "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
        "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
        "      externalCallSites originalEnvironment candidateEnvironment) :\n"
        if parameterized_environment else "    :\n"
    )
    original_program = (
        "(originalWorldProgram originalEnvironment)"
        if parameterized_environment else "originalWorldProgram"
    )
    candidate_program = (
        "(candidateWorldProgram candidateEnvironment)"
        if parameterized_environment else "candidateWorldProgram"
    )
    old_refined = (
        f"acceptanceRunningNode{node_id}Refined originalEnvironment "
        "candidateEnvironment environmentRefines"
        if parameterized_environment else
        f"acceptanceRunningNode{node_id}Refined"
    )
    return (
        f"theorem acceptanceLinkedRunningNode{node_id}Refined\n"
        + environment_binders
        + "    LinkedRunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      linkedProductControlProfile protocolCallbackTargets\n"
        f"      {original_program} {candidate_program} {node_id} := by\n"
        "  exact acceptanceLinkedRunningNodeRefinedOfShallow\n"
        + (
            "    originalEnvironment candidateEnvironment "
            if parameterized_environment else "    "
        )
        + f"{node_id}\n"
        f"    ({old_refined})"
    )


def _lean_acceptance_linked_shallow_lift(
    *, parameterized_environment: bool = False,
    parameterized_protocol_environment: bool = False,
) -> str:
    """Prove the old-to-linked profile bridge once for every generated node."""

    if parameterized_protocol_environment:
        raise StageAInputError(
            "shallow linked acceptance does not yet support protocol environments"
        )
    environment_binders = (
        "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
        if parameterized_environment else ""
    )
    original_program = (
        "(originalWorldProgram originalEnvironment)"
        if parameterized_environment else "originalWorldProgram"
    )
    candidate_program = (
        "(candidateWorldProgram candidateEnvironment)"
        if parameterized_environment else "candidateWorldProgram"
    )
    return (
        "theorem acceptanceLinkedRunningNodeRefinedOfShallow\n"
        + environment_binders
        + "    (nodeId : Nat)\n"
        "    (oldRefined : RunningProductNodeStepRefined staticProofContext\n"
        "      relationalProductGraph productInvariantTable\n"
        "      relationalProductReachabilityEvidence productControlProfile\n"
        f"      protocolCallbackTargets {original_program} {candidate_program}\n"
        "      nodeId) :\n"
        "    LinkedRunningProductNodeStepRefined staticProofContext\n"
        "      relationalProductGraph productInvariantTable\n"
        "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
        f"      protocolCallbackTargets {original_program} {candidate_program}\n"
        "      nodeId := by\n"
        "  exact LinkedRunningProductNodeStepRefined.of_shallow\n"
        "    staticProofContext relationalProductGraph productInvariantTable\n"
        "    relationalProductReachabilityEvidence productControlProfile\n"
        f"    linkedProductControlProfile protocolCallbackTargets {original_program}\n"
        f"    {candidate_program} nodeId\n"
        "    productControlProfilesOldToLinkedShallow\n"
        "    productControlProfilesLinkedToOldShallow\n"
        "    linkedProductControlProfileLinksEmpty oldRefined\n\n"
    )


def _linked_active_jump_case(
    step: dict[str, Any], linked_states: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if (
        step.get("kind") != "jump"
        or step.get("certificate_profile") != "composable_local_no_write_v1"
        or len(linked_states) != 1
    ):
        return None
    linked_state = linked_states[0]
    active = linked_state.get("active_frame")
    continuation = linked_state.get("continuation_target_id")
    if active is None or continuation is None:
        return None
    candidates = step.get("cases")
    if candidates is None:
        candidates = [step]
    matches: list[dict[str, Any]] = []
    for candidate in candidates:
        control = candidate.get("control_state") or {}
        calls = control.get("calls") or []
        offsets = control.get("frame_offsets") or []
        claims = candidate.get("return_slot_frame_transfer_claims") or []
        edges = candidate.get("edges") or []
        if (
            calls
            and offsets
            and int(calls[0]) == int(continuation)
            and offsets[0] == active
            and claims
            and len(edges) == 1
            and claims[0].get("source") == active
        ):
            matches.append({
                "continuation_target_id": int(continuation),
                "source_active": active,
                "target_active": claims[0]["target"],
                "frame_claim": claims[0],
                "edge": edges[0],
            })
    unique = {
        json.dumps(match, sort_keys=True, separators=(",", ":")): match
        for match in matches
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _linked_active_branch_case(
    step: dict[str, Any], linked_states: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if step.get("kind") != "branch" or len(linked_states) != 1:
        return None
    linked_state = linked_states[0]
    active = linked_state.get("active_frame")
    continuation = linked_state.get("continuation_target_id")
    if active is None or continuation is None:
        return None
    candidates = step.get("cases") or [step]
    matches: list[dict[str, Any]] = []
    for candidate in candidates:
        control = candidate.get("control_state") or {}
        calls = control.get("calls") or []
        offsets = control.get("frame_offsets") or []
        edges = candidate.get("edges") or []
        if (
            not calls
            or not offsets
            or int(calls[0]) != int(continuation)
            or offsets[0] != active
            or len(edges) != 2
            or any(
                edge.get("certificate_profile")
                    != "composable_local_no_write_deferred_guard_v1"
                or not isinstance(edge.get("frame_guard_claim"), dict)
                or len(edge.get("return_slot_frame_transfer_claims") or []) != 1
                or edge["return_slot_frame_transfer_claims"][0].get("source")
                    != active
                for edge in edges
            )
        ):
            continue
        matches.append({
            "continuation_target_id": int(continuation),
            "source_active": active,
            "edges": edges,
        })
    unique = {
        json.dumps(match, sort_keys=True, separators=(",", ":")): match
        for match in matches
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _step_uses_deferred_guard(step: dict[str, Any]) -> bool:
    """Whether a node needs linked-frame authority for at least one edge."""

    candidates = step.get("cases") or [step]
    return any(
        edge.get("certificate_profile")
            == "composable_local_no_write_deferred_guard_v1"
        for candidate in candidates
        for edge in candidate.get("edges", [])
    )


def _linked_direct_call_case(
    step: dict[str, Any], linked_states: list[dict[str, Any]],
    linked_control: dict[str, Any],
) -> dict[str, Any] | None:
    """Select a native linked direct-call proof shape.

    The first profile deliberately covers the ordinary IA-32 call instruction:
    one four-byte return-slot write, ESP-relative active inventories, and no
    dormant exact scalar words.  Richer checked write footprints can extend the
    same kernel interface without changing linked-stack composition.
    """

    if (
        step.get("kind") != "call"
        or step.get("certificate_profile") != "composable_direct_call_v1"
        or step.get("cases") is not None
        or len(step.get("edges") or []) != 1
        or len(linked_states) != 1
        or int(step.get("stack_amount", -1)) != 4
    ):
        return None
    state = linked_states[0]
    active = state.get("active_frame")
    continuation = state.get("continuation_target_id")
    control = step.get("control_state") or {}
    calls = control.get("calls") or []
    offsets = control.get("frame_offsets") or []
    seeded = step.get("seeded_frame_inventory")
    if not isinstance(seeded, dict) or seeded.get("exact_words", []) != []:
        return None
    if active is None:
        if continuation is not None or calls != [] or offsets != []:
            return None
        edge = step["edges"][0]
        targets = [
            candidate for candidate in linked_control.get("states", [])
            if int(candidate["node_id"]) == int(edge["target_node_id"])
            and candidate.get("continuation_target_id")
                == int(step["continuation_target_id"])
            and candidate.get("active_frame") == seeded
            and int(candidate.get("minimum_depth", -1)) <= 1
        ]
        if len(targets) != 1:
            return None
        return {
            "kind": "first", "source_state": state,
            "target_state": targets[0],
        }
    if (
        continuation is None
        or not calls
        or not offsets
        or int(calls[0]) != int(continuation)
        or offsets[0] != active
    ):
        return None
    claims = step.get("return_slot_frame_transfer_claims") or []
    if len(claims) != 1 or claims[0].get("source") != active:
        return None
    edge = step["edges"][0]
    matching = []
    for link in linked_control.get("links", []):
        if (
            int(link.get("source_state_id", -1)) == int(state["id"])
            and int(link.get("target_state_id", -1)) >= 0
            and int(link.get("call_source_target_id", -1)) == int(step["target_id"])
            and int(link.get("resume_target_id", -1))
                == int(step["continuation_target_id"])
            and int(link.get("resume_continuation", -1)) == int(continuation)
            and int(link.get("original_gap", -1)) == 4
            and int(link.get("candidate_gap", -1)) == 4
            and link.get("inner_inventory") == seeded
            and link.get("suspended_inventory") == claims[0].get("target")
            and link.get("inner_inventory", {}).get("exact_words", []) == []
            and link.get("suspended_inventory", {}).get("exact_words", []) == []
            and link.get("resume_inventory", {}).get("exact_words", []) == []
            and int(edge["target_node_id"])
                == int(linked_control["states"][int(link["target_state_id"])]["node_id"])
        ):
            matching.append(link)
    if len(matching) != 1:
        return None
    target_state = next((
        candidate for candidate in linked_control.get("states", [])
        if int(candidate["id"]) == int(matching[0]["target_state_id"])
    ), None)
    if target_state is None:
        return None
    return {
        "kind": "nested",
        "source_state": state,
        "target_state": target_state,
        "link": matching[0],
        "outer_claim": claims[0],
    }


def _linked_return_case(
    step: dict[str, Any], linked_states: list[dict[str, Any]],
    linked_control: dict[str, Any],
) -> dict[str, Any] | None:
    """Select an unambiguous native linked-return proof shape.

    Return dispatch is keyed by the concrete runtime-frame continuation.  The
    Lean profile rechecks that exactly one submitted link has that continuation;
    an ambiguous resume contract is never resolved by Python ordering.
    """

    if (
        step.get("kind") != "return"
        or step.get("cases") is not None
        or len(linked_states) != 1
        or step.get("active_frame_imports", []) != []
        or step.get("active_frame_relations", []) != []
        or step.get("import_transfer_claims", []) != []
    ):
        return None
    state = linked_states[0]
    active = state.get("active_frame")
    continuation = state.get("continuation_target_id")
    if (
        active is None
        or continuation is None
        or active != step.get("return_frame_inventory")
        or int(continuation) != int(step.get("target_target_id", -1))
    ):
        return None
    target_calls = (step.get("target_control_state") or {}).get("calls") or []
    target_continuation = int(target_calls[0]) if target_calls else None
    target_state = next((
        candidate for candidate in linked_control.get("states", [])
        if int(candidate["node_id"]) == int(step.get("target_node_id", -1))
        and candidate.get("continuation_target_id") == target_continuation
    ), None)
    if target_state is None:
        return None

    compatible_links = [
        link for link in linked_control.get("links", [])
        if int(link.get("resume_target_id", -1)) == int(continuation)
    ]
    claims = step.get("return_slot_frame_transfer_claims") or []
    nested = [
        link for link in compatible_links
        if int(link.get("target_state_id", -1)) == int(state["id"])
        and int(link.get("resume_state_id", -1)) == int(target_state["id"])
        and link.get("inner_inventory") == active
        and len(claims) == 1
        and claims[0].get("source") == link.get("suspended_inventory")
        and claims[0].get("target") == link.get("resume_inventory")
    ]
    if len(compatible_links) == 1 and len(nested) == 1:
        return {
            "kind": "nested",
            "source_state": state,
            "target_state": target_state,
            "link": nested[0],
            "outer_claim": claims[0],
        }
    if not compatible_links and not claims:
        target_control = step.get("target_control_state") or {}
        if (
            target_control.get("calls") == []
            and target_state.get("active_frame") is None
            and target_state.get("continuation_target_id") is None
        ):
            return {
                "kind": "last",
                "source_state": state,
                "target_state": target_state,
            }
    return None


def _lean_acceptance_linked_direct_call_node(
    step: dict[str, Any], call_case: dict[str, Any],
) -> str:
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_id = int(step["target_id"])
    edge = step["edges"][0]
    edge_id = int(edge["edge_id"])
    target_region_index = int(edge["target_region_index"])
    target_node_id = int(edge["target_node_id"])
    continuation = int(step["continuation_target_id"])
    continuation_node_id = int(step["continuation_node_id"])
    claim = step["call_push_claim"]
    original_return = int(claim["original_return_address"])
    candidate_return = int(claim["candidate_return_address"])
    stack_amount = int(step["stack_amount"])
    stack_amount_twos_complement = 2**32 - stack_amount
    source_window = _lean_stack_window(step["source_stack_window"])
    active_inventory = _lean_return_slot_offset_inventory(
        step["seeded_frame_inventory"]
    )
    protected_bytes = _runtime_frame_protected_bytes(
        step["seeded_frame_inventory"]
    )
    original_behavior = f"acceptanceOriginalNormalizedBehavior{node_id}"
    candidate_behavior = f"acceptanceCandidateNormalizedBehavior{node_id}"
    target_control_state = _lean_linked_product_control_state(
        call_case["target_state"]
    )

    common = (
        f"let activeFrameInventory : ReturnSlotOffsetInventory :=\n"
        f"  {active_inventory}\n"
        f"let sourceWindow : StackWindowPair := {source_window}\n"
        f"have stackAddressRewrite (value : Word) :\n"
        f"    value + BitVec.ofNat 32 {stack_amount_twos_complement} =\n"
        f"      value - BitVec.ofNat 32 {stack_amount} := by\n"
        f"  exact word_add_ia32_twos_complement value {stack_amount} (by decide)\n"
        f"have originalBehaviorSegment : {original_behavior} =\n"
        f"    segmentRefinementEdge{edge_id}OriginalNormalizedBehavior := by decide\n"
        f"have candidateBehaviorSegment : {candidate_behavior} =\n"
        f"    segmentRefinementEdge{edge_id}CandidateNormalizedBehavior := by decide\n"
        "let runtimeFrame : RelationalRuntimeCallFrame := {\n"
        f"  continuationTargetId := {continuation}\n"
        f"  originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
        f"  candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
        "  originalStackAddress := originalState.registers.get\n"
        f"    sourceWindow.originalRegister - BitVec.ofNat 32 {stack_amount}\n"
        "  candidateStackAddress := candidateState.registers.get\n"
        f"    sourceWindow.candidateRegister - BitVec.ofNat 32 {stack_amount}\n"
        f"  protectedBytes := {protected_bytes}\n"
        "}\n"
        f"have transition := segmentRefinementEdge{edge_id}TransitionChecked world\n"
        "  originalState candidateState statesRelated\n"
        f"have guardTrue : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
        "    originalState = true := by\n"
        f"  simp [segmentRefinementEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
        "have transitioned := transition.2 guardTrue\n"
        "have nextStatesRelated : StateRel staticProofContext world\n"
        f"    region{target_region_index}.inputInvariant\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState) := by\n"
        "  rw [originalBehaviorSegment, candidateBehaviorSegment]\n"
        "  exact transitioned.2.2.2\n"
        "have frameMemory : runtimeFrame.memoryHolds\n"
        f"    (({original_behavior}.eval originalState).nextMachineState\n"
        "      originalState).memory\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState\n"
        "      candidateState).memory := by\n"
        "  unfold RelationalRuntimeCallFrame.memoryHolds runtimeFrame\n"
        "  exact pairedStackWordWriteReadsBack_amount staticProofContext world\n"
        f"    region{region_index}.inputInvariant sourceWindow {stack_amount}\n"
        f"    (BitVec.ofNat 32 {original_return}) (BitVec.ofNat 32 {candidate_return})\n"
        "    originalState candidateState\n"
        f"    ({original_behavior}.eval originalState)\n"
        f"    ({candidate_behavior}.eval candidateState)\n"
        "    (by simp) (by simp) statesRelated\n"
        "    (by decide) (by decide) (by decide) (by decide)\n"
        "    (by simp [sourceWindow,\n"
        f"      acceptanceOriginalNormalizedWrites{node_id},\n"
        f"      originalBehavior{region_index}, evalNormalizedWrites, Expr.eval,\n"
        "      stackAddressRewrite])\n"
        "    (by simp [sourceWindow,\n"
        f"      acceptanceCandidateNormalizedWrites{node_id},\n"
        f"      candidateBehavior{region_index}, evalNormalizedWrites, Expr.eval,\n"
        "      stackAddressRewrite])\n"
        "have frameOffsetsHold : ReturnSlotOffsetPair.zero.holds runtimeFrame\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers := by\n"
        "  simp [ReturnSlotOffsetPair.zero, ReturnSlotOffsetPair.holds, runtimeFrame,\n"
        "    sourceWindow,\n"
        f"    acceptanceOriginalNormalizedRegisters{node_id},\n"
        f"    acceptanceCandidateNormalizedRegisters{node_id},\n"
        f"    originalBehavior{region_index}, candidateBehavior{region_index},\n"
        "    evalNormalizedRegisters, evalNormalizedRegisters_get,\n"
        "    StageA.Formal.Registers.get, Expr.eval, stackAddressRewrite]\n"
        "have sourceWindows := StateRel.stackWindowsHold staticProofContext world\n"
        f"  region{region_index}.inputInvariant originalState candidateState statesRelated\n"
        "simp only [stackWindowsRelated, List.all_eq_true] at sourceWindows\n"
        "have sourceWindowHolds : sourceWindow.holds world originalState.registers\n"
        "    candidateState.registers = true := by\n"
        "  exact sourceWindows sourceWindow (by decide)\n"
        "have frameProtected : runtimeFrame.protectedSpanValid\n"
        "    staticProofContext = true := by\n"
        "  exact RelationalRuntimeCallFrame.protectedSpanValid_of_window_call\n"
        "    staticProofContext world sourceWindow originalState.registers\n"
        "    candidateState.registers runtimeFrame " + str(stack_amount) + "\n"
        "    (StateRel.stackRangesValid staticProofContext world\n"
        f"      region{region_index}.inputInvariant originalState candidateState\n"
        "      statesRelated) sourceWindowHolds (by decide) (by decide)\n"
        "    (by simp [runtimeFrame]) (by simp [runtimeFrame, sourceWindow])\n"
        "    (by simp [runtimeFrame])\n"
        "    (by simp [runtimeFrame])\n"
        "have frameValid : runtimeFrame.valid staticProofContext = true := by\n"
        "  unfold RelationalRuntimeCallFrame.valid\n"
        "  simp only [Bool.and_eq_true]\n"
        "  constructor\n"
        "  · change RelationalCallFrame.valid staticProofContext {\n"
        f"    continuationTargetId := {continuation}\n"
        f"    originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
        f"    candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
        "    } = true\n"
        "    decide\n"
        "  · exact frameProtected\n"
        "have frameResolves : runtimeFrame.toRelationalCallFrame.resolves\n"
        "    staticProofContext = true := by\n"
        "  change RelationalCallFrame.resolves staticProofContext {\n"
        f"    continuationTargetId := {continuation}\n"
        f"    originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
        f"    candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
        "  } = true\n"
        "  decide\n"
        "have activeFrameInventoryHolds : activeFrameInventory.holds runtimeFrame\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers := by\n"
        "  refine And.intro (by decide) ?_\n"
        "  intro location locationMember\n"
        "  have locationExact : location = ReturnSlotOffsetPair.zero := by\n"
        "    simpa [activeFrameInventory] using locationMember\n"
        "  subst location\n"
        "  exact frameOffsetsHold\n"
        "have activeFrameExactWords : activeFrameInventory.boundedExactWordsHold runtimeFrame\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState).memory\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState).memory := by\n"
        "  simp [activeFrameInventory, ReturnSlotOffsetInventory.boundedExactWordsHold,\n"
        "    ReturnSlotOffsetInventory.exactWordsFit,\n"
        "    ReturnSlotOffsetInventory.exactWordsHold, runtimeFrame]\n"
        "have activeFrameImportSeedChecked :\n"
        "    activeFrameInventory.seedsPreservedImportsFrom\n"
        f"      region{region_index}.inputInvariant {original_behavior}\n"
        f"      {candidate_behavior} = true := by decide\n"
        "have activeFrameImportsNext : activeFrameInventory.preservedImportsHold\n"
        "    world\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers = true := by\n"
        "  exact ReturnSlotOffsetInventory."
        "preservedImportsHold_after_stateRel_of_checked\n"
        "    staticProofContext activeFrameInventory world\n"
        f"    region{region_index}.inputInvariant {original_behavior}\n"
        f"    {candidate_behavior} originalState candidateState\n"
        "    activeFrameImportSeedChecked statesRelated\n"
        "let activeFrameRegisterClaims : List InvariantWP.RegisterOutputClaim := ["
        + ", ".join(
            _lean_register_output_claim(output_claim)
            for output_claim in step.get("seeded_register_output_claims", [])
        )
        + "]\n"
        "have activeFrameRelationSeedChecked :\n"
        "    activeFrameInventory.seedsPreservedRelationsFromOutputClaims\n"
        f"      staticProofContext region{region_index} {original_behavior}\n"
        f"      {candidate_behavior} activeFrameRegisterClaims = true := by decide\n"
        "have activeFrameRelationsNext :\n"
        "    activeFrameInventory.preservedRelationsHold staticProofContext world\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers = true := by\n"
        "  exact ReturnSlotOffsetInventory."
        "preservedRelationsHold_after_stateRel_of_outputClaims\n"
        "    staticProofContext activeFrameInventory world\n"
        f"    region{region_index} {original_behavior} {candidate_behavior}\n"
        "    activeFrameRegisterClaims originalState candidateState\n"
        "    activeFrameRelationSeedChecked statesRelated\n"
        "have frameFactsNext : RelationalLinkedRuntimeCallFactsHold\n"
        "    staticProofContext world (some activeFrameInventory)\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers := by\n"
        "  exact ⟨activeFrameImportsNext, activeFrameRelationsNext⟩\n"
    )

    if call_case["kind"] == "first":
        control_setup = (
            "  have controlHead : none = calls.head? ∧ none = active := by\n"
            "    simpa [linkedProductControlProfile, LinkedProductControlState.matches] "
            "using controlMember.2\n"
            "  have controlShape : calls = [] ∧ active = none := by\n"
            "    constructor\n"
            "    · exact continuations_eq_nil_of_head?_eq_none calls controlHead.1\n"
            "    · exact controlHead.2.symm\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
            "  have stackShape : frames = [] ∧ links = [] := by\n"
            "    exact RelationalLinkedRuntimeCallStackHolds.empty_shape\n"
            "      staticProofContext originalState candidateState frames links stackHolds\n"
            "  rcases stackShape with ⟨rfl, rfl⟩\n"
        )
        stack_proof = (
            "have stackHoldsNext : RelationalLinkedRuntimeCallStackHolds\n"
            "    staticProofContext\n"
            f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            f"    [runtimeFrame] [{continuation}] (some activeFrameInventory) [] := by\n"
            "  exact RelationalLinkedRuntimeCallStackHolds.pushFirst staticProofContext\n"
            f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "    runtimeFrame " + str(continuation) + " activeFrameInventory (by decide)\n"
            "    activeFrameInventoryHolds activeFrameExactWords rfl frameValid\n"
            "    frameResolves frameMemory\n"
            "have linksAllowedNext : linkedProductControlProfile.LinksAllowed [] := by\n"
            "  exact LinkedProductControlProfile.LinksAllowed.nil\n"
            "    linkedProductControlProfile linkedProductControlProfileChecked\n"
            f"let targetControlState : LinkedProductControlState := "
            f"{target_control_state}\n"
            "have controlAllowedNext : linkedProductControlProfile.Allows\n"
            f"    {target_node_id} [{continuation}] (some activeFrameInventory) = true := by\n"
            "  exact LinkedProductControlProfile.allowsOfListedState\n"
            "    linkedProductControlProfile targetControlState _ _ _\n"
            "    linkedProductControlProfileChecked\n"
            "    (by simp [targetControlState, linkedProductControlProfile])\n"
            "    (by simp [targetControlState, LinkedProductControlState.matches, "
            "      activeFrameInventory])\n"
            "    (by simp [targetControlState])\n"
        )
        target = _lean_acceptance_linked_running_target(
            node_id=node_id,
            edge=edge,
            frames="[runtimeFrame]",
            calls=f"[{continuation}]",
            active="some activeFrameInventory",
            links="[]",
            target_control_proof="controlAllowedNext",
            links_allowed_proof="linksAllowedNext",
            frame_facts_proof="frameFactsNext",
            stack_targets_proof=(
                "(by simp only [RelationalRuntimeCallTargetsMapped]; "
                f"exact ⟨⟨{continuation_node_id}, relationalProductGraph.nodes["
                f"{continuation_node_id}], by decide, by decide⟩, True.intro⟩)"
            ),
        )
        body = (
            control_setup
            + "\n".join("  " + line for line in (common + stack_proof).splitlines())
            + "\n"
            + target
        )
    else:
        link = call_case["link"]
        outer_claim = call_case["outer_claim"]
        source_active = _lean_return_slot_offset_inventory(
            call_case["source_state"]["active_frame"]
        )
        source_minimum_depth = int(call_case["source_state"]["minimum_depth"])
        link_literal = _lean_relational_runtime_call_frame_link(link)
        outer_claim_literal = _lean_return_slot_frame_inventory_transfer_claim(
            outer_claim
        )
        source_continuation = int(call_case["source_state"]["continuation_target_id"])
        control_setup = (
            f"  have controlShape : (some {source_continuation} = calls.head? ∧\n"
            f"      some {source_active} = active) ∧\n"
            f"      {source_minimum_depth} <= calls.length := by\n"
            "    simpa [linkedProductControlProfile, LinkedProductControlState.matches] "
            "using controlMember.2\n"
            "  cases calls with\n"
            "  | nil => simp at controlShape\n"
            "  | cons selected continuations =>\n"
            "    simp only [List.head?_cons, Option.some.injEq] at controlShape\n"
            "    rcases controlShape with ⟨⟨rfl, rfl⟩, _depthEnough⟩\n"
            "    cases frames with\n"
            "    | nil => simp [RelationalLinkedRuntimeCallStackHolds] at stackHolds\n"
            "    | cons outer frames =>\n"
        )
        nested = (
            f"let outerClaim : ReturnSlotFrameInventoryTransferClaim :=\n"
            f"  {outer_claim_literal}\n"
            f"let newLink : RelationalRuntimeCallFrameLink := {link_literal}\n"
            + common
            + "have stackShape := stackHolds\n"
            "simp only [RelationalLinkedRuntimeCallStackHolds] at stackShape\n"
            "have outerOffsetsHold : ReturnSlotOffsetPair.zero.holds outer\n"
            "    originalState.registers candidateState.registers := by\n"
            "  have sourceHolds : outerClaim.source.holds outer\n"
            "      originalState.registers candidateState.registers := by\n"
            "    simpa [outerClaim] using stackShape.2.1\n"
            "  exact sourceHolds.2 ReturnSlotOffsetPair.zero (by decide)\n"
            "have linkHolds : newLink.holds runtimeFrame outer := by\n"
            "  exact RelationalRuntimeCallFrameLink.holds_of_esp_call\n"
            "    staticProofContext world sourceWindow originalState.registers\n"
            "    candidateState.registers\n"
            f"    ({original_behavior}.eval originalState).registers\n"
            f"    ({candidate_behavior}.eval candidateState).registers\n"
            f"    runtimeFrame outer newLink {stack_amount}\n"
            "    (StateRel.stackRangesValid staticProofContext world\n"
            f"      region{region_index}.inputInvariant originalState candidateState\n"
            "      statesRelated) sourceWindowHolds (by decide) (by decide)\n"
            "    (by decide) (by decide) (by decide)\n"
            "    (by simp [sourceWindow,\n"
            f"      acceptanceOriginalNormalizedRegisters{node_id},\n"
            f"      originalBehavior{region_index}, evalNormalizedRegisters,\n"
            "      evalNormalizedRegisters_get, StageA.Formal.Registers.get,\n"
            "      Expr.eval, stackAddressRewrite])\n"
            "    (by simp [sourceWindow,\n"
            f"      acceptanceCandidateNormalizedRegisters{node_id},\n"
            f"      candidateBehavior{region_index}, evalNormalizedRegisters,\n"
            "      evalNormalizedRegisters_get, StageA.Formal.Registers.get,\n"
            "      Expr.eval, stackAddressRewrite])\n"
            "    outerOffsetsHold frameOffsetsHold (by decide) (by decide)\n"
            "    (by decide) rfl (by simpa [newLink] using stackShape.2.2.2.1.1)\n"
            "    (by decide) (by decide)\n"
            "have originalMemory :\n"
            f"    (({original_behavior}.eval originalState).nextMachineState originalState).memory =\n"
            "      originalState.memory.write32 runtimeFrame.originalStackAddress\n"
            "        runtimeFrame.originalReturnAddress := by\n"
            "  simp [RelationalBehavior.nextMachineState, runtimeFrame, sourceWindow,\n"
            f"    acceptanceOriginalNormalizedWrites{node_id}, originalBehavior{region_index},\n"
            "    evalNormalizedWrites, applyConcreteWrites, Expr.eval, stackAddressRewrite]\n"
            "have candidateMemory :\n"
            f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState).memory =\n"
            "      candidateState.memory.write32 runtimeFrame.candidateStackAddress\n"
            "        runtimeFrame.candidateReturnAddress := by\n"
            "  simp [RelationalBehavior.nextMachineState, runtimeFrame, sourceWindow,\n"
            f"    acceptanceCandidateNormalizedWrites{node_id}, candidateBehavior{region_index},\n"
            "    evalNormalizedWrites, applyConcreteWrites, Expr.eval, stackAddressRewrite]\n"
            "have stackHoldsNext : RelationalLinkedRuntimeCallStackHolds\n"
            "    staticProofContext\n"
            f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            f"    (runtimeFrame :: outer :: frames) ({continuation} :: "
            f"{source_continuation} :: continuations)\n"
            "    (some activeFrameInventory) (newLink :: links) := by\n"
            "  exact RelationalLinkedRuntimeCallStackHolds."
            "pushNestedAfterSingletonWrite\n"
            f"    staticProofContext world region{region_index}.inputInvariant\n"
            f"    {original_behavior} {candidate_behavior} outerClaim originalState\n"
            "    candidateState runtimeFrame outer frames continuations newLink links\n"
            "    (by simpa [outerClaim, newLink] using stackHolds) (by decide)\n"
            "    statesRelated linkHolds (by decide) activeFrameInventoryHolds\n"
            "    activeFrameExactWords frameValid frameResolves frameMemory\n"
            "    originalMemory candidateMemory\n"
            "have linksAllowedNext : linkedProductControlProfile.LinksAllowed\n"
            "    (newLink :: links) := by\n"
            "  exact LinkedProductControlProfile.LinksAllowed.cons\n"
            "    linkedProductControlProfile newLink links (by decide) linksAllowed\n"
            f"let targetControlState : LinkedProductControlState := "
            f"{target_control_state}\n"
            "have controlAllowedNext : linkedProductControlProfile.Allows\n"
            f"    {target_node_id} ({continuation} :: {source_continuation} :: continuations)\n"
            "    (some activeFrameInventory) = true := by\n"
            "  exact LinkedProductControlProfile.allowsOfListedState\n"
            "    linkedProductControlProfile targetControlState _ _ _\n"
            "    linkedProductControlProfileChecked\n"
            "    (by simp [targetControlState, linkedProductControlProfile])\n"
            "    (by simp [targetControlState, LinkedProductControlState.matches, "
            "      activeFrameInventory])\n"
            "    (by simp [targetControlState])\n"
        )
        target = _lean_acceptance_linked_running_target(
            node_id=node_id,
            edge=edge,
            frames="runtimeFrame :: outer :: frames",
            calls=f"{continuation} :: {source_continuation} :: continuations",
            active="some activeFrameInventory",
            links="newLink :: links",
            target_control_proof="controlAllowedNext",
            links_allowed_proof="linksAllowedNext",
            frame_facts_proof="frameFactsNext",
            stack_targets_proof=(
                "(by simp only [RelationalRuntimeCallTargetsMapped]; "
                f"exact ⟨⟨{continuation_node_id}, "
                f"relationalProductGraph.nodes[{continuation_node_id}], "
                "by decide, by decide⟩, stackTargetsReachable⟩)"
            ),
        )
        body = (
            control_setup
            + "\n".join("    " + line for line in nested.splitlines())
            + "\n"
            + "\n".join("  " + line for line in target.splitlines())
        )

    return (
        f"theorem acceptanceLinkedRunningNode{node_id}Refined :\n"
        "    LinkedRunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      linkedProductControlProfile protocolCallbackTargets\n"
        f"      originalWorldProgram candidateWorldProgram {node_id} := by\n"
        "  unfold LinkedRunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {target_id} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls active links eventIndex world originalState candidateState\n"
        "    controlAllowed stackHolds linksAllowed frameFactsHold\n"
        "    stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [LinkedProductControlProfile.authority, "
        "LinkedProductControlProfile.Allows, Bool.and_eq_true] at controlMember\n"
        "  unfold DecodedWorldProgram.transitionSystem\n"
        "  simp only [stepWorldExecution]\n"
        f"  rw [originalWorldBehaviorNode{node_id}, candidateWorldBehaviorNode{node_id}]\n"
        "  simp only [transitionFromWorldBehavior, transitionFromWorldOutcome,\n"
        "    NormalizedSymbolicBehavior.eval_outcome,\n"
        f"    acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"    acceptanceCandidateNormalizedOutcome{node_id}, NormalizedOutcomeExpr.eval]\n"
        + body
    )


def _lean_acceptance_linked_return_node(
    step: dict[str, Any], return_case: dict[str, Any],
) -> str:
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_node_id = int(step["target_node_id"])
    target_region_index = int(step["target_region_index"])
    continuation = int(step["target_target_id"])
    source_state = return_case["source_state"]
    minimum_depth = int(source_state["minimum_depth"])
    target_control_state = _lean_linked_product_control_state(
        return_case["target_state"]
    )
    active_inventory = _lean_return_slot_offset_inventory(
        step["return_frame_inventory"]
    )
    original_behavior = f"acceptanceOriginalNormalizedBehavior{node_id}"
    candidate_behavior = f"acceptanceCandidateNormalizedBehavior{node_id}"
    return_claim = step["return_pop_claim"]
    frame_claim = step["return_frame_claim"]
    return_claim_literal = (
        "{ originalStackAddress := "
        + _lean_semantic_expr(return_claim["original_stack_address"])
        + ", candidateStackAddress := "
        + _lean_semantic_expr(return_claim["candidate_stack_address"])
        + f", popBytes := {int(return_claim['pop_bytes'])} }}"
    )
    frame_claim_literal = (
        "{ offsets := "
        + _lean_return_slot_offset_pair(frame_claim["offsets"])
        + ", originalSlot := "
        + _lean_register_offset_witness(frame_claim["original_slot_witness"])
        + ", candidateSlot := "
        + _lean_register_offset_witness(frame_claim["candidate_slot_witness"])
        + " }"
    )
    selected_offsets = _lean_return_slot_offset_pair(frame_claim["offsets"])
    output_claims = ", ".join(
        _lean_register_output_claim(claim) for claim in step["output_claims"]
    )
    stack_transfers = ", ".join(
        _lean_stack_window_transfer_claim(claim)
        for claim in step["stack_window_transfers"]
    )
    flag_transfer_claim = step.get("flag_transfer_claim")
    if flag_transfer_claim is None:
        output_flags_proof = (
            f"  simp [RegionRelation.inputInvariant, region{target_region_index}, "
            "flagsRelated]"
        )
    else:
        output_flags_proof = "\n".join(
            "  " + line
            for line in _lean_preserved_input_flags_proof(
                claim=flag_transfer_claim,
                source_region_index=region_index,
                original_behavior=original_behavior,
                candidate_behavior=candidate_behavior,
            ).splitlines()
        )

    state_relation = (
        "have relatedForTransfer := statesRelated\n"
        "rcases statesRelated with\n"
        "  ⟨_worldValid, stackRangesValid, _stackMemory, _importsStatic,\n"
        "    _importsComplete, _importsMemory, _originalImmutable,\n"
        "    _candidateImmutable, relatedCore, _inputImportRegisters⟩\n"
        "rcases relatedCore with\n"
        "  ⟨_inputRegisters, _inputBounds, _inputSeparations, inputStackWindows,\n"
        "    _inputMemory, _inputDynamicMemory, _inputUndefined, inputX87,\n"
        "    inputFlags, _inputFsBase⟩\n"
        f"let outputClaims : List InvariantWP.RegisterOutputClaim := [{output_claims}]\n"
        "have outputRegisters : registerRelationsHold\n"
        "    staticProofContext.originalPe.imageBase\n"
        "    staticProofContext.candidatePe.imageBase\n"
        "    staticProofContext.codeMap.entries.toList\n"
        "    (staticProofContext.relationalValueTargets world)\n"
        f"    region{target_region_index}.inputInvariant.registerRelations\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers = true := by\n"
        "  have inventory : outputClaims.map InvariantWP.RegisterOutputClaim.output =\n"
        f"      region{target_region_index}.inputInvariant.registerRelations := by decide\n"
        "  rw [← inventory]\n"
        "  exact InvariantWP.registerRelationsHold_of_nonMemoryOutputClaims\n"
        f"    staticProofContext world region{region_index} {original_behavior}\n"
        f"    {candidate_behavior} outputClaims (by decide) originalState\n"
        "    candidateState relatedForTransfer\n"
        "have outputBounds : boundsRelated\n"
        f"    region{target_region_index}.inputInvariant.bounds\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers = true := by\n"
        f"  simp [RegionRelation.inputInvariant, region{target_region_index}, boundsRelated]\n"
        "have outputSeparations : addressSeparationsRelated\n"
        f"    region{target_region_index}.inputInvariant.addressSeparations\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers = true := by\n"
        f"  simp [RegionRelation.inputInvariant, region{target_region_index},\n"
        "    addressSeparationsRelated]\n"
        f"let stackTransfers : List StackWindowAffineTransferClaim := [{stack_transfers}]\n"
        "have outputStackWindows := stackWindowsRelated_after_affine_of_checked\n"
        f"  staticProofContext world region{region_index}.inputInvariant\n"
        f"  region{target_region_index}.inputInvariant {original_behavior}\n"
        f"  {candidate_behavior} stackTransfers originalState candidateState\n"
        "  stackRangesValid inputStackWindows (by decide)\n"
        f"have originalX87Field : {original_behavior}.x87 =\n"
        f"    originalBehavior{region_index}.x87 := by decide\n"
        f"have candidateX87Field : {candidate_behavior}.x87 =\n"
        f"    candidateBehavior{region_index}.x87 := by decide\n"
        "have outputX87 :\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState).x87 =\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState).x87 := by\n"
        "  have inputLegacyX87 := inputX87.1\n"
        "  simp [originalX87Field, candidateX87Field,\n"
        f"    originalBehavior{region_index}, candidateBehavior{region_index},\n"
        "    RelationalBehavior.nextMachineState, evalNormalizedX87,\n"
        "    X87Expr.eval, Expr.eval, inputLegacyX87]\n"
        "have outputFlags : flagsRelated\n"
        f"    region{target_region_index}.inputInvariant.flagBits\n"
        f"    ({original_behavior}.eval originalState).eflags\n"
        f"    ({candidate_behavior}.eval candidateState).eflags = true := by\n"
        + output_flags_proof + "\n"
        f"have originalWritesField : {original_behavior}.writes = [] := by decide\n"
        f"have candidateWritesField : {candidate_behavior}.writes = [] := by decide\n"
        f"have originalWrites : ({original_behavior}.eval originalState).writes = [] := by\n"
        "  simp [originalWritesField, evalNormalizedWrites]\n"
        f"have candidateWrites : ({candidate_behavior}.eval candidateState).writes = [] := by\n"
        "  simp [candidateWritesField, evalNormalizedWrites]\n"
        "have originalMemory :\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState).memory =\n"
        "      originalState.memory := by\n"
        "  change applyConcreteWrites originalState.memory\n"
        f"      (({original_behavior}.eval originalState).writes) = originalState.memory\n"
        "  rw [originalWrites]\n"
        "  rfl\n"
        "have candidateMemory :\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState).memory =\n"
        "      candidateState.memory := by\n"
        "  change applyConcreteWrites candidateState.memory\n"
        f"      (({candidate_behavior}.eval candidateState).writes) = candidateState.memory\n"
        "  rw [candidateWrites]\n"
        "  rfl\n"
        "have outputImports : importRegisterRelationsHold world\n"
        f"    region{target_region_index}.inputInvariant.importRegisterRelations\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers = true := by\n"
        f"  simp [RegionRelation.inputInvariant, region{target_region_index},\n"
        "    importRegisterRelationsHold]\n"
        "have outputDynamic : activeDynamicRegisterRangeRelationsHold staticProofContext world\n"
        f"    region{target_region_index}.inputInvariant.dynamicRegisterRangeRelations\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState) = true := by\n"
        f"  simp [RegionRelation.inputInvariant, region{target_region_index},\n"
        "    activeDynamicRegisterRangeRelationsHold]\n"
        "have outputDynamicStack : activeDynamicStackRangeRelationsHold staticProofContext world\n"
        f"    region{target_region_index}.inputInvariant.dynamicStackRangeRelations\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState) = true := by\n"
        f"  simp [RegionRelation.inputInvariant, region{target_region_index},\n"
        "    activeDynamicStackRangeRelationsHold]\n"
        "have nextStatesRelated : StateRel staticProofContext world\n"
        f"    region{target_region_index}.inputInvariant\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState) :=\n"
        "  StateRel.afterNoWriteEvaluation staticProofContext world\n"
        f"    region{region_index}.inputInvariant region{target_region_index}.inputInvariant\n"
        f"    originalState candidateState ({original_behavior}.eval originalState)\n"
        f"    ({candidate_behavior}.eval candidateState) relatedForTransfer\n"
        "    originalWrites candidateWrites (by simp) (by simp)\n"
        "    outputRegisters outputBounds outputSeparations outputStackWindows\n"
        "    outputX87 outputFlags outputImports outputDynamic outputDynamicStack\n"
        f"    (by simp [RegionRelation.inputInvariant, region{target_region_index},\n"
        "      pairedStatePredicatesHold])\n"
    )

    control = (
        "  have controlShape : (some " + str(continuation) + " = calls.head? ∧\n"
        f"      some {active_inventory} = active) ∧ {minimum_depth} <= calls.length := by\n"
        "    simpa [linkedProductControlProfile, LinkedProductControlState.matches] "
        "using controlMember.2\n"
        "  cases calls with\n"
        "  | nil => simp at controlShape\n"
        "  | cons selected continuations =>\n"
        "    simp only [List.head?_cons, Option.some.injEq, List.length_cons] at controlShape\n"
        "    rcases controlShape with ⟨⟨rfl, rfl⟩, depthEnough⟩\n"
        "    cases frames with\n"
        "    | nil => simp [RelationalLinkedRuntimeCallStackHolds] at stackHolds\n"
        "    | cons frame frames =>\n"
    )
    common = (
        "have stackShape := stackHolds\n"
        "simp only [RelationalLinkedRuntimeCallStackHolds] at stackShape\n"
        "have frameContinuation := stackShape.2.2.2.1.1\n"
        "have frameResolves := stackShape.2.2.2.1.2.2.1\n"
        "have frameMemory := stackShape.2.2.2.1.2.2.2.1\n"
        f"have selectedFrameOffsetsHold : ({selected_offsets} : ReturnSlotOffsetPair).holds\n"
        "    frame originalState.registers candidateState.registers := by\n"
        f"  exact stackShape.2.1.2 ({selected_offsets} : ReturnSlotOffsetPair) (by decide)\n"
        f"let returnClaim : ReturnPopClaim := {return_claim_literal}\n"
        f"let frameClaim : ReturnPopFrameClaim := {frame_claim_literal}\n"
        "have returnTargets := returnPopTargetsRuntimeFrame_of_checked\n"
        f"  {original_behavior} {candidate_behavior} returnClaim frameClaim frame\n"
        "  originalState candidateState (by decide) (by decide)\n"
        "  selectedFrameOffsetsHold frameMemory\n"
        f"simp only [acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"  acceptanceCandidateNormalizedOutcome{node_id},\n"
        "  NormalizedOutcomeExpr.eval, PureOutcome.returned.injEq] at returnTargets\n"
        + state_relation
    )

    target_edge = {
        "target_node_id": target_node_id,
        "target_region_index": target_region_index,
        "target_target_id": continuation,
    }
    if return_case["kind"] == "nested":
        link = return_case["link"]
        link_literal = _lean_relational_runtime_call_frame_link(link)
        claim_literal = _lean_return_slot_frame_inventory_transfer_claim(
            return_case["outer_claim"]
        )
        target = _lean_acceptance_linked_running_target(
            node_id=node_id,
            edge=target_edge,
            frames="outer :: tailFrames",
            calls="outerContinuation :: tailContinuations",
            active="some expectedLink.resumeInventory",
            links="tailLinks",
            target_control_proof="controlAllowedNext",
            links_allowed_proof="linksAllowedNext",
            frame_facts_proof="frameFactsNext",
            stack_targets_proof=(
                "(by simpa only [RelationalRuntimeCallTargetsMapped] using "
                "stackTargetsReachable.2)"
            ),
        )
        body = (
            "cases continuations with\n"
            "| nil => simp at depthEnough\n"
            "| cons outerContinuation tailContinuations =>\n"
            "  cases frames with\n"
            "  | nil =>\n"
            "    have frameLengths :=\n"
            "      RelationalLinkedRuntimeCallStackHolds.length_eq\n"
            "        staticProofContext originalState candidateState _ _ _ _ stackHolds\n"
            "    simp at frameLengths\n"
            "  | cons outer tailFrames =>\n"
            "    cases links with\n"
            "    | nil =>\n"
            "      have impossible := stackHolds\n"
            "      simp [RelationalLinkedRuntimeCallStackHolds,\n"
            "        RelationalRuntimeCallFrameLinksHold] at impossible\n"
            "    | cons selectedLink tailLinks =>\n"
            f"      let expectedLink : RelationalRuntimeCallFrameLink := {link_literal}\n"
            f"      let outerClaim : ReturnSlotFrameInventoryTransferClaim := {claim_literal}\n"
            + "\n".join("      " + line for line in common.splitlines()) + "\n"
            "      have selectedLinkHolds := stackShape.2.2.2.2.1\n"
            "      have selectedLinkExact : selectedLink = expectedLink :=\n"
            "        LinkedProductControlProfile.selectedHeadLink_eq\n"
            "          linkedProductControlProfile " + str(continuation) + " expectedLink\n"
            "          selectedLink frame outer tailLinks (by decide) linksAllowed\n"
            "          frameContinuation selectedLinkHolds\n"
            "      subst selectedLink\n"
            "      have stackHoldsNext : RelationalLinkedRuntimeCallStackHolds\n"
            "          staticProofContext\n"
            f"          (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"          (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "          (outer :: tailFrames) (outerContinuation :: tailContinuations)\n"
            "          (some expectedLink.resumeInventory) tailLinks := by\n"
            "        exact RelationalLinkedRuntimeCallStackHolds."
            "popNestedAfterNoWriteTransfer\n"
            f"          staticProofContext world region{region_index}.inputInvariant\n"
            f"          {original_behavior} {candidate_behavior} outerClaim\n"
            "          originalState candidateState frame outer tailFrames\n"
            f"          {continuation} outerContinuation tailContinuations\n"
            f"          {active_inventory} expectedLink tailLinks stackHolds\n"
            "          (by decide) relatedForTransfer (by decide) (by decide)\n"
            "          (by decide) originalMemory candidateMemory\n"
            "      have linksAllowedNext := LinkedProductControlProfile.LinksAllowed.tail\n"
            "        linkedProductControlProfile expectedLink tailLinks linksAllowed\n"
            "      have controlAllowedRaw := LinkedProductControlProfile.allowsResumeOfLink\n"
            "        linkedProductControlProfile expectedLink frame outer tailContinuations\n"
            "        (by decide) selectedLinkHolds\n"
            "      have outerContinuationExact : outer.continuationTargetId =\n"
            "          outerContinuation := stackShape.2.2.2.1.2.2.2.2.1\n"
            "      have controlAllowedNext : linkedProductControlProfile.Allows\n"
            f"          {target_node_id} (outerContinuation :: tailContinuations)\n"
            "          (some expectedLink.resumeInventory) = true := by\n"
            "        simpa [expectedLink, outerContinuationExact] using controlAllowedRaw\n"
            "      have frameFactsNext := RelationalLinkedRuntimeCallFactsHold.of_stateRel\n"
            f"        staticProofContext world region{target_region_index}.inputInvariant\n"
            "        expectedLink.resumeInventory\n"
            f"        (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "        (by decide) nextStatesRelated\n"
            "      simp only [RelationalCallFrame.resolves, Bool.and_eq_true, beq_iff_eq]\n"
            "        at frameResolves\n"
            "      rw [frameContinuation] at frameResolves\n"
            "      simp [originalWorldProgram, candidateWorldProgram]\n"
            "      rw [returnTargets.1, returnTargets.2, frameResolves.1, frameResolves.2]\n"
            "      simp\n"
            + "\n".join("    " + line for line in target.splitlines())
        )
    else:
        target = _lean_acceptance_linked_running_target(
            node_id=node_id,
            edge=target_edge,
            frames="[]", calls="[]", active="none", links="[]",
            target_control_proof="controlAllowedNext",
            links_allowed_proof="linksAllowedNext",
            frame_facts_proof=(
                "(by simp [RelationalLinkedRuntimeCallFactsHold])"
            ),
            stack_targets_proof=(
                "(by simp [RelationalRuntimeCallTargetsMapped])"
            ),
        )
        body = (
            "have shallowCalls :=\n"
            "  RelationalLinkedRuntimeCallStackHolds."
            "shallow_calls_of_excluded_resume_target\n"
            "    staticProofContext linkedProductControlProfile originalState\n"
            "    candidateState (frame :: frames) (" + str(continuation) + " :: continuations)\n"
            f"    (some {active_inventory}) links {continuation} (by simp)\n"
            "    (by decide) stackHolds linksAllowed\n"
            "have continuationsEmpty : continuations = [] := by\n"
            "  rcases shallowCalls with impossible | ⟨selected, singleton⟩\n"
            "  · simp at impossible\n"
            "  · exact (List.cons.inj singleton).2\n"
            "subst continuations\n"
            "cases frames with\n"
            "| nil =>\n"
            + "\n".join("  " + line for line in common.splitlines()) + "\n"
            + "  have linksEmpty : links = [] := by\n"
            "    cases links with\n"
            "    | nil => rfl\n"
            "    | cons link tail =>\n"
            "      have impossible := stackHolds\n"
            "      simp [RelationalLinkedRuntimeCallStackHolds,\n"
            "        RelationalRuntimeCallFrameLinksHold] at impossible\n"
            "  subst links\n"
            "  have stackHoldsNext :=\n"
            "    RelationalLinkedRuntimeCallStackHolds.popLastAfter\n"
            "      staticProofContext originalState candidateState\n"
            f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            f"      frame {continuation} {active_inventory} (by\n"
            "        simpa using stackHolds)\n"
            "  have linksAllowedNext := LinkedProductControlProfile.LinksAllowed.nil\n"
            "    linkedProductControlProfile linkedProductControlProfileChecked\n"
            f"  let targetControlState : LinkedProductControlState := {target_control_state}\n"
            "  have controlAllowedNext : linkedProductControlProfile.Allows\n"
            f"      {target_node_id} [] none = true := by\n"
            "    exact LinkedProductControlProfile.allowsOfListedState\n"
            "      linkedProductControlProfile targetControlState _ _ _\n"
            "      linkedProductControlProfileChecked\n"
            "      (by simp [targetControlState, linkedProductControlProfile])\n"
            "      (by simp [targetControlState, LinkedProductControlState.matches])\n"
            "      (by simp [targetControlState])\n"
            "  simp only [RelationalCallFrame.resolves, Bool.and_eq_true, beq_iff_eq]\n"
            "    at frameResolves\n"
            "  rw [frameContinuation] at frameResolves\n"
            "  simp [originalWorldProgram, candidateWorldProgram]\n"
            "  rw [returnTargets.1, returnTargets.2, frameResolves.1, frameResolves.2]\n"
            "  simp\n"
            + "\n".join("" + line for line in target.splitlines())
            + "\n| cons unexpected tailFrames =>\n"
            "  have impossible := stackHolds\n"
            "  simp [RelationalLinkedRuntimeCallStackHolds,\n"
            "    RelationalRuntimeCallFramesHold] at impossible\n"
        )

    indented_body = "\n".join("      " + line for line in body.splitlines())
    return (
        f"theorem acceptanceLinkedRunningNode{node_id}Refined :\n"
        "    LinkedRunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      linkedProductControlProfile protocolCallbackTargets\n"
        f"      originalWorldProgram candidateWorldProgram {node_id} := by\n"
        "  unfold LinkedRunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {int(step['target_id'])} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls active links eventIndex world originalState candidateState\n"
        "    controlAllowed stackHolds linksAllowed frameFactsHold\n"
        "    stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [LinkedProductControlProfile.authority, "
        "LinkedProductControlProfile.Allows, Bool.and_eq_true] at controlMember\n"
        "  unfold DecodedWorldProgram.transitionSystem\n"
        "  simp only [stepWorldExecution]\n"
        f"  rw [originalWorldBehaviorNode{node_id}, candidateWorldBehaviorNode{node_id}]\n"
        "  simp only [transitionFromWorldBehavior, transitionFromWorldOutcome,\n"
        "    NormalizedSymbolicBehavior.eval_outcome,\n"
        f"    acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"    acceptanceCandidateNormalizedOutcome{node_id}, NormalizedOutcomeExpr.eval]\n"
        + control
        + indented_body
    )


def _linked_empty_terminate_supported(
    step: dict[str, Any], linked_states: list[dict[str, Any]],
) -> bool:
    return bool(
        step.get("kind") == "terminate"
        and step.get("cases") is None
        and len(linked_states) == 1
        and linked_states[0].get("continuation_target_id") is None
        and linked_states[0].get("active_frame") is None
        and int(linked_states[0].get("minimum_depth", -1)) == 0
        and (step.get("control_state") or {}).get("calls") == []
    )


def _lean_acceptance_linked_empty_terminate_node(step: dict[str, Any]) -> str:
    """Reuse the existing semantic termination proof from an empty linked stack."""

    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    return (
        f"theorem acceptanceLinkedRunningNode{node_id}Refined :\n"
        "    LinkedRunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      linkedProductControlProfile protocolCallbackTargets\n"
        f"      originalWorldProgram candidateWorldProgram {node_id} := by\n"
        "  unfold LinkedRunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {int(step['target_id'])} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls active links eventIndex world originalState candidateState\n"
        "    controlAllowed stackHolds linksAllowed frameFactsHold\n"
        "    stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [LinkedProductControlProfile.authority, "
        "LinkedProductControlProfile.Allows, Bool.and_eq_true] at controlMember\n"
        "  have controlHead : none = calls.head? ∧ none = active := by\n"
        "    simpa [linkedProductControlProfile, LinkedProductControlState.matches] "
        "using controlMember.2\n"
        "  have controlShape : calls = [] ∧ active = none := by\n"
        "    constructor\n"
        "    · exact continuations_eq_nil_of_head?_eq_none calls controlHead.1\n"
        "    · exact controlHead.2.symm\n"
        "  rcases controlShape with ⟨rfl, rfl⟩\n"
        "  have stackShape : frames = [] ∧ links = [] := by\n"
        "    exact RelationalLinkedRuntimeCallStackHolds.empty_shape\n"
        "      staticProofContext originalState candidateState frames links stackHolds\n"
        "  rcases stackShape with ⟨rfl, rfl⟩\n"
        f"  have oldResult := acceptanceRunningNode{node_id}Refined [] [] []\n"
        "    eventIndex world originalState candidateState (by decide)\n"
        "    (by simp [RelationalRuntimeCallStackHolds])\n"
        "    (RelationalRuntimeCallFactsHold.empty staticProofContext world _ _)\n"
        "    (by simp [RelationalRuntimeCallTargetsMapped]) statesRelated\n"
        "  refine ⟨oldResult.1, ?_⟩\n"
        "  simpa [WorldExecutionsRelated, LinkedWorldExecutionsRelated] using oldResult.2"
    )


def _lean_acceptance_linked_active_jump_node(
    step: dict[str, Any], linked_case: dict[str, Any]
) -> str:
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_id = int(step["target_id"])
    edge = linked_case["edge"]
    edge_id = int(edge["edge_id"])
    target_region_index = int(edge["target_region_index"])
    continuation = int(linked_case["continuation_target_id"])
    original_behavior = f"acceptanceOriginalNormalizedBehavior{node_id}"
    candidate_behavior = f"acceptanceCandidateNormalizedBehavior{node_id}"
    frame_claim = _lean_return_slot_frame_inventory_transfer_claim(
        linked_case["frame_claim"]
    )
    frame_word_claims = linked_case["frame_claim"].get(
        "frame_exact_word_register_outputs", []
    )
    frame_expression_claims = linked_case["frame_claim"].get(
        "frame_paired_expression_register_outputs", []
    )
    fact_claim = _lean_runtime_call_import_transfer_claim(
        linked_case["source_active"], linked_case["target_active"],
        linked_case["frame_claim"].get("carried_relations"),
    )
    frame_word_claims_literal = "[" + ", ".join(
        _lean_frame_exact_word_register_output_claim(claim)
        for claim in frame_word_claims
    ) + "]"
    frame_expression_claims_literal = "[" + ", ".join(
        _lean_frame_paired_expression_register_output_claim(claim)
        for claim in frame_expression_claims
    ) + "]"
    if frame_word_claims or frame_expression_claims:
        frame_facts_transfer = (
            "      let activeFrameWordClaims : List "
            "FrameExactWordRegisterOutputClaim :=\n"
            f"        {frame_word_claims_literal}\n"
            "      let activeFrameExpressionClaims : List "
            "FramePairedExpressionRegisterOutputClaim :=\n"
            f"        {frame_expression_claims_literal}\n"
            "      have stackShape := stackHolds\n"
            "      simp only [RelationalLinkedRuntimeCallStackHolds] at stackShape\n"
            "      have frameFactsNext :=\n"
            "        RelationalLinkedRuntimeCallFactsHold."
            "afterInternalWithFrameEvidence\n"
            f"          staticProofContext world {original_behavior} "
            f"{candidate_behavior}\n"
            "          activeFactClaim activeFrameWordClaims "
            "activeFrameExpressionClaims frame originalState\n"
            "          candidateState (by decide)\n"
            "          (by simpa [activeFactClaim] using frameFactsHold)\n"
            "          (by simpa [activeFactClaim] using stackShape.2.1)\n"
            "          (by simpa [activeFactClaim] using stackShape.2.2.1)\n"
        )
    else:
        frame_facts_transfer = (
            "      have frameFactsNext :=\n"
            "        RelationalLinkedRuntimeCallFactsHold.afterInternal\n"
            f"          staticProofContext world {original_behavior} "
            f"{candidate_behavior}\n"
            "          activeFactClaim originalState candidateState (by decide)\n"
            "          (by simpa [activeFactClaim] using frameFactsHold)\n"
        )
    target_active = _lean_return_slot_offset_inventory(
        linked_case["target_active"]
    )
    target = _lean_acceptance_linked_running_target(
        node_id=node_id,
        edge=edge,
        frames="frame :: frames",
        calls=f"{continuation} :: continuations",
        active=f"some {target_active}",
        links="links",
        target_control_proof="controlAllowedNext",
        links_allowed_proof="linksAllowed",
        frame_facts_proof="frameFactsNext",
        stack_targets_proof="stackTargetsReachable",
    )
    indented_target = "\n".join("    " + line for line in target.splitlines())
    return (
        f"theorem acceptanceLinkedRunningNode{node_id}Refined :\n"
        "    LinkedRunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      linkedProductControlProfile protocolCallbackTargets\n"
        f"      originalWorldProgram candidateWorldProgram {node_id} := by\n"
        "  unfold LinkedRunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {target_id} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls active links eventIndex world originalState candidateState\n"
        "    controlAllowed stackHolds linksAllowed frameFactsHold\n"
        "    stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [LinkedProductControlProfile.authority, "
        "LinkedProductControlProfile.Allows, Bool.and_eq_true] at controlMember\n"
        "  have controlShape : some " + str(continuation) + " = calls.head? ∧\n"
        "      some "
        + _lean_return_slot_offset_inventory(linked_case["source_active"])
        + " = active := by\n"
        "    simpa [linkedProductControlProfile, LinkedProductControlState.matches] "
        "using controlMember.2\n"
        "  cases calls with\n"
        "  | nil => simp at controlShape\n"
        "  | cons continuation continuations =>\n"
        "    simp only [List.head?_cons, Option.some.injEq] at controlShape\n"
        "    rcases controlShape with ⟨rfl, rfl⟩\n"
        "    cases frames with\n"
        "    | nil => simp [RelationalLinkedRuntimeCallStackHolds] at stackHolds\n"
        "    | cons frame frames =>\n"
        f"      let activeFrameClaim : ReturnSlotFrameInventoryTransferClaim :=\n"
        f"        {frame_claim}\n"
        "      let activeFactClaim : RelationalRuntimeCallImportTransferClaim :=\n"
        f"        {fact_claim}\n"
        "      unfold DecodedWorldProgram.transitionSystem\n"
        "      simp only [stepWorldExecution]\n"
        f"      rw [originalWorldBehaviorNode{node_id}, candidateWorldBehaviorNode{node_id}]\n"
        "      simp only [transitionFromWorldBehavior, transitionFromWorldOutcome,\n"
        "        NormalizedSymbolicBehavior.eval_outcome,\n"
        "        NormalizedSymbolicBehavior.eval_x87Fault,\n"
        f"        acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"        acceptanceCandidateNormalizedOutcome{node_id}, NormalizedOutcomeExpr.eval]\n"
        f"      have originalBehaviorSegment : {original_behavior} =\n"
        f"          segmentRefinementEdge{edge_id}OriginalNormalizedBehavior := by decide\n"
        f"      have candidateBehaviorSegment : {candidate_behavior} =\n"
        f"          segmentRefinementEdge{edge_id}CandidateNormalizedBehavior := by decide\n"
        f"      have transition := segmentRefinementEdge{edge_id}TransitionChecked world\n"
        "        originalState candidateState statesRelated\n"
        f"      have guardTrue : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
        "          originalState = true := by\n"
        f"        simp [segmentRefinementEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
        "      have transitioned := transition.2 guardTrue\n"
        "      have nextStatesRelated : StateRel staticProofContext world\n"
        f"          region{target_region_index}.inputInvariant\n"
        f"          (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"          (({candidate_behavior}.eval candidateState).nextMachineState candidateState) := by\n"
        "        rw [originalBehaviorSegment, candidateBehaviorSegment]\n"
        "        exact transitioned.2.2.2\n"
        "      have originalMemory :\n"
        f"          (({original_behavior}.eval originalState).nextMachineState\n"
        "            originalState).memory = originalState.memory := by\n"
        f"        simp [RelationalBehavior.nextMachineState,\n"
        f"          acceptanceOriginalNormalizedWrites{node_id},\n"
        f"          originalBehavior{region_index}, evalNormalizedWrites,\n"
        "          applyConcreteWrites]\n"
        "      have candidateMemory :\n"
        f"          (({candidate_behavior}.eval candidateState).nextMachineState\n"
        "            candidateState).memory = candidateState.memory := by\n"
        f"        simp [RelationalBehavior.nextMachineState,\n"
        f"          acceptanceCandidateNormalizedWrites{node_id},\n"
        f"          candidateBehavior{region_index}, evalNormalizedWrites,\n"
        "          applyConcreteWrites]\n"
        "      have stackHoldsNext :=\n"
        "        RelationalLinkedRuntimeCallStackHolds.afterActiveTransfer\n"
        f"          staticProofContext world region{region_index}.inputInvariant\n"
        f"          {original_behavior} {candidate_behavior} activeFrameClaim\n"
        f"          originalState candidateState frame frames {continuation} continuations links\n"
        "          (by decide) (by simpa [activeFrameClaim] using stackHolds)\n"
        "          statesRelated originalMemory candidateMemory\n"
        + frame_facts_transfer
        +
        "      have controlAllowedNext : linkedProductControlProfile.Allows\n"
        f"          {int(edge['target_node_id'])} ({continuation} :: continuations)\n"
        f"          (some {target_active}) = true := by\n"
        "        simp only [LinkedProductControlProfile.Allows, Bool.and_eq_true]\n"
        "        exact ⟨linkedProductControlProfileChecked, by\n"
        "          simp [linkedProductControlProfile, "
        "linkedRuntimeCallFrameLinkCandidates]⟩\n"
        + indented_target
    )


def _lean_acceptance_linked_active_branch_node(
    step: dict[str, Any], linked_case: dict[str, Any],
    regions: list[dict[str, Any]], behaviors: list[dict[str, Any]],
    *, parameterized_environment: bool = False,
    parameterized_protocol_environment: bool = False,
) -> str:
    if parameterized_protocol_environment:
        raise StageAInputError(
            "linked active-frame branches do not yet support protocol environments"
        )
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_id = int(step["target_id"])
    continuation = int(linked_case["continuation_target_id"])
    source_active_payload = linked_case["source_active"]
    source_active = _lean_return_slot_offset_inventory(source_active_payload)
    original_behavior = f"acceptanceOriginalNormalizedBehavior{node_id}"
    candidate_behavior = f"acceptanceCandidateNormalizedBehavior{node_id}"
    edges = linked_case["edges"]
    taken = next(edge for edge in edges if bool(edge["branch_value"]))
    fallthrough = next(edge for edge in edges if not bool(edge["branch_value"]))
    environment_binders = (
        "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
        "    (_environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
        "      externalCallSites originalEnvironment candidateEnvironment) :\n"
        if parameterized_environment else "    :\n"
    )
    original_program = (
        "(originalWorldProgram originalEnvironment)"
        if parameterized_environment else "originalWorldProgram"
    )
    candidate_program = (
        "(candidateWorldProgram candidateEnvironment)"
        if parameterized_environment else "candidateWorldProgram"
    )
    original_behavior_arguments = (
        " originalEnvironment" if parameterized_environment else ""
    )
    candidate_behavior_arguments = (
        " candidateEnvironment" if parameterized_environment else ""
    )

    def branch_case(edge: dict[str, Any], condition: bool) -> str:
        edge_id = int(edge["edge_id"])
        target_node_id = int(edge["target_node_id"])
        target_region_index = int(edge["target_region_index"])
        candidate_condition = bool(
            edge.get("candidate_branch_value", condition)
        )
        candidate_condition_literal = (
            "true" if candidate_condition else "false"
        )
        claims = edge["return_slot_frame_transfer_claims"]
        frame_claim_payload = claims[0]
        target_active_payload = frame_claim_payload["target"]
        target_active = _lean_return_slot_offset_inventory(target_active_payload)
        frame_claim = _lean_return_slot_frame_inventory_transfer_claim(
            frame_claim_payload
        )
        frame_word_claims = frame_claim_payload.get(
            "frame_exact_word_register_outputs", []
        )
        frame_expression_claims = frame_claim_payload.get(
            "frame_paired_expression_register_outputs", []
        )
        fact_claim = _lean_runtime_call_import_transfer_claim(
            source_active_payload, target_active_payload,
            frame_claim_payload.get("carried_relations"),
        )
        frame_word_claims_literal = "[" + ", ".join(
            _lean_frame_exact_word_register_output_claim(claim)
            for claim in frame_word_claims
        ) + "]"
        frame_expression_claims_literal = "[" + ", ".join(
            _lean_frame_paired_expression_register_output_claim(claim)
            for claim in frame_expression_claims
        ) + "]"
        if frame_word_claims or frame_expression_claims:
            frame_facts_transfer = (
                "      let activeFrameWordClaims : List "
                "FrameExactWordRegisterOutputClaim :=\n"
                f"        {frame_word_claims_literal}\n"
                "      let activeFrameExpressionClaims : List "
                "FramePairedExpressionRegisterOutputClaim :=\n"
                f"        {frame_expression_claims_literal}\n"
                "      have stackShape := stackHolds\n"
                "      simp only [RelationalLinkedRuntimeCallStackHolds] at stackShape\n"
                "      have frameFactsNext :=\n"
                "        RelationalLinkedRuntimeCallFactsHold."
                "afterInternalWithFrameEvidence\n"
                f"          staticProofContext world {original_behavior} "
                f"{candidate_behavior}\n"
                "          activeFactClaim activeFrameWordClaims "
                "activeFrameExpressionClaims frame originalState\n"
                "          candidateState (by decide)\n"
                "          (by simpa [activeFactClaim] using frameFactsHold)\n"
                "          (by simpa [activeFactClaim] using stackShape.2.1)\n"
                "          (by simpa [activeFactClaim] using stackShape.2.2.1)\n"
            )
        else:
            frame_facts_transfer = (
                "      have frameFactsNext :=\n"
                "        RelationalLinkedRuntimeCallFactsHold.afterInternal\n"
                f"          staticProofContext world {original_behavior} "
                f"{candidate_behavior}\n"
                "          activeFactClaim originalState candidateState (by decide)\n"
                "          (by simpa [activeFactClaim] using frameFactsHold)\n"
            )
        guard_claim = _lean_frame_exact_guard_claim(edge["frame_guard_claim"])
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
        original_guard = (
            f"        change region{region_index}OutcomeCondition.eval "
            "originalState = true\n"
            "        exact originalCondition\n"
            if condition else
            f"        change (!region{region_index}OutcomeCondition.eval "
            "originalState) = true\n"
            "        simp [originalCondition]\n"
        )
        target = _lean_acceptance_linked_running_target(
            node_id=node_id,
            edge=edge,
            frames="frame :: frames",
            calls=f"{continuation} :: continuations",
            active=f"some {target_active}",
            links="links",
            target_control_proof="controlAllowedNext",
            links_allowed_proof="linksAllowed",
            frame_facts_proof="frameFactsNext",
            stack_targets_proof="stackTargetsReachable",
        )
        indented_target = "\n".join(
            "      " + line for line in target.splitlines()
        )
        return (
            "      let activeFrameClaim : "
            "ReturnSlotFrameInventoryTransferClaim :=\n"
            f"        {frame_claim}\n"
            "      let activeFactClaim : "
            "RelationalRuntimeCallImportTransferClaim :=\n"
            f"        {fact_claim}\n"
            "      let activeGuardClaim : FrameExactGuardClaim :=\n"
            f"        {guard_claim}\n"
            f"      have originalBehaviorSegment : {original_behavior} =\n"
            f"          {segment_original_behavior} := by decide\n"
            f"      have candidateBehaviorSegment : {candidate_behavior} =\n"
            f"          {segment_candidate_behavior} := by decide\n"
            "      have guardAgreement :\n"
            f"          segmentRefinementEdge{edge_id}Spec.originalGuard.eval "
            "originalState =\n"
            f"            segmentRefinementEdge{edge_id}Spec.candidateGuard.eval "
            "candidateState := by\n"
            "        exact RelationalLinkedRuntimeCallFactsHold."
            "guardEvalEqual_of_frameExact\n"
            f"          staticProofContext world {source_active}\n"
            f"          segmentRefinementEdge{edge_id}Spec.originalGuard\n"
            f"          segmentRefinementEdge{edge_id}Spec.candidateGuard "
            "activeGuardClaim\n"
            "          originalState candidateState (by decide)\n"
            "          (by simpa [activeGuardClaim] using frameFactsHold)\n"
            f"      have originalGuard : segmentRefinementEdge{edge_id}Spec."
            "originalGuard.eval\n"
            "          originalState = true := by\n"
            + original_guard
            + f"      have transitioned := segmentRefinementEdge{edge_id}"
            "TransitionChecked world\n"
            "        originalState candidateState statesRelated guardAgreement "
            "originalGuard\n"
            "      have nextStatesRelated : StateRel staticProofContext world\n"
            f"          region{target_region_index}.inputInvariant\n"
            f"          (({original_behavior}.eval originalState).nextMachineState "
            "originalState)\n"
            f"          (({candidate_behavior}.eval candidateState).nextMachineState "
            "candidateState) := by\n"
            "        rw [originalBehaviorSegment, candidateBehaviorSegment]\n"
            "        exact transitioned.2.2.2\n"
            "      have originalMemory :\n"
            f"          (({original_behavior}.eval originalState).nextMachineState\n"
            "            originalState).memory = originalState.memory := by\n"
            "        simp [RelationalBehavior.nextMachineState,\n"
            f"          acceptanceOriginalNormalizedWrites{node_id},\n"
            f"          originalBehavior{region_index}, evalNormalizedWrites,\n"
            "          applyConcreteWrites]\n"
            "      have candidateMemory :\n"
            f"          (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "            candidateState).memory = candidateState.memory := by\n"
            "        simp [RelationalBehavior.nextMachineState,\n"
            f"          acceptanceCandidateNormalizedWrites{node_id},\n"
            f"          candidateBehavior{region_index}, evalNormalizedWrites,\n"
            "          applyConcreteWrites]\n"
            "      have stackHoldsNext :=\n"
            "        RelationalLinkedRuntimeCallStackHolds.afterActiveTransfer\n"
            f"          staticProofContext world region{region_index}.inputInvariant\n"
            f"          {original_behavior} {candidate_behavior} activeFrameClaim\n"
            f"          originalState candidateState frame frames {continuation} "
            "continuations links\n"
            "          (by decide) (by simpa [activeFrameClaim] using stackHolds)\n"
            "          statesRelated originalMemory candidateMemory\n"
            + frame_facts_transfer
            +
            "      have controlAllowedNext : linkedProductControlProfile.Allows\n"
            f"          {target_node_id} ({continuation} :: continuations)\n"
            f"          (some {target_active}) = true := by\n"
            "        simp only [LinkedProductControlProfile.Allows, "
            "Bool.and_eq_true]\n"
            "        exact ⟨linkedProductControlProfileChecked, by\n"
            "          simp [linkedProductControlProfile, "
            "linkedRuntimeCallFrameLinkCandidates]⟩\n"
            f"      have candidateGuard : segmentRefinementEdge{edge_id}Spec."
            "candidateGuard.eval\n"
            "          candidateState = true := by\n"
            "        rw [← guardAgreement]\n"
            "        exact originalGuard\n"
            f"      have candidateCondition : segmentRefinementEdge{edge_id}"
            "CandidateOutcomeCondition.eval\n"
            f"          candidateState = {candidate_condition_literal} := by\n"
            "        exact normalizedBranchCondition_eval_of_guard_true\n"
            f"          segmentRefinementEdge{edge_id}CandidateOutcomeCondition\n"
            f"          segmentRefinementEdge{edge_id}Spec.candidateGuard\n"
            f"          {candidate_condition_literal} candidateState (by decide) "
            "candidateGuard\n"
            f"      simp only [region{region_index}OutcomeCondition,\n"
            f"        segmentRefinementEdge{edge_id}CandidateOutcomeCondition] at\n"
            "        originalCondition candidateCondition\n"
            "      simp [originalCondition, candidateCondition]\n"
            + indented_target
        )

    source_prefix = (
        f"theorem acceptanceLinkedRunningNode{node_id}Refined\n"
        + environment_binders
        +
        "    LinkedRunningProductNodeStepRefined staticProofContext "
        "relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      linkedProductControlProfile protocolCallbackTargets\n"
        f"      {original_program} {candidate_program} {node_id} := by\n"
        "  unfold LinkedRunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {target_id} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls active links eventIndex world originalState "
        "candidateState\n"
        "    controlAllowed stackHolds linksAllowed frameFactsHold\n"
        "    stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [LinkedProductControlProfile.authority, "
        "LinkedProductControlProfile.Allows, Bool.and_eq_true] at "
        "controlMember\n"
        f"  have controlShape : some {continuation} = calls.head? ∧\n"
        f"      some {source_active} = active := by\n"
        "    simpa [linkedProductControlProfile, LinkedProductControlState.matches] "
        "using controlMember.2\n"
        "  cases calls with\n"
        "  | nil => simp at controlShape\n"
        "  | cons continuation continuations =>\n"
        "    simp only [List.head?_cons, Option.some.injEq] at controlShape\n"
        "    rcases controlShape with ⟨rfl, rfl⟩\n"
        "    cases frames with\n"
        "    | nil => simp [RelationalLinkedRuntimeCallStackHolds] at stackHolds\n"
        "    | cons frame frames =>\n"
        "      unfold DecodedWorldProgram.transitionSystem\n"
        "      simp only [stepWorldExecution]\n"
        f"      rw [originalWorldBehaviorNode{node_id}{original_behavior_arguments}, "
        f"candidateWorldBehaviorNode{node_id}{candidate_behavior_arguments}]\n"
        "      simp only [transitionFromWorldBehavior, transitionFromWorldOutcome,\n"
        "        NormalizedSymbolicBehavior.eval_outcome,\n"
        "        NormalizedSymbolicBehavior.eval_x87Fault,\n"
        f"        acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"        acceptanceCandidateNormalizedOutcome{node_id}, "
        "NormalizedOutcomeExpr.eval]\n"
        f"      cases originalCondition : region{region_index}OutcomeCondition.eval "
        "originalState with\n"
    )
    return (
        source_prefix
        + "      | false =>\n"
        + branch_case(fallthrough, False)
        + "\n      | true =>\n"
        + branch_case(taken, True)
    )


def _lean_acceptance_linked_empty_jump_node(
    step: dict[str, Any], *, parameterized_environment: bool = False,
    parameterized_protocol_environment: bool = False,
) -> str:
    """Emit a native linked-stack node proof for an empty-stack internal jump."""

    if not _linked_empty_jump_supported(step):
        raise StageAInputError(
            f"acceptance node {step.get('node_id')} is not an empty-stack jump"
        )
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_id = int(step["target_id"])
    edge = step["edges"][0]
    edge_id = int(edge["edge_id"])
    target_region_index = int(edge["target_region_index"])
    original_behavior = f"acceptanceOriginalNormalizedBehavior{node_id}"
    candidate_behavior = f"acceptanceCandidateNormalizedBehavior{node_id}"
    original_program = (
        "(originalWorldProgram originalEnvironment"
        + (" originalProtocolEnvironment" if parameterized_protocol_environment else "")
        + ")"
        if parameterized_environment else "originalWorldProgram"
    )
    candidate_program = (
        "(candidateWorldProgram candidateEnvironment"
        + (" candidateProtocolEnvironment" if parameterized_protocol_environment else "")
        + ")"
        if parameterized_environment else "candidateWorldProgram"
    )
    environment_binders = (
        "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
        + (
            "    (originalProtocolEnvironment candidateProtocolEnvironment : "
            "WorldExternalProtocolEnvironment)\n"
            if parameterized_protocol_environment else ""
        )
        + "    (_environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
        "      externalCallSites originalEnvironment candidateEnvironment) :\n"
        if parameterized_environment else ""
    )
    behavior_arguments = (
        " originalEnvironment"
        + (" originalProtocolEnvironment" if parameterized_protocol_environment else "")
        if parameterized_environment else ""
    )
    candidate_behavior_arguments = (
        " candidateEnvironment"
        + (" candidateProtocolEnvironment" if parameterized_protocol_environment else "")
        if parameterized_environment else ""
    )
    return (
        f"theorem acceptanceLinkedRunningNode{node_id}Refined\n"
        + environment_binders
        + ("    " if parameterized_environment else "    :\n")
        + "    LinkedRunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      linkedProductControlProfile protocolCallbackTargets\n"
        f"      {original_program} {candidate_program} {node_id} := by\n"
        "  unfold LinkedRunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {target_id} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls active links eventIndex world originalState candidateState\n"
        "    controlAllowed stackHolds linksAllowed frameFactsHold\n"
        "    stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [LinkedProductControlProfile.authority, "
        "LinkedProductControlProfile.Allows, Bool.and_eq_true] at controlMember\n"
        "  have controlHead : none = calls.head? ∧ none = active := by\n"
        "    simpa [linkedProductControlProfile, LinkedProductControlState.matches] "
        "using controlMember.2\n"
        "  have controlShape : calls = [] ∧ active = none := by\n"
        "    constructor\n"
        "    · exact continuations_eq_nil_of_head?_eq_none calls controlHead.1\n"
        "    · exact controlHead.2.symm\n"
        "  rcases controlShape with ⟨rfl, rfl⟩\n"
        "  have stackShape : frames = [] ∧ links = [] := by\n"
        "    exact RelationalLinkedRuntimeCallStackHolds.empty_shape\n"
        "      staticProofContext originalState candidateState frames links stackHolds\n"
        "  rcases stackShape with ⟨rfl, rfl⟩\n"
        "  unfold DecodedWorldProgram.transitionSystem\n"
        "  simp only [stepWorldExecution]\n"
        f"  rw [originalWorldBehaviorNode{node_id}{behavior_arguments},\n"
        f"    candidateWorldBehaviorNode{node_id}{candidate_behavior_arguments}]\n"
        "  simp only [transitionFromWorldBehavior, transitionFromWorldOutcome,\n"
        "    NormalizedSymbolicBehavior.eval_outcome,\n"
        f"    acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"    acceptanceCandidateNormalizedOutcome{node_id}, NormalizedOutcomeExpr.eval]\n"
        f"  have originalBehaviorSegment : {original_behavior} =\n"
        f"      segmentRefinementEdge{edge_id}OriginalNormalizedBehavior := by decide\n"
        f"  have candidateBehaviorSegment : {candidate_behavior} =\n"
        f"      segmentRefinementEdge{edge_id}CandidateNormalizedBehavior := by decide\n"
        f"  have transition := segmentRefinementEdge{edge_id}TransitionChecked world\n"
        "    originalState candidateState statesRelated\n"
        f"  have guardTrue : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
        "      originalState = true := by\n"
        f"    simp [segmentRefinementEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
        "  have transitioned := transition.2 guardTrue\n"
        "  have nextStatesRelated : StateRel staticProofContext world\n"
        f"      region{target_region_index}.inputInvariant\n"
        f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState) := by\n"
        "    rw [originalBehaviorSegment, candidateBehaviorSegment]\n"
        "    exact transitioned.2.2.2\n"
        "  have stackHoldsNext : RelationalLinkedRuntimeCallStackHolds\n"
        "      staticProofContext\n"
        f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
        "      [] [] none [] := by\n"
        "    simp [RelationalLinkedRuntimeCallStackHolds]\n"
        "  have linksAllowedNext : linkedProductControlProfile.LinksAllowed [] := by\n"
        "    exact LinkedProductControlProfile.LinksAllowed.nil\n"
        "      linkedProductControlProfile linkedProductControlProfileChecked\n"
        "  have frameFactsNext : RelationalLinkedRuntimeCallFactsHold staticProofContext\n"
        "      world none\n"
        f"      ({original_behavior}.eval originalState).registers\n"
        f"      ({candidate_behavior}.eval candidateState).registers := by\n"
        "    simp [RelationalLinkedRuntimeCallFactsHold]\n"
        + _lean_acceptance_linked_running_target(
            node_id=node_id,
            edge=edge,
            stack_targets_proof="stackTargetsReachable",
        )
    )

def _lean_acceptance_running_node(
    step: dict[str, Any], regions: list[dict[str, Any]],
    behaviors: list[dict[str, Any]], *,
    parameterized_environment: bool = False,
    parameterized_protocol_environment: bool = False,
) -> str:
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_id = int(step["target_id"])
    original_behavior = f"acceptanceOriginalNormalizedBehavior{node_id}"
    candidate_behavior = f"acceptanceCandidateNormalizedBehavior{node_id}"
    running = f"acceptanceRunningNode{node_id}Refined"
    original_program = (
        "(originalWorldProgram originalEnvironment"
        + (" originalProtocolEnvironment" if parameterized_protocol_environment else "")
        + ")"
        if parameterized_environment else "originalWorldProgram"
    )
    candidate_program = (
        "(candidateWorldProgram candidateEnvironment"
        + (" candidateProtocolEnvironment" if parameterized_protocol_environment else "")
        + ")"
        if parameterized_environment else "candidateWorldProgram"
    )
    environment_binders = (
        "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
        + (
            "    (originalProtocolEnvironment candidateProtocolEnvironment : "
            "WorldExternalProtocolEnvironment)\n"
            if parameterized_protocol_environment else ""
        )
        + "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
        "      externalCallSites originalEnvironment candidateEnvironment) :\n"
        if parameterized_environment else ""
    )
    behavior_rewrite_arguments = (
        " originalEnvironment"
        + (" originalProtocolEnvironment" if parameterized_protocol_environment else "")
        if parameterized_environment else ""
    )
    candidate_behavior_rewrite_arguments = (
        " candidateEnvironment"
        + (" candidateProtocolEnvironment" if parameterized_protocol_environment else "")
        if parameterized_environment else ""
    )
    prefix = (
        f"theorem {running}\n"
        + environment_binders
        + ("    " if parameterized_environment else "    :\n")
        + "    RunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      productControlProfile protocolCallbackTargets\n"
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
        "    controlAllowed stackHolds frameImportsHold stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [ProductControlProfile.Allows, Bool.and_eq_true] at controlMember\n"
    )
    prefix += (
        "  unfold DecodedWorldProgram.transitionSystem\n"
        "  simp only [stepWorldExecution]\n"
        f"  rw [originalWorldBehaviorNode{node_id}{behavior_rewrite_arguments}, "
        f"candidateWorldBehaviorNode{node_id}{candidate_behavior_rewrite_arguments}]\n"
    )
    if step.get("certificate_profile") != (
        "composable_x87_state_only_singleton_v1"
    ):
        prefix += (
            "  simp only [transitionFromWorldBehavior, transitionFromWorldOutcome, "
            "NormalizedSymbolicBehavior.eval_outcome,\n"
            f"    acceptanceOriginalNormalizedOutcome{node_id},\n"
            f"    acceptanceCandidateNormalizedOutcome{node_id}, "
            "NormalizedOutcomeExpr.eval]\n"
        )
    empty_control = (
        "  have controlShape : calls = [] ∧ frameOffsets = [] := by\n"
        "    simpa [productControlProfile] using controlMember.2\n"
        "  rcases controlShape with ⟨rfl, rfl⟩\n"
        "  have framesEmpty : frames = [] := by\n"
        "    cases frames with\n"
        "    | nil => rfl\n"
        "    | cons frame tail =>\n"
        "        simp [RelationalRuntimeCallStackHolds] at stackHolds\n"
        "  subst frames\n"
    )
    control_cases = step.get("cases")
    if control_cases is not None and step["kind"] != "return":
        if not control_cases:
            raise StageAInputError(
                f"acceptance node {node_id} has an empty control-case inventory"
            )
        case_shapes: list[str] = []
        case_bodies: list[str] = []
        for case_index, control_case in enumerate(control_cases):
            control_state = control_case["control_state"]
            calls_literal = "[" + ", ".join(
                str(int(item)) for item in control_state["calls"]
            ) + "]"
            offsets_literal = "[" + ", ".join(
                _lean_return_slot_offset_inventory(item)
                for item in control_state["frame_offsets"]
            ) + "]"
            case_shapes.append(
                f"(calls = {calls_literal} ∧ frameOffsets = {offsets_literal})"
            )
            case_step = {
                **step,
                **control_case,
                "control_already_selected": True,
            }
            case_step.pop("cases", None)
            case_source = _lean_acceptance_running_node(
                case_step,
                regions,
                behaviors,
                parameterized_environment=parameterized_environment,
                parameterized_protocol_environment=
                    parameterized_protocol_environment,
            )
            if not case_source.startswith(prefix):
                raise StageAInputError(
                    f"control case {case_index} did not share its node theorem prefix"
                )
            case_body = case_source[len(prefix):]
            case_bodies.append("\n".join(
                "  " + line for line in case_body.splitlines()
            ))
        return (
            prefix
            + "  have controlShape : "
            + " ∨\n      ".join(case_shapes)
            + " := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with "
            + " | ".join(
                f"controlCase{case_index}"
                for case_index in range(len(control_cases))
            )
            + "\n"
            + "\n".join(
                f"  · rcases controlCase{case_index} with ⟨rfl, rfl⟩\n"
                + case_body
                for case_index, case_body in enumerate(case_bodies)
            )
        )
    if step["kind"] == "call":
        edge = step["edges"][0]
        edge_id = int(edge["edge_id"])
        continuation_target_id = int(edge["target_target_id"])
        target_region_index = int(edge["target_region_index"])
        continuation = int(step["continuation_target_id"])
        claim = step["call_push_claim"]
        original_return = int(claim["original_return_address"])
        candidate_return = int(claim["candidate_return_address"])
        stack_amount = int(step["stack_amount"])
        stack_amount_twos_complement = 2**32 - stack_amount
        source_window = _lean_stack_window(step["source_stack_window"])
        control_calls = [int(item) for item in step["control_state"]["calls"]]
        source_calls_literal = "[" + ", ".join(
            str(item) for item in control_calls
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in step["control_state"]["frame_offsets"]
        ) + "]"
        frame_claims = step["return_slot_frame_transfer_claims"]
        frame_claims_literal = "[" + ", ".join(
            _lean_return_slot_frame_inventory_transfer_claim(item)
            for item in frame_claims
        ) + "]"
        frame_import_claims_literal = _lean_runtime_call_import_transfer_claims(
            frame_claims
        )
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item["target"])
            for item in frame_claims
        ) + "]"
        seeded_frame_inventory_literal = _lean_return_slot_offset_inventory(
            step["seeded_frame_inventory"]
        )
        protected_bytes = _runtime_frame_protected_bytes(
            step["seeded_frame_inventory"]
        )
        seeded_register_output_claims_literal = ", ".join(
            _lean_register_output_claim(claim)
            for claim in step.get("seeded_register_output_claims", [])
        )
        continuation_node_id = int(step["continuation_node_id"])
        combined_stack_writes = (
            step.get("certificate_profile")
            == "composable_direct_call_stack_writes_v1"
        )
        combined_prepared_writes = (
            step.get("certificate_profile")
            == "composable_direct_call_prepared_writes_v1"
        )
        known_indirect_call = bool(step.get("known_indirect_call"))
        combined_prefix_writes = combined_stack_writes or combined_prepared_writes
        writes_claim_name = (
            f"segmentRefinementEdge{edge_id}DirectCallPreparedWritesClaim"
            if combined_prepared_writes
            else f"segmentRefinementEdge{edge_id}DirectCallStackWritesClaim"
        )
        if known_indirect_call:
            segment_original_behavior = f"productNode{node_id}OriginalNormalized"
            segment_candidate_behavior = f"productNode{node_id}CandidateNormalized"
        elif _normalized_behavior_fast_path(
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
        exact_word_seed_claims = step.get("exact_word_seed_claims", [])
        seeded_exact_words = step["seeded_frame_inventory"].get(
            "exact_words", []
        )
        if len(exact_word_seed_claims) != len(seeded_exact_words):
            raise StageAInputError(
                f"call edge {edge_id} has mismatched exact-word seed and "
                "runtime-frame inventories"
            )
        if exact_word_seed_claims and not combined_prefix_writes:
            raise StageAInputError(
                f"call edge {edge_id} seeds exact words without a checked "
                "direct-call prepared-write certificate"
            )
        exact_seed_names = [
            f"segmentRefinementEdge{edge_id}DirectCallExactWordSeed{index}"
            for index in range(len(exact_word_seed_claims))
        ]
        exact_seed_type = (
            "DirectCallPreparedExactWordSeedClaim"
            if combined_prepared_writes else "DirectCallStackExactWordSeedClaim"
        )
        if not exact_seed_names:
            active_frame_exact_words = (
                "  have activeFrameExactWords : "
                "activeFrameInventory.boundedExactWordsHold runtimeFrame\n"
                f"      (({original_behavior}.eval originalState).nextMachineState\n"
                "        originalState).memory\n"
                f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
                "        candidateState).memory := by\n"
                "    simp [activeFrameInventory, runtimeFrame, "
                "ReturnSlotOffsetInventory.boundedExactWordsHold, "
                "ReturnSlotOffsetInventory.exactWordsFit, "
                "ReturnSlotOffsetInventory.exactWordsHold]\n"
            )
        else:
            word_cases = " ∨ ".join(
                f"word = {name}.exactWord" for name in exact_seed_names
            )

            def exact_seed_proof(name: str, *, bullet: bool) -> str:
                prefix = "      · " if bullet else "      "
                continuation_prefix = "        " if bullet else "      "
                return (
                    prefix + "have seededWordHolds :=\n"
                    + continuation_prefix
                    + (
                        "  DirectCallPreparedExactWordSeedClaim.holds_of_checked\n"
                        if combined_prepared_writes else
                        "  DirectCallStackExactWordSeedClaim.holds_of_checked\n"
                    )
                    + continuation_prefix
                    + f"    staticProofContext world region{region_index}.inputInvariant\n"
                    + continuation_prefix
                    + f"    {segment_original_behavior} {segment_candidate_behavior}\n"
                    + continuation_prefix
                    + f"    {writes_claim_name} {name} originalState candidateState\n"
                    + continuation_prefix
                    + (
                        "    (by decide) (by decide) statesRelated\n"
                        if combined_prepared_writes else
                        "    (by decide) (by decide) (by decide) statesRelated\n"
                    )
                    + continuation_prefix
                    + "simpa [runtimeFrame, sourceWindow,\n"
                    + continuation_prefix
                    + f"  {writes_claim_name}, "
                    + (
                        "DirectCallPreparedWritesClaim.runtimeFrame,\n"
                        if combined_prepared_writes else
                        "DirectCallStackWritesClaim.runtimeFrame,\n"
                    )
                    + continuation_prefix
                    + "  originalBehaviorSegment, candidateBehaviorSegment]\n"
                    + continuation_prefix
                    + "using seededWordHolds\n"
                )

            if len(exact_seed_names) == 1:
                exact_cases = (
                    "      subst word\n"
                    + exact_seed_proof(exact_seed_names[0], bullet=False)
                )
            else:
                exact_cases = (
                    "      rcases wordCases with "
                    + " | ".join("rfl" for _ in exact_seed_names)
                    + "\n"
                    + "".join(
                        exact_seed_proof(name, bullet=True)
                        for name in exact_seed_names
                    )
                )
            active_frame_exact_words = (
                "  have activeFrameExactWords : "
                "activeFrameInventory.boundedExactWordsHold runtimeFrame\n"
                f"      (({original_behavior}.eval originalState).nextMachineState\n"
                "        originalState).memory\n"
                f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
                "        candidateState).memory := by\n"
                "    constructor\n"
                "    · simp [activeFrameInventory, runtimeFrame, "
                "ReturnSlotOffsetInventory.exactWordsFit]\n"
                "    · intro word wordMember\n"
                f"      have wordCases : {word_cases} := by\n"
                "        simpa [activeFrameInventory, "
                + ", ".join(exact_seed_names)
                + "] using wordMember\n"
                + exact_cases
            )
        known_indirect_setup = ""
        known_indirect_dispatch = ""
        if known_indirect_call:
            decoded_control = step["decoded_control"]
            indirect_target_id = int(edge["target_target_id"])
            target_closed = f"productNode{node_id}ImmutableIndirectCallClosed"
            known_indirect_setup = (
                f"  rcases {target_closed} world originalState candidateState "
                "statesRelated with\n"
                "    ⟨originalTarget, candidateTarget, originalOutcome, "
                "candidateOutcome, originalTargetMatches, "
                "candidateTargetMatches⟩\n"
                "  have originalTargetExpression :\n"
                f"      ({_lean_semantic_expr(decoded_control['original_target_expression'])}).eval "
                "originalState = originalTarget := by\n"
                "    have normalizedOutcome := originalOutcome\n"
                "    rw [← originalBehaviorSegment] at normalizedOutcome\n"
                f"    simp only [acceptanceOriginalNormalizedOutcome{node_id}, "
                "NormalizedOutcomeExpr.eval, PureOutcome.indirectCall.injEq] "
                "at normalizedOutcome\n"
                "    exact normalizedOutcome.1\n"
                "  have candidateTargetExpression :\n"
                f"      ({_lean_semantic_expr(decoded_control['candidate_target_expression'])}).eval "
                "candidateState = candidateTarget := by\n"
                "    have normalizedOutcome := candidateOutcome\n"
                "    rw [← candidateBehaviorSegment] at normalizedOutcome\n"
                f"    simp only [acceptanceCandidateNormalizedOutcome{node_id}, "
                "NormalizedOutcomeExpr.eval, PureOutcome.indirectCall.injEq] "
                "at normalizedOutcome\n"
                "    exact normalizedOutcome.1\n"
                "  have originalTargetResolved : resolveMappedCodeTarget false\n"
                "      staticProofContext.originalPe.imageBase\n"
                "      staticProofContext.codeMap.entries.toList originalTarget =\n"
                f"      some {indirect_target_id} := by\n"
                "    simpa using knownIndirectCodeTargetResolved staticProofContext "
                f"{indirect_target_id} false originalTarget (by decide)\n"
                "      (by simpa using originalTargetMatches)\n"
                "  have candidateTargetResolved : resolveMappedCodeTarget true\n"
                "      staticProofContext.candidatePe.imageBase\n"
                "      staticProofContext.codeMap.entries.toList candidateTarget =\n"
                f"      some {indirect_target_id} := by\n"
                "    simpa using knownIndirectCodeTargetResolved staticProofContext "
                f"{indirect_target_id} true candidateTarget (by decide)\n"
                "      (by simpa using candidateTargetMatches)\n"
            )
            known_indirect_dispatch = (
                "  rw [originalTargetExpression, candidateTargetExpression]\n"
                "  simp only [originalWorldProgram, candidateWorldProgram,\n"
                "    Bool.false_eq_true, if_false, if_true]\n"
                "  rw [originalTargetResolved, candidateTargetResolved]\n"
                "  simp only\n"
            )
        frame_memory_body = (
            (
                "    exact pairedStackWordFinalWriteReadsBack_amount "
                "staticProofContext world\n"
                if combined_prefix_writes else
                "    exact pairedStackWordWriteReadsBack_amount "
                "staticProofContext world\n"
            )
            + f"      region{region_index}.inputInvariant sourceWindow "
            + f"{stack_amount}\n"
            + f"      (BitVec.ofNat 32 {original_return}) "
            + f"(BitVec.ofNat 32 {candidate_return})\n"
            + (
                f"      ({writes_claim_name}.preparedWrites.originalWrites "
                "originalState)\n"
                f"      ({writes_claim_name}.preparedWrites.candidateWrites "
                "candidateState)\n"
                if combined_prepared_writes else
                f"      ({writes_claim_name}.stackWrites.originalWrites "
                "originalState)\n"
                f"      ({writes_claim_name}.stackWrites.candidateWrites "
                "candidateState)\n"
                if combined_stack_writes else ""
            )
            + "      originalState candidateState\n"
            + f"      ({original_behavior}.eval originalState)\n"
            + f"      ({candidate_behavior}.eval candidateState)\n"
            + "      (by simp) (by simp) statesRelated\n"
            + "      (by decide) (by decide) (by decide) (by decide)\n"
            + "      (by simp [sourceWindow,\n"
            + f"        acceptanceOriginalNormalizedWrites{node_id},\n"
            + f"        originalBehavior{region_index}, evalNormalizedWrites, "
            + "Expr.eval,\n"
            + (
                f"        {writes_claim_name}, "
                "DirectCallPreparedWritesClaim.originalWrites,\n"
                "        PairedPreparedWordWritesClaim.originalWrites,\n"
                "        PairedPreparedWordWriteItem.originalAddress, "
                "PairedPreparedWordWriteItem.value, pairedStackWordAddress,\n"
                if combined_prepared_writes else
                f"        {writes_claim_name}, "
                "DirectCallStackWritesClaim.originalWrites,\n"
                "        PairedStackWordWritesClaim.originalWrites,\n"
                "        PairedStackWordWriteItem.originalAddress, "
                "pairedStackWordAddress,\n"
                if combined_stack_writes else ""
            )
            + "        stackAddressRewrite])\n"
            + "      (by simp [sourceWindow,\n"
            + f"        acceptanceCandidateNormalizedWrites{node_id},\n"
            + f"        candidateBehavior{region_index}, evalNormalizedWrites, "
            + "Expr.eval,\n"
            + (
                f"        {writes_claim_name}, "
                "DirectCallPreparedWritesClaim.candidateWrites,\n"
                "        PairedPreparedWordWritesClaim.candidateWrites,\n"
                "        PairedPreparedWordWriteItem.candidateAddress, "
                "PairedPreparedWordWriteItem.value, pairedStackWordAddress,\n"
                if combined_prepared_writes else
                f"        {writes_claim_name}, "
                "DirectCallStackWritesClaim.candidateWrites,\n"
                "        PairedStackWordWritesClaim.candidateWrites,\n"
                "        PairedStackWordWriteItem.candidateAddress, "
                "pairedStackWordAddress,\n"
                if combined_stack_writes else ""
            )
            + "        stackAddressRewrite])\n"
        )
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {source_calls_literal} \u2227\n"
            f"      frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        return (
            prefix
            + selected_control
            + f"  let outerFrameClaims : List ReturnSlotFrameInventoryTransferClaim :=\n"
            f"    {frame_claims_literal}\n"
            f"  let outerFrameImportClaims : List "
            "RelationalRuntimeCallImportTransferClaim :=\n"
            f"    {frame_import_claims_literal}\n"
            f"  let activeFrameInventory : ReturnSlotOffsetInventory :=\n"
            f"    {seeded_frame_inventory_literal}\n"
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
            + known_indirect_setup
            + "  let runtimeFrame : RelationalRuntimeCallFrame := {\n"
            f"    continuationTargetId := {continuation}\n"
            f"    originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
            f"    candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
            "    originalStackAddress := originalState.registers.get\n"
            f"      sourceWindow.originalRegister - BitVec.ofNat 32 {stack_amount}\n"
            "    candidateStackAddress := candidateState.registers.get\n"
            f"      sourceWindow.candidateRegister - BitVec.ofNat 32 {stack_amount}\n"
            f"    protectedBytes := {protected_bytes}\n"
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
            "    rw [originalBehaviorSegment, candidateBehaviorSegment]\n"
            "    exact transitioned.2.2.2\n"
            "  have frameMemory : runtimeFrame.memoryHolds\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState).memory\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "        candidateState).memory := by\n"
            "    unfold RelationalRuntimeCallFrame.memoryHolds runtimeFrame\n"
            + frame_memory_body
            + "  have frameOffsetsHold : ReturnSlotOffsetPair.zero.holds runtimeFrame\n"
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
            "  have sourceWindows := StateRel.stackWindowsHold staticProofContext world\n"
            f"    region{region_index}.inputInvariant originalState candidateState statesRelated\n"
            "  simp only [stackWindowsRelated, List.all_eq_true] at sourceWindows\n"
            "  have sourceWindowHolds : sourceWindow.holds world originalState.registers\n"
            "      candidateState.registers = true := by\n"
            "    exact sourceWindows sourceWindow (by decide)\n"
            "  have frameProtected : runtimeFrame.protectedSpanValid\n"
            "      staticProofContext = true := by\n"
            "    exact RelationalRuntimeCallFrame.protectedSpanValid_of_window_call\n"
            "      staticProofContext world sourceWindow originalState.registers\n"
            "      candidateState.registers runtimeFrame " + str(stack_amount) + "\n"
            "      (StateRel.stackRangesValid staticProofContext world\n"
            f"        region{region_index}.inputInvariant originalState candidateState\n"
            "        statesRelated) sourceWindowHolds (by decide) (by decide)\n"
            "      (by simp [runtimeFrame]) (by simp [runtimeFrame, sourceWindow])\n"
            "      (by simp [runtimeFrame]) (by simp [runtimeFrame])\n"
            "  have frameValid : runtimeFrame.valid staticProofContext = true := by\n"
            "    unfold RelationalRuntimeCallFrame.valid\n"
            "    simp only [Bool.and_eq_true]\n"
            "    constructor\n"
            "    · change RelationalCallFrame.valid staticProofContext {\n"
            f"      continuationTargetId := {continuation}\n"
            f"      originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
            f"      candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
            "      } = true\n"
            "      decide\n"
            "    · exact frameProtected\n"
            "  have frameResolves : runtimeFrame.toRelationalCallFrame.resolves\n"
            "      staticProofContext = true := by\n"
            "    change RelationalCallFrame.resolves staticProofContext {\n"
            f"      continuationTargetId := {continuation}\n"
            f"      originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
            f"      candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
            "    } = true\n"
            "    decide\n"
            "  have outerStackHolds : RelationalRuntimeCallStackHolds\n"
            "      staticProofContext\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"        candidateState) frames {source_calls_literal}\n"
            f"      {target_offsets_literal} := by\n"
            "    exact RelationalRuntimeCallStackHolds.afterInternal\n"
            f"      staticProofContext world region{region_index}.inputInvariant\n"
            f"      {original_behavior} {candidate_behavior}\n"
            f"      outerFrameClaims frames {source_calls_literal} originalState\n"
            "      candidateState (by decide)\n"
            "      (by simpa [outerFrameClaims] using stackHolds) statesRelated\n"
            "  have outerFrameFactsNext : RelationalRuntimeCallFactsHold "
            "staticProofContext world\n"
            f"      {target_offsets_literal}\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers := by\n"
            "    exact RelationalRuntimeCallFactsHold.afterInternal "
            "staticProofContext world\n"
            f"      {original_behavior} {candidate_behavior} outerFrameImportClaims\n"
            "      originalState candidateState (by decide)\n"
            "      (by simpa [outerFrameImportClaims] using frameImportsHold)\n"
            "  have activeFrameInventoryHolds : activeFrameInventory.holds runtimeFrame\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers := by\n"
            "    refine And.intro (by decide) ?_\n"
            "    intro location locationMember\n"
            "    have locationExact : location = ReturnSlotOffsetPair.zero := by\n"
            "      simpa [activeFrameInventory] using locationMember\n"
            "    subst location\n"
            "    exact frameOffsetsHold\n"
            + active_frame_exact_words
            + "  have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"        candidateState) (runtimeFrame :: frames)\n"
            f"      ({continuation} :: {source_calls_literal})\n"
            f"      (activeFrameInventory :: {target_offsets_literal}) := by\n"
            "    simp only [RelationalRuntimeCallStackHolds]\n"
            "    exact ⟨rfl, frameValid, frameResolves, frameMemory,\n"
            "      activeFrameInventoryHolds,\n"
            "      activeFrameExactWords,\n"
            "      outerStackHolds⟩\n"
            "  have activeFrameImportSeedChecked :\n"
            "      activeFrameInventory.seedsPreservedImportsFrom\n"
            f"        region{region_index}.inputInvariant {original_behavior}\n"
            f"        {candidate_behavior} = true := by decide\n"
            "  have activeFrameImportsNext : activeFrameInventory.preservedImportsHold\n"
            "      world\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    exact ReturnSlotOffsetInventory."
            "preservedImportsHold_after_stateRel_of_checked\n"
            f"      staticProofContext activeFrameInventory world\n"
            f"      region{region_index}.inputInvariant {original_behavior}\n"
            f"      {candidate_behavior} originalState candidateState\n"
            "      activeFrameImportSeedChecked statesRelated\n"
            "  let activeFrameRegisterClaims : List "
            "InvariantWP.RegisterOutputClaim := ["
            + seeded_register_output_claims_literal
            + "]\n"
            "  have activeFrameRelationSeedChecked :\n"
            "      activeFrameInventory.seedsPreservedRelationsFromOutputClaims\n"
            f"        staticProofContext region{region_index} {original_behavior}\n"
            f"        {candidate_behavior} activeFrameRegisterClaims = true := by decide\n"
            "  have activeFrameRelationsNext :\n"
            "      activeFrameInventory.preservedRelationsHold staticProofContext world\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    exact ReturnSlotOffsetInventory."
            "preservedRelationsHold_after_stateRel_of_outputClaims\n"
            "      staticProofContext activeFrameInventory world\n"
            f"      region{region_index} {original_behavior} {candidate_behavior}\n"
            "      activeFrameRegisterClaims originalState candidateState\n"
            "      activeFrameRelationSeedChecked statesRelated\n"
            "  have frameImportsNext : RelationalRuntimeCallFactsHold "
            "staticProofContext world\n"
            f"      (activeFrameInventory :: {target_offsets_literal})\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers := by\n"
            "    exact RelationalRuntimeCallFactsHold.cons staticProofContext world\n"
            "      activeFrameInventory _ _ _ activeFrameImportsNext\n"
            "      activeFrameRelationsNext outerFrameFactsNext\n"
            + known_indirect_dispatch
            + _lean_acceptance_running_target(
                node_id=node_id,
                region_index=region_index,
                edge=edge,
                frames="runtimeFrame :: frames",
                calls=f"{continuation} :: {source_calls_literal}",
                frame_offsets=(
                    "activeFrameInventory :: " + target_offsets_literal
                ),
                stack_targets_proof=(
                    "(by simp only [RelationalRuntimeCallTargetsMapped]; "
                    f"exact ⟨⟨{continuation_node_id}, "
                    f"relationalProductGraph.nodes[{continuation_node_id}], "
                    "by decide, by decide⟩, stackTargetsReachable⟩)"
                ),
                frame_imports_proof="frameImportsNext",
            )
        )
    if step["kind"] == "return":
        return_cases = step.get("cases")
        if return_cases is None:
            return _lean_acceptance_running_node(
                {**step, "kind": "return_case"},
                regions,
                behaviors,
                parameterized_environment=parameterized_environment,
                parameterized_protocol_environment=
                    parameterized_protocol_environment,
            )
        if len(return_cases) == 1:
            selected_return = {
                **step,
                **return_cases[0],
                "kind": "return_case",
            }
            selected_return.pop("cases", None)
            return _lean_acceptance_running_node(
                selected_return,
                regions,
                behaviors,
                parameterized_environment=parameterized_environment,
                parameterized_protocol_environment=
                    parameterized_protocol_environment,
            )
        case_shapes = []
        case_bodies = []
        for case_index, return_case in enumerate(return_cases):
            calls_literal = "[" + ", ".join(
                str(int(item))
                for item in return_case["control_state"]["calls"]
            ) + "]"
            offsets_literal = "[" + ", ".join(
                _lean_return_slot_offset_inventory(item)
                for item in return_case["control_state"]["frame_offsets"]
            ) + "]"
            case_shapes.append(
                f"(calls = {calls_literal} ∧ frameOffsets = {offsets_literal})"
            )
            selected_return = {
                **step,
                **return_case,
                "kind": "return_case",
                "control_already_selected": True,
            }
            selected_return.pop("cases", None)
            case_source = _lean_acceptance_running_node(
                selected_return,
                regions,
                behaviors,
                parameterized_environment=parameterized_environment,
                parameterized_protocol_environment=
                    parameterized_protocol_environment,
            )
            if not case_source.startswith(prefix):
                raise StageAInputError(
                    f"return case {case_index} did not share its node theorem prefix"
                )
            body = case_source[len(prefix):]
            case_bodies.append("\n".join(
                "  " + line for line in body.splitlines()
            ))
        return (
            prefix
            + "  have controlShape : "
            + " ∨\n      ".join(case_shapes)
            + " := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with "
            + " | ".join(
                f"controlCase{case_index}"
                for case_index in range(len(return_cases))
            )
            + "\n"
            + "\n".join(
                f"  · rcases controlCase{case_index} with ⟨rfl, rfl⟩\n"
                + case_body
                for case_index, case_body in enumerate(case_bodies)
            )
        )
    if step["kind"] == "return_case":
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
        typed_frame_offsets = f"({frame_offsets} : ReturnSlotOffsetPair)"
        frame_inventory = _lean_return_slot_offset_inventory(
            step["return_frame_inventory"]
        )
        control_calls = [int(item) for item in step["control_state"]["calls"]]
        source_calls_literal = "[" + ", ".join(
            str(item) for item in control_calls
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in step["control_state"]["frame_offsets"]
        ) + "]"
        target_calls = [
            int(item) for item in step["target_control_state"]["calls"]
        ]
        target_calls_literal = "[" + ", ".join(
            str(item) for item in target_calls
        ) + "]"
        outer_frame_claims = step["return_slot_frame_transfer_claims"]
        outer_frame_claims_literal = "[" + ", ".join(
            _lean_return_slot_frame_inventory_transfer_claim(item)
            for item in outer_frame_claims
        ) + "]"
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item["target"])
            for item in outer_frame_claims
        ) + "]"
        frame_import_claims_literal = _lean_runtime_call_import_transfer_claims([
            {
                "source": step["return_frame_inventory"],
                "target": step["return_frame_inventory"],
            },
            *outer_frame_claims,
        ])
        output_claims = ", ".join(
            _lean_register_output_claim(claim) for claim in step["output_claims"]
        )
        active_frame_relations_literal = ", ".join(
            _lean_register_relation_pair(relation)
            for relation in step.get("active_frame_relations", [])
        )
        residual_target_relations_literal = ", ".join(
            _lean_register_relation_pair(relation)
            for relation in step.get(
                "residual_target_register_relations", []
            )
        )
        stack_transfers = ", ".join(
            _lean_stack_window_transfer_claim(claim)
            for claim in step["stack_window_transfers"]
        )
        import_claim_rows: list[str] = []
        import_fact_rows: list[str] = []
        import_fact_names: list[str] = []
        import_claim_names: list[str] = []
        for claim_index, claim in enumerate(step["import_transfer_claims"]):
            if claim.get("kind") != "preserve":
                raise StageAInputError(
                    "whole-program return import transfer requires an existing "
                    "source import relation"
                )
            claim_name = f"returnImportClaim{node_id}_{claim_index}"
            fact_name = f"returnImportFact{node_id}_{claim_index}"
            import_claim_names.append(claim_name)
            import_fact_names.append(fact_name)
            import_claim_rows.append(
                f"    let {claim_name} : ImportRegisterPreserveClaim := {{\n"
                f"      imported := {_lean_external_target(claim['import'])}\n"
                f"      sourceOriginalRegister := .{claim['source_original_register']}\n"
                f"      sourceCandidateRegister := .{claim['source_candidate_register']}\n"
                f"      targetOriginalRegister := .{claim['target_original_register']}\n"
                f"      targetCandidateRegister := .{claim['target_candidate_register']}\n"
                "    }"
            )
            import_fact_rows.append(
                f"    have {fact_name} := "
                "importRegisterPreserveOutputHolds_of_checked\n"
                f"      staticProofContext world region{region_index}.inputInvariant\n"
                f"      region{target_region_index}.inputInvariant {original_behavior}\n"
                f"      {candidate_behavior} {claim_name} (by decide)\n"
                "      originalState candidateState relatedForTransfer"
            )
        import_fact_setup = "\n".join([*import_claim_rows, *import_fact_rows])
        if import_fact_setup:
            import_fact_setup += "\n"
        import_output_proof = (
            "    have outputImports : importRegisterRelationsHold world\n"
            f"        region{target_region_index}.inputInvariant.importRegisterRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            f"      simpa [activeFrameInventory,\n"
            "        ReturnSlotOffsetInventory.preservedImportsHold,\n"
            f"        RegionRelation.inputInvariant, region{target_region_index}] using\n"
            "        activeFrameImportsNext\n"
            if step["active_frame_imports"] else
            "    have outputImports : importRegisterRelationsHold world\n"
            f"        region{target_region_index}.inputInvariant.importRegisterRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            f"      simpa [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        importRegisterRelationsHold, "
            "ImportRegisterPreserveClaim.targetRelation,\n"
            + "        " + ", ".join(import_claim_names) + "] using "
            + (
                import_fact_names[0]
                if len(import_fact_names) == 1
                else "⟨" + ", ".join(import_fact_names) + "⟩"
            )
            + "\n"
            if import_fact_names else
            "    have outputImports : importRegisterRelationsHold world\n"
            f"        region{target_region_index}.inputInvariant.importRegisterRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        importRegisterRelationsHold]\n"
        )
        target_edge = {
            "target_node_id": target_node_id,
            "target_region_index": target_region_index,
            "target_target_id": continuation,
        }
        paired_writes_claim = step.get("paired_prepared_writes_claim")
        frame_exact_writes_claim = step.get("frame_exact_stack_writes_claim")
        if isinstance(paired_writes_claim, dict):
            paired_writes_literal = _lean_paired_prepared_word_writes_claim(
                paired_writes_claim
            )
            memory_transition = (
                "    let pairedWritesClaim : PairedPreparedWordWritesClaim := "
                + paired_writes_literal + "\n"
                f"    have originalWritesField : {original_behavior}.writes =\n"
                "        pairedWritesClaim.originalSymbolicWrites := by decide\n"
                f"    have candidateWritesField : {candidate_behavior}.writes =\n"
                "        pairedWritesClaim.candidateSymbolicWrites := by decide\n"
                f"    have originalWrites : ({original_behavior}.eval originalState).writes =\n"
                "        pairedWritesClaim.originalWrites originalState := by\n"
                "      simp [originalWritesField, evalNormalizedWrites,\n"
                "        PairedPreparedWordWritesClaim.originalSymbolicWrites,\n"
                "        PairedPreparedWordWritesClaim.originalWrites]\n"
                f"    have candidateWrites : ({candidate_behavior}.eval candidateState).writes =\n"
                "        pairedWritesClaim.candidateWrites candidateState := by\n"
                "      simp [candidateWritesField, evalNormalizedWrites,\n"
                "        PairedPreparedWordWritesClaim.candidateSymbolicWrites,\n"
                "        PairedPreparedWordWritesClaim.candidateWrites]\n"
                "    have nextStatesRelated : StateRel staticProofContext world\n"
                f"        region{target_region_index}.inputInvariant\n"
                f"        (({original_behavior}.eval originalState).nextMachineState originalState)\n"
                f"        (({candidate_behavior}.eval candidateState).nextMachineState candidateState) :=\n"
                "      StateRel.afterPairedPreparedWordWritesEvaluation\n"
                "        staticProofContext world\n"
                f"        region{region_index}.inputInvariant region{target_region_index}.inputInvariant\n"
                f"        originalState candidateState ({original_behavior}.eval originalState)\n"
                f"        ({candidate_behavior}.eval candidateState) pairedWritesClaim\n"
                "        staticProofContextChecked relatedForTransfer (by decide)\n"
                "        originalWrites candidateWrites (by simp) (by simp)\n"
                "        outputRegisters outputBounds outputSeparations\n"
                "        outputStackWindows outputX87 outputFlags outputImports\n"
                "        outputDynamic outputDynamicStack\n"
                f"        (by simp [RegionRelation.inputInvariant, region{target_region_index},\n"
                "          pairedStatePredicatesHold])\n"
            )
        elif isinstance(frame_exact_writes_claim, dict):
            frame_exact_writes_literal = _lean_frame_exact_stack_word_writes_claim(
                frame_exact_writes_claim
            )
            memory_transition = (
                "    let frameExactWritesClaim : FrameExactStackWordWritesClaim := "
                + frame_exact_writes_literal + "\n"
                f"    have originalWritesField : {original_behavior}.writes =\n"
                "        frameExactWritesClaim.originalSymbolicWrites := by decide\n"
                f"    have candidateWritesField : {candidate_behavior}.writes =\n"
                "        frameExactWritesClaim.candidateSymbolicWrites := by decide\n"
                f"    have originalWrites : ({original_behavior}.eval originalState).writes =\n"
                "        frameExactWritesClaim.originalWrites originalState := by\n"
                "      simp [originalWritesField, evalNormalizedWrites,\n"
                "        FrameExactStackWordWritesClaim.originalSymbolicWrites,\n"
                "        FrameExactStackWordWritesClaim.originalWrites]\n"
                f"    have candidateWrites : ({candidate_behavior}.eval candidateState).writes =\n"
                "        frameExactWritesClaim.candidateWrites candidateState := by\n"
                "      simp [candidateWritesField, evalNormalizedWrites,\n"
                "        FrameExactStackWordWritesClaim.candidateSymbolicWrites,\n"
                "        FrameExactStackWordWritesClaim.candidateWrites]\n"
                "    have activeFrameExactWords : activeFrameInventory.exactWordsHold frame\n"
                "        originalState.memory candidateState.memory := by\n"
                "      simpa [activeFrameInventory] using stackHolds.2.2.2.2.2.1.2\n"
                "    have nextStatesRelated : StateRel staticProofContext world\n"
                f"        region{target_region_index}.inputInvariant\n"
                f"        (({original_behavior}.eval originalState).nextMachineState originalState)\n"
                f"        (({candidate_behavior}.eval candidateState).nextMachineState candidateState) :=\n"
                "      StateRel.afterFrameExactStackWordWritesEvaluation\n"
                "        staticProofContext world\n"
                f"        region{region_index}.inputInvariant region{target_region_index}.inputInvariant\n"
                "        activeFrameInventory frame originalState candidateState\n"
                f"        ({original_behavior}.eval originalState)\n"
                f"        ({candidate_behavior}.eval candidateState) frameExactWritesClaim\n"
                "        staticProofContextChecked relatedForTransfer (by decide)\n"
                "        (by simpa [activeFrameInventory] using frameOffsetsHold)\n"
                "        activeFrameExactWords originalWrites candidateWrites\n"
                "        (by simp) (by simp) outputRegisters outputBounds\n"
                "        outputSeparations outputStackWindows outputX87 outputFlags\n"
                "        outputImports outputDynamic outputDynamicStack\n"
                f"        (by simp [RegionRelation.inputInvariant, region{target_region_index},\n"
                "          pairedStatePredicatesHold])\n"
            )
        else:
            memory_transition = (
                f"    have originalWritesField : {original_behavior}.writes = [] := by decide\n"
                f"    have candidateWritesField : {candidate_behavior}.writes = [] := by decide\n"
                f"    have originalWrites : ({original_behavior}.eval originalState).writes = [] := by\n"
                "      simp [originalWritesField, evalNormalizedWrites]\n"
                f"    have candidateWrites : ({candidate_behavior}.eval candidateState).writes = [] := by\n"
                "      simp [candidateWritesField, evalNormalizedWrites]\n"
                "    have nextStatesRelated : StateRel staticProofContext world\n"
                f"        region{target_region_index}.inputInvariant\n"
                f"        (({original_behavior}.eval originalState).nextMachineState originalState)\n"
                f"        (({candidate_behavior}.eval candidateState).nextMachineState candidateState) :=\n"
                "      StateRel.afterNoWriteEvaluation staticProofContext world\n"
                f"        region{region_index}.inputInvariant region{target_region_index}.inputInvariant\n"
                f"        originalState candidateState ({original_behavior}.eval originalState)\n"
                f"        ({candidate_behavior}.eval candidateState) relatedForTransfer\n"
                "        originalWrites candidateWrites (by simp) (by simp)\n"
                "        outputRegisters outputBounds\n"
                "        outputSeparations outputStackWindows outputX87 outputFlags\n"
                "        outputImports outputDynamic outputDynamicStack\n"
                f"        (by simp [RegionRelation.inputInvariant, region{target_region_index},\n"
                "          pairedStatePredicatesHold])\n"
            )
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {source_calls_literal} ∧\n"
            f"      frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        return (
            prefix
            + selected_control
            + "  cases frames with\n"
            "  | nil => simp [RelationalRuntimeCallStackHolds] at stackHolds\n"
            "  | cons frame tail =>\n"
            "    simp only [RelationalRuntimeCallStackHolds] at stackHolds\n"
            "    have frameContinuation := stackHolds.1\n"
            "    have frameResolves := stackHolds.2.2.1\n"
            "    have frameMemory := stackHolds.2.2.2.1\n"
            "    have frameOffsetsHold := stackHolds.2.2.2.2.1\n"
            "    have selectedFrameOffsetsHold :\n"
            f"        ({typed_frame_offsets}).holds frame originalState.registers\n"
            "          candidateState.registers := by\n"
            f"      exact frameOffsetsHold.2 ({typed_frame_offsets}) (by decide)\n"
            f"    let returnClaim : ReturnPopClaim := {return_claim_row}\n"
            f"    let frameClaim : ReturnPopFrameClaim := {frame_claim_row}\n"
            "    have returnTargets := returnPopTargetsRuntimeFrame_of_checked\n"
            f"      {original_behavior} {candidate_behavior} returnClaim frameClaim frame\n"
            "      originalState candidateState (by decide) (by decide)\n"
            "      selectedFrameOffsetsHold frameMemory\n"
            f"    simp only [acceptanceOriginalNormalizedOutcome{node_id},\n"
            f"      acceptanceCandidateNormalizedOutcome{node_id},\n"
            "      NormalizedOutcomeExpr.eval, PureOutcome.returned.injEq]\n"
            "      at returnTargets\n"
            "    let outerFrameClaims : List ReturnSlotFrameInventoryTransferClaim :=\n"
            f"      {outer_frame_claims_literal}\n"
            f"    let activeFrameInventory : ReturnSlotOffsetInventory := {frame_inventory}\n"
            "    let frameImportClaims : List "
            "RelationalRuntimeCallImportTransferClaim :=\n"
            f"      {frame_import_claims_literal}\n"
            "    have outerStackHolds : RelationalRuntimeCallStackHolds\n"
            "        staticProofContext\n"
            f"        (({original_behavior}.eval originalState).nextMachineState\n"
            "          originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"          candidateState) tail {target_calls_literal}\n"
            f"        {target_offsets_literal} := by\n"
            "      exact RelationalRuntimeCallStackHolds.afterInternal\n"
            f"        staticProofContext world region{region_index}.inputInvariant\n"
            f"        {original_behavior} {candidate_behavior} outerFrameClaims\n"
            f"        tail {target_calls_literal} originalState candidateState\n"
            "        (by decide)\n"
            "        (by simpa [outerFrameClaims] using stackHolds.2.2.2.2.2.2)\n"
            "        statesRelated\n"
            "    have frameFactsAfterInternal : RelationalRuntimeCallFactsHold "
            "staticProofContext world\n"
            f"        (activeFrameInventory :: {target_offsets_literal})\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers := by\n"
            "      exact RelationalRuntimeCallFactsHold.afterInternal "
            "staticProofContext world\n"
            f"        {original_behavior} {candidate_behavior} frameImportClaims\n"
            "        originalState candidateState (by decide)\n"
            "        (by simpa [frameImportClaims, activeFrameInventory] using\n"
            "          frameImportsHold)\n"
            "    have activeFrameImportsNext := "
            "RelationalRuntimeCallFactsHold.headImports\n"
            "      staticProofContext world activeFrameInventory _ _ _ "
            "frameFactsAfterInternal\n"
            "    have activeFrameRelationsNext := "
            "RelationalRuntimeCallFactsHold.headRelations\n"
            "      staticProofContext world activeFrameInventory _ _ _ "
            "frameFactsAfterInternal\n"
            "    have outerFrameImportsNext := RelationalRuntimeCallFactsHold.tail\n"
            "      staticProofContext world activeFrameInventory _ _ _ "
            "frameFactsAfterInternal\n"
            "    have relatedForTransfer := statesRelated\n"
            + import_fact_setup
            + "    rcases statesRelated with\n"
            "      ⟨_worldValid, stackRangesValid, _stackMemory, _importsStatic,\n"
            "        _importsComplete, _importsMemory, _originalImmutable,\n"
            "        _candidateImmutable, relatedCore, _inputImportRegisters⟩\n"
            "    rcases relatedCore with\n"
            "      ⟨_inputRegisters, _inputBounds, _inputSeparations, inputStackWindows,\n"
            "        _inputMemory, _inputDynamicMemory, _inputUndefined, inputX87,\n"
            "        _inputFlags, _inputFsBase⟩\n"
            f"    let outputClaims : List InvariantWP.RegisterOutputClaim := [{output_claims}]\n"
            "    let carriedRelations : List RegisterRelationPair := ["
            + active_frame_relations_literal
            + "]\n"
            "    let residualRelations : List RegisterRelationPair := ["
            + residual_target_relations_literal
            + "]\n"
            "    have outputRegisters : registerRelationsHold\n"
            "        staticProofContext.originalPe.imageBase\n"
            "        staticProofContext.candidatePe.imageBase\n"
            "        staticProofContext.codeMap.entries.toList\n"
            "        (staticProofContext.relationalValueTargets world)\n"
            f"        region{target_region_index}.inputInvariant.registerRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "      have carriedHolds : registerRelationsHold\n"
            "          staticProofContext.originalPe.imageBase\n"
            "          staticProofContext.candidatePe.imageBase\n"
            "          staticProofContext.codeMap.entries.toList\n"
            "          (staticProofContext.relationalValueTargets world)\n"
            "          carriedRelations\n"
            f"          ({original_behavior}.eval originalState).registers\n"
            f"          ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "        simpa [carriedRelations, activeFrameInventory,\n"
            "          ReturnSlotOffsetInventory.preservedRelationsHold] using\n"
            "          activeFrameRelationsNext\n"
            "      have residualHolds : registerRelationsHold\n"
            "          staticProofContext.originalPe.imageBase\n"
            "          staticProofContext.candidatePe.imageBase\n"
            "          staticProofContext.codeMap.entries.toList\n"
            "          (staticProofContext.relationalValueTargets world)\n"
            "          residualRelations\n"
            f"          ({original_behavior}.eval originalState).registers\n"
            f"          ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "        have inventory : outputClaims.map "
            "InvariantWP.RegisterOutputClaim.output = residualRelations := by decide\n"
            "        rw [← inventory]\n"
            "        exact InvariantWP.registerRelationsHold_of_nonMemoryOutputClaims\n"
            f"          staticProofContext world region{region_index} {original_behavior}\n"
            f"          {candidate_behavior} outputClaims (by decide)\n"
            "          originalState candidateState relatedForTransfer\n"
            "      have combinedHolds := registerRelationsHold_append_of_holds\n"
            "        staticProofContext.originalPe.imageBase\n"
            "        staticProofContext.candidatePe.imageBase\n"
            "        staticProofContext.codeMap.entries.toList\n"
            "        (staticProofContext.relationalValueTargets world)\n"
            "        carriedRelations residualRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers\n"
            "        carriedHolds residualHolds\n"
            "      rw [RegionRelation.inputInvariant]\n"
            "      exact registerRelationsHold_of_perm\n"
            "        staticProofContext.originalPe.imageBase\n"
            "        staticProofContext.candidatePe.imageBase\n"
            "        staticProofContext.codeMap.entries.toList\n"
            "        (staticProofContext.relationalValueTargets world)\n"
            f"        (carriedRelations ++ residualRelations) region{target_region_index}.inputRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers\n"
            "        (by decide) combinedHolds\n"
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
            "      have inputLegacyX87 := inputX87.1\n"
            "      simp [originalX87Field, candidateX87Field,\n"
            f"        originalBehavior{region_index}, candidateBehavior{region_index},\n"
            "        RelationalBehavior.nextMachineState, evalNormalizedX87,\n"
            "        X87Expr.eval, Expr.eval, inputLegacyX87]\n"
            "    have outputFlags : flagsRelated\n"
            f"        region{target_region_index}.inputInvariant.flagBits\n"
            f"        ({original_behavior}.eval originalState).eflags\n"
            f"        ({candidate_behavior}.eval candidateState).eflags = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        flagsRelated]\n"
            + import_output_proof
            + "    have outputDynamic : activeDynamicRegisterRangeRelationsHold "
            "staticProofContext world\n"
            f"        region{target_region_index}.inputInvariant.dynamicRegisterRangeRelations\n"
            f"        (({original_behavior}.eval originalState).nextMachineState "
            "originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState "
            "candidateState) = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        activeDynamicRegisterRangeRelationsHold]\n"
            "    have outputDynamicStack : activeDynamicStackRangeRelationsHold "
            "staticProofContext world\n"
            f"        region{target_region_index}.inputInvariant.dynamicStackRangeRelations\n"
            f"        (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState candidateState) = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        activeDynamicStackRangeRelationsHold]\n"
            + memory_transition
            + "    have stackHoldsNext := outerStackHolds\n"
            "    have outerTargetsReachable : RelationalRuntimeCallTargetsMapped\n"
            "        relationalProductGraph relationalProductReachabilityEvidence\n"
            f"        {target_calls_literal} := by\n"
            "      simpa only [RelationalRuntimeCallTargetsMapped] using\n"
            "        stackTargetsReachable.2\n"
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
                    frames="tail",
                    calls=target_calls_literal,
                    frame_offsets=target_offsets_literal,
                    stack_targets_proof="outerTargetsReachable",
                    frame_imports_proof="outerFrameImportsNext",
                ).splitlines()
            )
        )
    if step["kind"] == "external_terminate":
        site = step["external_site"]
        site_id = int(site["id"])
        continuation = int(site["continuation_target_id"])
        decoded_import_identity = _semantic_external_target_identity(
            step.get("decoded_import") or {}
        )
        if decoded_import_identity is None:
            raise StageAInputError(
                f"external-termination acceptance node {node_id} has no decoded import identity"
            )
        decoded_import_literal = _lean_external_target({
            "dll": decoded_import_identity[0],
            decoded_import_identity[1]: decoded_import_identity[2],
        })
        control_calls = [
            int(call) for call in step["control_state"]["calls"]
        ]
        calls_literal = "[" + ", ".join(
            str(call) for call in control_calls
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(offset)
            for offset in step["control_state"]["frame_offsets"]
        ) + "]"
        original_arguments = ", ".join(
            f"({_lean_semantic_expr(argument)}).eval originalState"
            for argument in site.get("argument_expressions", [])
        )
        candidate_arguments = ", ".join(
            f"({_lean_semantic_expr(argument)}).eval candidateState"
            for argument in site.get("argument_expressions", [])
        )
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {calls_literal} ∧ "
            f"frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        return (
            prefix
            + selected_control
            + f"  have originalBehaviorCommon : {original_behavior} =\n"
            f"      externalJumpSite{site_id}OriginalNormalized := by decide\n"
            f"  have candidateBehaviorCommon : {candidate_behavior} =\n"
            f"      externalJumpSite{site_id}CandidateNormalized := by decide\n"
            f"  have closed := externalJumpSite{site_id}TransitionChecked world\n"
            "    originalState candidateState statesRelated\n"
            f"  simp only [evalBehavior, externalJumpSite{site_id}OriginalNormalizedChecked,\n"
            f"    externalJumpSite{site_id}CandidateNormalizedChecked, Option.bind_some]\n"
            "    at closed\n"
            "  rcases closed with\n"
            "    ⟨originalCallArguments, candidateCallArguments, originalOutcome,\n"
            "      candidateOutcome, boundary⟩\n"
            f"  have originalArgumentsKnown : [{original_arguments}] =\n"
            "      originalCallArguments := by\n"
            "    have decomposed := originalOutcome\n"
            f"    simp only [externalJumpSite{site_id}OriginalOutcomeChecked,\n"
            "      NormalizedSymbolicBehavior.eval_outcome, NormalizedOutcomeExpr.eval,\n"
            "      Expr.eval, PureOutcome.externalJump.injEq] at decomposed\n"
            "    simpa only [List.map] using decomposed.2\n"
            f"  have candidateArgumentsKnown : [{candidate_arguments}] =\n"
            "      candidateCallArguments := by\n"
            "    have decomposed := candidateOutcome\n"
            f"    simp only [externalJumpSite{site_id}CandidateOutcomeChecked,\n"
            "      NormalizedSymbolicBehavior.eval_outcome, NormalizedOutcomeExpr.eval,\n"
            "      Expr.eval, PureOutcome.externalJump.injEq] at decomposed\n"
            "    simpa only [List.map] using decomposed.2\n"
            "  subst originalCallArguments\n"
            "  subst candidateCallArguments\n"
            "  let originalEvent : WorldExternalEvent := {\n"
            f"    siteId := {site_id}\n"
            f"    imported := externalJumpSite{site_id}MachineContract.imported\n"
            f"    arguments := [{original_arguments}]\n"
            "    state := normalizeImportReturnSlotState\n"
            f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            "    world\n"
            "  }\n"
            "  let candidateEvent : WorldExternalEvent := {\n"
            f"    siteId := {site_id}\n"
            f"    imported := externalJumpSite{site_id}MachineContract.imported\n"
            f"    arguments := [{candidate_arguments}]\n"
            "    state := normalizeImportReturnSlotState\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "    world\n"
            "  }\n"
            "  have boundaryKnown : ExternalCallBoundaryRelated staticProofContext\n"
            f"      externalCallSite{site_id} externalJumpSite{site_id}MachineContract\n"
            "      originalEvent candidateEvent := by\n"
            "    simpa [originalEvent, candidateEvent, originalBehaviorCommon,\n"
            "      candidateBehaviorCommon] using boundary\n"
            "  have argumentsRelated := boundaryKnown.2.2.2.2.2.2\n"
            "  have observationRelated : worldRelationalObservationsRelated\n"
            "      staticProofContext\n"
            f"      (some (.external world externalJumpSite{site_id}MachineContract.imported\n"
            f"        [{original_arguments}]))\n"
            f"      (some (.external world externalJumpSite{site_id}MachineContract.imported\n"
            f"        [{candidate_arguments}])) := by\n"
            "    exact ⟨rfl, rfl, argumentsRelated⟩\n"
            "  have siteResolved : resolveExternalCallSite staticProofContext\n"
            f"      externalCallSites {target_id} {continuation}\n"
            f"      externalJumpSite{site_id}MachineContract.imported = some {site_id} := by\n"
            "    decide\n"
            "  have contractResolved : resolvedExternalCallContract? staticProofContext\n"
            f"      externalCallSites {site_id} =\n"
            f"        some externalJumpSite{site_id}MachineContract := by\n"
            "    decide\n"
            f"  have importedCommon : ({decoded_import_literal} : ExternalTarget) =\n"
            f"      externalJumpSite{site_id}MachineContract.imported := by decide\n"
            "  rw [originalBehaviorCommon, candidateBehaviorCommon]\n"
            "  simp only [originalWorldProgram, candidateWorldProgram, importedCommon,\n"
            "    siteResolved, contractResolved]\n"
            "  exact ⟨observationRelated, rfl⟩\n"
        )
    if step["kind"] == "external_jump":
        site = step["external_site"]
        site_id = int(site["id"])
        continuation = int(step["target_target_id"])
        target_node_id = int(step["target_node_id"])
        target_region_index = int(step["target_region_index"])
        decoded_import_identity = _semantic_external_target_identity(
            step.get("decoded_import") or {}
        )
        if decoded_import_identity is None:
            raise StageAInputError(
                f"external-jump acceptance node {node_id} has no decoded import identity"
            )
        decoded_import_literal = _lean_external_target({
            "dll": decoded_import_identity[0],
            decoded_import_identity[1]: decoded_import_identity[2],
        })
        control_calls = [
            int(call) for call in step["control_state"]["calls"]
        ]
        outer_calls = control_calls[1:]
        calls_literal = "[" + ", ".join(
            str(call) for call in control_calls
        ) + "]"
        outer_calls_literal = "[" + ", ".join(
            str(call) for call in outer_calls
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(offset)
            for offset in step["control_state"]["frame_offsets"]
        ) + "]"
        outer_claims = step["return_slot_external_jump_transfer_claims"]
        outer_claims_literal = "[" + ", ".join(
            _lean_external_jump_return_slot_inventory_transfer_claim(claim)
            for claim in outer_claims
        ) + "]"
        outer_fact_claims_literal = _lean_runtime_call_import_transfer_claims(
            outer_claims
        )
        active_frame_inventory_literal = _lean_return_slot_offset_inventory(
            step["control_state"]["frame_offsets"][0]
        )
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(claim["target"])
            for claim in outer_claims
        ) + "]"
        original_arguments = ", ".join(
            f"({_lean_semantic_expr(argument)}).eval originalState"
            for argument in site.get("argument_expressions", [])
        )
        candidate_arguments = ", ".join(
            f"({_lean_semantic_expr(argument)}).eval candidateState"
            for argument in site.get("argument_expressions", [])
        )
        target_edge = {
            "target_node_id": target_node_id,
            "target_region_index": target_region_index,
            "target_target_id": continuation,
        }
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {calls_literal} ∧ "
            f"frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        return (
            prefix
            + selected_control
            + "  cases frames with\n"
            "  | nil => simp [RelationalRuntimeCallStackHolds] at stackHolds\n"
            "  | cons frame outerFrames =>\n"
            "    simp only [RelationalRuntimeCallStackHolds] at stackHolds\n"
            f"    let outerFrameClaims : List "
            "ExternalJumpReturnSlotInventoryTransferClaim := "
            f"{outer_claims_literal}\n"
            "    let outerFrameFactClaims : List "
            "RelationalRuntimeCallImportTransferClaim := "
            f"{outer_fact_claims_literal}\n"
            "    let activeFrameInventory : ReturnSlotOffsetInventory := "
            f"{active_frame_inventory_literal}\n"
            f"    have originalBehaviorCommon : {original_behavior} =\n"
            f"        externalJumpSite{site_id}OriginalNormalized := by decide\n"
            f"    have candidateBehaviorCommon : {candidate_behavior} =\n"
            f"        externalJumpSite{site_id}CandidateNormalized := by decide\n"
            f"    have closed := externalJumpSite{site_id}TransitionChecked world\n"
            "      originalState candidateState statesRelated\n"
            f"    simp only [evalBehavior, externalJumpSite{site_id}OriginalNormalizedChecked,\n"
            f"      externalJumpSite{site_id}CandidateNormalizedChecked, Option.bind_some]\n"
            "      at closed\n"
            "    rcases closed with\n"
            "      ⟨originalCallArguments, candidateCallArguments, originalOutcome,\n"
            "        candidateOutcome, boundary⟩\n"
            f"    have originalArgumentsKnown : [{original_arguments}] =\n"
            "        originalCallArguments := by\n"
            "      have decomposed := originalOutcome\n"
            f"      simp only [externalJumpSite{site_id}OriginalOutcomeChecked,\n"
            "        NormalizedSymbolicBehavior.eval_outcome, NormalizedOutcomeExpr.eval,\n"
            "        Expr.eval, PureOutcome.externalJump.injEq] at decomposed\n"
            "      simpa only [List.map] using decomposed.2\n"
            f"    have candidateArgumentsKnown : [{candidate_arguments}] =\n"
            "        candidateCallArguments := by\n"
            "      have decomposed := candidateOutcome\n"
            f"      simp only [externalJumpSite{site_id}CandidateOutcomeChecked,\n"
            "        NormalizedSymbolicBehavior.eval_outcome, NormalizedOutcomeExpr.eval,\n"
            "        Expr.eval, PureOutcome.externalJump.injEq] at decomposed\n"
            "      simpa only [List.map] using decomposed.2\n"
            "    subst originalCallArguments\n"
            "    subst candidateCallArguments\n"
            "    let originalEvent : WorldExternalEvent := {\n"
            f"      siteId := {site_id}\n"
            f"      imported := externalJumpSite{site_id}MachineContract.imported\n"
            f"      arguments := [{original_arguments}]\n"
            "      state := normalizeImportReturnSlotState\n"
            f"        (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            "      world\n"
            "    }\n"
            "    let candidateEvent : WorldExternalEvent := {\n"
            f"      siteId := {site_id}\n"
            f"      imported := externalJumpSite{site_id}MachineContract.imported\n"
            f"      arguments := [{candidate_arguments}]\n"
            "      state := normalizeImportReturnSlotState\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "      world\n"
            "    }\n"
            "    have boundaryKnown : ExternalCallBoundaryRelated staticProofContext\n"
            f"        externalCallSite{site_id} externalJumpSite{site_id}MachineContract\n"
            "        originalEvent candidateEvent := by\n"
            "      simpa [originalEvent, candidateEvent, originalBehaviorCommon,\n"
            "        candidateBehaviorCommon] using boundary\n"
            "    have environmentAt := ExternalEnvironmentRefines.at staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment\n"
            f"      environmentRefines externalCallSite{site_id}\n"
            f"      externalJumpSite{site_id}MachineContract (by decide)\n"
            f"      externalJumpSite{site_id}MachineContractResolved\n"
            "    have results := externalCallResultsRelated staticProofContext\n"
            f"      externalCallSite{site_id} externalJumpSite{site_id}MachineContract\n"
            "      originalEnvironment candidateEnvironment environmentAt (by decide) eventIndex\n"
            "      originalEvent candidateEvent boundaryKnown\n"
            "    dsimp only at results\n"
            "    rcases results with\n"
            "      ⟨resultWorldsEqual, _originalConforms, _candidateConforms,\n"
            "        _resultRegistersRelated, nextStatesRelated, framesPreserved⟩\n"
            "    have outerSourceFacts := RelationalRuntimeCallFactsHold.tail\n"
            "      staticProofContext world activeFrameInventory _ _ _\n"
            "      (by simpa [activeFrameInventory] using frameImportsHold)\n"
            "    have outerFactsAfterInternal :=\n"
            "      RelationalRuntimeCallFactsHold.afterInternal\n"
            f"        staticProofContext world {original_behavior} {candidate_behavior}\n"
            "        outerFrameFactClaims originalState candidateState (by decide)\n"
            "        (by simpa [outerFrameFactClaims] using outerSourceFacts)\n"
            "    have outerFactsAtBoundary : RelationalRuntimeCallFactsHold\n"
            "        staticProofContext world\n"
            f"        {target_offsets_literal} originalEvent.state.registers\n"
            "        candidateEvent.state.registers := by\n"
            "      have normalized :=\n"
            "        RelationalRuntimeCallFactsHold.normalizeImportReturnSlot\n"
            f"          staticProofContext externalJumpSite{site_id}MachineContract\n"
            f"          {target_offsets_literal} world\n"
            f"          (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"          (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "          (by decide)\n"
            "          (by simpa [RelationalBehavior.nextMachineState] using\n"
            "            outerFactsAfterInternal)\n"
            "      simpa [originalEvent, candidateEvent] using normalized\n"
            "    have pairConforms : ExactExternalCallPairConforms staticProofContext\n"
            f"        externalJumpSite{site_id}MachineContract originalEvent candidateEvent\n"
            "        (originalEnvironment.result eventIndex originalEvent)\n"
            "        (candidateEnvironment.result eventIndex candidateEvent) := {\n"
            "      siteId := rfl\n"
            "      originalImported := rfl\n"
            "      candidateImported := rfl\n"
            "      eventWorld := rfl\n"
            "      resultWorld := resultWorldsEqual\n"
            "      originalConforms := _originalConforms\n"
            "      candidateConforms := _candidateConforms\n"
            "    }\n"
            "    have activeImportsAtInput :\n"
            "        activeFrameInventory.preservedImportsHold world\n"
            "          originalState.registers candidateState.registers = true := by\n"
            "      exact RelationalRuntimeCallFactsHold.headImports\n"
            "        staticProofContext world activeFrameInventory _ _ _\n"
            "        (by simpa [activeFrameInventory] using frameImportsHold)\n"
            "    have activeImportsAfterInternal :=\n"
            "      activeFrameInventory.preservedImportsHold_after_of_checked world\n"
            f"        {original_behavior} {candidate_behavior}\n"
            "        originalState candidateState (by decide) activeImportsAtInput\n"
            "    have activeImportsAtBoundary :\n"
            "        activeFrameInventory.preservedImportsHold world\n"
            "          originalEvent.state.registers candidateEvent.state.registers = true := by\n"
            "      have normalized :=\n"
            "        activeFrameInventory.preservedImportsHold_normalizeImportReturnSlot\n"
            f"          staticProofContext externalJumpSite{site_id}MachineContract world\n"
            f"          (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"          (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "          (by decide)\n"
            "          (by simpa [RelationalBehavior.nextMachineState] using\n"
            "            activeImportsAfterInternal)\n"
            "      simpa [originalEvent, candidateEvent] using normalized\n"
            "    have activeImportsNext :=\n"
            "      activeFrameInventory.preservedImportsHold_afterExternal\n"
            f"        staticProofContext externalJumpSite{site_id}MachineContract\n"
            "        originalEvent candidateEvent\n"
            "        (originalEnvironment.result eventIndex originalEvent)\n"
            "        (candidateEnvironment.result eventIndex candidateEvent)\n"
            "        (by decide) activeImportsAtBoundary pairConforms\n"
            "    have nextStatesRelatedWithActiveImports :=\n"
            "      StateRel.withAdditionalImportRegisterRelations staticProofContext\n"
            "        (originalEnvironment.result eventIndex originalEvent).world\n"
            f"        externalCallSite{site_id}.targetInvariant\n"
            "        activeFrameInventory.preservedImports\n"
            "        (originalEnvironment.result eventIndex originalEvent).state\n"
            "        (candidateEnvironment.result eventIndex candidateEvent).state\n"
            "        nextStatesRelated activeImportsNext\n"
            "    have targetInvariantFromActiveFrame :\n"
            f"        externalCallSite{site_id}.targetInvariant."
            "withAdditionalImportRegisterRelations\n"
            "          activeFrameInventory.preservedImports =\n"
            f"          region{target_region_index}.inputInvariant := by decide\n"
            "    have nextStatesRelatedFull : StateRel staticProofContext\n"
            "        (originalEnvironment.result eventIndex originalEvent).world\n"
            f"        region{target_region_index}.inputInvariant\n"
            "        (originalEnvironment.result eventIndex originalEvent).state\n"
            "        (candidateEnvironment.result eventIndex candidateEvent).state := by\n"
            "      rw [← targetInvariantFromActiveFrame]\n"
            "      exact nextStatesRelatedWithActiveImports\n"
            "    have frameImportsNext : RelationalRuntimeCallFactsHold\n"
            "        staticProofContext\n"
            "        (originalEnvironment.result eventIndex originalEvent).world\n"
            f"        {target_offsets_literal}\n"
            "        (originalEnvironment.result eventIndex originalEvent).state.registers\n"
            "        (candidateEnvironment.result eventIndex candidateEvent).state.registers := by\n"
            "      exact RelationalRuntimeCallFactsHold.afterExternal\n"
            f"        staticProofContext externalJumpSite{site_id}MachineContract\n"
            f"        {target_offsets_literal} originalEvent candidateEvent\n"
            "        (originalEnvironment.result eventIndex originalEvent)\n"
            "        (candidateEnvironment.result eventIndex candidateEvent)\n"
            "        (by decide) outerFactsAtBoundary pairConforms\n"
            "    have argumentsRelated := boundaryKnown.2.2.2.2.2.2\n"
            "    have observationRelated : worldRelationalObservationsRelated\n"
            "        staticProofContext\n"
            f"        (some (.external world externalJumpSite{site_id}MachineContract.imported\n"
            f"          [{original_arguments}]))\n"
            f"        (some (.external world externalJumpSite{site_id}MachineContract.imported\n"
            f"          [{candidate_arguments}])) := by\n"
            "      exact ⟨rfl, rfl, argumentsRelated⟩\n"
            "    have originalSiteResolved : resolveExternalCallSite staticProofContext\n"
            f"        externalCallSites {target_id} {continuation}\n"
            f"        externalJumpSite{site_id}MachineContract.imported = some {site_id} := by\n"
            "      decide\n"
            "    have candidateSiteResolved : resolveExternalCallSite staticProofContext\n"
            f"        externalCallSites {target_id} {continuation}\n"
            f"        externalJumpSite{site_id}MachineContract.imported = some {site_id} := by\n"
            "      decide\n"
            "    have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
            "        (originalEnvironment.result eventIndex originalEvent).state\n"
            "        (candidateEnvironment.result eventIndex candidateEvent).state\n"
            f"        outerFrames {outer_calls_literal} {target_offsets_literal} := by\n"
            "      exact RelationalRuntimeCallStackHolds.afterExternalJump\n"
            f"        staticProofContext world region{region_index}.inputInvariant\n"
            f"        {original_behavior} {candidate_behavior}\n"
            f"        externalJumpSite{site_id}MachineContract outerFrameClaims\n"
            f"        outerFrames {outer_calls_literal} originalState candidateState\n"
            "        (originalEnvironment.result eventIndex originalEvent).state\n"
            "        (candidateEnvironment.result eventIndex candidateEvent).state\n"
            "        (by decide)\n"
            "        (by simpa [outerFrameClaims] using stackHolds.2.2.2.2.2.2)\n"
            "        (by simpa [originalEvent] using _originalConforms.2.1)\n"
            "        (by simpa [candidateEvent] using _candidateConforms.2.1)\n"
            "        statesRelated\n"
            "        (by\n"
            "          intro outerFrame inventory frameHolds exactWords\n"
            "          exact framesPreserved outerFrame inventory (by\n"
            "            simpa [originalEvent, candidateEvent] using frameHolds) (by\n"
            "            simpa [originalEvent, candidateEvent] using exactWords))\n"
            "    have outerTargetsReachable : RelationalRuntimeCallTargetsMapped\n"
            f"        relationalProductGraph relationalProductReachabilityEvidence\n"
            f"        {outer_calls_literal} := by\n"
            "      simpa only [RelationalRuntimeCallTargetsMapped] using\n"
            "        stackTargetsReachable.2\n"
            "    rw [originalBehaviorCommon, candidateBehaviorCommon]\n"
            "    simp only [originalWorldProgram, candidateWorldProgram]\n"
            f"    have importedCommon : ({decoded_import_literal} : ExternalTarget) =\n"
            f"        externalJumpSite{site_id}MachineContract.imported := by decide\n"
            "    rw [importedCommon, originalSiteResolved]\n"
            "    simp only\n"
            + "\n".join(
                "  " + line
                for line in _lean_acceptance_running_target(
                    node_id=node_id,
                    region_index=region_index,
                    edge=target_edge,
                    frames="outerFrames",
                    calls=outer_calls_literal,
                    frame_offsets=target_offsets_literal,
                    stack_targets_proof="outerTargetsReachable",
                    observation_proof="observationRelated",
                    world_equal_proof="resultWorldsEqual",
                    frame_imports_proof="frameImportsNext",
                    states_related_proof="nextStatesRelatedFull",
                ).splitlines()
            )
        )
    if step["kind"] in {"external_call", "external_protocol"}:
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
            # Register-dispatched calls record their checked import in the compact
            # machine-contract form rather than the normalized decoder form.
            imported_identity = _machine_import_call_contract_identity(
                step.get("machine_contract")
            )
        if imported_identity is None:
            raise StageAInputError(
                f"external acceptance node {node_id} has no decoded import identity"
            )
        control_state = step["control_state"]
        calls_literal = "[" + ", ".join(
            str(int(call)) for call in control_state["calls"]
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(offset)
            for offset in control_state["frame_offsets"]
        ) + "]"
        transfer_claims = step["return_slot_external_transfer_claims"]
        transfer_claims_literal = "[" + ", ".join(
            _lean_external_return_slot_inventory_transfer_claim(claim)
            for claim in transfer_claims
        ) + "]"
        frame_fact_claims_literal = _lean_runtime_call_import_transfer_claims(
            transfer_claims
        )
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(claim["target"])
            for claim in transfer_claims
        ) + "]"
        imported_literal = _lean_external_target({
            "dll": imported_identity[0], imported_identity[1]: imported_identity[2],
        })
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {calls_literal} ∧ "
            f"frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        register_dispatch = bool(step.get("register_dispatch"))
        zero_argument_register_dispatch = (
            register_dispatch
            and step["kind"] == "external_call"
            and not site.get("argument_expressions", [])
            and not step.get("machine_contract", {}).get(
                "stack_argument_offsets", []
            )
        )
        proof_original_behavior = original_behavior
        proof_candidate_behavior = candidate_behavior
        original_event_state = (
            f"({original_behavior}.eval originalState).nextMachineState\n"
            "      originalState"
        )
        candidate_event_state = (
            f"({candidate_behavior}.eval candidateState).nextMachineState\n"
            "      candidateState"
        )
        behavior_bridge = (
            f"  have originalBehaviorCommon : {original_behavior} =\n"
            f"      externalCallEdge{edge_id}OriginalNormalized := by decide\n"
            f"  have candidateBehaviorCommon : {candidate_behavior} =\n"
            f"      externalCallEdge{edge_id}CandidateNormalized := by decide\n"
        )
        boundary_bridge = (
            "    simpa [originalEvent, candidateEvent, originalBehaviorCommon,\n"
            "      candidateBehaviorCommon] using boundary\n"
        )
        final_world_bridge = (
            "  rw [originalBehaviorCommon, candidateBehaviorCommon]\n"
        )
        frame_event_bridge = ""
        result_abi_bridge = ""
        original_abi_proof = (
            "(by simpa [originalEvent] using _originalConforms.2.1)"
        )
        candidate_abi_proof = (
            "(by simpa [candidateEvent] using _candidateConforms.2.1)"
        )
        imported_world_bridge = (
            f"  have importedCommon : ({imported_literal} : ExternalTarget) =\n"
            f"      externalCallEdge{edge_id}MachineContract.imported := by decide\n"
            "  rw [importedCommon]\n"
        )
        if zero_argument_register_dispatch:
            original_register = str(
                step["decoded_control"]["original_register"]
            )
            candidate_register = str(
                step["decoded_control"]["candidate_register"]
            )
            proof_original_behavior = (
                f"externalCallEdge{edge_id}OriginalNormalized"
            )
            proof_candidate_behavior = (
                f"externalCallEdge{edge_id}CandidateNormalized"
            )
            original_event_state = (
                "normalizeImportReturnSlotState\n"
                f"      (({original_behavior}.eval originalState).nextMachineState\n"
                "        originalState)"
            )
            candidate_event_state = (
                "normalizeImportReturnSlotState\n"
                f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
                "        candidateState)"
            )
            behavior_bridge = (
                f"  have originalDecodedBehaviorCommon : {original_behavior} =\n"
                f"      externalCallEdge{edge_id}OriginalDecodedNormalized := by decide\n"
                f"  have candidateDecodedBehaviorCommon : {candidate_behavior} =\n"
                f"      externalCallEdge{edge_id}CandidateDecodedNormalized := by decide\n"
                f"  have dispatchTargets := externalCallEdge{edge_id}DispatchTargetsClosed\n"
                "    world originalState candidateState statesRelated\n"
                "  rcases dispatchTargets with\n"
                "    ⟨importBinding, importBindingMember, importBindingIdentity,\n"
                "      originalDispatchOutcome, candidateDispatchOutcome⟩\n"
                "  have originalTargetAddress :\n"
                f"      (Expr.inputReg .{original_register}).eval originalState =\n"
                "        importBinding.originalAddress := by\n"
                "    rw [← originalDecodedBehaviorCommon] at originalDispatchOutcome\n"
                f"    simp only [acceptanceOriginalNormalizedOutcome{node_id},\n"
                "      NormalizedOutcomeExpr.eval, Expr.eval,\n"
                "      PureOutcome.indirectCall.injEq] at originalDispatchOutcome\n"
                "    exact originalDispatchOutcome.1\n"
                "  have candidateTargetAddress :\n"
                f"      (Expr.inputReg .{candidate_register}).eval candidateState =\n"
                "        importBinding.candidateAddress := by\n"
                "    rw [← candidateDecodedBehaviorCommon] at candidateDispatchOutcome\n"
                f"    simp only [acceptanceCandidateNormalizedOutcome{node_id},\n"
                "      NormalizedOutcomeExpr.eval, Expr.eval,\n"
                "      PureOutcome.indirectCall.injEq] at candidateDispatchOutcome\n"
                "    exact candidateDispatchOutcome.1\n"
                "  have importBindingContractIdentity : importBinding.imported =\n"
                f"      externalCallEdge{edge_id}MachineContract.imported := by\n"
                f"    simpa [externalCallEdge{edge_id}DispatchClaim] using\n"
                "      importBindingIdentity\n"
                "  have importBindingValid := StateRel.importAddressStaticValid\n"
                f"    staticProofContext world region{region_index}.inputInvariant\n"
                "    originalState candidateState statesRelated importBinding\n"
                "    importBindingMember\n"
                "  have originalCodeMissing :=\n"
                "    importBinding.originalCodeUnresolved staticProofContext\n"
                "      importBindingValid\n"
                "  have candidateCodeMissing :=\n"
                "    importBinding.candidateCodeUnresolved staticProofContext\n"
                "      importBindingValid\n"
                "  have importsStatic := StateRel.importAddressesStaticValid\n"
                f"    staticProofContext world region{region_index}.inputInvariant\n"
                "    originalState candidateState statesRelated\n"
                "  have importContractFound :\n"
                "      staticProofContext.machineImportCallContracts.find? (fun candidate =>\n"
                "        candidate.imported == importBinding.imported) =\n"
                f"        some externalCallEdge{edge_id}MachineContract := by\n"
                "    rw [importBindingContractIdentity]\n"
                "    decide\n"
                "  have importContractHasNoArguments :\n"
                f"      externalCallEdge{edge_id}MachineContract.stackArgumentOffsets = [] := by\n"
                "    decide\n"
                "  have originalImportResolved : resolveWorldImportCall false\n"
                "      staticProofContext world importBinding.originalAddress\n"
                f"      (({original_behavior}.eval originalState).nextMachineState\n"
                "        originalState) =\n"
                f"        some (externalCallEdge{edge_id}MachineContract.imported, []) := by\n"
                "    have resolved := resolveWorldImportCall_zeroArguments_of_binding\n"
                "      false staticProofContext world\n"
                f"      (({original_behavior}.eval originalState).nextMachineState\n"
                "        originalState) importBinding importsStatic importBindingMember\n"
                f"      externalCallEdge{edge_id}MachineContract importContractFound\n"
                "      importContractHasNoArguments\n"
                "    simpa [importBindingContractIdentity] using resolved\n"
                "  have candidateImportResolved : resolveWorldImportCall true\n"
                "      staticProofContext world importBinding.candidateAddress\n"
                f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
                "        candidateState) =\n"
                f"        some (externalCallEdge{edge_id}MachineContract.imported, []) := by\n"
                "    have resolved := resolveWorldImportCall_zeroArguments_of_binding\n"
                "      true staticProofContext world\n"
                f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
                "        candidateState) importBinding importsStatic importBindingMember\n"
                f"      externalCallEdge{edge_id}MachineContract importContractFound\n"
                "      importContractHasNoArguments\n"
                "    simpa [importBindingContractIdentity] using resolved\n"
                "  have originalStateCommon :=\n"
                "    normalizeImportReturnSlotState_nextMachineState_eq_of_compatible\n"
                f"      {original_behavior} externalCallEdge{edge_id}OriginalNormalized\n"
                "      originalState (by constructor <;> decide)\n"
                "  have candidateStateCommon :=\n"
                "    normalizeImportReturnSlotState_nextMachineState_eq_of_compatible\n"
                f"      {candidate_behavior} externalCallEdge{edge_id}CandidateNormalized\n"
                "      candidateState (by constructor <;> decide)\n"
            )
            boundary_bridge = (
                "    simpa [originalEvent, candidateEvent, originalStateCommon,\n"
                "      candidateStateCommon] using boundary\n"
            )
            final_world_bridge = (
                "  rw [originalTargetAddress, candidateTargetAddress,\n"
                "    originalCodeMissing, candidateCodeMissing,\n"
                "    originalImportResolved, candidateImportResolved]\n"
            )
            frame_event_bridge = (
                ", originalStateCommon, candidateStateCommon"
            )
            result_abi_bridge = (
                "  have originalAbiNormalized : machineCallAbiResultHolds\n"
                f"      externalCallEdge{edge_id}MachineContract\n"
                "      (normalizeImportReturnSlotState\n"
                f"        (({original_behavior}.eval originalState).nextMachineState\n"
                "          originalState))\n"
                "      (originalEnvironment.result eventIndex originalEvent).state = true := by\n"
                "    exact _originalConforms.2.1\n"
                "  have candidateAbiNormalized : machineCallAbiResultHolds\n"
                f"      externalCallEdge{edge_id}MachineContract\n"
                "      (normalizeImportReturnSlotState\n"
                f"        (({candidate_behavior}.eval candidateState).nextMachineState\n"
                "          candidateState))\n"
                "      (candidateEnvironment.result eventIndex candidateEvent).state = true := by\n"
                "    exact _candidateConforms.2.1\n"
            )
            original_abi_proof = (
                "(by rw [← originalStateCommon]; exact originalAbiNormalized)"
            )
            candidate_abi_proof = (
                "(by rw [← candidateStateCommon]; exact candidateAbiNormalized)"
            )
            imported_world_bridge = ""
        common = (
            prefix
            + selected_control
            + f"  let frameClaims : List ExternalReturnSlotInventoryTransferClaim := "
            f"{transfer_claims_literal}\n"
            + "  let frameFactClaims : List "
            "RelationalRuntimeCallImportTransferClaim := "
            f"{frame_fact_claims_literal}\n"
            + behavior_bridge
            + f"  have transition := externalCallEdge{edge_id}TransitionChecked world\n"
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
            f"    state := {original_event_state}\n"
            "    world\n"
            "  }\n"
            "  let candidateEvent : WorldExternalEvent := {\n"
            f"    siteId := {edge_id}\n"
            f"    imported := externalCallEdge{edge_id}MachineContract.imported\n"
            f"    arguments := [{candidate_arguments}]\n"
            f"    state := {candidate_event_state}\n"
            "    world\n"
            "  }\n"
            "  have boundaryKnown : ExternalCallBoundaryRelated staticProofContext\n"
            f"      externalCallSite{edge_id} externalCallEdge{edge_id}MachineContract\n"
            "      originalEvent candidateEvent := by\n"
            + boundary_bridge
        )
        if step["kind"] == "external_protocol":
            return common + (
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
                f"      {int(site['continuation_target_id'])}\n"
                f"      externalCallEdge{edge_id}MachineContract.imported = some {edge_id} := by\n"
                "    decide\n"
                "  have candidateSiteResolved : resolveExternalCallSite staticProofContext\n"
                f"      externalCallSites {target_id}\n"
                f"      {int(site['continuation_target_id'])}\n"
                f"      externalCallEdge{edge_id}MachineContract.imported = some {edge_id} := by\n"
                "    decide\n"
                f"  have contractDisposition : externalCallEdge{edge_id}MachineContract.disposition =\n"
                "      .protocol := by decide\n"
                f"  have originalWritesField : {original_behavior}.writes = [] := by decide\n"
                f"  have candidateWritesField : {candidate_behavior}.writes = [] := by decide\n"
                f"  have originalWrites : ({original_behavior}.eval originalState).writes = [] := by\n"
                "    simp [originalWritesField, evalNormalizedWrites]\n"
                f"  have candidateWrites : ({candidate_behavior}.eval candidateState).writes = [] := by\n"
                "    simp [candidateWritesField, evalNormalizedWrites]\n"
                "  rcases boundaryKnown.2.2.2.2.2.1 with\n"
                "    ⟨_worldValid, _stackRangesValid, outputRegisters, outputBounds,\n"
                "      outputSeparations, outputStackWindows, _undefinedEqual, outputX87,\n"
                "      outputFlags, _fsBaseEqual, outputImports, outputDynamic,\n"
                "      outputDynamicStack⟩\n"
                "  have suspendedStatesRelated : StateRel staticProofContext world\n"
                f"      externalCallSite{edge_id}.boundaryInvariant originalEvent.state\n"
                "      candidateEvent.state := by\n"
                f"    apply StateRel.afterNoWriteEvaluation staticProofContext world\n"
                f"      region{region_index}.inputInvariant\n"
                f"      externalCallSite{edge_id}.boundaryInvariant originalState candidateState\n"
                f"      ({original_behavior}.eval originalState)\n"
                f"      ({candidate_behavior}.eval candidateState) statesRelated\n"
                "      originalWrites candidateWrites\n"
                "    · simp\n"
                "    · simp\n"
                "    · simpa [originalEvent, candidateEvent] using outputRegisters\n"
                "    · simpa [originalEvent, candidateEvent] using outputBounds\n"
                "    · simpa [originalEvent, candidateEvent] using outputSeparations\n"
                "    · simpa [originalEvent, candidateEvent] using outputStackWindows\n"
                "    · simpa [originalEvent, candidateEvent] using outputX87\n"
                "    · simpa [originalEvent, candidateEvent] using outputFlags\n"
                "    · simpa [originalEvent, candidateEvent] using outputImports\n"
                "    · simpa [originalEvent, candidateEvent] using outputDynamic\n"
                "    · simpa [originalEvent, candidateEvent] using outputDynamicStack\n"
                f"    · simp [externalCallSite{edge_id}, pairedStatePredicatesHold]\n"
                "  rw [originalBehaviorCommon, candidateBehaviorCommon]\n"
                "  simp only [originalWorldProgram, candidateWorldProgram]\n"
                f"  have importedCommon : ({imported_literal} : ExternalTarget) =\n"
                f"      externalCallEdge{edge_id}MachineContract.imported := by decide\n"
                "  rw [importedCommon]\n"
                "  rw [originalSiteResolved]\n"
                "  simp only [List.map_nil]\n"
                "  refine ⟨observationRelated, ?_⟩\n"
                "  refine ⟨?_, ?_, ⟨[], ?_⟩⟩\n"
                "  · refine ⟨rfl, rfl, rfl, rfl, argumentsRelated, rfl, rfl, rfl,\n"
                "      rfl, rfl, rfl, ?_, ?_⟩\n"
                "    · simpa [originalEvent, candidateEvent] using suspendedStatesRelated\n"
                f"    · refine ⟨externalCallSite{edge_id},\n"
                f"        externalCallEdge{edge_id}MachineContract, rfl, ?_, rfl, rfl, rfl,\n"
                f"        externalCallEdge{edge_id}MachineContractResolved, rfl,\n"
                "        contractDisposition, boundaryKnown, ?_⟩\n"
                "      · decide\n"
                "      · intro _phaseZero\n"
                "        exact ⟨rfl, rfl, rfl, rfl, rfl⟩\n"
                "  · simp [WorldExternalCallbackRuntimesRelated]\n"
                "  · simp [WorldExternalCallbackFramesHold]\n"
            )
        return common + (
            "  have environmentAt := ExternalEnvironmentRefines.at staticProofContext\n"
            "    externalCallSites originalEnvironment candidateEnvironment\n"
            f"    environmentRefines externalCallSite{edge_id}\n"
            f"    externalCallEdge{edge_id}MachineContract (by decide)\n"
            f"    externalCallEdge{edge_id}MachineContractResolved\n"
            "  have results := externalCallResultsRelated staticProofContext\n"
            f"    externalCallSite{edge_id} externalCallEdge{edge_id}MachineContract\n"
            "    originalEnvironment candidateEnvironment environmentAt (by decide) eventIndex\n"
            "    originalEvent candidateEvent boundaryKnown\n"
            "  dsimp only at results\n"
            "  rcases results with\n"
            "    ⟨resultWorldsEqual, _originalConforms, _candidateConforms,\n"
            "      _resultRegistersRelated, nextStatesRelated, framesPreserved⟩\n"
            + result_abi_bridge
            + "  have frameFactsAtBoundary : RelationalRuntimeCallFactsHold\n"
            "      staticProofContext world\n"
            f"      {target_offsets_literal} originalEvent.state.registers\n"
            "      candidateEvent.state.registers := by\n"
            "    have transferred := RelationalRuntimeCallFactsHold.afterInternal\n"
            f"      staticProofContext world {proof_original_behavior} "
            f"{proof_candidate_behavior}\n"
            "      frameFactClaims originalState candidateState (by decide)\n"
            "      (by simpa [frameFactClaims] using frameImportsHold)\n"
            "    simpa [originalEvent, candidateEvent"
            f"{frame_event_bridge},\n"
            "      RelationalBehavior.nextMachineState] using transferred\n"
            "  have pairConforms : ExactExternalCallPairConforms staticProofContext\n"
            f"      externalCallEdge{edge_id}MachineContract originalEvent candidateEvent\n"
            "      (originalEnvironment.result eventIndex originalEvent)\n"
            "      (candidateEnvironment.result eventIndex candidateEvent) := {\n"
            "    siteId := rfl\n"
            "    originalImported := rfl\n"
            "    candidateImported := rfl\n"
            "    eventWorld := rfl\n"
            "    resultWorld := resultWorldsEqual\n"
            "    originalConforms := _originalConforms\n"
            "    candidateConforms := _candidateConforms\n"
            "  }\n"
            "  have frameImportsNext : RelationalRuntimeCallFactsHold\n"
            "      staticProofContext\n"
            "      (originalEnvironment.result eventIndex originalEvent).world\n"
            f"      {target_offsets_literal}\n"
            "      (originalEnvironment.result eventIndex originalEvent).state.registers\n"
            "      (candidateEnvironment.result eventIndex candidateEvent).state.registers := by\n"
            "    exact RelationalRuntimeCallFactsHold.afterExternal\n"
            f"      staticProofContext externalCallEdge{edge_id}MachineContract\n"
            f"      {target_offsets_literal} originalEvent candidateEvent\n"
            "      (originalEnvironment.result eventIndex originalEvent)\n"
            "      (candidateEnvironment.result eventIndex candidateEvent)\n"
            "      (by decide) frameFactsAtBoundary pairConforms\n"
            "  have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
            "      (originalEnvironment.result eventIndex originalEvent).state\n"
            "      (candidateEnvironment.result eventIndex candidateEvent).state\n"
            f"      frames {calls_literal} {target_offsets_literal} := by\n"
            "    exact RelationalRuntimeCallStackHolds.afterExternalCall\n"
            f"      staticProofContext world region{region_index}.inputInvariant\n"
            f"      {proof_original_behavior} {proof_candidate_behavior}\n"
            f"      externalCallEdge{edge_id}MachineContract frameClaims frames\n"
            f"      {calls_literal} originalState candidateState\n"
            "      (originalEnvironment.result eventIndex originalEvent).state\n"
            "      (candidateEnvironment.result eventIndex candidateEvent).state\n"
            "      (by decide)\n"
            "      (by simpa [frameClaims] using stackHolds)\n"
            f"      {original_abi_proof}\n"
            f"      {candidate_abi_proof}\n"
            "      statesRelated\n"
            "      (by\n"
            "        intro frame inventory frameHolds exactWords\n"
            "        exact framesPreserved frame inventory (by\n"
            "          simpa [originalEvent, candidateEvent] using frameHolds) (by\n"
            "          simpa [originalEvent, candidateEvent] using exactWords))\n"
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
            f"      {int(site['continuation_target_id'])}\n"
            f"      externalCallEdge{edge_id}MachineContract.imported = some {edge_id} := by\n"
            "    decide\n"
            "  have candidateSiteResolved : resolveExternalCallSite staticProofContext\n"
            f"      externalCallSites {target_id}\n"
            f"      {int(site['continuation_target_id'])}\n"
            f"      externalCallEdge{edge_id}MachineContract.imported = some {edge_id} := by\n"
            "    decide\n"
            + "  simp only [originalWorldProgram, candidateWorldProgram,\n"
            "    Bool.false_eq_true, if_false, if_true]\n"
            + final_world_bridge
            + imported_world_bridge
            + "  rw [originalSiteResolved]\n"
            "  simp only [List.map_nil]\n"
            + _lean_acceptance_running_target(
                node_id=node_id,
                region_index=region_index,
                edge=edge,
                frames="frames",
                calls=calls_literal,
                frame_offsets=target_offsets_literal,
                stack_targets_proof="stackTargetsReachable",
                observation_proof="observationRelated",
                world_equal_proof="resultWorldsEqual",
                frame_imports_proof="frameImportsNext",
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
            "    have inputLegacyX87 := inputX87.1\n"
            "    simp [originalX87Field, candidateX87Field,\n"
            f"      originalBehavior{region_index}, candidateBehavior{region_index},\n"
            "      RelationalBehavior.nextMachineState, evalNormalizedX87,\n"
            "      X87Expr.eval, Expr.eval, inputLegacyX87]\n"
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
            "  have outputDynamic : activeDynamicRegisterRangeRelationsHold "
            "staticProofContext world\n"
            "      terminalInvariant.dynamicRegisterRangeRelations\n"
            f"      (({original_behavior}.eval originalState).nextMachineState "
            "originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState "
            "candidateState) = true := by\n"
            "    simp [terminalInvariant, activeDynamicRegisterRangeRelationsHold]\n"
            "  have outputDynamicStack : activeDynamicStackRangeRelationsHold "
            "staticProofContext world\n"
            "      terminalInvariant.dynamicStackRangeRelations\n"
            f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState) = true := by\n"
            "    simp [terminalInvariant, activeDynamicStackRangeRelationsHold]\n"
            "  have nextStatesRelated : StateRel staticProofContext world\n"
            "      terminalInvariant\n"
            f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState) :=\n"
            "    StateRel.afterNoWriteEvaluation staticProofContext world\n"
            f"      region{region_index}.inputInvariant terminalInvariant\n"
            f"      originalState candidateState ({original_behavior}.eval originalState)\n"
            f"      ({candidate_behavior}.eval candidateState) relatedForTransfer\n"
            "      originalWrites candidateWrites (by simp) (by simp)\n"
            "      outputRegisters outputBounds\n"
            "      outputSeparations outputStackWindows outputX87 outputFlags\n"
            "      outputImports outputDynamic outputDynamicStack\n"
            "      (by simp [terminalInvariant, pairedStatePredicatesHold])\n"
            "  have returnCodeEqual :\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState).registers.eax =\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "        candidateState).registers.eax := by\n"
            "    rcases nextStatesRelated with\n"
            "      ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,\n"
            "        _importsComplete, _importsMemory, _originalImmutable,\n"
            "        _candidateImmutable, outputCore, _outputSpecialRegisters⟩\n"
            "    exact registerRelationsHold_exact_identity\n"
            "      staticProofContext.originalPe.imageBase\n"
            "      staticProofContext.candidatePe.imageBase\n"
            "      staticProofContext.codeMap.entries.toList\n"
            "      (staticProofContext.relationalValueTargets world)\n"
            "      terminalInvariant.registerRelations _ _ .eax outputCore.1 (by decide)\n"
            "  simp [originalWorldProgram, candidateWorldProgram,\n"
            "    transitionFromWorldOutcome]\n"
            "  constructor\n"
            "  · exact ⟨rfl, returnCodeEqual⟩\n"
            "  · exact ⟨rfl, nextStatesRelated⟩\n"
        )
    if step["kind"] == "indirect_jump":
        edge = step["edges"][0]
        edge_id = int(edge["edge_id"])
        target_region_index = int(edge["target_region_index"])
        target_id = int(edge["target_target_id"])
        control_calls = [int(item) for item in step["control_state"]["calls"]]
        calls_literal = "[" + ", ".join(
            str(item) for item in control_calls
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in step["control_state"]["frame_offsets"]
        ) + "]"
        frame_claims = step["return_slot_frame_transfer_claims"]
        frame_claims_literal = "[" + ", ".join(
            _lean_return_slot_frame_inventory_transfer_claim(item)
            for item in frame_claims
        ) + "]"
        frame_import_claims_literal = _lean_runtime_call_import_transfer_claims(
            frame_claims
        )
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item["target"])
            for item in frame_claims
        ) + "]"
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {calls_literal} ∧\n"
            f"      frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        original_product_behavior = f"productNode{node_id}OriginalNormalized"
        candidate_product_behavior = f"productNode{node_id}CandidateNormalized"
        fixed_code_address = (
            step["decoded_control"].get("profile") ==
            "fixed_code_address_indirect_jump_v1"
        )
        claim = (
            f"productNode{node_id}FixedCodeAddressIndirectJumpClaim"
            if fixed_code_address else
            f"productNode{node_id}ImmutableIndirectJumpClaim"
        )
        target_closed = (
            f"productNode{node_id}FixedCodeAddressIndirectJumpClosed"
            if fixed_code_address else
            f"productNode{node_id}ImmutableIndirectJumpClosed"
        )
        return (
            prefix
            + selected_control
            + f"  let frameClaims : List ReturnSlotFrameInventoryTransferClaim :=\n"
            f"    {frame_claims_literal}\n"
            "  let frameImportClaims : List "
            "RelationalRuntimeCallImportTransferClaim :=\n"
            f"    {frame_import_claims_literal}\n"
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
            "  have stackHoldsNext : RelationalRuntimeCallStackHolds\n"
            "      staticProofContext\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"        candidateState) frames {calls_literal}\n"
            f"      {target_offsets_literal} := by\n"
            "    exact RelationalRuntimeCallStackHolds.afterInternal\n"
            f"      staticProofContext world region{region_index}.inputInvariant\n"
            f"      {original_behavior} {candidate_behavior}\n"
            f"      frameClaims frames {calls_literal} originalState candidateState\n"
            "      (by decide) (by simpa [frameClaims] using stackHolds) statesRelated\n"
            "  have frameImportsNext : RelationalRuntimeCallFactsHold "
            "staticProofContext world\n"
            f"      {target_offsets_literal}\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers := by\n"
            "    exact RelationalRuntimeCallFactsHold.afterInternal "
            "staticProofContext world\n"
            f"      {original_behavior} {candidate_behavior} frameImportClaims\n"
            "      originalState candidateState (by decide)\n"
            "      (by simpa [frameImportClaims] using frameImportsHold)\n"
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
                calls=calls_literal,
                frame_offsets=target_offsets_literal,
                stack_targets_proof="stackTargetsReachable",
                frame_imports_proof="frameImportsNext",
            )
        )
    if (
        step["kind"] == "jump"
        and step.get("certificate_profile")
            == "composable_x87_state_only_singleton_v1"
    ):
        edge = step["edges"][0]
        edge_id = int(edge["edge_id"])
        continuation_target_id = int(edge["target_target_id"])
        target_region_index = int(edge["target_region_index"])
        control_calls = [int(item) for item in step["control_state"]["calls"]]
        calls_literal = "[" + ", ".join(
            str(item) for item in control_calls
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in step["control_state"]["frame_offsets"]
        ) + "]"
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in step["target_control_state"]["frame_offsets"]
        ) + "]"
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {calls_literal} ∧\n"
            f"      frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        original_execution = (
            "StageA.Relational.X87.executeSingletonCommand false "
            "staticProofContext.originalPe "
            f"segmentRefinementEdge{edge_id}Spec.originalSpan "
            f"region{region_index}.targets originalState"
        )
        candidate_execution = (
            "StageA.Relational.X87.executeSingletonCommand true "
            "staticProofContext.candidatePe "
            f"segmentRefinementEdge{edge_id}Spec.candidateSpan "
            f"region{region_index}.targets candidateState"
        )
        target_proof = _lean_acceptance_running_target(
            node_id=node_id,
            region_index=region_index,
            edge=edge,
            frames="frames",
            calls=calls_literal,
            frame_offsets=target_offsets_literal,
            stack_targets_proof="stackTargetsReachable",
            frame_imports_proof="frameImportsNext",
        )
        return (
            prefix
            + selected_control
            + f"  have transitionClosed := segmentRefinementEdge{edge_id}TransitionChecked\n"
            "  unfold X87SegmentTransitionClosed at transitionClosed\n"
            f"  rw [segmentRefinementEdge{edge_id}LocalCodeTargetsResolved,\n"
            f"    segmentRefinementEdge{edge_id}LocalValuesResolved] at transitionClosed\n"
            "  have transition := transitionClosed world originalState candidateState statesRelated\n"
            f"  have guardTrue : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
            "      originalState = true := by\n"
            f"    simp [segmentRefinementEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
            "  have transitioned := transition.2 guardTrue\n"
            f"  cases originalExecuted : {original_execution} with\n"
            "  | none =>\n"
            "      simp [originalExecuted] at transitioned\n"
            "  | some originalResult =>\n"
            f"      cases candidateExecuted : {candidate_execution} with\n"
            "      | none =>\n"
            "          simp [originalExecuted, candidateExecuted] at transitioned\n"
            "      | some candidateResult =>\n"
            "          rw [originalExecuted, candidateExecuted] at transitioned\n"
            "          simp only at transitioned\n"
            "          have faultsRelated := transitioned.1\n"
            "          simp only\n"
            f"          have originalOutcome : originalResult.outcome = "
            f".jump {continuation_target_id} :=\n"
            "            StageA.Relational.X87."
            "executeSingletonCommand_outcome_of_continuation\n"
            f"              false staticProofContext.originalPe "
            f"segmentRefinementEdge{edge_id}Spec.originalSpan\n"
            f"              region{region_index}.targets originalState "
            f"originalResult {continuation_target_id}\n"
            f"              segmentRefinementEdge{edge_id}OriginalContinuation "
            "originalExecuted\n"
            f"          have candidateOutcome : candidateResult.outcome = "
            f".jump {continuation_target_id} :=\n"
            "            StageA.Relational.X87."
            "executeSingletonCommand_outcome_of_continuation\n"
            f"              true staticProofContext.candidatePe "
            f"segmentRefinementEdge{edge_id}Spec.candidateSpan\n"
            f"              region{region_index}.targets candidateState "
            f"candidateResult {continuation_target_id}\n"
            f"              segmentRefinementEdge{edge_id}CandidateContinuation "
            "candidateExecuted\n"
            "          cases originalFault : originalResult.x87Fault with\n"
            "          | some fault =>\n"
            "              have candidateFault : candidateResult.x87Fault = "
            "some fault := by\n"
            "                rw [← faultsRelated]\n"
            "                exact originalFault\n"
            "              cases fault\n"
            "              simp [transitionFromWorldBehavior, originalFault, "
            "candidateFault,\n"
            "                worldRelationalObservationsRelated, "
            "WorldExecutionsRelated]\n"
            "          | none =>\n"
            "              have candidateFault : candidateResult.x87Fault = none := by\n"
            "                rw [← faultsRelated]\n"
            "                exact originalFault\n"
            "              rw [originalFault, candidateFault] at transitioned\n"
            "              rcases transitioned.2 with\n"
            "                ⟨_originalExit, _candidateExit, _outcomes, "
            "nextStatesRelated,\n"
            "                  originalRegisters, candidateRegisters, "
            "originalMemory, candidateMemory⟩\n"
            "              have stackHoldsNext : RelationalRuntimeCallStackHolds\n"
            "                  staticProofContext\n"
            "                  (originalResult.nextMachineState originalState)\n"
            "                  (candidateResult.nextMachineState candidateState) "
            f"frames {calls_literal}\n"
            f"                  {target_offsets_literal} := by\n"
            "                cases frames <;>\n"
            "                  simp [RelationalRuntimeCallStackHolds] at "
            "stackHolds ⊢\n"
            "              have frameImportsNext : RelationalRuntimeCallFactsHold\n"
            "                  staticProofContext world "
            f"{target_offsets_literal}\n"
            "                  (originalResult.nextMachineState "
            "originalState).registers\n"
            "                  (candidateResult.nextMachineState "
            "candidateState).registers := by\n"
            "                rw [originalRegisters, candidateRegisters]\n"
            "                simpa using frameImportsHold\n"
            "              unfold transitionFromWorldBehavior\n"
            "              rw [originalFault, candidateFault]\n"
            "              rw [originalOutcome, candidateOutcome]\n"
            "              simp only [transitionFromWorldOutcome]\n"
            + "\n".join("              " + line[2:] if line.startswith("  ") else
                "              " + line for line in target_proof.splitlines())
        )
    if step["kind"] == "jump":
        edge = step["edges"][0]
        edge_id = int(edge["edge_id"])
        target_region_index = int(edge["target_region_index"])
        control_calls = [int(item) for item in step["control_state"]["calls"]]
        calls_literal = "[" + ", ".join(
            str(item) for item in control_calls
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in step["control_state"]["frame_offsets"]
        ) + "]"
        frame_claims = step["return_slot_frame_transfer_claims"]
        frame_claims_literal = "[" + ", ".join(
            _lean_return_slot_frame_inventory_transfer_claim(item)
            for item in frame_claims
        ) + "]"
        frame_import_claims_literal = _lean_runtime_call_import_transfer_claims(
            frame_claims
        )
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item["target"])
            for item in frame_claims
        ) + "]"
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {calls_literal} ∧\n"
            f"      frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        empty_runtime_inventory = (
            not control_calls
            and not step["control_state"]["frame_offsets"]
            and not frame_claims
        )
        if empty_runtime_inventory:
            stack_transfer = (
                "    exact RelationalRuntimeCallStackHolds.emptyInventoryTransition\n"
                "      staticProofContext originalState candidateState\n"
                f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
                f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
                "      frames stackHolds\n"
            )
            facts_transfer = (
                "    exact RelationalRuntimeCallFactsHold.empty staticProofContext world\n"
                f"      ({original_behavior}.eval originalState).registers\n"
                f"      ({candidate_behavior}.eval candidateState).registers\n"
            )
        else:
            stack_transfer = (
                "    exact RelationalRuntimeCallStackHolds.afterInternal\n"
                f"      staticProofContext world region{region_index}.inputInvariant\n"
                f"      {original_behavior} {candidate_behavior}\n"
                f"      frameClaims frames {calls_literal} originalState candidateState\n"
                "      (by decide) (by simpa [frameClaims] using stackHolds) statesRelated\n"
            )
            facts_transfer = (
                "    exact RelationalRuntimeCallFactsHold.afterInternal "
                "staticProofContext world\n"
                f"      {original_behavior} {candidate_behavior} frameImportClaims\n"
                "      originalState candidateState (by decide)\n"
                "      (by simpa [frameImportClaims] using frameImportsHold)\n"
            )
        return (
            prefix
            + selected_control
            + f"  let frameClaims : List ReturnSlotFrameInventoryTransferClaim :=\n"
            f"    {frame_claims_literal}\n"
            f"  let frameImportClaims : List "
            "RelationalRuntimeCallImportTransferClaim :=\n"
            f"    {frame_import_claims_literal}\n"
            + f"  have originalBehaviorSegment : {original_behavior} =\n"
            f"      segmentRefinementEdge{edge_id}OriginalNormalizedBehavior := by decide\n"
            f"  have candidateBehaviorSegment : {candidate_behavior} =\n"
            f"      segmentRefinementEdge{edge_id}CandidateNormalizedBehavior := by decide\n"
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
            "    rw [originalBehaviorSegment, candidateBehaviorSegment]\n"
            "    exact transitioned.2.2.2\n"
            "  have stackHoldsNext : RelationalRuntimeCallStackHolds\n"
            "      staticProofContext\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"        candidateState) frames {calls_literal}\n"
            f"      {target_offsets_literal} := by\n"
            + stack_transfer
            + "  have frameImportsNext : RelationalRuntimeCallFactsHold "
            "staticProofContext world\n"
            f"      {target_offsets_literal}\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers := by\n"
            + facts_transfer
            + _lean_acceptance_running_target(
                node_id=node_id,
                region_index=region_index,
                edge=edge,
                frames="frames",
                calls=calls_literal,
                frame_offsets=target_offsets_literal,
                stack_targets_proof="stackTargetsReachable",
                frame_imports_proof="frameImportsNext",
            )
        )

    taken, fallthrough = step["edges"]
    taken_id = int(taken["edge_id"])
    fallthrough_id = int(fallthrough["edge_id"])
    branch_calls = [int(item) for item in step["control_state"]["calls"]]
    branch_calls_literal = "[" + ", ".join(
        str(item) for item in branch_calls
    ) + "]"
    branch_source_offsets_literal = "[" + ", ".join(
        _lean_return_slot_offset_inventory(item)
        for item in step["control_state"]["frame_offsets"]
    ) + "]"
    branch_control = (
        ""
        if step.get("control_already_selected") else
        f"  have controlShape : calls = {branch_calls_literal} ∧\n"
        f"      frameOffsets = {branch_source_offsets_literal} := by\n"
        "    simpa [productControlProfile] using controlMember.2\n"
        "  rcases controlShape with ⟨rfl, rfl⟩\n"
    )

    def branch_case(edge: dict[str, Any], condition: bool) -> str:
        edge_id = int(edge["edge_id"])
        target_region_index = int(edge["target_region_index"])
        candidate_condition = bool(
            edge.get("candidate_branch_value", condition)
        )
        candidate_condition_literal = (
            "true" if candidate_condition else "false"
        )
        candidate_condition_name = (
            f"segmentRefinementEdge{edge_id}CandidateOutcomeCondition"
        )
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
        original_guard = (
            f"      change region{region_index}OutcomeCondition.eval originalState = true\n"
            "      exact originalCondition\n"
            if condition else
            f"      change (!region{region_index}OutcomeCondition.eval originalState) = true\n"
            "      simp [originalCondition]\n"
        )
        frame_claims_literal = "[" + ", ".join(
            _lean_return_slot_frame_inventory_transfer_claim(item)
            for item in edge["return_slot_frame_transfer_claims"]
        ) + "]"
        frame_import_claims_literal = _lean_runtime_call_import_transfer_claims(
            edge["return_slot_frame_transfer_claims"]
        )
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in edge["target_control_state"]["frame_offsets"]
        ) + "]"
        stack_proof = (
            "    let frameClaims : List "
            "ReturnSlotFrameInventoryTransferClaim :=\n"
            f"      {frame_claims_literal}\n"
            "    let frameImportClaims : List "
            "RelationalRuntimeCallImportTransferClaim :=\n"
            f"      {frame_import_claims_literal}\n"
            "    have stackHoldsNext : RelationalRuntimeCallStackHolds\n"
            "        staticProofContext\n"
            f"        (({original_behavior}.eval originalState).nextMachineState\n"
            "          originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"          candidateState) frames {branch_calls_literal}\n"
            f"        {target_offsets_literal} := by\n"
            "      exact RelationalRuntimeCallStackHolds.afterInternal\n"
            f"        staticProofContext world region{region_index}.inputInvariant\n"
            f"        {original_behavior} {candidate_behavior}\n"
            f"        frameClaims frames {branch_calls_literal} originalState\n"
            "        candidateState (by decide)\n"
            "        (by simpa [frameClaims] using stackHolds) statesRelated\n"
            "    have frameImportsNext : RelationalRuntimeCallFactsHold "
            "staticProofContext world\n"
            f"        {target_offsets_literal}\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers := by\n"
            "      exact RelationalRuntimeCallFactsHold.afterInternal "
            "staticProofContext world\n"
            f"        {original_behavior} {candidate_behavior} frameImportClaims\n"
            "        originalState candidateState (by decide)\n"
            "        (by simpa [frameImportClaims] using frameImportsHold)"
        )
        target_proof = "\n".join(
            "  " + line
            for line in _lean_acceptance_running_target(
                node_id=node_id, region_index=region_index, edge=edge,
                frames="frames", calls=branch_calls_literal,
                frame_offsets=target_offsets_literal,
                stack_targets_proof="stackTargetsReachable",
                frame_imports_proof="frameImportsNext",
            ).splitlines()
        )
        return (
            f"    have originalBehaviorSegment : {original_behavior} =\n"
            f"        {segment_original_behavior} := by decide\n"
            f"    have candidateBehaviorSegment : {candidate_behavior} =\n"
            f"        {segment_candidate_behavior} := by decide\n"
            f"    have originalGuard : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
            "        originalState = true := by\n"
            + original_guard
            + f"    have candidateGuard : segmentRefinementEdge{edge_id}Spec.candidateGuard.eval\n"
            "        candidateState = true := by\n"
            f"      rw [← transition{edge_id}.1]\n"
            "      exact originalGuard\n"
            f"    have candidateCondition : {candidate_condition_name}.eval\n"
            f"        candidateState = {candidate_condition_literal} := by\n"
            "      exact normalizedBranchCondition_eval_of_guard_true\n"
            f"        {candidate_condition_name}\n"
            f"        segmentRefinementEdge{edge_id}Spec.candidateGuard\n"
            f"        {candidate_condition_literal} candidateState (by decide) candidateGuard\n"
            f"    have transitioned := transition{edge_id}.2 originalGuard\n"
            "    have nextStatesRelated : StateRel staticProofContext world\n"
            f"        region{target_region_index}.inputInvariant\n"
            f"        (({original_behavior}.eval originalState).nextMachineState\n"
            "          originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "          candidateState) := by\n"
            "      rw [originalBehaviorSegment, candidateBehaviorSegment]\n"
            "      exact transitioned.2.2.2\n"
            + stack_proof
            + "\n"
            f"    simp only [region{region_index}OutcomeCondition, "
            f"{candidate_condition_name}] at "
            "originalCondition candidateCondition\n"
            "    simp [originalCondition, candidateCondition]\n"
            + target_proof
        )

    return (
        prefix
        + branch_control
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
    if step["kind"] in {"external_call", "external_protocol"}:
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

def _paired_launch_import_bindings(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    *,
    reserved_ranges: list[tuple[int, int]],
) -> tuple[list[dict[str, Any]], str | None]:
    def identity(imported: Any) -> tuple[str, str, str | int] | None:
        if imported.thunk_rva is None:
            return None
        dll = str(imported.dll).lower()
        if imported.symbol is not None:
            return (dll, "symbol", str(imported.symbol))
        if imported.ordinal is not None:
            return (dll, "ordinal", int(imported.ordinal))
        return None

    original_groups: dict[
        tuple[str, str, str | int], list[Any]
    ] = {}
    candidate_groups: dict[
        tuple[str, str, str | int], list[Any]
    ] = {}
    for imported in original_bin.imports:
        key = identity(imported)
        if key is None:
            return [], "the original import table has an unresolved IAT entry"
        original_groups.setdefault(key, []).append(imported)
    for imported in candidate_bin.imports:
        key = identity(imported)
        if key is None:
            return [], "the candidate import table has an unresolved IAT entry"
        candidate_groups.setdefault(key, []).append(imported)
    if set(original_groups) != set(candidate_groups):
        return [], "the images do not have the same normalized import identities"
    for key in original_groups:
        if len(original_groups[key]) != len(candidate_groups[key]):
            return [], f"the import occurrence count differs for {key!r}"

    def allocate(start: int, used: set[int]) -> int | None:
        address = start
        while address + 4 <= 2**32:
            if address not in used and all(
                address + 4 <= lower or upper <= address
                for lower, upper in reserved_ranges
            ):
                used.add(address)
                return address
            address += 0x1000
        return None

    used: set[int] = set()
    addresses: dict[tuple[str, str, str | int], tuple[int, int]] = {}
    for index, key in enumerate(sorted(original_groups, key=repr)):
        original_address = allocate(0x60000000 + index * 0x1000, used)
        candidate_address = allocate(0x68000000 + index * 0x1000, used)
        if original_address is None or candidate_address is None:
            return [], "no disjoint synthetic import-address range is available"
        addresses[key] = (original_address, candidate_address)

    bindings: list[dict[str, Any]] = []
    for key in sorted(original_groups, key=repr):
        original_address, candidate_address = addresses[key]
        for original_import, candidate_import in zip(
            original_groups[key], candidate_groups[key], strict=True
        ):
            imported: dict[str, Any] = {"dll": key[0]}
            imported[key[1]] = key[2]
            bindings.append({
                "id": len(bindings),
                "import": imported,
                "original_iat_rva": int(original_import.thunk_rva),
                "candidate_iat_rva": int(candidate_import.thunk_rva),
                "original_address": original_address,
                "candidate_address": candidate_address,
            })
    return bindings, None


def _semantic_bool_is_structural_tautology(expression: object) -> bool:
    """Recognize a small proof-by-reduction fragment used at launch roots.

    This is only a generation gate. The emitted `StateRel` launch theorem still
    evaluates the predicate in Lean, so a mistaken proposal cannot authorize
    acceptance.
    """
    if not isinstance(expression, dict):
        return False
    operation = expression.get("op")
    if operation == "bool_constant":
        return expression.get("value") is True
    if operation == "equal":
        return expression.get("left") == expression.get("right")
    if operation == "and":
        return (
            _semantic_bool_is_structural_tautology(expression.get("left"))
            and _semantic_bool_is_structural_tautology(expression.get("right"))
        )
    if operation != "or":
        return False
    left = expression.get("left")
    right = expression.get("right")
    if (
        isinstance(left, dict)
        and left.get("op") == "not"
        and left.get("value") == right
    ) or (
        isinstance(right, dict)
        and right.get("op") == "not"
        and right.get("value") == left
    ):
        return True
    return (
        _semantic_bool_is_structural_tautology(left)
        or _semantic_bool_is_structural_tautology(right)
    )


def _launch_state_predicates_structurally_true(predicates: object) -> bool:
    if not isinstance(predicates, list):
        return False
    return all(
        isinstance(predicate, dict)
        and predicate.get("exact_memory_reads", []) == []
        and _semantic_bool_is_structural_tautology(predicate.get("original"))
        and _semantic_bool_is_structural_tautology(predicate.get("candidate"))
        for predicate in predicates
    )


def _segment_module_ownership(
    segment_refinement_modules: list[dict[str, Any]] | None,
) -> dict[int, str]:
    ownership: dict[int, str] = {}
    for segment_module in segment_refinement_modules or []:
        module = str(segment_module["module"])
        for raw_edge_id in segment_module.get("edge_ids", []):
            edge_id = int(raw_edge_id)
            previous = ownership.setdefault(edge_id, module)
            if previous != module:
                raise StageAInputError(
                    f"segment edge {edge_id} is owned by both {previous} and {module}"
                )
    return ownership


def _acceptance_segment_imports(
    selected_steps: list[dict[str, Any]], segment_module_by_edge: Mapping[int, str]
) -> str:
    edge_ids = {
        int(edge["edge_id"])
        for step in selected_steps
        if step.get("kind") not in {"external_call", "external_protocol"}
        for edge in step.get("edges", [])
    }
    missing = sorted(edge_ids - segment_module_by_edge.keys())
    if missing:
        raise StageAInputError(
            "acceptance steps reference segment edges without generated Lean "
            f"owners: {missing}"
        )
    modules = sorted({segment_module_by_edge[edge_id] for edge_id in edge_ids})
    return "".join(f"import StageA.{module}\n" for module in modules)


def _write_relational_acceptance_modules(
    lean_dir: Path,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    product_graph: dict[str, Any],
    register_relations: dict[str, Any],
    segment_candidates: list[dict[str, Any]],
    decode_chunk_regions: list[list[int]],
    external_site_candidates: list[dict[str, Any]],
    *,
    runtime_frame_affine: Mapping[str, Any] | None = None,
    deferred_guard_segment_candidates: list[dict[str, Any]] | None = None,
    segment_refinement_modules: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    stage_a = lean_dir / "StageA"
    for path in [
        *stage_a.glob("RelationalAcceptance*.lean"),
        *stage_a.glob("RelationalAcceptance*.olean"),
        *stage_a.glob("RelationalLaunch*.lean"),
        *stage_a.glob("RelationalLaunch*.olean"),
        *stage_a.glob("RelationalLinkedControl*.lean"),
        *stage_a.glob("RelationalLinkedControl*.olean"),
        *stage_a.glob("RelationalAffineLinkedControl*.lean"),
        *stage_a.glob("RelationalAffineLinkedControl*.olean"),
    ]:
        path.unlink()
    all_segment_candidates = (
        segment_candidates + list(deferred_guard_segment_candidates or [])
    )
    segment_module_by_edge = _segment_module_ownership(
        segment_refinement_modules
    )
    x87_region_indices = {
        int(candidate["source_region_index"])
        for candidate in all_segment_candidates
        if str(candidate.get("certificate_profile", "")).startswith(
            "composable_x87_"
        )
    }
    physical_state_only_region_indices = {
        index
        for index in x87_region_indices
        if original_bin.pe.get_data(
            int(contract["regions"][index]["original"]["rva_start"]),
            int(contract["regions"][index]["original"]["size"]),
        ) == b"\x9b"
        or candidate_bin.pe.get_data(
            int(contract["regions"][index]["candidate"]["rva_start"]),
            int(contract["regions"][index]["candidate"]["size"]),
        ) == b"\x9b"
    }
    plan = _whole_program_acceptance_plan(
        contract, behaviors, product_graph, register_relations,
        all_segment_candidates,
        external_site_candidates,
        runtime_frame_affine=runtime_frame_affine,
        physical_state_only_region_indices=physical_state_only_region_indices,
        launch_profile={
            "original_is_dll": original_bin.is_dll,
            "candidate_is_dll": candidate_bin.is_dll,
            "original_exports": (
                [
                    {
                        "ordinal": exported.ordinal,
                        "name": exported.name,
                        "rva": exported.rva,
                        "kind": exported.kind,
                        "forwarder": exported.forwarder,
                    }
                    for exported in original_bin.exports
                ]
                if original_bin.exports is not None else None
            ),
            "candidate_exports": (
                [
                    {
                        "ordinal": exported.ordinal,
                        "name": exported.name,
                        "rva": exported.rva,
                        "kind": exported.kind,
                        "forwarder": exported.forwarder,
                    }
                    for exported in candidate_bin.exports
                ]
                if candidate_bin.exports is not None else None
            ),
            "original_export_parse_error": original_bin.export_parse_error,
            "candidate_export_parse_error": candidate_bin.export_parse_error,
            "original_loader_diagnostics": (
                original_bin.loader_diagnostics.as_payload()
            ),
            "candidate_loader_diagnostics": (
                candidate_bin.loader_diagnostics.as_payload()
            ),
            "original_tls_directory": {
                "rva": original_bin.tls_directory_rva,
                "size": original_bin.tls_directory_size,
            },
            "candidate_tls_directory": {
                "rva": candidate_bin.tls_directory_rva,
                "size": candidate_bin.tls_directory_size,
            },
            "original_tls_callback_rvas": original_bin.tls_callback_rvas,
            "candidate_tls_callback_rvas": candidate_bin.tls_callback_rvas,
            "original_tls_callback_array_immutable": (
                original_bin.tls_callback_array_immutable
            ),
            "candidate_tls_callback_array_immutable": (
                candidate_bin.tls_callback_array_immutable
            ),
            "original_tls_callback_parse_error": (
                original_bin.tls_callback_parse_error
            ),
            "candidate_tls_callback_parse_error": (
                candidate_bin.tls_callback_parse_error
            ),
        },
    )
    launch_plan = plan.get("launch") or {}
    launch_root_node_id = plan.get("root_node_id", launch_plan.get("root_node_id"))
    if launch_root_node_id is not None:
        root_node_id = int(launch_root_node_id)
        root_region = contract["regions"][root_node_id]
        input_relations = root_region.get("input_relations", [])
        self_related_inputs = all(
            relation.get("original") == relation.get("candidate")
            and relation.get("relation") in {"exact", "related_word"}
            for relation in input_relations
        )
        launch_reasons: list[str] = []
        if original_bin.image_base != candidate_bin.image_base:
            launch_reasons.append("the preferred image bases differ")
        if original_bin.size_of_image != candidate_bin.size_of_image:
            launch_reasons.append("the preferred image spans differ")
        value_targets = list(contract.get("value_targets", []))
        if any(
            int(target.get("mapped_size", 0)) != 0
            and int(target.get("original_value", -1))
                != int(target.get("candidate_value", -2))
            for target in value_targets
        ):
            launch_reasons.append("the static data map is not identity-addressed")
        if contract.get("static_dynamic_pointer_slots"):
            launch_reasons.append("the launch has static dynamic-pointer slots")
        if not self_related_inputs:
            launch_reasons.append(
                "root register relations are not concrete self relations"
            )
        for key in (
            "input_import_relations",
            "input_dynamic_range_relations",
            "input_dynamic_stack_range_relations",
            "bounds",
            "address_separations",
            "state_predicates",
        ):
            if (
                key == "state_predicates"
                and root_region.get(key)
                and _launch_state_predicates_structurally_true(
                    root_region.get(key)
                )
            ):
                continue
            if root_region.get(key):
                launch_reasons.append(f"the root invariant has {key}")
        stack_size = 4096
        stack_base = 0x70000000
        stack_pointer = stack_base + stack_size // 2
        code_target_by_id = {
            int(target["id"]): target for target in contract.get("code_targets", [])
        }
        launch_frames: list[dict[str, int]] = []
        occupied_frame_bytes: set[tuple[str, int]] = set()
        continuation_target_ids = [
            int(target_id)
            for target_id in launch_plan.get("continuation_target_ids", [])
        ]
        frame_offsets = list(launch_plan.get("frame_offsets", []))
        if len(continuation_target_ids) != len(frame_offsets):
            launch_reasons.append(
                "the TLS continuation and return-slot inventories differ in length"
            )
        for frame_index, (continuation_target_id, inventory) in enumerate(
            zip(continuation_target_ids, frame_offsets, strict=False)
        ):
            locations = list(inventory.get("locations", []))
            esp_locations = [
                location for location in locations
                if location.get("original_register") == "esp"
                and location.get("candidate_register") == "esp"
            ]
            target = code_target_by_id.get(continuation_target_id)
            if target is None:
                launch_reasons.append(
                    f"TLS frame {frame_index} has no canonical continuation target"
                )
                continue
            if not esp_locations:
                launch_reasons.append(
                    f"TLS frame {frame_index} has no paired ESP-relative slot"
                )
                continue
            location = esp_locations[0]
            original_offset = int(location.get("original", 2**32))
            candidate_offset = int(location.get("candidate", 2**32))
            original_stack_address = stack_pointer + original_offset
            candidate_stack_address = stack_pointer + candidate_offset
            if (
                original_offset >= 2**31
                or candidate_offset >= 2**31
                or original_stack_address < stack_base
                or candidate_stack_address < stack_base
                or original_stack_address + 16 > stack_base + stack_size
                or candidate_stack_address + 16 > stack_base + stack_size
            ):
                launch_reasons.append(
                    f"TLS frame {frame_index} is outside the bounded launch stack"
                )
                continue
            frame_byte_keys = {
                *(('original', original_stack_address + byte) for byte in range(16)),
                *(('candidate', candidate_stack_address + byte) for byte in range(16)),
            }
            if occupied_frame_bytes.intersection(frame_byte_keys):
                launch_reasons.append(
                    f"TLS frame {frame_index} overlaps another launch frame"
                )
                continue
            occupied_frame_bytes.update(frame_byte_keys)
            launch_frames.append({
                "continuation_target_id": continuation_target_id,
                "original_return_address": (
                    original_bin.image_base + int(target["original_rva"])
                ),
                "candidate_return_address": (
                    candidate_bin.image_base + int(target["candidate_rva"])
                ),
                "original_stack_address": original_stack_address,
                "candidate_stack_address": candidate_stack_address,
            })
        stack_windows = root_region.get("stack_windows", [])
        if any(
            int(window.get("range_id", -1)) != 0
            or window.get("original_register") != "esp"
            or window.get("candidate_register") != "esp"
            or int(window.get("bytes_below", -1)) < 0
            or int(window.get("bytes_above", -1)) < 0
            or stack_pointer - int(window.get("bytes_below", 0)) < stack_base
            or stack_pointer + int(window.get("bytes_above", 0))
                > stack_base + stack_size
            for window in stack_windows
        ):
            launch_reasons.append(
                "the root stack windows are outside the bounded ESP launch profile"
            )
        for image in (original_bin, candidate_bin):
            image_end = image.image_base + image.size_of_image
            if not (
                stack_base + stack_size <= image.image_base
                or image_end <= stack_base
            ):
                launch_reasons.append("the canonical launch stack overlaps an image")
                break
        import_bindings, import_pair_error = _paired_launch_import_bindings(
            original_bin,
            candidate_bin,
            reserved_ranges=[
                (
                    original_bin.image_base,
                    original_bin.image_base + original_bin.size_of_image,
                ),
                (
                    candidate_bin.image_base,
                    candidate_bin.image_base + candidate_bin.size_of_image,
                ),
                (stack_base, stack_base + stack_size),
            ],
        )
        if import_pair_error is not None:
            launch_reasons.append(import_pair_error)
        if launch_reasons:
            launch_blocker = {
                "code": "launch_realizability_certificate_unsupported",
                "message": (
                    "no checked concrete launch-state certificate is available: "
                    + "; ".join(launch_reasons)
                ),
                "next_action": (
                    "extend the generic launch-memory/state witness checker for this "
                    "constraint family"
                ),
            }
            plan = {
                **plan,
                "status": "incomplete",
                "theorem": None,
                "blockers": [*plan.get("blockers", []), launch_blocker],
            }
        else:
            plan["launch_realizability"] = {
                "profile": (
                    "paired-preferred-base-import-stack-tls-static-v2"
                    if (
                        launch_frames
                        or value_targets
                        or contract.get("static_word_relation_slots")
                    )
                    else "paired-preferred-base-import-stack-v1"
                ),
                "stack_base": stack_base,
                "stack_size": stack_size,
                "stack_pointer": stack_pointer,
                "import_bindings": import_bindings,
                "frames": launch_frames,
            }
    write_json(lean_dir.parent / "whole-program-acceptance.json", plan)
    affine_linked_control = plan.get("affine_linked_control")
    if (
        isinstance(affine_linked_control, Mapping)
        and affine_linked_control.get("shape_projection_status") == "complete"
        and affine_linked_control.get("gaps") == []
    ):
        write_relational_affine_linked_control_module(
            lean_dir, affine_linked_control
        )
        write_relational_affine_linked_control_binding_modules(
            lean_dir, affine_linked_control
        )
        write_relational_affine_linked_call_binding_modules(
            lean_dir, affine_linked_control
        )
        write_relational_affine_linked_external_call_binding_modules(
            lean_dir, affine_linked_control
        )
        write_relational_affine_linked_memory_binding_modules(
            lean_dir, affine_linked_control
        )
    linked_control = plan["linked_control"]
    linked_rows = []
    for state in linked_control["states"]:
        continuation = (
            "none" if state["continuation_target_id"] is None
            else f"some {int(state['continuation_target_id'])}"
        )
        active = (
            "none" if state["active_frame"] is None
            else "some " + _lean_return_slot_offset_inventory(state["active_frame"])
        )
        linked_rows.append(
            "{ nodeId := " + str(int(state["node_id"]))
            + f", continuation := {continuation}, active := {active}"
            + f", minimumDepth := {int(state['minimum_depth'])} }}"
        )
    linked_link_rows = [
        "{ callSourceTargetId := " + str(int(link["call_source_target_id"]))
        + ", resumeNodeId := " + str(int(link["resume_node_id"]))
        + ", resumeTargetId := " + str(int(link["resume_target_id"]))
        + ", resumeContinuation := " + str(int(link["resume_continuation"]))
        + ", innerInventory := "
        + _lean_return_slot_offset_inventory(link["inner_inventory"])
        + ", suspendedInventory := "
        + _lean_return_slot_offset_inventory(link["suspended_inventory"])
        + ", resumeInventory := "
        + _lean_return_slot_offset_inventory(link["resume_inventory"])
        + ", originalGap := " + str(int(link["original_gap"]))
        + ", candidateGap := " + str(int(link["candidate_gap"])) + " }"
        for link in linked_control["links"]
    ]
    linked_control_source = (
        "import StageA.RelationalLinkedFrames\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "def linkedRuntimeCallFrameLinkCandidates :\n"
        "    List RelationalRuntimeCallFrameLink := ["
        + ", ".join(linked_link_rows) + "]\n\n"
        "def linkedProductControlProfile : LinkedProductControlProfile := {\n"
        "  states := [" + ", ".join(linked_rows) + "]\n"
        "  links := linkedRuntimeCallFrameLinkCandidates\n"
        "}\n\n"
        "theorem linkedProductControlProfileChecked :\n"
        "    linkedProductControlProfile.checked = true := by decide\n\n"
        "theorem linkedRuntimeCallFrameLinkCandidatesChecked :\n"
        "    linkedRuntimeCallFrameLinkCandidates.all\n"
        "      RelationalRuntimeCallFrameLink.checked = true := by native_decide\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalLinkedControlProfile.lean", linked_control_source
    )
    acceptance_ready = plan["status"] == "ready"
    if "launch_realizability" not in plan:
        return plan

    nodes = product_graph["nodes"]
    root_node_id = int(plan["root_node_id"])
    launch_plan = plan["launch"]
    entry_root_node_id = int(launch_plan["entry_root_node_id"])
    entry_target_id = int(launch_plan["entry_target_id"])
    tls_callback_node_ids = [
        int(node_id) for node_id in launch_plan["tls_callback_node_ids"]
    ]
    tls_callback_target_ids = [
        int(target_id) for target_id in launch_plan["tls_callback_target_ids"]
    ]
    launch_continuation_target_ids = [
        *tls_callback_target_ids[1:], entry_target_id
    ] if tls_callback_target_ids else []
    node_id_by_target = {
        int(node["target_id"]): node_id for node_id, node in enumerate(nodes)
    }
    launch_continuation_node_ids = [
        node_id_by_target[target_id]
        for target_id in launch_continuation_target_ids
    ]
    launch_frame_offsets = [
        _lean_return_slot_offset_inventory(inventory)
        for inventory in launch_plan["frame_offsets"]
    ]
    parameterized_environment = any(
        step["kind"] in {
            "external_call", "external_protocol", "external_jump", "external_terminate"
        }
        for step in plan["node_steps"]
    )
    parameterized_protocol_environment = any(
        step["kind"] == "external_protocol" for step in plan["node_steps"]
    )
    linked_states_by_node: dict[int, list[dict[str, Any]]] = {}
    for linked_state in linked_control["states"]:
        linked_states_by_node.setdefault(int(linked_state["node_id"]), []).append(
            linked_state
        )
    linked_acceptance_steps = list(plan.get("node_steps", []))
    linked_native_cases_by_node: dict[int, tuple[str, dict[str, Any] | None]] = {}
    for step in linked_acceptance_steps:
        node_id = int(step["node_id"])
        states = linked_states_by_node.get(node_id, [])
        direct_call = _linked_direct_call_case(step, states, linked_control)
        linked_return = _linked_return_case(step, states, linked_control)
        active_jump = _linked_active_jump_case(step, states)
        active_branch = _linked_active_branch_case(step, states)
        if direct_call is not None:
            linked_native_cases_by_node[node_id] = ("direct_call", direct_call)
        elif linked_return is not None:
            linked_native_cases_by_node[node_id] = ("return", linked_return)
        elif active_jump is not None:
            linked_native_cases_by_node[node_id] = ("active_jump", active_jump)
        elif active_branch is not None:
            linked_native_cases_by_node[node_id] = (
                "active_branch", active_branch
            )
        elif _linked_empty_jump_supported(step):
            linked_native_cases_by_node[node_id] = ("empty_jump", None)
        elif _linked_empty_terminate_supported(step, states):
            linked_native_cases_by_node[node_id] = ("empty_terminate", None)
    linked_native_ready = bool(
        acceptance_ready
        and not parameterized_environment
        and not launch_frame_offsets
        and not plan.get("protocol_callback_states")
        and linked_acceptance_steps
        and len(linked_native_cases_by_node) == len(linked_acceptance_steps)
    )
    linked_empty_jump_ready = bool(
        acceptance_ready
        and not parameterized_environment
        and not launch_frame_offsets
        and not plan.get("protocol_callback_states")
        and linked_acceptance_steps
        and all(_linked_empty_jump_supported(step) for step in linked_acceptance_steps)
        and all(
            len(linked_states_by_node.get(int(step["node_id"]), [])) == 1
            and linked_states_by_node[int(step["node_id"])][0].get(
                "continuation_target_id"
            ) is None
            and linked_states_by_node[int(step["node_id"])][0].get("active_frame")
                is None
            for step in linked_acceptance_steps
        )
    )
    linked_shallow_compatibility_ready = bool(
        acceptance_ready
        and not parameterized_protocol_environment
        and not launch_frame_offsets
        and not plan.get("protocol_callback_states")
        and linked_acceptance_steps
        and _linked_shallow_profiles_supported(
            list(plan.get("control_states", [])), linked_control
        )
    )
    deferred_guard_node_ids = {
        int(step["node_id"])
        for step in linked_acceptance_steps
        if _step_uses_deferred_guard(step)
    }
    linked_mixed_frame_guard_ready = bool(
        linked_shallow_compatibility_ready
        and deferred_guard_node_ids
        and all(
            (
                linked_native_cases_by_node.get(node_id, (None, None))[0]
                == "active_branch"
            )
            for node_id in deferred_guard_node_ids
        )
    )
    ordinary_profile_eligible = bool(
        acceptance_ready and not deferred_guard_node_ids
    )
    linked_acceptance_mode = (
        "native-linked-call-return-v1"
        if linked_native_ready else
        "lean-checked-shallow-with-native-frame-guards-v1"
        if linked_mixed_frame_guard_ready else
        "native-empty-stack-internal-jump-v1"
        if linked_empty_jump_ready else
        "lean-checked-shallow-profile-compatibility-v1"
        if linked_shallow_compatibility_ready and ordinary_profile_eligible else None
    )
    linked_acceptance_ready = linked_acceptance_mode is not None
    # Shallow linked acceptance is a checked wrapper around the ordinary node
    # proofs, while native linked modes close their nodes directly.
    ordinary_acceptance_ready = bool(
        ordinary_profile_eligible
        and (
            not linked_acceptance_ready
            or linked_acceptance_mode
                == "lean-checked-shallow-profile-compatibility-v1"
        )
    )
    plan["linked_acceptance"] = {
        "status": "ready" if linked_acceptance_ready else "incomplete",
        "profile": linked_acceptance_mode,
        "theorem": (
            RELATIONAL_LINKED_ACCEPTANCE_THEOREM
            if linked_acceptance_ready else None
        ),
        "blockers": [] if linked_acceptance_ready else [
            {
                "code": "linked_acceptance_node_family_pending",
                "message": (
                    "the linked acceptance generator does not yet cover every "
                    "reachable node, recursive call-frame, and launch-frame family"
                ),
                "next_action": (
                    "add native linked call, return, branch, termination, and "
                    "external-cutpoint node proofs"
                ),
            }
        ],
    }
    if plan["status"] == "ready":
        selected_theorem = choose_relational_acceptance_theorem(
            ordinary_ready=ordinary_acceptance_ready,
            linked_ready=linked_acceptance_ready,
        )
        if selected_theorem is None:
            plan = {
                **plan,
                "status": "incomplete",
                "theorem": None,
                "blockers": [
                    *plan.get("blockers", []),
                    {
                        "code": "whole_program_acceptance_theorem_pending",
                        "message": (
                            "no supported generated whole-program theorem closes "
                            "the selected control model"
                        ),
                        "next_action": (
                            "complete either ordinary or linked whole-program "
                            "acceptance for every reachable node"
                        ),
                    },
                ],
            }
        else:
            plan["required_theorem"] = selected_theorem
            plan["theorem"] = selected_theorem
    write_json(lean_dir.parent / "whole-program-acceptance.json", plan)
    acceptance_ready = plan["status"] == "ready"
    root_invariant = _lean_region_input_invariant(root_region)
    terminal_region_index = int(plan["terminal_region_index"])
    terminal_invariant = _lean_state_invariant(plan["terminal_invariant"])
    invariant_rows = ", ".join(
        f"region{node_id}.inputInvariant" for node_id in range(len(nodes))
    )
    control_rows = ", ".join(
        "{ nodeId := " + str(int(state["node_id"]))
        + ", calls := [" + ", ".join(str(int(item)) for item in state["calls"])
        + "], frameOffsets := ["
        + ", ".join(
            _lean_return_slot_offset_inventory(offsets)
            for offsets in state["frame_offsets"]
        )
        + "] }"
        for state in plan["control_states"]
    )
    callback_target_rows = ", ".join(
        "{ nodeId := " + str(int(state["node_id"]))
        + ", activeFrameOffset := "
        + _lean_return_slot_offset_pair(state["active_frame_offset"])
        + ", returnInvariant := terminalInvariant"
        + ", outerFrameTransferRules := ["
        + ", ".join(
            _lean_return_slot_transfer_rule(rule)
            for rule in state["outer_frame_transfer_rules"]
        )
        + "] }"
        for state in plan["protocol_callback_states"]
    )
    inert_protocol_source = (
        "def inertWorldProtocolEnvironment : WorldExternalProtocolEnvironment := {\n"
        "  action := fun request => .returned { state := request.state, world := request.world }\n"
        "}\n\n"
    )
    if parameterized_environment:
        protocol_parameter = (
            " (protocolEnvironment : WorldExternalProtocolEnvironment)"
            if parameterized_protocol_environment else ""
        )
        protocol_assignment = (
            "protocolEnvironment" if parameterized_protocol_environment
            else "inertWorldProtocolEnvironment"
        )
        world_program_source = (
            inert_protocol_source
            + "def originalWorldProgram (environment : WorldExternalEnvironment)"
            + protocol_parameter + " : DecodedWorldProgram := {\n"
            "  candidate := false\n  context := staticProofContext\n"
            "  regions := allRegions\n  externalCallSites\n"
            f"  environment\n  protocolEnvironment := {protocol_assignment}\n}}\n\n"
            + "def candidateWorldProgram (environment : WorldExternalEnvironment)"
            + protocol_parameter + " : DecodedWorldProgram := {\n"
            "  candidate := true\n  context := staticProofContext\n"
            "  regions := allRegions\n  externalCallSites\n"
            f"  environment\n  protocolEnvironment := {protocol_assignment}\n}}\n\n"
        )
    else:
        world_program_source = (
            inert_protocol_source
            + "def inertWorldEnvironment : WorldExternalEnvironment := {\n"
            "  result := fun _ event => { state := event.state, world := event.world }\n"
            "}\n\n"
            "def originalWorldProgram : DecodedWorldProgram := {\n"
            "  candidate := false\n  context := staticProofContext\n"
            "  regions := allRegions\n  externalCallSites\n"
            "  environment := inertWorldEnvironment\n"
            "  protocolEnvironment := inertWorldProtocolEnvironment\n}\n\n"
            "def candidateWorldProgram : DecodedWorldProgram := {\n"
            "  candidate := true\n  context := staticProofContext\n"
            "  regions := allRegions\n  externalCallSites\n"
            "  environment := inertWorldEnvironment\n"
            "  protocolEnvironment := inertWorldProtocolEnvironment\n}\n\n"
        )
    launch_definition_source = (
        "import StageA.RelationalCertificates\n"
        "import StageA.RelationalStaticContextBase\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "def consoleLaunch : PE32ConsoleLaunchV2 := {\n"
        f"  rootNodeId := {root_node_id}\n"
        f"  rootTargetId := {int(nodes[root_node_id]['target_id'])}\n"
        f"  entryNodeId := {entry_root_node_id}\n"
        f"  entryTargetId := {entry_target_id}\n"
        "  tlsCallbackNodeIds := ["
        + ", ".join(str(node_id) for node_id in tls_callback_node_ids)
        + "]\n"
        "  tlsCallbackTargetIds := ["
        + ", ".join(str(target_id) for target_id in tls_callback_target_ids)
        + "]\n"
        f"  rootInvariant := {root_invariant}\n"
        "  frameOffsets := [" + ", ".join(launch_frame_offsets) + "]\n"
        "}\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalLaunchDefinition.lean", launch_definition_source
    )
    linked_shallow_compatibility_source = ""
    if linked_acceptance_mode in {
        "lean-checked-shallow-profile-compatibility-v1",
        "lean-checked-shallow-with-native-frame-guards-v1",
    }:
        linked_shallow_compatibility_source = (
            "theorem productControlProfilesShallowEquivalentChecked :\n"
            "    ProductControlProfilesShallowEquivalent productControlProfile\n"
            "      linkedProductControlProfile = true := by decide\n\n"
            "theorem productControlProfilesOldToLinkedShallow :\n"
            "    ProductControlProfilesOldToLinkedShallow productControlProfile\n"
            "      linkedProductControlProfile :=\n"
            "  ProductControlProfilesShallowEquivalent.oldToLinked\n"
            "    productControlProfile linkedProductControlProfile\n"
            "    productControlProfilesShallowEquivalentChecked\n\n"
            "theorem productControlProfilesLinkedToOldShallow :\n"
            "    ProductControlProfilesLinkedToOldShallow productControlProfile\n"
            "      linkedProductControlProfile :=\n"
            "  ProductControlProfilesShallowEquivalent.linkedToOld\n"
            "    productControlProfile linkedProductControlProfile\n"
            "    productControlProfilesShallowEquivalentChecked\n\n"
            "theorem linkedProductControlProfileLinksEmpty :\n"
            "    linkedProductControlProfile.links = [] :=\n"
            "  ProductControlProfilesShallowEquivalent.links_eq_nil\n"
            "    productControlProfile linkedProductControlProfile\n"
            "    productControlProfilesShallowEquivalentChecked\n\n"
        )
    context_source = (
        "import StageA.RelationalCertificates\n"
        "import StageA.RelationalLinkedExecution\n"
        "import StageA.RelationalLaunchDefinition\n"
        "import StageA.RelationalLinkedControlProfile\n"
        "import StageA.RelationalProofClosureBase\n"
        "import StageA.RelationalProofStaticUsageCertificate\n"
        "import StageA.RelationalProductGraphCertificate\n"
        "import StageA.RelationalProductNodeCoverageCertificate\n"
        "import StageA.RelationalProductReachabilityCertificate\n"
        "import StageA.RelationalProductDecodedControlCertificate\n"
        "import StageA.RelationalReachableProductLocalCertificate\n"
        "import StageA.RelationalExternalCallSites\n"
        "import StageA.RelationalImportRegisterSeedCertificate\n"
        "import StageA.RelationalDynamicRangeIndirectCallCertificate\n"
        "import StageA.RelationalExternalCallRefinementCertificate\n"
        "import StageA.RelationalExternalJumpRefinementCertificate\n\n"
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
        + linked_shallow_compatibility_source
        + "def protocolCallbackTargets : ProtocolCallbackTargetProfile := {\n"
        f"  states := [{callback_target_rows}]\n"
        "}\n\n"
        + world_program_source
        + (
            _lean_acceptance_linked_shallow_lift(
                parameterized_environment=parameterized_environment,
                parameterized_protocol_environment=
                    parameterized_protocol_environment,
            )
            if linked_acceptance_mode in {
                "lean-checked-shallow-profile-compatibility-v1",
                "lean-checked-shallow-with-native-frame-guards-v1",
            }
            else ""
        )
        + "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalAcceptanceContext.lean", context_source
    )

    launch_witness = plan["launch_realizability"]
    stack_base = int(launch_witness["stack_base"])
    stack_size = int(launch_witness["stack_size"])
    stack_pointer = int(launch_witness["stack_pointer"])
    import_binding_rows = ", ".join(
        "{ id := " + str(int(binding["id"]))
        + ", imported := " + _lean_external_target(binding["import"])
        + ", originalIatRva := " + str(int(binding["original_iat_rva"]))
        + ", candidateIatRva := " + str(int(binding["candidate_iat_rva"]))
        + ", originalAddress := BitVec.ofNat 32 "
        + str(int(binding["original_address"]))
        + ", candidateAddress := BitVec.ofNat 32 "
        + str(int(binding["candidate_address"])) + " }"
        for binding in launch_witness["import_bindings"]
    )
    launch_frame_rows = ", ".join(
        "{ continuationTargetId := "
        + str(int(frame["continuation_target_id"]))
        + ", originalReturnAddress := BitVec.ofNat 32 "
        + str(int(frame["original_return_address"]))
        + ", candidateReturnAddress := BitVec.ofNat 32 "
        + str(int(frame["candidate_return_address"]))
        + ", originalStackAddress := BitVec.ofNat 32 "
        + str(int(frame["original_stack_address"]))
        + ", candidateStackAddress := BitVec.ofNat 32 "
        + str(int(frame["candidate_stack_address"]))
        + ", protectedBytes := 16"
        + " }"
        for frame in launch_witness["frames"]
    )
    original_launch_writes: list[tuple[int, int]] = []
    candidate_launch_writes: list[tuple[int, int]] = []
    for frame in launch_witness["frames"]:
        original_stack_address = int(frame["original_stack_address"])
        candidate_stack_address = int(frame["candidate_stack_address"])
        original_launch_writes.extend([
            (original_stack_address, int(frame["original_return_address"])),
            (original_stack_address + 4, original_bin.image_base),
            (original_stack_address + 8, 1),
            (original_stack_address + 12, 0),
        ])
        candidate_launch_writes.extend([
            (candidate_stack_address, int(frame["candidate_return_address"])),
            (candidate_stack_address + 4, candidate_bin.image_base),
            (candidate_stack_address + 8, 1),
            (candidate_stack_address + 12, 0),
        ])

    def stack_offset_writes(
        writes: list[tuple[int, int]], *, side: str
    ) -> list[tuple[int, int]]:
        result: list[tuple[int, int]] = []
        for address, value in writes:
            offset = address - stack_base
            if offset < 0 or offset + 4 > stack_size:
                raise StageAInputError(
                    f"{side} launch write at {address:#x} is outside the "
                    "checked launch stack range"
                )
            result.append((offset, value))
        return result

    original_stack_writes = stack_offset_writes(
        original_launch_writes, side="original"
    )
    candidate_stack_writes = stack_offset_writes(
        candidate_launch_writes, side="candidate"
    )

    def lean_stack_writes(writes: list[tuple[int, int]]) -> str:
        return ", ".join(
            "(" + str(offset) + ", BitVec.ofNat 32 " + str(value) + ")"
            for offset, value in writes
        )

    launch_context_source = (
        "import StageA.RelationalLaunchDefinition\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        "def consoleLaunchStackRange : DynamicAddressRangePair := {\n"
        "  id := 0\n"
        f"  originalBase := BitVec.ofNat 32 {stack_base}\n"
        f"  candidateBase := BitVec.ofNat 32 {stack_base}\n"
        f"  size := {stack_size}\n"
        "}\n\n"
        f"def consoleLaunchImportAddresses : List ImportAddressPair := [{import_binding_rows}]\n\n"
        f"def consoleLaunchFrames : List RelationalRuntimeCallFrame := [{launch_frame_rows}]\n\n"
        "def consoleLaunchOriginalStackWrites : List (Nat × Word) := ["
        + lean_stack_writes(original_stack_writes) + "]\n\n"
        "def consoleLaunchCandidateStackWrites : List (Nat × Word) := ["
        + lean_stack_writes(candidate_stack_writes) + "]\n\n"
        "def consoleLaunchOriginalWrites : List (Word × Word) :=\n"
        "  stackRangeConcreteWrites consoleLaunchStackRange.originalBase\n"
        "    consoleLaunchOriginalStackWrites\n\n"
        "def consoleLaunchCandidateWrites : List (Word × Word) :=\n"
        "  stackRangeConcreteWrites consoleLaunchStackRange.candidateBase\n"
        "    consoleLaunchCandidateStackWrites\n\n"
        "def consoleLaunchWorld : RelationalWorld := {\n"
        "  stackRanges := [consoleLaunchStackRange]\n"
        "  importAddresses := consoleLaunchImportAddresses\n"
        "}\n\n"
        "def consoleLaunchRegisters : Registers Word := {\n"
        "  eax := BitVec.ofNat 32 0\n"
        "  ebx := BitVec.ofNat 32 0\n"
        "  ecx := BitVec.ofNat 32 0\n"
        "  edx := BitVec.ofNat 32 0\n"
        "  esi := BitVec.ofNat 32 0\n"
        "  edi := BitVec.ofNat 32 0\n"
        "  ebp := BitVec.ofNat 32 0\n"
        f"  esp := BitVec.ofNat 32 {stack_pointer}\n"
        "}\n\n"
        "def consoleLaunchOriginalMemory : Memory :=\n"
        "  applyConcreteWrites\n"
        "    (loaderPopulatedPreferredBaseMemory false staticProofContext consoleLaunchWorld)\n"
        "    consoleLaunchOriginalWrites\n\n"
        "def consoleLaunchCandidateExcludedMemory : Memory :=\n"
        "  applyConcreteWrites\n"
        "    (loaderPopulatedPreferredBaseMemory true staticProofContext consoleLaunchWorld)\n"
        "    consoleLaunchCandidateWrites\n\n"
        "def consoleLaunchCandidateMemory : Memory :=\n"
        "  ordinaryMemoryCandidateProjection staticProofContext consoleLaunchWorld\n"
        "    (staticProofContext.relationalValueTargets consoleLaunchWorld)\n"
        "    consoleLaunchOriginalMemory consoleLaunchCandidateExcludedMemory\n\n"
        "def consoleLaunchOriginalState : MachineState := {\n"
        "  registers := consoleLaunchRegisters\n"
        "  memory := consoleLaunchOriginalMemory\n"
        "}\n\n"
        "def consoleLaunchCandidateState : MachineState := {\n"
        "  registers := consoleLaunchRegisters\n"
        "  memory := consoleLaunchCandidateMemory\n"
        "}\n\n"
        "def consoleLaunchOriginalImageMappedAt : Nat -> Bool :=\n"
        "  preferredBaseImageMemoryAt staticProofContext.originalPe\n"
        "    staticProofContext.originalImports consoleLaunchOriginalState.memory\n\n"
        "def consoleLaunchCandidateImageCompatibilityAt : Nat -> Bool :=\n"
        "  candidateProjectionImageCompatibleAt staticProofContext consoleLaunchWorld\n"
        "\n"
        "def consoleLaunchOriginalImmutableImageAt : Nat -> Bool :=\n"
        "  immutableImageWordMemoryAtWithImports staticProofContext.originalPe\n"
        "    staticProofContext.originalImports consoleLaunchOriginalState.memory\n\n"
        "def consoleLaunchCandidateImmutableImageAt : Nat -> Bool :=\n"
        "  immutableImageWordMemoryAtWithImports staticProofContext.candidatePe\n"
        "    staticProofContext.candidateImports consoleLaunchCandidateState.memory\n\n"
        "def consoleLaunchStackMemoryAt : Nat -> Bool :=\n"
        "  stackRangeMemoryHoldAt staticProofContext consoleLaunchWorld\n"
        "    consoleLaunchOriginalState.memory consoleLaunchCandidateState.memory\n"
        "    consoleLaunchStackRange\n\n"
        "def consoleLaunchStaticWordSlotAt : Nat -> Bool :=\n"
        "  staticWordRelationSlotMemoryHoldAt staticProofContext consoleLaunchWorld\n"
        "    consoleLaunchOriginalState.memory consoleLaunchCandidateState.memory\n\n"
        "theorem consoleLaunchWorldValid :\n"
        "    PE32ConsoleLaunchWorldV1.Valid staticProofContext consoleLaunchWorld := by\n"
        "  unfold PE32ConsoleLaunchWorldV1.Valid\n"
        "  refine ⟨by decide, by decide, rfl, rfl, rfl, rfl, by decide,\n"
        "    by decide⟩\n\n"
        "theorem consoleLaunchCandidateLoaderImageChecked :\n"
        "    preferredBaseLoaderImageValid staticProofContext.candidatePe = true := by\n"
        "  decide\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalLaunchContext.lean", launch_context_source
    )

    launch_chunk_size = max(
        1,
        int(os.environ.get(
            "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_LAUNCH_CHECK_CHUNK",
            "1024",
        )),
    )
    launch_stack_chunk_size = max(
        1,
        int(os.environ.get(
            "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_LAUNCH_STACK_CHECK_CHUNK",
            "64",
        )),
    )
    launch_aggregation_fanout = max(
        2,
        int(os.environ.get(
            "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_LAUNCH_AGGREGATION_FANOUT",
            "8",
        )),
    )
    launch_leaf_module_by_theorem: dict[str, str] = {}
    launch_aggregation_source = (
        "import StageA.RelationalLaunchContext\n"
        "import StageA.RelationalStaticTree\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "theorem launchAllIndexedBoolRangesHold_append (predicate : Nat -> Bool) :\n"
        "    ∀ left right,\n"
        "      AllIndexedBoolRangesHold predicate left ->\n"
        "      AllIndexedBoolRangesHold predicate right ->\n"
        "      AllIndexedBoolRangesHold predicate (left ++ right) := by\n"
        "  intro left\n"
        "  induction left with\n"
        "  | nil =>\n"
        "      intro right _ rightHolds\n"
        "      simpa [AllIndexedBoolRangesHold] using rightHolds\n"
        "  | cons span spans ih =>\n"
        "      intro right leftHolds rightHolds\n"
        "      change IndexedBoolRangeHolds predicate span ∧\n"
        "        AllIndexedBoolRangesHold predicate spans at leftHolds\n"
        "      change IndexedBoolRangeHolds predicate span ∧\n"
        "        AllIndexedBoolRangesHold predicate (spans ++ right)\n"
        "      exact And.intro leftHolds.1\n"
        "        (ih right leftHolds.2 rightHolds)\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalLaunchProofAggregation.lean",
        launch_aggregation_source,
    )

    def write_launch_span_leaves(
        *,
        module_prefix: str,
        theorem_prefix: str,
        spans: list[tuple[int, int]],
        predicate: str,
        chunk_size: int = launch_chunk_size,
    ) -> list[tuple[int, int, list[tuple[str, int, int]]]]:
        checked_spans: list[tuple[int, int, list[tuple[str, int, int]]]] = []
        leaf_index = 0
        for span_start, span_size in spans:
            checked_ranges: list[tuple[str, int, int]] = []
            for relative_start, count in _launch_check_ranges(
                span_size, chunk_size
            ):
                start = span_start + relative_start
                module = f"{module_prefix}{leaf_index}"
                theorem_name = f"{theorem_prefix}{leaf_index}"
                source_rows = [
                    "import StageA.RelationalLaunchContext\n\n",
                    "import StageA.RelationalStaticTree\n\n",
                    "namespace StageA.GeneratedRelational\n\n",
                    "open StageA.Formal StageA.Relational\n\n",
                    "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n",
                ]
                source_rows.extend([
                    f"theorem {theorem_name} :\n",
                    f"    IndexedBoolRangeHolds {predicate} "
                    f"{{ start := {start}, size := {count} }} := by\n",
                    "  apply indexedBoolRangeHolds_of_checked\n",
                    "  decide\n\n",
                ])
                source_rows.append("end StageA.GeneratedRelational\n")
                source = "".join(source_rows)
                _write_text_if_changed(stage_a / f"{module}.lean", source)
                launch_leaf_module_by_theorem[theorem_name] = module
                checked_ranges.append((theorem_name, start, count))
                leaf_index += 1
            checked_spans.append((span_start, span_size, checked_ranges))
        return checked_spans

    def write_launch_leaves(
        *,
        module_prefix: str,
        theorem_prefix: str,
        total: int,
        predicate: str,
        chunk_size: int = launch_chunk_size,
    ) -> list[tuple[str, int, int]]:
        return write_launch_span_leaves(
            module_prefix=module_prefix,
            theorem_prefix=theorem_prefix,
            spans=[(0, total)],
            predicate=predicate,
            chunk_size=chunk_size,
        )[0][2]

    def partition_candidate_image_span(
        span_start: int,
        span_size: int,
        *,
        structurally_immutable: bool,
    ) -> list[tuple[int, int, bool]]:
        iat_ranges = [
            (int(imported.thunk_rva), int(imported.thunk_rva) + 4)
            for imported in candidate_bin.imports
            if imported.thunk_rva is not None
        ]
        return _launch_structural_image_ranges(
            image_base=candidate_bin.image_base,
            span_start=span_start,
            span_size=span_size,
            excluded_ranges=iat_ranges,
            structurally_immutable=structurally_immutable,
        )

    def write_candidate_image_span_leaves(
    ) -> list[tuple[int, int, list[tuple[str, int, int]]]]:
        checked_spans: list[tuple[int, int, list[tuple[str, int, int]]]] = []
        leaf_index = 0
        mapped_spans = [(0, candidate_bin.size_of_headers, True)] + [
            (
                section.rva_start,
                section.rva_end - section.rva_start,
                not section.writable,
            )
            for section in candidate_bin.sections
        ]
        predicate = "consoleLaunchCandidateImageCompatibilityAt"
        for span_start, span_size, structurally_immutable in mapped_spans:
            checked_ranges: list[tuple[str, int, int]] = []
            for range_start, range_size, structural in partition_candidate_image_span(
                span_start,
                span_size,
                structurally_immutable=structurally_immutable,
            ):
                chunk_size = range_size if structural else launch_chunk_size
                for relative_start, count in _launch_check_ranges(
                    range_size, chunk_size
                ):
                    start = range_start + relative_start
                    module = (
                        f"RelationalLaunchCandidateImageMappedLeaf{leaf_index}"
                    )
                    theorem_name = (
                        f"consoleLaunchCandidateImageMappedRange{leaf_index}"
                    )
                    source_rows = [
                        "import StageA.RelationalLaunchContext\n",
                        "import StageA.RelationalStaticTree\n\n",
                        "namespace StageA.GeneratedRelational\n\n",
                        "open StageA.Formal StageA.Relational\n\n",
                        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n",
                    ]
                    if structural:
                        source_rows.extend([
                            f"theorem {theorem_name} :\n",
                            f"    IndexedBoolRangeHolds {predicate} "
                            f"{{ start := {start}, size := {count} }} := by\n",
                            "  apply "
                            "candidateProjectionImageCompatibleAt_of_immutable_span\n",
                            "    staticProofContext consoleLaunchWorld\n",
                            f"    {{ start := {start}, size := {count} }}\n",
                            "    consoleLaunchCandidateLoaderImageChecked\n",
                            "  decide\n\n",
                        ])
                    elif count > 1:
                        level: list[tuple[str, int, int]] = []
                        for offset in range(count):
                            row_name = f"{theorem_name}Byte{offset}"
                            row_start = start + offset
                            source_rows.extend([
                                f"theorem {row_name} :\n",
                                f"    IndexedBoolRangeHolds {predicate} "
                                f"{{ start := {row_start}, size := 1 }} := by\n",
                                "  apply indexedBoolRangeHolds_of_checked\n",
                                "  decide\n\n",
                            ])
                            level.append((row_name, row_start, 1))
                        merge_level = 0
                        while len(level) > 1:
                            next_level: list[tuple[str, int, int]] = []
                            for pair_index in range(0, len(level), 2):
                                left = level[pair_index]
                                if pair_index + 1 >= len(level):
                                    next_level.append(left)
                                    continue
                                right = level[pair_index + 1]
                                merge_name = (
                                    f"{theorem_name}Merge{merge_level}_"
                                    f"{pair_index // 2}"
                                )
                                source_rows.extend([
                                    f"theorem {merge_name} :\n",
                                    f"    IndexedBoolRangeHolds {predicate} "
                                    f"{{ start := {left[1]}, "
                                    f"size := {left[2] + right[2]} }} :=\n",
                                    f"  indexedBoolRangeHolds_append {predicate}\n",
                                    f"    {{ start := {left[1]}, size := {left[2]} }}\n",
                                    f"    {{ start := {right[1]}, size := {right[2]} }}\n",
                                    f"    (by decide) {left[0]} {right[0]}\n\n",
                                ])
                                next_level.append((
                                    merge_name,
                                    left[1],
                                    left[2] + right[2],
                                ))
                            level = next_level
                            merge_level += 1
                        source_rows.extend([
                            f"theorem {theorem_name} :\n",
                            f"    IndexedBoolRangeHolds {predicate} "
                            f"{{ start := {start}, size := {count} }} :=\n",
                            f"  {level[0][0]}\n\n",
                        ])
                    else:
                        source_rows.extend([
                            f"theorem {theorem_name} :\n",
                            f"    IndexedBoolRangeHolds {predicate} "
                            f"{{ start := {start}, size := 1 }} := by\n",
                            "  apply indexedBoolRangeHolds_of_checked\n",
                            "  decide\n\n",
                        ])
                    source_rows.append("end StageA.GeneratedRelational\n")
                    _write_text_if_changed(
                        stage_a / f"{module}.lean", "".join(source_rows)
                    )
                    launch_leaf_module_by_theorem[theorem_name] = module
                    checked_ranges.append((theorem_name, start, count))
                    leaf_index += 1
            checked_spans.append((span_start, span_size, checked_ranges))
        return checked_spans

    candidate_image_spans = write_candidate_image_span_leaves()
    stack_ranges = write_launch_leaves(
        module_prefix="RelationalLaunchStackMemoryLeaf",
        theorem_prefix="consoleLaunchStackMemoryRange",
        total=stack_size,
        predicate="consoleLaunchStackMemoryAt",
        chunk_size=launch_stack_chunk_size,
    )
    static_word_slot_ranges = write_launch_leaves(
        module_prefix="RelationalLaunchStaticWordSlotLeaf",
        theorem_prefix="consoleLaunchStaticWordSlotRange",
        total=len(contract.get("static_word_relation_slots", [])),
        predicate="consoleLaunchStaticWordSlotAt",
    )

    def launch_certificate(name: str, ranges: list[tuple[str, int, int]]) -> str:
        span_rows = ", ".join(
            f"{{ start := {start}, size := {count} }}"
            for _theorem, start, count in ranges
        )
        return (
            f"def {name} : IndexedBoolCertificate := "
            f"{{ ranges := [{span_rows}] }}\n\n"
        )

    def lean_span_list(
        spans: list[tuple[int, int, list[tuple[str, int, int]]]],
    ) -> str:
        return "[" + ", ".join(
            f"{{ start := {start}, size := {size} }}"
            for start, size, _chunks in spans
        ) + "]"

    def launch_range_leaf(
        theorem: str, start: int, size: int
    ) -> dict[str, Any]:
        module = launch_leaf_module_by_theorem.get(theorem)
        if module is None:
            raise StageAInputError(
                f"launch proof leaf {theorem} has no generated module"
            )
        return {
            "module": module,
            "theorem": theorem,
            "start": start,
            "size": size,
        }

    def write_contiguous_launch_aggregation(
        *,
        module_prefix: str,
        theorem_prefix: str,
        predicate: str,
        chunks: list[tuple[str, int, int]],
        expected_start: int,
        expected_size: int,
    ) -> dict[str, Any]:
        if not chunks:
            raise StageAInputError("mapped launch span cannot be empty")
        nodes = [
            launch_range_leaf(theorem, start, size)
            for theorem, start, size in chunks
        ]
        cursor = expected_start
        for node in nodes:
            if int(node["start"]) != cursor or int(node["size"]) <= 0:
                raise StageAInputError(
                    "mapped launch proof chunks are not an exact contiguous span"
                )
            cursor += int(node["size"])
        if cursor != expected_start + expected_size:
            raise StageAInputError(
                "mapped launch proof chunks do not cover the expected span"
            )

        level = 0
        while len(nodes) > 1:
            next_nodes: list[dict[str, Any]] = []
            for group_offset in range(0, len(nodes), launch_aggregation_fanout):
                group = nodes[
                    group_offset : group_offset + launch_aggregation_fanout
                ]
                if len(group) == 1:
                    next_nodes.append(group[0])
                    continue
                node_index = group_offset // launch_aggregation_fanout
                module = f"{module_prefix}Level{level}Node{node_index}"
                imports = "\n".join(
                    f"import StageA.{name}"
                    for name in dict.fromkeys([
                        "RelationalLaunchProofAggregation",
                        *(str(child["module"]) for child in group),
                    ])
                )
                definitions: list[str] = []
                current = group[0]
                for merge_index, right in enumerate(group[1:], 1):
                    start = int(current["start"])
                    size = int(current["size"])
                    right_start = int(right["start"])
                    right_size = int(right["size"])
                    if right_start != start + size or right_size <= 0:
                        raise StageAInputError(
                            "mapped launch proof chunks are not adjacent"
                        )
                    theorem = (
                        f"{theorem_prefix}Level{level}Node{node_index}"
                        f"Step{merge_index}Checked"
                    )
                    definitions.append(
                        f"theorem {theorem} :\n"
                        f"    IndexedBoolRangeHolds {predicate} "
                        f"{{ start := {start}, size := {size + right_size} }} :=\n"
                        f"  indexedBoolRangeHolds_append {predicate}\n"
                        f"    {{ start := {start}, size := {size} }}\n"
                        f"    {{ start := {right_start}, size := {right_size} }}\n"
                        f"    (by decide) {current['theorem']} {right['theorem']}"
                    )
                    current = {
                        "module": module,
                        "theorem": theorem,
                        "start": start,
                        "size": size + right_size,
                    }
                source = (
                    imports
                    + "\n\nnamespace StageA.GeneratedRelational\n\n"
                    "open StageA.Formal StageA.Relational\n\n"
                    "set_option maxRecDepth 1000000\n"
                    "set_option maxHeartbeats 0\n\n"
                    + "\n\n".join(definitions)
                    + "\n\nend StageA.GeneratedRelational\n"
                )
                _write_text_if_changed(stage_a / f"{module}.lean", source)
                next_nodes.append(current)
            nodes = next_nodes
            level += 1
        return nodes[0]

    def write_launch_range_list_aggregation(
        *,
        module_prefix: str,
        theorem_prefix: str,
        predicate: str,
        nodes: list[dict[str, Any]],
    ) -> dict[str, str]:
        if not nodes:
            return {
                "module": "RelationalLaunchProofAggregation",
                "ranges": "[]",
                "proof": "True.intro",
            }
        level = 0
        while len(nodes) > 1:
            next_nodes: list[dict[str, Any]] = []
            for group_offset in range(0, len(nodes), launch_aggregation_fanout):
                group = nodes[
                    group_offset : group_offset + launch_aggregation_fanout
                ]
                if len(group) == 1:
                    next_nodes.append(group[0])
                    continue
                node_index = group_offset // launch_aggregation_fanout
                module = f"{module_prefix}Level{level}Node{node_index}"
                imports = "\n".join(
                    f"import StageA.{name}"
                    for name in dict.fromkeys([
                        "RelationalLaunchProofAggregation",
                        *(str(child["module"]) for child in group),
                    ])
                )
                definitions: list[str] = []
                current = group[0]
                for merge_index, right in enumerate(group[1:], 1):
                    name = (
                        f"{theorem_prefix}Level{level}Node{node_index}"
                        f"Step{merge_index}"
                    )
                    ranges = f"{name}Ranges"
                    proof = f"{name}Checked"
                    definitions.extend([
                        f"def {ranges} : List Span :=\n"
                        f"  {current['ranges']} ++ {right['ranges']}",
                        f"theorem {proof} :\n"
                        f"    AllIndexedBoolRangesHold {predicate} {ranges} := by\n"
                        f"  exact launchAllIndexedBoolRangesHold_append {predicate}\n"
                        f"    {current['ranges']} {right['ranges']}\n"
                        f"    ({current['proof']}) ({right['proof']})",
                    ])
                    current = {
                        "module": module,
                        "ranges": ranges,
                        "proof": proof,
                    }
                source = (
                    imports
                    + "\n\nnamespace StageA.GeneratedRelational\n\n"
                    "open StageA.Formal StageA.Relational\n\n"
                    "set_option maxRecDepth 1000000\n"
                    "set_option maxHeartbeats 0\n\n"
                    + "\n\n".join(definitions)
                    + "\n\nend StageA.GeneratedRelational\n"
                )
                _write_text_if_changed(stage_a / f"{module}.lean", source)
                next_nodes.append(current)
            nodes = next_nodes
            level += 1
        root = nodes[0]
        return {
            "module": str(root["module"]),
            "ranges": str(root["ranges"]),
            "proof": str(root["proof"]),
        }

    candidate_span_nodes: list[dict[str, Any]] = []
    for span_index, (span_start, span_size, chunks) in enumerate(
        candidate_image_spans
    ):
        span_root = write_contiguous_launch_aggregation(
            module_prefix=(
                f"RelationalLaunchCandidateImageSpan{span_index}Aggregate"
            ),
            theorem_prefix=(
                f"consoleLaunchCandidateImageSpan{span_index}Aggregate"
            ),
            predicate="consoleLaunchCandidateImageCompatibilityAt",
            chunks=chunks,
            expected_start=span_start,
            expected_size=span_size,
        )
        candidate_span_nodes.append({
            "module": span_root["module"],
            "ranges": f"[{{ start := {span_start}, size := {span_size} }}]",
            "proof": f"⟨{span_root['theorem']}, True.intro⟩",
        })
    candidate_image_range_root = write_launch_range_list_aggregation(
        module_prefix="RelationalLaunchCandidateImageAggregate",
        theorem_prefix="consoleLaunchCandidateImageAggregate",
        predicate="consoleLaunchCandidateImageCompatibilityAt",
        nodes=candidate_span_nodes,
    )
    stack_range_root = write_launch_range_list_aggregation(
        module_prefix="RelationalLaunchStackMemoryAggregate",
        theorem_prefix="consoleLaunchStackMemoryAggregate",
        predicate="consoleLaunchStackMemoryAt",
        nodes=[{
            "module": launch_range_leaf(theorem, start, size)["module"],
            "ranges": f"[{{ start := {start}, size := {size} }}]",
            "proof": f"⟨{theorem}, True.intro⟩",
        } for theorem, start, size in stack_ranges],
    )
    static_word_slot_range_root = write_launch_range_list_aggregation(
        module_prefix="RelationalLaunchStaticWordSlotAggregate",
        theorem_prefix="consoleLaunchStaticWordSlotAggregate",
        predicate="consoleLaunchStaticWordSlotAt",
        nodes=[{
            "module": launch_range_leaf(theorem, start, size)["module"],
            "ranges": f"[{{ start := {start}, size := {size} }}]",
            "proof": f"⟨{theorem}, True.intro⟩",
        } for theorem, start, size in static_word_slot_ranges],
    )
    launch_check_imports = "\n".join(
        f"import StageA.{module}"
        for module in dict.fromkeys([
            str(candidate_image_range_root["module"]),
            str(stack_range_root["module"]),
            str(static_word_slot_range_root["module"]),
        ])
    )

    launch_checks_source = (
        launch_check_imports
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        + launch_certificate("consoleLaunchStackCertificate", stack_ranges)
        + launch_certificate(
            "consoleLaunchStaticWordSlotCertificate", static_word_slot_ranges
        )
        + "theorem consoleLaunchOriginalImageMapped :\n"
        "    PreferredBaseImageMemory staticProofContext.originalPe\n"
        "      staticProofContext.originalImports consoleLaunchOriginalState.memory := by\n"
        "  have loaderMapped := loaderPopulatedPreferredBaseMemory_maps_image\n"
        "    false staticProofContext consoleLaunchWorld (by decide)\n"
        "    (by decide) (by decide)\n"
        "  have stackMapped := preferredBaseImageMemory_after_stack_range_writes\n"
        "    staticProofContext.originalPe staticProofContext.originalImports\n"
        "    (loaderPopulatedPreferredBaseMemory false staticProofContext\n"
        "      consoleLaunchWorld) consoleLaunchStackRange.originalBase\n"
        "    consoleLaunchStackRange.size consoleLaunchOriginalStackWrites\n"
        "    (by decide) (by decide) (by decide) (by decide) loaderMapped\n"
        "  simpa [consoleLaunchOriginalState, consoleLaunchOriginalMemory,\n"
        "    consoleLaunchOriginalWrites] using stackMapped\n\n"
        "theorem consoleLaunchCandidateExcludedImageMapped :\n"
        "    PreferredBaseImageMemory staticProofContext.candidatePe\n"
        "      staticProofContext.candidateImports\n"
        "      consoleLaunchCandidateExcludedMemory := by\n"
        "  have loaderMapped := loaderPopulatedPreferredBaseMemory_maps_image\n"
        "    true staticProofContext consoleLaunchWorld (by decide)\n"
        "    (by decide) (by decide)\n"
        "  have stackMapped := preferredBaseImageMemory_after_stack_range_writes\n"
        "    staticProofContext.candidatePe staticProofContext.candidateImports\n"
        "    (loaderPopulatedPreferredBaseMemory true staticProofContext\n"
        "      consoleLaunchWorld) consoleLaunchStackRange.candidateBase\n"
        "    consoleLaunchStackRange.size consoleLaunchCandidateStackWrites\n"
        "    (by decide) (by decide) (by decide) (by decide) loaderMapped\n"
        "  simpa [consoleLaunchCandidateExcludedMemory, consoleLaunchCandidateWrites]\n"
        "    using stackMapped\n\n"
        "theorem consoleLaunchCandidateImageMapped :\n"
        "    PreferredBaseImageMemory staticProofContext.candidatePe\n"
        "      staticProofContext.candidateImports consoleLaunchCandidateState.memory := by\n"
        "  change PreferredBaseImageMemory staticProofContext.candidatePe\n"
        "    staticProofContext.candidateImports\n"
        "    (ordinaryMemoryCandidateProjection staticProofContext consoleLaunchWorld\n"
        "      (staticProofContext.relationalValueTargets consoleLaunchWorld)\n"
        "      consoleLaunchOriginalMemory consoleLaunchCandidateExcludedMemory)\n"
        "  apply preferredBaseImageMemory_projection_of_compatible_ranges\n"
        "  · decide\n"
        "  · decide\n"
        "  · decide\n"
        "  · decide\n"
        "  · decide\n"
        "  · exact consoleLaunchOriginalImageMapped\n"
        "  · exact consoleLaunchCandidateExcludedImageMapped\n"
        "  have rangesHold : AllIndexedBoolRangesHold\n"
        "      consoleLaunchCandidateImageCompatibilityAt\n"
        "      (mappedImageSpans staticProofContext.candidatePe) := by\n"
        "    change AllIndexedBoolRangesHold "
        "consoleLaunchCandidateImageCompatibilityAt "
        + lean_span_list(candidate_image_spans) + "\n"
        f"    exact {candidate_image_range_root['proof']}\n"
        "  simpa [consoleLaunchCandidateImageCompatibilityAt] using rangesHold\n\n"
        "theorem consoleLaunchOriginalImmutableImage :\n"
        "    ImmutableImageWordMemory staticProofContext.originalPe\n"
        "      consoleLaunchOriginalState.memory := by\n"
        "  exact preferredBaseImageMemory_implies_immutable\n"
        "    staticProofContext.originalPe staticProofContext.originalImports\n"
        "    consoleLaunchOriginalState.memory (by decide)\n"
        "    consoleLaunchOriginalImageMapped (by decide)\n\n"
        "theorem consoleLaunchCandidateImmutableImage :\n"
        "    ImmutableImageWordMemory staticProofContext.candidatePe\n"
        "      consoleLaunchCandidateState.memory := by\n"
        "  exact preferredBaseImageMemory_implies_immutable\n"
        "    staticProofContext.candidatePe staticProofContext.candidateImports\n"
        "    consoleLaunchCandidateState.memory (by decide)\n"
        "    consoleLaunchCandidateImageMapped (by decide)\n\n"
        "theorem consoleLaunchStackMemoryRelated :\n"
        "    StackRangesMemoryHold staticProofContext consoleLaunchWorld\n"
        "      consoleLaunchOriginalState.memory consoleLaunchCandidateState.memory := by\n"
        "  apply stackRangesMemoryHold_of_single_range_indexed_holds staticProofContext\n"
        "    consoleLaunchWorld consoleLaunchOriginalState.memory\n"
        "    consoleLaunchCandidateState.memory consoleLaunchStackRange\n"
        "  · rfl\n"
        "  · have rangesHold : AllIndexedBoolRangesHold consoleLaunchStackMemoryAt\n"
        "        consoleLaunchStackCertificate.ranges := by\n"
        f"      exact {stack_range_root['proof']}\n"
        "    have checked := IndexedBoolCertificate.holds_of_ranges\n"
        "      consoleLaunchStackMemoryAt consoleLaunchStackRange.size\n"
        "      consoleLaunchStackCertificate (by decide) rangesHold\n"
        "    simpa [consoleLaunchStackMemoryAt] using checked\n\n"
        "theorem consoleLaunchStaticWordSlotsRelated :\n"
        "    StaticWordRelationSlotsMemoryHold staticProofContext consoleLaunchWorld\n"
        "      consoleLaunchOriginalState.memory consoleLaunchCandidateState.memory := by\n"
        "  apply staticWordRelationSlotsMemoryHold_of_indexed_holds\n"
        "    staticProofContext consoleLaunchWorld consoleLaunchOriginalState.memory\n"
        "    consoleLaunchCandidateState.memory consoleLaunchStaticWordSlotCertificate\n"
        "  have rangesHold : AllIndexedBoolRangesHold consoleLaunchStaticWordSlotAt\n"
        "      consoleLaunchStaticWordSlotCertificate.ranges := by\n"
        f"    exact {static_word_slot_range_root['proof']}\n"
        "  have checked := IndexedBoolCertificate.holds_of_ranges\n"
        "    consoleLaunchStaticWordSlotAt staticProofContext.staticWordRelationSlots.length\n"
        "    consoleLaunchStaticWordSlotCertificate (by decide) rangesHold\n"
        "  simpa [consoleLaunchStaticWordSlotAt] using checked\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalLaunchCheckCertificate.lean", launch_checks_source
    )

    linked_launch_realizability_source = ""
    if linked_acceptance_ready:
        linked_launch_realizability_source = (
            "theorem consoleLaunchLinkedRealizable :\n"
            "    consoleLaunch.LinkedRealizable staticProofContext relationalProductGraph\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile := by\n"
            "  refine ⟨consoleLaunchWorld, consoleLaunchOriginalState,\n"
            "    consoleLaunchCandidateState, consoleLaunchFrames, [],\n"
            "    consoleLaunchWorldValid, consoleLaunchOriginalImageMapped,\n"
            "    consoleLaunchCandidateImageMapped, ?_, ?_, ?_, ?_, ?_,\n"
            "    consoleLaunchStateRelated⟩\n"
            "  · simp [consoleLaunch, consoleLaunchFrames,\n"
            "    consoleLaunchOriginalState, consoleLaunchCandidateState,\n"
            "    consoleLaunchOriginalMemory, consoleLaunchCandidateMemory,\n"
            "    consoleLaunchCandidateExcludedMemory, consoleLaunchOriginalWrites,\n"
            "    consoleLaunchCandidateWrites, RelationalLinkedRuntimeCallStackHolds,\n"
            "    PE32ConsoleLaunchV2.continuationTargetIds] <;> decide\n"
            "  · exact LinkedProductControlProfile.LinksAllowed.nil\n"
            "      linkedProductControlProfile linkedProductControlProfileChecked\n"
            "  · simp [consoleLaunch, RelationalLinkedRuntimeCallFactsHold]\n"
            "  · exact RelationalRuntimeCallTargetsMapped.of_checked\n"
            "      relationalProductGraph relationalProductReachabilityEvidence\n"
            "      [] consoleLaunch.continuationTargetIds (by decide)\n"
            "  · simp [consoleLaunch, consoleLaunchFrames,\n"
            "    consoleLaunchOriginalState, consoleLaunchCandidateState,\n"
            "    consoleLaunchOriginalMemory, consoleLaunchCandidateMemory,\n"
            "    consoleLaunchCandidateExcludedMemory, consoleLaunchOriginalWrites,\n"
            "    consoleLaunchCandidateWrites, PE32TlsProcessAttachArgumentsHold] <;> decide\n\n"
        )
    launch_realizability_source = (
        "import StageA.RelationalLaunchCheckCertificate\n"
        "import StageA.RelationalProductGraphContext\n"
        "import StageA.RelationalLinkedExecution\n"
        "import StageA.RelationalLinkedControlProfile\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        "theorem consoleLaunchStateRelated :\n"
        "    StateRel staticProofContext consoleLaunchWorld consoleLaunch.rootInvariant\n"
        "      consoleLaunchOriginalState consoleLaunchCandidateState := by\n"
        "  refine ⟨consoleLaunchWorldValid.1, by decide, ?_, by decide, by decide,\n"
        "    ?_, ?_, ?_, ?_, ?_⟩\n"
        "  · exact consoleLaunchStackMemoryRelated\n"
        "  · apply importAddressesMemoryHold_of_checked\n"
        "    decide\n"
        "  · exact consoleLaunchOriginalImmutableImage\n"
        "  · exact consoleLaunchCandidateImmutableImage\n"
        "  · refine ⟨by decide, by decide, by decide, by decide, ?_, ?_, rfl, ?_,\n"
        "      by decide, rfl⟩\n"
        "    · exact ordinaryMemoryRelated_projection_of_mapped_identity\n"
        "        staticProofContext consoleLaunchWorld\n"
        "        staticProofContext.codeMap.entries.toList\n"
        "        (staticProofContext.relationalValueTargets consoleLaunchWorld)\n"
        "        consoleLaunchOriginalMemory consoleLaunchCandidateExcludedMemory\n"
        "        (by decide)\n"
        "    · refine { staticPointerSlots := ?_, staticWordSlots := ?_, active := ?_ }\n"
        "      · intro slot member\n"
        "        simp [staticProofContext] at member\n"
        "      · exact consoleLaunchStaticWordSlotsRelated\n"
        "      · exact { registerRanges := by decide, stackRanges := by decide }\n"
        "    · simp [MachineX87Related, consoleLaunchOriginalState,\n"
        "        consoleLaunchCandidateState, StageA.Relational.X87.StateRelated,\n"
        "        StageA.Relational.X87.MetadataRelated, StageA.X87.PhysicalState.core,\n"
        "        StageA.X87.PhysicalState.metadata, x87AddressRelation]\n"
        "  · decide\n\n"
        "theorem consoleLaunchRealizable :\n"
        "    consoleLaunch.Realizable staticProofContext relationalProductGraph\n"
        "      relationalProductReachabilityEvidence := by\n"
        "  refine ⟨consoleLaunchWorld, consoleLaunchOriginalState,\n"
        "    consoleLaunchCandidateState, consoleLaunchFrames,\n"
        "    consoleLaunchWorldValid, consoleLaunchOriginalImageMapped,\n"
        "    consoleLaunchCandidateImageMapped, ?_, ?_, ?_, ?_,\n"
        "    consoleLaunchStateRelated⟩\n"
        "  · simp [consoleLaunch, consoleLaunchFrames,\n"
        "    consoleLaunchOriginalState, consoleLaunchCandidateState,\n"
        "    consoleLaunchOriginalMemory, consoleLaunchCandidateMemory,\n"
        "    consoleLaunchCandidateExcludedMemory, consoleLaunchOriginalWrites,\n"
        "    consoleLaunchCandidateWrites, RelationalRuntimeCallStackHolds,\n"
        "    RelationalRuntimeCallFrame.memoryHolds,\n"
        "    ReturnSlotOffsetInventory.holds,\n"
        "    ReturnSlotOffsetInventory.exactWordsHold,\n"
        "    ReturnSlotExactWordPair.holds, ReturnSlotOffsetPair.holds,\n"
        "    PE32ConsoleLaunchV2.continuationTargetIds] <;> decide\n"
        "  · simp [consoleLaunch, consoleLaunchOriginalState,\n"
        "    consoleLaunchCandidateState,\n"
        "    RelationalRuntimeCallFactsHold, RelationalRuntimeCallImportsHold,\n"
        "    RelationalRuntimeCallRelationsHold] <;> decide\n"
        "  · exact RelationalRuntimeCallTargetsMapped.of_checked\n"
        "      relationalProductGraph relationalProductReachabilityEvidence\n"
        "      ["
        + ", ".join(str(node_id) for node_id in launch_continuation_node_ids)
        + "] consoleLaunch.continuationTargetIds (by decide)\n"
        "  · simp [consoleLaunch, consoleLaunchFrames,\n"
        "    consoleLaunchOriginalState, consoleLaunchCandidateState,\n"
        "    consoleLaunchOriginalMemory, consoleLaunchCandidateMemory,\n"
        "    consoleLaunchCandidateExcludedMemory, consoleLaunchOriginalWrites,\n"
        "    consoleLaunchCandidateWrites,\n"
        "    PE32TlsProcessAttachArgumentsHold] <;> decide\n\n"
        + linked_launch_realizability_source
        + "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalLaunchRealizabilityCertificate.lean",
        launch_realizability_source,
    )

    if not acceptance_ready:
        return plan

    decode_chunk_by_region = {
        region_index: chunk_index
        for chunk_index, region_indices in enumerate(decode_chunk_regions)
        for region_index in region_indices
    }
    chunk_size = max(
        1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_ACCEPTANCE_CHUNK", "1"))
    )
    region_chunks: list[dict[str, str]] = []
    for chunk_index, offset in enumerate(range(0, len(nodes), chunk_size)):
        selected_node_ids = list(range(offset, min(offset + chunk_size, len(nodes))))
        module = f"RelationalAcceptanceRegionChunk{chunk_index}"
        ids_name = f"acceptanceRegionNodeChunk{chunk_index}Ids"
        definitions: list[str] = []
        region_theorems: list[str] = []
        for node_id in selected_node_ids:
            node = nodes[node_id]
            target_id = int(node["target_id"])
            region_index = int(contract["regions"][node_id]["numeric_id"])
            region_match = f"acceptanceRegionNode{node_id}Matches"
            region_theorems.append(region_match)
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
        definitions.extend([
            f"def {ids_name} : List Nat := "
            f"[{', '.join(map(str, selected_node_ids))}]",
            (
                f"theorem acceptanceRegionChunk{chunk_index}Checked :\n"
                "    AllListedRegionsMatchProductGraph staticProofContext\n"
                f"      relationalProductGraph allRegions {ids_name} := by\n"
                f"  exact {_lean_all_listed_proof(region_theorems)}"
            ),
        ])
        source = (
            "import StageA.RelationalAcceptanceContext\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(stage_a / f"{module}.lean", source)
        region_chunks.append({
            "module": module,
            "ids": ids_name,
            "regions": f"acceptanceRegionChunk{chunk_index}Checked",
        })

    chunks: list[dict[str, str]] = []
    steps = plan["node_steps"]
    for chunk_index, offset in enumerate(range(0, len(steps), chunk_size)):
        selected = steps[offset : offset + chunk_size]
        module = f"RelationalAcceptanceChunk{chunk_index}"
        ids_name = f"acceptanceNodeChunk{chunk_index}Ids"
        edge_ids_name = f"acceptanceEdgeChunk{chunk_index}Ids"
        definitions: list[str] = []
        running_theorems: list[str] = []
        linked_running_theorems: list[str] = []
        edge_theorems: list[str] = []
        for step in selected:
            node_id = int(step["node_id"])
            region_index = int(step["region_index"])
            target_id = int(step["target_id"])
            decode_chunk = decode_chunk_by_region[region_index]
            uses_deferred_guard = _step_uses_deferred_guard(step)
            running = f"acceptanceRunningNode{node_id}Refined"
            if not uses_deferred_guard:
                running_theorems.append(
                    f"{running} originalEnvironment candidateEnvironment "
                    + (
                        "originalProtocolEnvironment candidateProtocolEnvironment "
                        if parameterized_protocol_environment else ""
                    )
                    + "environmentRefines"
                    if parameterized_environment else running
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
                protocol_environment_name = f"{side}ProtocolEnvironment"
                world_program = (
                    f"({side}WorldProgram {environment_name}"
                    + (
                        f" {protocol_environment_name}"
                        if parameterized_protocol_environment else ""
                    )
                    + ")"
                    if parameterized_environment else f"{side}WorldProgram"
                )
                world_behavior_binder = (
                    f" ({environment_name} : WorldExternalEnvironment)"
                    + (
                        f" ({protocol_environment_name} : "
                        "WorldExternalProtocolEnvironment)"
                        if parameterized_protocol_environment else ""
                    )
                    if parameterized_environment else ""
                )
                if step.get("certificate_profile") == (
                    "composable_x87_state_only_singleton_v1"
                ):
                    definitions.append(
                        f"theorem {side}WorldBehaviorNode{node_id}"
                        f"{world_behavior_binder} (state : MachineState) :\n"
                        f"    decodedWorldRegionBehavior {world_program} "
                        f"{target_id} state =\n"
                        "      StageA.Relational.X87.executeSingletonCommand "
                        f"{side_bool} staticProofContext.{side}Pe "
                        f"segmentRefinementEdge{int(step['edges'][0]['edge_id'])}Spec.{side}Span "
                        f"region{region_index}.targets state := by\n"
                        f"  have regionFound : regionById allRegions {target_id} = "
                        f"some region{region_index} := by decide\n"
                        f"  unfold decodedWorldRegionBehavior {side}WorldProgram\n"
                        "  rw [regionFound]\n"
                        "  simp only [Bool.false_eq_true, if_false, if_true]\n"
                        "  rfl"
                    )
                    continue
                if _has_compositional_normalized_support(
                    contract["regions"][region_index], behaviors[region_index]
                ):
                    definitions.append(
                        f"abbrev {normalized_name} : NormalizedSymbolicBehavior :=\n"
                        f"  region{region_index}NormalizedBehavior\n\n"
                        f"theorem {normalized_checked} : normalizeSymbolicBehavior {side_bool}\n"
                        f"    region{region_index}.targets {side}Behavior{region_index} =\n"
                        f"      some {normalized_name} := by\n"
                        f"  simpa only [{normalized_name}] using "
                        f"region{region_index}{side_title}Normalized\n\n"
                        f"theorem {normalized_writes} : {normalized_name}.writes =\n"
                        f"    {side}Behavior{region_index}.writes := by\n"
                        f"  simpa only [{normalized_name}] using "
                        f"region{region_index}{side_title}NormalizedWrites\n\n"
                        f"theorem {normalized_registers} : {normalized_name}.registers =\n"
                        f"    {side}Behavior{region_index}.registers := by\n"
                        f"  simpa only [{normalized_name}] using "
                        f"region{region_index}{side_title}NormalizedRegisters\n\n"
                        f"theorem {normalized_outcome} : {normalized_name}.outcome =\n"
                        f"    {_lean_acceptance_outcome(behaviors[region_index][side + '_ir']['outcome'])} "
                        ":= by\n"
                        f"  simpa only [{normalized_name}] using "
                        f"region{region_index}NormalizedOutcome"
                    )
                else:
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
                    f"  change evalBehavior {side_bool} region{region_index}.targets state "
                    f"{side}Behavior{region_index} = some ({normalized_name}.eval state)\n"
                    f"  exact evalBehavior_of_normalized {side_bool} "
                    f"region{region_index}.targets state {side}Behavior{region_index} "
                    f"{normalized_name} {normalized_checked}"
                )
            native_case = linked_native_cases_by_node.get(node_id)
            linked_termination_reuses_ordinary_node = bool(
                linked_acceptance_ready
                and linked_acceptance_mode == "native-linked-call-return-v1"
                and native_case is not None
                and native_case[0] == "empty_terminate"
            )
            if (
                ordinary_acceptance_ready or linked_termination_reuses_ordinary_node
            ) and not uses_deferred_guard:
                definitions.append(_lean_acceptance_running_node(
                    step, contract["regions"], behaviors,
                    parameterized_environment=parameterized_environment,
                    parameterized_protocol_environment=
                        parameterized_protocol_environment,
                ))
            if linked_acceptance_ready:
                linked_running = f"acceptanceLinkedRunningNode{node_id}Refined"
                linked_running_theorems.append(
                    f"{linked_running} originalEnvironment candidateEnvironment "
                    + (
                        "originalProtocolEnvironment candidateProtocolEnvironment "
                        if parameterized_protocol_environment else ""
                    )
                    + "environmentRefines"
                    if parameterized_environment else linked_running
                )
                if linked_acceptance_mode == "native-linked-call-return-v1":
                    if native_case is None:
                        raise StageAInputError(
                            f"linked native node {node_id} lost its proof family"
                        )
                    family, payload = native_case
                    if family == "direct_call":
                        assert payload is not None
                        definitions.append(_lean_acceptance_linked_direct_call_node(
                            step, payload
                        ))
                    elif family == "return":
                        assert payload is not None
                        definitions.append(_lean_acceptance_linked_return_node(
                            step, payload
                        ))
                    elif family == "active_jump":
                        assert payload is not None
                        definitions.append(_lean_acceptance_linked_active_jump_node(
                            step, payload
                        ))
                    elif family == "active_branch":
                        assert payload is not None
                        definitions.append(
                            _lean_acceptance_linked_active_branch_node(
                                step, payload, contract["regions"], behaviors
                            )
                        )
                    elif family == "empty_jump":
                        definitions.append(_lean_acceptance_linked_empty_jump_node(
                            step,
                            parameterized_environment=parameterized_environment,
                            parameterized_protocol_environment=
                                parameterized_protocol_environment,
                        ))
                    elif family == "empty_terminate":
                        definitions.append(
                            _lean_acceptance_linked_empty_terminate_node(step)
                        )
                    else:
                        raise StageAInputError(
                            f"unknown linked native node family {family!r}"
                        )
                elif linked_acceptance_mode == (
                    "lean-checked-shallow-profile-compatibility-v1"
                ):
                    definitions.append(_lean_acceptance_linked_shallow_node(
                        step,
                        parameterized_environment=parameterized_environment,
                        parameterized_protocol_environment=
                            parameterized_protocol_environment,
                    ))
                elif linked_acceptance_mode == (
                    "lean-checked-shallow-with-native-frame-guards-v1"
                ):
                    if native_case is not None and native_case[0] == "active_branch":
                        assert native_case[1] is not None
                        definitions.append(_lean_acceptance_linked_active_branch_node(
                            step, native_case[1], contract["regions"], behaviors,
                            parameterized_environment=parameterized_environment,
                            parameterized_protocol_environment=
                                parameterized_protocol_environment,
                        ))
                    else:
                        definitions.append(_lean_acceptance_linked_shallow_node(
                            step,
                            parameterized_environment=parameterized_environment,
                            parameterized_protocol_environment=
                                parameterized_protocol_environment,
                        ))
                elif native_case is not None and native_case[0] == "active_jump":
                    assert native_case[1] is not None
                    definitions.append(_lean_acceptance_linked_active_jump_node(
                        step, native_case[1]
                    ))
                elif native_case is not None and native_case[0] == "active_branch":
                    assert native_case[1] is not None
                    definitions.append(_lean_acceptance_linked_active_branch_node(
                        step, native_case[1], contract["regions"], behaviors,
                        parameterized_environment=parameterized_environment,
                        parameterized_protocol_environment=
                            parameterized_protocol_environment,
                    ))
                elif _linked_empty_jump_supported(step):
                    definitions.append(_lean_acceptance_linked_empty_jump_node(
                        step,
                        parameterized_environment=parameterized_environment,
                        parameterized_protocol_environment=
                            parameterized_protocol_environment,
                    ))
                else:
                    definitions.append(_lean_acceptance_linked_shallow_node(
                        step,
                        parameterized_environment=parameterized_environment,
                        parameterized_protocol_environment=
                            parameterized_protocol_environment,
                    ))
            if "callback_profile_index" in step:
                definitions.append(_lean_acceptance_callback_return_node(
                    step,
                    parameterized_environment=parameterized_environment,
                    parameterized_protocol_environment=parameterized_protocol_environment,
                ))
            if ordinary_acceptance_ready and not uses_deferred_guard:
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
        edge_ids.sort()
        ordinary_edge_ids = [
            int(edge["edge_id"])
            for step in selected
            if not _step_uses_deferred_guard(step)
            for edge in step["edges"]
        ]
        ordinary_edge_ids.sort()
        edge_theorems = [
            f"acceptanceExecutionEdge{edge_id}Refined"
            for edge_id in ordinary_edge_ids
        ]
        definitions.extend([
            f"def {ids_name} : List Nat := [{', '.join(map(str, node_ids))}]",
            f"def {edge_ids_name} : List Nat := [{', '.join(map(str, edge_ids))}]",
        ])
        if ordinary_acceptance_ready:
            definitions.extend([
                (
                f"theorem acceptanceRunningChunk{chunk_index}Checked"
                + (
                    " (originalEnvironment candidateEnvironment : "
                    "WorldExternalEnvironment)\n"
                    + (
                        "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                        "WorldExternalProtocolEnvironment)\n"
                        if parameterized_protocol_environment else ""
                    )
                    + "    (environmentRefines : ExternalEnvironmentRefines "
                    "staticProofContext externalCallSites\n"
                    "      originalEnvironment candidateEnvironment)"
                    if parameterized_environment else ""
                )
                + " :\n"
                "    AllListedRunningProductNodesRefined staticProofContext\n"
                "      relationalProductGraph productInvariantTable\n"
                "      relationalProductReachabilityEvidence productControlProfile\n"
                "      protocolCallbackTargets\n"
                + (
                    "      (originalWorldProgram originalEnvironment"
                    + (
                        " originalProtocolEnvironment"
                        if parameterized_protocol_environment else ""
                    )
                    + ")\n"
                    + "      (candidateWorldProgram candidateEnvironment"
                    + (
                        " candidateProtocolEnvironment"
                        if parameterized_protocol_environment else ""
                    )
                    + ") "
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
        if linked_acceptance_ready:
            definitions.append(
                f"theorem acceptanceLinkedRunningChunk{chunk_index}Checked"
                + (
                    " (originalEnvironment candidateEnvironment : "
                    "WorldExternalEnvironment)\n"
                    + (
                        "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                        "WorldExternalProtocolEnvironment)\n"
                        if parameterized_protocol_environment else ""
                    )
                    + "    (environmentRefines : ExternalEnvironmentRefines "
                    "staticProofContext externalCallSites\n"
                    "      originalEnvironment candidateEnvironment)"
                    if parameterized_environment else ""
                )
                + " :\n"
                "    AllListedLinkedRunningProductNodesRefined staticProofContext\n"
                "      relationalProductGraph productInvariantTable\n"
                "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
                "      protocolCallbackTargets\n"
                + (
                    "      (originalWorldProgram originalEnvironment"
                    + (
                        " originalProtocolEnvironment"
                        if parameterized_protocol_environment else ""
                    )
                    + ")\n"
                    + "      (candidateWorldProgram candidateEnvironment"
                    + (
                        " candidateProtocolEnvironment"
                        if parameterized_protocol_environment else ""
                    )
                    + ") "
                    if parameterized_environment else
                    "      originalWorldProgram\n"
                    "      candidateWorldProgram "
                )
                + f"{ids_name} := by\n"
                f"  exact {_lean_all_listed_proof(linked_running_theorems)}"
            )
        source = (
            "import StageA.RelationalAcceptanceContext\n"
            + _acceptance_segment_imports(selected, segment_module_by_edge)
            + "\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n"
            "set_option linter.constructorNameAsVariable false\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(stage_a / f"{module}.lean", source)
        chunks.append({
            "module": module,
            "ids": ids_name,
            "edge_ids": edge_ids_name,
            "running": (
                f"acceptanceRunningChunk{chunk_index}Checked originalEnvironment "
                "candidateEnvironment "
                + (
                    "originalProtocolEnvironment candidateProtocolEnvironment "
                    if parameterized_protocol_environment else ""
                )
                + "environmentRefines"
                if parameterized_environment else
                f"acceptanceRunningChunk{chunk_index}Checked"
            ),
            "linked_running": (
                f"acceptanceLinkedRunningChunk{chunk_index}Checked "
                "originalEnvironment candidateEnvironment "
                + (
                    "originalProtocolEnvironment candidateProtocolEnvironment "
                    if parameterized_protocol_environment else ""
                )
                + "environmentRefines"
                if linked_acceptance_ready and parameterized_environment else
                f"acceptanceLinkedRunningChunk{chunk_index}Checked"
                if linked_acceptance_ready else ""
            ),
            "edges": f"acceptanceExecutionEdgeChunk{chunk_index}Checked",
        })

    node_ids_expr = _lean_appended_list([chunk["ids"] for chunk in chunks])
    edge_ids_expr = _lean_appended_list([chunk["edge_ids"] for chunk in chunks])
    region_node_ids_expr = _lean_appended_list(
        [chunk["ids"] for chunk in region_chunks]
    )
    region_proof = _lean_appended_proof(
        region_chunks, "allListedRegionsMatchProductGraph_append",
        "staticProofContext relationalProductGraph allRegions", "regions",
    )
    acceptance_original_program = (
        "(originalWorldProgram originalEnvironment"
        + (" originalProtocolEnvironment" if parameterized_protocol_environment else "")
        + ")"
        if parameterized_environment else "originalWorldProgram"
    )
    acceptance_candidate_program = (
        "(candidateWorldProgram candidateEnvironment"
        + (" candidateProtocolEnvironment" if parameterized_protocol_environment else "")
        + ")"
        if parameterized_environment else "candidateWorldProgram"
    )
    running_proof = ""
    if ordinary_acceptance_ready:
        running_proof = _lean_appended_proof(
            chunks, "allListedRunningProductNodesRefined_append",
            "staticProofContext relationalProductGraph productInvariantTable "
            "relationalProductReachabilityEvidence productControlProfile "
            "protocolCallbackTargets "
            f"{acceptance_original_program} {acceptance_candidate_program}",
            "running",
        )
    linked_running_proof = ""
    if linked_acceptance_ready:
        linked_running_proof = _lean_appended_proof(
            chunks, "allListedLinkedRunningProductNodesRefined_append",
            "staticProofContext relationalProductGraph productInvariantTable "
            "relationalProductReachabilityEvidence linkedProductControlProfile "
            "protocolCallbackTargets "
            f"{acceptance_original_program} {acceptance_candidate_program}",
            "linked_running",
        )
    edge_proof = ""
    if ordinary_acceptance_ready:
        edge_proof = _lean_appended_proof(
            [dict(chunk, ids=chunk["edge_ids"]) for chunk in chunks],
            "allListedProductExecutionEdgesRefined_append",
            "staticProofContext relationalProductGraph allRegions productInvariantTable",
            "edges",
        )
    root_target_id = int(nodes[root_node_id]["target_id"])
    callback_node_ids = [
        int(state["node_id"]) for state in plan["protocol_callback_states"]
    ]
    callback_node_ids_literal = "[" + ", ".join(map(str, callback_node_ids)) + "]"
    callback_theorems = [
        f"acceptanceCallbackRunningNode{node_id}Refined"
        + (
            " originalEnvironment candidateEnvironment"
            + (
                " originalProtocolEnvironment candidateProtocolEnvironment"
                if parameterized_protocol_environment else ""
            )
            + " environmentRefines"
            if parameterized_environment else ""
        )
        for node_id in callback_node_ids
    ]
    callback_closure_source = ""
    if parameterized_protocol_environment:
        callback_closure_source = (
            f"def allAcceptanceCallbackNodeIds : List Nat := {callback_node_ids_literal}\n\n"
            "theorem allAcceptanceCallbackRunningNodesListed\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (originalProtocolEnvironment candidateProtocolEnvironment : "
            "WorldExternalProtocolEnvironment)\n"
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    AllListedCallbackRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets\n"
            "      (originalWorldProgram originalEnvironment originalProtocolEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment candidateProtocolEnvironment)\n"
            "      allAcceptanceCallbackNodeIds := by\n"
            f"  exact {_lean_all_listed_proof(callback_theorems)}\n\n"
            "theorem allAcceptanceCallbackRunningNodesRefined\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (originalProtocolEnvironment candidateProtocolEnvironment : "
            "WorldExternalProtocolEnvironment)\n"
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    ReachableCallbackRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets\n"
            "      (originalWorldProgram originalEnvironment originalProtocolEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment candidateProtocolEnvironment) := by\n"
            "  apply reachableCallbackRunningProductNodesRefined_of_listed_profile\n"
            "  have ids : allAcceptanceCallbackNodeIds =\n"
            "      (protocolCallbackTargets.states.map fun state => state.nodeId) := by decide\n"
            "  rw [\u2190 ids]\n"
            "  exact allAcceptanceCallbackRunningNodesListed originalEnvironment\n"
            "    candidateEnvironment originalProtocolEnvironment\n"
            "    candidateProtocolEnvironment environmentRefines\n\n"
        )
    linked_running_closure_source = ""
    if linked_acceptance_ready and parameterized_environment:
        linked_running_closure_source = (
            "theorem allAcceptanceLinkedRunningNodesListed\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            + (
                "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                "WorldExternalProtocolEnvironment)\n"
                if parameterized_protocol_environment else ""
            )
            + "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    AllListedLinkedRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets\n"
            f"      {acceptance_original_program}\n"
            f"      {acceptance_candidate_program} allAcceptanceNodeIds := by\n"
            f"  simpa [allAcceptanceNodeIds] using ({linked_running_proof})\n\n"
            "theorem allAcceptanceLinkedRunningNodesRefined\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            + (
                "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                "WorldExternalProtocolEnvironment)\n"
                if parameterized_protocol_environment else ""
            )
            + "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    ReachableLinkedRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets\n"
            f"      {acceptance_original_program}\n"
            f"      {acceptance_candidate_program} := by\n"
            "  apply reachableLinkedRunningProductNodesRefined_of_complete_evidence\n"
            "    staticProofContext relationalProductGraph productInvariantTable\n"
            "    relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "    protocolCallbackTargets\n"
            f"    {acceptance_original_program}\n"
            f"    {acceptance_candidate_program} relationalProductLocalEvidence\n"
            "    relationalProductLocalEvidenceCompleteChecked\n"
            "  have ids : allAcceptanceNodeIds =\n"
            "      relationalProductLocalEvidence.decodedNodeIds := by decide\n"
            "  rw [← ids]\n"
            "  exact allAcceptanceLinkedRunningNodesListed originalEnvironment\n"
            "    candidateEnvironment "
            + (
                "originalProtocolEnvironment candidateProtocolEnvironment "
                if parameterized_protocol_environment else ""
            )
            + "environmentRefines\n\n"
        )
    elif linked_acceptance_ready:
        linked_running_closure_source = (
            "theorem allAcceptanceLinkedRunningNodesListed :\n"
            "    AllListedLinkedRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets originalWorldProgram candidateWorldProgram\n"
            "      allAcceptanceNodeIds := by\n"
            f"  simpa [allAcceptanceNodeIds] using ({linked_running_proof})\n\n"
            "theorem allAcceptanceLinkedRunningNodesRefined :\n"
            "    ReachableLinkedRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets originalWorldProgram candidateWorldProgram := by\n"
            "  apply reachableLinkedRunningProductNodesRefined_of_complete_evidence\n"
            "    staticProofContext relationalProductGraph productInvariantTable\n"
            "    relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "    protocolCallbackTargets originalWorldProgram candidateWorldProgram\n"
            "    relationalProductLocalEvidence relationalProductLocalEvidenceCompleteChecked\n"
            "  have ids : allAcceptanceNodeIds =\n"
            "      relationalProductLocalEvidence.decodedNodeIds := by decide\n"
            "  rw [← ids]\n"
            "  exact allAcceptanceLinkedRunningNodesListed\n\n"
        )
    if parameterized_environment:
        running_closure_source = (
            "theorem allAcceptanceRunningNodesListed\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            + (
                "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                "WorldExternalProtocolEnvironment)\n"
                if parameterized_protocol_environment else ""
            )
            +
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    AllListedRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets\n"
            f"      {acceptance_original_program}\n"
            f"      {acceptance_candidate_program} allAcceptanceNodeIds := by\n"
            f"  simpa [allAcceptanceNodeIds] using ({running_proof})\n\n"
            "theorem allAcceptanceRunningNodesRefined\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            + (
                "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                "WorldExternalProtocolEnvironment)\n"
                if parameterized_protocol_environment else ""
            )
            +
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    ReachableRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets\n"
            f"      {acceptance_original_program}\n"
            f"      {acceptance_candidate_program} := by\n"
            "  apply reachableRunningProductNodesRefined_of_complete_evidence\n"
            "    staticProofContext relationalProductGraph productInvariantTable\n"
            "    relationalProductReachabilityEvidence productControlProfile\n"
            "    protocolCallbackTargets\n"
            f"    {acceptance_original_program}\n"
            f"    {acceptance_candidate_program}\n"
            "    relationalProductLocalEvidence\n"
            "    relationalProductLocalEvidenceCompleteChecked\n"
            "  have ids : allAcceptanceNodeIds =\n"
            "      relationalProductLocalEvidence.decodedNodeIds := by decide\n"
            "  rw [← ids]\n"
            "  exact allAcceptanceRunningNodesListed originalEnvironment\n"
            "    candidateEnvironment "
            + (
                "originalProtocolEnvironment candidateProtocolEnvironment "
                if parameterized_protocol_environment else ""
            )
            + "environmentRefines\n\n"
        )
        if parameterized_protocol_environment:
            acceptance_certificate_source = (
                "def wholeProgramCertificate\n"
                "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
                "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                "WorldExternalProtocolEnvironment)\n"
                "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
                "      externalCallSites originalEnvironment candidateEnvironment)\n"
                "    (protocolRefines : WorldExternalProtocolEnvironmentsRefine\n"
                "      staticProofContext relationalProductGraph productInvariantTable\n"
                "      relationalProductReachabilityEvidence productControlProfile\n"
                "      protocolCallbackTargets externalCallSites\n"
                "      originalProtocolEnvironment candidateProtocolEnvironment) :\n"
                "    WholeProgramCertificate staticProofContext relationalProductGraph\n"
                "      allRegions productInvariantTable relationalProductReachabilityEvidence\n"
                "      productControlProfile protocolCallbackTargets externalCallSites consoleLaunch\n"
                "      originalEnvironment candidateEnvironment\n"
                "      originalProtocolEnvironment candidateProtocolEnvironment := {\n"
                "  imageBundle := proofBundle\n"
                "  executableImagesCovered := ⟨rfl, rfl, rfl, structuralChecked⟩\n"
                "  originalCodeAliasesSemanticallyValid := "
                "staticOriginalCodeAliasesSemanticallyChecked\n"
                "  candidateCodeAliasesSemanticallyValid := "
                "staticCandidateCodeAliasesSemanticallyChecked\n"
                "  originalCodeAliasesInstructionSemanticallyValid := "
                "staticOriginalCodeAliasesInstructionSemanticallyChecked\n"
                "  candidateCodeAliasesInstructionSemanticallyValid := "
                "staticCandidateCodeAliasesInstructionSemanticallyChecked\n"
                "  staticContextValid := staticProofContextChecked\n"
                "  productGraphValid := relationalProductGraphIndexedValidChecked\n"
                "  regionsUseCanonicalContext := allRegionsUseStaticContextChecked\n"
                "  regionsMatchProductGraph := allRegionsMatchProductGraph\n"
                "  invariantTableValid := productInvariantTableValid\n"
                "  callbackTargetsValid := by decide\n"
                "  reachabilityClosed := generatedDeclaredGraphReachabilityCertificateChecked\n"
                "  decodedControlComplete := reachableProductLocalCertificate.reachableControlComplete\n"
                "  reachableEdgesRefined := reachableProductLocalCertificate.reachableEdgesRefined\n"
                "  reachableExecutionEdgesRefined := allAcceptanceExecutionEdgesRefined\n"
                "  environmentsRefined := environmentRefines\n"
                "  protocolEnvironmentsRefined := protocolRefines\n"
                "  launchValid := consoleLaunchValid\n"
                "  launchRealizable := consoleLaunchRealizable\n"
                "  launchControlAllowed := by decide\n"
                "  runningProductNodesRefined := allAcceptanceRunningNodesRefined\n"
                "    originalEnvironment candidateEnvironment originalProtocolEnvironment\n"
                "    candidateProtocolEnvironment environmentRefines\n"
                "  callbackRunningProductNodesRefined :=\n"
                "    allAcceptanceCallbackRunningNodesRefined originalEnvironment\n"
                "      candidateEnvironment originalProtocolEnvironment\n"
                "      candidateProtocolEnvironment environmentRefines\n"
                "  originalInstructionSemanticsAdequate := by\n"
                "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
                "    simpa [originalWorldProgram, allRegions] using\n"
                "      allOriginalRegionsInstructionAdequate\n"
                "  candidateInstructionSemanticsAdequate := by\n"
                "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
                "    simpa [candidateWorldProgram, allRegions] using\n"
                "      allCandidateRegionsInstructionAdequate\n"
                "}\n\n"
                "theorem candidatePE32ProgramsEquivalent\n"
                "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
                "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                "WorldExternalProtocolEnvironment)\n"
                "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
                "      externalCallSites originalEnvironment candidateEnvironment)\n"
                "    (protocolRefines : WorldExternalProtocolEnvironmentsRefine\n"
                "      staticProofContext relationalProductGraph productInvariantTable\n"
                "      relationalProductReachabilityEvidence productControlProfile\n"
                "      protocolCallbackTargets externalCallSites\n"
                "      originalProtocolEnvironment candidateProtocolEnvironment) :\n"
                "    PE32RawProgramsObservationallyEquivalent staticProofContext\n"
                "      relationalProductGraph productInvariantTable\n"
                "      relationalProductReachabilityEvidence productControlProfile consoleLaunch\n"
                "      (originalWorldProgram originalEnvironment originalProtocolEnvironment)\n"
                "      (candidateWorldProgram candidateEnvironment candidateProtocolEnvironment) := by\n"
                "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
                "    pe32ProgramsEquivalent_raw staticProofContext relationalProductGraph allRegions\n"
                "      productInvariantTable relationalProductReachabilityEvidence productControlProfile\n"
                "      protocolCallbackTargets externalCallSites consoleLaunch\n"
                "      originalEnvironment candidateEnvironment originalProtocolEnvironment\n"
                "      candidateProtocolEnvironment\n"
                "      (wholeProgramCertificate originalEnvironment candidateEnvironment\n"
                "        originalProtocolEnvironment candidateProtocolEnvironment\n"
                "        environmentRefines protocolRefines)\n\n"
                "#print axioms candidatePE32ProgramsEquivalent\n\n"
            )
        else:
            acceptance_certificate_source = (
            "theorem noProtocolExternalCallSitesChecked :\n"
            "    externalCallSitesExcludeProtocol staticProofContext externalCallSites = true :=\n"
            "  by decide\n\n"
            "def wholeProgramCertificate\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    WholeProgramCertificate staticProofContext relationalProductGraph\n"
            "      allRegions productInvariantTable relationalProductReachabilityEvidence\n"
            "      productControlProfile protocolCallbackTargets externalCallSites consoleLaunch\n"
            "      originalEnvironment candidateEnvironment\n"
            "      inertWorldProtocolEnvironment inertWorldProtocolEnvironment := {\n"
            "  imageBundle := proofBundle\n"
            "  executableImagesCovered := ⟨rfl, rfl, rfl, structuralChecked⟩\n"
            "  originalCodeAliasesSemanticallyValid := "
            "staticOriginalCodeAliasesSemanticallyChecked\n"
            "  candidateCodeAliasesSemanticallyValid := "
            "staticCandidateCodeAliasesSemanticallyChecked\n"
            "  originalCodeAliasesInstructionSemanticallyValid := "
            "staticOriginalCodeAliasesInstructionSemanticallyChecked\n"
            "  candidateCodeAliasesInstructionSemanticallyValid := "
            "staticCandidateCodeAliasesInstructionSemanticallyChecked\n"
            "  staticContextValid := staticProofContextChecked\n"
            "  productGraphValid := relationalProductGraphIndexedValidChecked\n"
            "  regionsUseCanonicalContext := allRegionsUseStaticContextChecked\n"
            "  regionsMatchProductGraph := allRegionsMatchProductGraph\n"
            "  invariantTableValid := productInvariantTableValid\n"
            "  callbackTargetsValid := by decide\n"
            "  reachabilityClosed := generatedDeclaredGraphReachabilityCertificateChecked\n"
            "  decodedControlComplete := reachableProductLocalCertificate.reachableControlComplete\n"
            "  reachableEdgesRefined := reachableProductLocalCertificate.reachableEdgesRefined\n"
            "  reachableExecutionEdgesRefined := allAcceptanceExecutionEdgesRefined\n"
            "  environmentsRefined := environmentRefines\n"
            "  protocolEnvironmentsRefined :=\n"
            "    WorldExternalProtocolEnvironmentsRefine.of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets externalCallSites inertWorldProtocolEnvironment\n"
            "      inertWorldProtocolEnvironment noProtocolExternalCallSitesChecked\n"
            "  launchValid := consoleLaunchValid\n"
            "  launchRealizable := consoleLaunchRealizable\n"
            "  launchControlAllowed := by decide\n"
            "  runningProductNodesRefined := allAcceptanceRunningNodesRefined\n"
            "    originalEnvironment candidateEnvironment environmentRefines\n"
            "  callbackRunningProductNodesRefined :=\n"
            "    reachableCallbackRunningProductNodesRefined_of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets\n"
            "      (originalWorldProgram originalEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment)\n"
            "      productInvariantTableValid noProtocolExternalCallSitesChecked\n"
            "  originalInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [originalWorldProgram, allRegions] using\n"
            "      allOriginalRegionsInstructionAdequate\n"
            "  candidateInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [candidateWorldProgram, allRegions] using\n"
            "      allCandidateRegionsInstructionAdequate\n"
            "}\n\n"
            "theorem candidatePE32ProgramsEquivalent\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    PE32RawProgramsObservationallyEquivalent staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile consoleLaunch\n"
            "      (originalWorldProgram originalEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment) := by\n"
            "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "    pe32ProgramsEquivalent_raw staticProofContext relationalProductGraph allRegions\n"
            "      productInvariantTable relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets externalCallSites consoleLaunch\n"
            "      originalEnvironment candidateEnvironment\n"
            "      inertWorldProtocolEnvironment inertWorldProtocolEnvironment\n"
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
            "      protocolCallbackTargets\n"
            "      originalWorldProgram\n"
            "      candidateWorldProgram allAcceptanceNodeIds := by\n"
            f"  simpa [allAcceptanceNodeIds] using ({running_proof})\n\n"
            "theorem allAcceptanceRunningNodesRefined :\n"
            "    ReachableRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets\n"
            "      originalWorldProgram\n"
            "      candidateWorldProgram := by\n"
            "  apply reachableRunningProductNodesRefined_of_complete_evidence\n"
            "    staticProofContext relationalProductGraph productInvariantTable\n"
            "    relationalProductReachabilityEvidence productControlProfile\n"
            "    protocolCallbackTargets\n"
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
            "theorem noProtocolExternalCallSitesChecked :\n"
            "    externalCallSitesExcludeProtocol staticProofContext externalCallSites = true :=\n"
            "  by decide\n\n"
            "def wholeProgramCertificate : WholeProgramCertificate staticProofContext\n"
            "    relationalProductGraph allRegions productInvariantTable\n"
            "    relationalProductReachabilityEvidence productControlProfile\n"
            "    protocolCallbackTargets externalCallSites consoleLaunch\n"
            "    inertWorldEnvironment inertWorldEnvironment\n"
            "    inertWorldProtocolEnvironment inertWorldProtocolEnvironment := {\n"
            "  imageBundle := proofBundle\n"
            "  executableImagesCovered := ⟨rfl, rfl, rfl, structuralChecked⟩\n"
            "  originalCodeAliasesSemanticallyValid := "
            "staticOriginalCodeAliasesSemanticallyChecked\n"
            "  candidateCodeAliasesSemanticallyValid := "
            "staticCandidateCodeAliasesSemanticallyChecked\n"
            "  originalCodeAliasesInstructionSemanticallyValid := "
            "staticOriginalCodeAliasesInstructionSemanticallyChecked\n"
            "  candidateCodeAliasesInstructionSemanticallyValid := "
            "staticCandidateCodeAliasesInstructionSemanticallyChecked\n"
            "  staticContextValid := staticProofContextChecked\n"
            "  productGraphValid := relationalProductGraphIndexedValidChecked\n"
            "  regionsUseCanonicalContext := allRegionsUseStaticContextChecked\n"
            "  regionsMatchProductGraph := allRegionsMatchProductGraph\n"
            "  invariantTableValid := productInvariantTableValid\n"
            "  callbackTargetsValid := by decide\n"
            "  reachabilityClosed := generatedDeclaredGraphReachabilityCertificateChecked\n"
            "  decodedControlComplete := reachableProductLocalCertificate.reachableControlComplete\n"
            "  reachableEdgesRefined := reachableProductLocalCertificate.reachableEdgesRefined\n"
            "  reachableExecutionEdgesRefined := allAcceptanceExecutionEdgesRefined\n"
            "  environmentsRefined := inertEnvironmentRefines\n"
            "  protocolEnvironmentsRefined :=\n"
            "    WorldExternalProtocolEnvironmentsRefine.of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets externalCallSites inertWorldProtocolEnvironment\n"
            "      inertWorldProtocolEnvironment noProtocolExternalCallSitesChecked\n"
            "  launchValid := consoleLaunchValid\n"
            "  launchRealizable := consoleLaunchRealizable\n"
            "  launchControlAllowed := by decide\n"
            "  runningProductNodesRefined := by\n"
            "    simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "      allAcceptanceRunningNodesRefined\n"
            "  callbackRunningProductNodesRefined :=\n"
            "    reachableCallbackRunningProductNodesRefined_of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets originalWorldProgram candidateWorldProgram\n"
            "      productInvariantTableValid\n"
            "      noProtocolExternalCallSitesChecked\n"
            "  originalInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [originalWorldProgram, allRegions] using\n"
            "      allOriginalRegionsInstructionAdequate\n"
            "  candidateInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [candidateWorldProgram, allRegions] using\n"
            "      allCandidateRegionsInstructionAdequate\n"
            "}\n\n"
            "theorem candidatePE32ProgramsEquivalent :\n"
            "    PE32RawProgramsObservationallyEquivalent staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile consoleLaunch\n"
            "      originalWorldProgram candidateWorldProgram := by\n"
            "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "    pe32ProgramsEquivalent_raw staticProofContext relationalProductGraph allRegions\n"
            "      productInvariantTable relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets externalCallSites\n"
            "      consoleLaunch inertWorldEnvironment inertWorldEnvironment\n"
            "      inertWorldProtocolEnvironment inertWorldProtocolEnvironment\n"
            "      wholeProgramCertificate\n\n"
            "#print axioms candidatePE32ProgramsEquivalent\n\n"
        )
    linked_environment_support_source = ""
    if linked_acceptance_ready and not ordinary_acceptance_ready:
        if parameterized_protocol_environment:
            raise StageAInputError(
                "linked acceptance certificate does not yet support protocol environments"
            )
        linked_environment_support_source = (
            (
                "theorem inertEnvironmentRefines :\n"
                "    ExternalEnvironmentRefines staticProofContext externalCallSites\n"
                "      inertWorldEnvironment inertWorldEnvironment := by\n"
                "  unfold ExternalEnvironmentRefines\n"
                "  refine ⟨by decide, by decide, ?_⟩\n"
                "  intro site member\n  simp [externalCallSites] at member\n\n"
                if not parameterized_environment else ""
            )
            + "theorem noProtocolExternalCallSitesChecked :\n"
            "    externalCallSitesExcludeProtocol staticProofContext externalCallSites = true :=\n"
            "  by decide\n\n"
        )
        running_closure_source = ""
        callback_closure_source = ""
        acceptance_certificate_source = ""

    linked_acceptance_certificate_source = ""
    if linked_acceptance_ready and parameterized_environment:
        if parameterized_protocol_environment:
            raise StageAInputError(
                "linked acceptance certificate does not yet support protocol environments"
            )
        linked_acceptance_certificate_source = (
            "def linkedWholeProgramCertificate\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    LinkedWholeProgramCertificate staticProofContext relationalProductGraph\n"
            "      allRegions productInvariantTable relationalProductReachabilityEvidence\n"
            "      linkedProductControlProfile protocolCallbackTargets externalCallSites consoleLaunch\n"
            "      originalEnvironment candidateEnvironment\n"
            "      inertWorldProtocolEnvironment inertWorldProtocolEnvironment := {\n"
            "  imageBundle := proofBundle\n"
            "  executableImagesCovered := ⟨rfl, rfl, rfl, structuralChecked⟩\n"
            "  originalCodeAliasesSemanticallyValid := "
            "staticOriginalCodeAliasesSemanticallyChecked\n"
            "  candidateCodeAliasesSemanticallyValid := "
            "staticCandidateCodeAliasesSemanticallyChecked\n"
            "  originalCodeAliasesInstructionSemanticallyValid := "
            "staticOriginalCodeAliasesInstructionSemanticallyChecked\n"
            "  candidateCodeAliasesInstructionSemanticallyValid := "
            "staticCandidateCodeAliasesInstructionSemanticallyChecked\n"
            "  staticContextValid := staticProofContextChecked\n"
            "  productGraphValid := relationalProductGraphIndexedValidChecked\n"
            "  regionsUseCanonicalContext := allRegionsUseStaticContextChecked\n"
            "  regionsMatchProductGraph := allRegionsMatchProductGraph\n"
            "  invariantTableValid := productInvariantTableValid\n"
            "  callbackTargetsValid := by decide\n"
            "  reachabilityClosed := generatedDeclaredGraphReachabilityCertificateChecked\n"
            "  decodedControlComplete := "
            "reachableProductLocalCertificate.reachableControlComplete\n"
            "  environmentsRefined := environmentRefines\n"
            "  protocolEnvironmentsRefined :=\n"
            "    LinkedWorldExternalProtocolEnvironmentsRefine.of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets externalCallSites inertWorldProtocolEnvironment\n"
            "      inertWorldProtocolEnvironment noProtocolExternalCallSitesChecked\n"
            "  launchValid := consoleLaunchValid\n"
            "  launchRealizable := consoleLaunchLinkedRealizable\n"
            "  launchControlAllowed := by\n"
            "    change linkedProductControlProfile.Allows\n"
            "      consoleLaunch.rootNodeId consoleLaunch.continuationTargetIds\n"
            "      consoleLaunch.frameOffsets.head? = true\n"
            "    decide\n"
            "  runningProductNodesRefined := allAcceptanceLinkedRunningNodesRefined\n"
            "    originalEnvironment candidateEnvironment environmentRefines\n"
            "  callbackRunningProductNodesRefined :=\n"
            "    reachableLinkedCallbackRunningProductNodesRefined_of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets\n"
            "      (originalWorldProgram originalEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment)\n"
            "      productInvariantTableValid noProtocolExternalCallSitesChecked\n"
            "  originalInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [originalWorldProgram, allRegions] using\n"
            "      allOriginalRegionsInstructionAdequate\n"
            "  candidateInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [candidateWorldProgram, allRegions] using\n"
            "      allCandidateRegionsInstructionAdequate\n"
            "}\n\n"
            "theorem candidatePE32ProgramsEquivalentLinked\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    PE32RawProgramsLinkedObservationallyEquivalent staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile consoleLaunch\n"
            "      (originalWorldProgram originalEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment) := by\n"
            "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "    pe32ProgramsEquivalentLinked_raw staticProofContext relationalProductGraph\n"
            "      allRegions productInvariantTable relationalProductReachabilityEvidence\n"
            "      linkedProductControlProfile protocolCallbackTargets externalCallSites\n"
            "      consoleLaunch originalEnvironment candidateEnvironment\n"
            "      inertWorldProtocolEnvironment inertWorldProtocolEnvironment\n"
            "      (linkedWholeProgramCertificate originalEnvironment candidateEnvironment\n"
            "        environmentRefines)\n\n"
            "#print axioms candidatePE32ProgramsEquivalentLinked\n\n"
        )
    elif linked_acceptance_ready:
        linked_acceptance_certificate_source = (
            "def linkedWholeProgramCertificate : LinkedWholeProgramCertificate\n"
            "    staticProofContext relationalProductGraph allRegions productInvariantTable\n"
            "    relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "    protocolCallbackTargets externalCallSites consoleLaunch\n"
            "    inertWorldEnvironment inertWorldEnvironment\n"
            "    inertWorldProtocolEnvironment inertWorldProtocolEnvironment := {\n"
            "  imageBundle := proofBundle\n"
            "  executableImagesCovered := ⟨rfl, rfl, rfl, structuralChecked⟩\n"
            "  originalCodeAliasesSemanticallyValid := "
            "staticOriginalCodeAliasesSemanticallyChecked\n"
            "  candidateCodeAliasesSemanticallyValid := "
            "staticCandidateCodeAliasesSemanticallyChecked\n"
            "  originalCodeAliasesInstructionSemanticallyValid := "
            "staticOriginalCodeAliasesInstructionSemanticallyChecked\n"
            "  candidateCodeAliasesInstructionSemanticallyValid := "
            "staticCandidateCodeAliasesInstructionSemanticallyChecked\n"
            "  staticContextValid := staticProofContextChecked\n"
            "  productGraphValid := relationalProductGraphIndexedValidChecked\n"
            "  regionsUseCanonicalContext := allRegionsUseStaticContextChecked\n"
            "  regionsMatchProductGraph := allRegionsMatchProductGraph\n"
            "  invariantTableValid := productInvariantTableValid\n"
            "  callbackTargetsValid := by decide\n"
            "  reachabilityClosed := generatedDeclaredGraphReachabilityCertificateChecked\n"
            "  decodedControlComplete := "
            "reachableProductLocalCertificate.reachableControlComplete\n"
            "  environmentsRefined := inertEnvironmentRefines\n"
            "  protocolEnvironmentsRefined :=\n"
            "    LinkedWorldExternalProtocolEnvironmentsRefine.of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets externalCallSites inertWorldProtocolEnvironment\n"
            "      inertWorldProtocolEnvironment noProtocolExternalCallSitesChecked\n"
            "  launchValid := consoleLaunchValid\n"
            "  launchRealizable := consoleLaunchLinkedRealizable\n"
            "  launchControlAllowed := by\n"
            "    change linkedProductControlProfile.Allows\n"
            "      consoleLaunch.rootNodeId consoleLaunch.continuationTargetIds\n"
            "      consoleLaunch.frameOffsets.head? = true\n"
            "    decide\n"
            "  runningProductNodesRefined := by\n"
            "    simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "      allAcceptanceLinkedRunningNodesRefined\n"
            "  callbackRunningProductNodesRefined :=\n"
            "    reachableLinkedCallbackRunningProductNodesRefined_of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets originalWorldProgram candidateWorldProgram\n"
            "      productInvariantTableValid noProtocolExternalCallSitesChecked\n"
            "  originalInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [originalWorldProgram, allRegions] using\n"
            "      allOriginalRegionsInstructionAdequate\n"
            "  candidateInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [candidateWorldProgram, allRegions] using\n"
            "      allCandidateRegionsInstructionAdequate\n"
            "}\n\n"
            "theorem candidatePE32ProgramsEquivalentLinked :\n"
            "    PE32RawProgramsLinkedObservationallyEquivalent staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      consoleLaunch originalWorldProgram candidateWorldProgram := by\n"
            "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "    pe32ProgramsEquivalentLinked_raw staticProofContext relationalProductGraph\n"
            "      allRegions productInvariantTable relationalProductReachabilityEvidence\n"
            "      linkedProductControlProfile protocolCallbackTargets externalCallSites\n"
            "      consoleLaunch inertWorldEnvironment inertWorldEnvironment\n"
            "      inertWorldProtocolEnvironment inertWorldProtocolEnvironment\n"
            "      linkedWholeProgramCertificate\n\n"
            "#print axioms candidatePE32ProgramsEquivalentLinked\n\n"
        )
    ordinary_execution_closure_source = ""
    if ordinary_acceptance_ready:
        ordinary_execution_closure_source = (
            "theorem allAcceptanceExecutionEdgesListed :\n"
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
            "  have inventoriesMatch :\n"
            "      allAcceptanceEdgeIds.all\n"
            "          relationalProductLocalEvidence.refinedEdgeIds.contains &&\n"
            "        relationalProductLocalEvidence.refinedEdgeIds.all\n"
            "          allAcceptanceEdgeIds.contains = true := by decide\n"
            "  simp only [Bool.and_eq_true] at inventoriesMatch\n"
            "  exact allListedProductExecutionEdgesRefined_of_contains\n"
            "    staticProofContext relationalProductGraph allRegions\n"
            "    productInvariantTable allAcceptanceEdgeIds\n"
            "    relationalProductLocalEvidence.refinedEdgeIds\n"
            "    allAcceptanceExecutionEdgesListed inventoriesMatch.2\n\n"
        )

    final_source = (
        "import StageA.RelationalInstructionAdequacyCertificate\n"
        "import StageA.RelationalISARequirementReplayCertificate\n"
        "import StageA.RelationalPEWorldExecution\n"
        "import StageA.RelationalLaunchRealizabilityCertificate\n"
        + "".join(
            f"import StageA.{chunk['module']}\n" for chunk in region_chunks
        )
        + "".join(f"import StageA.{chunk['module']}\n" for chunk in chunks)
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        f"def allAcceptanceNodeIds : List Nat := {node_ids_expr}\n\n"
        f"def allAcceptanceRegionNodeIds : List Nat := {region_node_ids_expr}\n\n"
        f"def allAcceptanceEdgeIds : List Nat := {edge_ids_expr}\n\n"
        "theorem allAcceptanceRegionsListed :\n"
        "    AllListedRegionsMatchProductGraph staticProofContext relationalProductGraph\n"
        "      allRegions allAcceptanceRegionNodeIds := by\n"
        f"  simpa [allAcceptanceRegionNodeIds] using ({region_proof})\n\n"
        "theorem allAcceptanceRegionNodeIdsComplete :\n"
        "    allAcceptanceRegionNodeIds = List.range relationalProductGraph.nodes.size := by\n"
        "  decide\n\n"
        "theorem allRegionsMatchProductGraph :\n"
        "    RegionsMatchProductGraph staticProofContext relationalProductGraph allRegions := by\n"
        "  apply regionsMatchProductGraph_of_listed_range\n"
        "  rw [← allAcceptanceRegionNodeIdsComplete]\n"
        "  exact allAcceptanceRegionsListed\n\n"
        + running_closure_source
        + linked_running_closure_source
        + callback_closure_source
        + ordinary_execution_closure_source
        +
        "theorem productInvariantTableValid :\n"
        "    productInvariantTable.Valid relationalProductGraph := by\n"
        "  unfold ProductInvariantTable.Valid\n  decide\n\n"
        "theorem consoleLaunchValid :\n"
        "    consoleLaunch.Valid staticProofContext relationalProductGraph\n"
        "      productInvariantTable := by\n"
        "  refine ⟨by decide, by decide, by decide, by decide, by decide,\n"
        "    by decide, by decide, ?_, ?_, ⟨by decide, by decide⟩⟩\n"
        f"  · exact ⟨relationalProductGraph.nodes[{entry_root_node_id}], by decide,\n"
        "      by decide, by decide, by decide, by decide⟩\n"
        f"  · exact ⟨relationalProductGraph.nodes[{root_node_id}], by decide,\n"
        "      by decide, by decide, by decide, by decide⟩\n\n"
        + linked_environment_support_source
        + acceptance_certificate_source
        + linked_acceptance_certificate_source
        + "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(stage_a / "RelationalAcceptance.lean", final_source)
    return plan
