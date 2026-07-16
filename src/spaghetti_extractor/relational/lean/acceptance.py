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
    _register_offset_witness,
    _semantic_external_target_identity,
)
from ..analyses.callbacks import (
    attach_protocol_callback_states,
    protocol_callback_controls_by_node,
)
from ..analyses.frames import (
    return_frame_claim_for_location,
    runtime_frame_location_key as location_key,
    runtime_frame_location_payload as location_payload,
)
from ..analyses.stack import _stack_window_transfer_claims
from ..artifacts import write_text_if_changed as _write_text_if_changed
from ..contract import _raw_base_relocations
from ..model import (
    _semantic_constant_bool,
    _semantic_hash,
    _target_shaped_register_output_claims,
)
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
from .callbacks import _lean_acceptance_callback_return_node


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
    machine_contract_by_import = {
        _semantic_external_target_identity(item.get("import") or {}): item
        for item in contract.get("machine_import_call_contracts", [])
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
    node_by_target = {
        int(node["target_id"]): node_id for node_id, node in enumerate(nodes)
    }
    protocol_callback_contract_by_node = protocol_callback_controls_by_node(
        contract, node_by_target, block
    )
    if len(roots) != 1:
        block(
            "console_launch_root_unsupported",
            "pe32-console-launch-v1 currently requires exactly one checked entry root",
            "select the PE console entry root and model additional roots separately",
        )
    control_states: list[dict[str, Any]] = []
    control_states_by_node: dict[int, list[dict[str, Any]]] = {}
    if len(roots) == 1 and len(nodes) == len(behaviors):
        register_edges_by_pair: dict[tuple[int, int], list[dict[str, Any]]] = {}
        for edge in register_relations.get("edges", []):
            register_edges_by_pair.setdefault((
                int(edge["source_region_index"]),
                int(edge["target_region_index"]),
            ), []).append(edge)

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

        def inventory_key(payload: dict[str, Any]) -> tuple[
            tuple[str, int, str, int], ...
        ]:
            return tuple(location_key(item) for item in payload["locations"])

        def inventory_payload(
            locations: tuple[tuple[str, int, str, int], ...],
        ) -> dict[str, Any]:
            return {
                "locations": [location_payload(location) for location in locations],
            }

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
                ordered = tuple(sorted(
                    candidates,
                    key=lambda target: location_rank(
                        candidates[target], target, target_node_id
                    ),
                ))
                if len(ordered) > max_frame_aliases:
                    block(
                        "runtime_frame_alias_budget_exceeded",
                        f"product {target_description} from {source_node_id} "
                        f"produces {len(ordered)} aliases for one runtime frame",
                        "supply a checked canonical alias policy or raise the Lean-checked "
                        "finite alias profile deliberately",
                    )
                    return None
                transferred_inventories.append(ordered)
            return tuple(transferred_inventories)

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
            return all(
                (left + left_byte) % 2**32
                    != (right + right_byte) % 2**32
                for left_byte in range(4)
                for right_byte in range(4)
            )

        def write_witnesses(
            behavior: dict[str, Any], register: str, frame_offset: int,
        ) -> list[dict[str, Any]] | None:
            witnesses = []
            for write in behavior.get("writes") or []:
                result = _register_offset_witness(
                    write.get("address"), register
                )
                if result is None:
                    return None
                witness, write_offset = result
                if not word_offsets_disjoint(frame_offset, int(write_offset)):
                    return None
                witnesses.append(witness)
            return witnesses

        static_word_slots = list(contract.get("static_word_relation_slots", []))

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
            ) or framed_memory_claim(source_node_id, source_location) is not None

        def location_outgoing_transfer_ready(
            source_node_id: int,
            source_location: tuple[str, int, str, int],
        ) -> bool:
            for edge_id in nodes[source_node_id].get("outgoing_edge_ids", []):
                edge = edges[int(edge_id)]
                if edge.get("infeasible"):
                    continue
                if edge.get("kind") not in {"jump", "call"}:
                    continue
                matching_edges = register_edges_by_pair.get((
                    source_node_id, int(edge["target_node_id"])
                ), [])
                if len(matching_edges) != 1:
                    return False
                relation_edge = matching_edges[0]
                has_claim = any(
                    location_key(claim["source"]) == source_location
                    for claim in relation_edge.get(
                        "return_slot_transfer_claims", []
                    )
                )
                has_rule = any(
                    rule["original_source_register"] == source_location[0]
                    and rule["candidate_source_register"] == source_location[2]
                    for rule in relation_edge.get(
                        "return_slot_transfer_rules", []
                    )
                )
                if not has_claim and not has_rule:
                    return False
            return True

        def internal_transfer_claims(
            source_node_id: int,
            source_inventories: tuple[
                tuple[tuple[str, int, str, int], ...], ...
            ],
            target_inventories: tuple[
                tuple[tuple[str, int, str, int], ...], ...
            ],
        ) -> list[dict[str, Any]] | None:
            if len(source_inventories) != len(target_inventories):
                return None
            relation_row = register_relations.get("regions", [])[source_node_id]
            local_rules = relation_row.get(
                "return_slot_local_transfer_rules", []
            )
            original = behaviors[source_node_id].get("original_ir") or {}
            candidate = behaviors[source_node_id].get("candidate_ir") or {}
            inventory_claims = []
            for source_inventory, target_inventory in zip(
                source_inventories, target_inventories, strict=True
            ):
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
                inventory_claims.append({
                    "profile": "return_slot_frame_inventory_transfer_v1",
                    "source": inventory_payload(source_inventory),
                    "target": inventory_payload(target_inventory),
                    "transfers": transfers,
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

        pending: list[tuple[
            int, tuple[int, ...],
            tuple[tuple[tuple[str, int, str, int], ...], ...],
        ]] = [(roots[0], (), ())]
        seen: set[tuple[
            int, tuple[int, ...],
            tuple[tuple[tuple[str, int, str, int], ...], ...],
        ]] = set()
        control_incomplete = False
        while pending and not control_incomplete:
            node_id, calls, frame_inventories = pending.pop(0)
            key = (node_id, calls, frame_inventories)
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
            if len(frame_inventories) != len(calls):
                block(
                    "runtime_frame_offset_inventory_incomplete",
                    f"product node {node_id} has {len(calls)} runtime frames but "
                    f"{len(frame_inventories)} checked return-slot inventories",
                    "propagate a checked return-slot alias inventory for every live runtime frame",
                )
                control_incomplete = True
                break
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
                control_incomplete = True
                break
            state = {
                "node_id": node_id,
                "calls": list(calls),
                "frame_offsets": [
                    inventory_payload(inventory)
                    for inventory in frame_inventories
                ],
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
            successor_targets: list[tuple[
                int, tuple[int, ...], str,
            ]] = []
            if operation == "jump":
                if original_outcome.get("target") != candidate_outcome.get("target"):
                    control_incomplete = True
                else:
                    successor_targets.append((
                        int(original_outcome["target"]), calls, "transfer",
                    ))
            elif operation == "branch":
                original_condition = original_outcome.get("condition") or {}
                candidate_condition = candidate_outcome.get("condition") or {}
                original_constant = _semantic_constant_bool(original_condition)
                candidate_constant = _semantic_constant_bool(candidate_condition)
                if original_constant != candidate_constant:
                    control_incomplete = True
                    fields = ()
                elif original_constant is True:
                    fields = ("taken",)
                elif original_constant is False:
                    fields = ("fallthrough",)
                else:
                    fields = ("taken", "fallthrough")
                for field in fields:
                    if original_outcome.get(field) != candidate_outcome.get(field):
                        control_incomplete = True
                        break
                    successor_targets.append((
                        int(original_outcome[field]), calls, "transfer",
                    ))
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
                        "call",
                    ))
            elif operation == "external_call":
                if any(
                    original_outcome.get(field) != candidate_outcome.get(field)
                    for field in ("import", "continuation")
                ):
                    control_incomplete = True
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
                if original_outcome.get("continuation") != candidate_outcome.get(
                    "continuation"
                ):
                    control_incomplete = True
                else:
                    successor_targets.append((
                        int(original_outcome["continuation"]), calls,
                        "external",
                    ))
            elif operation == "external_jump":
                if original_outcome.get("import") != candidate_outcome.get("import"):
                    control_incomplete = True
                elif not calls:
                    block(
                        "top_level_external_jump_unsupported",
                        f"product node {node_id} reaches an import jump without a checked return frame",
                        "map the importing call and propagate its runtime continuation frame",
                    )
                    control_incomplete = True
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
                if (
                    decoded_control.get("profile") not in {
                        "immutable_relocated_function_pointer_call_v1",
                        "fixed_static_function_pointer_call_v1",
                    }
                    or original_outcome.get("continuation") !=
                        candidate_outcome.get("continuation")
                ):
                    block(
                        "bounded_indirect_control_profile_unmet",
                        f"product node {node_id} has no checked finite indirect-call target",
                        "classify the target by provenance and emit a checked finite target set",
                    )
                    control_incomplete = True
                else:
                    continuation = int(original_outcome["continuation"])
                    successor_targets.append((
                        int(decoded_control["target_id"]),
                        (continuation, *calls),
                        "call",
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
            for target_id, successor_calls, frame_operation in successor_targets:
                target_node_id = node_by_target.get(target_id)
                if target_node_id is None:
                    block(
                        "control_profile_target_unmapped",
                        f"control target {target_id} from product node {node_id} has no product node",
                        "close the rooted decoded-control mapping frontier",
                    )
                    control_incomplete = True
                    break
                if frame_operation == "transfer":
                    successor_locations = transfer_locations(
                        node_id, target_node_id, frame_inventories
                    )
                    if successor_locations is None:
                        control_incomplete = True
                        break
                elif frame_operation == "call":
                    transferred_outer = transfer_locations(
                        node_id, target_node_id, frame_inventories
                    )
                    if transferred_outer is None:
                        control_incomplete = True
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
                        control_incomplete = True
                        break
                    successor_locations = (
                        (location_key(seed["offsets"]),), *transferred_outer,
                    )
                elif frame_operation == "return_pop":
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
                        control_incomplete = True
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
                        control_incomplete = True
                        break
                elif frame_operation == "external_pop":
                    active_inventory = frame_inventories[0]
                    if ("esp", 0, "esp", 0) not in active_inventory:
                        block(
                            "external_jump_active_frame_location_unmet",
                            f"external jump {node_id}->{target_node_id} has active "
                            f"runtime frame aliases {active_inventory}",
                            "propagate the decoded direct-call return slot to ESP+0",
                        )
                        control_incomplete = True
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
                        control_incomplete = True
                        break
                    successor_locations = tuple(
                        (location_key(claim["target"]),)
                        for claim in outer_claims
                    )
                else:
                    successor_locations = external_transfer_locations(
                        node_id, target_node_id, frame_inventories
                    )
                    if successor_locations is None:
                        control_incomplete = True
                        break
                pending.append((target_node_id, successor_calls, successor_locations))

    candidate_by_edge = {
        int(candidate["edge_index"]): candidate for candidate in segment_candidates
    }
    external_by_edge = {
        int(candidate["edge_index"]): candidate
        for candidate in external_site_candidates
        if "edge_index" in candidate
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
            if all(outcome.get("op") == "external_jump" for outcome in outcomes):
                if len(control_rows) != 1 or not control_rows[0]["calls"]:
                    block(
                        "external_jump_control_profile_unmet",
                        f"import-thunk node {node_id} does not have one checked active caller frame",
                        "generate continuation-specific external-jump cases for every allowed runtime frame",
                    )
                    continue
                control_row = control_rows[0]
                continuation_target_id = int(control_row["calls"][0])
                external_site = external_thunk_by_source_continuation.get(
                    (node_id, continuation_target_id)
                )
                if external_site is None:
                    block(
                        "external_jump_site_missing",
                        f"import-thunk node {node_id} continuation {continuation_target_id} lacks a checked site",
                        "close the thunk identity, ABI argument, boundary, and continuation evidence",
                    )
                    continue
                frame_offsets = control_row["frame_offsets"]
                if (
                    len(frame_offsets) != len(control_row["calls"])
                    or not frame_offsets
                    or ("esp", 0, "esp", 0)
                        not in inventory_key(frame_offsets[0])
                ):
                    block(
                        "external_jump_frame_offset_missing",
                        f"import-thunk node {node_id} lacks a checked active ESP+0 return slot",
                        "propagate every caller return slot into the thunk control state",
                    )
                    continue
                target_node_id = next(
                    (
                        candidate_id for candidate_id, candidate_node in enumerate(nodes)
                        if int(candidate_node["target_id"]) == continuation_target_id
                    ),
                    -1,
                )
                if target_node_id < 0:
                    block(
                        "external_jump_continuation_unmapped",
                        f"import-thunk node {node_id} continuation {continuation_target_id} is unmapped",
                        "add the continuation to the checked product graph",
                    )
                    continue
                machine_contract = machine_contract_by_id.get(
                    int(external_site["machine_contract_id"])
                )
                if machine_contract is None:
                    block(
                        "external_jump_machine_contract_missing",
                        f"import-thunk node {node_id} has no resolved machine contract",
                        "declare one complete machine-level import contract",
                    )
                    continue
                if machine_contract.get("disposition") == "terminates":
                    node_steps.append({
                        "kind": "external_terminate",
                        "node_id": node_id,
                        "region_index": node_id,
                        "target_id": target_id,
                        "control_state": control_row,
                        "external_site": external_site,
                        "machine_contract": machine_contract,
                        "decoded_import": outcomes[0].get("import"),
                        "edges": [],
                    })
                    has_external_call = True
                    continue
                outer_transfers = external_jump_transfer_claims(
                    node_id,
                    continuation_target_id,
                    tuple(inventory_key(item)[0] for item in frame_offsets[1:]),
                )
                if outer_transfers is None:
                    block(
                        "external_jump_outer_frame_transfer_incomplete",
                        f"import-thunk node {node_id} cannot transfer every outer runtime frame",
                        "emit decoded thunk, normalization, memory, and ABI transfer claims",
                    )
                    continue
                outer_claims = [
                    {
                        "profile":
                            "external_jump_return_slot_inventory_transfer_v1",
                        "source": source_inventory,
                        "target": inventory_payload((
                            location_key(transfer["target"]),
                        )),
                        "transfers": [transfer],
                    }
                    for source_inventory, transfer in zip(
                        frame_offsets[1:], outer_transfers, strict=True
                    )
                ]
                target_offsets = [
                    claim["target"] for claim in outer_claims
                ]
                target_control_rows = [
                    row for row in control_states_by_node.get(target_node_id, [])
                    if row["calls"] == control_row["calls"][1:]
                    and row["frame_offsets"] == target_offsets
                ]
                if len(target_control_rows) != 1:
                    block(
                        "external_jump_target_control_state_missing",
                        f"import-thunk node {node_id} has no unique checked outer-frame successor",
                        "regenerate rooted control closure from the checked thunk transfers",
                    )
                    continue
                node_steps.append({
                    "kind": "external_jump",
                    "node_id": node_id,
                    "region_index": node_id,
                    "target_id": target_id,
                    "control_state": control_row,
                    "target_control_state": target_control_rows[0],
                    "return_slot_external_jump_transfer_claims": outer_claims,
                    "target_node_id": target_node_id,
                    "target_region_index": target_node_id,
                    "target_target_id": continuation_target_id,
                    "external_site": external_site,
                    "machine_contract": machine_contract,
                    "decoded_import": outcomes[0].get("import"),
                    "edges": [],
                })
                has_external_call = True
                continue
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
                active_inventory = inventory_key(
                    control_rows[0]["frame_offsets"][0]
                )
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
                control_row = control_rows[0]
                target_control_rows = [
                    row for row in control_states_by_node.get(target_node_id, [])
                    if row["calls"] == calls[1:]
                ]
                if len(target_control_rows) != 1:
                    block(
                        "return_target_control_state_missing",
                        f"return node {node_id} has no unique checked successor "
                        "control state for its remaining runtime frames",
                        "regenerate rooted control closure from the checked return transfer",
                    )
                    continue
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
                    node_id, source_outer_inventories, target_inventories
                )
                if outer_frame_claims is None:
                    block(
                        "return_outer_frame_transfer_incomplete",
                        f"return node {node_id} cannot preserve every remaining "
                        "runtime frame",
                        "emit checked register and memory-footprint transfers for "
                        "each outer frame",
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
                    "target_control_state": target_control_row,
                    "target_node_id": target_node_id,
                    "target_region_index": target_node_id,
                    "target_target_id": continuation_target_id,
                    "return_pop_claim": relation_row["return_pop_claim"],
                    "return_frame_claim": return_frame_claim,
                    "return_frame_inventory":
                        control_rows[0]["frame_offsets"][0],
                    "return_slot_frame_transfer_claims": outer_frame_claims,
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
                exact_eax_output = any(
                    claim.get("output") == {
                        "original": "eax",
                        "candidate": "eax",
                        "relation": "exact",
                    }
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
                control_rows = control_states_by_node.get(node_id, [])
                if (
                    call_push_claim is None
                    or any(int(outcome.get("continuation", -1)) != continuation for outcome in outcomes)
                    or len(control_rows) != 1
                ):
                    block(
                        "direct_call_control_profile_unmet",
                        f"call node {node_id} lacks a unique checked runtime-frame seed",
                        "close the call push and finite rooted control-state evidence",
                    )
                    continue
                control_row = control_rows[0]
                source_locations = tuple(
                    inventory_key(item) for item in control_row["frame_offsets"]
                )
                target_control_rows = [
                    row for row in control_states_by_node.get(target_node_id, [])
                    if row["calls"] == [
                        continuation, *control_row["calls"]
                    ]
                    and inventory_key(row["frame_offsets"][0]) == (
                        ("esp", 0, "esp", 0),
                    )
                ]
                if len(target_control_rows) != 1:
                    block(
                        "direct_call_target_control_state_missing",
                        f"call node {node_id} has no unique checked successor "
                        "control state for its new and transferred runtime frames",
                        "regenerate rooted control closure from the checked call transfer",
                    )
                    continue
                target_control_row = target_control_rows[0]
                target_inventories = tuple(
                    inventory_key(item)
                    for item in target_control_row["frame_offsets"][1:]
                )
                selected_claims = internal_transfer_claims(
                    node_id, source_locations, target_inventories
                )
                if selected_claims is None:
                    block(
                        "direct_call_outer_frame_transfer_incomplete",
                        f"call node {node_id} lacks a checked register/memory "
                        "transfer for every live outer runtime frame",
                        "emit affine register and call-push write-disjointness witnesses",
                    )
                    continue
                continuation_node_id = node_by_target.get(continuation)
                if continuation_node_id is None:
                    block(
                        "direct_call_continuation_unmapped",
                        f"call node {node_id} continuation {continuation} has no "
                        "canonical product node",
                        "close the decoded continuation mapping frontier",
                    )
                    continue
                step["control_state"] = control_row
                step["target_control_state"] = target_control_row
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
                step["return_slot_frame_transfer_claims"] = selected_claims
                step["source_stack_window"] = segment["source_stack_window"]
                step["stack_amount"] = int(segment["stack_amount"])
                has_internal_call = True
            elif external_profile:
                control_rows = control_states_by_node.get(node_id, [])
                if len(control_rows) != 1:
                    block(
                        "external_call_control_profile_ambiguous",
                        f"external-call node {node_id} has {len(control_rows)} rooted control states",
                        "split the node theorem into one checked case per rooted control state",
                    )
                    continue
                control_row = control_rows[0]
                register_edge = register_edge_by_source_target.get(
                    (node_id, target_node_id), {}
                )
                transfer_claims = register_edge.get(
                    "return_slot_external_transfer_claims", []
                )
                target_control_rows = [
                    row for row in control_states_by_node.get(target_node_id, [])
                    if row["calls"] == control_row["calls"]
                ]
                if len(target_control_rows) != 1:
                    block(
                        "external_runtime_frame_target_state_missing",
                        f"external-call node {node_id} has no unique checked successor "
                        "control state for its transferred runtime frames",
                        "regenerate the rooted control profile from the checked transfer claims",
                    )
                    continue
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
                            if location_key(claim["source"]) in source_inventory
                            and location_key(claim["target"]) == target_location
                        ]
                        if not candidates:
                            break
                        transfers.append(sorted(
                            candidates,
                            key=lambda claim: location_key(claim["source"]),
                        )[0])
                    if len(transfers) != len(target_inventory):
                        break
                    selected_claims.append({
                        "profile": "external_return_slot_inventory_transfer_v1",
                        "source": source_payload,
                        "target": target_payload,
                        "transfers": transfers,
                    })
                if len(selected_claims) != len(control_row["frame_offsets"]):
                    block(
                        "external_runtime_frame_transfer_claim_missing",
                        f"external-call node {node_id} lacks a checked memory/register "
                        "transfer claim for every live runtime frame",
                        "emit affine call-setup, write-disjointness, and ABI-result witnesses",
                    )
                    continue
                step["kind"] = "external_call"
                step["control_state"] = control_row
                step["target_control_state"] = target_control_row
                step["return_slot_external_transfer_claims"] = selected_claims
                step["external_site"] = external_site
                step["decoded_import"] = outcomes[0].get("import")
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
                if machine_contract.get("disposition") == "protocol":
                    step["kind"] = "external_protocol"
                has_external_call = True
            elif jump_profile:
                control_rows = control_states_by_node.get(node_id, [])
                if len(control_rows) != 1:
                    block(
                        "jump_control_profile_ambiguous",
                        f"jump node {node_id} has {len(control_rows)} rooted control states",
                        "split the node theorem into one checked case per rooted control state",
                    )
                    continue
                control_row = control_rows[0]
                target_control_rows = [
                    row for row in control_states_by_node.get(target_node_id, [])
                    if row["calls"] == control_row["calls"]
                ]
                if len(target_control_rows) != 1:
                    block(
                        "jump_target_control_state_missing",
                        f"jump node {node_id} has no unique checked successor "
                        "control state for its transferred runtime frames",
                        "regenerate rooted control closure from the checked transfer",
                    )
                    continue
                target_control_row = target_control_rows[0]
                source_locations = tuple(
                    inventory_key(item) for item in control_row["frame_offsets"]
                )
                selected_claims = internal_transfer_claims(
                    node_id,
                    source_locations,
                    tuple(
                        inventory_key(item)
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
                    continue
                step["control_state"] = control_row
                step["target_control_state"] = target_control_row
                step["return_slot_frame_transfer_claims"] = selected_claims
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
                    "composable_paired_prepared_word_writes_v1",
                    "composable_direct_call_prepared_writes_v1",
                    "composable_direct_call_stack_writes_v1",
                }
            for edge in edge_rows
        )
        ordered_edges = [taken_edge, fallthrough_edge]
        control_rows = control_states_by_node.get(node_id, [])
        if len(control_rows) != 1:
            block(
                "branch_control_profile_ambiguous",
                f"branch node {node_id} has {len(control_rows)} rooted control states",
                "emit one canonical bounded-alias control state at the cutpoint",
            )
            continue
        control_row = control_rows[0]
        source_inventories = tuple(
            inventory_key(item) for item in control_row["frame_offsets"]
        )
        planned_edges = []
        branch_frames_complete = True
        for edge in ordered_edges:
            target_node_id = int(edge["target_node_id"])
            target_rows = [
                row for row in control_states_by_node.get(target_node_id, [])
                if row["calls"] == control_row["calls"]
            ]
            if len(target_rows) != 1:
                block(
                    "branch_target_control_state_missing",
                    f"branch edge {int(edge['id'])} has no unique checked target "
                    "control state",
                    "regenerate rooted control closure through both decoded guards",
                )
                branch_frames_complete = False
                break
            target_row = target_rows[0]
            frame_claims = internal_transfer_claims(
                node_id,
                source_inventories,
                tuple(
                    inventory_key(item)
                    for item in target_row["frame_offsets"]
                ),
            )
            if frame_claims is None:
                block(
                    "branch_runtime_frame_transfer_incomplete",
                    f"branch edge {int(edge['id'])} cannot preserve every live "
                    "runtime frame",
                    "emit checked register and memory-footprint transfers for one "
                    "or more retained aliases",
                )
                branch_frames_complete = False
                break
            planned_edges.append({
                "edge_id": int(edge["id"]),
                "branch_value": edge.get("kind") == "branchTaken",
                "target_node_id": target_node_id,
                "target_region_index": target_node_id,
                "target_target_id": int(edge["target_target_id"]),
                "target_control_state": target_row,
                "return_slot_frame_transfer_claims": frame_claims,
            })
        if not branch_frames_complete:
            continue
        node_steps.append({
            "kind": "branch",
            "node_id": node_id,
            "region_index": node_id,
            "target_id": target_id,
            "control_state": control_row,
            "edges": planned_edges,
        })

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
            "control_states": control_states,
            "protocol_callback_node_ids": sorted(protocol_callback_contract_by_node),
            "protocol_callback_states": protocol_callback_states,
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
            returned_region_indices[0]
            if returned_region_indices else roots[0]
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
        "control_states": control_states,
        "protocol_callback_node_ids": sorted(protocol_callback_contract_by_node),
        "protocol_callback_states": protocol_callback_states,
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

def _lean_return_slot_offset_inventory(inventory: dict[str, Any]) -> str:
    return (
        "({ locations := ["
        + ", ".join(
            _lean_return_slot_offset_pair(location)
            for location in inventory["locations"]
        )
        + "] } : ReturnSlotOffsetInventory)"
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
    elif memory.get("profile") == "stack_image_separated_v1":
        location = memory["location"]
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
        + "] }"
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
        "    controlAllowed stackHolds stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [ProductControlProfile.Allows, Bool.and_eq_true] at controlMember\n"
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
    if step["kind"] == "call":
        edge = step["edges"][0]
        edge_id = int(edge["edge_id"])
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
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item["target"])
            for item in frame_claims
        ) + "]"
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
            + f"      ({candidate_behavior}.eval candidateState) statesRelated\n"
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
        return (
            prefix
            + f"  have controlShape : calls = {source_calls_literal} \u2227\n"
            f"      frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
            f"  let outerFrameClaims : List ReturnSlotFrameInventoryTransferClaim :=\n"
            f"    {frame_claims_literal}\n"
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
            "  have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"        candidateState) (runtimeFrame :: frames)\n"
            f"      ({continuation} :: {source_calls_literal})\n"
            f"      (ReturnSlotOffsetInventory.zero :: {target_offsets_literal}) := by\n"
            "    simp only [RelationalRuntimeCallStackHolds]\n"
            "    exact ⟨rfl, frameValid, frameResolves, frameMemory,\n"
            "      ReturnSlotOffsetInventory.zero_holds runtimeFrame\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers frameOffsetsHold,\n"
            "      outerStackHolds⟩\n"
            + known_indirect_dispatch
            + _lean_acceptance_running_target(
                node_id=node_id,
                region_index=region_index,
                edge=edge,
                frames="runtimeFrame :: frames",
                calls=f"{continuation} :: {source_calls_literal}",
                frame_offsets=(
                    "ReturnSlotOffsetInventory.zero :: " + target_offsets_literal
                ),
                stack_targets_proof=(
                    "(by simp only [RelationalRuntimeCallTargetsReachable]; "
                    f"exact ⟨⟨{continuation_node_id}, "
                    f"relationalProductGraph.nodes[{continuation_node_id}], "
                    "by decide, by decide, by decide⟩, stackTargetsReachable⟩)"
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
            + f"  have controlShape : calls = {source_calls_literal} ∧\n"
            f"      frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
            "  cases frames with\n"
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
            "        (by simpa [outerFrameClaims] using stackHolds.2.2.2.2.2)\n"
            "        statesRelated\n"
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
            "    have outputDynamic : activeDynamicRegisterRangeRelationsHold "
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
            "        outputImports outputDynamic outputDynamicStack\n"
            "    have stackHoldsNext := outerStackHolds\n"
            "    have outerTargetsReachable : RelationalRuntimeCallTargetsReachable\n"
            "        relationalProductGraph relationalProductReachabilityEvidence\n"
            f"        {target_calls_literal} := by\n"
            "      simpa only [RelationalRuntimeCallTargetsReachable] using\n"
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
        return (
            prefix
            + f"  have controlShape : calls = {calls_literal} ∧ "
            f"frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
            f"  have originalBehaviorCommon : {original_behavior} =\n"
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
        return (
            prefix
            + f"  have controlShape : calls = {calls_literal} ∧ "
            f"frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
            "  cases frames with\n"
            "  | nil => simp [RelationalRuntimeCallStackHolds] at stackHolds\n"
            "  | cons frame outerFrames =>\n"
            "    simp only [RelationalRuntimeCallStackHolds] at stackHolds\n"
            f"    let outerFrameClaims : List "
            "ExternalJumpReturnSlotInventoryTransferClaim := "
            f"{outer_claims_literal}\n"
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
            f"        staticProofContext {original_behavior} {candidate_behavior}\n"
            f"        externalJumpSite{site_id}MachineContract outerFrameClaims\n"
            f"        outerFrames {outer_calls_literal} originalState candidateState\n"
            "        (originalEnvironment.result eventIndex originalEvent).state\n"
            "        (candidateEnvironment.result eventIndex candidateEvent).state\n"
            "        (by decide)\n"
            "        (by simpa [outerFrameClaims] using stackHolds.2.2.2.2.2)\n"
            "        (by simpa [originalEvent] using _originalConforms.2.1)\n"
            "        (by simpa [candidateEvent] using _candidateConforms.2.1)\n"
            "        (by\n"
            "          intro outerFrame frameHolds\n"
            "          exact framesPreserved outerFrame (by\n"
            "            simpa [originalEvent, candidateEvent] using frameHolds))\n"
            "    have outerTargetsReachable : RelationalRuntimeCallTargetsReachable\n"
            f"        relationalProductGraph relationalProductReachabilityEvidence\n"
            f"        {outer_calls_literal} := by\n"
            "      simpa only [RelationalRuntimeCallTargetsReachable] using\n"
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
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(claim["target"])
            for claim in transfer_claims
        ) + "]"
        imported_literal = _lean_external_target({
            "dll": imported_identity[0], imported_identity[1]: imported_identity[2],
        })
        common = (
            prefix
            + f"  have controlShape : calls = {calls_literal} ∧ "
            f"frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
            f"  let frameClaims : List ExternalReturnSlotInventoryTransferClaim := "
            f"{transfer_claims_literal}\n"
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
                "    · simpa [originalEvent, candidateEvent] using outputRegisters\n"
                "    · simpa [originalEvent, candidateEvent] using outputBounds\n"
                "    · simpa [originalEvent, candidateEvent] using outputSeparations\n"
                "    · simpa [originalEvent, candidateEvent] using outputStackWindows\n"
                "    · simpa [originalEvent, candidateEvent] using outputX87\n"
                "    · simpa [originalEvent, candidateEvent] using outputFlags\n"
                "    · simpa [originalEvent, candidateEvent] using outputImports\n"
                "    · simpa [originalEvent, candidateEvent] using outputDynamic\n"
                "    · simpa [originalEvent, candidateEvent] using outputDynamicStack\n"
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
            "  have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
            "      (originalEnvironment.result eventIndex originalEvent).state\n"
            "      (candidateEnvironment.result eventIndex candidateEvent).state\n"
            f"      frames {calls_literal} {target_offsets_literal} := by\n"
            "    exact RelationalRuntimeCallStackHolds.afterExternalCall\n"
            f"      staticProofContext {original_behavior} {candidate_behavior}\n"
            f"      externalCallEdge{edge_id}MachineContract frameClaims frames\n"
            f"      {calls_literal} originalState candidateState\n"
            "      (originalEnvironment.result eventIndex originalEvent).state\n"
            "      (candidateEnvironment.result eventIndex candidateEvent).state\n"
            "      (by decide)\n"
            "      (by simpa [frameClaims] using stackHolds)\n"
            "      (by simpa [originalEvent] using _originalConforms.2.1)\n"
            "      (by simpa [candidateEvent] using _candidateConforms.2.1)\n"
            "      (by\n"
            "        intro frame frameHolds\n"
            "        exact framesPreserved frame (by\n"
            "          simpa [originalEvent, candidateEvent] using frameHolds))\n"
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
            "  rw [originalBehaviorCommon, candidateBehaviorCommon]\n"
            "  simp only [originalWorldProgram, candidateWorldProgram]\n"
            f"  have importedCommon : ({imported_literal} : ExternalTarget) =\n"
            f"      externalCallEdge{edge_id}MachineContract.imported := by decide\n"
            "  rw [importedCommon]\n"
            "  rw [originalSiteResolved]\n"
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
            "      originalWrites candidateWrites outputRegisters outputBounds\n"
            "      outputSeparations outputStackWindows outputX87 outputFlags\n"
            "      outputImports outputDynamic outputDynamicStack\n"
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
            "      intro register\n"
            "      change (evalNormalizedRegisters originalState\n"
            f"        {original_product_behavior}.registers).get register =\n"
            "          originalState.registers.get register\n"
            f"      rw [evalNormalizedRegisters_get,\n"
            f"        {original_product_behavior}RegistersGet]\n"
            "      rfl)\n"
            "    (by\n"
            "      intro register\n"
            "      change (evalNormalizedRegisters candidateState\n"
            f"        {candidate_product_behavior}.registers).get register =\n"
            "          candidateState.registers.get register\n"
            f"      rw [evalNormalizedRegisters_get,\n"
            f"        {candidate_product_behavior}RegistersGet]\n"
            "      rfl)\n"
            "  have targetControlAllowed : productControlProfile.Allows\n"
            f"      {int(edge['target_node_id'])} calls frameOffsets = true := by\n"
            "    simpa [productControlProfile, ProductControlProfile.Allows] using\n"
            "      controlMember\n"
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
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item["target"])
            for item in frame_claims
        ) + "]"
        return (
            prefix
            + f"  have controlShape : calls = {calls_literal} ∧\n"
            f"      frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
            f"  let frameClaims : List ReturnSlotFrameInventoryTransferClaim :=\n"
            f"    {frame_claims_literal}\n"
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
            "    simpa [originalBehaviorSegment, candidateBehaviorSegment] using\n"
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
            + _lean_acceptance_running_target(
                node_id=node_id,
                region_index=region_index,
                edge=edge,
                frames="frames",
                calls=calls_literal,
                frame_offsets=target_offsets_literal,
                stack_targets_proof="stackTargetsReachable",
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
        f"  have controlShape : calls = {branch_calls_literal} ∧\n"
        f"      frameOffsets = {branch_source_offsets_literal} := by\n"
        "    simpa [productControlProfile] using controlMember.2\n"
        "  rcases controlShape with ⟨rfl, rfl⟩\n"
    )

    def branch_case(edge: dict[str, Any], condition: bool) -> str:
        edge_id = int(edge["edge_id"])
        target_region_index = int(edge["target_region_index"])
        condition_literal = "true" if condition else "false"
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
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in edge["target_control_state"]["frame_offsets"]
        ) + "]"
        stack_proof = (
            "    let frameClaims : List "
            "ReturnSlotFrameInventoryTransferClaim :=\n"
            f"      {frame_claims_literal}\n"
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
            "        (by simpa [frameClaims] using stackHolds) statesRelated"
        )
        target_proof = "\n".join(
            "  " + line
            for line in _lean_acceptance_running_target(
                node_id=node_id, region_index=region_index, edge=edge,
                frames="frames", calls=branch_calls_literal,
                frame_offsets=target_offsets_literal,
                stack_targets_proof="stackTargetsReachable",
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
            f"        candidateState = {condition_literal} := by\n"
            "      exact normalizedBranchCondition_eval_of_guard_true\n"
            f"        {candidate_condition_name}\n"
            f"        segmentRefinementEdge{edge_id}Spec.candidateGuard\n"
            f"        {condition_literal} candidateState (by decide) candidateGuard\n"
            f"    have transitioned := transition{edge_id}.2 originalGuard\n"
            "    have nextStatesRelated : StateRel staticProofContext world\n"
            f"        region{target_region_index}.inputInvariant\n"
            f"        (({original_behavior}.eval originalState).nextMachineState\n"
            "          originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "          candidateState) := by\n"
            "      simpa [originalBehaviorSegment, candidateBehaviorSegment] using\n"
            "        transitioned.2.2.2\n"
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
        step["kind"] in {
            "external_call", "external_protocol", "external_jump", "external_terminate"
        }
        for step in plan["node_steps"]
    )
    parameterized_protocol_environment = any(
        step["kind"] == "external_protocol" for step in plan["node_steps"]
    )
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
    context_source = (
        "import StageA.RelationalCertificates\n"
        "import StageA.RelationalProofStaticUsageCertificate\n"
        "import StageA.RelationalSegmentRefinementCertificate\n"
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
        "def protocolCallbackTargets : ProtocolCallbackTargetProfile := {\n"
        f"  states := [{callback_target_rows}]\n"
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
                f"{running} originalEnvironment candidateEnvironment "
                + (
                    "originalProtocolEnvironment candidateProtocolEnvironment "
                    if parameterized_protocol_environment else ""
                )
                + "environmentRefines"
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
                parameterized_protocol_environment=parameterized_protocol_environment,
            ))
            if "callback_profile_index" in step:
                definitions.append(_lean_acceptance_callback_return_node(
                    step,
                    parameterized_environment=parameterized_environment,
                    parameterized_protocol_environment=parameterized_protocol_environment,
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
        edge_ids.sort()
        edge_theorems = [
            f"acceptanceExecutionEdge{edge_id}Refined"
            for edge_id in edge_ids
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
                "candidateEnvironment "
                + (
                    "originalProtocolEnvironment candidateProtocolEnvironment "
                    if parameterized_protocol_environment else ""
                )
                + "environmentRefines"
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
    running_proof = _lean_appended_proof(
        chunks, "allListedRunningProductNodesRefined_append",
        "staticProofContext relationalProductGraph productInvariantTable "
        "relationalProductReachabilityEvidence productControlProfile "
        "protocolCallbackTargets "
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
                "  launchControlAllowed := by decide\n"
                "  runningProductNodesRefined := allAcceptanceRunningNodesRefined\n"
                "    originalEnvironment candidateEnvironment originalProtocolEnvironment\n"
                "    candidateProtocolEnvironment environmentRefines\n"
                "  callbackRunningProductNodesRefined :=\n"
                "    allAcceptanceCallbackRunningNodesRefined originalEnvironment\n"
                "      candidateEnvironment originalProtocolEnvironment\n"
                "      candidateProtocolEnvironment environmentRefines\n"
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
                "    PE32ProgramsObservationallyEquivalent staticProofContext\n"
                "      relationalProductGraph productInvariantTable\n"
                "      relationalProductReachabilityEvidence productControlProfile consoleLaunch\n"
                "      (originalWorldProgram originalEnvironment originalProtocolEnvironment)\n"
                "      (candidateWorldProgram candidateEnvironment candidateProtocolEnvironment) := by\n"
                "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
                "    pe32ProgramsEquivalent staticProofContext relationalProductGraph allRegions\n"
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
            "}\n\n"
            "theorem candidatePE32ProgramsEquivalent :\n"
            "    PE32ProgramsObservationallyEquivalent staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile consoleLaunch\n"
            "      originalWorldProgram candidateWorldProgram := by\n"
            "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "    pe32ProgramsEquivalent staticProofContext relationalProductGraph allRegions\n"
            "      productInvariantTable relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets externalCallSites\n"
            "      consoleLaunch inertWorldEnvironment inertWorldEnvironment\n"
            "      inertWorldProtocolEnvironment inertWorldProtocolEnvironment\n"
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
        + callback_closure_source
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
        "    consoleLaunch.Valid staticProofContext relationalProductGraph\n"
        "      productInvariantTable := by\n"
        f"  refine ⟨relationalProductGraph.nodes[{root_node_id}],\n"
        "    (by decide), ?_, ?_, ?_, ?_, ?_, ?_⟩\n"
        "  all_goals decide\n\n"
        + acceptance_certificate_source
        + "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(stage_a / "RelationalAcceptance.lean", final_source)
    return plan
