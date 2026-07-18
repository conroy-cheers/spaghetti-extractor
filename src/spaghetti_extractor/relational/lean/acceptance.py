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
    _machine_import_call_contract_identity,
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
from ..analyses.segments import _import_register_transfer_claims
from ..analyses.stack import _stack_window_transfer_claims
from ..analyses.registers import (
    _propose_internal_callsite_preservation_summaries,
)
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
    _lean_region_input_invariant,
    _normalized_behavior_fast_path,
)
from .common import _lean_register_relation_pair
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
    launch_profile: dict[str, Any] | None = None,
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
    if launch_root_node_id is not None and len(nodes) == len(behaviors):
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

        def internal_frame_relations_preserved(
            node_id: int,
            frame_relation_inventories: tuple[tuple[str, ...], ...],
        ) -> bool:
            original = behaviors[node_id].get("original_ir") or {}
            candidate = behaviors[node_id].get("candidate_ir") or {}
            for relation_key in (
                relation_key
                for inventory in frame_relation_inventories
                for relation_key in inventory
            ):
                if not register_relation_behavior_preserved(
                    relation_key, original, candidate
                ):
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
        ) -> dict[str, Any]:
            payload = {
                "locations": [location_payload(location) for location in locations],
            }
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
            source_imports: tuple[tuple[str, ...], ...] | None = None,
            target_imports: tuple[tuple[str, ...], ...] | None = None,
            source_relations: tuple[tuple[str, ...], ...] | None = None,
            target_relations: tuple[tuple[str, ...], ...] | None = None,
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
            if (
                len(source_imports) != len(source_inventories)
                or len(target_imports) != len(target_inventories)
                or len(source_relations) != len(source_inventories)
                or len(target_relations) != len(target_inventories)
            ):
                return None
            relation_row = register_relations.get("regions", [])[source_node_id]
            local_rules = relation_row.get(
                "return_slot_local_transfer_rules", []
            )
            original = behaviors[source_node_id].get("original_ir") or {}
            candidate = behaviors[source_node_id].get("candidate_ir") or {}
            inventory_claims = []
            for source_inventory, target_inventory, source_frame_imports, \
                    target_frame_imports, source_frame_relations, \
                    target_frame_relations in zip(
                source_inventories, target_inventories, source_imports,
                target_imports, source_relations, target_relations, strict=True
            ):
                if (
                    source_frame_imports != target_frame_imports
                    or source_frame_relations != target_frame_relations
                ):
                    return None
                for relation_key in source_frame_imports:
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
                for relation_key in source_frame_relations:
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
                    "source": inventory_payload(
                        source_inventory, source_frame_imports,
                        source_frame_relations,
                    ),
                    "target": inventory_payload(
                        target_inventory, target_frame_imports,
                        target_frame_relations,
                    ),
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
            tuple[tuple[str, ...], ...],
            tuple[tuple[str, ...], ...],
        ]] = [(
            launch_root_node_id,
            tuple(launch_continuation_target_ids),
            launch_frame_inventories,
            tuple(() for _ in launch_continuation_target_ids),
            tuple(() for _ in launch_continuation_target_ids),
        )]
        seen: set[tuple[
            int, tuple[int, ...],
            tuple[tuple[tuple[str, int, str, int], ...], ...],
            tuple[tuple[str, ...], ...],
            tuple[tuple[str, ...], ...],
        ]] = set()
        while pending:
            (
                node_id, calls, frame_inventories, frame_imports,
                frame_relations,
            ) = pending.pop(0)
            key = (
                node_id, calls, frame_inventories, frame_imports,
                frame_relations,
            )
            if key in seen:
                continue
            if len(seen) >= 512 or len(calls) > 32:
                block(
                    "finite_control_profile_exceeded",
                    "the rooted call-stack control profile is recursive or exceeds its finite bound",
                    "add an inductive checked control-stack profile for recursion",
                )
                break
            seen.add(key)
            if (
                len(frame_inventories) != len(calls)
                or len(frame_imports) != len(calls)
                or len(frame_relations) != len(calls)
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
                    inventory_payload(inventory, imports, relations)
                    for inventory, imports, relations in zip(
                        frame_inventories, frame_imports, frame_relations,
                        strict=True,
                    )
                ],
            }
            control_states.append(state)
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
                if original_constant != candidate_constant:
                    state_incomplete = True
                    fields = ()
                elif original_constant is True:
                    fields = ("taken",)
                elif original_constant is False:
                    fields = ("fallthrough",)
                else:
                    fields = ("taken", "fallthrough")
                for field in fields:
                    if original_outcome.get(field) != candidate_outcome.get(field):
                        state_incomplete = True
                        break
                    successor_targets.append((
                        int(original_outcome[field]), calls, "transfer",
                    ))
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
                if any(frame_imports):
                    block(
                        "runtime_frame_import_external_crossing_unsupported",
                        f"external call node {node_id} crosses an active preserved-"
                        "import runtime frame",
                        "supply an environment-aware preservation theorem before "
                        "crossing the external boundary",
                    )
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
                if any(frame_imports):
                    block(
                        "runtime_frame_import_external_crossing_unsupported",
                        f"external jump node {node_id} crosses an active preserved-"
                        "import runtime frame",
                        "use a checked internal return or add an environment-aware "
                        "preservation theorem",
                    )
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
                if (
                    decoded_control.get("profile") not in {
                        "immutable_relocated_function_pointer_call_v1",
                        "fixed_static_function_pointer_call_v1",
                        "inductive_fixed_code_pointer_register_call_v1",
                    }
                    or original_outcome.get("continuation") !=
                        candidate_outcome.get("continuation")
                ):
                    block(
                        "bounded_indirect_control_profile_unmet",
                        f"product node {node_id} has no checked finite indirect-call target",
                        "classify the target by provenance and emit a checked finite target set",
                    )
                    state_incomplete = True
                else:
                    continuation = int(original_outcome["continuation"])
                    successor_targets.append((
                        int(decoded_control["target_id"]),
                        (continuation, *calls),
                        "call",
                    ))
            elif operation == "indirect_jump":
                decoded_control = decoded_control_by_node.get(node_id, {})
                if decoded_control.get("profile") not in {
                    "immutable_relocated_function_pointer_jump_v1",
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
                        node_id, frame_relations
                    ):
                        state_incomplete = True
                        break
                    successor_locations = transfer_locations(
                        node_id, target_node_id, frame_inventories
                    )
                    successor_imports = frame_imports
                    successor_relations = frame_relations
                    if successor_locations is None:
                        state_incomplete = True
                        break
                elif frame_operation == "call":
                    if not internal_frame_relations_preserved(
                        node_id, frame_relations
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
                    successor_relations = (seeded_relations, *frame_relations)
                elif frame_operation == "return_pop":
                    if not internal_frame_relations_preserved(
                        node_id, frame_relations
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
                else:
                    successor_locations = external_transfer_locations(
                        node_id, target_node_id, frame_inventories
                    )
                    if successor_locations is None:
                        state_incomplete = True
                        break
                    successor_imports = frame_imports
                    successor_relations = frame_relations
                pending.append((
                    target_node_id, successor_calls, successor_locations,
                    successor_imports, successor_relations,
                ))

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
                                    inventory_register_key(source_inventory)),
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
                return_cases: list[dict[str, Any]] = []
                return_cases_complete = True
                for control_row in control_rows:
                    calls = list(control_row["calls"])
                    active_inventory_payload = control_row["frame_offsets"][0]
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
                    target_output_claims = _target_shaped_register_output_claims(
                        relation_row, {
                            **target_relation_row,
                            "inputs": residual_target_inputs,
                        }
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
                    unsupported_target_families = [
                        field for field in (
                            "bounds",
                            "address_separations",
                            "flag_inputs",
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
                call_cases: list[dict[str, Any]] = []
                call_cases_complete = True
                for control_row in control_rows:
                    source_locations = tuple(
                        inventory_key(item)
                        for item in control_row["frame_offsets"]
                    )
                    target_control_rows = [
                        row for row in control_states_by_node.get(
                            target_node_id, []
                        )
                        if row["calls"] == [
                            continuation, *control_row["calls"]
                        ]
                        and inventory_key(row["frame_offsets"][0]) == (
                            ("esp", 0, "esp", 0),
                        )
                        and inventory_import_key(row["frame_offsets"][0])
                            == seeded_imports
                        and inventory_register_key(row["frame_offsets"][0])
                            == seeded_relations
                    ]
                    if len(target_control_rows) != 1:
                        block(
                            "direct_call_target_control_state_missing",
                            f"call node {node_id} control state has no unique "
                            "checked successor state",
                            "regenerate rooted control closure from the checked call transfer",
                        )
                        call_cases_complete = False
                        break
                    target_control_row = target_control_rows[0]
                    target_inventories = tuple(
                        inventory_key(item)
                        for item in target_control_row["frame_offsets"][1:]
                    )
                    selected_claims = internal_transfer_claims(
                        node_id, source_locations, target_inventories,
                        tuple(
                            inventory_import_key(item)
                            for item in control_row["frame_offsets"]
                        ),
                        tuple(
                            inventory_import_key(item)
                            for item in target_control_row["frame_offsets"][1:]
                        ),
                        tuple(
                            inventory_register_key(item)
                            for item in control_row["frame_offsets"]
                        ),
                        tuple(
                            inventory_register_key(item)
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
                        "seeded_frame_inventory": target_control_row[
                            "frame_offsets"
                        ][0],
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
                        selected_claims.append({
                            "profile":
                                "external_return_slot_inventory_transfer_v1",
                            "source": source_payload,
                            "target": target_payload,
                            "transfers": transfers,
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
                if len(external_cases) == 1:
                    step.update(external_cases[0])
                else:
                    step["cases"] = external_cases
                has_external_call = True
            elif jump_profile:
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
                planned_edges.append({
                    "edge_id": int(edge["id"]),
                    "branch_value": edge.get("kind") == "branchTaken",
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
                    "target_node_id": int(edge["target_node_id"]),
                    "target_region_index": int(edge["target_node_id"]),
                    "target_target_id": int(edge["target_target_id"]),
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
            "control_states": control_states,
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
                    inventory_payload(inventory, ())
                    for inventory in launch_frame_inventories
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
        "control_states": control_states,
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
                inventory_payload(inventory, ())
                for inventory in launch_frame_inventories
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
        + preserved_imports_field
        + preserved_relations_field
        + " } : ReturnSlotOffsetInventory)"
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

def _lean_runtime_call_import_transfer_claim(
    source: dict[str, Any], target: dict[str, Any],
) -> str:
    return (
        "{ source := " + _lean_return_slot_offset_inventory(source)
        + ", target := " + _lean_return_slot_offset_inventory(target)
        + " }"
    )

def _lean_runtime_call_import_transfer_claims(
    claims: list[dict[str, Any]],
) -> str:
    return "[" + ", ".join(
        _lean_runtime_call_import_transfer_claim(
            claim["source"], claim["target"]
        )
        for claim in claims
    ) + "]"

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
        "    controlAllowed stackHolds frameImportsHold stackTargetsReachable statesRelated\n"
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
            "  have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"        candidateState) (runtimeFrame :: frames)\n"
            f"      ({continuation} :: {source_calls_literal})\n"
            f"      (activeFrameInventory :: {target_offsets_literal}) := by\n"
            "    simp only [RelationalRuntimeCallStackHolds]\n"
            "    exact ⟨rfl, frameValid, frameResolves, frameMemory,\n"
            "      activeFrameInventoryHolds,\n"
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
            "        (by simpa [outerFrameClaims] using stackHolds.2.2.2.2.2)\n"
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
            f"        (by simp [RegionRelation.inputInvariant, region{target_region_index},\n"
            "          pairedStatePredicatesHold])\n"
            "    have stackHoldsNext := outerStackHolds\n"
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
        common = (
            prefix
            + selected_control
            + f"  let frameClaims : List ExternalReturnSlotInventoryTransferClaim := "
            f"{transfer_claims_literal}\n"
            + "  let frameFactClaims : List "
            "RelationalRuntimeCallImportTransferClaim := "
            f"{frame_fact_claims_literal}\n"
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
            "  have frameFactsAtBoundary : RelationalRuntimeCallFactsHold\n"
            "      staticProofContext world\n"
            f"      {target_offsets_literal} originalEvent.state.registers\n"
            "      candidateEvent.state.registers := by\n"
            "    have transferred := RelationalRuntimeCallFactsHold.afterInternal\n"
            f"      staticProofContext world {original_behavior} {candidate_behavior}\n"
            "      frameFactClaims originalState candidateState (by decide)\n"
            "      (by simpa [frameFactClaims] using frameImportsHold)\n"
            "    simpa [originalEvent, candidateEvent,\n"
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
) -> dict[str, Any]:
    stage_a = lean_dir / "StageA"
    for path in [
        *stage_a.glob("RelationalAcceptance*.lean"),
        *stage_a.glob("RelationalAcceptance*.olean"),
        *stage_a.glob("RelationalLaunch*.lean"),
        *stage_a.glob("RelationalLaunch*.olean"),
    ]:
        path.unlink()
    plan = _whole_program_acceptance_plan(
        contract, behaviors, product_graph, register_relations, segment_candidates,
        external_site_candidates,
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
        identity_inputs = all(
            relation.get("original") == relation.get("candidate")
            and relation.get("relation") == "exact"
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
        if not identity_inputs:
            launch_reasons.append("root register relations are not exact identities")
        for key in (
            "input_import_relations",
            "input_dynamic_range_relations",
            "input_dynamic_stack_range_relations",
            "bounds",
            "address_separations",
            "state_predicates",
        ):
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
    root_invariant = _lean_region_input_invariant(root_region)
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
    launch_definition_source = (
        "import StageA.RelationalCertificates\n"
        "import StageA.RelationalProductGraphContext\n\n"
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
    context_source = (
        "import StageA.RelationalCertificates\n"
        "import StageA.RelationalLaunchDefinition\n"
        "import StageA.RelationalProofClosureBase\n"
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
        + world_program_source
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

    def lean_concrete_writes(writes: list[tuple[int, int]]) -> str:
        return ", ".join(
            "(BitVec.ofNat 32 " + str(address)
            + ", BitVec.ofNat 32 " + str(value) + ")"
            for address, value in writes
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
        "def consoleLaunchOriginalWrites : List (Word × Word) := ["
        + lean_concrete_writes(original_launch_writes) + "]\n\n"
        "def consoleLaunchCandidateWrites : List (Word × Word) := ["
        + lean_concrete_writes(candidate_launch_writes) + "]\n\n"
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
        "def consoleLaunchCandidateImageMappedAt : Nat -> Bool :=\n"
        "  preferredBaseImageMemoryAt staticProofContext.candidatePe\n"
        "    staticProofContext.candidateImports consoleLaunchCandidateState.memory\n\n"
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
    launch_leaf_modules: list[str] = []

    def write_launch_span_leaves(
        *,
        module_prefix: str,
        theorem_prefix: str,
        spans: list[tuple[int, int]],
        predicate: str,
    ) -> list[tuple[int, int, list[tuple[str, int, int]]]]:
        checked_spans: list[tuple[int, int, list[tuple[str, int, int]]]] = []
        leaf_index = 0
        for span_start, span_size in spans:
            checked_ranges: list[tuple[str, int, int]] = []
            for relative_start, count in _launch_check_ranges(
                span_size, launch_chunk_size
            ):
                start = span_start + relative_start
                module = f"{module_prefix}{leaf_index}"
                theorem_name = f"{theorem_prefix}{leaf_index}"
                source = (
                    "import StageA.RelationalLaunchContext\n\n"
                    "namespace StageA.GeneratedRelational\n\n"
                    "open StageA.Formal StageA.Relational\n\n"
                    "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
                    f"theorem {theorem_name} :\n"
                    f"    IndexedBoolRangeHolds {predicate} "
                    f"{{ start := {start}, size := {count} }} := by\n"
                    "  apply indexedBoolRangeHolds_of_checked\n"
                    "  decide\n\n"
                    "end StageA.GeneratedRelational\n"
                )
                _write_text_if_changed(stage_a / f"{module}.lean", source)
                launch_leaf_modules.append(module)
                checked_ranges.append((theorem_name, start, count))
                leaf_index += 1
            checked_spans.append((span_start, span_size, checked_ranges))
        return checked_spans

    def write_launch_leaves(
        *, module_prefix: str, theorem_prefix: str, total: int, predicate: str
    ) -> list[tuple[str, int, int]]:
        return write_launch_span_leaves(
            module_prefix=module_prefix,
            theorem_prefix=theorem_prefix,
            spans=[(0, total)],
            predicate=predicate,
        )[0][2]

    def mapped_image_spans(binary: StageABinary) -> list[tuple[int, int]]:
        return [(0, binary.size_of_headers)] + [
            (section.rva_start, section.rva_end - section.rva_start)
            for section in binary.sections
        ]

    original_image_spans = write_launch_span_leaves(
        module_prefix="RelationalLaunchOriginalImageMappedLeaf",
        theorem_prefix="consoleLaunchOriginalImageMappedRange",
        spans=mapped_image_spans(original_bin),
        predicate="consoleLaunchOriginalImageMappedAt",
    )
    candidate_image_spans = write_launch_span_leaves(
        module_prefix="RelationalLaunchCandidateImageMappedLeaf",
        theorem_prefix="consoleLaunchCandidateImageMappedRange",
        spans=mapped_image_spans(candidate_bin),
        predicate="consoleLaunchCandidateImageMappedAt",
    )
    stack_ranges = write_launch_leaves(
        module_prefix="RelationalLaunchStackMemoryLeaf",
        theorem_prefix="consoleLaunchStackMemoryRange",
        total=stack_size,
        predicate="consoleLaunchStackMemoryAt",
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

    def combined_span_proof(
        predicate: str, chunks: list[tuple[str, int, int]]
    ) -> str:
        if not chunks:
            raise StageAInputError("mapped launch span cannot be empty")
        proof, start, size = chunks[0]
        for next_proof, next_start, next_size in chunks[1:]:
            proof = (
                f"indexedBoolRangeHolds_append {predicate} "
                f"{{ start := {start}, size := {size} }} "
                f"{{ start := {next_start}, size := {next_size} }} "
                f"(by decide) ({proof}) ({next_proof})"
            )
            size += next_size
        return proof

    def mapped_spans_proof(
        predicate: str,
        spans: list[tuple[int, int, list[tuple[str, int, int]]]],
    ) -> str:
        return _lean_all_listed_proof([
            combined_span_proof(predicate, chunks)
            for _start, _size, chunks in spans
        ])

    def lean_span_list(
        spans: list[tuple[int, int, list[tuple[str, int, int]]]],
    ) -> str:
        return "[" + ", ".join(
            f"{{ start := {start}, size := {size} }}"
            for start, size, _chunks in spans
        ) + "]"

    original_image_range_proof = mapped_spans_proof(
        "consoleLaunchOriginalImageMappedAt", original_image_spans
    )
    candidate_image_range_proof = mapped_spans_proof(
        "consoleLaunchCandidateImageMappedAt", candidate_image_spans
    )
    stack_range_proof = _lean_all_listed_proof([
        theorem for theorem, _start, _count in stack_ranges
    ])
    static_word_slot_range_proof = _lean_all_listed_proof([
        theorem for theorem, _start, _count in static_word_slot_ranges
    ])

    launch_checks_source = (
        "".join(f"import StageA.{module}\n" for module in launch_leaf_modules)
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
        "  apply preferredBaseImageMemory_of_mapped_ranges\n"
        "  have rangesHold : AllIndexedBoolRangesHold\n"
        "      consoleLaunchOriginalImageMappedAt\n"
        "      (mappedImageSpans staticProofContext.originalPe) := by\n"
        "    change AllIndexedBoolRangesHold consoleLaunchOriginalImageMappedAt "
        + lean_span_list(original_image_spans) + "\n"
        f"    exact {original_image_range_proof}\n"
        "  simpa [consoleLaunchOriginalImageMappedAt] using rangesHold\n\n"
        "theorem consoleLaunchCandidateImageMapped :\n"
        "    PreferredBaseImageMemory staticProofContext.candidatePe\n"
        "      staticProofContext.candidateImports consoleLaunchCandidateState.memory := by\n"
        "  apply preferredBaseImageMemory_of_mapped_ranges\n"
        "  have rangesHold : AllIndexedBoolRangesHold\n"
        "      consoleLaunchCandidateImageMappedAt\n"
        "      (mappedImageSpans staticProofContext.candidatePe) := by\n"
        "    change AllIndexedBoolRangesHold consoleLaunchCandidateImageMappedAt "
        + lean_span_list(candidate_image_spans) + "\n"
        f"    exact {candidate_image_range_proof}\n"
        "  simpa [consoleLaunchCandidateImageMappedAt] using rangesHold\n\n"
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
        f"      exact {stack_range_proof}\n"
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
        f"    exact {static_word_slot_range_proof}\n"
        "  have checked := IndexedBoolCertificate.holds_of_ranges\n"
        "    consoleLaunchStaticWordSlotAt staticProofContext.staticWordRelationSlots.length\n"
        "    consoleLaunchStaticWordSlotCertificate (by decide) rangesHold\n"
        "  simpa [consoleLaunchStaticWordSlotAt] using checked\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalLaunchCheckCertificate.lean", launch_checks_source
    )

    launch_realizability_source = (
        "import StageA.RelationalLaunchCheckCertificate\n\n"
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
        "  · refine ⟨by decide, by decide, by decide, by decide, ?_, ?_, rfl, rfl,\n"
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
        "    ReturnSlotOffsetInventory.holds, ReturnSlotOffsetPair.holds,\n"
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
        "end StageA.GeneratedRelational\n"
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
        1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_ACCEPTANCE_CHUNK", "2"))
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
        edge_theorems: list[str] = []
        for step in selected:
            node_id = int(step["node_id"])
            region_index = int(step["region_index"])
            target_id = int(step["target_id"])
            decode_chunk = decode_chunk_by_region[region_index]
            running = f"acceptanceRunningNode{node_id}Refined"
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
        "  refine ⟨by decide, by decide, by decide, by decide, by decide,\n"
        "    by decide, by decide, ?_, ?_, ⟨by decide, by decide⟩⟩\n"
        f"  · exact ⟨relationalProductGraph.nodes[{entry_root_node_id}], by decide,\n"
        "      by decide, by decide, by decide, by decide⟩\n"
        f"  · exact ⟨relationalProductGraph.nodes[{root_node_id}], by decide,\n"
        "      by decide, by decide, by decide, by decide⟩\n\n"
        + acceptance_certificate_source
        + "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(stage_a / "RelationalAcceptance.lean", final_source)
    return plan
