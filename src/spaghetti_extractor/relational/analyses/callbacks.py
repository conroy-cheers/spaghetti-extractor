from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..schema import ProtocolCallbackControl
from .frames import (
    return_frame_claim_for_location,
    runtime_frame_location_key,
    runtime_frame_location_payload,
)


Blocker = Callable[[str, str, str], None]


def protocol_callback_controls_by_node(
    contract: dict[str, Any],
    node_by_target: dict[int, int],
    block: Blocker,
) -> dict[int, dict[str, Any]]:
    try:
        control = ProtocolCallbackControl.parse(contract.get(
            "protocol_callback_control",
            ProtocolCallbackControl.empty().to_payload(),
        ))
    except (TypeError, ValueError):
        block(
            "protocol_callback_control_invalid",
            "the callback control inventory does not match its versioned schema",
            "normalize the relation contract before generating acceptance evidence",
        )
        return {}
    result: dict[int, dict[str, Any]] = {}
    for state in control.states:
        node_id = node_by_target.get(state.target_id)
        if node_id is None:
            block(
                "protocol_callback_target_unmapped",
                f"callback target {state.target_id} has no canonical product node",
                "map the callback entry and all callback-mode continuations into the product graph",
            )
            continue
        result[node_id] = state.to_payload()
    return result


def attach_protocol_callback_states(
    node_steps: list[dict[str, Any]],
    callback_contract_by_node: dict[int, dict[str, Any]],
    register_relations: dict[str, Any],
    block: Blocker,
) -> list[dict[str, Any]]:
    step_by_node_id = {int(step["node_id"]): step for step in node_steps}
    protocol_callback_states: list[dict[str, Any]] = []
    relation_rows = register_relations.get("regions", [])
    for node_id in sorted(callback_contract_by_node):
        callback_step = step_by_node_id.get(node_id)
        if callback_step is None or callback_step.get("kind") != "terminate":
            block(
                "callback_control_step_incomplete",
                f"callback-mode node {node_id} is not yet a checked callback return",
                "provide callback-frame offset transfer and callback-mode refinement for this node",
            )
            continue
        if node_id >= len(relation_rows):
            block(
                "callback_register_relation_missing",
                f"callback return node {node_id} has no register-relation row",
                "regenerate register relations for every callback control node",
            )
            continue
        relation_row = relation_rows[node_id]
        callback_contract_state = callback_contract_by_node[node_id]
        active_location = runtime_frame_location_key(
            callback_contract_state["active_frame_offset"]
        )
        if callback_contract_state["return_invariant"] != {"kind": "terminal"}:
            block(
                "callback_return_invariant_profile_incomplete",
                f"callback return node {node_id} uses an unsupported return invariant",
                "add checked callback-state transfer for the declared invariant reference",
            )
            continue
        active_frame_claim = return_frame_claim_for_location(
            relation_row, active_location
        )
        if active_frame_claim is None:
            block(
                "callback_return_frame_claim_missing",
                f"callback return node {node_id} does not resolve its declared active callback frame",
                "emit a checked return-pop frame claim for the callback entry return slot",
            )
            continue
        rules_by_source: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for rule in relation_row.get("return_slot_local_transfer_rules", []):
            rules_by_source.setdefault((
                str(rule["original_source_register"]),
                str(rule["candidate_source_register"]),
            ), []).append(rule)

        def rule_rank(rule: dict[str, Any]) -> tuple[Any, ...]:
            same_pair = (
                str(rule["original_source_register"])
                    == str(rule["original_target_register"])
                and str(rule["candidate_source_register"])
                    == str(rule["candidate_target_register"])
            )
            return (
                0 if same_pair else 1,
                0 if rule["original_target_register"] == "ebp" else 1,
                0 if rule["candidate_target_register"] == "ebp" else 1,
                str(rule["original_target_register"]),
                str(rule["candidate_target_register"]),
            )

        callback_rules = [
            sorted(rules, key=rule_rank)[0]
            for _source, rules in sorted(rules_by_source.items())
        ]
        if not any(
            rule["original_source_register"] == "esp"
            and rule["candidate_source_register"] == "esp"
            for rule in callback_rules
        ):
            block(
                "callback_outer_frame_transfer_incomplete",
                f"callback return node {node_id} lacks an affine ESP-pair frame transfer",
                "emit a checked local affine transfer rule for nested callback frames",
            )
            continue
        callback_step["callback_return_frame_claim"] = active_frame_claim
        callback_step["callback_outer_transfer_rules"] = callback_rules
        callback_step["callback_profile_index"] = len(protocol_callback_states)
        protocol_callback_states.append({
            "node_id": node_id,
            "active_frame_offset": runtime_frame_location_payload(active_location),
            "return_invariant": callback_contract_state["return_invariant"],
            "outer_frame_transfer_rules": callback_rules,
        })
    return protocol_callback_states
