from __future__ import annotations

from typing import Any

from .schema import REGISTERS


def _nonzero_word_guard(expression: dict[str, Any]) -> dict[str, Any]:
    return {
        "op": "not",
        "value": {
            "op": "equal",
            "left": {
                "op": "bit_and", "left": expression, "right": expression,
            },
            "right": {"op": "constant", "value": 0},
        },
    }

def _read32_input_register_offset(
    expression: dict[str, Any],
) -> tuple[str, int] | None:
    if expression.get("op") != "read32":
        return None
    address = expression.get("address") or {}
    if address.get("op") == "input_reg":
        return str(address["reg"]), 0
    if address.get("op") != "add":
        return None
    left = address.get("left") or {}
    right = address.get("right") or {}
    if left.get("op") == "constant" and right.get("op") == "input_reg":
        left, right = right, left
    if left.get("op") != "input_reg" or right.get("op") != "constant":
        return None
    return str(left["reg"]), int(right["value"]) & 0xFFFFFFFF

def _dynamic_pointer_traversal_diagnostic(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    register_relations: dict[str, Any],
    edge: dict[str, Any],
    source_index: int,
    target_index: int,
) -> dict[str, Any] | None:
    register_regions = register_relations.get("regions", [])
    if source_index >= len(register_regions) or source_index >= len(behaviors):
        return None
    original_registers = behaviors[source_index]["original_ir"].get("registers") or {}
    candidate_registers = behaviors[source_index]["candidate_ir"].get("registers") or {}
    source = contract["regions"][source_index]
    target = contract["regions"][target_index]
    diagnostics: list[dict[str, Any]] = []
    for output in register_regions[source_index].get("outputs", []):
        if output.get("relation") != "related_word":
            continue
        original_output = str(output["original"])
        candidate_output = str(output["candidate"])
        original_expression = original_registers.get(original_output) or {}
        candidate_expression = candidate_registers.get(candidate_output) or {}
        original_read = _read32_input_register_offset(original_expression)
        candidate_read = _read32_input_register_offset(candidate_expression)
        if original_read is None or candidate_read is None:
            continue
        if original_read[1] != candidate_read[1]:
            continue
        original_source, word_offset = original_read
        candidate_source = candidate_read[0]
        guard_matches = (
            edge.get("original_guard") == _nonzero_word_guard(original_expression)
            and edge.get("candidate_guard") == _nonzero_word_guard(candidate_expression)
        )
        source_matches = [
            relation for relation in source.get("input_dynamic_range_relations", [])
            if str(relation["original"]) == original_source
            and str(relation["candidate"]) == candidate_source
            and int(relation.get("original_offset", -1)) == 0
            and int(relation.get("candidate_offset", -1)) == 0
            and {
                "offset": word_offset, "kind": "nullableDynamicPointer",
            } in relation.get("required_words", [])
        ]
        target_matches = [
            relation for relation in target.get("input_dynamic_range_relations", [])
            if str(relation["original"]) == original_output
            and str(relation["candidate"]) == candidate_output
            and int(relation.get("original_offset", -1)) == 0
            and int(relation.get("candidate_offset", -1)) == 0
        ]
        if not source_matches and not target_matches:
            continue
        if not guard_matches and not target_matches:
            continue
        shape_matches = 0
        if len(source_matches) == 1:
            source_words = {
                (int(word["offset"]), str(word["kind"]))
                for word in source_matches[0].get("required_words", [])
            }
            shape_matches = sum(
                {
                    (int(word["offset"]), str(word["kind"]))
                    for word in relation.get("required_words", [])
                } <= source_words
                for relation in target_matches
            )
        blockers = []
        if len(source_matches) != 1:
            blockers.append("source_nullable_pointer_relation_not_unique")
        if len(target_matches) != 1:
            blockers.append("successor_dynamic_range_relation_not_unique")
        elif shape_matches != 1:
            blockers.append("successor_range_shape_not_preserved")
        if not guard_matches:
            blockers.append("paired_nonzero_guard_not_exact")
        diagnostics.append({
            "profile": "paired_nullable_dynamic_pointer_traversal_v1",
            "original_source_register": original_source,
            "candidate_source_register": candidate_source,
            "original_output_register": original_output,
            "candidate_output_register": candidate_output,
            "word_offset": word_offset,
            "source_relation_matches": len(source_matches),
            "target_relation_matches": len(target_matches),
            "shape_matches": shape_matches,
            "guard_matches": guard_matches,
            "blockers": blockers,
        })
    if len(diagnostics) != 1:
        return None
    diagnostic = diagnostics[0]
    diagnostic["status"] = (
        "ready_for_lean_replay" if not diagnostic["blockers"] else "incomplete"
    )
    diagnostic["next_action"] = (
        "replay the checked nullable dynamic-pointer load, nonzero guard, range-shape "
        "preservation, and successor register relation in Lean"
        if not diagnostic["blockers"] else
        f"classify original {diagnostic['original_source_register']} and candidate "
        f"{diagnostic['candidate_source_register']} as one unique dynamic range, mark "
        f"word offset {diagnostic['word_offset']} nullableDynamicPointer, propagate the "
        f"same required-word shape to original {diagnostic['original_output_register']} "
        f"and candidate {diagnostic['candidate_output_register']} at the successor, and "
        "use the exact paired nonzero branch guard"
    )
    return diagnostic

def _static_dynamic_pointer_seed_diagnostic(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    register_relations: dict[str, Any],
    edge: dict[str, Any],
    source_index: int,
    target_index: int,
) -> dict[str, Any] | None:
    if source_index >= len(behaviors):
        return None
    register_regions = register_relations.get("regions", [])
    if source_index >= len(register_regions):
        return None
    source_registers = register_regions[source_index]
    original_registers = behaviors[source_index]["original_ir"].get("registers") or {}
    candidate_registers = behaviors[source_index]["candidate_ir"].get("registers") or {}
    target_relations = contract["regions"][target_index].get(
        "input_dynamic_range_relations", []
    )
    matches: list[dict[str, Any]] = []
    for output in source_registers.get("outputs", []):
        if output.get("relation") != "related_word":
            continue
        target_matches = [
            relation for relation in target_relations
            if relation["original"] == output["original"]
            and relation["candidate"] == output["candidate"]
            and int(relation.get("original_offset", -1)) == 0
            and int(relation.get("candidate_offset", -1)) == 0
        ]
        if len(target_matches) != 1:
            continue
        original_expression = original_registers.get(output["original"]) or {}
        candidate_expression = candidate_registers.get(output["candidate"]) or {}
        if (
            original_expression.get("op") != "read32"
            or candidate_expression.get("op") != "read32"
            or (original_expression.get("address") or {}).get("op") != "constant"
            or (candidate_expression.get("address") or {}).get("op") != "constant"
        ):
            continue
        original_address = int(original_expression["address"]["value"])
        candidate_address = int(candidate_expression["address"]["value"])
        slots = [
            slot for slot in contract.get("static_dynamic_pointer_slots", [])
            if int(slot["original_address"]) == original_address
            and int(slot["candidate_address"]) == candidate_address
        ]
        guard_kind = None
        if (
            edge.get("original_guard") == _nonzero_word_guard(original_expression)
            and edge.get("candidate_guard") == _nonzero_word_guard(candidate_expression)
        ):
            guard_kind = "nonzero"
        elif (
            edge.get("original_guard") == _nonzero_word_guard(original_expression)["value"]
            and edge.get("candidate_guard") == _nonzero_word_guard(candidate_expression)["value"]
        ):
            guard_kind = "zero"
        required_words = target_matches[0].get("required_words", [])
        slot_shape_matches = sum(
            {
                (int(word["offset"]), str(word["kind"]))
                for word in required_words
            } <= {
                (int(word["offset"]), str(word["kind"]))
                for word in slot.get("required_words", [])
            }
            for slot in slots
        )
        blockers: list[str] = []
        if len(slots) != 1:
            blockers.append("static_dynamic_pointer_slot_not_unique")
        elif slot_shape_matches != 1:
            blockers.append("static_dynamic_pointer_slot_shape_insufficient")
        if guard_kind != "nonzero":
            blockers.append("paired_nonzero_static_pointer_guard_not_exact")
        matches.append({
            "profile": "paired_static_dynamic_pointer_seed_v1",
            "original_address": original_address,
            "candidate_address": candidate_address,
            "original_output_register": output["original"],
            "candidate_output_register": output["candidate"],
            "required_words": required_words,
            "slot_matches": len(slots),
            "slot_shape_matches": slot_shape_matches,
            "guard_kind": guard_kind,
            "blockers": blockers,
        })
    if len(matches) != 1:
        return None
    diagnostic = matches[0]
    diagnostic["status"] = (
        "ready_for_lean_replay" if not diagnostic["blockers"] else "incomplete"
    )
    diagnostic["next_action"] = (
        "replay the checked writable-PE pointer slot, nonzero guard, dynamic-range "
        "shape, and loaded-register relation in Lean"
        if not diagnostic["blockers"] else
        "declare one static_dynamic_pointer_slots entry for original address "
        f"0x{diagnostic['original_address']:08x} and candidate address "
        f"0x{diagnostic['candidate_address']:08x}, give it the successor's required "
        "dynamic word shape, and retain the exact paired nonzero branch guard"
    )
    return diagnostic

def _complete_counterexample_assignment(region: dict[str, Any], assignment: dict[str, int]) -> dict[str, int]:
    completed = {
        f"{side}{register}": assignment.get(f"{side}{register}", 0)
        for side in ("o", "c")
        for register in REGISTERS
    }
    for pair in region["inputs"]:
        completed[f"c{pair['candidate']}"] = completed[f"o{pair['original']}"]
    return completed
