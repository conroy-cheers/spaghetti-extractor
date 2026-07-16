from __future__ import annotations

import json
from typing import Any

from ..util import sha256_bytes


PURE_SEMANTIC_EXPR_OPERATIONS = frozenset({
    "input_reg", "input_fs_base", "constant", "undefined", "add", "sub",
    "bit_and", "bit_xor", "bit_not", "extract_byte", "shift_left",
    "shift_right", "shift_left_by", "shift_right_by",
    "shift_arithmetic_right_by", "bit_or", "if_equal",
    "unsigned_less_value", "bit_value", "multiply",
    "multiply_high_unsigned", "multiply_high_signed", "divide_quotient",
    "divide_remainder", "division_valid_value", "lowest_set_bit",
    "highest_set_bit",
})


def _semantic_hash(value: dict[str, Any]) -> str:
    return sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _semantic_constant_word(expression: dict[str, Any]) -> int | None:
    operation = expression.get("op")
    if operation == "constant":
        return int(expression["value"]) & 0xFFFFFFFF
    if operation == "sub" and expression.get("left") == expression.get("right"):
        return 0
    return None


def _semantic_constant_bool(expression: dict[str, Any]) -> bool | None:
    operation = expression.get("op")
    if operation == "bool_constant":
        return bool(expression.get("value"))
    if operation in {"equal", "unsigned_less"}:
        left = expression.get("left") or {}
        right = expression.get("right") or {}
        if operation == "equal" and left == right:
            return True
        left_value = _semantic_constant_word(left)
        right_value = _semantic_constant_word(right)
        if left_value is None or right_value is None:
            return None
        return (
            left_value == right_value
            if operation == "equal"
            else left_value < right_value
        )
    if operation == "not":
        value = _semantic_constant_bool(expression.get("value") or {})
        return None if value is None else not value
    if operation in {"and", "or", "xor"}:
        left = _semantic_constant_bool(expression.get("left") or {})
        right = _semantic_constant_bool(expression.get("right") or {})
        if left is None or right is None:
            return None
        return {
            "and": left and right,
            "or": left or right,
            "xor": left != right,
        }[operation]
    return None


def _target_shaped_register_output_claims(
    source: dict[str, Any], target: dict[str, Any],
) -> list[dict[str, Any]] | None:
    """Build checked source claims whose outputs are exactly the target inventory."""
    existing_by_register = {
        str(claim["output"]["original"]): claim
        for claim in source.get("output_claims", [])
    }
    exact_by_register = {
        str(claim["register"]): claim
        for claim in source.get("exact_output_claims", [])
    }
    source_outputs = {
        str(relation["original"]): relation
        for relation in source.get("outputs", [])
    }
    claims: list[dict[str, Any]] = []
    for target_relation in target.get("inputs", []):
        register = str(target_relation["original"])
        existing = existing_by_register.get(register)
        if existing is not None and existing.get("output") == target_relation:
            claims.append(existing)
            continue
        if (
            existing is not None
            and existing.get("kind") in {
                "constant", "immutable_image_word", "static_word_slot",
            }
            and target_relation.get("relation") == "related_word"
            and existing.get("output", {}).get("candidate")
                == target_relation.get("candidate")
        ):
            claims.append({**existing, "output": target_relation})
            continue
        exact = exact_by_register.get(register)
        source_output = source_outputs.get(register)
        if (
            exact is None
            or source_output is None
            or source_output.get("candidate") != target_relation.get("candidate")
            or target_relation.get("relation") not in {"exact", "related_word"}
        ):
            return None
        claims.append({
            "kind": "exact_expression",
            "output": target_relation,
            "expression": exact["expression"],
        })
    return claims


def _stack_window_transfer_claims(
    source: dict[str, Any],
    target: dict[str, Any],
    behavior: dict[str, Any],
) -> list[dict[str, Any]] | None:
    target_windows = target.get("stack_windows", [])
    if not target_windows:
        return []
    source_windows = source.get("stack_windows", [])
    original_registers = behavior["original_ir"].get("registers") or {}
    candidate_registers = behavior["candidate_ir"].get("registers") or {}

    def adjustment(expression: Any, register: str) -> dict[str, Any] | None:
        def offset(node: Any) -> int | None:
            if node == {"op": "input_reg", "reg": register}:
                return 0
            if not isinstance(node, dict) or node.get("op") not in {"add", "sub"}:
                return None
            operation = str(node["op"])
            left = node.get("left") or {}
            right = node.get("right") or {}
            if operation == "add" and left.get("op") == "constant":
                left, right = right, left
            if right.get("op") != "constant":
                return None
            value = int(right.get("value", -1))
            if not 0 <= value < 2**32:
                return None
            prior = offset(left)
            if prior is None:
                return None
            word_offset = (
                prior + value if operation == "add" else prior - value
            ) % 2**32
            return word_offset if word_offset < 2**31 else word_offset - 2**32

        delta = offset(expression)
        if delta is None:
            return None
        if not -(2**31) < delta < 2**31 or delta % 4 != 0:
            return None
        if delta == 0:
            return {"kind": "identity", "amount": 0}
        return {
            "kind": "add" if delta > 0 else "subtract",
            "amount": abs(delta),
        }

    claims: list[dict[str, Any]] = []
    for target_window in target_windows:
        matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for source_window in source_windows:
            if int(source_window.get("range_id", -1)) != int(
                target_window.get("range_id", -2)
            ):
                continue
            original_adjustment = adjustment(
                original_registers.get(target_window["original_register"]),
                str(source_window["original_register"]),
            )
            candidate_adjustment = adjustment(
                candidate_registers.get(target_window["candidate_register"]),
                str(source_window["candidate_register"]),
            )
            if (
                original_adjustment is None
                or original_adjustment != candidate_adjustment
            ):
                continue
            amount = int(original_adjustment["amount"])
            if original_adjustment["kind"] == "add":
                required_below = max(
                    int(target_window.get("bytes_below", 0)) - amount, 0
                )
                required_above = int(target_window["bytes_above"]) + amount
            elif original_adjustment["kind"] == "subtract":
                required_below = int(target_window.get("bytes_below", 0)) + amount
                required_above = max(
                    int(target_window["bytes_above"]) - amount, 0
                )
            else:
                required_below = int(target_window.get("bytes_below", 0))
                required_above = int(target_window["bytes_above"])
            if (
                int(source_window.get("bytes_below", 0)) >= required_below
                and int(source_window.get("bytes_above", 0)) >= required_above
            ):
                matches.append((source_window, original_adjustment))
        if len(matches) != 1:
            return None
        source_window, original_adjustment = matches[0]
        claims.append({
            "source": source_window,
            "target": target_window,
            "adjustment": original_adjustment,
        })
    return claims
