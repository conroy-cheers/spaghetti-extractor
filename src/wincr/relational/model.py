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
        if expression == {"op": "input_reg", "reg": register}:
            return {"kind": "identity", "amount": 0}
        if not isinstance(expression, dict) or expression.get("op") not in {"add", "sub"}:
            return None
        left = expression.get("left") or {}
        right = expression.get("right") or {}
        if (
            left != {"op": "input_reg", "reg": register}
            or right.get("op") != "constant"
        ):
            return None
        amount = int(right.get("value", -1))
        if not 0 <= amount < 2**32:
            return None
        signed = amount if amount < 2**31 else amount - 2**32
        delta = signed if expression["op"] == "add" else -signed
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
        original_adjustment = adjustment(
            original_registers.get(target_window["original_register"]),
            str(target_window["original_register"]),
        )
        candidate_adjustment = adjustment(
            candidate_registers.get(target_window["candidate_register"]),
            str(target_window["candidate_register"]),
        )
        if original_adjustment is None or original_adjustment != candidate_adjustment:
            return None
        amount = int(original_adjustment["amount"])
        if original_adjustment["kind"] == "add":
            required_below = max(int(target_window.get("bytes_below", 0)) - amount, 0)
            required_above = int(target_window["bytes_above"]) + amount
        elif original_adjustment["kind"] == "subtract":
            required_below = int(target_window.get("bytes_below", 0)) + amount
            required_above = max(int(target_window["bytes_above"]) - amount, 0)
        else:
            required_below = int(target_window.get("bytes_below", 0))
            required_above = int(target_window["bytes_above"])
        matches = [
            window for window in source_windows
            if int(window.get("range_id", -1)) == int(target_window.get("range_id", -2))
            and str(window.get("original_register"))
                == str(target_window.get("original_register"))
            and str(window.get("candidate_register"))
                == str(target_window.get("candidate_register"))
            and int(window.get("bytes_below", 0)) >= required_below
            and int(window.get("bytes_above", 0)) >= required_above
        ]
        if len(matches) != 1:
            return None
        claims.append({
            "source": matches[0],
            "target": target_window,
            "adjustment": original_adjustment,
        })
    return claims
