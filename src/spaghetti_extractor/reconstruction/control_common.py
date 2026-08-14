"""Shared expression normalization and deterministic control helpers."""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from typing import Any, Iterable, Mapping, Sequence


_REGISTER_OPS = frozenset({"input_reg", "reg", "register"})


def _binary_operands(expression: Any, expected_op: str) -> tuple[Any, Any] | None:
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op", "")).lower()
    aliases = {
        "add32": "add",
        "multiply": "mul",
        "mul32": "mul",
        "shl": "shift_left",
        "shl32": "shift_left",
    }
    if aliases.get(op, op) != aliases.get(expected_op, expected_op):
        return None
    if "left" in expression and "right" in expression:
        return expression["left"], expression["right"]
    arguments = expression.get("args")
    if (
        isinstance(arguments, Sequence)
        and not isinstance(arguments, (str, bytes))
        and len(arguments) == 2
    ):
        return arguments[0], arguments[1]
    return None


def _constant_value(expression: Any) -> int | None:
    if isinstance(expression, int) and not isinstance(expression, bool):
        return expression
    if not isinstance(expression, Mapping) or str(expression.get("op", "")).lower() not in {
        "constant",
        "const",
    }:
        return None
    value = expression.get("value")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _index_register(expression: Mapping[str, Any]) -> str | None:
    op = str(expression.get("op", "")).lower()
    if op in _REGISTER_OPS:
        value = expression.get("reg", expression.get("name"))
        return str(value).lower() if value is not None else None
    if op == "and32":
        operands = _binary_operands(expression, "and32")
        if operands is None:
            return None
        for register_expression, mask_expression in (operands, reversed(operands)):
            register = (
                _index_register(register_expression)
                if isinstance(register_expression, Mapping)
                else None
            )
            mask = _constant_value(mask_expression)
            if register is None:
                continue
            if mask == 0xFF and register in {"eax", "ebx", "ecx", "edx"}:
                return {"eax": "al", "ebx": "bl", "ecx": "cl", "edx": "dl"}[
                    register
                ]
            if mask == 0xFFFF and register in {"eax", "ebx", "ecx", "edx"}:
                return {"eax": "ax", "ebx": "bx", "ecx": "cx", "edx": "dx"}[
                    register
                ]
    return None


def _instruction_register(operand: Any) -> str | None:
    if not isinstance(operand, Mapping) or operand.get("kind") != "register":
        return None
    value = operand.get("name")
    return str(value).lower() if value is not None else None


def _instruction_immediate(operand: Any) -> int | None:
    if not isinstance(operand, Mapping) or operand.get("kind") != "immediate":
        return None
    value = operand.get("value")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _same_expression(left: Any, right: Any) -> bool:
    return _normalized_expression(left) == _normalized_expression(right)


def _normalized_expression(value: Any) -> Any:
    if isinstance(value, Mapping):
        op = str(value.get("op", "")).lower()
        if op in {"constant", "const"}:
            return ("constant", _constant_value(value))
        if op in _REGISTER_OPS:
            return ("register", _index_register(value))
        return tuple(
            sorted(
                (str(key), _normalized_expression(item))
                for key, item in value.items()
            )
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(_normalized_expression(item) for item in value)
    return value


def _is_u32(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFFFFFFFF


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _canonical_mapping_key(value: Any) -> str:
    if not isinstance(value, Mapping):
        return _canonical_json({"invalid": str(type(value).__name__)})
    return _canonical_json(value)


def _stable_id(prefix: str, value: Mapping[str, Any]) -> str:
    return f"{prefix}:{sha256(_canonical_json(value).encode('utf-8')).hexdigest()[:16]}"


def _deduplicate_mappings(values: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_key = {_canonical_json(value): copy.deepcopy(dict(value)) for value in values}
    return [by_key[key] for key in sorted(by_key)]


def _deduplicate_frontiers(values: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for value in sorted(values, key=_canonical_mapping_key):
        identity = str(value["id"])
        current = by_id.setdefault(identity, {})
        for key, item in value.items():
            if key not in current:
                current[key] = copy.deepcopy(item)
    return [by_id[identity] for identity in sorted(by_id)]
