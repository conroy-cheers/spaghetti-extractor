"""Fixed-width expression and byte-view normalization for semantic paths."""

from __future__ import annotations

import copy
from collections.abc import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .semantic_path_errors import SemanticPathError


def simplify_logical_arithmetic(
    value: Mapping[str, object],
) -> dict[str, object]:
    """Normalize identities valid for fixed-width bitvector expressions."""

    result: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(item, Mapping):
            result[str(key)] = simplify_logical_arithmetic(item)
        elif isinstance(item, list):
            result[str(key)] = [
                simplify_logical_arithmetic(child)
                if isinstance(child, Mapping)
                else copy.deepcopy(child)
                for child in item
            ]
        else:
            result[str(key)] = copy.deepcopy(item)
    op = result.get("op")
    args = result.get("args")
    if op == "add32" and isinstance(args, list) and len(args) == 2:
        return _build_additive_expression(_additive_terms(result))
    if op == "sub32" and isinstance(args, list) and len(args) == 2:
        left = _object(args[0], "subtraction left operand")
        right = _object(args[1], "subtraction right operand")
        left_view = byte_view_offset(left)
        right_view = byte_view_offset(right)
        if left_view is not None and right_view is not None and left_view[0] == right_view[0]:
            return simplify_logical_arithmetic(
                {"op": "sub32", "args": [left_view[1], right_view[1]]}
            )
        terms = _additive_terms(left)
        if right.get("op") == "const" and right.get("width") == 32:
            raw = right.get("value")
            if isinstance(raw, int) and not isinstance(raw, bool):
                return _build_additive_expression(
                    [
                        *terms,
                        {"op": "const", "value": (-raw) & 0xFFFFFFFF, "width": 32},
                    ]
                )
        right_key = canonical_sha256_v3(right)
        for index, term in enumerate(terms):
            if canonical_sha256_v3(term) == right_key:
                return _build_additive_expression(
                    [*terms[:index], *terms[index + 1 :]]
                )
    if op in {"and32", "or32", "xor32"} and isinstance(args, list) and len(args) == 2:
        left = _object(args[0], f"{op} left operand")
        right = _object(args[1], f"{op} right operand")
        left_constant = _word32_constant(left)
        right_constant = _word32_constant(right)
        if left_constant is not None and right_constant is not None:
            folded = {
                "and32": left_constant & right_constant,
                "or32": left_constant | right_constant,
                "xor32": left_constant ^ right_constant,
            }[op]
            return {"op": "const", "value": folded, "width": 32}
        if left_constant is not None:
            left, right = right, left
            right_constant = left_constant
        if right_constant is not None:
            if op == "and32" and right_constant == 0:
                return {"op": "const", "value": 0, "width": 32}
            if op == "and32" and right_constant == 0xFFFFFFFF:
                return copy.deepcopy(dict(left))
            if op in {"or32", "xor32"} and right_constant == 0:
                return copy.deepcopy(dict(left))
            nested_args = left.get("args")
            if (
                op == "and32"
                and left.get("op") == "and32"
                and isinstance(nested_args, list)
                and len(nested_args) == 2
            ):
                nested_left = _object(nested_args[0], "nested mask operand")
                nested_right = _object(nested_args[1], "nested mask operand")
                nested_constant = _word32_constant(nested_right)
                if nested_constant is None:
                    nested_left, nested_right = nested_right, nested_left
                    nested_constant = _word32_constant(nested_right)
                if nested_constant is not None:
                    return simplify_logical_arithmetic(
                        {
                            "op": "and32",
                            "args": [
                                nested_left,
                                {
                                    "op": "const",
                                    "value": nested_constant & right_constant,
                                    "width": 32,
                                },
                            ],
                        }
                    )
            if (
                op == "and32"
                and left.get("op") == "or32"
                and isinstance(nested_args, list)
                and len(nested_args) == 2
            ):
                return simplify_logical_arithmetic(
                    {
                        "op": "or32",
                        "args": [
                            {
                                "op": "and32",
                                "args": [
                                    _object(nested_args[0], "masked union operand"),
                                    {"op": "const", "value": right_constant, "width": 32},
                                ],
                            },
                            {
                                "op": "and32",
                                "args": [
                                    _object(nested_args[1], "masked union operand"),
                                    {"op": "const", "value": right_constant, "width": 32},
                                ],
                            },
                        ],
                    }
                )
            if (
                op == "and32"
                and left.get("op") == "ite"
                and isinstance(nested_args, list)
                and len(nested_args) == 3
            ):
                return simplify_logical_arithmetic(
                    {
                        "op": "ite",
                        "args": [
                            _object(nested_args[0], "masked conditional condition"),
                            {
                                "op": "and32",
                                "args": [
                                    _object(nested_args[1], "masked conditional branch"),
                                    {"op": "const", "value": right_constant, "width": 32},
                                ],
                            },
                            {
                                "op": "and32",
                                "args": [
                                    _object(nested_args[2], "masked conditional branch"),
                                    {"op": "const", "value": right_constant, "width": 32},
                                ],
                            },
                        ],
                    }
                )
            return {"op": op, "args": [left, right]}
    return result


def byte_view_offset(
    value: Mapping[str, object],
) -> tuple[str, dict[str, object]] | None:
    op = value.get("op")
    if op == "bytes_address":
        name = value.get("name")
        if not isinstance(name, str) or not name:
            return None
        return name, {"op": "const", "value": 0, "width": 32}
    args = value.get("args")
    if op == "ite" and isinstance(args, list) and len(args) == 3:
        if any(not isinstance(item, Mapping) for item in args):
            return None
        condition, true_value, false_value = args
        true_view = byte_view_offset(true_value)
        false_view = byte_view_offset(false_value)
        if true_view is None or false_view is None or true_view[0] != false_view[0]:
            return None
        return true_view[0], {
            "op": "ite",
            "args": [copy.deepcopy(dict(condition)), true_view[1], false_view[1]],
        }
    if op not in {"add32", "sub32"} or not isinstance(args, list) or len(args) != 2:
        return None
    left = args[0] if isinstance(args[0], Mapping) else None
    right = args[1] if isinstance(args[1], Mapping) else None
    if left is None or right is None:
        return None
    left_view = byte_view_offset(left)
    right_view = byte_view_offset(right)
    if op == "add32":
        if (left_view is None) == (right_view is None):
            return None
        view = left_view if left_view is not None else right_view
        offset = right if left_view is not None else left
        assert view is not None
        return view[0], {
            "op": "add32",
            "args": [view[1], copy.deepcopy(dict(offset))],
        }
    if left_view is None or right_view is not None:
        return None
    return left_view[0], {
        "op": "sub32",
        "args": [left_view[1], copy.deepcopy(dict(right))],
    }


def _word32_constant(value: Mapping[str, object]) -> int | None:
    raw = value.get("value")
    if (
        value.get("op") != "const"
        or value.get("width") != 32
        or not isinstance(raw, int)
        or isinstance(raw, bool)
    ):
        return None
    return raw & 0xFFFFFFFF


def _additive_terms(value: Mapping[str, object]) -> list[dict[str, object]]:
    args = value.get("args")
    if value.get("op") == "add32" and isinstance(args, list) and len(args) == 2:
        return [
            *_additive_terms(_object(args[0], "addition operand")),
            *_additive_terms(_object(args[1], "addition operand")),
        ]
    return [copy.deepcopy(dict(value))]


def _build_additive_expression(terms: list[dict[str, object]]) -> dict[str, object]:
    constants = [
        int(term["value"])
        for term in terms
        if term.get("op") == "const" and term.get("width") == 32
    ]
    nonconstant = [
        term
        for term in terms
        if not (term.get("op") == "const" and term.get("width") == 32)
    ]
    nonconstant.sort(key=canonical_sha256_v3)
    constant = sum(constants) & 0xFFFFFFFF
    nonzero = [
        *nonconstant,
        *([{"op": "const", "value": constant, "width": 32}] if constant else []),
    ]
    if not nonzero:
        return {"op": "const", "value": 0, "width": 32}
    result = nonzero[0]
    for term in nonzero[1:]:
        result = {"op": "add32", "args": [result, term]}
    return result


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SemanticPathError(f"{context} must be an object")
    return value


__all__ = ["byte_view_offset", "simplify_logical_arithmetic"]
