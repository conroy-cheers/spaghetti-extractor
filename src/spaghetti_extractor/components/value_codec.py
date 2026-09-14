"""Checked expressions relating portable values to machine representations."""

from __future__ import annotations

import copy
import re
from typing import Mapping


_IDENTIFIER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.:-]*[A-Za-z0-9])?\Z")


class ValueCodecError(ValueError):
    """A machine/logical value codec is malformed."""


def parse_value_codec_expression(
    value: object, context: str
) -> tuple[dict[str, object], str]:
    """Parse one canonical word/Boolean expression used by checked codecs."""

    if not isinstance(value, Mapping):
        raise ValueCodecError(f"{context} must be an object")
    op = _identifier(value.get("op"), f"{context} operation")
    if op == "const":
        row = _exact(value, {"op", "value", "width"}, context)
        raw = row["value"]
        width = row["width"]
        if (
            not isinstance(raw, int)
            or isinstance(raw, bool)
            or not isinstance(width, int)
            or isinstance(width, bool)
            or width not in {1, 8, 16, 32, 64}
            or raw < 0
            or raw >= (1 << width)
        ):
            raise ValueCodecError(f"{context} constant is invalid")
        return {"op": op, "value": raw, "width": width}, "word"
    if op in {
        "parameter",
        "state_input",
        "bytes_address",
        "byte_extent",
        "resource_identity",
    }:
        row = _exact(value, {"op", "name"}, context)
        return {
            "op": op,
            "name": _identifier(row["name"], f"{context} name"),
        }, "word"
    if op == "projected_value":
        _exact(value, {"op"}, context)
        return {"op": op}, "word"
    if op == "byte_read":
        row = _exact(value, {"op", "name", "index"}, context)
        index, sort = parse_value_codec_expression(
            row["index"], f"{context} index"
        )
        if sort != "word":
            raise ValueCodecError(f"{context} index must be a word")
        return {
            "op": op,
            "name": _identifier(row["name"], f"{context} name"),
            "index": index,
        }, "word"
    if op in {"true", "false"}:
        _exact(value, {"op"}, context)
        return {"op": op}, "bool"
    arities = {
        "not": 1,
        "add32": 2,
        "sub32": 2,
        "and32": 2,
        "or32": 2,
        "xor32": 2,
        "eq": 2,
        "ult32": 2,
        "ule32": 2,
        "and": 2,
        "or": 2,
        "ite": 3,
    }
    if op not in arities:
        raise ValueCodecError(f"{context} operation {op!r} is unsupported")
    row = _exact(value, {"op", "args"}, context)
    if not isinstance(row["args"], list) or len(row["args"]) != arities[op]:
        raise ValueCodecError(f"{context} has the wrong arity")
    parsed = [
        parse_value_codec_expression(item, f"{context} argument {index}")
        for index, item in enumerate(row["args"])
    ]
    args = [item[0] for item in parsed]
    sorts = [item[1] for item in parsed]
    if op == "not":
        valid, result_sort = sorts == ["bool"], "bool"
    elif op in {"and", "or"}:
        valid, result_sort = sorts == ["bool", "bool"], "bool"
    elif op in {"eq", "ult32", "ule32"}:
        valid, result_sort = sorts == ["word", "word"], "bool"
    elif op == "ite":
        valid = sorts[0] == "bool" and sorts[1] == sorts[2]
        result_sort = sorts[1]
    else:
        valid, result_sort = sorts == ["word", "word"], "word"
    if not valid:
        raise ValueCodecError(f"{context} operand sorts are invalid")
    return {"op": op, "args": args}, result_sort


def value_codec_expression_references(
    value: Mapping[str, object],
) -> dict[str, set[str]]:
    """Collect typed references, including references nested in byte indices."""

    result = {
        "parameter": set(),
        "state_input": set(),
        "bytes_address": set(),
        "byte_extent": set(),
        "byte_read": set(),
        "resource_identity": set(),
        "projected_value": set(),
    }
    op = value.get("op")
    if op in result:
        if op == "projected_value":
            result[op].add("value")
        else:
            name = value.get("name")
            if isinstance(name, str):
                result[op].add(name)
    children: list[object] = list(value.get("args", []))
    if "index" in value:
        children.append(value["index"])
    for item in children:
        if not isinstance(item, Mapping):
            continue
        nested = value_codec_expression_references(item)
        for kind in result:
            result[kind].update(nested[kind])
    return result


def copy_value_codec_expression(value: Mapping[str, object]) -> dict[str, object]:
    return copy.deepcopy(dict(value))


def _exact(
    value: Mapping[str, object], fields: set[str], context: str
) -> Mapping[str, object]:
    if set(value) != fields:
        raise ValueCodecError(
            f"{context} must contain exactly {sorted(fields)!r}"
        )
    return value


def _identifier(value: object, context: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueCodecError(f"{context} is invalid")
    return value


__all__ = [
    "ValueCodecError",
    "copy_value_codec_expression",
    "parse_value_codec_expression",
    "value_codec_expression_references",
]
