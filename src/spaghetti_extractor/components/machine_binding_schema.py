"""Strict schema helpers for component machine bindings."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path

from .machine_binding_checks import ComponentMachineBindingError

_DIGEST = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,127}")
_ARTIFACT_ID = re.compile(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\Z")

def _load(value: Path | str | Mapping[str, object] | object, context: str) -> dict[str, object]:
    if isinstance(value, Mapping):
        return json.loads(json.dumps(value))
    if isinstance(value, (Path, str)):
        try:
            payload = json.loads(Path(value).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ComponentMachineBindingError(f"cannot read {context}: {exc}") from exc
        return dict(_object(payload, context))
    raise ComponentMachineBindingError(f"{context} is unsupported")


def _index(value: object, context: str) -> dict[str, Mapping[str, object]]:
    result: dict[str, Mapping[str, object]] = {}
    for item in _array(value, context):
        row = _object(item, context)
        identity = _identifier(row.get("id"), f"{context} id")
        if identity in result:
            raise ComponentMachineBindingError(f"{context} ids are duplicated")
        result[identity] = row
    return result


def _rows(parser, value: object, context: str):
    rows = tuple(parser(item, f"{context} {index}") for index, item in enumerate(_array(value, context)))
    def row_id(row: object) -> str:
        for field in ("identity", "operation_id", "service_id", "effect_id"):
            observed = getattr(row, field, None)
            if isinstance(observed, str):
                return observed
        raise ComponentMachineBindingError(f"{context} row has no stable id")
    if tuple(row_id(row) for row in rows) != tuple(
        sorted({row_id(row) for row in rows})
    ):
        raise ComponentMachineBindingError(f"{context} rows must be canonically ordered")
    return rows


def _strings(value: object, context: str, *, nonempty: bool = False) -> tuple[str, ...]:
    rows = tuple(_text(item, context) for item in _array(value, context))
    if nonempty and not rows:
        raise ComponentMachineBindingError(f"{context} must not be empty")
    if rows != tuple(sorted(set(rows))):
        raise ComponentMachineBindingError(f"{context} must be sorted and unique")
    return rows


def _identifiers(value: object, context: str) -> tuple[str, ...]:
    rows = _strings(value, context)
    for row in rows:
        _identifier(row, context)
    return rows


def _unique(values, context: str) -> None:
    rows = tuple(values)
    if len(rows) != len(set(rows)):
        raise ComponentMachineBindingError(f"{context} ids are duplicated")


def _issue(issues: list[dict[str, object]], status: str, code: str, **detail: object) -> None:
    issues.append({"status": status, "code": code, **detail})


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentMachineBindingError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ComponentMachineBindingError(f"{context} must be an array")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentMachineBindingError(f"{context} must be a nonempty string")
    return value


def _identifier(value: object, context: str) -> str:
    result = _text(value, context)
    if _IDENTIFIER.fullmatch(result) is None:
        raise ComponentMachineBindingError(f"{context} is not a portable identifier")
    return result


def _artifact_id(value: object, context: str) -> str:
    result = _text(value, context)
    if _ARTIFACT_ID.fullmatch(result) is None:
        raise ComponentMachineBindingError(f"{context} is not a valid artifact id")
    return result


def _digest(value: object, context: str) -> str:
    result = _text(value, context)
    if _DIGEST.fullmatch(result) is None:
        raise ComponentMachineBindingError(f"{context} is not a SHA-256 digest")
    return result


def _uint(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ComponentMachineBindingError(f"{context} must be a nonnegative integer")
    return value


def _width(value: object, context: str) -> int:
    result = _uint(value, f"{context} width")
    if result not in {8, 16, 32, 64}:
        raise ComponentMachineBindingError(f"{context} width is unsupported")
    return result


def _phase(value: object, context: str) -> str:
    result = _text(value, f"{context} phase")
    if result not in {"entry", "exit", "call"}:
        raise ComponentMachineBindingError(f"{context} phase is invalid")
    return result


def _exact(value: Mapping[str, object], fields: set[str], context: str) -> None:
    if set(value) != fields:
        raise ComponentMachineBindingError(
            f"{context} fields differ: missing={sorted(fields-set(value))!r}, "
            f"extra={sorted(set(value)-fields)!r}"
        )
