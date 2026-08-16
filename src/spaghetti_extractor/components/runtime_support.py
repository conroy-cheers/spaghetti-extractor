"""Shared validation and rendering utilities for component runtime packages."""

from __future__ import annotations

import copy
import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from ..util import sha256_file
from .intent import ComponentIntentError
from .logical_abi import logical_c_type

def _member_spans(members: Mapping[str, Mapping[str, object]]) -> list[dict[str, int]]:
    return [
        {
            "start": int(_object(_object(row.get("source"), "unit source").get("original"), "unit original")["rva_start"]),
            "end": int(_object(_object(row.get("source"), "unit source").get("original"), "unit original")["rva_end"]),
        }
        for row in sorted(members.values(), key=_unit_rva)
    ]


def _artifact(path: Path, root: Path, *, symbol: str | None = None) -> dict[str, object]:
    row: dict[str, object] = {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256_file(path),
    }
    if symbol is not None:
        row["symbol"] = symbol
    return row


def _required_mapping_path(
    values: Mapping[str, Path | str], identity: str, description: str
) -> Path:
    value = values.get(identity)
    if value is None:
        raise ComponentIntentError(f"component {identity} has no {description}")
    return Path(value)


def _unit_rva(row: Mapping[str, object]) -> int:
    return int(_object(_object(row.get("source"), "unit source").get("original"), "unit original")["rva_start"])


def _c_type(value: object, *, source_abi: object) -> str:
    result = logical_c_type(value, source_abi=source_abi)
    if result is None:
        raise ComponentIntentError(f"unsupported logical C type: {value}")
    return result


def _c_identifier(value: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not result or result[0].isdigit():
        result = "component_" + result
    return result


def _check_self_hash(
    payload: Mapping[str, object], format_name: str, field: str, description: str
) -> None:
    if payload.get("format") != format_name:
        raise ComponentIntentError(f"unsupported {description} format")
    core = copy.deepcopy(dict(payload))
    expected = core.pop(field, None)
    if expected != _canonical_sha256(core):
        raise ComponentIntentError(f"{description} self-hash is stale")


def _read_object(path: Path, description: str) -> dict[str, object]:
    try:
        return dict(_object(json.loads(path.read_text(encoding="utf-8")), description))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentIntentError(f"cannot read {description}: {exc}") from exc


def _object(value: object, description: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ComponentIntentError(f"{description} must be an object")
    return value


def _array(value: object, description: str) -> list[Any]:
    if not isinstance(value, list):
        raise ComponentIntentError(f"{description} must be an array")
    return value


def _string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentIntentError(f"{description} must be a nonempty string")
    return value


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return sha256(encoded).hexdigest()
