"""Shared validation and rendering helpers for checked status artifacts."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Mapping


class StatusArtifactError(ValueError):
    """A checked status input is malformed or binds another subject."""


def load_object(path: Path | str, description: str) -> Mapping[str, object]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StatusArtifactError(f"cannot read {description}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise StatusArtifactError(f"{description} must be an object")
    return value


def checked_status(
    value: object, description: str, *, allow_complete: bool
) -> str:
    allowed = (
        {"complete", "incomplete", "violated"}
        if allow_complete
        else {"ready", "incomplete", "violated"}
    )
    if value not in allowed:
        raise StatusArtifactError(f"{description} is unsupported: {value!r}")
    return str(value)


def checked_bool(value: object, description: str) -> bool:
    if not isinstance(value, bool):
        raise StatusArtifactError(f"{description} must be Boolean")
    return value


def checked_count(value: object, name: str, description: str) -> int:
    if not isinstance(value, Mapping):
        raise StatusArtifactError(f"{description} counts must be an object")
    count = value.get(name, 0)
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise StatusArtifactError(f"{description} count {name} is invalid")
    return count


def copied_rows(
    value: object, description: str
) -> list[dict[str, object]]:
    if not isinstance(value, list) or any(
        not isinstance(row, Mapping) for row in value
    ):
        raise StatusArtifactError(f"{description} must be an array of objects")
    return [copy.deepcopy(dict(row)) for row in value]


def frontier_key(value: Mapping[str, object]) -> tuple[int, int, str, str, str]:
    dependent = value.get("dependent_occurrences", 0)
    return (
        0 if value.get("status") == "violated" else 1,
        -dependent
        if isinstance(dependent, int) and not isinstance(dependent, bool)
        else 0,
        str(value.get("family", "")),
        str(value.get("code", "")),
        str(value.get("record_id", "")),
    )


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


__all__ = [
    "StatusArtifactError",
    "canonical_sha256",
    "checked_bool",
    "checked_count",
    "checked_status",
    "copied_rows",
    "frontier_key",
    "load_object",
]
