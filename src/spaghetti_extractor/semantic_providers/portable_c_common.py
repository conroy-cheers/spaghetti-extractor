"""Shared failure and JSON input primitives for Portable-C providers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


class PortableCWorkPackageError(ValueError):
    """A direct portable provider is stale or cannot be qualified."""


def fail(message: str) -> None:
    raise PortableCWorkPackageError(message)


def load_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read {context}: {exc}")
    if not isinstance(value, Mapping):
        fail(f"{context} must be an object")
    return value


__all__ = ["PortableCWorkPackageError", "fail", "load_json"]
