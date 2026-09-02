"""Common filesystem and schema helpers for behavioral-C module builds."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import native_build
from .build_model import CandidateNativeBuildError


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=native_build._reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise CandidateNativeBuildError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise CandidateNativeBuildError(f"{label} must be a JSON object")
    return value


def _relative_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise CandidateNativeBuildError(f"{label} must be a relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise CandidateNativeBuildError(f"{label} must be a canonical relative path")
    return path


def _file(value: Path | str, label: str) -> Path:
    path = Path(value)
    if not path.is_file():
        raise CandidateNativeBuildError(f"{label} does not exist: {path}")
    return path


def _u32(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise CandidateNativeBuildError(f"{label} must be an unsigned 32-bit integer")
    return value


def _align_up(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment
