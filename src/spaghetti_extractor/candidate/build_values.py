"""Common filesystem and schema helpers for interpreter-native builds."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..util import sha256_file
from . import native_build
from .build_model import (
    CandidateNativeBuildError,
    _Artifact,
    _Package,
)


def _artifact(
    root: Path, owner: str, role: str, raw: Mapping[str, Any]
) -> _Artifact:
    relative = _relative_path(raw.get("path"), f"{owner} {role} path")
    digest = native_build._digest(raw.get("sha256"), f"{owner} {role} SHA-256")
    path = root / relative
    if not path.is_file():
        raise CandidateNativeBuildError(
            f"{owner} {role} artifact is missing: {relative}"
        )
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise CandidateNativeBuildError(
            f"{owner} {role} artifact escapes its package root"
        ) from exc
    if sha256_file(path) != digest:
        raise CandidateNativeBuildError(
            f"{owner} {role} artifact SHA-256 mismatch"
        )
    return _Artifact(owner, role, relative.as_posix(), digest, path)


def _revalidate_package(package: _Package) -> None:
    if sha256_file(package.manifest_path) != package.manifest_sha256:
        raise CandidateNativeBuildError(
            f"{package.owner} manifest changed during compilation"
        )
    for item in package.artifacts:
        if not item.path.is_file() or sha256_file(item.path) != item.sha256:
            raise CandidateNativeBuildError(
                f"{package.owner} artifact changed during compilation: "
                f"{item.relative_path}"
            )


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
