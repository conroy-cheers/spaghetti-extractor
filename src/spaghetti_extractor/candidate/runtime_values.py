"""Filesystem and schema value helpers for native runtime packages."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..util import sha256_file
from .runtime_model import StageBNativeRuntimeError, _SHA256_RE


def _manifest_path(
    value: Path | str, filename: str, label: str
) -> Path:
    path = Path(value)
    if path.is_dir():
        path = path / filename
    if not path.is_file():
        raise StageBNativeRuntimeError(f"{label} manifest does not exist: {path}")
    return path


def _bound_artifact(root: Path, value: dict[str, Any], label: str) -> Path:
    name = _required_relative_path(value.get("path"), f"{label} path")
    expected = _required_sha256(value.get("sha256"), f"{label} SHA-256")
    path = root / name
    if not path.is_file():
        raise StageBNativeRuntimeError(f"{label} does not exist: {path}")
    if sha256_file(path) != expected:
        raise StageBNativeRuntimeError(f"{label} SHA-256 mismatch")
    return path


def _verify_artifact_inventory(
    root: Path, value: Any, label: str, *, require_role: bool
) -> dict[str, Path]:
    rows = _required_list(value, f"{label} inventory")
    if not rows:
        raise StageBNativeRuntimeError(f"{label} inventory is empty")
    seen: set[str] = set()
    result: dict[str, Path] = {}
    for index, raw in enumerate(rows):
        row = _required_object(raw, f"{label} {index}")
        key: str
        if require_role:
            key = _required_string(row.get("role"), f"{label} {index} role")
            if key in result:
                raise StageBNativeRuntimeError(
                    f"{label} inventory has duplicate roles"
                )
        name = _required_relative_path(row.get("path"), f"{label} {index} path")
        if name in seen:
            raise StageBNativeRuntimeError(f"{label} inventory has duplicate paths")
        seen.add(name)
        path = _bound_artifact(root, row, f"{label} {index}")
        result[key if require_role else name] = path
    return result


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageBNativeRuntimeError(f"cannot read {label}: {path}") from exc
    return _required_object(value, label)


def _required_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StageBNativeRuntimeError(f"{field} must be an object")
    return value


def _required_list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageBNativeRuntimeError(f"{field} must be a list")
    return value


def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageBNativeRuntimeError(f"{field} must be a non-empty string")
    return value


def _required_portable_identity(value: Any, field: str) -> str:
    text = _required_string(value, field)
    try:
        encoded = text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise StageBNativeRuntimeError(f"{field} must be printable ASCII") from exc
    if any(byte < 0x20 or byte > 0x7E for byte in encoded):
        raise StageBNativeRuntimeError(f"{field} must be printable ASCII")
    return text


def _required_relative_path(value: Any, field: str) -> str:
    text = _required_string(value, field)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or len(path.parts) != 1:
        raise StageBNativeRuntimeError(f"{field} must be a local artifact name")
    return text


def _required_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StageBNativeRuntimeError(f"{field} must be a lowercase SHA-256")
    return value


def _required_u32(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise StageBNativeRuntimeError(f"{field} must be a 32-bit unsigned integer")
    return value


def _required_count(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StageBNativeRuntimeError(f"{field} must be a nonnegative integer")
    return value
