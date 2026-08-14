"""Content-bind portable source inputs for one independently lifted unit."""

from __future__ import annotations

import json
import re
import shutil
import copy
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Mapping

from ..util import sha256_file, write_json
from .formats import COMPONENT_SOURCE_PACKAGE_V2_FORMAT
from .intent import ComponentIntentError


_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\Z")


def build_component_source_package_v2(
    *,
    lift_unit_id: str,
    files: Mapping[str, Path | str],
    shared_inputs: Mapping[str, Path | str] | None,
    entry: Mapping[str, object],
    out_dir: Path | str,
) -> dict[str, object]:
    """Copy and hash the exact source tree consumed by qualification/builds."""

    if _IDENTIFIER.fullmatch(lift_unit_id) is None:
        raise ComponentIntentError("source package has an invalid lift-unit id")
    regular = _normalize_inputs(files, "source file")
    shared = _normalize_inputs(shared_inputs or {}, "shared source input")
    overlap = sorted(set(regular) & set(shared))
    if overlap:
        raise ComponentIntentError(
            f"source and shared-input paths overlap: {overlap}"
        )
    if not regular:
        raise ComponentIntentError("component source package has no source files")
    entry_payload = _normalize_entry(entry)

    output = Path(out_dir)
    source_root = output / "sources"
    if source_root.exists():
        shutil.rmtree(source_root)
    source_root.mkdir(parents=True, exist_ok=True)
    file_rows = _copy_inputs(regular, source_root, role="source")
    shared_rows = _copy_inputs(shared, source_root, role="shared_input")
    core = {
        "format": COMPONENT_SOURCE_PACKAGE_V2_FORMAT,
        "lift_unit_id": lift_unit_id,
        "files": file_rows,
        "shared_inputs": shared_rows,
        "entry": entry_payload,
    }
    result = {**core, "implementation_sha256": _canonical_sha256(core)}
    write_json(output / "source-package.json", result)
    return result


def load_component_source_package_v2(value: Path | str) -> dict[str, object]:
    """Load a package only after rechecking its manifest against source bytes."""

    path = Path(value)
    manifest_path = path / "source-package.json" if path.is_dir() else path
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentIntentError(f"cannot read component source package: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ComponentIntentError("component source-package manifest must be an object")
    payload = copy.deepcopy(dict(raw))
    if payload.get("format") != COMPONENT_SOURCE_PACKAGE_V2_FORMAT:
        raise ComponentIntentError("unsupported component source-package format")
    expected = payload.get("implementation_sha256")
    core = copy.deepcopy(payload)
    core.pop("implementation_sha256", None)
    if expected != _canonical_sha256(core):
        raise ComponentIntentError("component source-package self-hash is stale")
    _normalize_entry(_mapping(payload.get("entry"), "component source entry"))

    source_root = manifest_path.parent / "sources"
    listed: set[str] = set()
    for field, expected_role in (("files", "source"), ("shared_inputs", "shared_input")):
        rows = payload.get(field)
        if not isinstance(rows, list):
            raise ComponentIntentError(f"component source package {field} must be an array")
        for raw_row in rows:
            if not isinstance(raw_row, Mapping):
                raise ComponentIntentError("component source-package entry must be an object")
            relative = _safe_manifest_path(raw_row.get("path"))
            text = relative.as_posix()
            if text in listed:
                raise ComponentIntentError(f"duplicate component source path: {text}")
            listed.add(text)
            if raw_row.get("role") != expected_role:
                raise ComponentIntentError(f"component source role is stale for {text}")
            source = source_root.joinpath(*relative.parts)
            if not source.is_file():
                raise ComponentIntentError(f"component source file is missing: {text}")
            if raw_row.get("size") != source.stat().st_size:
                raise ComponentIntentError(f"component source size is stale: {text}")
            if raw_row.get("sha256") != sha256_file(source):
                raise ComponentIntentError(f"component source hash is stale: {text}")
    actual = {
        path.relative_to(source_root).as_posix()
        for path in source_root.rglob("*")
        if path.is_file()
    }
    if actual != listed:
        raise ComponentIntentError(
            "component source package has missing or unlisted files: "
            f"missing={sorted(listed - actual)}, unlisted={sorted(actual - listed)}"
        )
    return payload


def _normalize_entry(value: Mapping[str, object]) -> dict[str, str]:
    if set(value) != {"abi", "symbol"}:
        raise ComponentIntentError("component source entry fields are not canonical")
    abi = value.get("abi")
    symbol = value.get("symbol")
    if abi != "logical-c-v1":
        raise ComponentIntentError("component source entry ABI is unsupported")
    if not isinstance(symbol, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol) is None:
        raise ComponentIntentError("component source entry symbol is not a C identifier")
    return {"abi": abi, "symbol": symbol}


def _mapping(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentIntentError(f"{description} must be an object")
    return value


def _normalize_inputs(
    values: Mapping[str, Path | str], description: str
) -> dict[PurePosixPath, Path]:
    result: dict[PurePosixPath, Path] = {}
    for raw_relative, raw_source in values.items():
        if not isinstance(raw_relative, str):
            raise ComponentIntentError(f"{description} path must be a string")
        relative = PurePosixPath(raw_relative)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ComponentIntentError(
                f"{description} must have a safe relative destination"
            )
        source = Path(raw_source)
        if not source.is_file():
            raise ComponentIntentError(f"{description} does not exist: {source}")
        if relative in result:
            raise ComponentIntentError(f"duplicate {description}: {relative}")
        result[relative] = source
    return result


def _safe_manifest_path(value: object) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise ComponentIntentError("component source path must be a nonempty string")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ComponentIntentError("component source path is unsafe")
    return path


def _copy_inputs(
    values: Mapping[PurePosixPath, Path], output: Path, *, role: str
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for relative, source in sorted(values.items(), key=lambda item: item[0].as_posix()):
        destination = output.joinpath(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        rows.append(
            {
                "path": relative.as_posix(),
                "role": role,
                "sha256": sha256_file(destination),
                "size": destination.stat().st_size,
            }
        )
    return rows


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256(encoded).hexdigest()


__all__ = [
    "build_component_source_package_v2",
    "load_component_source_package_v2",
]
