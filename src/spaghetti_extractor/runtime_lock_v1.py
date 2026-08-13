"""Canonical dependency lock for portable Stage B candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .authority_bindings_v2 import canonical_json, canonical_json_bytes


RUNTIME_LOCK_V1_FORMAT = "spaghetti-extractor-runtime-lock-v1"
RUNTIME_LOCK_SPEC_V1_FORMAT = "spaghetti-extractor-runtime-lock-spec-v1"


class RuntimeLockV1Error(ValueError):
    """A dependency lock specification is malformed or unhashable."""


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    if path.is_file():
        digest.update(b"file\0")
        digest.update(path.read_bytes())
        return digest.hexdigest()
    if not path.is_dir():
        raise RuntimeLockV1Error(f"runtime dependency path does not exist: {path}")
    digest.update(b"directory\0")
    for item in sorted(path.rglob("*"), key=lambda row: row.relative_to(path).as_posix()):
        relative = item.relative_to(path).as_posix().encode("utf-8")
        if item.is_symlink():
            digest.update(b"symlink\0" + relative + b"\0")
            digest.update(item.readlink().as_posix().encode("utf-8") + b"\0")
        elif item.is_file():
            digest.update(b"file\0" + relative + b"\0")
            digest.update(hashlib.sha256(item.read_bytes()).digest())
        elif item.is_dir():
            digest.update(b"directory\0" + relative + b"\0")
    return digest.hexdigest()


def build_runtime_lock_v1(specification: Mapping[str, Any]) -> dict[str, Any]:
    if specification.get("format") != RUNTIME_LOCK_SPEC_V1_FORMAT:
        raise RuntimeLockV1Error("runtime-lock specification has the wrong format")
    raw_dependencies = specification.get("dependencies")
    if not isinstance(raw_dependencies, list) or not raw_dependencies:
        raise RuntimeLockV1Error("runtime-lock specification has no dependencies")
    dependencies: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw in raw_dependencies:
        if not isinstance(raw, Mapping) or set(raw) != {"kind", "identity", "path"}:
            raise RuntimeLockV1Error("runtime dependency has noncanonical fields")
        kind = raw["kind"]
        identity = raw["identity"]
        path = raw["path"]
        if any(not isinstance(value, str) or not value for value in (kind, identity, path)):
            raise RuntimeLockV1Error("runtime dependency fields must be nonempty text")
        key = (kind, identity)
        if key in seen:
            raise RuntimeLockV1Error(f"runtime dependency is duplicated: {key!r}")
        seen.add(key)
        dependencies.append(
            {
                "kind": kind,
                "identity": identity,
                "content_sha256": _hash_path(Path(path)),
            }
        )
    dependencies.sort(key=lambda row: (row["kind"], row["identity"]))
    core = {
        "format": RUNTIME_LOCK_V1_FORMAT,
        "schema_version": 1,
        "status": "complete",
        "dependencies": dependencies,
    }
    return {
        **core,
        "lock_id": "runtime-lock-v1:"
        + hashlib.sha256(canonical_json_bytes(core)).hexdigest(),
    }


def emit_runtime_lock_v1(*, specification_path: Path, output_path: Path) -> dict[str, Any]:
    try:
        specification = json.loads(specification_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeLockV1Error(
            f"cannot read runtime-lock specification {specification_path}: {exc}"
        ) from exc
    if not isinstance(specification, Mapping):
        raise RuntimeLockV1Error("runtime-lock specification is not an object")
    result = build_runtime_lock_v1(specification)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(canonical_json(result), encoding="ascii")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a canonical runtime lock")
    parser.add_argument("--specification", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    emit_runtime_lock_v1(
        specification_path=arguments.specification, output_path=arguments.out
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
