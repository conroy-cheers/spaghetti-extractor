#!/usr/bin/env python3
"""Generate and check the registry of clean-cut domain-owned formats."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import sys
from pathlib import Path
from typing import Iterable

from spaghetti_extractor.artifacts.format_spec import FormatSpecV1


_SPEC_MODULES = (
    "spaghetti_extractor.abi.formats",
    "spaghetti_extractor.artifacts.build_formats",
    "spaghetti_extractor.candidate.formats",
    "spaghetti_extractor.components.formats",
    "spaghetti_extractor.external.formats",
    "spaghetti_extractor.libraries.formats",
    "spaghetti_extractor.native_realization.formats",
    "spaghetti_extractor.operator.formats",
    "spaghetti_extractor.pe32.formats",
    "spaghetti_extractor.qualified_platform.formats",
    "spaghetti_extractor.semantic_objects.formats",
    "spaghetti_extractor.semantic_link.formats",
    "spaghetti_extractor.semantic_providers.formats",
    "spaghetti_extractor.transfer.formats",
)
_SCAN_ROOTS = ("src", "nix", "native", "targets", "tests", "tools")
_PRODUCTION_ROOTS = frozenset({"src", "nix", "native", "targets"})
_TEXT_SUFFIXES = {".c", ".h", ".json", ".nix", ".py", ".s"}


def _module_path(root: Path, module: str) -> Path:
    return root / "src" / Path(*module.split(".")).with_suffix(".py")


def _files(root: Path) -> tuple[Path, ...]:
    return tuple(sorted({
        path
        for relative in _SCAN_ROOTS
        for path in (root / relative).rglob("*")
        if path.is_file()
        and path.suffix in _TEXT_SUFFIXES
        and "__pycache__" not in path.parts
        and path != root / "nix/generated/format-registry.json"
        and path != root / "docs/baselines/2026-08-23-format-consumers.json"
    }))


def _load_specs() -> tuple[FormatSpecV1, ...]:
    specs: list[FormatSpecV1] = []
    for name in _SPEC_MODULES:
        module = importlib.import_module(name)
        raw = getattr(module, "FORMAT_SPECS", None)
        if not isinstance(raw, tuple) or any(
            not isinstance(item, FormatSpecV1) for item in raw
        ):
            raise ValueError(f"{name} has no typed FORMAT_SPECS tuple")
        specs.extend(raw)
    return tuple(specs)


def _unique(specs: Iterable[FormatSpecV1], field: str) -> None:
    rows: dict[str, list[str]] = {}
    for spec in specs:
        value = str(getattr(spec, field))
        rows.setdefault(value, []).append(f"{spec.owner}:{spec.symbol}")
    duplicates = {
        value: owners for value, owners in rows.items() if len(owners) > 1
    }
    if duplicates:
        raise ValueError(f"duplicate registered format {field}: {duplicates!r}")


def build_registry(root: Path) -> dict[str, object]:
    specs = _load_specs()
    _unique(specs, "literal")
    _unique(specs, "symbol")
    files = _files(root)
    texts = {
        path: path.read_text(encoding="utf-8", errors="replace") for path in files
    }
    rows: list[dict[str, object]] = []
    for spec in specs:
        owner_path = _module_path(root, spec.owner)
        codec_path = _module_path(root, spec.codec)
        if not owner_path.is_file():
            raise ValueError(f"format owner module is missing: {spec.owner}")
        if not codec_path.is_file():
            raise ValueError(f"format codec module is missing: {spec.codec}")
        literal_readers = [
            path.relative_to(root).as_posix()
            for path, text in texts.items()
            if path != owner_path and spec.literal in text
        ]
        symbol_pattern = re.compile(rf"\b{re.escape(spec.symbol)}\b")
        symbol_readers = [
            path.relative_to(root).as_posix()
            for path, text in texts.items()
            if path != owner_path and symbol_pattern.search(text) is not None
        ]
        codec_relative = codec_path.relative_to(root).as_posix()
        if (
            spec.state == "active"
            and spec.codec != spec.owner
            and codec_relative not in symbol_readers
        ):
            raise ValueError(
                f"active format {spec.literal} is orphaned from its declared codec"
            )
        production_readers = sorted({
            path
            for path in (*literal_readers, *symbol_readers)
            if path.split("/", 1)[0] in _PRODUCTION_ROOTS
        })
        if spec.state == "retired" and production_readers:
            raise ValueError(
                f"retired format {spec.literal} remains in production roots: "
                f"{production_readers!r}"
            )
        rows.append({
            **spec.to_payload(),
            "literal_readers": literal_readers,
            "symbol_readers": symbol_readers,
        })
    rows.sort(key=lambda row: str(row["literal"]))
    core: dict[str, object] = {
        "registry_version": 1,
        "status": "complete",
        "spec_modules": list(_SPEC_MODULES),
        "formats": rows,
        "counts": {
            "formats": len(rows),
            "active": sum(row["state"] == "active" for row in rows),
            "retired": sum(row["state"] == "retired" for row in rows),
        },
    }
    canonical = json.dumps(
        core, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return {**core, "registry_sha256": hashlib.sha256(canonical).hexdigest()}


def _encoded(payload: dict[str, object]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--out", type=Path)
    mode.add_argument("--check", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    payload = build_registry(root)
    encoded = _encoded(payload)
    if args.check is not None:
        path = args.check if args.check.is_absolute() else root / args.check
        if not path.is_file() or path.read_bytes() != encoded:
            raise SystemExit(
                "format registry is stale; regenerate it with "
                "tools/generate-format-registry.py"
            )
        return
    assert args.out is not None
    output = args.out if args.out.is_absolute() else root / args.out
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(encoded)


if __name__ == "__main__":
    main()
