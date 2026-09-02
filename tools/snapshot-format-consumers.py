#!/usr/bin/env python3
"""Snapshot pre-migration format declarations and their in-tree consumers."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Iterable


_DECLARATION_NAME = re.compile(
    r"(?:FORMAT|KIND|SCHEMA|MODEL_ID|PROFILE_ID)(?:_V[0-9]+)?$"
)
_SCAN_ROOTS = ("src", "nix", "native", "targets", "tests", "tools")
_TEXT_SUFFIXES = {
    ".c",
    ".h",
    ".json",
    ".md",
    ".nix",
    ".py",
    ".s",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _files(root: Path) -> tuple[Path, ...]:
    rows = {
        path
        for relative in _SCAN_ROOTS
        for path in (root / relative).rglob("*")
        if path.is_file()
        and path.suffix in _TEXT_SUFFIXES
        and "__pycache__" not in path.parts
    }
    return tuple(sorted(rows))


def _string_declarations(path: Path) -> Iterable[tuple[str, str, int]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError):
        return ()
    rows: list[tuple[str, str, int]] = []
    for node in tree.body:
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        if not isinstance(target, ast.Name) or value is None:
            continue
        if _DECLARATION_NAME.search(target.id) is None:
            continue
        try:
            literal = ast.literal_eval(value)
        except (ValueError, TypeError):
            continue
        if isinstance(literal, str):
            rows.append((target.id, literal, node.lineno))
    return rows


def build_snapshot(root: Path) -> dict[str, object]:
    files = _files(root)
    texts = {
        path: path.read_text(encoding="utf-8", errors="replace") for path in files
    }
    declarations: list[dict[str, object]] = []
    for path in files:
        if path.suffix != ".py":
            continue
        relative = path.relative_to(root).as_posix()
        for name, literal, line in _string_declarations(path):
            declarations.append({
                "name": name,
                "literal": literal,
                "owner_file": relative,
                "owner_line": line,
                "literal_consumers": [
                    candidate.relative_to(root).as_posix()
                    for candidate, text in texts.items()
                    if candidate != path and literal in text
                ],
                "symbol_consumers": [
                    candidate.relative_to(root).as_posix()
                    for candidate, text in texts.items()
                    if candidate != path and name in text
                ],
            })
    declarations.sort(
        key=lambda row: (str(row["literal"]), str(row["owner_file"]), str(row["name"]))
    )
    by_literal: dict[str, list[str]] = {}
    for row in declarations:
        by_literal.setdefault(str(row["literal"]), []).append(
            f'{row["owner_file"]}:{row["name"]}'
        )
    duplicate_literals = {
        literal: owners
        for literal, owners in sorted(by_literal.items())
        if len(owners) > 1
    }
    workspace_digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(root).as_posix()
        workspace_digest.update(relative.encode("utf-8") + b"\0")
        workspace_digest.update(_sha256(path.read_bytes()).encode("ascii") + b"\n")
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    return {
        "snapshot_kind": "pre-migration-format-consumer-inventory",
        "source_revision": revision,
        "workspace_tree_sha256": workspace_digest.hexdigest(),
        "scan_roots": list(_SCAN_ROOTS),
        "counts": {
            "scanned_files": len(files),
            "declarations": len(declarations),
            "unique_literals": len(by_literal),
            "duplicate_literals": len(duplicate_literals),
        },
        "duplicate_literals": duplicate_literals,
        "declarations": declarations,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.out if args.out.is_absolute() else root / args.out
    payload = build_snapshot(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
