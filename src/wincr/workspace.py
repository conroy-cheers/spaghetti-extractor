from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any, Iterable


_DISPOSABLE_NAMES = {
    "candidate-validation-cache",
    "traces",
}


def _disposable_directory(path: Path) -> bool:
    name = path.name.lower()
    return (
        name in _DISPOSABLE_NAMES
        or "wineprefix" in name
        or name.endswith("-prefix")
        or name.startswith("work.")
    )


def _directory_size(path: Path) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for filename in files:
            try:
                total += (Path(root) / filename).stat().st_size
            except OSError:
                pass
    return total


def workspace_prune(
    *,
    root: Path,
    apply: bool = False,
    include: Iterable[Path] = (),
) -> dict[str, Any]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError(f"workspace root is not a directory: {root}")
    explicit = {(root / path).resolve() for path in include}
    if any(path != root and root not in path.parents for path in explicit):
        raise ValueError("workspace prune include escapes the workspace root")

    candidates: list[Path] = []
    for current, directories, _ in os.walk(root):
        current_path = Path(current)
        retained: list[str] = []
        for directory in directories:
            path = current_path / directory
            if path.resolve() in explicit or _disposable_directory(path):
                candidates.append(path)
            else:
                retained.append(directory)
        directories[:] = retained
    for path in explicit:
        if path.is_dir() and path not in candidates:
            candidates.append(path)

    rows = [
        {
            "path": str(path.relative_to(root)),
            "bytes": _directory_size(path),
            "reason": (
                "explicit" if path.resolve() in explicit
                else "disposable_cache_or_runtime_state"
            ),
        }
        for path in sorted(candidates)
        if path.is_dir()
    ]
    if apply:
        for row in rows:
            shutil.rmtree(root / row["path"])
    return {
        "format": "wincr-workspace-prune-v1",
        "status": "pruned" if apply else "dry_run",
        "root": str(root),
        "entries": rows,
        "counts": {
            "directories": len(rows),
            "bytes": sum(row["bytes"] for row in rows),
        },
    }

