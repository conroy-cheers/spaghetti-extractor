"""Filesystem location and diagnostics for Nix evaluator receipts."""

from __future__ import annotations

import os
from pathlib import Path


def evaluation_receipt_directory() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "spaghetti-extractor" / "nix-evaluations"
    return Path.home() / ".cache" / "spaghetti-extractor" / "nix-evaluations"


def evaluation_receipt_inventory() -> tuple[Path, int, int]:
    """Return the cache path plus readable receipt count and total bytes."""

    directory = evaluation_receipt_directory()
    try:
        paths = tuple(path for path in directory.glob("*.json") if path.is_file())
        return directory, len(paths), sum(path.stat().st_size for path in paths)
    except OSError:
        return directory, 0, 0


__all__ = ["evaluation_receipt_directory", "evaluation_receipt_inventory"]
