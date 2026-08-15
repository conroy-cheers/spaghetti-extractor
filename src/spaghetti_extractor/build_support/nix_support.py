"""Minimal Nix process helpers shared by public cached workers."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from ..errors import ToolkitInputError
from .nix_invocation import BuilderPolicy


def nix_executable() -> str:
    override = os.environ.get("SPAGHETTI_EXTRACTOR_NIX")
    candidates = [override, "/run/current-system/sw/bin/nix", shutil.which("nix")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return str(Path(candidate).resolve())
    raise ToolkitInputError("cannot find an executable Nix client")


def find_flake_root(explicit: Path | None = None) -> Path:
    if explicit is not None:
        root = Path(explicit).resolve()
        if (root / "flake.nix").is_file():
            return root
        raise ToolkitInputError(f"not a flake root: {root}")
    for start in (Path.cwd(), Path(__file__).resolve()):
        for candidate in (start, *start.parents):
            if (candidate / "flake.nix").is_file():
                return candidate
    raise ToolkitInputError("cannot locate the Spaghetti Extractor flake")


def nix_build_expression(
    expression: str,
    *,
    builder_policy: BuilderPolicy,
) -> list[str]:
    command = [
        nix_executable(),
        "build",
        "--json",
        "--no-link",
        "--impure",
        "--extra-experimental-features",
        "nix-command flakes ca-derivations",
        "--expr",
        expression,
    ]
    command.extend(builder_policy.nix_arguments())
    return command
