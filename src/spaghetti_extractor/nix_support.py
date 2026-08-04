"""Minimal Nix process helpers shared by public cached workers."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from .stage_binary import StageAInputError


def nix_executable() -> str:
    override = os.environ.get("SPAGHETTI_EXTRACTOR_NIX")
    candidates = [override, "/run/current-system/sw/bin/nix", shutil.which("nix")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return str(Path(candidate).resolve())
    raise StageAInputError("cannot find an executable Nix client")


def find_flake_root(explicit: Path | None = None) -> Path:
    if explicit is not None:
        root = Path(explicit).resolve()
        if (root / "flake.nix").is_file():
            return root
        raise StageAInputError(f"not a flake root: {root}")
    for start in (Path.cwd(), Path(__file__).resolve()):
        for candidate in (start, *start.parents):
            if (candidate / "flake.nix").is_file():
                return candidate
    raise StageAInputError("cannot locate the Spaghetti Extractor flake")


def nix_build_expression(
    expression: str,
    *,
    builders_file: Path | None = None,
    trusted_public_keys_file: Path | None = None,
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
    if builders_file is not None:
        command.extend(["--builders", f"@{Path(builders_file).resolve()}"])
    if trusted_public_keys_file is not None:
        keys = " ".join(
            line.strip()
            for line in Path(trusted_public_keys_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        if keys:
            command.extend(["--option", "trusted-public-keys", keys])
    return command
