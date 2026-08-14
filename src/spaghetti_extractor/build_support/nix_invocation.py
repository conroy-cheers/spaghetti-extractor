"""Canonical Nix invocation and builder selection for operator workflows."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse


BUILDERS_FILE_ENV = "SPAGHETTI_EXTRACTOR_BUILDERS_FILE"
NIX_FEATURES = "nix-command flakes ca-derivations"


class NixInvocationError(ValueError):
    """A requested Nix execution policy is invalid or unavailable."""


def nix_command(*arguments: str) -> list[str]:
    return ["nix", "--extra-experimental-features", NIX_FEATURES, *arguments]


def builder_arguments(
    *,
    target_flake: str,
    builders_file: Path | str | None,
    local: bool,
    cwd: Path | None = None,
) -> list[str]:
    """Return an explicit Nix builder policy for a public realization.

    A user-selected file has priority, followed by the environment and the
    nearest repository ``nix/stage-a-builders`` inventory. ``--local`` always
    disables every configured remote builder, including host-global entries.
    """

    if local and builders_file is not None:
        raise NixInvocationError("--local and --builders-file are mutually exclusive")
    if local:
        return ["--builders", ""]

    selected = _selected_builders_file(
        target_flake=target_flake,
        explicit=builders_file,
        cwd=Path.cwd() if cwd is None else cwd,
    )
    if selected is None:
        return ["--builders", ""]
    return [
        "--builders",
        f"@{selected}",
        "--option",
        "builders-use-substitutes",
        "true",
    ]


def _selected_builders_file(
    *,
    target_flake: str,
    explicit: Path | str | None,
    cwd: Path,
) -> Path | None:
    requested = explicit
    if requested is None:
        requested = os.environ.get(BUILDERS_FILE_ENV)
    if requested is not None:
        path = _resolve_path(Path(requested), cwd)
        if not path.is_file():
            raise NixInvocationError(f"Nix builders file does not exist: {path}")
        return path

    starts = [cwd.resolve()]
    flake_path = _local_flake_path(target_flake, cwd)
    if flake_path is not None:
        starts.insert(0, flake_path)
    visited: set[Path] = set()
    for start in starts:
        directory = start if start.is_dir() else start.parent
        for candidate_root in (directory, *directory.parents):
            if candidate_root in visited:
                continue
            visited.add(candidate_root)
            candidate = candidate_root / "nix" / "stage-a-builders"
            if candidate.is_file():
                return candidate.resolve()
    return None


def _local_flake_path(reference: str, cwd: Path) -> Path | None:
    if reference.startswith("path:"):
        return _resolve_path(Path(reference.removeprefix("path:")), cwd)
    parsed = urlparse(reference)
    if parsed.scheme == "file":
        return Path(parsed.path).resolve()
    if parsed.scheme or "#" in reference:
        return None
    return _resolve_path(Path(reference), cwd)


def _resolve_path(path: Path, cwd: Path) -> Path:
    return (path if path.is_absolute() else cwd / path).resolve()


__all__ = [
    "BUILDERS_FILE_ENV",
    "NIX_FEATURES",
    "NixInvocationError",
    "builder_arguments",
    "nix_command",
]
