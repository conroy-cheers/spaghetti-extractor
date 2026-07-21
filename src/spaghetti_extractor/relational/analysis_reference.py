"""Validated immutable views over materialized relational analysis files."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Mapping

from ..errors import StageAInputError
from ..util import sha256_file
from .analysis_artifact import (
    RELATIONAL_ANALYSIS_MANIFEST,
    RelationalAnalysisManifest,
    validate_relational_analysis,
)


_NIX_STORE_ITEM_RE = re.compile(r"[0-9a-df-np-sv-z]{32}-.+")


def immutable_nix_store_file(path: Path) -> Path | None:
    """Return the resolved immutable Nix store file, if any."""

    path = Path(path)
    try:
        resolved = path.resolve(strict=True)
        store_root = Path(
            os.environ.get("NIX_STORE_DIR", "/nix/store")
        ).resolve(strict=True)
        relative = resolved.relative_to(store_root)
    except (FileNotFoundError, OSError, ValueError):
        return None
    if (
        len(relative.parts) < 2
        or _NIX_STORE_ITEM_RE.fullmatch(relative.parts[0]) is None
        or not resolved.is_file()
    ):
        return None
    return resolved


def validate_relational_analysis_view(
    root: Path,
) -> RelationalAnalysisManifest:
    """Validate regular files or immutable Nix-store-backed references."""

    root = Path(root)
    manifest_path = root / RELATIONAL_ANALYSIS_MANIFEST
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise StageAInputError("relational analysis manifest is missing")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(
            f"could not read relational analysis manifest: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise StageAInputError("relational analysis manifest must be an object")
    manifest = RelationalAnalysisManifest.parse(payload)
    for relative, expected in manifest.files.items():
        path = root / relative
        if not path.is_file():
            raise StageAInputError(
                f"analysis artifact file is missing: {relative}"
            )
        if path.is_symlink() and immutable_nix_store_file(path) is None:
            raise StageAInputError(
                "analysis artifact symlink is not an immutable Nix store file: "
                f"{relative}"
            )
        if sha256_file(path) != expected:
            raise StageAInputError(
                f"analysis artifact hash mismatch: {relative}"
            )
    if sha256_file(root / "artifacts" / "original.pe") != (
        manifest.original_sha256
    ):
        raise StageAInputError("analysis original binary hash mismatch")
    if sha256_file(root / "artifacts" / "candidate.pe") != (
        manifest.candidate_sha256
    ):
        raise StageAInputError("analysis candidate binary hash mismatch")
    return manifest


def materialize_relational_analysis_view(
    source: Path, destination: Path
) -> None:
    """Copy a validated view into a portable regular-file analysis artifact."""

    source = Path(source)
    destination = Path(destination)
    manifest = validate_relational_analysis_view(source)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for relative in manifest.files:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, target)
    shutil.copyfile(
        source / RELATIONAL_ANALYSIS_MANIFEST,
        destination / RELATIONAL_ANALYSIS_MANIFEST,
    )
    validate_relational_analysis(destination)


__all__ = [
    "immutable_nix_store_file",
    "materialize_relational_analysis_view",
    "validate_relational_analysis_view",
]
