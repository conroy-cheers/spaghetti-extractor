"""Strict access to a content-bound V4 library release set."""

from __future__ import annotations

import json
from pathlib import Path

from ..artifacts.formats import LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT
from .v4_identity_records import (
    LIBRARY_RELEASE_HYPOTHESES_CODEC_V4,
    LibraryIslandHypothesisV4,
    LibraryReleaseHypothesesV4,
)
from .v4_record_support import canonical_sha256


def read_library_release_set_v4(
    value: Path | str,
) -> tuple[LibraryReleaseHypothesesV4, ...]:
    root = Path(value)
    try:
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read library release manifest: {error}") from error
    if not isinstance(manifest, dict):
        raise ValueError("library release manifest must be an object")
    core = dict(manifest)
    observed_hash = core.pop("manifest_sha256", None)
    if set(core) != {
        "format",
        "target_id",
        "target_binary_sha256",
        "target_signature_graph_sha256",
        "catalog_search_index_sha256",
        "releases",
    }:
        raise ValueError("library release manifest fields are not canonical")
    if core["format"] != LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT:
        raise ValueError("library release manifest has the wrong format")
    if observed_hash != canonical_sha256(core):
        raise ValueError("library release manifest hash is stale")
    rows = core["releases"]
    if not isinstance(rows, list):
        raise ValueError("library release manifest has no release inventory")

    releases = []
    declared = {"manifest.json"}
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {
            "family_id",
            "release_id",
            "path",
            "hypotheses_sha256",
            "status",
        }:
            raise ValueError(f"library release manifest row {index} is malformed")
        relative = Path(str(row["path"]))
        if relative.is_absolute() or len(relative.parts) != 1:
            raise ValueError("library release manifest path is not a local filename")
        release = LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.read(root / relative)
        if (
            release.target_id != core["target_id"]
            or release.target_binary_sha256 != core["target_binary_sha256"]
            or release.target_signature_graph_sha256
            != core["target_signature_graph_sha256"]
            or release.catalog_search_index_sha256
            != core["catalog_search_index_sha256"]
            or release.family_id != row["family_id"]
            or release.release_id != row["release_id"]
            or release.hypotheses_sha256 != row["hypotheses_sha256"]
            or release.status != row["status"]
        ):
            raise ValueError("library release manifest row is stale")
        declared.add(relative.as_posix())
        releases.append(release)
    observed = {
        path.relative_to(root).as_posix() for path in root.iterdir() if path.is_file()
    }
    if observed != declared:
        raise ValueError("library release artifact directory has undeclared files")
    identities = tuple((row.family_id, row.release_id) for row in releases)
    if len(set(identities)) != len(identities):
        raise ValueError("library release set contains duplicate releases")
    return tuple(sorted(releases, key=lambda row: (row.family_id, row.release_id)))


def select_library_island_v1(
    release_set: Path | str,
    island_id: str,
) -> tuple[LibraryReleaseHypothesesV4, LibraryIslandHypothesisV4]:
    found = [
        (release, island)
        for release in read_library_release_set_v4(release_set)
        for island in release.islands
        if island.island_id == island_id
    ]
    if len(found) != 1:
        raise ValueError(
            f"library island {island_id!r} appears {len(found)} times in release hypotheses"
        )
    return found[0]


__all__ = ["read_library_release_set_v4", "select_library_island_v1"]
