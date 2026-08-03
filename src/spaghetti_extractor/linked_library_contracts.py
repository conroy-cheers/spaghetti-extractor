"""Dependency-light validators for linked-library pipeline boundaries."""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from typing import Any, Mapping

from .artifact_formats import (
    LINKED_ISLAND_MANIFEST_FORMAT,
    LINKED_ISLAND_MANIFEST_V2_FORMAT,
)


LINKED_ISLAND_KINDS = {
    "application",
    "linked_dependency",
    "compiler_linker_support",
    "import_thunk",
    "unknown",
}


class LinkedLibraryContractError(ValueError):
    """A linked-library boundary artifact is malformed or stale."""


def validate_linked_island_manifest(payload: Mapping[str, Any]) -> None:
    if payload.get("format") not in {
        LINKED_ISLAND_MANIFEST_FORMAT,
        LINKED_ISLAND_MANIFEST_V2_FORMAT,
    }:
        raise LinkedLibraryContractError("unsupported linked-island manifest format")
    core = copy.deepcopy(dict(payload))
    observed = core.pop("manifest_sha256", None)
    if observed != _canonical_sha256(core):
        raise LinkedLibraryContractError("linked-island manifest self-hash is stale")
    if payload.get("executes_original_binary") is not False:
        raise LinkedLibraryContractError(
            "linked-island manifest lacks static-only assurance"
        )
    islands = payload.get("islands")
    if not isinstance(islands, list):
        raise LinkedLibraryContractError("linked islands must be an array")
    unit_ids: list[str] = []
    island_ids: set[str] = set()
    units_by_kind = {kind: 0 for kind in LINKED_ISLAND_KINDS}
    for island in islands:
        if not isinstance(island, Mapping):
            raise LinkedLibraryContractError("linked island must be an object")
        island_id = island.get("id")
        if not isinstance(island_id, str) or not island_id:
            raise LinkedLibraryContractError("linked island has no identity")
        if island_id in island_ids:
            raise LinkedLibraryContractError("linked-island identities are duplicated")
        island_ids.add(island_id)
        if island.get("kind") not in LINKED_ISLAND_KINDS:
            raise LinkedLibraryContractError("linked-island manifest has an invalid kind")
        units = island.get("unit_ids")
        if not isinstance(units, list) or not units:
            raise LinkedLibraryContractError("linked island units must be a nonempty array")
        if island.get("unit_count") != len(units):
            raise LinkedLibraryContractError("linked-island unit count is inconsistent")
        unit_ids.extend(str(value) for value in units)
        units_by_kind[str(island["kind"])] += len(units)
        if island.get("replacement_authorized") is not False:
            raise LinkedLibraryContractError(
                "recognition manifest attempts to authorize replacement"
            )
    if len(unit_ids) != len(set(unit_ids)):
        raise LinkedLibraryContractError("linked-island manifest overlaps machine units")
    coverage = payload.get("coverage")
    if not isinstance(coverage, Mapping):
        raise LinkedLibraryContractError("linked-island coverage must be an object")
    if (
        coverage.get("classified_exactly_once") is not True
        or coverage.get("machine_units") != len(unit_ids)
        or coverage.get("classified_units") != len(unit_ids)
        or coverage.get("units_by_kind")
        != {kind: count for kind, count in units_by_kind.items() if count}
        or coverage.get("unknown_units") != units_by_kind["unknown"]
    ):
        raise LinkedLibraryContractError("linked-island manifest coverage is incomplete")
    authority = payload.get("authority")
    if (
        not isinstance(authority, Mapping)
        or authority.get("artifact_recognition_authorizes_replacement") is not False
        or authority.get("semantic_qualification_required") is not True
    ):
        raise LinkedLibraryContractError(
            "linked-island manifest has an invalid authority boundary"
        )


def _canonical_sha256(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


__all__ = [
    "LINKED_ISLAND_KINDS",
    "LinkedLibraryContractError",
    "validate_linked_island_manifest",
]
