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
_REVIEWED_COMPLEMENT_AUTHORITY = "operator_reviewed_exact_complement"
_REVIEWED_COMPLEMENT_SCOPE = "otherwise_unclaimed_exact_machine_units"


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
    _validate_reviewed_complement(payload, islands, authority)


def _validate_reviewed_complement(
    payload: Mapping[str, Any],
    islands: list[Any],
    authority: Mapping[str, Any],
) -> None:
    complement_rows = [
        island
        for island in islands
        if isinstance(island, Mapping)
        and isinstance(island.get("match"), Mapping)
        and island["match"].get("authority") == _REVIEWED_COMPLEMENT_AUTHORITY
    ]
    if "reviewed_unclaimed_exact_units" not in payload:
        if complement_rows or "reviewed_complement_binds_ownership_only" in authority:
            raise LinkedLibraryContractError(
                "reviewed-complement island lacks its exact policy binding"
            )
        return
    summary = payload.get("reviewed_unclaimed_exact_units")
    if not isinstance(summary, Mapping):
        raise LinkedLibraryContractError(
            "reviewed unclaimed-unit complement must be an object"
        )
    base_fields = {
        "authority",
        "exact_bindings",
        "id",
        "kind",
        "operator_reviewed",
        "preserved_claimed_island_ids",
        "replacement_authorized",
        "review_rationale",
        "scope",
        "unit_count",
    }
    expected_fields = base_fields | (
        {"unit_contract_sha256"} if summary.get("unit_count") else set()
    )
    if set(summary) != expected_fields:
        raise LinkedLibraryContractError(
            "reviewed unclaimed-unit complement fields are inconsistent"
        )
    identity = summary.get("id")
    unit_count = summary.get("unit_count")
    if not isinstance(identity, str) or not identity:
        raise LinkedLibraryContractError(
            "reviewed unclaimed-unit complement has no identity"
        )
    if summary.get("kind") not in {
        "linked_dependency",
        "compiler_linker_support",
    }:
        raise LinkedLibraryContractError(
            "reviewed unclaimed-unit complement has an invalid kind"
        )
    if (
        summary.get("authority") != _REVIEWED_COMPLEMENT_AUTHORITY
        or summary.get("scope") != _REVIEWED_COMPLEMENT_SCOPE
        or summary.get("operator_reviewed") is not True
        or summary.get("replacement_authorized") is not False
        or not isinstance(summary.get("review_rationale"), str)
        or not str(summary.get("review_rationale")).strip()
        or not isinstance(unit_count, int)
        or isinstance(unit_count, bool)
        or unit_count < 0
    ):
        raise LinkedLibraryContractError(
            "reviewed unclaimed-unit complement is not visibly reviewed and non-authorizing"
        )
    if authority.get("reviewed_complement_binds_ownership_only") is not True:
        raise LinkedLibraryContractError(
            "reviewed unclaimed-unit complement crosses the authority boundary"
        )
    coverage = payload.get("coverage")
    if not isinstance(coverage, Mapping) or coverage.get("unknown_units") != 0:
        raise LinkedLibraryContractError(
            "reviewed unclaimed-unit complement did not close unknown ownership"
        )
    manifest_bindings = payload.get("bindings")
    exact_bindings = summary.get("exact_bindings")
    if not isinstance(manifest_bindings, Mapping) or not isinstance(
        exact_bindings, Mapping
    ):
        raise LinkedLibraryContractError(
            "reviewed unclaimed-unit complement lacks exact bindings"
        )
    exact_fields = {
        "machine_ir_manifest_sha256",
        "machine_ir_sha256",
        "original_binary_sha256",
        "review_sha256",
        "unit_ids_sha256",
    }
    if set(exact_bindings) != exact_fields:
        raise LinkedLibraryContractError(
            "reviewed unclaimed-unit complement exact bindings are malformed"
        )
    for field in exact_fields:
        value = exact_bindings.get(field)
        if not isinstance(value, str) or len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise LinkedLibraryContractError(
                "reviewed unclaimed-unit complement has a malformed exact binding"
            )
    for field in exact_fields - {"unit_ids_sha256"}:
        if exact_bindings.get(field) != manifest_bindings.get(field):
            raise LinkedLibraryContractError(
                "reviewed unclaimed-unit complement is stale for this binary or machine IR"
            )
    if len(complement_rows) != (1 if unit_count else 0):
        raise LinkedLibraryContractError(
            "reviewed unclaimed-unit complement island count is inconsistent"
        )
    other_ids = sorted(
        str(island.get("id"))
        for island in islands
        if isinstance(island, Mapping) and island.get("id") != identity
    )
    if summary.get("preserved_claimed_island_ids") != other_ids:
        raise LinkedLibraryContractError(
            "reviewed unclaimed-unit complement silently discarded an existing claim"
        )
    if not complement_rows:
        return
    row = complement_rows[0]
    match = row.get("match")
    if (
        row.get("id") != identity
        or row.get("kind") != summary.get("kind")
        or row.get("unit_count") != unit_count
        or row.get("replacement_authorized") is not False
        or row.get("unit_contract_sha256") != summary.get("unit_contract_sha256")
        or not isinstance(match, Mapping)
        or match.get("exact_bindings") != exact_bindings
        or match.get("operator_reviewed") is not True
        or match.get("scope") != _REVIEWED_COMPLEMENT_SCOPE
        or match.get("review_rationale") != summary.get("review_rationale")
        or match.get("preserved_claimed_island_ids") != other_ids
    ):
        raise LinkedLibraryContractError(
            "reviewed unclaimed-unit complement island contradicts its policy binding"
        )
    unit_ids = row.get("unit_ids")
    if (
        not isinstance(unit_ids, list)
        or any(not isinstance(unit_id, str) or not unit_id for unit_id in unit_ids)
        or _canonical_sha256(sorted(unit_ids))
        != exact_bindings.get("unit_ids_sha256")
    ):
        raise LinkedLibraryContractError(
            "reviewed unclaimed-unit complement exact unit binding is stale"
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
