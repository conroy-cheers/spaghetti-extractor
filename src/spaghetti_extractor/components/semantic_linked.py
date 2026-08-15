"""Linked-library ownership views for semantic component catalogs."""

from __future__ import annotations

import copy
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

from ..libraries.contracts import (
    LinkedLibraryContractError,
    validate_linked_island_manifest,
)
from ..util import sha256_file
from .semantic_model import _MachineInputs, SemanticComponentError


def load_linked_island_scope(
    linked_islands: Path | str | Mapping[str, Any] | None,
    *,
    machine: _MachineInputs,
) -> dict[str, Any] | None:
    if linked_islands is None:
        return None
    manifest = (
        copy.deepcopy(dict(linked_islands))
        if isinstance(linked_islands, Mapping)
        else _json_object(Path(linked_islands), "linked-island manifest")
    )
    try:
        validate_linked_island_manifest(manifest)
    except LinkedLibraryContractError as error:
        raise SemanticComponentError(
            f"invalid linked-island manifest: {error}"
        ) from error
    bindings = _object(manifest.get("bindings"), "linked-island bindings")
    expected = {
        "original_binary_sha256": machine.manifest["binary"]["sha256"],
        "machine_ir_sha256": machine.manifest["artifacts"]["machine_ir"][
            "sha256"
        ],
        "machine_ir_manifest_sha256": sha256_file(machine.manifest_path),
    }
    stale = {
        key: {"expected": value, "observed": bindings.get(key)}
        for key, value in expected.items()
        if bindings.get(key) != value
    }
    if stale:
        raise SemanticComponentError(
            f"semantic components/linked-island binding is stale: {stale}"
        )
    owner_by_unit: dict[str, Mapping[str, Any]] = {}
    for raw_island in _array(manifest.get("islands"), "linked islands"):
        island = _object(raw_island, "linked island")
        for unit_id in _array(island.get("unit_ids"), "linked island units"):
            owner_by_unit[str(unit_id)] = island
    if set(owner_by_unit) != set(machine.units_by_id):
        raise SemanticComponentError(
            "linked-island manifest does not classify the exact machine-IR unit set"
        )
    return {
        "manifest_sha256": manifest["manifest_sha256"],
        "status": manifest.get("status"),
        "islands": manifest["islands"],
        "owner_by_unit": owner_by_unit,
    }


def component_linked_island_membership(
    linked_scope: Mapping[str, Any],
    members: set[str],
) -> dict[str, Any]:
    owner_by_unit = _object(
        linked_scope.get("owner_by_unit"), "linked-island unit ownership"
    )
    grouped: dict[str, dict[str, Any]] = {}
    for unit_id in sorted(members):
        island = _object(owner_by_unit[unit_id], "linked island")
        island_id = str(island["id"])
        grouped.setdefault(
            island_id,
            {"island_id": island_id, "kind": island["kind"], "unit_ids": []},
        )["unit_ids"].append(unit_id)
    rows = []
    for row in sorted(grouped.values(), key=lambda item: item["island_id"]):
        rows.append({**row, "unit_count": len(row["unit_ids"])})
    kinds = sorted({str(row["kind"]) for row in rows})
    return {
        "manifest_sha256": linked_scope["manifest_sha256"],
        "islands": rows,
        "kinds": kinds,
        "crosses_island_boundaries": len(rows) > 1,
        "crosses_ownership_kinds": len(kinds) > 1,
        "identity_authorizes_replacement": False,
    }


def component_catalog_linked_coverage(
    linked_scope: Mapping[str, Any],
    *,
    declared_units: set[str],
) -> dict[str, Any]:
    owner_by_unit = _object(
        linked_scope.get("owner_by_unit"), "linked-island unit ownership"
    )
    totals: dict[str, int] = defaultdict(int)
    declared: dict[str, int] = defaultdict(int)
    for unit_id, raw_island in owner_by_unit.items():
        island = _object(raw_island, "linked island")
        kind = str(island["kind"])
        totals[kind] += 1
        if unit_id in declared_units:
            declared[kind] += 1
    return {
        "manifest_sha256": linked_scope["manifest_sha256"],
        "classification_status": linked_scope["status"],
        "machine_units_by_kind": dict(sorted(totals.items())),
        "component_declared_units_by_kind": dict(sorted(declared.items())),
        "remaining_units_by_kind": {
            kind: count - declared.get(kind, 0)
            for kind, count in sorted(totals.items())
        },
        "identity_authorizes_replacement": False,
    }


def _json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        import json

        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise SemanticComponentError(f"cannot read {label}: {error}") from error
    return _object(value, label)


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SemanticComponentError(f"{label} must be an object")
    return dict(value)


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SemanticComponentError(f"{label} must be an array")
    return value


__all__ = [
    "component_catalog_linked_coverage",
    "component_linked_island_membership",
    "load_linked_island_scope",
]
