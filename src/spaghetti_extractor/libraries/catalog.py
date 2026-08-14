"""Linked-library catalog."""

from __future__ import annotations

import copy
import json
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..artifacts.formats import (
    COMPONENT_QUALIFICATION_FORMAT,
    LIBRARY_ARTIFACT_INDEX_FORMAT,
    LIBRARY_ARTIFACT_INDEX_V2_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_V2_FORMAT,
    LIBRARY_CATALOG_LOCK_FORMAT,
    LIBRARY_HYPOTHESIS_SET_FORMAT,
    LIBRARY_INTERFACE_CATALOG_FORMAT,
    LIBRARY_MATCH_EVIDENCE_FORMAT,
    LIBRARY_REPLACEMENT_PLAN_FORMAT,
    DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
    LINKED_INTERFACE_ASSIGNMENTS_FORMAT,
    LINKED_INTERFACE_QUALIFICATION_FORMAT,
    LINKED_ISLAND_MANIFEST_FORMAT,
    LINKED_ISLAND_MANIFEST_V2_FORMAT,
    LINKED_ISLAND_REVIEW_FORMAT,
    MACHINE_IR_FORMAT,
)
from ..pe32.stage_binary import StageAInputError, _parse_stage_a_pe
from .contracts import (
    validate_linked_island_manifest as _validate_linked_island_contract,
)
from ..util import sha256_file, write_json


from .artifact_parsers import (
    _artifact_function_count,
    _decorate_v2_artifact_index,
    _index_artifact_blob,
)
from .matching_support import (
    _array,
    _canonical_sha256,
    _copy_object,
    _nonempty,
    _object,
    _read_object,
    _validate_artifact_index,
)
from .model import (
    LinkedLibraryError,
    _ARTIFACT_INPUT_FORMATS,
)

def bind_library_artifact_inputs(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a self-hashed artifact-input declaration."""

    core = copy.deepcopy(dict(payload))
    core.pop("inputs_sha256", None)
    if core.get("format") not in _ARTIFACT_INPUT_FORMATS:
        raise LinkedLibraryError("unsupported library artifact inputs format")
    _nonempty(core.get("catalog_id"), "library artifact catalog ID")
    if core.get("format") == LIBRARY_ARTIFACT_INPUTS_V2_FORMAT:
        snapshot = _object(core.get("snapshot"), "library catalog snapshot")
        _nonempty(snapshot.get("id"), "library catalog snapshot ID")
        target = _object(snapshot.get("target"), "library catalog target")
        _nonempty(target.get("architecture"), "library target architecture")
        _nonempty(target.get("object_format"), "library target object format")
        _nonempty(target.get("abi"), "library target ABI")
    artifacts = _array(core.get("artifacts"), "library artifacts")
    if not artifacts:
        raise LinkedLibraryError("library artifact inputs contain no artifacts")
    seen: set[str] = set()
    for raw in artifacts:
        artifact = _object(raw, "library artifact input")
        identity = _nonempty(artifact.get("id"), "library artifact ID")
        if identity in seen:
            raise LinkedLibraryError(f"duplicate library artifact ID: {identity}")
        seen.add(identity)
        _nonempty(artifact.get("path"), "library artifact path")
        visibility = artifact.get("visibility", "public")
        if visibility not in {"public", "private"}:
            raise LinkedLibraryError(
                f"library artifact {identity} has invalid visibility"
            )
        island_kind = artifact.get("island_kind", "linked_dependency")
        if island_kind not in {"linked_dependency", "compiler_linker_support"}:
            raise LinkedLibraryError(
                f"library artifact {identity} has invalid island kind"
            )
        if core.get("format") == LIBRARY_ARTIFACT_INPUTS_V2_FORMAT:
            library = _object(
                artifact.get("library_identity"),
                f"library artifact {identity} identity",
            )
            _nonempty(library.get("family_id"), "library family ID")
            _nonempty(library.get("component_id"), "library component ID")
            _nonempty(library.get("abi_id"), "library ABI ID")
            retention = artifact.get("retention_model", "unknown")
            if retention not in {"unknown", "archive_member", "section_gc"}:
                raise LinkedLibraryError(
                    f"library artifact {identity} has invalid retention model"
                )
    return {**core, "inputs_sha256": _canonical_sha256(core)}


def index_library_artifacts(
    *,
    inputs: Path | str | Mapping[str, Any],
    artifact_root: Path | str,
    out: Path | str,
) -> dict[str, Any]:
    """Index content-bound library artifacts without executing any binary."""

    declaration = (
        _copy_object(inputs, "library artifact inputs")
        if isinstance(inputs, Mapping)
        else _read_object(Path(inputs), "library artifact inputs")
    )
    expected = declaration.get("inputs_sha256")
    bound = bind_library_artifact_inputs(declaration)
    if expected != bound["inputs_sha256"]:
        raise LinkedLibraryError("library artifact inputs self-hash is stale")
    root = Path(artifact_root).resolve()
    rows: list[dict[str, Any]] = []
    private_count = 0
    for raw in _array(declaration.get("artifacts"), "library artifacts"):
        artifact = _object(raw, "library artifact input")
        relative = Path(_nonempty(artifact.get("path"), "library artifact path"))
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise LinkedLibraryError("library artifact path escapes artifact root") from error
        if not path.is_file():
            raise LinkedLibraryError(f"library artifact does not exist: {relative}")
        visibility = str(artifact.get("visibility", "public"))
        private_count += visibility == "private"
        indexed = _index_artifact_blob(
            data=path.read_bytes(),
            label=relative.as_posix(),
            source_path=path,
        )
        if declaration.get("format") == LIBRARY_ARTIFACT_INPUTS_V2_FORMAT:
            indexed = _decorate_v2_artifact_index(
                indexed,
                artifact_sha256=sha256_file(path),
                member_path=(),
            )
        rows.append(
            {
                "id": _nonempty(artifact.get("id"), "library artifact ID"),
                "path": relative.as_posix(),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
                "visibility": visibility,
                "redistributable": bool(artifact.get("redistributable", False)),
                "island_kind": str(
                    artifact.get("island_kind", "linked_dependency")
                ),
                "provenance": copy.deepcopy(artifact.get("provenance", {})),
                "library_identity": copy.deepcopy(
                    artifact.get("library_identity", {})
                ),
                "retention_model": str(
                    artifact.get("retention_model", "unknown")
                ),
                "interface_claims": copy.deepcopy(
                    _array(artifact.get("interface_claims", []), "interface claims")
                ),
                "index": indexed,
            }
        )
    rows.sort(key=lambda item: item["id"])
    fingerprints = sum(_artifact_function_count(row["index"]) for row in rows)
    core = {
        "format": (
            LIBRARY_ARTIFACT_INDEX_V2_FORMAT
            if declaration.get("format") == LIBRARY_ARTIFACT_INPUTS_V2_FORMAT
            else LIBRARY_ARTIFACT_INDEX_FORMAT
        ),
        "status": "indexed",
        "executes_original_binary": False,
        "catalog_id": declaration["catalog_id"],
        "snapshot": copy.deepcopy(declaration.get("snapshot")),
        "bindings": {"inputs_sha256": expected},
        "artifacts": rows,
        "counts": {
            "artifacts": len(rows),
            "private_artifacts": private_count,
            "public_artifacts": len(rows) - private_count,
            "function_fingerprints": fingerprints,
        },
        "authority": {
            "recognition": "proposal_only_until_target_bytes_and_semantics_are_checked",
            "symbols_and_names": "non_authoritative_hints",
            "can_authorize_replacement": False,
        },
    }
    payload = {**core, "index_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def lock_library_catalog(
    *, indexes: Sequence[Path | str], out: Path | str
) -> dict[str, Any]:
    """Lock only selected immutable catalog indexes for reproducible analysis."""

    entries = []
    catalog_ids: set[str] = set()
    for raw_path in indexes:
        path = Path(raw_path).resolve()
        payload = _read_object(path, "library artifact index")
        _validate_artifact_index(payload)
        catalog_id = str(payload["catalog_id"])
        if catalog_id in catalog_ids:
            raise LinkedLibraryError(f"duplicate locked catalog ID: {catalog_id}")
        catalog_ids.add(catalog_id)
        entries.append(
            {
                "catalog_id": catalog_id,
                "path": str(path),
                "file_sha256": sha256_file(path),
                "index_sha256": payload["index_sha256"],
                "contains_private_artifacts": bool(
                    payload["counts"]["private_artifacts"]
                ),
            }
        )
    entries.sort(key=lambda item: item["catalog_id"])
    core = {
        "format": LIBRARY_CATALOG_LOCK_FORMAT,
        "status": "locked",
        "entries": entries,
        "counts": {"catalogs": len(entries)},
        "policy": {
            "catalog_growth_invalidates_existing_lock": False,
            "private_entries_may_not_be_published": True,
        },
    }
    result = {**core, "lock_sha256": _canonical_sha256(core)}
    write_json(Path(out), result)
    return result
