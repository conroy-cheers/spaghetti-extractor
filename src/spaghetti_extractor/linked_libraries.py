"""Static linked-library recognition, qualification, and replacement planning.

Recognition is deliberately proposal-only.  Exact bytes and canonical machine
IR remain authoritative, and a recognized name never authorizes a replacement
without a separately checked component contract.
"""

from __future__ import annotations

import copy
import json
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .artifact_formats import (
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
from .stage_binary import StageAInputError, _parse_stage_a_pe
from .linked_library_contracts import (
    validate_linked_island_manifest as _validate_linked_island_contract,
)
from .util import sha256_file, write_json


_AR_MAGIC = b"!<arch>\n"
_THIN_AR_MAGIC = b"!<thin>\n"
_PE_MACHINE_I386 = 0x014C
_PE_MACHINE_AMD64 = 0x8664
_COFF_RELOCATION_WIDTHS_I386 = {
    0x0001: 2,
    0x0002: 2,
    0x0006: 4,
    0x0007: 4,
    0x000A: 2,
    0x000B: 4,
    0x000C: 1,
    0x0014: 4,
}
_COFF_RELOCATION_WIDTHS_AMD64 = {
    0x0001: 8,
    0x0002: 4,
    0x0003: 4,
    0x0004: 4,
    0x0005: 4,
    0x0006: 4,
    0x0007: 4,
    0x0008: 4,
    0x0009: 4,
    0x000A: 4,
    0x000B: 4,
}
_ISLAND_KINDS = {
    "application",
    "linked_dependency",
    "compiler_linker_support",
    "import_thunk",
    "unknown",
}
_MATCH_AUTHORITIES = {
    "exact_artifact",
    "exact_normalized_object",
    "operator_reviewed_exact_range",
    "proposal_only",
    "none",
}
_REPLACEMENT_KINDS = {
    "replace_by_canonical_interface",
    "replace_with_pinned_source_dependency",
    "relink_pinned_object",
    "lift_locally",
    "portable_machine_ir_fallback",
}
_ARTIFACT_INPUT_FORMATS = {
    LIBRARY_ARTIFACT_INPUTS_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_V2_FORMAT,
}
_ARTIFACT_INDEX_FORMATS = {
    LIBRARY_ARTIFACT_INDEX_FORMAT,
    LIBRARY_ARTIFACT_INDEX_V2_FORMAT,
}
_IDENTITY_STATUSES = {
    "exact_artifact",
    "exact_release",
    "library_family_abi",
    "ambiguous_family",
    "unidentified",
}
_DEFAULT_HYPOTHESIS_CAP = 256


class LinkedLibraryError(ValueError):
    """A linked-library artifact is malformed, stale, or contradictory."""


@dataclass(frozen=True)
class _Unit:
    identity: str
    start: int
    end: int
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class _MachinePackage:
    root: Path
    manifest_path: Path
    ir_path: Path
    manifest: Mapping[str, Any]
    units: tuple[_Unit, ...]
    by_id: Mapping[str, _Unit]
    ir_sha256: str
    manifest_sha256: str


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


def bind_linked_island_review(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Self-bind operator-reviewed exact ownership ranges."""

    core = copy.deepcopy(dict(payload))
    core.pop("review_sha256", None)
    if core.get("format") != LINKED_ISLAND_REVIEW_FORMAT:
        raise LinkedLibraryError("unsupported linked-island review format")
    _sha256(core.get("original_binary_sha256"), "review original binary SHA-256")
    seen: set[str] = set()
    for raw in _array(core.get("islands", []), "reviewed linked islands"):
        island = _object(raw, "reviewed linked island")
        identity = _nonempty(island.get("id"), "reviewed linked island ID")
        if identity in seen:
            raise LinkedLibraryError(f"duplicate reviewed island ID: {identity}")
        seen.add(identity)
        if island.get("kind") not in _ISLAND_KINDS - {"import_thunk", "unknown"}:
            raise LinkedLibraryError(f"reviewed island {identity} has invalid kind")
        if island.get("authority") != "operator_reviewed_exact_range":
            raise LinkedLibraryError(
                f"reviewed island {identity} lacks exact-range authority"
            )
        if not _array(island.get("ranges"), "reviewed linked island ranges"):
            raise LinkedLibraryError(f"reviewed island {identity} has no ranges")
    return {**core, "review_sha256": _canonical_sha256(core)}


def match_linked_islands(
    *,
    original: Path | str,
    machine_ir: Path | str,
    catalog_lock: Path | str | None,
    review: Path | str | Mapping[str, Any] | None,
    out: Path | str,
) -> dict[str, Any]:
    """Partition machine units and propose content-bound library identities."""

    original_path = Path(original)
    binary = _parse_stage_a_pe(original_path)
    machine = _load_machine_package(Path(machine_ir))
    machine_binary = _object(machine.manifest.get("binary"), "machine IR binary")
    if machine_binary.get("sha256") != binary.sha256:
        raise LinkedLibraryError("linked-island machine IR/original binary is stale")
    claimed: dict[str, str] = {}
    islands: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []

    if review is not None:
        reviewed = (
            _copy_object(review, "linked-island review")
            if isinstance(review, Mapping)
            else _read_object(Path(review), "linked-island review")
        )
        expected = reviewed.get("review_sha256")
        checked = bind_linked_island_review(reviewed)
        if expected != checked["review_sha256"]:
            raise LinkedLibraryError("linked-island review self-hash is stale")
        if reviewed.get("original_binary_sha256") != binary.sha256:
            raise LinkedLibraryError("linked-island review/original binary is stale")
        for raw in _array(reviewed.get("islands", []), "reviewed linked islands"):
            row = _reviewed_island(raw, machine, claimed)
            islands.append(row)
    else:
        expected = None

    thunk_groups: dict[tuple[str, str, int | None], list[_Unit]] = defaultdict(list)
    for unit in machine.units:
        if unit.identity in claimed:
            continue
        event = _import_thunk_event(unit.payload)
        if event is None:
            continue
        key = (
            str(event.get("dll", "")).lower(),
            str(event.get("symbol") or ""),
            event.get("ordinal") if isinstance(event.get("ordinal"), int) else None,
        )
        thunk_groups[key].append(unit)
    for (dll, symbol, ordinal), units in sorted(thunk_groups.items()):
        suffix = symbol or f"ordinal-{ordinal}"
        identity = f"import-thunk:{dll}:{suffix}"
        row = _island_from_units(
            identity=identity,
            kind="import_thunk",
            units=units,
            match={
                "authority": "exact_artifact",
                "identity_status": "exact_import_identity",
                "import": {"dll": dll, "symbol": symbol or None, "ordinal": ordinal},
            },
        )
        _claim_units(row, claimed)
        islands.append(row)

    indexes, lock_binding = _load_catalog_lock(catalog_lock)
    candidates = _catalog_function_candidates(indexes)
    target_matches = _find_target_artifact_matches(binary, machine, candidates)
    accepted: list[dict[str, Any]] = []
    ambiguous = 0
    for target_key, matches in sorted(target_matches.items()):
        start, end = target_key
        units = [
            unit for unit in machine.units
            if unit.start >= start and unit.end <= end and unit.identity not in claimed
        ]
        if not units or min(unit.start for unit in units) != start or max(unit.end for unit in units) != end:
            continue
        if len(matches) != 1:
            ambiguous += 1
            issues.append(
                _issue(
                    "incomplete",
                    "ambiguous_artifact_match",
                    "multiple library fingerprints match one exact target span",
                    rva_start=start,
                    rva_end=end,
                    candidates=[item["candidate_id"] for item in matches[:16]],
                )
            )
            continue
        match = matches[0]
        identity = "linked-artifact:" + sha256(
            f"{start:x}:{end:x}:{match['candidate_id']}".encode("ascii")
        ).hexdigest()[:20]
        row = _island_from_units(
            identity=identity,
            kind=str(match["island_kind"]),
            units=units,
            match={
                "authority": "exact_normalized_object",
                "identity_status": "exact_normalized_object",
                **match,
            },
        )
        _claim_units(row, claimed)
        accepted.append(row)
        islands.append(row)

    remaining = [unit for unit in machine.units if unit.identity not in claimed]
    if remaining:
        unknown = _island_from_units(
            identity="unknown:unclassified-machine-units",
            kind="unknown",
            units=remaining,
            match={
                "authority": "none",
                "identity_status": "unknown",
            },
        )
        _claim_units(unknown, claimed)
        islands.append(unknown)

    if set(claimed) != set(machine.by_id):
        raise LinkedLibraryError("linked-island classification omitted machine units")
    counts_by_kind = Counter(island["kind"] for island in islands)
    units_by_kind = Counter()
    reachable_by_kind = Counter()
    potential_by_kind = Counter()
    for island in islands:
        units_by_kind[island["kind"]] += island["unit_count"]
        reachable_by_kind[island["kind"]] += island["reachability"]["reachable_units"]
        potential_by_kind[island["kind"]] += island["reachability"]["potential_units"]
    islands.sort(key=lambda item: (item["rva_spans"][0]["rva_start"], item["id"]))
    status = "incomplete" if units_by_kind["unknown"] or issues else "classified"
    core = {
        "format": LINKED_ISLAND_MANIFEST_FORMAT,
        "status": status,
        "executes_original_binary": False,
        "bindings": {
            "original_binary_sha256": binary.sha256,
            "machine_ir_sha256": machine.ir_sha256,
            "machine_ir_manifest_sha256": machine.manifest_sha256,
            "review_sha256": expected,
            **lock_binding,
        },
        "islands": islands,
        "coverage": {
            "machine_units": len(machine.units),
            "classified_units": len(claimed),
            "classified_exactly_once": len(claimed) == len(machine.units),
            "units_by_kind": dict(sorted(units_by_kind.items())),
            "reachable_units_by_kind": dict(sorted(reachable_by_kind.items())),
            "potential_units_by_kind": dict(sorted(potential_by_kind.items())),
            "unknown_units": units_by_kind["unknown"],
        },
        "counts": {
            "islands": len(islands),
            "islands_by_kind": dict(sorted(counts_by_kind.items())),
            "artifact_matches": len(accepted),
            "ambiguous_artifact_matches": ambiguous,
            "issues": len(issues),
        },
        "issues": sorted(issues, key=_issue_sort_key),
        "authority": {
            "artifact_recognition_authorizes_replacement": False,
            "reviewed_ranges_bind_ownership_only": True,
            "semantic_qualification_required": True,
        },
    }
    payload = {**core, "manifest_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def propose_library_match_evidence(
    *,
    original: Path | str,
    machine_ir: Path | str,
    catalog_lock: Path | str,
    review: Path | str | Mapping[str, Any] | None,
    out: Path | str,
) -> dict[str, Any]:
    """Emit every exact artifact match without selecting an identity."""

    original_path = Path(original)
    binary = _parse_stage_a_pe(original_path)
    machine = _load_machine_package(Path(machine_ir))
    machine_binary = _object(machine.manifest.get("binary"), "machine IR binary")
    if machine_binary.get("sha256") != binary.sha256:
        raise LinkedLibraryError("library evidence machine IR/original binary is stale")

    excluded: dict[str, str] = {}
    review_sha256 = None
    if review is not None:
        reviewed = (
            _copy_object(review, "linked-island review")
            if isinstance(review, Mapping)
            else _read_object(Path(review), "linked-island review")
        )
        review_sha256 = reviewed.get("review_sha256")
        if bind_linked_island_review(reviewed).get("review_sha256") != review_sha256:
            raise LinkedLibraryError("linked-island review self-hash is stale")
        if reviewed.get("original_binary_sha256") != binary.sha256:
            raise LinkedLibraryError("linked-island review/original binary is stale")
        for raw in _array(reviewed.get("islands", []), "reviewed linked islands"):
            _reviewed_island(raw, machine, excluded)
    for unit in machine.units:
        if unit.identity not in excluded and _import_thunk_event(unit.payload) is not None:
            excluded[unit.identity] = "exact-import-thunk"

    indexes, lock_binding = _load_catalog_lock(catalog_lock)
    candidates = _catalog_function_candidates(indexes)
    target_matches = _find_target_artifact_matches(binary, machine, candidates)
    observations: list[dict[str, Any]] = []
    for (start, end), raw_matches in sorted(target_matches.items()):
        units = [
            unit
            for unit in machine.units
            if unit.start >= start
            and unit.end <= end
            and unit.identity not in excluded
        ]
        if (
            not units
            or min(unit.start for unit in units) != start
            or max(unit.end for unit in units) != end
        ):
            continue
        collapsed = _collapse_candidate_aliases(raw_matches)
        observations.append(
            {
                "id": f"target:{start:08x}-{end:08x}",
                "target": {
                    "rva_start": start,
                    "rva_end": end,
                    "unit_ids": sorted(unit.identity for unit in units),
                    "reachable": any(_unit_reachable(unit) for unit in units),
                },
                "candidates": collapsed,
                "candidate_count": len(collapsed),
            }
        )

    edges = []
    starts = {unit.start: unit.identity for unit in machine.units}
    for unit in machine.units:
        control = _object(unit.payload.get("control", {}), "machine unit control")
        for target in control.get("direct_targets", []) or []:
            if isinstance(target, int) and target in starts:
                edges.append(
                    {
                        "source_unit_id": unit.identity,
                        "target_unit_id": starts[target],
                        "control_kind": str(control.get("kind", "unknown")),
                    }
                )
    core = {
        "format": LIBRARY_MATCH_EVIDENCE_FORMAT,
        "status": "proposed",
        "executes_original_binary": False,
        "bindings": {
            "original_binary_sha256": binary.sha256,
            "machine_ir_sha256": machine.ir_sha256,
            "machine_ir_manifest_sha256": machine.manifest_sha256,
            "review_sha256": review_sha256,
            **lock_binding,
        },
        "observations": observations,
        "observed_control_edges": sorted(
            edges,
            key=lambda item: (
                item["source_unit_id"],
                item["target_unit_id"],
                item["control_kind"],
            ),
        ),
        "counts": {
            "target_spans": len(observations),
            "candidate_placements": sum(
                len(item["candidates"]) for item in observations
            ),
            "ambiguous_target_spans": sum(
                len(item["candidates"]) > 1 for item in observations
            ),
            "excluded_machine_units": len(excluded),
        },
        "authority": {
            "matching_is_provenance_evidence_only": True,
            "can_authorize_replacement": False,
        },
    }
    payload = {**core, "evidence_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def infer_library_hypotheses(
    *,
    match_evidence: Path | str | Mapping[str, Any],
    out: Path | str,
    max_hypotheses: int = _DEFAULT_HYPOTHESIS_CAP,
) -> dict[str, Any]:
    """Jointly resolve exact match evidence at member and library granularity."""

    if max_hypotheses <= 0:
        raise LinkedLibraryError("library hypothesis cap must be positive")
    evidence = (
        _copy_object(match_evidence, "library match evidence")
        if isinstance(match_evidence, Mapping)
        else _read_object(Path(match_evidence), "library match evidence")
    )
    _validate_self_hash(
        evidence,
        LIBRARY_MATCH_EVIDENCE_FORMAT,
        "evidence_sha256",
        "library match evidence",
    )

    observations = copy.deepcopy(
        _array(evidence.get("observations", []), "library match observations")
    )
    anchored_members: set[tuple[str, str]] = set()
    for observation in observations:
        candidates = _array(observation.get("candidates", []), "match candidates")
        if len(candidates) == 1 and _candidate_match_strength(
            _object(candidates[0], "match candidate")
        ) == "strong":
            key = _candidate_member_key(_object(candidates[0], "match candidate"))
            if key is not None:
                anchored_members.add(key)

    changed = True
    while changed:
        changed = False
        for observation in observations:
            candidates = _array(
                observation.get("candidates", []), "match candidates"
            )
            if len(candidates) <= 1:
                continue
            anchored = [
                candidate
                for candidate in candidates
                if _candidate_member_key(_object(candidate, "match candidate"))
                in anchored_members
            ]
            anchored_keys = {
                _candidate_member_key(_object(candidate, "match candidate"))
                for candidate in anchored
            }
            anchored_keys.discard(None)
            if len(anchored_keys) == 1:
                key = next(iter(anchored_keys))
                if len(anchored) < len(candidates):
                    observation["candidates"] = anchored
                    observation["candidate_count"] = len(anchored)
                    changed = True
                if key not in anchored_members:
                    anchored_members.add(key)
                    changed = True

    hypothesis_rows: dict[tuple[str, ...], dict[str, Any]] = {}
    selections: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for observation in observations:
        candidates = [
            _object(candidate, "match candidate")
            for candidate in _array(observation.get("candidates", []), "match candidates")
        ]
        for candidate in candidates:
            key = _candidate_hypothesis_key(candidate)
            row = hypothesis_rows.setdefault(
                key,
                {
                    "identity": _candidate_library_identity(candidate),
                    "snapshot": copy.deepcopy(candidate.get("snapshot")),
                    "artifact_id": candidate.get("artifact_id"),
                    "artifact_sha256": candidate.get("artifact_sha256"),
                    "target_ids": set(),
                    "member_ids": set(),
                    "symbols": set(),
                    "fixed_bytes": 0,
                },
            )
            row["target_ids"].add(str(observation["id"]))
            member_id = candidate.get("member_id")
            if isinstance(member_id, str):
                row["member_ids"].add(member_id)
            row["symbols"].update(str(value) for value in candidate.get("symbols", []))
            row["fixed_bytes"] += int(candidate.get("fixed_bytes") or 0)

        identity_status = _candidate_set_identity_status(candidates)
        if candidates and all(
            _candidate_match_strength(candidate) == "weak"
            for candidate in candidates
        ):
            identity_status = "unidentified"
        selection = {
            "target_id": observation["id"],
            "target": copy.deepcopy(observation["target"]),
            "identity_status": identity_status,
            "candidates": copy.deepcopy(candidates),
        }
        if identity_status in {"ambiguous_family", "unidentified"}:
            issues.append(
                _issue(
                    "incomplete",
                    "ambiguous_library_family"
                    if identity_status == "ambiguous_family"
                    else "unidentified_library_target",
                    "target span is not explained by one library family and ABI",
                    target_id=observation["id"],
                    rva_start=observation["target"]["rva_start"],
                )
            )
        selections.append(selection)

    hypotheses = []
    for key, row in sorted(hypothesis_rows.items()):
        hypothesis_id = "library-hypothesis:" + _canonical_sha256(list(key))[:24]
        hypotheses.append(
            {
                "id": hypothesis_id,
                "identity": row["identity"],
                "snapshot": row["snapshot"],
                "artifact_id": row["artifact_id"],
                "artifact_sha256": row["artifact_sha256"],
                "target_ids": sorted(row["target_ids"]),
                "member_ids": sorted(row["member_ids"]),
                "symbols": sorted(row["symbols"]),
                "rank": {
                    "exact_target_spans": len(row["target_ids"]),
                    "unique_fixed_bytes": row["fixed_bytes"],
                    "distinct_members": len(row["member_ids"]),
                    "checked_cross_member_edges": 0,
                    "unresolved_provider_frontiers": 0,
                },
            }
        )
    if len(hypotheses) > max_hypotheses:
        issues.append(
            _issue(
                "incomplete",
                "hypothesis_cap_exceeded",
                "library hypothesis enumeration exceeded its configured cap",
                expected_max=max_hypotheses,
                observed=len(hypotheses),
            )
        )
        hypotheses = hypotheses[:max_hypotheses]
    core = {
        "format": LIBRARY_HYPOTHESIS_SET_FORMAT,
        "status": "incomplete" if issues else "inferred",
        "executes_original_binary": False,
        "bindings": {
            "match_evidence_sha256": evidence["evidence_sha256"],
            **copy.deepcopy(evidence["bindings"]),
        },
        "hypotheses": hypotheses,
        "selected_placements": selections,
        "issues": sorted(issues, key=_issue_sort_key),
        "counts": {
            "hypotheses": len(hypotheses),
            "target_spans": len(selections),
            "exact_artifact": sum(
                item["identity_status"] == "exact_artifact" for item in selections
            ),
            "library_family_abi": sum(
                item["identity_status"] == "library_family_abi"
                for item in selections
            ),
            "ambiguous": sum(
                item["identity_status"] in {"ambiguous_family", "unidentified"}
                for item in selections
            ),
        },
        "authority": {
            "library_identity_is_provenance_only": True,
            "abi_identity_implies_behavior": False,
            "can_authorize_replacement": False,
        },
    }
    payload = {**core, "hypothesis_set_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def derive_dynamic_library_requirements(
    *,
    machine_ir: Path | str,
    machine_import_report: Path | str | None = None,
    out: Path | str,
) -> dict[str, Any]:
    """Preserve exact dynamic import identities and checked ABI call boundaries."""

    machine = _load_machine_package(Path(machine_ir))
    if machine_import_report is not None:
        return _derive_dynamic_requirements_from_report(
            machine=machine,
            report_path=Path(machine_import_report),
            out=Path(out),
        )
    requirements: dict[str, dict[str, Any]] = {}
    callsites: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for unit in machine.units:
        event = _import_thunk_event(unit.payload)
        if event is None:
            continue
        dll = _nonempty(event.get("dll"), "dynamic import DLL").lower()
        symbol = event.get("symbol")
        ordinal = event.get("ordinal")
        identity = str(symbol) if isinstance(symbol, str) and symbol else f"ordinal-{ordinal}"
        abi = event.get("abi_contract")
        qualified = isinstance(abi, Mapping) and all(
            key in abi
            for key in (
                "argument_words",
                "disposition",
                "memory_effect",
                "world_effect",
            )
        )
        if not qualified:
            issues.append(
                _issue(
                    "incomplete",
                    "dynamic_call_abi_incomplete",
                    "dynamic import has no complete checked machine-call contract",
                    unit_id=unit.identity,
                    dll=dll,
                    symbol=symbol,
                    ordinal=ordinal,
                    rva_start=unit.start,
                )
            )
        callsite = {
            "id": f"dynamic-call:{unit.start:08x}:{dll}:{identity}",
            "unit_id": unit.identity,
            "rva_start": unit.start,
            "rva_end": unit.end,
            "reachable": _unit_reachable(unit),
            "import": {"dll": dll, "symbol": symbol, "ordinal": ordinal},
            "status": "qualified" if qualified else "incomplete",
            "arguments": copy.deepcopy(event.get("arguments", [])),
            "stack_inputs": copy.deepcopy(event.get("stack_inputs", [])),
            "abi_contract": copy.deepcopy(abi),
        }
        callsites.append(callsite)
        requirement = requirements.setdefault(
            dll,
            {
                "dll": dll,
                "identity_status": "exact_import_identity",
                "symbols": set(),
                "ordinals": set(),
                "callsite_ids": [],
                "exact_runtime_version_known": False,
            },
        )
        if isinstance(symbol, str) and symbol:
            requirement["symbols"].add(symbol)
        elif isinstance(ordinal, int):
            requirement["ordinals"].add(ordinal)
        requirement["callsite_ids"].append(callsite["id"])

    libraries = []
    imports = []
    for dll, row in sorted(requirements.items()):
        libraries.append(
            {
                "id": f"dynamic-library:{dll}",
                "dll": dll,
                "identity_status": row["identity_status"],
                "symbols": sorted(row["symbols"]),
                "ordinals": sorted(row["ordinals"]),
                "callsite_ids": sorted(row["callsite_ids"]),
                "exact_runtime_version_known": False,
            }
        )
        for symbol in sorted(row["symbols"]):
            matching = [
                item
                for item in callsites
                if item["import"]["dll"] == dll
                and item["import"].get("symbol") == symbol
            ]
            imports.append(
                {
                    "id": f"dynamic-import:{dll}:{symbol}",
                    "import": {"dll": dll, "symbol": symbol, "ordinal": None},
                    "status": (
                        "qualified"
                        if matching and all(item["status"] == "qualified" for item in matching)
                        else "incomplete"
                    ),
                    "callsite_ids": sorted(item["id"] for item in matching),
                    "thunk_rvas": sorted({item["rva_start"] for item in matching}),
                }
            )
    reachable = [item for item in callsites if item["reachable"]]
    core = {
        "format": DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
        "status": (
            "incomplete"
            if any(item["status"] != "qualified" for item in reachable)
            else "qualified"
        ),
        "executes_original_binary": False,
        "bindings": {
            "machine_ir_sha256": machine.ir_sha256,
            "machine_ir_manifest_sha256": machine.manifest_sha256,
        },
        "libraries": libraries,
        "imports": imports,
        "callsites": sorted(callsites, key=lambda item: (item["rva_start"], item["id"])),
        "issues": sorted(issues, key=_issue_sort_key),
        "counts": {
            "libraries": len(libraries),
            "import_identities": sum(
                len(item["symbols"]) + len(item["ordinals"]) for item in libraries
            ),
            "callsites": len(callsites),
            "reachable_callsites": len(reachable),
            "qualified_reachable_callsites": sum(
                item["status"] == "qualified" for item in reachable
            ),
        },
        "authority": {
            "same_abi_implies_same_behavior": False,
            "lockstep_external_identity_preserved": True,
            "can_authorize_static_library_replacement": False,
        },
    }
    payload = {**core, "requirements_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def _derive_dynamic_requirements_from_report(
    *,
    machine: _MachinePackage,
    report_path: Path,
    out: Path,
) -> dict[str, Any]:
    report = _read_object(report_path, "static machine import contract report")
    if report.get("format") != "stage-a-static-machine-import-contracts-v1":
        raise LinkedLibraryError("unsupported static machine import report format")
    if report.get("status") != "ready":
        raise LinkedLibraryError("static machine import report is not ready")
    authority = _object(report.get("authority"), "machine import report authority")
    if (
        authority.get("lean_redecodes_boundary_routes") is not True
        or authority.get("lean_reparses_exact_pe_imports") is not True
        or authority.get("profile_status_fields_trusted") is not False
    ):
        raise LinkedLibraryError("static machine import report lacks checked authority")
    if report.get("exact_inventory_matches") is not True:
        raise LinkedLibraryError("static machine import report inventory is not exact")
    if _array(report.get("remaining_premises", []), "machine import premises"):
        raise LinkedLibraryError("static machine import report has remaining premises")
    if _array(report.get("blockers", []), "machine import blockers"):
        raise LinkedLibraryError("static machine import report has blockers")
    inputs = _object(report.get("inputs"), "machine import report inputs")
    machine_binary = _object(machine.manifest.get("binary"), "machine IR binary")
    if inputs.get("original_sha256") != machine_binary.get("sha256"):
        raise LinkedLibraryError("machine import report/original binary is stale")

    signature_rows = [
        _object(item, "machine import signature")
        for item in _array(report.get("signatures"), "machine import signatures")
    ]
    if any(not isinstance(item.get("id"), int) for item in signature_rows):
        raise LinkedLibraryError("machine import signature has no integer ID")
    signatures = {int(item["id"]): item for item in signature_rows}
    if len(signatures) != len(signature_rows):
        raise LinkedLibraryError("machine import report has duplicate signature IDs")
    units_by_start = {unit.start: unit for unit in machine.units}
    callsites: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    boundary_rows = [
        _object(item, "machine import boundary")
        for item in _array(report.get("boundaries"), "machine import boundaries")
    ]
    boundary_ids = [item.get("id") for item in boundary_rows]
    if any(not isinstance(value, int) for value in boundary_ids):
        raise LinkedLibraryError("machine import boundary has no integer ID")
    if len(set(boundary_ids)) != len(boundary_ids):
        raise LinkedLibraryError("machine import report has duplicate boundary IDs")
    for boundary in boundary_rows:
        imported = _object(boundary.get("import"), "machine import identity")
        dll = _nonempty(imported.get("dll"), "machine import DLL").lower()
        symbol = imported.get("symbol")
        ordinal = imported.get("ordinal")
        signature = signatures.get(boundary.get("signature_id"))
        argument_words = boundary.get("argument_words")
        qualified = (
            signature is not None
            and signature.get("bridgeable") is True
            and isinstance(argument_words, int)
            and argument_words >= 0
            and isinstance(boundary.get("argument_evidence"), str)
            and bool(boundary.get("argument_evidence"))
        )
        instruction_rva = int(boundary.get("instruction_rva", boundary.get("source_rva", 0)))
        containing = next(
            (
                unit
                for unit in machine.units
                if unit.start <= instruction_rva < unit.end
            ),
            None,
        )
        thunk_rva = boundary.get("thunk_rva")
        thunk_unit = units_by_start.get(thunk_rva) if isinstance(thunk_rva, int) else None
        identity = str(symbol) if isinstance(symbol, str) and symbol else f"ordinal-{ordinal}"
        if not qualified:
            issues.append(
                _issue(
                    "incomplete",
                    "checked_import_boundary_incomplete",
                    "checked import boundary lacks a bridgeable exact argument contract",
                    boundary_id=boundary.get("id"),
                    dll=dll,
                    symbol=symbol,
                    ordinal=ordinal,
                    rva_start=instruction_rva,
                )
            )
        callsites.append(
            {
                "id": f"dynamic-call:{instruction_rva:08x}:{dll}:{identity}:{boundary.get('id')}",
                "unit_id": containing.identity if containing is not None else None,
                "thunk_unit_id": thunk_unit.identity if thunk_unit is not None else None,
                "rva_start": int(boundary.get("source_rva", instruction_rva)),
                "rva_end": int(boundary.get("continuation_rva", instruction_rva + 1)),
                "instruction_rva": instruction_rva,
                "reachable": True,
                "import": {"dll": dll, "symbol": symbol, "ordinal": ordinal},
                "status": "qualified" if qualified else "incomplete",
                "route": boundary.get("route"),
                "thunk_rva": thunk_rva,
                "argument_evidence": boundary.get("argument_evidence"),
                "argument_words": argument_words,
                "abi_contract": (
                    {
                        "contract_id": (
                            f"{signature.get('profile_id')}:{signature.get('id')}"
                        ),
                        "calling_convention": signature.get("abi"),
                        "arity": copy.deepcopy(signature.get("arity")),
                        "argument_words": argument_words,
                        "disposition": signature.get("disposition"),
                        "memory_effect": signature.get("memory_effect"),
                        "memory_footprints": copy.deepcopy(
                            signature.get("memory_footprints", [])
                        ),
                        "world_effect": signature.get("world_effect"),
                        "callback_mode": signature.get("callback_mode"),
                    }
                    if signature is not None
                    else None
                ),
            }
        )

    grouped: dict[tuple[str, str | None, int | None], list[dict[str, Any]]] = defaultdict(list)
    for callsite in callsites:
        imported = callsite["import"]
        grouped[(imported["dll"], imported.get("symbol"), imported.get("ordinal"))].append(callsite)
    imports = []
    libraries_by_dll: dict[str, dict[str, Any]] = {}
    for (dll, symbol, ordinal), rows in sorted(
        grouped.items(), key=lambda item: (item[0][0], str(item[0][1]), int(item[0][2] or -1))
    ):
        identity = symbol or f"ordinal-{ordinal}"
        imports.append(
            {
                "id": f"dynamic-import:{dll}:{identity}",
                "import": {"dll": dll, "symbol": symbol, "ordinal": ordinal},
                "status": (
                    "qualified" if all(row["status"] == "qualified" for row in rows) else "incomplete"
                ),
                "callsite_ids": sorted(row["id"] for row in rows),
                "thunk_rvas": sorted(
                    {row["thunk_rva"] for row in rows if isinstance(row.get("thunk_rva"), int)}
                ),
            }
        )
        library = libraries_by_dll.setdefault(
            dll,
            {"symbols": set(), "ordinals": set(), "callsite_ids": []},
        )
        if symbol is not None:
            library["symbols"].add(symbol)
        elif ordinal is not None:
            library["ordinals"].add(ordinal)
        library["callsite_ids"].extend(row["id"] for row in rows)
    libraries = [
        {
            "id": f"dynamic-library:{dll}",
            "dll": dll,
            "identity_status": "exact_import_identity",
            "symbols": sorted(row["symbols"]),
            "ordinals": sorted(row["ordinals"]),
            "callsite_ids": sorted(row["callsite_ids"]),
            "exact_runtime_version_known": False,
        }
        for dll, row in sorted(libraries_by_dll.items())
    ]
    core = {
        "format": DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
        "status": "incomplete" if issues else "qualified",
        "executes_original_binary": False,
        "bindings": {
            "machine_ir_sha256": machine.ir_sha256,
            "machine_ir_manifest_sha256": machine.manifest_sha256,
            "machine_import_report_sha256": sha256_file(report_path),
            "reference_contract_sha256": inputs.get("reference_contract_sha256"),
        },
        "libraries": libraries,
        "imports": imports,
        "callsites": sorted(callsites, key=lambda item: (item["instruction_rva"], item["id"])),
        "issues": sorted(issues, key=_issue_sort_key),
        "counts": {
            "libraries": len(libraries),
            "import_identities": len(imports),
            "callsites": len(callsites),
            "reachable_callsites": len(callsites),
            "qualified_reachable_callsites": sum(
                item["status"] == "qualified" for item in callsites
            ),
        },
        "authority": {
            "same_abi_implies_same_behavior": False,
            "lockstep_external_identity_preserved": True,
            "callsite_routes_lean_redecoded": True,
            "can_authorize_static_library_replacement": False,
        },
    }
    payload = {**core, "requirements_sha256": _canonical_sha256(core)}
    write_json(out, payload)
    return payload


def refine_linked_islands(
    *,
    original: Path | str,
    machine_ir: Path | str,
    match_evidence: Path | str,
    hypotheses: Path | str,
    review: Path | str | Mapping[str, Any] | None,
    out: Path | str,
) -> dict[str, Any]:
    """Materialize v2 ownership islands from checked constellation evidence."""

    original_path = Path(original)
    binary = _parse_stage_a_pe(original_path)
    machine = _load_machine_package(Path(machine_ir))
    machine_binary = _object(machine.manifest.get("binary"), "machine IR binary")
    if machine_binary.get("sha256") != binary.sha256:
        raise LinkedLibraryError("refined islands machine IR/original binary is stale")
    evidence = _read_object(Path(match_evidence), "library match evidence")
    _validate_self_hash(
        evidence,
        LIBRARY_MATCH_EVIDENCE_FORMAT,
        "evidence_sha256",
        "library match evidence",
    )
    hypothesis_set = _read_object(Path(hypotheses), "library hypothesis set")
    _validate_self_hash(
        hypothesis_set,
        LIBRARY_HYPOTHESIS_SET_FORMAT,
        "hypothesis_set_sha256",
        "library hypothesis set",
    )
    if hypothesis_set.get("bindings", {}).get("match_evidence_sha256") != evidence.get(
        "evidence_sha256"
    ):
        raise LinkedLibraryError("library hypotheses/match evidence are stale")
    if evidence.get("bindings", {}).get("original_binary_sha256") != binary.sha256:
        raise LinkedLibraryError("library evidence/original binary is stale")
    if evidence.get("bindings", {}).get("machine_ir_sha256") != machine.ir_sha256:
        raise LinkedLibraryError("library evidence/machine IR is stale")

    claimed: dict[str, str] = {}
    islands: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    review_sha256 = None
    if review is not None:
        reviewed = (
            _copy_object(review, "linked-island review")
            if isinstance(review, Mapping)
            else _read_object(Path(review), "linked-island review")
        )
        review_sha256 = reviewed.get("review_sha256")
        if bind_linked_island_review(reviewed).get("review_sha256") != review_sha256:
            raise LinkedLibraryError("linked-island review self-hash is stale")
        if reviewed.get("original_binary_sha256") != binary.sha256:
            raise LinkedLibraryError("linked-island review/original binary is stale")
        for raw in _array(reviewed.get("islands", []), "reviewed linked islands"):
            islands.append(_reviewed_island(raw, machine, claimed))

    thunk_groups: dict[tuple[str, str, int | None], list[_Unit]] = defaultdict(list)
    for unit in machine.units:
        if unit.identity in claimed:
            continue
        event = _import_thunk_event(unit.payload)
        if event is not None:
            key = (
                str(event.get("dll", "")).lower(),
                str(event.get("symbol") or ""),
                event.get("ordinal") if isinstance(event.get("ordinal"), int) else None,
            )
            thunk_groups[key].append(unit)
    for (dll, symbol, ordinal), units in sorted(thunk_groups.items()):
        suffix = symbol or f"ordinal-{ordinal}"
        row = _island_from_units(
            identity=f"import-thunk:{dll}:{suffix}",
            kind="import_thunk",
            units=units,
            match={
                "authority": "exact_artifact",
                "identity_status": "exact_import_identity",
                "import": {"dll": dll, "symbol": symbol or None, "ordinal": ordinal},
            },
        )
        _claim_units(row, claimed)
        islands.append(row)

    for placement in hypothesis_set.get("selected_placements", []):
        status = placement.get("identity_status")
        if status not in {"exact_artifact", "exact_release", "library_family_abi"}:
            continue
        target = _object(placement.get("target"), "selected target")
        unit_ids = [str(value) for value in target.get("unit_ids", [])]
        units = [machine.by_id[value] for value in unit_ids if value in machine.by_id]
        if len(units) != len(unit_ids) or any(unit.identity in claimed for unit in units):
            continue
        candidates = [
            _object(value, "selected target candidate")
            for value in placement.get("candidates", [])
        ]
        kinds = {str(candidate.get("island_kind")) for candidate in candidates}
        if len(kinds) != 1 or next(iter(kinds)) not in {
            "linked_dependency",
            "compiler_linker_support",
        }:
            issues.append(
                _issue(
                    "incomplete",
                    "constellation_kind_ambiguous",
                    "selected library candidates disagree about ownership kind",
                    target_id=placement.get("target_id"),
                    rva_start=target.get("rva_start"),
                )
            )
            continue
        kind = next(iter(kinds))
        identities = [_candidate_library_identity(candidate) for candidate in candidates]
        island_id = "constellation:" + _canonical_sha256(
            {
                "target_id": placement.get("target_id"),
                "status": status,
                "identities": identities,
            }
        )[:24]
        row = _island_from_units(
            identity=island_id,
            kind=kind,
            units=units,
            match={
                "authority": "exact_normalized_object",
                "identity_status": status,
                "library_identities": identities,
                "candidates": copy.deepcopy(candidates),
                "target_id": placement.get("target_id"),
            },
        )
        _claim_units(row, claimed)
        islands.append(row)

    remaining = [unit for unit in machine.units if unit.identity not in claimed]
    for position, units in enumerate(_unknown_unit_components(remaining)):
        row = _island_from_units(
            identity=f"unknown:cfg-component-{position:05d}",
            kind="unknown",
            units=units,
            match={"authority": "none", "identity_status": "unknown"},
        )
        _claim_units(row, claimed)
        islands.append(row)

    if set(claimed) != set(machine.by_id):
        raise LinkedLibraryError("refined linked islands omitted machine units")
    counts_by_kind = Counter(str(island["kind"]) for island in islands)
    units_by_kind = Counter()
    reachable_by_kind = Counter()
    potential_by_kind = Counter()
    for island in islands:
        kind = str(island["kind"])
        units_by_kind[kind] += int(island["unit_count"])
        reachable_by_kind[kind] += int(island["reachability"]["reachable_units"])
        potential_by_kind[kind] += int(island["reachability"]["potential_units"])
    islands.sort(key=lambda item: (item["rva_spans"][0]["rva_start"], item["id"]))
    if hypothesis_set.get("status") == "incomplete":
        issues.extend(copy.deepcopy(hypothesis_set.get("issues", [])))
    core = {
        "format": LINKED_ISLAND_MANIFEST_V2_FORMAT,
        "status": "incomplete" if units_by_kind["unknown"] or issues else "classified",
        "executes_original_binary": False,
        "bindings": {
            "original_binary_sha256": binary.sha256,
            "machine_ir_sha256": machine.ir_sha256,
            "machine_ir_manifest_sha256": machine.manifest_sha256,
            "review_sha256": review_sha256,
            "match_evidence_sha256": evidence["evidence_sha256"],
            "hypothesis_set_sha256": hypothesis_set["hypothesis_set_sha256"],
            "catalog_lock_sha256": evidence["bindings"].get("catalog_lock_sha256"),
        },
        "islands": islands,
        "coverage": {
            "machine_units": len(machine.units),
            "classified_units": len(claimed),
            "classified_exactly_once": len(claimed) == len(machine.units),
            "units_by_kind": dict(sorted(units_by_kind.items())),
            "reachable_units_by_kind": dict(sorted(reachable_by_kind.items())),
            "potential_units_by_kind": dict(sorted(potential_by_kind.items())),
            "unknown_units": units_by_kind["unknown"],
        },
        "counts": {
            "islands": len(islands),
            "islands_by_kind": dict(sorted(counts_by_kind.items())),
            "constellation_matches": sum(
                island["id"].startswith("constellation:") for island in islands
            ),
            "unknown_cfg_components": counts_by_kind["unknown"],
            "issues": len(issues),
        },
        "issues": sorted(issues, key=_issue_sort_key),
        "authority": {
            "artifact_recognition_authorizes_replacement": False,
            "reviewed_ranges_bind_ownership_only": True,
            "semantic_qualification_required": True,
            "abi_identity_implies_behavior": False,
        },
    }
    payload = {**core, "manifest_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def bind_interface_contract_catalog(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and self-bind reusable interface contracts and replacements."""

    core = copy.deepcopy(dict(payload))
    core.pop("catalog_sha256", None)
    if core.get("format") != LIBRARY_INTERFACE_CATALOG_FORMAT:
        raise LinkedLibraryError("unsupported interface contract catalog format")
    _nonempty(core.get("catalog_id"), "interface contract catalog ID")
    contract_ids: set[str] = set()
    for raw in _array(core.get("contracts", []), "interface contracts"):
        contract = _object(raw, "interface contract")
        identity = _nonempty(contract.get("id"), "interface contract ID")
        if identity in contract_ids:
            raise LinkedLibraryError(f"duplicate interface contract ID: {identity}")
        contract_ids.add(identity)
        descriptor = _object(contract.get("component_contract"), "component contract")
        _nonempty(descriptor.get("format"), "component contract format")
        _sha256(descriptor.get("contract_sha256"), "component contract SHA-256")
        domain = _object(contract.get("domain"), "interface contract domain")
        if domain.get("kind") not in {"total", "caller_proven", "guarded"}:
            raise LinkedLibraryError(f"interface contract {identity} has invalid domain")
    replacement_ids: set[str] = set()
    for raw in _array(core.get("replacements", []), "interface replacements"):
        replacement = _object(raw, "interface replacement")
        identity = _nonempty(replacement.get("id"), "interface replacement ID")
        if identity in replacement_ids:
            raise LinkedLibraryError(f"duplicate interface replacement ID: {identity}")
        replacement_ids.add(identity)
        if replacement.get("contract_id") not in contract_ids:
            raise LinkedLibraryError(
                f"replacement {identity} references unknown interface contract"
            )
        if replacement.get("kind") not in _REPLACEMENT_KINDS - {
            "portable_machine_ir_fallback",
            "lift_locally",
        }:
            raise LinkedLibraryError(f"replacement {identity} has invalid kind")
        qualification = _object(
            replacement.get("qualification"), "replacement qualification"
        )
        if qualification.get("status") not in {"qualified", "guarded", "incomplete"}:
            raise LinkedLibraryError(
                f"replacement {identity} has invalid qualification status"
            )
        implementation = _object(
            replacement.get("implementation"), "replacement implementation"
        )
        _sha256(
            implementation.get("portable_source_sha256"),
            "replacement portable source SHA-256",
        )
        _nonempty(
            implementation.get("portable_symbol"),
            "replacement portable symbol",
        )
    return {**core, "catalog_sha256": _canonical_sha256(core)}


def bind_linked_interface_assignments(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return self-bound operator assignments for linked interfaces."""

    core = copy.deepcopy(dict(payload))
    core.pop("assignments_sha256", None)
    if core.get("format") != LINKED_INTERFACE_ASSIGNMENTS_FORMAT:
        raise LinkedLibraryError("unsupported linked interface assignments format")
    _sha256(
        core.get("linked_island_manifest_sha256"),
        "linked-island manifest SHA-256",
    )
    seen: set[str] = set()
    for raw in _array(core.get("assignments", []), "linked interface assignments"):
        assignment = _object(raw, "linked interface assignment")
        island_id = _nonempty(assignment.get("island_id"), "assigned island ID")
        if island_id in seen:
            raise LinkedLibraryError(f"duplicate linked interface assignment: {island_id}")
        seen.add(island_id)
        _nonempty(assignment.get("contract_id"), "assigned contract ID")
        _object(assignment.get("evidence"), "linked interface assignment evidence")
    return {**core, "assignments_sha256": _canonical_sha256(core)}


def qualify_linked_interfaces(
    *,
    linked_islands: Path | str,
    interface_catalog: Path | str | Mapping[str, Any],
    assignments: Path | str | Mapping[str, Any],
    out: Path | str,
) -> dict[str, Any]:
    """Bind checked component evidence to proposed library interfaces."""

    manifest_path = Path(linked_islands)
    manifest = _read_object(manifest_path, "linked-island manifest")
    _validate_linked_island_manifest(manifest)
    catalog = (
        _copy_object(interface_catalog, "interface contract catalog")
        if isinstance(interface_catalog, Mapping)
        else _read_object(Path(interface_catalog), "interface contract catalog")
    )
    expected_catalog = catalog.get("catalog_sha256")
    checked_catalog = bind_interface_contract_catalog(catalog)
    if expected_catalog != checked_catalog["catalog_sha256"]:
        raise LinkedLibraryError("interface contract catalog self-hash is stale")
    assignment_payload = (
        _copy_object(assignments, "linked interface assignments")
        if isinstance(assignments, Mapping)
        else _read_object(Path(assignments), "linked interface assignments")
    )
    if assignment_payload.get("format") != LINKED_INTERFACE_ASSIGNMENTS_FORMAT:
        raise LinkedLibraryError("unsupported linked interface assignments format")
    assignment_core = copy.deepcopy(assignment_payload)
    observed_assignment_hash = assignment_core.pop("assignments_sha256", None)
    if observed_assignment_hash != _canonical_sha256(assignment_core):
        raise LinkedLibraryError("linked interface assignments self-hash is stale")
    if assignment_payload.get("linked_island_manifest_sha256") != manifest["manifest_sha256"]:
        raise LinkedLibraryError("linked interface assignments are stale")

    islands = {str(item["id"]): item for item in manifest["islands"]}
    contracts = {str(item["id"]): item for item in catalog.get("contracts", [])}
    results: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    seen_islands: set[str] = set()
    for raw in _array(assignment_payload.get("assignments", []), "interface assignments"):
        assignment = _object(raw, "linked interface assignment")
        island_id = _nonempty(assignment.get("island_id"), "assigned island ID")
        contract_id = _nonempty(assignment.get("contract_id"), "assigned contract ID")
        if island_id in seen_islands:
            raise LinkedLibraryError(f"duplicate interface assignment: {island_id}")
        seen_islands.add(island_id)
        island = islands.get(island_id)
        contract = contracts.get(contract_id)
        row_issues: list[dict[str, Any]] = []
        if island is None:
            row_issues.append(
                _issue("violated", "unknown_assigned_island", "assignment names an unknown island", island_id=island_id)
            )
        if contract is None:
            row_issues.append(
                _issue("violated", "unknown_assigned_contract", "assignment names an unknown contract", island_id=island_id, contract_id=contract_id)
            )
        evidence = _object(assignment.get("evidence"), "interface assignment evidence")
        evidence_kind = evidence.get("kind")
        evidence_binding: dict[str, Any] = {"kind": evidence_kind}
        if evidence_kind == "component_qualification":
            path = Path(_nonempty(evidence.get("path"), "component qualification path"))
            qualification = _read_object(path, "component qualification")
            expected_file = evidence.get("file_sha256")
            if expected_file != sha256_file(path):
                row_issues.append(
                    _issue("violated", "stale_component_qualification", "component qualification file hash differs", island_id=island_id)
                )
            try:
                _validate_self_hash(
                    qualification,
                    COMPONENT_QUALIFICATION_FORMAT,
                    "qualification_sha256",
                    "component qualification",
                )
            except LinkedLibraryError as error:
                row_issues.append(
                    _issue(
                        "violated",
                        "malformed_component_qualification",
                        str(error),
                        island_id=island_id,
                    )
                )
            if (
                qualification.get("status") != "qualified"
                or qualification.get("executes_original_binary") is not False
                or qualification.get("activation", {}).get("authorized") is not True
            ):
                row_issues.append(
                    _issue("incomplete", "component_not_qualified", "component evidence is not qualified", island_id=island_id)
                )
            descriptor = _qualification_contract_descriptor(qualification)
            expected_descriptor = contract.get("component_contract") if contract else None
            if descriptor != expected_descriptor:
                row_issues.append(
                    _issue("violated", "component_contract_mismatch", "component qualification proves a different contract", island_id=island_id, contract_id=contract_id, expected=expected_descriptor, observed=descriptor)
                )
            if island is not None:
                qualified_units = set(_qualification_unit_ids(qualification))
                island_units = set(island["unit_ids"])
                if qualified_units != island_units:
                    row_issues.append(
                        _issue("violated", "qualification_membership_mismatch", "component qualification does not cover the exact island", island_id=island_id, expected=sorted(island_units), observed=sorted(qualified_units))
                    )
            implementation = qualification.get("implementation")
            if not isinstance(implementation, Mapping):
                row_issues.append(
                    _issue(
                        "violated",
                        "qualification_implementation_missing",
                        "component qualification omits its portable implementation identity",
                        island_id=island_id,
                    )
                )
            else:
                try:
                    portable_source_sha256 = _sha256(
                        implementation.get("portable_source_sha256"),
                        "qualified portable source SHA-256",
                    )
                    portable_symbol = _nonempty(
                        implementation.get("portable_symbol"),
                        "qualified portable symbol",
                    )
                    evidence_binding["implementation"] = {
                        "portable_source_sha256": portable_source_sha256,
                        "portable_symbol": portable_symbol,
                    }
                except LinkedLibraryError as error:
                    row_issues.append(
                        _issue(
                            "violated",
                            "qualification_implementation_malformed",
                            str(error),
                            island_id=island_id,
                        )
                    )
            evidence_binding.update(
                {
                    "path": str(path.resolve()),
                    "file_sha256": sha256_file(path),
                    "qualification_sha256": qualification.get(
                        "qualification_sha256"
                    ),
                }
            )
        elif evidence_kind == "checked_contract_certificate":
            row_issues.append(
                _issue(
                    "incomplete",
                    "certificate_checker_unavailable",
                    "a certificate hash cannot authorize replacement without a checked certificate format",
                    island_id=island_id,
                    contract_id=contract_id,
                )
            )
        elif evidence_kind in {"identity_only", "operator_proposal"}:
            row_issues.append(
                _issue("incomplete", "semantic_qualification_missing", "artifact identity does not establish interface behavior", island_id=island_id, contract_id=contract_id)
            )
        else:
            row_issues.append(
                _issue("violated", "unsupported_qualification_evidence", "assignment uses unsupported evidence", island_id=island_id, contract_id=contract_id)
            )
        status = (
            "violated" if any(item["status"] == "violated" for item in row_issues)
            else "incomplete" if row_issues
            else "qualified"
        )
        issues.extend(row_issues)
        results.append(
            {
                "island_id": island_id,
                "contract_id": contract_id,
                "status": status,
                "domain": copy.deepcopy(contract.get("domain")) if contract else None,
                "evidence": evidence_binding,
                "issues": sorted(row_issues, key=_issue_sort_key),
            }
        )
    qualified = sum(row["status"] == "qualified" for row in results)
    overall = (
        "violated" if any(item["status"] == "violated" for item in issues)
        else "incomplete" if issues or qualified < len(islands)
        else "qualified"
    )
    core = {
        "format": LINKED_INTERFACE_QUALIFICATION_FORMAT,
        "status": overall,
        "executes_original_binary": False,
        "bindings": {
            "linked_island_manifest_sha256": manifest["manifest_sha256"],
            "interface_catalog_sha256": expected_catalog,
            "assignments_sha256": observed_assignment_hash,
        },
        "qualifications": sorted(results, key=lambda item: item["island_id"]),
        "counts": {
            "islands": len(islands),
            "assignments": len(results),
            "qualified": qualified,
            "incomplete": sum(row["status"] == "incomplete" for row in results),
            "violated": sum(row["status"] == "violated" for row in results),
            "unassigned": len(islands) - len(results),
        },
        "issues": sorted(issues, key=_issue_sort_key),
        "authority": {
            "artifact_identity_is_semantic_proof": False,
            "component_contract_authority_reused": True,
        },
    }
    payload = {**core, "qualification_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def plan_library_replacements(
    *,
    linked_islands: Path | str,
    interface_qualification: Path | str,
    interface_catalog: Path | str | Mapping[str, Any],
    dynamic_requirements: Path | str | None = None,
    out: Path | str,
) -> dict[str, Any]:
    """Select qualified portable replacements and explicit machine-IR fallbacks."""

    manifest = _read_object(Path(linked_islands), "linked-island manifest")
    _validate_linked_island_manifest(manifest)
    qualification = _read_object(
        Path(interface_qualification), "linked interface qualification"
    )
    _validate_self_hash(
        qualification,
        LINKED_INTERFACE_QUALIFICATION_FORMAT,
        "qualification_sha256",
        "linked interface qualification",
    )
    if qualification["bindings"]["linked_island_manifest_sha256"] != manifest["manifest_sha256"]:
        raise LinkedLibraryError("interface qualification/linked islands are stale")
    catalog = (
        _copy_object(interface_catalog, "interface contract catalog")
        if isinstance(interface_catalog, Mapping)
        else _read_object(Path(interface_catalog), "interface contract catalog")
    )
    expected_catalog = catalog.get("catalog_sha256")
    if expected_catalog != bind_interface_contract_catalog(catalog)["catalog_sha256"]:
        raise LinkedLibraryError("interface contract catalog self-hash is stale")
    if qualification["bindings"]["interface_catalog_sha256"] != expected_catalog:
        raise LinkedLibraryError("interface qualification/catalog binding is stale")

    dynamic = None
    dynamic_by_unit: dict[str, Mapping[str, Any]] = {}
    dynamic_by_import: dict[tuple[str, str | None, int | None], Mapping[str, Any]] = {}
    if dynamic_requirements is not None:
        dynamic = _read_object(
            Path(dynamic_requirements), "dynamic library requirements"
        )
        _validate_self_hash(
            dynamic,
            DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
            "requirements_sha256",
            "dynamic library requirements",
        )
        dynamic_by_unit = {
            str(item["unit_id"]): item for item in dynamic.get("callsites", [])
            if item.get("unit_id") is not None
        }
        dynamic_by_import = {
            (
                str(item.get("import", {}).get("dll", "")).lower(),
                item.get("import", {}).get("symbol"),
                item.get("import", {}).get("ordinal"),
            ): item
            for item in dynamic.get("imports", [])
        }

    qualified_by_island = {
        str(item["island_id"]): item
        for item in qualification.get("qualifications", [])
        if item.get("status") == "qualified"
    }
    replacements_by_contract: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for replacement in catalog.get("replacements", []):
        if replacement.get("qualification", {}).get("status") in {"qualified", "guarded"}:
            replacements_by_contract[str(replacement["contract_id"])].append(replacement)
    plan: list[dict[str, Any]] = []
    for island in manifest["islands"]:
        island_id = str(island["id"])
        qualified = qualified_by_island.get(island_id)
        selected: Mapping[str, Any] | None = None
        if qualified is not None:
            choices = replacements_by_contract.get(str(qualified["contract_id"]), [])
            qualified_implementation = qualified.get("evidence", {}).get(
                "implementation"
            )
            bound_choices = [
                choice
                for choice in choices
                if choice.get("implementation") == qualified_implementation
            ]
            portable = [
                choice
                for choice in bound_choices
                if bool(choice.get("portable", False))
            ]
            ordered = sorted(
                portable or bound_choices, key=lambda item: str(item["id"])
            )
            selected = ordered[0] if ordered else None
        external_calls = [
            dynamic_by_unit.get(str(unit_id)) for unit_id in island["unit_ids"]
        ]
        import_identity = island.get("match", {}).get("import", {})
        import_requirement = (
            dynamic_by_import.get(
                (
                    str(import_identity.get("dll", "")).lower(),
                    import_identity.get("symbol"),
                    import_identity.get("ordinal"),
                )
            )
            if island["kind"] == "import_thunk"
            else None
        )
        external_preserved = (
            island["kind"] == "import_thunk"
            and (
                (
                    import_requirement is not None
                    and import_requirement.get("status") == "qualified"
                )
                or (
                    bool(external_calls)
                    and all(
                        call is not None and call.get("status") == "qualified"
                        for call in external_calls
                    )
                )
            )
        )
        if selected is not None:
            disposition = str(selected["kind"])
            status = "ready"
            reason = "qualified_interface_and_replacement"
            replacement_id = selected["id"]
        elif external_preserved:
            disposition = "preserve_external_call"
            status = "ready"
            reason = "exact_import_identity_and_checked_machine_call_contract"
            replacement_id = None
        elif island["kind"] == "application":
            disposition = "lift_locally"
            status = "incomplete"
            reason = "application_island_requires_component_or_source_lift"
            replacement_id = None
        else:
            disposition = "portable_machine_ir_fallback"
            status = "fallback"
            reason = "no_qualified_portable_replacement"
            replacement_id = None
        plan.append(
            {
                "island_id": island_id,
                "kind": island["kind"],
                "unit_ids": copy.deepcopy(island["unit_ids"]),
                "status": status,
                "disposition": disposition,
                "reason": reason,
                "contract_id": qualified.get("contract_id") if qualified else None,
                "replacement_id": replacement_id,
                "external_call_contract_ids": sorted(
                    {
                        str(call.get("abi_contract", {}).get("contract_id"))
                        for call in external_calls
                        if isinstance(call, Mapping)
                        and isinstance(call.get("abi_contract"), Mapping)
                        and call.get("abi_contract", {}).get("contract_id") is not None
                    }
                ),
                "dynamic_import_requirement_id": (
                    import_requirement.get("id")
                    if import_requirement is not None
                    else None
                ),
            }
        )
    counts = Counter(row["status"] for row in plan)
    dynamic_callsites = (
        [
            {
                "id": item["id"],
                "status": (
                    "ready" if item.get("status") == "qualified" else "incomplete"
                ),
                "import": copy.deepcopy(item.get("import")),
                "source_unit_id": item.get("unit_id"),
                "instruction_rva": item.get(
                    "instruction_rva", item.get("rva_start")
                ),
                "contract_id": (
                    item.get("abi_contract", {}).get("contract_id")
                    if isinstance(item.get("abi_contract"), Mapping)
                    else None
                ),
            }
            for item in dynamic.get("callsites", [])
        ]
        if dynamic is not None
        else []
    )
    ready_dynamic_callsites = sum(
        item["status"] == "ready" for item in dynamic_callsites
    )
    incomplete_dynamic_callsites = len(dynamic_callsites) - ready_dynamic_callsites
    idiomatic_complete = (
        not counts["fallback"]
        and not counts["incomplete"]
        and not incomplete_dynamic_callsites
    )
    core = {
        "format": LIBRARY_REPLACEMENT_PLAN_FORMAT,
        "status": "complete" if idiomatic_complete else "incomplete",
        "executes_original_binary": False,
        "bindings": {
            "linked_island_manifest_sha256": manifest["manifest_sha256"],
            "interface_qualification_sha256": qualification["qualification_sha256"],
            "interface_catalog_sha256": expected_catalog,
            "dynamic_requirements_sha256": (
                dynamic.get("requirements_sha256") if dynamic is not None else None
            ),
        },
        "islands": plan,
        "dynamic_callsites": dynamic_callsites,
        "counts": {
            "islands": len(plan),
            "ready": counts["ready"],
            "fallback": counts["fallback"],
            "incomplete": counts["incomplete"],
            "preserved_external_calls": sum(
                row["disposition"] == "preserve_external_call" for row in plan
            ),
            "dynamic_callsites": (
                len(dynamic.get("callsites", [])) if dynamic is not None else 0
            ),
            "ready_dynamic_callsites": ready_dynamic_callsites,
            "incomplete_dynamic_callsites": incomplete_dynamic_callsites,
        },
        "completion": {
            "working_hybrid_executable": True,
            "idiomatic_source_complete": idiomatic_complete,
            "fallback_counts_as_lifting_progress": False,
        },
    }
    payload = {**core, "plan_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def _index_artifact_blob(*, data: bytes, label: str, source_path: Path) -> dict[str, Any]:
    if data.startswith(_THIN_AR_MAGIC):
        return {
            "kind": "thin_archive",
            "status": "incomplete",
            "sha256": sha256(data).hexdigest(),
            "issues": [{"code": "thin_archive_external_members", "message": "thin archives require an explicit materialized member manifest"}],
        }
    if data.startswith(_AR_MAGIC):
        return _index_archive(data, label=label)
    if data.startswith(b"MZ"):
        return _index_pe(source_path)
    if _looks_like_coff(data):
        return _index_coff(data, label=label)
    if _looks_like_omf(data):
        return _index_omf(data, label=label)
    return {
        "kind": "opaque",
        "status": "indexed",
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
        "function_fingerprints": [],
    }


def _index_archive(data: bytes, *, label: str) -> dict[str, Any]:
    offset = len(_AR_MAGIC)
    long_names = b""
    members: list[dict[str, Any]] = []
    while offset < len(data):
        if offset + 60 > len(data):
            raise LinkedLibraryError(f"archive {label} has a truncated member header")
        header = data[offset : offset + 60]
        if header[58:60] != b"`\n":
            raise LinkedLibraryError(f"archive {label} has an invalid member header")
        raw_name = header[:16].decode("ascii", errors="replace").rstrip()
        try:
            size = int(header[48:58].decode("ascii").strip() or "0")
        except ValueError as error:
            raise LinkedLibraryError(f"archive {label} has an invalid member size") from error
        start = offset + 60
        end = start + size
        if end > len(data):
            raise LinkedLibraryError(f"archive {label} has a truncated member")
        body = data[start:end]
        name = raw_name.rstrip("/")
        if raw_name == "//":
            long_names = body
            offset = end + (end & 1)
            continue
        if raw_name.startswith("#1/"):
            name_size = int(raw_name[3:])
            if name_size > len(body):
                raise LinkedLibraryError(f"archive {label} has a bad BSD member name")
            name = body[:name_size].decode("utf-8", errors="replace").rstrip("\0")
            body = body[name_size:]
        elif raw_name.startswith("/") and raw_name[1:].isdigit() and long_names:
            name_offset = int(raw_name[1:])
            if name_offset >= len(long_names):
                raise LinkedLibraryError(f"archive {label} has a bad GNU name offset")
            name_end = long_names.find(b"/\n", name_offset)
            if name_end < 0:
                name_end = long_names.find(b"\0", name_offset)
            if name_end < 0:
                name_end = len(long_names)
            name = long_names[name_offset:name_end].decode("utf-8", errors="replace")
        special = raw_name in {"/", "//"} or raw_name.startswith("/ ")
        if special:
            nested = {
                "kind": "archive_index",
                "status": "indexed",
                "function_fingerprints": [],
            }
        elif body.startswith(b"MZ"):
            nested = {
                "kind": "pe_image_member",
                "status": "incomplete",
                "sha256": sha256(body).hexdigest(),
                "bytes": len(body),
                "function_fingerprints": [],
                "issues": [
                    {
                        "code": "embedded_pe_requires_materialization",
                        "message": (
                            "archive-contained PE images must be declared as "
                            "standalone content-bound artifacts"
                        ),
                    }
                ],
            }
        else:
            nested = _index_artifact_blob(
                data=body,
                label=f"{label}:{name}",
                source_path=Path(name),
            )
        members.append(
            {
                "name": name or raw_name,
                "sha256": sha256(body).hexdigest(),
                "bytes": len(body),
                "index": nested,
            }
        )
        offset = end + (end & 1)
    return {
        "kind": "archive",
        "status": "indexed",
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
        "members": members,
        "counts": {
            "members": len(members),
            "function_fingerprints": sum(_artifact_function_count(member["index"]) for member in members),
        },
    }


def _looks_like_coff(data: bytes) -> bool:
    if len(data) < 20:
        return False
    machine, section_count, _time, _symbols, _count, optional_size, _flags = struct.unpack_from("<HHIIIHH", data, 0)
    return machine in {_PE_MACHINE_I386, _PE_MACHINE_AMD64} and 0 < section_count < 512 and optional_size == 0


def _index_coff(data: bytes, *, label: str) -> dict[str, Any]:
    machine, section_count, timestamp, symbol_pointer, symbol_count, optional_size, flags = struct.unpack_from("<HHIIIHH", data, 0)
    section_start = 20 + optional_size
    if section_start + section_count * 40 > len(data):
        raise LinkedLibraryError(f"COFF object {label} has a truncated section table")
    string_start = symbol_pointer + symbol_count * 18
    string_size = (
        int.from_bytes(data[string_start : string_start + 4], "little")
        if string_start + 4 <= len(data)
        else 0
    )
    sections: list[dict[str, Any]] = []
    relocations_by_section: dict[int, list[dict[str, int]]] = defaultdict(list)
    for index in range(section_count):
        offset = section_start + index * 40
        header = data[offset : offset + 40]
        name = _coff_name(header[:8], data, string_start, string_size)
        virtual_size, virtual_address, raw_size, raw_pointer, reloc_pointer, _line_pointer, reloc_count, _line_count, characteristics = struct.unpack_from("<IIIIIIHHI", header, 8)
        if raw_pointer + raw_size > len(data):
            raise LinkedLibraryError(f"COFF object {label} section {name} exceeds file")
        section_bytes = data[raw_pointer : raw_pointer + raw_size]
        relocation_widths = _COFF_RELOCATION_WIDTHS_I386 if machine == _PE_MACHINE_I386 else _COFF_RELOCATION_WIDTHS_AMD64
        if reloc_pointer + reloc_count * 10 > len(data):
            raise LinkedLibraryError(f"COFF object {label} has truncated relocations")
        for relocation_index in range(reloc_count):
            relocation_offset = reloc_pointer + relocation_index * 10
            address, symbol_index, relocation_type = struct.unpack_from("<IIH", data, relocation_offset)
            relocations_by_section[index + 1].append(
                {
                    "offset": address,
                    "symbol_index": symbol_index,
                    "type": relocation_type,
                    "width": relocation_widths.get(relocation_type, 0),
                }
            )
        sections.append(
            {
                "index": index + 1,
                "name": name,
                "raw_size": raw_size,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "characteristics": characteristics,
                "contains_code": bool(characteristics & 0x20),
                "executable": bool(characteristics & 0x20000000),
                "sha256": sha256(section_bytes).hexdigest(),
                "data": section_bytes,
            }
        )
    symbols = _coff_symbols(data, symbol_pointer, symbol_count, string_start, string_size)
    symbols_by_index = {int(symbol["index"]): symbol for symbol in symbols}
    for relocations in relocations_by_section.values():
        for relocation in relocations:
            target = symbols_by_index.get(int(relocation["symbol_index"]))
            relocation["target_symbol"] = (
                str(target.get("name", "")) if target is not None else ""
            )
            relocation["target_section_number"] = (
                int(target.get("section_number", 0)) if target is not None else 0
            )
            relocation["target_storage_class"] = (
                int(target.get("storage_class", 0)) if target is not None else 0
            )
    functions = _coff_function_fingerprints(sections, symbols, relocations_by_section)
    public_sections = [
        {key: value for key, value in section.items() if key != "data"}
        for section in sections
    ]
    return {
        "kind": "coff_object",
        "status": "indexed",
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
        "machine": "i386" if machine == _PE_MACHINE_I386 else "x86_64",
        "timestamp": timestamp,
        "characteristics": flags,
        "sections": public_sections,
        "symbols": [
            {key: value for key, value in symbol.items() if key != "aux"}
            for symbol in symbols
        ],
        "defined_symbols": sorted(
            str(symbol["name"])
            for symbol in symbols
            if int(symbol["section_number"]) > 0 and symbol["name"]
        ),
        "undefined_symbols": sorted(
            str(symbol["name"])
            for symbol in symbols
            if int(symbol["section_number"]) == 0 and symbol["name"]
        ),
        "relocations": {
            str(key): value for key, value in sorted(relocations_by_section.items())
        },
        "function_fingerprints": functions,
        "counts": {
            "sections": len(sections),
            "symbols": len(symbols),
            "relocations": sum(len(value) for value in relocations_by_section.values()),
            "function_fingerprints": len(functions),
        },
    }


def _coff_symbols(data: bytes, pointer: int, count: int, string_start: int, string_size: int) -> list[dict[str, Any]]:
    if not pointer or not count:
        return []
    if pointer + count * 18 > len(data):
        raise LinkedLibraryError("COFF object has a truncated symbol table")
    symbols = []
    index = 0
    while index < count:
        offset = pointer + index * 18
        row = data[offset : offset + 18]
        name = _coff_name(row[:8], data, string_start, string_size)
        value, section_number, symbol_type, storage_class, aux_count = struct.unpack_from("<IhHBB", row, 8)
        aux_start = offset + 18
        aux_end = aux_start + aux_count * 18
        if aux_end > pointer + count * 18:
            raise LinkedLibraryError("COFF symbol has truncated auxiliary records")
        symbols.append(
            {
                "index": index,
                "name": name,
                "value": value,
                "section_number": section_number,
                "type": symbol_type,
                "storage_class": storage_class,
                "aux_count": aux_count,
                "aux": data[aux_start:aux_end],
            }
        )
        index += 1 + aux_count
    return symbols


def _coff_function_fingerprints(
    sections: Sequence[Mapping[str, Any]],
    symbols: Sequence[Mapping[str, Any]],
    relocations: Mapping[int, Sequence[Mapping[str, int]]],
) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    by_section: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for symbol in symbols:
        section_number = int(symbol["section_number"])
        if section_number <= 0 or section_number > len(sections):
            continue
        section = sections[section_number - 1]
        code_like = bool(int(symbol["type"]) & 0x20) or (
            bool(section["contains_code"]) and int(symbol["storage_class"]) in {2, 3}
        )
        if code_like and symbol["name"]:
            by_section[section_number].append(symbol)
    for section_number, members in sorted(by_section.items()):
        section = sections[section_number - 1]
        data = bytes(section["data"])
        ordered = sorted(members, key=lambda item: (int(item["value"]), str(item["name"])))
        for position, symbol in enumerate(ordered):
            start = int(symbol["value"])
            size = 0
            aux = bytes(symbol["aux"])
            if int(symbol["aux_count"]) and len(aux) >= 8 and int(symbol["type"]) & 0x20:
                size = int.from_bytes(aux[4:8], "little")
            if size <= 0:
                next_offsets = [int(other["value"]) for other in ordered[position + 1 :] if int(other["value"]) > start]
                end = next_offsets[0] if next_offsets else len(data)
            else:
                end = start + size
            if start < 0 or end <= start or end > len(data):
                continue
            object_blob = data[start:end]
            blob, trailing_alignment = _trim_x86_function_alignment(object_blob)
            end = start + len(blob)
            masked = bytearray(blob)
            holes: list[dict[str, int]] = []
            for relocation in relocations.get(section_number, []):
                relocation_offset = int(relocation["offset"])
                width = int(relocation["width"])
                if width <= 0 or relocation_offset < start or relocation_offset + width > end:
                    continue
                local = relocation_offset - start
                masked[local : local + width] = b"\0" * width
                holes.append({"offset": local, "width": width, "type": int(relocation["type"])})
            fixed = len(blob) - sum(item["width"] for item in holes)
            functions.append(
                {
                    "name": str(symbol["name"]),
                    "section": str(section["name"]),
                    "section_index": section_number,
                    "offset": start,
                    "size": len(blob),
                    "object_size": len(object_blob),
                    "trailing_alignment": trailing_alignment.hex(),
                    "bytes_sha256": sha256(blob).hexdigest(),
                    "normalized_sha256": sha256(masked).hexdigest(),
                    "masked_bytes": bytes(masked).hex(),
                    "relocation_holes": holes,
                    "fixed_bytes": fixed,
                    "matchable": fixed >= 4,
                    "match_strength": (
                        "strong" if fixed >= max(8, len(blob) // 4) else "weak"
                    ),
                }
            )
    functions.sort(key=lambda item: (item["section_index"], item["offset"], item["name"]))
    return functions


def _coff_name(field: bytes, data: bytes, string_start: int, string_size: int) -> str:
    if len(field) != 8:
        return ""
    if field.startswith(b"/") and field[1:].rstrip(b"\0").isdigit():
        offset = int(field[1:].rstrip(b"\0"))
        return _coff_string(data, string_start, string_size, offset)
    if field[:4] == b"\0\0\0\0":
        offset = int.from_bytes(field[4:8], "little")
        return _coff_string(data, string_start, string_size, offset)
    return field.rstrip(b"\0").decode("utf-8", errors="replace")


def _coff_string(data: bytes, start: int, size: int, offset: int) -> str:
    if size < 4 or offset < 4 or offset >= size or start + size > len(data):
        return ""
    begin = start + offset
    end = data.find(b"\0", begin, start + size)
    if end < 0:
        end = start + size
    return data[begin:end].decode("utf-8", errors="replace")


def _looks_like_omf(data: bytes) -> bool:
    if len(data) < 4 or data[0] not in {0x80, 0x82, 0x88, 0x96, 0x98, 0x99}:
        return False
    length = int.from_bytes(data[1:3], "little")
    return 1 <= length <= len(data) - 3


def _index_omf(data: bytes, *, label: str) -> dict[str, Any]:
    offset = 0
    records: list[dict[str, Any]] = []
    names: list[str] = []
    public_names: list[str] = []
    public_symbols: list[dict[str, Any]] = []
    segment_data: dict[int, dict[int, int]] = defaultdict(dict)
    module_name = ""
    has_fixups = False
    while offset < len(data):
        if offset + 3 > len(data):
            raise LinkedLibraryError(f"OMF object {label} has a truncated record header")
        record_type = data[offset]
        length = int.from_bytes(data[offset + 1 : offset + 3], "little")
        end = offset + 3 + length
        if length < 1 or end > len(data):
            raise LinkedLibraryError(f"OMF object {label} has a truncated record")
        payload = data[offset + 3 : end - 1]
        checksum = data[end - 1]
        checksum_valid = sum(data[offset:end]) & 0xFF == 0
        if record_type in {0x80, 0x82} and payload:
            name_length = payload[0]
            if name_length + 1 <= len(payload):
                module_name = payload[1 : 1 + name_length].decode("utf-8", errors="replace")
        elif record_type == 0x96:
            cursor = 0
            while cursor < len(payload):
                name_length = payload[cursor]
                cursor += 1
                if cursor + name_length > len(payload):
                    break
                names.append(payload[cursor : cursor + name_length].decode("utf-8", errors="replace"))
                cursor += name_length
        elif record_type in {0x90, 0x91}:
            symbols = _omf_public_symbols(payload, use32=record_type == 0x91)
            public_symbols.extend(symbols)
            public_names.extend(str(symbol["name"]) for symbol in symbols)
        elif record_type in {0xA0, 0xA1}:
            segment, cursor = _omf_index(payload, 0)
            offset_width = 4 if record_type == 0xA1 else 2
            if cursor + offset_width <= len(payload):
                data_offset = int.from_bytes(
                    payload[cursor : cursor + offset_width], "little"
                )
                cursor += offset_width
                for index, value in enumerate(payload[cursor:]):
                    segment_data[segment][data_offset + index] = value
        elif record_type in {0x9C, 0x9D}:
            has_fixups = True
        records.append(
            {
                "offset": offset,
                "type": record_type,
                "payload_bytes": len(payload),
                "payload_sha256": sha256(payload).hexdigest(),
                "checksum": checksum,
                "checksum_valid": checksum_valid,
            }
        )
        offset = end
    fingerprints = _omf_function_fingerprints(
        public_symbols,
        segment_data,
        has_fixups=has_fixups,
    )
    return {
        "kind": "omf_object",
        "status": "indexed" if all(row["checksum_valid"] for row in records) else "incomplete",
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
        "module_name": module_name,
        "names": names,
        "public_names": sorted(set(public_names)),
        "public_symbols": public_symbols,
        "record_type_counts": {str(key): value for key, value in sorted(Counter(row["type"] for row in records).items())},
        "records": records,
        "function_fingerprints": fingerprints,
        "counts": {
            "records": len(records),
            "public_symbols": len(public_symbols),
            "function_fingerprints": len(fingerprints),
            "unresolved_fixup_records": sum(
                row["type"] in {0x9C, 0x9D} for row in records
            ),
        },
        "authority": "OMF names and records are proposal evidence; semantic matching remains required",
    }


def _omf_public_symbols(
    payload: bytes,
    *,
    use32: bool,
) -> list[dict[str, Any]]:
    symbols: list[dict[str, Any]] = []
    try:
        cursor = 0
        group, cursor = _omf_index(payload, cursor)
        segment, cursor = _omf_index(payload, cursor)
        if segment == 0:
            cursor += 2
        offset_width = 4 if use32 else 2
        while cursor < len(payload):
            name_length = payload[cursor]
            cursor += 1
            if cursor + name_length + offset_width > len(payload):
                break
            name = payload[cursor : cursor + name_length].decode(
                "utf-8", errors="replace"
            )
            cursor += name_length
            symbol_offset = int.from_bytes(
                payload[cursor : cursor + offset_width], "little"
            )
            cursor += offset_width
            type_index, cursor = _omf_index(payload, cursor)
            symbols.append(
                {
                    "name": name,
                    "group_index": group,
                    "segment_index": segment,
                    "offset": symbol_offset,
                    "type_index": type_index,
                }
            )
    except (IndexError, ValueError):
        return symbols
    return symbols


def _omf_function_fingerprints(
    symbols: Sequence[Mapping[str, Any]],
    segment_data: Mapping[int, Mapping[int, int]],
    *,
    has_fixups: bool,
) -> list[dict[str, Any]]:
    by_segment: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for symbol in symbols:
        segment = int(symbol.get("segment_index", 0))
        if segment > 0:
            by_segment[segment].append(symbol)
    result: list[dict[str, Any]] = []
    for segment, segment_symbols in sorted(by_segment.items()):
        values = segment_data.get(segment, {})
        if not values:
            continue
        data_end = max(values) + 1
        ordered = sorted(
            segment_symbols,
            key=lambda item: (int(item["offset"]), str(item["name"])),
        )
        for position, symbol in enumerate(ordered):
            start = int(symbol["offset"])
            later = [
                int(item["offset"])
                for item in ordered[position + 1 :]
                if int(item["offset"]) > start
            ]
            end = later[0] if later else data_end
            if end <= start or any(offset not in values for offset in range(start, end)):
                continue
            blob = bytes(values[offset] for offset in range(start, end))
            result.append(
                {
                    "name": str(symbol["name"]),
                    "section": f"omf-segment-{segment}",
                    "section_index": segment,
                    "offset": start,
                    "size": len(blob),
                    "bytes_sha256": sha256(blob).hexdigest(),
                    "normalized_sha256": sha256(blob).hexdigest(),
                    "masked_bytes": blob.hex(),
                    "relocation_holes": [],
                    "fixed_bytes": len(blob),
                    "matchable": len(blob) >= 8 and not has_fixups,
                    "blocker": (
                        "unresolved_omf_fixupp_records" if has_fixups else None
                    ),
                }
            )
    return result


def _omf_index(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first & 0x80:
        return ((first & 0x7F) << 8) | data[offset + 1], offset + 2
    return first, offset + 1


def _index_pe(path: Path) -> dict[str, Any]:
    binary = _parse_stage_a_pe(path)
    debug = _pe_debug_identities(binary)
    return {
        "kind": "pe_image",
        "status": "indexed",
        "sha256": binary.sha256,
        "bytes": binary.size,
        "machine": binary.machine,
        "bitness": binary.bitness,
        "image_base": binary.image_base,
        "entrypoint_rva": binary.entrypoint_rva,
        "is_dll": binary.is_dll,
        "sections": [
            {
                "name": section.name,
                "rva_start": section.rva_start,
                "rva_end": section.rva_end,
                "executable": section.executable,
                "writable": section.writable,
            }
            for section in binary.sections
        ],
        "imports": [
            {"dll": item.dll, "symbol": item.symbol, "ordinal": item.ordinal, "thunk_rva": item.thunk_rva}
            for item in binary.imports
        ],
        "exports": [
            {"name": item.name, "ordinal": item.ordinal, "rva": item.rva, "kind": item.kind, "forwarder": item.forwarder}
            for item in (binary.exports or ())
        ],
        "debug_identities": debug,
        "function_fingerprints": [],
    }


def _pe_debug_identities(binary: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in getattr(binary.pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        entry = item.struct
        size = int(getattr(entry, "SizeOfData", 0) or 0)
        address = int(getattr(entry, "AddressOfRawData", 0) or 0)
        debug_type = int(getattr(entry, "Type", 0) or 0)
        payload = binary.pe.get_data(address, size) if address and size else b""
        row: dict[str, Any] = {
            "type": debug_type,
            "timestamp": int(getattr(entry, "TimeDateStamp", 0) or 0),
            "size": size,
            "payload_sha256": sha256(payload).hexdigest(),
        }
        if debug_type == 2 and payload.startswith(b"RSDS") and len(payload) >= 24:
            guid = payload[4:20]
            row.update(
                {
                    "kind": "codeview_rsds",
                    "guid": _format_guid(guid),
                    "age": int.from_bytes(payload[20:24], "little"),
                    "pdb_path": payload[24:].split(b"\0", 1)[0].decode("utf-8", errors="replace"),
                }
            )
        elif debug_type == 2 and payload.startswith(b"NB10") and len(payload) >= 16:
            row.update(
                {
                    "kind": "codeview_nb10",
                    "signature": int.from_bytes(payload[8:12], "little"),
                    "age": int.from_bytes(payload[12:16], "little"),
                    "pdb_path": payload[16:].split(b"\0", 1)[0].decode("utf-8", errors="replace"),
                }
            )
        elif debug_type == 16:
            row["kind"] = "reproducible"
        elif debug_type == 19:
            row["kind"] = "pdb_checksum"
            if b"\0" in payload:
                algorithm, digest = payload.split(b"\0", 1)
                row["algorithm"] = algorithm.decode("ascii", errors="replace")
                row["digest"] = digest.hex()
        else:
            row["kind"] = "other"
        result.append(row)
    return result


def _format_guid(data: bytes) -> str:
    if len(data) != 16:
        return data.hex()
    first, second, third = struct.unpack_from("<IHH", data, 0)
    return f"{first:08x}-{second:04x}-{third:04x}-{data[8:10].hex()}-{data[10:16].hex()}"


def _artifact_function_count(index: Mapping[str, Any]) -> int:
    own = len(index.get("function_fingerprints", []))
    return own + sum(
        _artifact_function_count(_object(member.get("index"), "nested artifact index"))
        for member in index.get("members", [])
        if isinstance(member, Mapping)
    )


def _decorate_v2_artifact_index(
    index: Mapping[str, Any],
    *,
    artifact_sha256: str,
    member_path: tuple[str, ...],
) -> dict[str, Any]:
    """Attach stable member and fingerprint identities to an indexed artifact."""

    result = copy.deepcopy(dict(index))
    functions = []
    for position, raw in enumerate(result.get("function_fingerprints", [])):
        function = dict(_object(raw, "function fingerprint"))
        canonical = {
            "artifact_sha256": artifact_sha256,
            "member_path": list(member_path),
            "section_index": function.get("section_index"),
            "offset": function.get("offset"),
            "size": function.get("size"),
            "normalized_sha256": function.get("normalized_sha256"),
        }
        function["fingerprint_id"] = "fingerprint:" + _canonical_sha256(
            canonical
        )[:24]
        function["fingerprint_scope"] = "function"
        function["ordinal"] = position
        functions.append(function)
    result["function_fingerprints"] = functions

    members = []
    for ordinal, raw in enumerate(result.get("members", [])):
        member = dict(_object(raw, "archive member"))
        name = str(member.get("name", f"member-{ordinal}"))
        child_path = (*member_path, name)
        member_identity = {
            "artifact_sha256": artifact_sha256,
            "member_path": list(child_path),
            "member_sha256": member.get("sha256"),
            "ordinal": ordinal,
        }
        member["ordinal"] = ordinal
        member["member_id"] = "member:" + _canonical_sha256(member_identity)[:24]
        member["index"] = _decorate_v2_artifact_index(
            _object(member.get("index"), "archive member index"),
            artifact_sha256=artifact_sha256,
            member_path=child_path,
        )
        members.append(member)
    if "members" in result:
        result["members"] = members
    return result


def _load_machine_package(path: Path) -> _MachinePackage:
    manifest_path = path / "machine-ir-manifest.json" if path.is_dir() else path
    manifest = _read_object(manifest_path, "machine IR manifest")
    if manifest.get("format") != MACHINE_IR_FORMAT:
        raise LinkedLibraryError("unsupported machine IR format")
    artifact = _object(_object(manifest.get("artifacts"), "machine IR artifacts").get("machine_ir"), "machine IR artifact")
    ir_path = (manifest_path.parent / str(artifact.get("path", "machine-ir.jsonl"))).resolve()
    try:
        ir_path.relative_to(manifest_path.parent.resolve())
    except ValueError as error:
        raise LinkedLibraryError("machine IR artifact escapes its package") from error
    if not ir_path.is_file() or artifact.get("sha256") != sha256_file(ir_path):
        raise LinkedLibraryError("machine IR artifact binding is stale")
    units = []
    by_id: dict[str, _Unit] = {}
    with ir_path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            raw = json.loads(line)
            unit = _object(raw, f"machine IR unit {line_number}")
            source = _object(unit.get("source"), "machine IR unit source")
            original = _object(source.get("original"), "machine IR unit original range")
            start = original.get("rva_start")
            end = original.get("rva_end")
            identity = _nonempty(unit.get("id"), "machine IR unit ID")
            if not isinstance(start, int) or not isinstance(end, int) or end <= start:
                raise LinkedLibraryError(f"machine IR unit {identity} has invalid range")
            if identity in by_id:
                raise LinkedLibraryError(f"duplicate machine IR unit ID: {identity}")
            parsed = _Unit(identity=identity, start=start, end=end, payload=unit)
            units.append(parsed)
            by_id[identity] = parsed
    units.sort(key=lambda item: (item.start, item.end, item.identity))
    return _MachinePackage(
        root=manifest_path.parent,
        manifest_path=manifest_path,
        ir_path=ir_path,
        manifest=manifest,
        units=tuple(units),
        by_id=by_id,
        ir_sha256=sha256_file(ir_path),
        manifest_sha256=sha256_file(manifest_path),
    )


def _reviewed_island(
    raw: Any,
    machine: _MachinePackage,
    claimed: dict[str, str],
) -> dict[str, Any]:
    review = _object(raw, "reviewed linked island")
    selected: list[_Unit] = []
    ranges: list[dict[str, int]] = []
    for raw_range in _array(review.get("ranges"), "reviewed linked island ranges"):
        region = _object(raw_range, "reviewed linked island range")
        start = region.get("rva_start")
        end = region.get("rva_end")
        if not isinstance(start, int) or not isinstance(end, int) or end <= start:
            raise LinkedLibraryError("reviewed linked island has an invalid range")
        contained = []
        for unit in machine.units:
            overlaps = unit.start < end and unit.end > start
            inside = unit.start >= start and unit.end <= end
            if overlaps and not inside:
                raise LinkedLibraryError(
                    f"reviewed linked island cuts machine unit {unit.identity}"
                )
            if inside:
                contained.append(unit)
        if not contained:
            raise LinkedLibraryError("reviewed linked island range contains no units")
        selected.extend(contained)
        ranges.append({"rva_start": start, "rva_end": end})
    deduplicated = {unit.identity: unit for unit in selected}
    row = _island_from_units(
        identity=str(review["id"]),
        kind=str(review["kind"]),
        units=sorted(deduplicated.values(), key=lambda item: item.start),
        match={
            "authority": "operator_reviewed_exact_range",
            "identity_status": "reviewed_ownership",
            "provenance_hints": copy.deepcopy(review.get("provenance_hints", [])),
        },
    )
    _claim_units(row, claimed)
    row["reviewed_ranges"] = ranges
    return row


def _island_from_units(*, identity: str, kind: str, units: Sequence[_Unit], match: Mapping[str, Any]) -> dict[str, Any]:
    if kind not in _ISLAND_KINDS:
        raise LinkedLibraryError(f"invalid linked island kind: {kind}")
    if not units:
        raise LinkedLibraryError(f"linked island {identity} has no units")
    authority = match.get("authority")
    if authority not in _MATCH_AUTHORITIES:
        raise LinkedLibraryError(f"linked island {identity} has invalid authority")
    spans = _merge_unit_spans(units)
    reachable = sum(bool(unit.payload.get("reachable")) or unit.payload.get("reachability") == "reachable" for unit in units)
    potential = len(units) - reachable
    unit_contract = [
        {
            "id": unit.identity,
            "contract_sha256": _object(unit.payload.get("source"), "unit source").get("contract_sha256"),
            "instruction_bytes_sha256": _object(unit.payload.get("source"), "unit source").get("instruction_bytes_sha256"),
        }
        for unit in units
    ]
    return {
        "id": identity,
        "kind": kind,
        "unit_ids": sorted(unit.identity for unit in units),
        "unit_count": len(units),
        "rva_spans": spans,
        "unit_contract_sha256": _canonical_sha256(unit_contract),
        "reachability": {"reachable_units": reachable, "potential_units": potential},
        "match": copy.deepcopy(dict(match)),
        "semantic_qualification": "not_attempted",
        "replacement_authorized": False,
        "owned_data": {"status": "not_analyzed", "ranges": []},
    }


def _claim_units(island: Mapping[str, Any], claimed: dict[str, str]) -> None:
    for unit_id in island["unit_ids"]:
        if unit_id in claimed:
            raise LinkedLibraryError(
                f"linked islands overlap machine unit {unit_id}: {claimed[unit_id]} and {island['id']}"
            )
        claimed[unit_id] = str(island["id"])


def _merge_unit_spans(units: Sequence[_Unit]) -> list[dict[str, int]]:
    ordered = sorted((unit.start, unit.end) for unit in units)
    spans: list[list[int]] = []
    for start, end in ordered:
        if spans and start <= spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], end)
        else:
            spans.append([start, end])
    return [{"rva_start": start, "rva_end": end} for start, end in spans]


def _import_thunk_event(unit: Mapping[str, Any]) -> Mapping[str, Any] | None:
    control = _object(unit.get("control", {}), "machine unit control")
    if control.get("kind") != "external_jump":
        return None
    events = _array(_object(unit.get("semantics", {}), "unit semantics").get("external_events", []), "unit external events")
    if len(events) != 1 or not isinstance(events[0], Mapping):
        return None
    event = events[0]
    return event if event.get("kind") == "external_call" and event.get("dll") else None


def _load_catalog_lock(path: Path | str | None) -> tuple[list[Mapping[str, Any]], dict[str, Any]]:
    if path is None:
        return [], {"catalog_lock_sha256": None}
    lock_path = Path(path)
    lock = _read_object(lock_path, "library catalog lock")
    _validate_self_hash(lock, LIBRARY_CATALOG_LOCK_FORMAT, "lock_sha256", "library catalog lock")
    indexes = []
    for raw in _array(lock.get("entries"), "library catalog lock entries"):
        entry = _object(raw, "library catalog lock entry")
        index_path = Path(_nonempty(entry.get("path"), "locked catalog path"))
        if not index_path.is_file() or entry.get("file_sha256") != sha256_file(index_path):
            raise LinkedLibraryError("locked library catalog file is stale")
        index = _read_object(index_path, "locked library artifact index")
        _validate_artifact_index(index)
        if entry.get("index_sha256") != index["index_sha256"]:
            raise LinkedLibraryError("locked library catalog identity is stale")
        indexes.append(index)
    return indexes, {"catalog_lock_sha256": lock["lock_sha256"]}


def _catalog_function_candidates(indexes: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for index in indexes:
        for artifact in index.get("artifacts", []):
            _collect_artifact_functions(
                result,
                catalog_id=str(index["catalog_id"]),
                artifact_id=str(artifact["id"]),
                artifact_sha256=str(artifact["sha256"]),
                island_kind=str(
                    artifact.get("island_kind", "linked_dependency")
                ),
                snapshot=copy.deepcopy(index.get("snapshot")),
                library_identity=copy.deepcopy(
                    artifact.get("library_identity", {})
                ),
                retention_model=str(artifact.get("retention_model", "unknown")),
                member_path=[],
                member_id=None,
                index=_object(artifact.get("index"), "artifact index"),
            )
    return result


def _collect_artifact_functions(
    result: list[dict[str, Any]],
    *,
    catalog_id: str,
    artifact_id: str,
    artifact_sha256: str,
    island_kind: str,
    snapshot: Mapping[str, Any] | None,
    library_identity: Mapping[str, Any],
    retention_model: str,
    member_path: list[str],
    member_id: str | None,
    index: Mapping[str, Any],
) -> None:
    for function in index.get("function_fingerprints", []):
        if not function.get("matchable"):
            continue
        candidate_id = ":".join(
            [catalog_id, artifact_id, *member_path, str(function.get("name", "anonymous"))]
        )
        result.append(
            {
                "candidate_id": candidate_id,
                "catalog_id": catalog_id,
                "artifact_id": artifact_id,
                "artifact_sha256": artifact_sha256,
                "island_kind": island_kind,
                "snapshot": copy.deepcopy(snapshot),
                "library_identity": copy.deepcopy(library_identity),
                "retention_model": retention_model,
                "member_path": copy.deepcopy(member_path),
                "member_id": member_id,
                "symbol": function.get("name"),
                "fingerprint_id": function.get("fingerprint_id"),
                "fingerprint_scope": function.get("fingerprint_scope", "function"),
                "section_index": function.get("section_index"),
                "member_offset": function.get("offset"),
                "size": function.get("size"),
                "normalized_sha256": function.get("normalized_sha256"),
                "masked_bytes": function.get("masked_bytes"),
                "relocation_holes": copy.deepcopy(function.get("relocation_holes", [])),
                "fixed_bytes": function.get("fixed_bytes"),
                "match_strength": function.get("match_strength", "strong"),
            }
        )
    for member in index.get("members", []):
        _collect_artifact_functions(
            result,
            catalog_id=catalog_id,
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            island_kind=island_kind,
            snapshot=snapshot,
            library_identity=library_identity,
            retention_model=retention_model,
            member_path=[*member_path, str(member.get("name", "member"))],
            member_id=(
                str(member["member_id"])
                if isinstance(member.get("member_id"), str)
                else None
            ),
            index=_object(member.get("index"), "archive member index"),
        )


def _find_target_artifact_matches(binary: Any, machine: _MachinePackage, candidates: Sequence[Mapping[str, Any]]) -> dict[tuple[int, int], list[dict[str, Any]]]:
    result: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    boundaries = {unit.start for unit in machine.units} | {unit.end for unit in machine.units}
    for candidate in candidates:
        size = candidate.get("size")
        masked_hex = candidate.get("masked_bytes")
        if not isinstance(size, int) or size <= 0 or not isinstance(masked_hex, str):
            continue
        try:
            pattern = bytes.fromhex(masked_hex)
        except ValueError:
            continue
        if len(pattern) != size:
            continue
        holes = [(int(item["offset"]), int(item["width"])) for item in candidate.get("relocation_holes", [])]
        hole_positions = {position for offset, width in holes for position in range(offset, offset + width)}
        anchor_offset, anchor = _longest_fixed_anchor(pattern, hole_positions)
        if not anchor:
            continue
        for section in binary.sections:
            if not section.executable:
                continue
            section_data = binary.pe.get_data(section.rva_start, section.rva_end - section.rva_start)
            search_from = 0
            while True:
                anchor_position = section_data.find(anchor, search_from)
                if anchor_position < 0:
                    break
                search_from = anchor_position + 1
                offset = anchor_position - anchor_offset
                if offset < 0 or offset + size > len(section_data):
                    continue
                start = section.rva_start + offset
                end = start + size
                if start not in boundaries or end not in boundaries:
                    continue
                target = section_data[offset : offset + size]
                if all(index in hole_positions or target[index] == pattern[index] for index in range(size)):
                    normalized = bytearray(target)
                    for hole_offset, width in holes:
                        normalized[hole_offset : hole_offset + width] = b"\0" * width
                    if sha256(normalized).hexdigest() != candidate.get("normalized_sha256"):
                        continue
                    result[(start, end)].append(
                        {
                            key: copy.deepcopy(candidate[key])
                            for key in (
                                "candidate_id",
                                "catalog_id",
                                "artifact_id",
                                "artifact_sha256",
                                "island_kind",
                                "snapshot",
                                "library_identity",
                                "retention_model",
                                "member_path",
                                "member_id",
                                "symbol",
                                "fingerprint_id",
                                "fingerprint_scope",
                                "section_index",
                                "member_offset",
                                "normalized_sha256",
                                "fixed_bytes",
                                "match_strength",
                            )
                        }
                    )
    for matches in result.values():
        matches.sort(key=lambda item: item["candidate_id"])
    return result


def _trim_x86_function_alignment(blob: bytes) -> tuple[bytes, bytes]:
    """Separate unambiguous one-byte alignment after a near/far return."""

    end = len(blob)
    while end > 0 and blob[end - 1] in {0x90, 0xCC}:
        end -= 1
    terminal_return = end > 0 and blob[end - 1] in {0xC3, 0xCB}
    terminal_near_jump = end >= 5 and blob[end - 5] == 0xE9
    terminal_short_jump = end >= 2 and blob[end - 2] == 0xEB
    if end < len(blob) and (
        terminal_return or terminal_near_jump or terminal_short_jump
    ):
        return blob[:end], blob[end:]
    return blob, b""


def _candidate_match_strength(candidate: Mapping[str, Any]) -> str:
    strength = candidate.get("match_strength", "strong")
    return str(strength) if strength in {"strong", "weak"} else "weak"


def _collapse_candidate_aliases(
    candidates: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        key = (
            candidate.get("catalog_id"),
            candidate.get("artifact_sha256"),
            candidate.get("member_id"),
            tuple(candidate.get("member_path", [])),
            candidate.get("section_index"),
            candidate.get("member_offset"),
            candidate.get("normalized_sha256"),
            candidate.get("fixed_bytes"),
            _candidate_match_strength(candidate),
        )
        groups[key].append(candidate)
    result = []
    for _key, aliases in sorted(groups.items(), key=lambda item: repr(item[0])):
        first = copy.deepcopy(dict(aliases[0]))
        first["candidate_ids"] = sorted(
            str(alias.get("candidate_id")) for alias in aliases
        )
        first["symbols"] = sorted(
            {
                str(alias.get("symbol"))
                for alias in aliases
                if isinstance(alias.get("symbol"), str) and alias.get("symbol")
            }
        )
        first["alias_count"] = len(aliases)
        first.pop("candidate_id", None)
        first.pop("symbol", None)
        result.append(first)
    return result


def _candidate_member_key(candidate: Mapping[str, Any]) -> tuple[str, str] | None:
    if candidate.get("retention_model") != "archive_member":
        return None
    artifact = candidate.get("artifact_sha256")
    member = candidate.get("member_id")
    if not isinstance(artifact, str):
        return None
    if not isinstance(member, str):
        path = candidate.get("member_path")
        if not isinstance(path, list) or not path:
            return None
        member = "/".join(str(value) for value in path)
    return artifact, member


def _candidate_library_identity(candidate: Mapping[str, Any]) -> dict[str, Any]:
    raw = candidate.get("library_identity")
    library = dict(raw) if isinstance(raw, Mapping) else {}
    snapshot = candidate.get("snapshot")
    target = snapshot.get("target", {}) if isinstance(snapshot, Mapping) else {}
    return {
        "family_id": str(library.get("family_id") or candidate.get("artifact_id") or "unknown"),
        "component_id": str(library.get("component_id") or candidate.get("artifact_id") or "unknown"),
        "release_id": library.get("release_id"),
        "build_id": library.get("build_id"),
        "abi_id": str(library.get("abi_id") or target.get("abi") or "unknown"),
        "architecture": str(target.get("architecture") or "unknown"),
    }


def _candidate_hypothesis_key(candidate: Mapping[str, Any]) -> tuple[str, ...]:
    identity = _candidate_library_identity(candidate)
    snapshot = candidate.get("snapshot")
    snapshot_id = str(snapshot.get("id", "unknown")) if isinstance(snapshot, Mapping) else "unknown"
    return (
        identity["family_id"],
        identity["component_id"],
        identity["abi_id"],
        str(identity.get("release_id") or "unknown"),
        str(identity.get("build_id") or "unknown"),
        snapshot_id,
        str(candidate.get("artifact_sha256") or "unknown"),
    )


def _candidate_set_identity_status(candidates: Sequence[Mapping[str, Any]]) -> str:
    if not candidates:
        return "unidentified"
    artifact_hashes = {str(candidate.get("artifact_sha256")) for candidate in candidates}
    if len(artifact_hashes) == 1:
        return "exact_artifact"
    identities = [_candidate_library_identity(candidate) for candidate in candidates]
    releases = {
        (identity["family_id"], identity["abi_id"], identity.get("release_id"))
        for identity in identities
    }
    if len(releases) == 1 and next(iter(releases))[2] is not None:
        return "exact_release"
    families = {(identity["family_id"], identity["abi_id"]) for identity in identities}
    return "library_family_abi" if len(families) == 1 else "ambiguous_family"


def _unit_reachable(unit: _Unit) -> bool:
    return bool(unit.payload.get("reachable")) or unit.payload.get("reachability") == "reachable"


def _unknown_unit_components(units: Sequence[_Unit]) -> list[list[_Unit]]:
    """Split unknown code by checked non-call CFG connectivity."""

    if not units:
        return []
    by_id = {unit.identity: unit for unit in units}
    by_start = {unit.start: unit.identity for unit in units}
    parent = {unit.identity: unit.identity for unit in units}

    def find(value: str) -> str:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root == right_root:
            return
        if left_root < right_root:
            parent[right_root] = left_root
        else:
            parent[left_root] = right_root

    for unit in units:
        control = _object(unit.payload.get("control", {}), "machine unit control")
        if control.get("kind") in {"call", "external_call", "external_jump"}:
            continue
        for target in control.get("direct_targets", []) or []:
            target_id = by_start.get(target) if isinstance(target, int) else None
            if target_id in by_id:
                union(unit.identity, target_id)
    groups: dict[str, list[_Unit]] = defaultdict(list)
    for unit in units:
        groups[find(unit.identity)].append(unit)
    return sorted(
        (
            sorted(group, key=lambda item: (item.start, item.end, item.identity))
            for group in groups.values()
        ),
        key=lambda group: (group[0].start, group[0].identity),
    )


def _longest_fixed_anchor(
    pattern: bytes,
    hole_positions: set[int],
) -> tuple[int, bytes]:
    best_start = 0
    best_end = 0
    cursor = 0
    while cursor < len(pattern):
        while cursor < len(pattern) and cursor in hole_positions:
            cursor += 1
        start = cursor
        while cursor < len(pattern) and cursor not in hole_positions:
            cursor += 1
        if cursor - start > best_end - best_start:
            best_start, best_end = start, cursor
    return best_start, pattern[best_start:best_end]


def _qualification_contract_descriptor(qualification: Mapping[str, Any]) -> Mapping[str, Any] | None:
    refinement = qualification.get("component_refinement")
    if not isinstance(refinement, Mapping):
        refinement = qualification.get("refinement")
    if isinstance(refinement, Mapping) and isinstance(refinement.get("component_contract"), Mapping):
        return refinement["component_contract"]
    if isinstance(qualification.get("component_contract"), Mapping):
        return qualification["component_contract"]
    return None


def _qualification_unit_ids(qualification: Mapping[str, Any]) -> list[str]:
    component = qualification.get("component")
    if isinstance(component, Mapping) and isinstance(component.get("unit_ids"), list):
        return [str(value) for value in component["unit_ids"]]
    refinement = qualification.get("component_refinement")
    if isinstance(refinement, Mapping):
        nested = refinement.get("component")
        if isinstance(nested, Mapping) and isinstance(nested.get("unit_ids"), list):
            return [str(value) for value in nested["unit_ids"]]
    return []


def _validate_artifact_index(payload: Mapping[str, Any]) -> None:
    if payload.get("format") not in _ARTIFACT_INDEX_FORMATS:
        raise LinkedLibraryError("unsupported library artifact index format")
    core = copy.deepcopy(dict(payload))
    observed = core.pop("index_sha256", None)
    if observed != _canonical_sha256(core):
        raise LinkedLibraryError("library artifact index self-hash is stale")
    if payload.get("executes_original_binary") is not False:
        raise LinkedLibraryError("library artifact index lacks static-only assurance")
    if payload.get("format") == LIBRARY_ARTIFACT_INDEX_V2_FORMAT:
        snapshot = _object(payload.get("snapshot"), "library artifact snapshot")
        _nonempty(snapshot.get("id"), "library artifact snapshot ID")
        target = _object(snapshot.get("target"), "library artifact target")
        for field in ("architecture", "object_format", "abi"):
            _nonempty(target.get(field), f"library artifact target {field}")
        member_ids: set[str] = set()
        fingerprint_ids: set[str] = set()
        for raw in _array(payload.get("artifacts"), "library artifacts"):
            artifact = _object(raw, "library artifact")
            library = _object(artifact.get("library_identity"), "library identity")
            for field in ("family_id", "component_id", "abi_id"):
                _nonempty(library.get(field), f"library identity {field}")
            _validate_v2_index_identities(
                _object(artifact.get("index"), "artifact index"),
                member_ids=member_ids,
                fingerprint_ids=fingerprint_ids,
            )


def _validate_v2_index_identities(
    index: Mapping[str, Any],
    *,
    member_ids: set[str],
    fingerprint_ids: set[str],
) -> None:
    for raw in index.get("function_fingerprints", []):
        fingerprint = _object(raw, "function fingerprint")
        identity = _nonempty(fingerprint.get("fingerprint_id"), "fingerprint ID")
        fingerprint_ids.add(identity)
    for raw in index.get("members", []):
        member = _object(raw, "archive member")
        identity = _nonempty(member.get("member_id"), "archive member ID")
        if identity in member_ids:
            raise LinkedLibraryError("library artifact member IDs are duplicated")
        member_ids.add(identity)
        _validate_v2_index_identities(
            _object(member.get("index"), "archive member index"),
            member_ids=member_ids,
            fingerprint_ids=fingerprint_ids,
        )


def _validate_linked_island_manifest(payload: Mapping[str, Any]) -> None:
    try:
        _validate_linked_island_contract(payload)
    except ValueError as error:
        raise LinkedLibraryError(str(error)) from error


def validate_linked_island_manifest(payload: Mapping[str, Any]) -> None:
    """Check a linked-island manifest at a downstream trust boundary."""

    _validate_linked_island_manifest(payload)


def _validate_self_hash(payload: Mapping[str, Any], expected_format: str, hash_field: str, label: str) -> None:
    if payload.get("format") != expected_format:
        raise LinkedLibraryError(f"unsupported {label} format")
    core = copy.deepcopy(dict(payload))
    observed = core.pop(hash_field, None)
    if observed != _canonical_sha256(core):
        raise LinkedLibraryError(f"{label} self-hash is stale")


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LinkedLibraryError(f"cannot read {label}: {error}") from error
    return dict(_object(value, label))


def _copy_object(value: Mapping[str, Any], label: str) -> dict[str, Any]:
    return copy.deepcopy(dict(_object(value, label)))


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise LinkedLibraryError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise LinkedLibraryError(f"{label} must be an array")
    return value


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise LinkedLibraryError(f"{label} must be a non-empty string")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise LinkedLibraryError(f"{label} must be a lowercase SHA-256")
    return value


def _canonical_sha256(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()


def _issue(status: str, code: str, message: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "code": code, "message": message, **details}


def _issue_sort_key(issue: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        0 if issue.get("status") == "violated" else 1,
        str(issue.get("code", "")),
        int(issue.get("rva_start", -1)),
        str(issue.get("island_id", "")),
    )


__all__ = [
    "LinkedLibraryError",
    "bind_interface_contract_catalog",
    "bind_library_artifact_inputs",
    "bind_linked_interface_assignments",
    "bind_linked_island_review",
    "derive_dynamic_library_requirements",
    "index_library_artifacts",
    "infer_library_hypotheses",
    "lock_library_catalog",
    "match_linked_islands",
    "plan_library_replacements",
    "propose_library_match_evidence",
    "qualify_linked_interfaces",
    "refine_linked_islands",
    "validate_linked_island_manifest",
]
