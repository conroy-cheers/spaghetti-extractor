"""Linked-library matching."""

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
from ..errors import ToolkitInputError
from ..pe32.image import parse_pe_image
from .contracts import (
    validate_linked_island_manifest as _validate_linked_island_contract,
)
from ..util import sha256_file, write_json


from .matching_support import (
    _array,
    _candidate_hypothesis_key,
    _candidate_library_identity,
    _candidate_match_strength,
    _candidate_member_key,
    _candidate_set_identity_status,
    _canonical_sha256,
    _catalog_function_candidates,
    _claim_units,
    _collapse_candidate_aliases,
    _copy_object,
    _find_target_artifact_matches,
    _import_thunk_event,
    _island_from_units,
    _issue,
    _issue_sort_key,
    _load_catalog_lock,
    _load_machine_package,
    _materialize_reviewed_complement,
    _nonempty,
    _object,
    _optional_reviewed_complement_policy,
    _read_object,
    _reviewed_complement_policy,
    _reviewed_island,
    _sha256,
    _unit_reachable,
    _validate_self_hash,
)
from .model import (
    LinkedLibraryError,
    _DEFAULT_HYPOTHESIS_CAP,
    _ISLAND_KINDS,
    _Unit,
)
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
    if "unclaimed_exact_units" in core:
        complement = _reviewed_complement_policy(core.get("unclaimed_exact_units"))
        if complement.get("id") in seen:
            raise LinkedLibraryError(
                "reviewed unclaimed-unit policy duplicates a reviewed island ID"
            )
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
    binary = parse_pe_image(original_path)
    machine = _load_machine_package(Path(machine_ir))
    machine_binary = _object(machine.manifest.get("binary"), "machine IR binary")
    if machine_binary.get("sha256") != binary.sha256:
        raise LinkedLibraryError("linked-island machine IR/original binary is stale")
    claimed: dict[str, str] = {}
    islands: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    complement_policy: Mapping[str, Any] | None = None

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
        complement_policy = _optional_reviewed_complement_policy(reviewed)
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

    reviewed_complement = None
    if complement_policy is not None:
        complement, reviewed_complement = _materialize_reviewed_complement(
            policy=complement_policy,
            machine=machine,
            claimed=claimed,
            original_binary_sha256=binary.sha256,
            review_sha256=str(expected),
        )
        if complement is not None:
            islands.append(complement)

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
    if reviewed_complement is not None:
        core["reviewed_unclaimed_exact_units"] = reviewed_complement
        core["authority"]["reviewed_complement_binds_ownership_only"] = True
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
    binary = parse_pe_image(original_path)
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
