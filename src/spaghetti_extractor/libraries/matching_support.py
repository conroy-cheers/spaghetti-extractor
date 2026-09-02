"""Linked-library matching support."""

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


from .model import (
    LinkedLibraryError,
    _ARTIFACT_INDEX_FORMATS,
    _ISLAND_KINDS,
    _MATCH_AUTHORITIES,
    _MachinePackage,
    _REVIEWED_COMPLEMENT_AUTHORITY,
    _REVIEWED_COMPLEMENT_SCOPE,
    _Unit,
)

def load_machine_package(path: Path) -> _MachinePackage:
    manifest_path = _machine_manifest_path(path)
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


# Compatibility for the proposal-only V3 modules while they are migrated.
_load_machine_package = load_machine_package


def _machine_manifest_path(path: Path) -> Path:
    if path.is_dir():
        return path / "machine-ir-manifest.json"
    if path.name == "machine-ir.jsonl":
        return path.with_name("machine-ir-manifest.json")
    return path


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


def _optional_reviewed_complement_policy(
    review: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    if "unclaimed_exact_units" not in review:
        return None
    return _reviewed_complement_policy(review.get("unclaimed_exact_units"))


def _reviewed_complement_policy(raw: Any) -> Mapping[str, Any]:
    policy = _object(raw, "reviewed unclaimed-unit policy")
    expected_fields = {
        "authority",
        "id",
        "kind",
        "operator_reviewed",
        "replacement_authorized",
        "review_rationale",
        "scope",
    }
    unknown = sorted(set(policy) - expected_fields)
    missing = sorted(expected_fields - set(policy))
    if unknown or missing:
        details = []
        if missing:
            details.append(f"missing {missing}")
        if unknown:
            details.append(f"unsupported {unknown}")
        raise LinkedLibraryError(
            "reviewed unclaimed-unit policy fields are invalid: " + ", ".join(details)
        )
    _nonempty(policy.get("id"), "reviewed unclaimed-unit policy ID")
    if policy.get("kind") not in {
        "linked_dependency",
        "compiler_linker_support",
    }:
        raise LinkedLibraryError(
            "reviewed unclaimed-unit policy kind must be linked_dependency "
            "or compiler_linker_support"
        )
    if policy.get("authority") != _REVIEWED_COMPLEMENT_AUTHORITY:
        raise LinkedLibraryError(
            "reviewed unclaimed-unit policy lacks exact-complement authority"
        )
    if policy.get("scope") != _REVIEWED_COMPLEMENT_SCOPE:
        raise LinkedLibraryError(
            "reviewed unclaimed-unit policy has an unsupported scope"
        )
    if policy.get("operator_reviewed") is not True:
        raise LinkedLibraryError(
            "reviewed unclaimed-unit policy must be visibly operator-reviewed"
        )
    rationale = _nonempty(
        policy.get("review_rationale"),
        "reviewed unclaimed-unit policy rationale",
    )
    if not rationale.strip():
        raise LinkedLibraryError(
            "reviewed unclaimed-unit policy rationale must not be blank"
        )
    if policy.get("replacement_authorized") is not False:
        raise LinkedLibraryError(
            "reviewed unclaimed-unit policy may not authorize replacement"
        )
    return policy


def _materialize_reviewed_complement(
    *,
    policy: Mapping[str, Any],
    machine: _MachinePackage,
    claimed: dict[str, str],
    original_binary_sha256: str,
    review_sha256: str,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    checked = _reviewed_complement_policy(policy)
    preserved_claims = sorted(set(claimed.values()))
    if checked.get("id") in preserved_claims:
        raise LinkedLibraryError(
            "reviewed unclaimed-unit policy duplicates an existing island ID"
        )
    units = [unit for unit in machine.units if unit.identity not in claimed]
    unit_ids = sorted(unit.identity for unit in units)
    exact_bindings = {
        "machine_ir_manifest_sha256": machine.manifest_sha256,
        "machine_ir_sha256": machine.ir_sha256,
        "original_binary_sha256": original_binary_sha256,
        "review_sha256": review_sha256,
        "unit_ids_sha256": _canonical_sha256(unit_ids),
    }
    summary: dict[str, Any] = {
        "authority": _REVIEWED_COMPLEMENT_AUTHORITY,
        "exact_bindings": exact_bindings,
        "id": str(checked["id"]),
        "kind": str(checked["kind"]),
        "operator_reviewed": True,
        "preserved_claimed_island_ids": preserved_claims,
        "replacement_authorized": False,
        "review_rationale": str(checked["review_rationale"]),
        "scope": _REVIEWED_COMPLEMENT_SCOPE,
        "unit_count": len(units),
    }
    if not units:
        return None, summary
    row = _island_from_units(
        identity=str(checked["id"]),
        kind=str(checked["kind"]),
        units=units,
        match={
            "authority": _REVIEWED_COMPLEMENT_AUTHORITY,
            "exact_bindings": exact_bindings,
            "identity_status": "reviewed_complement_ownership",
            "operator_reviewed": True,
            "preserved_claimed_island_ids": preserved_claims,
            "review_rationale": str(checked["review_rationale"]),
            "scope": _REVIEWED_COMPLEMENT_SCOPE,
        },
    )
    _claim_units(row, claimed)
    summary["unit_contract_sha256"] = row["unit_contract_sha256"]
    return row, summary


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
    "load_machine_package",
    "lock_library_catalog",
    "match_linked_islands",
    "plan_library_replacements",
    "propose_library_match_evidence",
    "qualify_linked_interfaces",
    "refine_linked_islands",
    "validate_linked_island_manifest",
]
