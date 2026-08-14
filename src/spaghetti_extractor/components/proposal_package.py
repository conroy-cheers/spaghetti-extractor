"""Bounded, selectively readable component-discovery proposal packages."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import (
    ARTIFACT_SET_V3_FORMAT,
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetWriterV3,
)
from ..artifacts.io import ArtifactSetReaderV3
from ..util import json_dumps, write_json
from .formats import (
    COMPONENT_DISCOVERY_RESULT_V2_FORMAT,
    COMPONENT_PROPOSAL_INDEX_V2_FORMAT,
    COMPONENT_PROPOSAL_PACKAGE_V2_FORMAT,
    COMPONENT_PROPOSAL_RECORD_V2_KIND,
    COMPONENT_UNIT_BINDING_INDEX_V2_FORMAT,
)


PROPOSAL_INDEX_FILENAME = "proposal-index.json"
PROPOSAL_RECORDS_DIRECTORY = "proposals"
_SIDECARS = {
    "coverage": "coverage.json",
    "graph_facts": "graph-facts.json",
    "issues": "issues.json",
    "seed_index": "seed-index.json",
    "unit_bindings": "unit-bindings.json",
}
_SHA256_LENGTH = 64


class ComponentProposalPackageError(ValueError):
    """A proposal package is malformed, stale, or internally contradictory."""


@dataclass(frozen=True)
class ComponentProposalPackageV2:
    root: Path
    manifest: Mapping[str, Any]
    index: Mapping[str, Any]
    records: ArtifactSetReaderV3
    unit_bindings: Mapping[str, Mapping[str, str]]
    summaries_by_id: Mapping[str, Mapping[str, Any]]

    def get_proposal(self, proposal_id: str) -> dict[str, Any]:
        summary = self.summaries_by_id.get(proposal_id)
        if summary is None:
            raise ComponentProposalPackageError(
                f"proposal index has no proposal {proposal_id!r}"
            )
        value = self.records.get_record(proposal_id).value.to_value()
        if not isinstance(value, dict):
            raise ComponentProposalPackageError(
                f"proposal {proposal_id!r} is not an object"
            )
        _validate_proposal_value(
            value=value,
            proposal_id=proposal_id,
            summary=summary,
            unit_bindings=self.unit_bindings,
        )
        return value

    def validate_all_proposals(self) -> None:
        """Stream and validate every rich diagnostic record.

        Operator selection intentionally validates only the compact index and
        the selected record. Producers call this method once before publishing
        a package so an unrelated corrupt diagnostic pack cannot escape the
        generation gate.
        """

        seen: set[str] = set()
        for record in self.records.iter_records():
            proposal_id = record.record_id
            summary = self.summaries_by_id.get(proposal_id)
            if summary is None:
                raise ComponentProposalPackageError(
                    f"proposal artifact has unexpected record {proposal_id!r}"
                )
            value = record.value.to_value()
            if not isinstance(value, dict):
                raise ComponentProposalPackageError(
                    f"proposal {proposal_id!r} is not an object"
                )
            _validate_proposal_value(
                value=value,
                proposal_id=proposal_id,
                summary=summary,
                unit_bindings=self.unit_bindings,
            )
            seen.add(proposal_id)
        expected = set(self.summaries_by_id)
        if seen != expected:
            raise ComponentProposalPackageError(
                "proposal artifact does not cover its complete index"
            )


def write_component_proposal_package_v2(
    *, payload: Mapping[str, Any], out: Path | str
) -> dict[str, Any]:
    """Split one discovery result into a checked index and bounded records."""

    root = Path(out)
    if root.exists() and any(root.iterdir()):
        raise ComponentProposalPackageError(
            f"proposal package output {root} is not empty"
        )
    root.mkdir(parents=True, exist_ok=True)
    try:
        if payload.get("format") != COMPONENT_DISCOVERY_RESULT_V2_FORMAT:
            raise ComponentProposalPackageError(
                "unsupported component discovery result"
            )
        _check_self_hash(payload, "discovery_result_sha256", "discovery result")
        if payload.get("executes_original_binary") is not False:
            raise ComponentProposalPackageError(
                "component discovery result has runtime authority"
            )
        authority = _mapping(payload.get("authority"), "proposal authority")
        if authority.get("can_authorize_replacement") is not False:
            raise ComponentProposalPackageError(
                "component discovery result grants replacement authority"
            )
        limits = _mapping(payload.get("limits"), "proposal limits")
        proposals = _proposal_rows(payload.get("proposals"))
        bindings = _mapping(payload.get("bindings"), "proposal bindings")
        status = _status(payload.get("status"))
        unit_bindings = _unit_bindings(payload.get("graph_facts"))
        for proposal in proposals:
            _check_membership_binding(proposal, unit_bindings)
        record_manifest = ArtifactSetWriterV3(
            artifact_kind=COMPONENT_PROPOSAL_RECORD_V2_KIND,
            status="incomplete" if status == "incomplete" else "complete",
            bindings=(
                ArtifactBindingV3(
                    "discovery-inputs",
                    "component-discovery",
                    "component-proposal-package-v2",
                    _canonical_sha256(bindings),
                ),
            ),
        ).write(
            root / PROPOSAL_RECORDS_DIRECTORY,
            (
                ArtifactRecordV3.create(str(row["id"]), row)
                for row in proposals
            ),
        )
        record_descriptor = {
            "path": PROPOSAL_RECORDS_DIRECTORY,
            "format": ARTIFACT_SET_V3_FORMAT,
            "artifact_kind": record_manifest.artifact_kind,
            "artifact_id": record_manifest.artifact_id,
            "manifest_sha256": record_manifest.manifest_sha256,
            "record_count": record_manifest.record_count,
        }
        summaries = [_proposal_summary(row) for row in proposals]
        index_core = {
            "format": COMPONENT_PROPOSAL_INDEX_V2_FORMAT,
            "status": status,
            "authority": copy.deepcopy(payload.get("authority")),
            "executes_original_binary": False,
            "bindings": copy.deepcopy(dict(bindings)),
            "limits": copy.deepcopy(dict(limits)),
            "validation_scopes": {
                "selection": "index-and-selected-record-v1",
                "producer": "complete-package-v1",
            },
            "proposal_artifact": copy.deepcopy(record_descriptor),
            "counts": {
                "proposals": len(summaries),
                "seeds": len(_sequence(payload.get("seed_index"), "seed index")),
                "issues": len(_sequence(payload.get("issues"), "issues")),
            },
            "proposals": summaries,
        }
        index = {**index_core, "index_sha256": _canonical_sha256(index_core)}
        write_json(root / PROPOSAL_INDEX_FILENAME, index)

        files: dict[str, dict[str, Any]] = {
            "index": _file_descriptor(root / PROPOSAL_INDEX_FILENAME, root)
        }
        for field, filename in _SIDECARS.items():
            if field == "unit_bindings":
                unit_binding_rows = [
                    copy.deepcopy(dict(unit_bindings[identity]))
                    for identity in sorted(unit_bindings)
                ]
                unit_binding_core = {
                    "format": COMPONENT_UNIT_BINDING_INDEX_V2_FORMAT,
                    "bindings": unit_binding_rows,
                }
                value = {
                    **unit_binding_core,
                    "unit_binding_index_sha256": _canonical_sha256(
                        unit_binding_core
                    ),
                }
            else:
                value = payload.get(field)
            if field in {"issues", "seed_index"}:
                value = copy.deepcopy(_sequence(value, field.replace("_", " ")))
            elif not isinstance(value, Mapping):
                raise ComponentProposalPackageError(
                    f"component proposal {field.replace('_', ' ')} must be an object"
                )
            write_json(root / filename, value)
            files[field] = _file_descriptor(root / filename, root)

        manifest_core = {
            "format": COMPONENT_PROPOSAL_PACKAGE_V2_FORMAT,
            "proposal_artifact": record_descriptor,
            "files": files,
        }
        manifest = {
            **manifest_core,
            "package_sha256": _canonical_sha256(manifest_core),
        }
        write_json(root / "manifest.json", manifest)
        return manifest
    except Exception:
        for child in tuple(root.iterdir()) if root.exists() else ():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        raise


def load_component_proposal_package_v2(
    path: Path | str,
) -> ComponentProposalPackageV2:
    root = Path(path)
    manifest = _read_object(root / "manifest.json", "proposal package manifest")
    if manifest.get("format") != COMPONENT_PROPOSAL_PACKAGE_V2_FORMAT:
        raise ComponentProposalPackageError("unsupported component proposal package")
    _check_self_hash(manifest, "package_sha256", "proposal package")
    if set(manifest) != {
        "format",
        "proposal_artifact",
        "files",
        "package_sha256",
    }:
        raise ComponentProposalPackageError(
            "proposal package manifest is not transport-only"
        )
    files = _mapping(manifest.get("files"), "proposal package files")
    if set(files) != set(_SIDECARS) | {"index"}:
        raise ComponentProposalPackageError("proposal package file inventory is incomplete")
    expected_top_level = {
        "manifest.json",
        PROPOSAL_RECORDS_DIRECTORY,
        *(str(_mapping(value, "file descriptor").get("path")) for value in files.values()),
    }
    if {item.name for item in root.iterdir()} != expected_top_level:
        raise ComponentProposalPackageError("proposal package layout is not canonical")
    index_path = _checked_file(root, files["index"])
    index = _read_object(index_path, "proposal index")
    if index.get("format") != COMPONENT_PROPOSAL_INDEX_V2_FORMAT:
        raise ComponentProposalPackageError("unsupported component proposal index")
    _check_self_hash(index, "index_sha256", "proposal index")
    _status(index.get("status"))
    if index.get("executes_original_binary") is not False:
        raise ComponentProposalPackageError("proposal index has runtime authority")
    authority = _mapping(index.get("authority"), "proposal authority")
    if authority.get("can_authorize_replacement") is not False:
        raise ComponentProposalPackageError("proposal index grants replacement authority")
    bindings = _mapping(index.get("bindings"), "proposal bindings")
    _mapping(index.get("limits"), "proposal limits")
    if index.get("validation_scopes") != {
        "selection": "index-and-selected-record-v1",
        "producer": "complete-package-v1",
    }:
        raise ComponentProposalPackageError("proposal validation scope is unsupported")
    records = ArtifactSetReaderV3(root / PROPOSAL_RECORDS_DIRECTORY)
    descriptor = _mapping(manifest.get("proposal_artifact"), "proposal artifact")
    if descriptor != index.get("proposal_artifact"):
        raise ComponentProposalPackageError("proposal artifact index binding is stale")
    if (
        descriptor.get("path") != PROPOSAL_RECORDS_DIRECTORY
        or descriptor.get("format") != ARTIFACT_SET_V3_FORMAT
        or descriptor.get("artifact_kind") != records.manifest.artifact_kind
        or descriptor.get("artifact_id") != records.manifest.artifact_id
        or descriptor.get("manifest_sha256") != records.manifest_sha256
        or descriptor.get("record_count") != records.manifest.record_count
    ):
        raise ComponentProposalPackageError("proposal artifact descriptor is stale")
    expected_record_binding = ArtifactBindingV3(
        "discovery-inputs",
        "component-discovery",
        "component-proposal-package-v2",
        _canonical_sha256(bindings),
    )
    if records.manifest.bindings != (expected_record_binding,):
        raise ComponentProposalPackageError(
            "proposal record artifact input binding contradicts its index"
        )
    summaries = _sequence(index.get("proposals"), "proposal summaries")
    summaries_by_id: dict[str, Mapping[str, Any]] = {}
    proposal_ids: list[str] = []
    for raw in summaries:
        summary = _mapping(raw, "proposal summary")
        proposal_id = summary.get("id")
        if (
            not isinstance(proposal_id, str)
            or not proposal_id
            or proposal_id in summaries_by_id
        ):
            raise ComponentProposalPackageError(
                "proposal index has stale or duplicate identities"
            )
        proposal_ids.append(proposal_id)
        summaries_by_id[proposal_id] = summary
    if (
        len(proposal_ids) != records.manifest.record_count
        or len(set(proposal_ids)) != len(proposal_ids)
    ):
        raise ComponentProposalPackageError("proposal index inventory is stale")
    counts = _mapping(index.get("counts"), "proposal counts")
    if counts.get("proposals") != len(proposal_ids):
        raise ComponentProposalPackageError("proposal count is stale")
    checked_sidecars = {
        name: _checked_file(root, files[name]) for name in _SIDECARS
    }
    issues = _read_array(checked_sidecars["issues"], "proposal issues")
    seeds = _read_array(checked_sidecars["seed_index"], "proposal seed index")
    if counts.get("issues") != len(issues) or counts.get("seeds") != len(seeds):
        raise ComponentProposalPackageError("proposal sidecar counts are stale")
    _read_object(checked_sidecars["coverage"], "proposal coverage")
    _read_object(checked_sidecars["graph_facts"], "proposal graph facts")
    unit_bindings = _load_unit_bindings(checked_sidecars["unit_bindings"])
    return ComponentProposalPackageV2(
        root, manifest, index, records, unit_bindings, summaries_by_id
    )


def _proposal_rows(value: Any) -> tuple[dict[str, Any], ...]:
    rows = _sequence(value, "proposals")
    result: list[dict[str, Any]] = []
    identities: set[str] = set()
    for raw in rows:
        row = copy.deepcopy(dict(_mapping(raw, "proposal")))
        identity = row.get("id")
        expected = row.get("proposal_sha256")
        core = copy.deepcopy(row)
        core.pop("proposal_sha256", None)
        if (
            not isinstance(identity, str)
            or not identity
            or identity in identities
            or not _digest(expected)
            or expected != _canonical_sha256(core)
        ):
            raise ComponentProposalPackageError("proposal identity or self-hash is stale")
        identities.add(identity)
        result.append(row)
    if not result:
        raise ComponentProposalPackageError("proposal package has no proposals")
    return tuple(result)


def _proposal_summary(row: Mapping[str, Any]) -> dict[str, Any]:
    membership = _mapping(row.get("membership"), "proposal membership")
    score = _mapping(row.get("score", {}), "proposal score")
    blockers = _sequence(row.get("blockers", []), "proposal blockers")
    return {
        "id": row["id"],
        "proposal_sha256": row["proposal_sha256"],
        "status": row.get("status"),
        "proposal_kinds": copy.deepcopy(row.get("proposal_kinds", [])),
        "membership": {
            key: copy.deepcopy(membership.get(key))
            for key in ("rva_start", "rva_end", "unit_count", "noncontiguous")
        },
        "reachability": copy.deepcopy(row.get("reachability")),
        "score": {key: copy.deepcopy(score.get(key)) for key in ("front", "rank")},
        "blockers": {
            "count": len(blockers),
            "categories": sorted(
                {
                    str(item.get("category"))
                    for item in blockers
                    if isinstance(item, Mapping) and item.get("category") is not None
                }
            ),
        },
    }


def _unit_bindings(value: Any) -> dict[str, dict[str, str]]:
    graph = _mapping(value, "proposal graph facts")
    nodes = _sequence(graph.get("nodes"), "proposal graph nodes")
    result: dict[str, dict[str, str]] = {}
    for raw in nodes:
        node = _mapping(raw, "proposal graph node")
        identity = node.get("unit_id")
        contract = node.get("contract_sha256")
        instructions = node.get("instruction_bytes_sha256")
        if (
            not isinstance(identity, str)
            or not identity
            or identity in result
            or not _digest(contract)
            or not _digest(instructions)
        ):
            raise ComponentProposalPackageError(
                "proposal graph has stale or duplicate unit bindings"
            )
        result[identity] = {
            "unit_id": identity,
            "contract_sha256": str(contract),
            "instruction_bytes_sha256": str(instructions),
        }
    if not result:
        raise ComponentProposalPackageError("proposal graph has no unit bindings")
    return result


def _load_unit_bindings(path: Path) -> dict[str, dict[str, str]]:
    payload = _read_object(path, "proposal unit bindings")
    if payload.get("format") != COMPONENT_UNIT_BINDING_INDEX_V2_FORMAT:
        raise ComponentProposalPackageError("unsupported proposal unit binding index")
    _check_self_hash(
        payload, "unit_binding_index_sha256", "proposal unit binding index"
    )
    return _unit_bindings({"nodes": payload.get("bindings")})


def _check_membership_binding(
    proposal: Mapping[str, Any],
    unit_bindings: Mapping[str, Mapping[str, str]],
) -> None:
    identity = proposal.get("id")
    membership = _mapping(proposal.get("membership"), "proposal membership")
    unit_ids = _sequence(membership.get("unit_ids"), "proposal unit IDs")
    if (
        not unit_ids
        or any(not isinstance(value, str) or not value for value in unit_ids)
        or len(set(unit_ids)) != len(unit_ids)
    ):
        raise ComponentProposalPackageError(
            f"proposal {identity!r} has invalid unit membership"
        )
    try:
        selected = [unit_bindings[str(unit_id)] for unit_id in unit_ids]
    except KeyError as exc:
        raise ComponentProposalPackageError(
            f"proposal {identity!r} references unknown unit {exc.args[0]!r}"
        ) from exc
    bindings = _mapping(proposal.get("bindings"), "proposal bindings")
    expected = bindings.get("membership_bindings_sha256")
    observed = _canonical_sha256(selected)
    if not _digest(expected) or expected != observed:
        raise ComponentProposalPackageError(
            f"proposal {identity!r} has stale membership binding"
        )


def _validate_proposal_value(
    *,
    value: Mapping[str, Any],
    proposal_id: str,
    summary: Mapping[str, Any],
    unit_bindings: Mapping[str, Mapping[str, str]],
) -> None:
    if value.get("id") != proposal_id:
        raise ComponentProposalPackageError(
            f"proposal record {proposal_id!r} contains a different identity"
        )
    expected = summary.get("proposal_sha256")
    observed = value.get("proposal_sha256")
    core = copy.deepcopy(dict(value))
    core.pop("proposal_sha256", None)
    if (
        not _digest(expected)
        or observed != expected
        or expected != _canonical_sha256(core)
    ):
        raise ComponentProposalPackageError(
            f"proposal {proposal_id!r} contradicts its index binding"
        )
    if _proposal_summary(value) != summary:
        raise ComponentProposalPackageError(
            f"proposal {proposal_id!r} contradicts its index summary"
        )
    _check_membership_binding(value, unit_bindings)


def _file_descriptor(path: Path, root: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _checked_file(root: Path, raw: Any) -> Path:
    descriptor = _mapping(raw, "file descriptor")
    relative = descriptor.get("path")
    if not isinstance(relative, str) or Path(relative).name != relative:
        raise ComponentProposalPackageError("proposal sidecar path is invalid")
    path = root / relative
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ComponentProposalPackageError(
            f"cannot read proposal package sidecar {relative}: {exc}"
        ) from exc
    if (
        descriptor.get("size") != len(data)
        or descriptor.get("sha256") != hashlib.sha256(data).hexdigest()
    ):
        raise ComponentProposalPackageError(
            f"proposal package sidecar {relative} is stale"
        )
    return path


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentProposalPackageError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ComponentProposalPackageError(f"{label} must be an object")
    if path.read_text(encoding="ascii") != json_dumps(value) + "\n":
        raise ComponentProposalPackageError(f"{label} is not canonical compact JSON")
    return value


def _read_array(path: Path, label: str) -> list[Any]:
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentProposalPackageError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, list):
        raise ComponentProposalPackageError(f"{label} must be an array")
    if path.read_text(encoding="ascii") != json_dumps(value) + "\n":
        raise ComponentProposalPackageError(f"{label} is not canonical compact JSON")
    return value


def _check_self_hash(value: Mapping[str, Any], field: str, label: str) -> None:
    expected = value.get(field)
    core = copy.deepcopy(dict(value))
    core.pop(field, None)
    if not _digest(expected) or expected != _canonical_sha256(core):
        raise ComponentProposalPackageError(f"{label} self-hash is stale")


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ComponentProposalPackageError(f"{label} must be an object")
    return value


def _sequence(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, list):
        raise ComponentProposalPackageError(f"{label} must be an array")
    return value


def _status(value: Any) -> str:
    if value not in {"proposed", "incomplete"}:
        raise ComponentProposalPackageError("proposal status is invalid")
    return str(value)


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _SHA256_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(json_dumps(value).encode("ascii")).hexdigest()


__all__ = [
    "ComponentProposalPackageError",
    "ComponentProposalPackageV2",
    "PROPOSAL_INDEX_FILENAME",
    "load_component_proposal_package_v2",
    "write_component_proposal_package_v2",
]
