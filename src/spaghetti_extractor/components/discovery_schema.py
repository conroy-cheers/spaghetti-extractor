"""Input loading and schema checks for component discovery."""

from __future__ import annotations

import copy
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from .discovery_model import (
    MACHINE_IR_FILENAME,
    MACHINE_IR_FORMAT,
    MACHINE_IR_MANIFEST_FILENAME,
    RECONSTRUCTION_PLAN_FORMAT,
    ComponentDiscoveryError,
    _Inputs,
    _canonical_sha256,
    _mapping,
    _unit_key,
    _unit_span,
)


def _load_inputs(machine_path: Path, plan_path: Path) -> _Inputs:
    manifest_path = (
        machine_path / MACHINE_IR_MANIFEST_FILENAME
        if machine_path.is_dir()
        else machine_path
    )
    manifest = _read_object(manifest_path, "machine IR manifest")
    if manifest.get("format") != MACHINE_IR_FORMAT:
        raise ComponentDiscoveryError("unsupported machine IR manifest format")
    artifacts = _mapping(manifest.get("artifacts"), "machine IR artifacts")
    artifact = _mapping(artifacts.get("machine_ir"), "machine IR artifact")
    relative_ir = artifact.get("path", MACHINE_IR_FILENAME)
    if not isinstance(relative_ir, str) or not relative_ir:
        raise ComponentDiscoveryError("machine IR artifact path is malformed")
    ir_path = (manifest_path.parent / relative_ir).resolve()
    try:
        ir_path.relative_to(manifest_path.parent.resolve())
    except ValueError as error:
        raise ComponentDiscoveryError("machine IR artifact escapes its package") from error
    if not ir_path.is_file():
        raise ComponentDiscoveryError(f"machine IR artifact does not exist: {ir_path}")
    if artifact.get("sha256") != _sha256_file(ir_path):
        raise ComponentDiscoveryError("machine IR artifact hash does not match manifest")

    units = tuple(_read_jsonl(ir_path))
    if not units:
        raise ComponentDiscoveryError("machine IR package contains no units")
    by_id: dict[str, dict[str, Any]] = {}
    by_rva: dict[int, str] = {}
    for unit in units:
        identity = unit.get("id")
        if not isinstance(identity, str) or not identity:
            raise ComponentDiscoveryError("machine IR unit has no stable ID")
        if identity in by_id:
            raise ComponentDiscoveryError(f"duplicate machine IR unit ID {identity!r}")
        start, end = _unit_span(unit)
        if start in by_rva:
            raise ComponentDiscoveryError(f"duplicate machine IR RVA 0x{start:x}")
        if end <= start:
            raise ComponentDiscoveryError(f"machine IR unit {identity!r} has empty span")
        source = _mapping(unit.get("source"), f"machine IR unit {identity} source")
        for digest_name in ("contract_sha256", "instruction_bytes_sha256"):
            digest = source.get(digest_name)
            if not isinstance(digest, str) or len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            ):
                raise ComponentDiscoveryError(
                    f"machine IR unit {identity!r} has no exact {digest_name} binding"
                )
        semantics = unit.get("semantics")
        if not isinstance(semantics, Mapping):
            raise ComponentDiscoveryError(f"machine IR unit {identity!r} has no semantics")
        by_id[identity] = copy.deepcopy(unit)
        by_rva[start] = identity

    resolved_plan = (
        plan_path / "reconstruction-plan.json" if plan_path.is_dir() else plan_path
    )
    plan = _read_object(resolved_plan, "reconstruction plan")
    if plan.get("format") != RECONSTRUCTION_PLAN_FORMAT:
        raise ComponentDiscoveryError("unsupported reconstruction plan format")
    plan_sha = plan.get("plan_sha256")
    if not isinstance(plan_sha, str) or plan_sha != _canonical_sha256(
        {key: value for key, value in plan.items() if key != "plan_sha256"}
    ):
        raise ComponentDiscoveryError("reconstruction plan self hash is stale")
    binding = _mapping(
        _mapping(plan.get("inputs"), "reconstruction plan inputs").get("machine_ir"),
        "reconstruction plan machine IR binding",
    )
    expected_binding = {
        "format": MACHINE_IR_FORMAT,
        "sha256": _sha256_file(ir_path),
        "manifest_sha256": _sha256_file(manifest_path),
    }
    for name, expected in expected_binding.items():
        if binding.get(name) != expected:
            raise ComponentDiscoveryError(
                f"reconstruction plan machine IR {name} binding is stale"
            )

    clusters: dict[str, tuple[str, ...]] = {}
    cluster_by_unit_lists: dict[str, list[str]] = defaultdict(list)
    raw_clusters = plan.get("clusters", [])
    if not isinstance(raw_clusters, list):
        raise ComponentDiscoveryError("reconstruction plan clusters must be an array")
    for index, raw in enumerate(raw_clusters):
        item = _mapping(raw, f"reconstruction cluster {index}")
        identity = item.get("id")
        members = item.get("unit_ids")
        if not isinstance(identity, str) or not identity:
            raise ComponentDiscoveryError(f"reconstruction cluster {index} has no ID")
        if identity in clusters:
            raise ComponentDiscoveryError(f"duplicate reconstruction cluster {identity!r}")
        if not isinstance(members, list) or not all(
            isinstance(value, str) for value in members
        ):
            raise ComponentDiscoveryError(f"cluster {identity!r} unit IDs are malformed")
        unknown = sorted(set(members) - set(by_id))
        if unknown:
            raise ComponentDiscoveryError(
                f"cluster {identity!r} references unknown units: {unknown}"
            )
        ordered = tuple(sorted(set(members), key=lambda value: _unit_key(by_id[value])))
        clusters[identity] = ordered
        for unit_id in ordered:
            cluster_by_unit_lists[unit_id].append(identity)
    cluster_by_unit = {
        unit_id: tuple(sorted(values))
        for unit_id, values in cluster_by_unit_lists.items()
    }
    return _Inputs(
        manifest_path=manifest_path,
        ir_path=ir_path,
        plan_path=resolved_plan,
        manifest=manifest,
        plan=plan,
        units=tuple(by_id[identity] for identity in sorted(by_id, key=lambda value: _unit_key(by_id[value]))),
        by_id=by_id,
        by_rva=by_rva,
        cluster_by_unit=cluster_by_unit,
        clusters=clusters,
        ir_sha256=expected_binding["sha256"],
        manifest_sha256=expected_binding["manifest_sha256"],
        plan_file_sha256=_sha256_file(resolved_plan),
        unit_hint_facts={},
    )


def _read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ComponentDiscoveryError(
                    f"invalid machine IR JSON on line {line_number}"
                ) from error
            if not isinstance(value, dict):
                raise ComponentDiscoveryError(
                    f"machine IR line {line_number} is not an object"
                )
            yield value


def _read_object(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise ComponentDiscoveryError(f"{label} does not exist: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ComponentDiscoveryError(f"cannot read {label}: {path}") from error
    if not isinstance(value, dict):
        raise ComponentDiscoveryError(f"{label} must be a JSON object")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
