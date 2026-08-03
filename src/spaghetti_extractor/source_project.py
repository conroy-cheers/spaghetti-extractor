"""Static bindings and candidate-only assurance for idiomatic source projects."""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .linked_library_contracts import (
    LinkedLibraryContractError,
    validate_linked_island_manifest,
)
from .util import sha256_file, write_json


SOURCE_PROJECT_SPEC_FORMAT = "stage-b-source-project-spec-v1"
SOURCE_PROJECT_BINDING_FORMAT = "stage-b-source-project-binding-v1"
SOURCE_PROJECT_BUILD_FORMAT = "stage-b-source-project-build-v1"
SOURCE_PROJECT_ASSURANCE_FORMAT = "stage-b-source-project-assurance-v1"


class SourceProjectError(ValueError):
    """A source-project specification or evidence package is malformed."""


def bind_source_project(
    *,
    machine_ir: Path | str,
    specification: Path | str | Mapping[str, Any],
    source_root: Path | str,
    linked_islands: Path | str | Mapping[str, Any] | None = None,
    out: Path | str,
) -> dict[str, Any]:
    """Bind reviewed source islands to exact machine-IR units without proving them."""

    manifest_path = _machine_manifest_path(Path(machine_ir))
    manifest = _read_object(manifest_path, "machine IR manifest")
    if manifest.get("format") != "stage-a-machine-ir-v2":
        raise SourceProjectError("unsupported machine IR format")
    artifact = _object(
        _object(manifest.get("artifacts"), "machine IR artifacts").get("machine_ir"),
        "machine IR artifact",
    )
    ir_path = (manifest_path.parent / str(artifact.get("path", "machine-ir.jsonl"))).resolve()
    try:
        ir_path.relative_to(manifest_path.parent.resolve())
    except ValueError as error:
        raise SourceProjectError("machine IR artifact escapes its package") from error
    if not ir_path.is_file() or artifact.get("sha256") != sha256_file(ir_path):
        raise SourceProjectError("machine IR artifact binding is stale")
    units = [_object(value, "machine IR unit") for value in _read_jsonl(ir_path)]
    if not units:
        raise SourceProjectError("machine IR contains no units")

    spec = (
        _copy_object(specification, "source-project specification")
        if isinstance(specification, Mapping)
        else _read_object(Path(specification), "source-project specification")
    )
    if spec.get("format") != SOURCE_PROJECT_SPEC_FORMAT:
        raise SourceProjectError("unsupported source-project specification format")
    expected_spec_hash = spec.get("specification_sha256")
    spec_core = copy.deepcopy(spec)
    spec_core.pop("specification_sha256", None)
    if expected_spec_hash != _canonical_sha256(spec_core):
        raise SourceProjectError("source-project specification self-hash is stale")
    binary = _object(manifest.get("binary"), "machine IR binary")
    if spec.get("original_binary_sha256") != binary.get("sha256"):
        raise SourceProjectError("source project/original binary binding is stale")

    root = Path(source_root).resolve()
    source_rows = _array(spec.get("sources"), "source-project sources")
    sources: list[dict[str, Any]] = []
    for raw_source in source_rows:
        source = _object(raw_source, "source-project source")
        relative = Path(_nonempty(source.get("path"), "source path"))
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise SourceProjectError("source path escapes source root") from error
        if not path.is_file():
            raise SourceProjectError(f"source file does not exist: {relative}")
        sources.append(
            {
                "path": relative.as_posix(),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    if not sources:
        raise SourceProjectError("source project contains no source files")

    by_rva: dict[int, Mapping[str, Any]] = {}
    spans: list[tuple[int, int, Mapping[str, Any]]] = []
    for unit in units:
        start, end = _unit_span(unit)
        if start in by_rva:
            raise SourceProjectError(f"machine IR has duplicate RVA 0x{start:x}")
        by_rva[start] = unit
        spans.append((start, end, unit))
    spans.sort(key=lambda item: (item[0], item[1]))

    claimed_units: set[str] = set()
    islands: list[dict[str, Any]] = []
    for raw_island in _array(spec.get("islands"), "source-project islands"):
        island = _object(raw_island, "source-project island")
        island_id = _nonempty(island.get("id"), "source island ID")
        ranges = []
        selected: list[Mapping[str, Any]] = []
        for raw_range in _array(island.get("ranges"), "source island ranges"):
            region = _object(raw_range, "source island range")
            start = region.get("rva_start")
            end = region.get("rva_end")
            if not isinstance(start, int) or not isinstance(end, int) or end <= start:
                raise SourceProjectError(f"source island {island_id} has invalid range")
            for unit_start, unit_end, unit in spans:
                overlaps = unit_start < end and unit_end > start
                contained = unit_start >= start and unit_end <= end
                if overlaps and not contained:
                    raise SourceProjectError(
                        f"source island {island_id} cuts machine unit at RVA 0x{unit_start:x}"
                    )
                if contained:
                    selected.append(unit)
            ranges.append({"rva_start": start, "rva_end": end})
        selected_by_id = {str(unit["id"]): unit for unit in selected}
        if not selected_by_id:
            raise SourceProjectError(f"source island {island_id} contains no machine units")
        duplicate = claimed_units.intersection(selected_by_id)
        if duplicate:
            raise SourceProjectError(
                f"source islands overlap machine units: {sorted(duplicate)[:4]}"
            )
        claimed_units.update(selected_by_id)
        entry_rvas = _integers(island.get("entry_rvas"), "source island entries")
        missing_entries = [rva for rva in entry_rvas if rva not in by_rva]
        outside_entries = [
            rva for rva in entry_rvas if str(by_rva.get(rva, {}).get("id")) not in selected_by_id
        ]
        if missing_entries or outside_entries:
            raise SourceProjectError(
                f"source island {island_id} has invalid entries: "
                f"missing={missing_entries}, outside={outside_entries}"
            )
        boundaries = _island_boundaries(selected_by_id, by_rva)
        islands.append(
            {
                "id": island_id,
                "source_symbol": _nonempty(
                    island.get("source_symbol"), "source island symbol"
                ),
                "ranges": ranges,
                "entry_rvas": entry_rvas,
                "unit_ids": sorted(selected_by_id),
                "unit_count": len(selected_by_id),
                "unit_contract_sha256": _canonical_sha256(
                    [
                        {
                            "id": unit_id,
                            "contract_sha256": _object(
                                selected_by_id[unit_id].get("source"), "unit source"
                            ).get("contract_sha256"),
                            "instruction_bytes_sha256": _object(
                                selected_by_id[unit_id].get("source"), "unit source"
                            ).get("instruction_bytes_sha256"),
                        }
                        for unit_id in sorted(selected_by_id)
                    ]
                ),
                "boundary": boundaries,
                "assurance": "operator_reconstruction_pending_validation",
            }
        )

    if not islands:
        raise SourceProjectError("source project contains no islands")

    raw_scope = _object(spec.get("coverage_scope"), "source-project coverage scope")
    if raw_scope.get("kind") != "reviewed_machine_ranges":
        raise SourceProjectError("unsupported source-project coverage scope kind")
    required_ranges = _checked_scope_ranges(
        _array(raw_scope.get("required_ranges"), "source-project required ranges"),
        spans,
    )
    required_unit_ids = {
        unit_id
        for required_range in required_ranges
        for unit_id in required_range["unit_ids"]
    }
    missing_scope_units = required_unit_ids - claimed_units
    outside_scope_units = claimed_units - required_unit_ids
    if missing_scope_units or outside_scope_units:
        raise SourceProjectError(
            "source islands do not exactly cover the reviewed machine range scope: "
            f"missing={sorted(missing_scope_units)[:4]}, "
            f"outside={sorted(outside_scope_units)[:4]}"
        )
    out_of_scope_policy = _nonempty(
        raw_scope.get("out_of_scope_policy"),
        "source-project out-of-scope policy",
    )
    linked_scope = _bind_linked_island_scope(
        linked_islands=linked_islands,
        source_bound_units=claimed_units,
        machine_units={str(unit["id"]) for unit in units},
        machine_ir_sha256=sha256_file(ir_path),
        machine_ir_manifest_sha256=sha256_file(manifest_path),
        original_binary_sha256=str(binary.get("sha256")),
    )
    core = {
        "format": SOURCE_PROJECT_BINDING_FORMAT,
        "status": "bound",
        "equivalence_status": "not_proven",
        "executes_original_binary": False,
        "program_id": _nonempty(spec.get("program_id"), "source project program ID"),
        "bindings": {
            "specification_sha256": expected_spec_hash,
            "machine_ir_sha256": sha256_file(ir_path),
            "machine_ir_manifest_sha256": sha256_file(manifest_path),
            "original_binary_sha256": binary.get("sha256"),
            "linked_island_manifest_sha256": (
                linked_scope["manifest_sha256"] if linked_scope else None
            ),
        },
        "sources": sources,
        "islands": sorted(islands, key=lambda item: item["id"]),
        "coverage": {
            "machine_units": len(units),
            "source_bound_units": len(claimed_units),
            "remaining_machine_units": len(units) - len(claimed_units),
            "source_bound_unit_ids": sorted(claimed_units),
            "reviewed_scope": {
                "kind": "reviewed_machine_ranges",
                "required_ranges": required_ranges,
                "required_machine_units": len(required_unit_ids),
                "source_bound_machine_units": len(claimed_units),
                "remaining_machine_units": 0,
                "fully_source_bound": True,
                "out_of_scope_policy": out_of_scope_policy,
            },
            "linked_islands": linked_scope,
        },
        "authority": {
            "class": "checked_static_source_binding",
            "proves_source_semantics": False,
            "can_authorize_machine_override": False,
            "candidate_runtime_validation_required": True,
            "linked_dependency_identity_authorizes_source_replacement": False,
        },
    }
    payload = {**core, "binding_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def _bind_linked_island_scope(
    *,
    linked_islands: Path | str | Mapping[str, Any] | None,
    source_bound_units: set[str],
    machine_units: set[str],
    machine_ir_sha256: str,
    machine_ir_manifest_sha256: str,
    original_binary_sha256: str,
) -> dict[str, Any] | None:
    if linked_islands is None:
        return None
    manifest = (
        _copy_object(linked_islands, "linked-island manifest")
        if isinstance(linked_islands, Mapping)
        else _read_object(Path(linked_islands), "linked-island manifest")
    )
    try:
        validate_linked_island_manifest(manifest)
    except LinkedLibraryContractError as error:
        raise SourceProjectError(f"invalid linked-island manifest: {error}") from error
    bindings = _object(manifest.get("bindings"), "linked-island bindings")
    expected_bindings = {
        "original_binary_sha256": original_binary_sha256,
        "machine_ir_sha256": machine_ir_sha256,
        "machine_ir_manifest_sha256": machine_ir_manifest_sha256,
    }
    stale = {
        key: {"expected": expected, "observed": bindings.get(key)}
        for key, expected in expected_bindings.items()
        if bindings.get(key) != expected
    }
    if stale:
        raise SourceProjectError(
            f"source project/linked-island binding is stale: {stale}"
        )
    owner_by_unit: dict[str, Mapping[str, Any]] = {}
    units_by_kind: dict[str, set[str]] = {}
    for raw_island in _array(manifest.get("islands"), "linked islands"):
        island = _object(raw_island, "linked island")
        kind = _nonempty(island.get("kind"), "linked island kind")
        owned = {str(value) for value in _array(island.get("unit_ids"), "linked island units")}
        units_by_kind.setdefault(kind, set()).update(owned)
        for unit_id in owned:
            owner_by_unit[unit_id] = island
    if set(owner_by_unit) != machine_units:
        raise SourceProjectError(
            "linked-island manifest does not classify the exact machine-IR unit set"
        )
    non_application = {
        unit_id: str(owner_by_unit[unit_id].get("kind"))
        for unit_id in sorted(source_bound_units)
        if owner_by_unit[unit_id].get("kind") != "application"
    }
    if non_application:
        raise SourceProjectError(
            "source islands may bind only reviewed application units: "
            f"{dict(list(non_application.items())[:8])}"
        )
    application_units = units_by_kind.get("application", set())
    remaining_application = application_units - source_bound_units
    return {
        "manifest_sha256": manifest["manifest_sha256"],
        "classification_status": manifest.get("status"),
        "machine_units": len(machine_units),
        "units_by_kind": {
            kind: len(unit_ids) for kind, unit_ids in sorted(units_by_kind.items())
        },
        "source_bound_application_units": len(source_bound_units),
        "remaining_application_units": len(remaining_application),
        "remaining_application_unit_ids": sorted(remaining_application),
        "unknown_units": len(units_by_kind.get("unknown", set())),
        "all_source_units_are_reviewed_application": True,
        "identity_authorizes_replacement": False,
    }


def assess_source_project(
    *,
    binding: Path | str,
    candidate_binary: Path | str,
    functional_report: Path | str,
    out: Path | str,
) -> dict[str, Any]:
    """Combine static binding and candidate-only tests without claiming proof."""

    binding_path = Path(binding)
    project = _read_object(binding_path, "source-project binding")
    if project.get("format") != SOURCE_PROJECT_BINDING_FORMAT:
        raise SourceProjectError("unsupported source-project binding format")
    binding_core = copy.deepcopy(project)
    observed_binding_hash = binding_core.pop("binding_sha256", None)
    if observed_binding_hash != _canonical_sha256(binding_core):
        raise SourceProjectError("source-project binding self-hash is stale")
    report_path = Path(functional_report)
    report = _read_object(report_path, "functional report")
    if report.get("format") != "stage-b-functional-report-v1":
        raise SourceProjectError("unsupported functional report format")
    report_status = report.get("status")
    if report_status not in {"pass", "fail"}:
        raise SourceProjectError("functional report has an invalid status")
    counts = _object(report.get("counts"), "functional report counts")
    case_count = counts.get("cases")
    passed_count = counts.get("passed")
    failed_count = counts.get("failed")
    if (
        not all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in (case_count, passed_count, failed_count)
        )
        or case_count != passed_count + failed_count
    ):
        raise SourceProjectError("functional report counts are inconsistent")
    oracle = _object(report.get("oracle"), "functional report oracle")
    if oracle.get("original_runtime_observations") is not False:
        raise SourceProjectError(
            "source-project assurance requires an explicit candidate-only oracle"
        )
    candidate = Path(candidate_binary)
    if not candidate.is_file():
        raise SourceProjectError("source-project candidate binary is missing")
    candidate_sha256 = sha256_file(candidate)
    candidate_binding = _object(
        _object(report.get("binary_bindings"), "functional binary bindings").get(
            "candidate"
        ),
        "functional candidate binding",
    )
    if (
        candidate_binding.get("provided") is not True
        or candidate_binding.get("exists") is not True
        or candidate_binding.get("sha256") != candidate_sha256
    ):
        raise SourceProjectError(
            "functional report is not bound to the source-project candidate"
        )
    passed = report_status == "pass" and failed_count == 0 and passed_count == case_count
    core = {
        "format": SOURCE_PROJECT_ASSURANCE_FORMAT,
        "status": "behavior_validated" if passed else "violated",
        "equivalence_status": "not_proven",
        "executes_original_binary": False,
        "program_id": project.get("program_id"),
        "bindings": {
            "source_project_binding_sha256": observed_binding_hash,
            "source_project_binding_artifact_sha256": sha256_file(binding_path),
            "candidate_binary_sha256": candidate_sha256,
            "functional_report_sha256": sha256_file(report_path),
        },
        "coverage": copy.deepcopy(project.get("coverage")),
        "functional": {
            "suite_id": report.get("suite_id"),
            "status": report_status,
            "counts": copy.deepcopy(dict(counts)),
            "original_runtime_observations": False,
        },
        "authority": {
            "class": "candidate_only_behavior_evidence",
            "proves_equivalence": False,
            "can_authorize_machine_override": False,
            "runtime_failure_is_veto": True,
        },
    }
    payload = {**core, "assurance_sha256": _canonical_sha256(core)}
    write_json(Path(out), payload)
    return payload


def bind_source_project_specification(payload: Mapping[str, Any]) -> dict[str, Any]:
    core = _copy_object(payload, "source-project specification")
    core.pop("specification_sha256", None)
    if core.get("format") != SOURCE_PROJECT_SPEC_FORMAT:
        raise SourceProjectError("unsupported source-project specification format")
    return {**core, "specification_sha256": _canonical_sha256(core)}


def _island_boundaries(
    members: Mapping[str, Mapping[str, Any]], by_rva: Mapping[int, Mapping[str, Any]]
) -> dict[str, Any]:
    member_ids = set(members)
    calls = []
    control = []
    imports = []
    for unit_id in sorted(members):
        unit = members[unit_id]
        semantics = _object(unit.get("semantics"), "unit semantics")
        for index, raw_event in enumerate(
            _array(semantics.get("external_events", []), "unit external events")
        ):
            event = _object(raw_event, "unit external event")
            row = {"source_unit_id": unit_id, "event_index": index, **copy.deepcopy(event)}
            if event.get("kind") == "internal_call":
                target_rva = event.get("target_rva")
                target = by_rva.get(target_rva) if isinstance(target_rva, int) else None
                if target is None or str(target.get("id")) not in member_ids:
                    calls.append(row)
            else:
                imports.append(row)
        for target_rva in _array(
            _object(unit.get("control", {}), "unit control").get("direct_targets", []),
            "unit direct targets",
        ):
            if not isinstance(target_rva, int):
                continue
            target = by_rva.get(target_rva)
            if target is None or str(target.get("id")) not in member_ids:
                control.append(
                    {"source_unit_id": unit_id, "target_rva": target_rva}
                )
    return {
        "internal_calls": calls,
        "external_events": imports,
        "outgoing_control": control,
        "counts": {
            "internal_calls": len(calls),
            "external_events": len(imports),
            "outgoing_control": len(control),
        },
    }


def _machine_manifest_path(path: Path) -> Path:
    return path / "machine-ir-manifest.json" if path.is_dir() else path


def _checked_scope_ranges(
    values: list[Any],
    spans: list[tuple[int, int, Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    if not values:
        raise SourceProjectError("source-project required ranges must not be empty")
    normalized: list[tuple[int, int, str, Mapping[str, Any]]] = []
    for value in values:
        raw_value = _object(value, "source-project required range")
        range_id = _nonempty(raw_value.get("id"), "source-project required range ID")
        start, end = raw_value.get("rva_start"), raw_value.get("rva_end")
        if not isinstance(start, int) or not isinstance(end, int) or end <= start:
            raise SourceProjectError(f"source-project required range {range_id} is invalid")
        normalized.append((start, end, range_id, raw_value))
    ranges: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    previous_end: int | None = None
    for start, end, range_id, raw_value in sorted(
        normalized, key=lambda item: (item[0], item[1], item[2])
    ):
        if range_id in seen_ids:
            raise SourceProjectError(f"duplicate source-project required range ID: {range_id}")
        seen_ids.add(range_id)
        if previous_end is not None and start < previous_end:
            raise SourceProjectError("source-project required ranges overlap")
        previous_end = end
        selected: list[tuple[int, int, Mapping[str, Any]]] = []
        for unit_start, unit_end, unit in spans:
            overlaps = unit_start < end and unit_end > start
            contained = unit_start >= start and unit_end <= end
            if overlaps and not contained:
                raise SourceProjectError(
                    f"source-project required range {range_id} cuts machine unit "
                    f"at RVA 0x{unit_start:x}"
                )
            if contained:
                selected.append((unit_start, unit_end, unit))
        cursor = start
        for unit_start, unit_end, _unit in selected:
            if unit_start != cursor:
                raise SourceProjectError(
                    f"source-project required range {range_id} is not exactly "
                    f"partitioned by machine IR at RVA 0x{cursor:x}"
                )
            cursor = unit_end
        if cursor != end:
            raise SourceProjectError(
                f"source-project required range {range_id} is not exactly "
                f"partitioned by machine IR at RVA 0x{cursor:x}"
            )
        ranges.append(
            {
                "id": range_id,
                "rva_start": start,
                "rva_end": end,
                "provenance_hint": str(raw_value.get("provenance_hint", "")),
                "unit_ids": [str(unit["id"]) for _, _, unit in selected],
                "unit_count": len(selected),
            }
        )
    return ranges


def _unit_span(unit: Mapping[str, Any]) -> tuple[int, int]:
    original = _object(_object(unit.get("source"), "unit source").get("original"), "unit span")
    start, end = original.get("rva_start"), original.get("rva_end")
    if not isinstance(start, int) or not isinstance(end, int) or end <= start:
        raise SourceProjectError("machine IR unit has an invalid span")
    return start, end


def _read_jsonl(path: Path) -> list[Any]:
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, json.JSONDecodeError) as error:
        raise SourceProjectError(f"cannot read machine IR: {error}") from error


def _read_object(path: Path, description: str) -> dict[str, Any]:
    try:
        return _copy_object(json.loads(path.read_text(encoding="utf-8")), description)
    except (OSError, json.JSONDecodeError) as error:
        raise SourceProjectError(f"cannot read {description}: {error}") from error


def _copy_object(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SourceProjectError(f"{description} must be an object")
    return copy.deepcopy(dict(value))


def _object(value: Any, description: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SourceProjectError(f"{description} must be an object")
    return value


def _array(value: Any, description: str) -> list[Any]:
    if not isinstance(value, list):
        raise SourceProjectError(f"{description} must be an array")
    return value


def _integers(value: Any, description: str) -> list[int]:
    rows = _array(value, description)
    if any(not isinstance(item, int) or item < 0 for item in rows):
        raise SourceProjectError(f"{description} must contain non-negative integers")
    return list(rows)


def _nonempty(value: Any, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise SourceProjectError(f"{description} must be a non-empty string")
    return value


def _canonical_sha256(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


__all__ = [
    "SourceProjectError",
    "SOURCE_PROJECT_ASSURANCE_FORMAT",
    "SOURCE_PROJECT_BINDING_FORMAT",
    "SOURCE_PROJECT_BUILD_FORMAT",
    "SOURCE_PROJECT_SPEC_FORMAT",
    "assess_source_project",
    "bind_source_project",
    "bind_source_project_specification",
]
