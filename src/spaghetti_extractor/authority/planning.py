"""Checked structural and dependency planning for v3 authority graphs.

The planner is deliberately framework-owned.  Dynamic target preparation and
standalone corruption fixtures invoke these same functions, so there is only
one implementation of schedule validation, SCC decomposition, and stable pack
routing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..artifact_set_v3 import (
    MAX_DEPENDENCY_SCHEDULE_BYTES,
    MAX_STRUCTURAL_SCHEDULE_BYTES,
    DependencyNodePlanV3,
    DependencySchedulingManifestV3,
    RecordDependencyV3,
    StructuralSchedulingManifestV3,
    StructuralUnitPlanV3,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
    identity_bucket_v3,
)
from ._schema import fail, mapping, sequence, text, uint


STRUCTURAL_INVENTORY_FORMAT_V3 = "spaghetti-extractor-structural-inventory-v3"
RECORD_EDGES_FORMAT_V3 = "spaghetti-extractor-record-edges-v3"
STRUCTURAL_PACK_INDEX_FORMAT_V3 = (
    "spaghetti-extractor-structural-pack-index-v3"
)
DEPENDENCY_PACK_INDEX_FORMAT_V3 = (
    "spaghetti-extractor-dependency-pack-index-v3"
)
BOUNDARY_SET_FORMAT_V3 = "spaghetti-extractor-scheduling-boundaries-v3"
_BUCKET_COUNTS = frozenset({1, 2, 4, 8, 16, 32, 64})
_RESOURCE_RANK = {"small": 0, "medium": 1, "large": 2, "oracle": 3}

DEFAULT_RESOURCE_CLASSES_V3: dict[str, dict[str, dict[str, int]]] = {
    "small": {
        "resource": {"cores": 1, "memory_mib": 768, "disk_mib": 1024},
        "timing": {"expected_seconds": 30, "timeout_seconds": 300},
    },
    "medium": {
        "resource": {"cores": 2, "memory_mib": 1536, "disk_mib": 4096},
        "timing": {"expected_seconds": 180, "timeout_seconds": 1800},
    },
    "large": {
        "resource": {"cores": 4, "memory_mib": 3584, "disk_mib": 16384},
        "timing": {"expected_seconds": 900, "timeout_seconds": 7200},
    },
    "oracle": {
        "resource": {"cores": 8, "memory_mib": 32768, "disk_mib": 32768},
        "timing": {"expected_seconds": 3600, "timeout_seconds": 21600},
    },
}


@dataclass(frozen=True)
class SchedulingBoundaryV3:
    """Paths and checked metadata emitted by one planning boundary."""

    output_directory: Path
    plan_id: str
    schedule_sha256: str
    pack_index_sha256: str
    validation_sha256: str

    def descriptor(self, *, relative_to: Path) -> dict[str, Any]:
        directory = self.output_directory.relative_to(relative_to).as_posix()
        return {
            "directory": directory,
            "schedule": {
                "filename": f"{directory}/schedule.json",
                "sha256": self.schedule_sha256,
            },
            "validation": {
                "filename": f"{directory}/validation.json",
                "sha256": self.validation_sha256,
            },
            "pack_index": {
                "filename": f"{directory}/pack-index.json",
                "sha256": self.pack_index_sha256,
            },
            "packs_directory": f"{directory}/packs",
            "plan_id": self.plan_id,
        }


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        fail(
            "missing_planning_input",
            f"cannot inspect {label} {path}: {exc}",
            "provide the exact checked planning input",
        )
    if size > limit:
        fail(
            "oversized_planning_input",
            f"{label} is {size} bytes; limit is {limit}",
            "keep semantic facts in artifact packs and planning inventories compact",
        )
    return path.read_bytes()


def _load_json(path: Path, limit: int, label: str) -> tuple[bytes, Any]:
    data = _read_bounded(path, limit, label)

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(
                    "duplicate_json_key",
                    f"{label} repeats key {key!r}",
                    "regenerate the planning input with the canonical v3 writer",
                )
            result[key] = value
        return result

    def reject_number(value: str) -> Any:
        fail(
            "noncanonical_json_number",
            f"{label} contains non-integer number {value!r}",
            "encode exact planning values as integers",
        )

    try:
        return data, json.loads(
            data.decode("ascii"),
            object_pairs_hook=unique_object,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(
            "invalid_planning_json",
            f"cannot parse {label}: {exc}",
            "regenerate the input with the canonical v3 writer",
        )


def _bucket_count(value: int) -> int:
    if value not in _BUCKET_COUNTS:
        fail(
            "invalid_schedule_bucket_count",
            f"schedule bucket count is {value}",
            "use a power-of-two divisor of 64",
        )
    return value


def _validate_resource_classes(
    value: dict[str, Any],
) -> dict[str, dict[str, dict[str, int]]]:
    policies = mapping(value, "resource-class policies")
    result: dict[str, dict[str, dict[str, int]]] = {}
    for resource_class, raw_policy in policies.items():
        if resource_class not in _RESOURCE_RANK:
            fail(
                "invalid_resource_class",
                f"planning policy contains class {resource_class!r}",
                "use small, medium, large, or oracle",
            )
        policy = mapping(raw_policy, f"resource policy {resource_class}")
        if set(policy) != {"resource", "timing"}:
            fail(
                "invalid_resource_policy",
                f"resource policy {resource_class!r} has unexpected fields",
                "provide exact resource and timing objects",
            )
        resource = mapping(policy["resource"], f"resource policy {resource_class}")
        timing = mapping(policy["timing"], f"timing policy {resource_class}")
        if set(resource) != {"cores", "memory_mib", "disk_mib"} or set(timing) != {
            "expected_seconds",
            "timeout_seconds",
        }:
            fail(
                "invalid_resource_policy",
                f"resource policy {resource_class!r} is incomplete",
                "use the framework resource policy schema",
            )
        parsed_resource = {
            key: uint(raw, f"{resource_class}.{key}") for key, raw in resource.items()
        }
        parsed_timing = {
            key: uint(raw, f"{resource_class}.{key}") for key, raw in timing.items()
        }
        if not all(parsed_resource.values()) or not all(parsed_timing.values()):
            fail(
                "invalid_resource_policy",
                f"resource policy {resource_class!r} contains zero",
                "use positive resource and timing limits",
            )
        if parsed_timing["timeout_seconds"] < parsed_timing["expected_seconds"]:
            fail(
                "invalid_resource_policy",
                f"resource policy {resource_class!r} times out before its estimate",
                "set timeout_seconds at least as high as expected_seconds",
            )
        result[resource_class] = {
            "resource": parsed_resource,
            "timing": parsed_timing,
        }
    if set(result) != set(_RESOURCE_RANK):
        fail(
            "incomplete_resource_policy",
            "resource-class policy does not cover every framework class",
            "provide small, medium, large, and oracle policies",
        )
    return result


def prepare_structural_boundary_v3(
    *,
    inventory: Path,
    output_directory: Path,
    resource_classes: dict[str, Any],
    schedule: Path | None = None,
    schedule_bucket_count: int = 4,
) -> SchedulingBoundaryV3:
    """Check structural coverage and emit stable unit schedule packs."""

    bucket_count = _bucket_count(schedule_bucket_count)
    policies = _validate_resource_classes(resource_classes)
    inventory_bytes, raw_inventory = _load_json(
        inventory, MAX_STRUCTURAL_SCHEDULE_BYTES, "structural inventory"
    )
    document = mapping(raw_inventory, "structural inventory")
    if set(document) != {"format", "universe_sha256", "units"}:
        fail(
            "invalid_structural_inventory",
            "structural inventory has unexpected fields",
            "regenerate it from exact source preparation",
        )
    if document["format"] != STRUCTURAL_INVENTORY_FORMAT_V3:
        fail(
            "wrong_structural_inventory_format",
            "structural inventory is not v3",
            "use the v3 source planner",
        )

    expected: dict[str, tuple[int, int, tuple[str, ...]]] = {}
    expected_resources: dict[str, str] = {}
    units: list[StructuralUnitPlanV3] = []
    for index, raw_row in enumerate(sequence(document["units"], "structural units")):
        row = mapping(raw_row, f"structural unit {index}")
        if set(row) != {
            "unit_id",
            "start",
            "end",
            "dependencies",
            "resource_class",
        }:
            fail(
                "invalid_structural_unit",
                f"structural unit {index} has unexpected fields",
                "emit the exact v3 structural-unit schema",
            )
        unit_id = text(row["unit_id"], "structural unit ID")
        if unit_id in expected:
            fail(
                "duplicate_structural_unit",
                f"structural inventory repeats {unit_id!r}",
                "emit each structural unit exactly once",
            )
        dependencies = tuple(
            text(item, f"dependency of {unit_id}")
            for item in sequence(row["dependencies"], f"dependencies of {unit_id}")
        )
        resource_class = text(row["resource_class"], f"resource class of {unit_id}")
        if resource_class not in policies:
            fail(
                "invalid_resource_class",
                f"unit {unit_id!r} uses {resource_class!r}",
                "select a declared framework resource class",
            )
        start = uint(row["start"], f"start of {unit_id}")
        end = uint(row["end"], f"end of {unit_id}")
        unit = StructuralUnitPlanV3.create(
            unit_id,
            start,
            end,
            dependencies=dependencies,
            resource_class=resource_class,
        )
        units.append(unit)
        expected[unit_id] = (start, end, dependencies)
        expected_resources[unit_id] = resource_class

    if schedule is None:
        plan = StructuralSchedulingManifestV3.create(
            text(document["universe_sha256"], "structural universe SHA-256"),
            units,
        )
    else:
        plan = StructuralSchedulingManifestV3.parse_bytes(
            _read_bounded(schedule, MAX_STRUCTURAL_SCHEDULE_BYTES, "structural schedule"),
            location=str(schedule),
        )
    if plan.universe_sha256 != document["universe_sha256"]:
        fail(
            "structural_universe_mismatch",
            "structural schedule binds a different universe",
            "regenerate it from the exact structural inventory",
        )
    plan.validate(expected)
    if {row.unit_id: row.resource_class for row in plan.units} != expected_resources:
        fail(
            "structural_resource_mismatch",
            "structural schedule resource classes differ from the inventory",
            "regenerate scheduling metadata from the checked inventory",
        )

    output_directory.mkdir(parents=True, exist_ok=True)
    packs_directory = output_directory / "packs"
    packs_directory.mkdir()
    schedule_bytes = plan.to_bytes()
    (output_directory / "schedule.json").write_bytes(schedule_bytes)
    divisor = 64 // bucket_count
    groups: dict[str, list[StructuralUnitPlanV3]] = {}
    for unit in plan.units:
        bucket = identity_bucket_v3(unit.unit_id) // divisor
        groups.setdefault(f"{unit.resource_class}-{bucket:02d}", []).append(unit)
    pack_rows: list[dict[str, Any]] = []
    for key, raw_members in sorted(groups.items()):
        members = tuple(sorted(raw_members, key=lambda row: row.unit_id))
        resource_class, bucket_text = key.rsplit("-", 1)
        item_ids = [row.unit_id for row in members]
        policy = policies[resource_class]
        core = {
            "format": "spaghetti-extractor-schedule-pack-v3",
            "schema_version": 3,
            "pack_kind": "structural",
            "identity_bucket": int(bucket_text),
            "resource_class": resource_class,
            "item_ids": item_ids,
            "dependencies": sorted(
                {dependency for row in members for dependency in row.dependencies}
            ),
            "items": [row.to_payload() for row in members],
            "resource": policy["resource"],
            "timing": policy["timing"],
        }
        pack_id = "schedule-pack-v3:" + canonical_sha256_v3(core)
        payload = {**core, "pack_id": pack_id}
        filename = f"{key}.json"
        pack_bytes = canonical_json_bytes_v3(payload)
        (packs_directory / filename).write_bytes(pack_bytes)
        pack_rows.append(
            {
                "key": key,
                "filename": filename,
                "identity_bucket": int(bucket_text),
                "resource_class": resource_class,
                "item_count": len(item_ids),
                "item_ids": item_ids,
                "item_ids_sha256": canonical_sha256_v3(item_ids),
                "pack_id": pack_id,
                "pack_sha256": hashlib.sha256(pack_bytes).hexdigest(),
            }
        )
    pack_index = {
        "format": STRUCTURAL_PACK_INDEX_FORMAT_V3,
        "schema_version": 3,
        "bucket_count": bucket_count,
        "plan_id": plan.plan_id,
        "unit_count": len(plan.units),
        "packs": pack_rows,
    }
    pack_index_bytes = canonical_json_bytes_v3(pack_index)
    (output_directory / "pack-index.json").write_bytes(pack_index_bytes)
    validation = {
        "format": "spaghetti-extractor-structural-boundary-validation-v3",
        "inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
        "plan_id": plan.plan_id,
        "schedule_sha256": hashlib.sha256(schedule_bytes).hexdigest(),
        "unit_count": len(plan.units),
        "pack_count": len(pack_rows),
    }
    validation_bytes = canonical_json_bytes_v3(validation)
    (output_directory / "validation.json").write_bytes(validation_bytes)
    return SchedulingBoundaryV3(
        output_directory=output_directory,
        plan_id=plan.plan_id,
        schedule_sha256=hashlib.sha256(schedule_bytes).hexdigest(),
        pack_index_sha256=hashlib.sha256(pack_index_bytes).hexdigest(),
        validation_sha256=hashlib.sha256(validation_bytes).hexdigest(),
    )


def prepare_dependency_boundary_v3(
    *,
    structural_schedule: Path,
    record_edges: Path,
    output_directory: Path,
    schedule: Path | None = None,
    require_structural_coverage: bool = True,
    schedule_bucket_count: int = 4,
) -> SchedulingBoundaryV3:
    """Check dependency completeness, exact SCCs, and stable closure packs."""

    bucket_count = _bucket_count(schedule_bucket_count)
    structural = StructuralSchedulingManifestV3.parse_bytes(
        _read_bounded(
            structural_schedule, MAX_STRUCTURAL_SCHEDULE_BYTES, "structural schedule"
        ),
        location=str(structural_schedule),
    )
    edge_bytes, raw_edges = _load_json(
        record_edges, MAX_DEPENDENCY_SCHEDULE_BYTES, "record-edge inventory"
    )
    edge_inventory = mapping(raw_edges, "record-edge inventory")
    if set(edge_inventory) != {"format", "nodes"}:
        fail(
            "invalid_record_edge_inventory",
            "record-edge inventory has unexpected fields",
            "regenerate it from checked transition dependencies",
        )
    if edge_inventory["format"] != RECORD_EDGES_FORMAT_V3:
        fail(
            "wrong_record_edge_format",
            "record-edge inventory is not v3",
            "use the v3 dependency planner",
        )

    expected_edges: dict[str, tuple[str, ...]] = {}
    expected_records: dict[str, tuple[RecordDependencyV3, ...]] = {}
    resources: dict[str, str] = {}
    nodes: list[DependencyNodePlanV3] = []
    for index, raw_row in enumerate(sequence(edge_inventory["nodes"], "record-edge nodes")):
        row = mapping(raw_row, f"record-edge node {index}")
        if set(row) != {"node_id", "dependencies", "records", "resource_class"}:
            fail(
                "invalid_record_edge_node",
                f"record-edge node {index} has unexpected fields",
                "emit the exact v3 record-edge schema",
            )
        node_id = text(row["node_id"], "record-edge node ID")
        if node_id in expected_edges:
            fail(
                "duplicate_dependency_node",
                f"record-edge inventory repeats {node_id!r}",
                "emit each dependency node exactly once",
            )
        dependencies = tuple(
            text(item, f"dependency of {node_id}")
            for item in sequence(row["dependencies"], f"dependencies of {node_id}")
        )
        records = tuple(
            RecordDependencyV3.parse(item)
            for item in sequence(row["records"], f"record references of {node_id}")
        )
        resource_class = text(row["resource_class"], f"resource class of {node_id}")
        if resource_class not in _RESOURCE_RANK:
            fail(
                "invalid_resource_class",
                f"dependency node {node_id!r} uses {resource_class!r}",
                "use small, medium, large, or oracle",
            )
        nodes.append(
            DependencyNodePlanV3.create(
                node_id, dependencies=dependencies, records=records
            )
        )
        expected_edges[node_id] = dependencies
        expected_records[node_id] = records
        resources[node_id] = resource_class

    if require_structural_coverage:
        structural_ids = {row.unit_id for row in structural.units}
        edge_ids = set(expected_edges)
        if edge_ids != structural_ids:
            fail(
                "dependency_coverage_mismatch",
                "record-edge nodes differ from the structural inventory: "
                f"missing={sorted(structural_ids-edge_ids)!r}, "
                f"unexpected={sorted(edge_ids-structural_ids)!r}",
                "emit one dependency node for every checked structural unit",
            )

    def scc_resource(members: tuple[str, ...]) -> str:
        return max((resources[member] for member in members), key=_RESOURCE_RANK.get)

    if schedule is None:
        plan = DependencySchedulingManifestV3.create(
            structural.sha256, nodes, resource_class=scc_resource
        )
    else:
        plan = DependencySchedulingManifestV3.parse_bytes(
            _read_bounded(schedule, MAX_DEPENDENCY_SCHEDULE_BYTES, "dependency schedule"),
            location=str(schedule),
        )
    if plan.structural_plan_sha256 != structural.sha256:
        fail(
            "dependency_structural_mismatch",
            "dependency schedule binds a different structural plan",
            "regenerate it from the exact checked structural schedule",
        )
    plan.validate(expected_edges, expected_records=expected_records)
    for scc in plan.sccs:
        if scc.resource_class != scc_resource(scc.members):
            fail(
                "dependency_resource_mismatch",
                f"SCC {scc.scc_id!r} has a stale resource class",
                "regenerate it from member resource classes",
            )

    output_directory.mkdir(parents=True, exist_ok=True)
    packs_directory = output_directory / "packs"
    packs_directory.mkdir()
    schedule_bytes = plan.to_bytes()
    (output_directory / "schedule.json").write_bytes(schedule_bytes)
    scc_by_id = {row.scc_id: row for row in plan.sccs}
    node_by_id = {row.node_id: row for row in plan.nodes}
    structural_by_id = {row.unit_id: row for row in structural.units}
    divisor = 64 // bucket_count
    groups: dict[str, list[str]] = {}
    for scc in plan.sccs:
        bucket = identity_bucket_v3(scc.scc_id) // divisor
        groups.setdefault(f"{scc.resource_class}-{bucket:02d}", []).append(scc.scc_id)

    def dependency_closure(selected: tuple[str, ...]) -> tuple[str, ...]:
        pending = list(selected)
        seen: set[str] = set()
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            pending.extend(scc_by_id[current].dependencies)
        return tuple(sorted(seen))

    pack_rows: list[dict[str, Any]] = []
    for key, raw_selected_ids in sorted(groups.items()):
        selected_ids = tuple(sorted(raw_selected_ids))
        closure_ids = dependency_closure(selected_ids)
        closure_sccs = tuple(
            sorted((scc_by_id[value] for value in closure_ids), key=lambda row: row.members)
        )
        closure_node_ids = tuple(member for scc in closure_sccs for member in scc.members)
        closure_nodes = tuple(node_by_id[value] for value in closure_node_ids)
        closure_units = tuple(structural_by_id[value] for value in closure_node_ids)
        local_scope_sha256 = canonical_sha256_v3(
            {
                "units": [row.to_payload() for row in closure_units],
                "nodes": [row.to_payload() for row in closure_nodes],
            }
        )
        expected_by_members = {row.members: row for row in closure_sccs}

        def local_resource(members: tuple[str, ...]) -> str:
            try:
                return expected_by_members[members].resource_class
            except KeyError:
                fail(
                    "dependency_slice_mismatch",
                    f"dependency slice {key!r} created unexpected SCC {members!r}",
                    "repair dependency closure construction",
                )

        local_plan = DependencySchedulingManifestV3.create(
            local_scope_sha256, closure_nodes, resource_class=local_resource
        )
        if local_plan.sccs != closure_sccs:
            fail(
                "dependency_slice_mismatch",
                f"dependency slice {key!r} differs from the global SCC closure",
                "regenerate the closure from the checked global plan",
            )
        filename = f"{key}.json"
        local_bytes = local_plan.to_bytes()
        (packs_directory / filename).write_bytes(local_bytes)
        selected_node_ids = tuple(
            sorted(
                member
                for scc_id in selected_ids
                for member in scc_by_id[scc_id].members
            )
        )
        resource_class = scc_by_id[selected_ids[0]].resource_class
        pack_rows.append(
            {
                "key": key,
                "identity_bucket": int(key.rsplit("-", 1)[1]),
                "resource_class": resource_class,
                "selected_scc_ids": list(selected_ids),
                "selected_node_ids": list(selected_node_ids),
                "closure_node_ids": sorted(closure_node_ids),
                "closure_scc_ids": list(closure_ids),
                "filename": filename,
                "schedule_sha256": hashlib.sha256(local_bytes).hexdigest(),
            }
        )
    pack_index = {
        "format": DEPENDENCY_PACK_INDEX_FORMAT_V3,
        "schema_version": 3,
        "bucket_count": bucket_count,
        "plan_id": plan.plan_id,
        "node_count": len(plan.nodes),
        "scc_count": len(plan.sccs),
        "scc_ids_sha256": canonical_sha256_v3(sorted(row.scc_id for row in plan.sccs)),
        "packs": pack_rows,
    }
    pack_index_bytes = canonical_json_bytes_v3(pack_index)
    (output_directory / "pack-index.json").write_bytes(pack_index_bytes)
    validation = {
        "format": "spaghetti-extractor-dependency-boundary-validation-v3",
        "node_count": len(plan.nodes),
        "record_edges_sha256": hashlib.sha256(edge_bytes).hexdigest(),
        "plan_id": plan.plan_id,
        "scc_count": len(plan.sccs),
        "schedule_sha256": hashlib.sha256(schedule_bytes).hexdigest(),
        "structural_plan_sha256": structural.sha256,
        "pack_count": len(pack_rows),
    }
    validation_bytes = canonical_json_bytes_v3(validation)
    (output_directory / "validation.json").write_bytes(validation_bytes)
    return SchedulingBoundaryV3(
        output_directory=output_directory,
        plan_id=plan.plan_id,
        schedule_sha256=hashlib.sha256(schedule_bytes).hexdigest(),
        pack_index_sha256=hashlib.sha256(pack_index_bytes).hexdigest(),
        validation_sha256=hashlib.sha256(validation_bytes).hexdigest(),
    )


def prepare_scheduling_boundaries_v3(
    *,
    structural_inventory: Path,
    record_edges: Path,
    output_directory: Path,
    resource_classes: dict[str, Any] | None = None,
    structural_schedule: Path | None = None,
    dependency_schedule: Path | None = None,
    require_structural_coverage: bool = True,
    schedule_bucket_count: int = 4,
) -> dict[str, Any]:
    """Check both graph boundaries in one process and return bound descriptors."""

    output_directory.mkdir(parents=True, exist_ok=True)
    structural = prepare_structural_boundary_v3(
        inventory=structural_inventory,
        output_directory=output_directory / "structural",
        resource_classes=resource_classes or DEFAULT_RESOURCE_CLASSES_V3,
        schedule=structural_schedule,
        schedule_bucket_count=schedule_bucket_count,
    )
    dependency = prepare_dependency_boundary_v3(
        structural_schedule=structural.output_directory / "schedule.json",
        record_edges=record_edges,
        output_directory=output_directory / "dependency",
        schedule=dependency_schedule,
        require_structural_coverage=require_structural_coverage,
        schedule_bucket_count=schedule_bucket_count,
    )
    return {
        "format": BOUNDARY_SET_FORMAT_V3,
        "schedule_bucket_count": schedule_bucket_count,
        "structural": structural.descriptor(relative_to=output_directory.parent),
        "dependency": dependency.descriptor(relative_to=output_directory.parent),
    }


def _path_or_none(value: str) -> Path | None:
    return None if value == "-" else Path(value)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    structural = subparsers.add_parser("structural")
    structural.add_argument("--inventory", type=Path, required=True)
    structural.add_argument("--schedule", default="-")
    structural.add_argument("--bucket-count", type=int, required=True)
    structural.add_argument("--resource-classes", required=True)
    structural.add_argument("--output", type=Path, required=True)
    dependency = subparsers.add_parser("dependency")
    dependency.add_argument("--structural-schedule", type=Path, required=True)
    dependency.add_argument("--record-edges", type=Path, required=True)
    dependency.add_argument("--schedule", default="-")
    dependency.add_argument("--bucket-count", type=int, required=True)
    dependency.add_argument("--require-structural-coverage", choices=("0", "1"), required=True)
    dependency.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.command == "structural":
        prepare_structural_boundary_v3(
            inventory=arguments.inventory,
            output_directory=arguments.output,
            resource_classes=json.loads(arguments.resource_classes),
            schedule=_path_or_none(arguments.schedule),
            schedule_bucket_count=arguments.bucket_count,
        )
    else:
        prepare_dependency_boundary_v3(
            structural_schedule=arguments.structural_schedule,
            record_edges=arguments.record_edges,
            output_directory=arguments.output,
            schedule=_path_or_none(arguments.schedule),
            require_structural_coverage=arguments.require_structural_coverage == "1",
            schedule_bucket_count=arguments.bucket_count,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = [
    "BOUNDARY_SET_FORMAT_V3",
    "DEFAULT_RESOURCE_CLASSES_V3",
    "DEPENDENCY_PACK_INDEX_FORMAT_V3",
    "RECORD_EDGES_FORMAT_V3",
    "STRUCTURAL_INVENTORY_FORMAT_V3",
    "STRUCTURAL_PACK_INDEX_FORMAT_V3",
    "SchedulingBoundaryV3",
    "prepare_dependency_boundary_v3",
    "prepare_scheduling_boundaries_v3",
    "prepare_structural_boundary_v3",
]
