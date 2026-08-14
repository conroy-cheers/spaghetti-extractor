"""Structural and dependency scheduling certificates."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .artifact_set import (
    DEPENDENCY_SCHEDULE_V3_FORMAT,
    MAX_DEPENDENCY_SCHEDULE_BYTES,
    MAX_STRUCTURAL_SCHEDULE_BYTES,
    SCHEMA_VERSION,
    STRUCTURAL_SCHEDULE_V3_FORMAT,
    JsonValue,
    RecordDependencyV3,
    _RESOURCE_CLASSES,
    _canonical_tuple,
    _digest,
    _fail,
    _strict_object,
    _strict_sequence,
    _text,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
    identity_bucket_v3,
    parse_canonical_json_v3,
)

@dataclass(frozen=True, order=True)
class StructuralUnitPlanV3:
    unit_id: str
    start: int
    end: int
    dependencies: tuple[str, ...] = ()
    resource_class: str = "small"
    bucket: int = -1

    def __post_init__(self) -> None:
        _text(self.unit_id, "structural unit ID")
        if self.start < 0 or self.end <= self.start:
            _fail("invalid_unit_span", f"unit {self.unit_id!r} has an invalid span", "bind the exact nonempty structural span")
        if self.dependencies != _canonical_tuple(self.dependencies, "structural dependencies"):
            _fail("noncanonical_dependencies", f"unit {self.unit_id!r} dependencies are noncanonical", "sort and deduplicate direct dependencies")
        if self.resource_class not in _RESOURCE_CLASSES:
            _fail("invalid_resource_class", f"unit {self.unit_id!r} has resource class {self.resource_class!r}", "use small, medium, large, or oracle")
        if self.bucket != identity_bucket_v3(self.unit_id):
            _fail("wrong_unit_bucket", f"unit {self.unit_id!r} has a stale bucket", "construct it with StructuralUnitPlanV3.create")

    @classmethod
    def create(cls, unit_id: str, start: int, end: int, *, dependencies: Iterable[str] = (), resource_class: str = "small") -> "StructuralUnitPlanV3":
        return cls(unit_id, start, end, _canonical_tuple(sorted(set(dependencies)), "structural dependencies"), resource_class, identity_bucket_v3(unit_id))

    def to_payload(self) -> dict[str, JsonValue]:
        return {"unit_id": self.unit_id, "start": self.start, "end": self.end, "dependencies": list(self.dependencies), "resource_class": self.resource_class, "bucket": self.bucket}

    @classmethod
    def parse(cls, value: Any) -> "StructuralUnitPlanV3":
        row = _strict_object(value, {"unit_id", "start", "end", "dependencies", "resource_class", "bucket"}, "structural unit plan")
        return cls(str(row["unit_id"]), int(row["start"]), int(row["end"]), tuple(str(item) for item in _strict_sequence(row["dependencies"], "structural dependencies")), str(row["resource_class"]), int(row["bucket"]))


@dataclass(frozen=True)
class StructuralSchedulingManifestV3:
    universe_sha256: str
    units: tuple[StructuralUnitPlanV3, ...]
    plan_id: str

    def __post_init__(self) -> None:
        _digest(self.universe_sha256, "structural universe SHA-256")
        if self.units != tuple(sorted(self.units, key=lambda row: row.unit_id)) or len({row.unit_id for row in self.units}) != len(self.units):
            _fail("noncanonical_structural_plan", "structural units are duplicated or unsorted", "construct the plan with StructuralSchedulingManifestV3.create")
        known = {row.unit_id for row in self.units}
        unknown = sorted({dependency for row in self.units for dependency in row.dependencies} - known)
        if unknown:
            _fail("unknown_structural_dependency", f"structural plan refers to unknown units {unknown!r}", "include every structurally discovered unit before scheduling")
        expected = "structural-plan-v3:" + canonical_sha256_v3(self.identity_payload())
        if self.plan_id != expected:
            _fail("stale_plan_id", "structural plan ID is stale", "regenerate the scheduling manifest")

    def identity_payload(self) -> dict[str, JsonValue]:
        return {"format": STRUCTURAL_SCHEDULE_V3_FORMAT, "schema_version": SCHEMA_VERSION, "universe_sha256": self.universe_sha256, "units": [row.to_payload() for row in self.units]}

    def to_payload(self) -> dict[str, JsonValue]:
        return {**self.identity_payload(), "plan_id": self.plan_id}

    def to_bytes(self) -> bytes:
        data = canonical_json_bytes_v3(self.to_payload())
        if len(data) > MAX_STRUCTURAL_SCHEDULE_BYTES:
            _fail("oversized_structural_plan", f"structural scheduling manifest is {len(data)} bytes", "move semantic data into artifact packs and keep only spans, edges, buckets, and resource hints in the plan")
        return data

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def create(cls, universe_sha256: str, units: Iterable[StructuralUnitPlanV3]) -> "StructuralSchedulingManifestV3":
        ordered = tuple(sorted(units, key=lambda row: row.unit_id))
        payload = {"format": STRUCTURAL_SCHEDULE_V3_FORMAT, "schema_version": SCHEMA_VERSION, "universe_sha256": universe_sha256, "units": [row.to_payload() for row in ordered]}
        return cls(universe_sha256, ordered, "structural-plan-v3:" + canonical_sha256_v3(payload))

    @classmethod
    def parse_bytes(cls, data: bytes, *, location: str = "structural-schedule.json") -> "StructuralSchedulingManifestV3":
        if len(data) > MAX_STRUCTURAL_SCHEDULE_BYTES:
            _fail("oversized_structural_plan", f"structural plan is {len(data)} bytes", "regenerate a compact scheduling-only plan", location=location)
        row = _strict_object(parse_canonical_json_v3(data, location=location), {"format", "schema_version", "universe_sha256", "units", "plan_id"}, "structural scheduling manifest")
        if row["format"] != STRUCTURAL_SCHEDULE_V3_FORMAT or row["schema_version"] != SCHEMA_VERSION:
            _fail("wrong_schedule_format", "document is not a structural-schedule-v3 manifest", "use the matching v3 planner", location=location)
        return cls(str(row["universe_sha256"]), tuple(StructuralUnitPlanV3.parse(item) for item in _strict_sequence(row["units"], "structural units")), str(row["plan_id"]))

    def validate(self, expected: Mapping[str, tuple[int, int, Iterable[str]]]) -> None:
        submitted = {row.unit_id: (row.start, row.end, tuple(row.dependencies)) for row in self.units}
        canonical = {unit_id: (start, end, tuple(sorted(set(dependencies)))) for unit_id, (start, end, dependencies) in expected.items()}
        if submitted != canonical:
            _fail("planner_omission", "structural schedule does not exactly cover independently derived spans and edges", "regenerate it from the checked structural universe")


@dataclass(frozen=True, order=True)
class DependencyNodePlanV3:
    node_id: str
    dependencies: tuple[str, ...]
    records: tuple[RecordDependencyV3, ...]

    def __post_init__(self) -> None:
        _text(self.node_id, "dependency node ID")
        if self.dependencies != _canonical_tuple(self.dependencies, "node dependencies"):
            _fail("noncanonical_dependencies", f"node {self.node_id!r} dependencies are noncanonical", "sort and deduplicate node dependencies")
        if self.records != tuple(sorted(set(self.records))):
            _fail("noncanonical_record_dependencies", f"node {self.node_id!r} record references are noncanonical", "sort and deduplicate record references")

    @classmethod
    def create(cls, node_id: str, *, dependencies: Iterable[str] = (), records: Iterable[RecordDependencyV3] = ()) -> "DependencyNodePlanV3":
        return cls(node_id, _canonical_tuple(sorted(set(dependencies)), "node dependencies"), tuple(sorted(set(records))))

    def to_payload(self) -> dict[str, JsonValue]:
        return {"node_id": self.node_id, "dependencies": list(self.dependencies), "records": [row.to_payload() for row in self.records]}

    @classmethod
    def parse(cls, value: Any) -> "DependencyNodePlanV3":
        row = _strict_object(value, {"node_id", "dependencies", "records"}, "dependency node plan")
        return cls(str(row["node_id"]), tuple(str(item) for item in _strict_sequence(row["dependencies"], "node dependencies")), tuple(RecordDependencyV3.parse(item) for item in _strict_sequence(row["records"], "node record references")))


@dataclass(frozen=True, order=True)
class DependencySccPlanV3:
    scc_id: str
    members: tuple[str, ...]
    dependencies: tuple[str, ...]
    resource_class: str = "small"

    def __post_init__(self) -> None:
        _text(self.scc_id, "SCC ID")
        if self.members != _canonical_tuple(self.members, "SCC members") or not self.members:
            _fail("invalid_scc_members", f"SCC {self.scc_id!r} has noncanonical members", "derive SCCs with DependencySchedulingManifestV3.create")
        if self.dependencies != _canonical_tuple(self.dependencies, "SCC dependencies"):
            _fail("invalid_scc_dependencies", f"SCC {self.scc_id!r} dependencies are noncanonical", "derive SCC dependencies from node edges")
        if self.resource_class not in _RESOURCE_CLASSES:
            _fail("invalid_resource_class", f"SCC {self.scc_id!r} has invalid resource class", "use small, medium, large, or oracle")
        expected = "scc-v3:" + canonical_sha256_v3(list(self.members))[:24]
        if self.scc_id != expected:
            _fail("stale_scc_id", f"SCC ID {self.scc_id!r} is stale", "derive it from the canonical member inventory")

    def to_payload(self) -> dict[str, JsonValue]:
        return {"scc_id": self.scc_id, "members": list(self.members), "dependencies": list(self.dependencies), "resource_class": self.resource_class}

    @classmethod
    def parse(cls, value: Any) -> "DependencySccPlanV3":
        row = _strict_object(value, {"scc_id", "members", "dependencies", "resource_class"}, "dependency SCC plan")
        return cls(str(row["scc_id"]), tuple(str(item) for item in _strict_sequence(row["members"], "SCC members")), tuple(str(item) for item in _strict_sequence(row["dependencies"], "SCC dependencies")), str(row["resource_class"]))


def _strongly_connected_components(nodes: Mapping[str, tuple[str, ...]]) -> tuple[tuple[str, ...], ...]:
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    result: list[tuple[str, ...]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for target in nodes[node]:
            if target not in indices:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])
        if lowlinks[node] == indices[node]:
            members: list[str] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                members.append(member)
                if member == node:
                    break
            result.append(tuple(sorted(members)))

    for node in sorted(nodes):
        if node not in indices:
            visit(node)
    return tuple(sorted(result))


@dataclass(frozen=True)
class DependencySchedulingManifestV3:
    structural_plan_sha256: str
    nodes: tuple[DependencyNodePlanV3, ...]
    sccs: tuple[DependencySccPlanV3, ...]
    plan_id: str

    def __post_init__(self) -> None:
        _digest(self.structural_plan_sha256, "structural plan SHA-256")
        if self.nodes != tuple(sorted(self.nodes, key=lambda row: row.node_id)) or len({row.node_id for row in self.nodes}) != len(self.nodes):
            _fail("noncanonical_dependency_plan", "dependency nodes are duplicated or unsorted", "construct the plan with DependencySchedulingManifestV3.create")
        node_map = {row.node_id: row.dependencies for row in self.nodes}
        unknown = sorted({target for edges in node_map.values() for target in edges} - set(node_map))
        if unknown:
            _fail("unknown_dependency_node", f"dependency graph refers to unknown nodes {unknown!r}", "include every dependency node before SCC decomposition")
        expected_members = _strongly_connected_components(node_map)
        if tuple(row.members for row in self.sccs) != expected_members:
            _fail("incorrect_scc_partition", "submitted SCCs are not the exact graph decomposition", "derive SCCs with DependencySchedulingManifestV3.create")
        owner = {member: row.scc_id for row in self.sccs for member in row.members}
        expected_scc_dependencies = {
            row.scc_id: tuple(sorted({owner[target] for member in row.members for target in node_map[member] if owner[target] != row.scc_id}))
            for row in self.sccs
        }
        if any(row.dependencies != expected_scc_dependencies[row.scc_id] for row in self.sccs):
            _fail("incorrect_scc_dependencies", "SCC dependency edges do not match the node graph", "derive condensation edges with DependencySchedulingManifestV3.create")
        expected = "dependency-plan-v3:" + canonical_sha256_v3(self.identity_payload())
        if self.plan_id != expected:
            _fail("stale_plan_id", "dependency plan ID is stale", "regenerate the scheduling manifest")

    def identity_payload(self) -> dict[str, JsonValue]:
        return {"format": DEPENDENCY_SCHEDULE_V3_FORMAT, "schema_version": SCHEMA_VERSION, "structural_plan_sha256": self.structural_plan_sha256, "nodes": [row.to_payload() for row in self.nodes], "sccs": [row.to_payload() for row in self.sccs]}

    def to_payload(self) -> dict[str, JsonValue]:
        return {**self.identity_payload(), "plan_id": self.plan_id}

    def to_bytes(self) -> bytes:
        data = canonical_json_bytes_v3(self.to_payload())
        if len(data) > MAX_DEPENDENCY_SCHEDULE_BYTES:
            _fail("oversized_dependency_plan", f"dependency scheduling manifest is {len(data)} bytes", "move semantic facts into packs and keep only nodes, edges, record references, SCCs, and resource hints in the plan")
        return data

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def create(
        cls,
        structural_plan_sha256: str,
        nodes: Iterable[DependencyNodePlanV3],
        *,
        resource_class: Callable[[tuple[str, ...]], str] | None = None,
    ) -> "DependencySchedulingManifestV3":
        ordered_nodes = tuple(sorted(nodes, key=lambda row: row.node_id))
        node_map = {row.node_id: row.dependencies for row in ordered_nodes}
        if len(node_map) != len(ordered_nodes):
            _fail("duplicate_dependency_node", "dependency plan repeats a node", "emit each dependency node exactly once")
        unknown = sorted(
            {target for edges in node_map.values() for target in edges}
            - set(node_map)
        )
        if unknown:
            _fail(
                "unknown_dependency_node",
                f"dependency graph refers to unknown nodes {unknown!r}",
                "include every dependency node before SCC decomposition",
            )
        components = _strongly_connected_components(node_map)
        ids = {members: "scc-v3:" + canonical_sha256_v3(list(members))[:24] for members in components}
        owner = {member: ids[members] for members in components for member in members}
        sccs = tuple(
            DependencySccPlanV3(
                scc_id=ids[members],
                members=members,
                dependencies=tuple(sorted({owner[target] for member in members for target in node_map[member] if owner[target] != ids[members]})),
                resource_class="small" if resource_class is None else resource_class(members),
            )
            for members in components
        )
        payload = {"format": DEPENDENCY_SCHEDULE_V3_FORMAT, "schema_version": SCHEMA_VERSION, "structural_plan_sha256": structural_plan_sha256, "nodes": [row.to_payload() for row in ordered_nodes], "sccs": [row.to_payload() for row in sccs]}
        return cls(structural_plan_sha256, ordered_nodes, sccs, "dependency-plan-v3:" + canonical_sha256_v3(payload))

    @classmethod
    def parse_bytes(cls, data: bytes, *, location: str = "dependency-schedule.json") -> "DependencySchedulingManifestV3":
        if len(data) > MAX_DEPENDENCY_SCHEDULE_BYTES:
            _fail("oversized_dependency_plan", f"dependency plan is {len(data)} bytes", "regenerate a compact scheduling-only plan", location=location)
        row = _strict_object(parse_canonical_json_v3(data, location=location), {"format", "schema_version", "structural_plan_sha256", "nodes", "sccs", "plan_id"}, "dependency scheduling manifest")
        if row["format"] != DEPENDENCY_SCHEDULE_V3_FORMAT or row["schema_version"] != SCHEMA_VERSION:
            _fail("wrong_schedule_format", "document is not a dependency-schedule-v3 manifest", "use the matching v3 planner", location=location)
        return cls(str(row["structural_plan_sha256"]), tuple(DependencyNodePlanV3.parse(item) for item in _strict_sequence(row["nodes"], "dependency nodes")), tuple(DependencySccPlanV3.parse(item) for item in _strict_sequence(row["sccs"], "dependency SCCs")), str(row["plan_id"]))

    def validate(
        self,
        expected_dependencies: Mapping[str, Iterable[str]],
        *,
        expected_records: Mapping[str, Iterable[RecordDependencyV3]] | None = None,
    ) -> None:
        submitted = {row.node_id: row.dependencies for row in self.nodes}
        expected = {node: tuple(sorted(set(edges))) for node, edges in expected_dependencies.items()}
        if submitted != expected:
            _fail("planner_omission", "dependency schedule does not exactly cover independently derived nodes and edges", "regenerate it from checked transition and alias dependencies")
        if expected_records is not None:
            observed_records = {row.node_id: row.records for row in self.nodes}
            canonical_records = {node: tuple(sorted(set(records))) for node, records in expected_records.items()}
            if observed_records != canonical_records:
                _fail("planner_omission", "dependency schedule record bindings are incomplete or unexpected", "regenerate record references from exact phase dependencies")


__all__ = [
    "ARTIFACT_BUNDLE_V3_FORMAT",
    "ARTIFACT_PACK_V3_FORMAT",
    "ARTIFACT_SET_V3_FORMAT",
    "DEPENDENCY_SCHEDULE_V3_FORMAT",
    "IDENTITY_BUCKETS",
    "MAX_ARTIFACT_MANIFEST_BYTES",
    "MAX_DEPENDENCY_SCHEDULE_BYTES",
    "MAX_PACK_BYTES",
    "MAX_STRUCTURAL_SCHEDULE_BYTES",
    "ArtifactBundleManifestV3",
    "ArtifactBundleMemberV3",
    "ArtifactBundleReaderV3",
    "ArtifactInputManifestV3",
    "ArtifactInputReaderV3",
    "ArtifactBindingV3",
    "ArtifactDependencyV3",
    "ArtifactPackV3",
    "ArtifactRecordV3",
    "ArtifactSetManifestV3",
    "ArtifactSetReaderV3",
    "ArtifactSetWriterV3",
    "ArtifactV3Error",
    "CanonicalValueV3",
    "DependencyNodePlanV3",
    "DependencySccPlanV3",
    "DependencySchedulingManifestV3",
    "InternedExpressionV3",
    "EncodedValueV3",
    "RecursiveJsonCodecV3",
    "RecordDependencyV3",
    "StructuralSchedulingManifestV3",
    "StructuralUnitPlanV3",
    "canonical_json_bytes_v3",
    "canonical_sha256_v3",
    "check_artifact_set_v3",
    "identity_bucket_v3",
    "open_artifact_reader_v3",
    "parse_canonical_json_v3",
    "value_codec_v3",
    "write_artifact_bundle_v3",
]
