"""Conservative memory-version graph over exact transition summaries.

The graph retains concrete byte ranges and exact event bindings.  Its alias
partition exists only to reduce later certificate work; it is never proof that
two components are disjoint.  Symbolic addresses therefore remain explicit
frontiers, and unknown writes kill every component they may affect.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .address_expression_v2 import (
    affine_register_offset,
    affine_special_offset,
    constant_u32,
)
from .authority_bindings_v2 import (
    AuthorityDataError,
    BinaryBinding,
    CanonicalJson,
    EventBinding,
    UnitBinding,
    canonical_json_bytes,
)
from .machine_ir_authority_v2 import machine_ir_sha256
from .transition_summary_v2 import (
    TransitionMemoryAccessV2,
    TransitionSummaryV2,
    TransitionSummaryV2Error,
    check_transition_summary_v2,
    derive_transition_summary_v2,
)


MEMORY_VERSION_GRAPH_V2_FORMAT = "spaghetti-extractor-memory-version-graph-v2"
_ALIAS_POLICIES = frozenset({"fail_closed", "merge_all"})
_ADDRESS_CLASSES = frozenset({"concrete", "stack_frame", "tls", "unknown"})
_VERSION_KINDS = frozenset({"initial", "write", "unknown_write_kill"})


class MemoryVersionGraphV2Error(ValueError):
    """A memory graph or one of its exact dependencies is invalid."""


@dataclass(frozen=True, order=True)
class ConcreteByteRangeV2:
    range_id: str
    start: int
    end: int

    def __post_init__(self) -> None:
        _uint(self.start, "memory range start")
        _uint(self.end, "memory range end", maximum=1 << 32)
        if self.end <= self.start:
            raise AuthorityDataError("memory range is empty or reversed")
        _check_id(self.range_id, "memory-range", self.identity_payload())

    @property
    def size(self) -> int:
        return self.end - self.start

    def overlaps(self, other: "ConcreteByteRangeV2") -> bool:
        return self.start < other.end and other.start < self.end

    def identity_payload(self) -> dict[str, int]:
        return {"start": self.start, "end": self.end}

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.range_id, **self.identity_payload()}

    @classmethod
    def create(cls, start: int, end: int) -> "ConcreteByteRangeV2":
        identity = {"start": start, "end": end}
        return cls(_node_id("memory-range", identity), start, end)

    @classmethod
    def parse(cls, value: Any) -> "ConcreteByteRangeV2":
        row = _object(value, {"id", "start", "end"}, "concrete memory range")
        return cls(
            range_id=_text(row["id"], "memory range ID"),
            start=_uint(row["start"], "memory range start"),
            end=_uint(row["end"], "memory range end", maximum=1 << 32),
        )


@dataclass(frozen=True, order=True)
class MemoryAliasComponentV2:
    component_id: str
    ranges: tuple[ConcreteByteRangeV2, ...]
    access_ids: tuple[str, ...]
    address_class: str
    contains_unknown_address: bool

    def __post_init__(self) -> None:
        if self.address_class not in _ADDRESS_CLASSES:
            raise AuthorityDataError("alias component has an invalid address class")
        if not self.ranges and self.address_class == "concrete":
            raise AuthorityDataError("alias component has neither ranges nor unknown access")
        if self.address_class == "concrete" and self.contains_unknown_address:
            raise AuthorityDataError("concrete alias component is marked unknown")
        if self.address_class != "concrete" and not self.contains_unknown_address:
            raise AuthorityDataError("symbolic alias component is not marked unknown")
        if tuple(sorted(self.ranges, key=lambda row: (row.start, row.end))) != self.ranges:
            raise AuthorityDataError("alias-component ranges are not canonical")
        if tuple(sorted(set(self.access_ids))) != self.access_ids:
            raise AuthorityDataError("alias-component accesses are not sorted and unique")
        if not isinstance(self.contains_unknown_address, bool):
            raise AuthorityDataError("alias-component unknown marker must be Boolean")
        _check_id(self.component_id, "alias-component", self.subject_payload())

    def subject_payload(self) -> dict[str, Any]:
        return {
            "ranges": [row.to_payload() for row in self.ranges],
            "address_class": self.address_class,
            "contains_unknown_address": self.contains_unknown_address,
        }

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.component_id,
            **self.subject_payload(),
            "access_ids": list(self.access_ids),
        }

    @classmethod
    def create(
        cls,
        *,
        ranges: Sequence[ConcreteByteRangeV2],
        access_ids: Sequence[str],
        address_class: str,
        contains_unknown_address: bool,
    ) -> "MemoryAliasComponentV2":
        canonical_ranges = tuple(sorted(set(ranges), key=lambda row: (row.start, row.end)))
        subject = {
            "ranges": [row.to_payload() for row in canonical_ranges],
            "address_class": address_class,
            "contains_unknown_address": contains_unknown_address,
        }
        return cls(
            _node_id("alias-component", subject),
            canonical_ranges,
            tuple(sorted(set(access_ids))),
            address_class,
            contains_unknown_address,
        )

    @classmethod
    def parse(cls, value: Any) -> "MemoryAliasComponentV2":
        row = _object(
            value,
            {
                "id", "ranges", "access_ids", "address_class",
                "contains_unknown_address",
            },
            "memory alias component",
        )
        return cls(
            component_id=_text(row["id"], "alias component ID"),
            ranges=tuple(ConcreteByteRangeV2.parse(item) for item in _array(row["ranges"], "alias ranges")),
            access_ids=_string_tuple(row["access_ids"], "alias access IDs"),
            address_class=_text(row["address_class"], "alias address class"),
            contains_unknown_address=_boolean(row["contains_unknown_address"], "unknown-address marker"),
        )


@dataclass(frozen=True, order=True)
class MemoryVersionV2:
    version_id: str
    component_id: str
    kind: str
    defining_access_id: str | None
    predecessor_version_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.component_id, "memory-version component ID")
        if self.kind not in _VERSION_KINDS:
            raise AuthorityDataError("memory version has an invalid kind")
        if self.kind == "initial":
            if self.defining_access_id is not None or self.predecessor_version_ids:
                raise AuthorityDataError("initial memory version has predecessors or a write")
        else:
            _text(self.defining_access_id, "memory-version defining access ID")
            if len(self.predecessor_version_ids) != 1:
                raise AuthorityDataError("write memory version must have one local predecessor")
        if tuple(sorted(set(self.predecessor_version_ids))) != self.predecessor_version_ids:
            raise AuthorityDataError("memory-version predecessors are noncanonical")
        _check_id(self.version_id, "memory-version", self.subject_payload())

    def subject_payload(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "kind": self.kind,
            "defining_access_id": self.defining_access_id,
        }

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.version_id,
            **self.subject_payload(),
            "predecessor_version_ids": list(self.predecessor_version_ids),
        }

    @classmethod
    def create(
        cls,
        *,
        component_id: str,
        kind: str,
        defining_access_id: str | None,
        predecessor_version_ids: Sequence[str],
    ) -> "MemoryVersionV2":
        subject = {
            "component_id": component_id,
            "kind": kind,
            "defining_access_id": defining_access_id,
        }
        return cls(
            _node_id("memory-version", subject),
            component_id,
            kind,
            defining_access_id,
            tuple(sorted(set(predecessor_version_ids))),
        )

    @classmethod
    def parse(cls, value: Any) -> "MemoryVersionV2":
        row = _object(
            value,
            {"id", "component_id", "kind", "defining_access_id", "predecessor_version_ids"},
            "memory version",
        )
        defining = row["defining_access_id"]
        if defining is not None:
            defining = _text(defining, "memory-version defining access ID")
        return cls(
            version_id=_text(row["id"], "memory version ID"),
            component_id=_text(row["component_id"], "memory-version component ID"),
            kind=_text(row["kind"], "memory-version kind"),
            defining_access_id=defining,
            predecessor_version_ids=_string_tuple(row["predecessor_version_ids"], "memory-version predecessors"),
        )


@dataclass(frozen=True, order=True)
class MemoryMergeInputV2:
    predecessor_unit_id: str
    version_id: str

    def __post_init__(self) -> None:
        _text(self.predecessor_unit_id, "merge predecessor unit ID")
        _text(self.version_id, "merge predecessor version ID")

    def to_payload(self) -> dict[str, str]:
        return {
            "predecessor_unit_id": self.predecessor_unit_id,
            "version_id": self.version_id,
        }

    @classmethod
    def parse(cls, value: Any) -> "MemoryMergeInputV2":
        row = _object(value, {"predecessor_unit_id", "version_id"}, "memory merge input")
        return cls(
            predecessor_unit_id=_text(row["predecessor_unit_id"], "merge predecessor unit ID"),
            version_id=_text(row["version_id"], "merge predecessor version ID"),
        )


@dataclass(frozen=True, order=True)
class MemoryMergeV2:
    merge_id: str
    component_id: str
    cutpoint: UnitBinding
    incoming: tuple[MemoryMergeInputV2, ...]

    def __post_init__(self) -> None:
        _text(self.component_id, "memory-merge component ID")
        if not self.incoming:
            raise AuthorityDataError("memory merge has no incoming versions")
        if tuple(sorted(self.incoming, key=lambda row: row.predecessor_unit_id)) != self.incoming:
            raise AuthorityDataError("memory merge inputs are not canonical")
        if len({row.predecessor_unit_id for row in self.incoming}) != len(self.incoming):
            raise AuthorityDataError("memory merge repeats a predecessor")
        _check_id(self.merge_id, "memory-merge", self.subject_payload())

    def subject_payload(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "cutpoint": self.cutpoint.to_payload(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.merge_id,
            **self.subject_payload(),
            "incoming": [row.to_payload() for row in self.incoming],
        }

    @classmethod
    def create(
        cls,
        *,
        component_id: str,
        cutpoint: UnitBinding,
        incoming: Sequence[MemoryMergeInputV2],
    ) -> "MemoryMergeV2":
        subject = {"component_id": component_id, "cutpoint": cutpoint.to_payload()}
        return cls(
            _node_id("memory-merge", subject),
            component_id,
            cutpoint,
            tuple(sorted(incoming, key=lambda row: row.predecessor_unit_id)),
        )

    @classmethod
    def parse(cls, value: Any) -> "MemoryMergeV2":
        row = _object(value, {"id", "component_id", "cutpoint", "incoming"}, "memory merge")
        return cls(
            merge_id=_text(row["id"], "memory merge ID"),
            component_id=_text(row["component_id"], "memory-merge component ID"),
            cutpoint=UnitBinding.parse(row["cutpoint"]),
            incoming=tuple(MemoryMergeInputV2.parse(item) for item in _array(row["incoming"], "memory merge inputs")),
        )


@dataclass(frozen=True, order=True)
class UnknownWriteKillV2:
    kill_id: str
    access_id: str
    binding: EventBinding
    affected_scope: str
    affected_component_ids: tuple[str, ...]
    reason: str

    def __post_init__(self) -> None:
        _text(self.access_id, "unknown-write access ID")
        if self.affected_scope not in {"all_components", "finite_components"}:
            raise AuthorityDataError("unknown-write kill has an invalid affected scope")
        if tuple(sorted(set(self.affected_component_ids))) != self.affected_component_ids:
            raise AuthorityDataError("unknown-write components are not sorted and unique")
        if self.affected_scope == "all_components" and self.affected_component_ids:
            raise AuthorityDataError("all-components kill redundantly enumerates components")
        if self.affected_scope == "finite_components" and not self.affected_component_ids:
            raise AuthorityDataError("finite-components kill has an empty component set")
        _text(self.reason, "unknown-write reason")
        _check_id(self.kill_id, "unknown-write-kill", self.identity_payload())

    def identity_payload(self) -> dict[str, Any]:
        return {
            "access_id": self.access_id,
            "binding": self.binding.to_payload(),
            "affected_scope": self.affected_scope,
            "affected_component_ids": list(self.affected_component_ids),
            "reason": self.reason,
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.kill_id, **self.identity_payload()}

    @classmethod
    def create(
        cls,
        *,
        access_id: str,
        binding: EventBinding,
        affected_scope: str,
        affected_component_ids: Sequence[str] = (),
        reason: str,
    ) -> "UnknownWriteKillV2":
        identity = {
            "access_id": access_id,
            "binding": binding.to_payload(),
            "affected_scope": affected_scope,
            "affected_component_ids": list(sorted(set(affected_component_ids))),
            "reason": reason,
        }
        return cls(
            _node_id("unknown-write-kill", identity),
            access_id,
            binding,
            affected_scope,
            tuple(identity["affected_component_ids"]),
            reason,
        )

    @classmethod
    def parse(cls, value: Any) -> "UnknownWriteKillV2":
        row = _object(
            value,
            {
                "id", "access_id", "binding", "affected_scope",
                "affected_component_ids", "reason",
            },
            "unknown-write kill",
        )
        return cls(
            kill_id=_text(row["id"], "unknown-write kill ID"),
            access_id=_text(row["access_id"], "unknown-write access ID"),
            binding=EventBinding.parse(row["binding"]),
            affected_scope=_text(row["affected_scope"], "unknown-write affected scope"),
            affected_component_ids=_string_tuple(row["affected_component_ids"], "unknown-write components"),
            reason=_text(row["reason"], "unknown-write reason"),
        )


@dataclass(frozen=True, order=True)
class MemoryAccessVersionV2:
    link_id: str
    access_id: str
    component_id: str
    ranges: tuple[ConcreteByteRangeV2, ...]
    version_before: str
    version_after: str

    def __post_init__(self) -> None:
        _text(self.access_id, "memory-access link access ID")
        _text(self.component_id, "memory-access link component ID")
        if tuple(sorted(self.ranges, key=lambda row: (row.start, row.end))) != self.ranges:
            raise AuthorityDataError("memory-access link ranges are noncanonical")
        _text(self.version_before, "memory-access version before")
        _text(self.version_after, "memory-access version after")
        _check_id(self.link_id, "memory-access-version", self.identity_payload())

    def identity_payload(self) -> dict[str, Any]:
        return {
            "access_id": self.access_id,
            "component_id": self.component_id,
            "ranges": [row.to_payload() for row in self.ranges],
            "version_before": self.version_before,
            "version_after": self.version_after,
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.link_id, **self.identity_payload()}

    @classmethod
    def create(
        cls,
        *,
        access_id: str,
        component_id: str,
        ranges: Sequence[ConcreteByteRangeV2],
        version_before: str,
        version_after: str,
    ) -> "MemoryAccessVersionV2":
        canonical_ranges = tuple(sorted(set(ranges), key=lambda row: (row.start, row.end)))
        identity = {
            "access_id": access_id,
            "component_id": component_id,
            "ranges": [row.to_payload() for row in canonical_ranges],
            "version_before": version_before,
            "version_after": version_after,
        }
        return cls(
            _node_id("memory-access-version", identity),
            access_id,
            component_id,
            canonical_ranges,
            version_before,
            version_after,
        )

    @classmethod
    def parse(cls, value: Any) -> "MemoryAccessVersionV2":
        row = _object(
            value,
            {"id", "access_id", "component_id", "ranges", "version_before", "version_after"},
            "memory-access version link",
        )
        return cls(
            link_id=_text(row["id"], "memory-access version link ID"),
            access_id=_text(row["access_id"], "memory-access link access ID"),
            component_id=_text(row["component_id"], "memory-access link component ID"),
            ranges=tuple(ConcreteByteRangeV2.parse(item) for item in _array(row["ranges"], "memory-access ranges")),
            version_before=_text(row["version_before"], "memory-access version before"),
            version_after=_text(row["version_after"], "memory-access version after"),
        )


@dataclass(frozen=True, order=True)
class MemoryGraphIssueV2:
    issue_id: str
    status: str
    code: str
    subject_id: str
    detail: CanonicalJson

    def __post_init__(self) -> None:
        if self.status not in {"incomplete", "violated"}:
            raise AuthorityDataError("memory-graph issue has an invalid status")
        _text(self.code, "memory-graph issue code", maximum=128)
        _text(self.subject_id, "memory-graph issue subject")
        if not isinstance(self.detail, CanonicalJson):
            raise AuthorityDataError("memory-graph issue detail is not canonical JSON")
        _check_id(self.issue_id, "memory-graph-issue", self.identity_payload())

    def identity_payload(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "code": self.code,
            "subject_id": self.subject_id,
            "detail": self.detail.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.issue_id, **self.identity_payload()}

    @classmethod
    def create(cls, *, status: str, code: str, subject_id: str, detail: Any) -> "MemoryGraphIssueV2":
        canonical = CanonicalJson.of(detail)
        identity = {"status": status, "code": code, "subject_id": subject_id, "detail": canonical.to_value()}
        return cls(_node_id("memory-graph-issue", identity), status, code, subject_id, canonical)

    @classmethod
    def parse(cls, value: Any) -> "MemoryGraphIssueV2":
        row = _object(value, {"id", "status", "code", "subject_id", "detail"}, "memory-graph issue")
        return cls(
            issue_id=_text(row["id"], "memory-graph issue ID"),
            status=_text(row["status"], "memory-graph issue status"),
            code=_text(row["code"], "memory-graph issue code", maximum=128),
            subject_id=_text(row["subject_id"], "memory-graph issue subject"),
            detail=CanonicalJson.of(row["detail"]),
        )


@dataclass(frozen=True)
class MemoryVersionGraphV2:
    graph_id: str
    status: str
    binary: BinaryBinding
    transition_summary_ids: tuple[str, ...]
    alias_policy: str
    alias_components: tuple[MemoryAliasComponentV2, ...]
    versions: tuple[MemoryVersionV2, ...]
    merges: tuple[MemoryMergeV2, ...]
    access_versions: tuple[MemoryAccessVersionV2, ...]
    unknown_write_kills: tuple[UnknownWriteKillV2, ...]
    issues: tuple[MemoryGraphIssueV2, ...]

    def __post_init__(self) -> None:
        if self.status not in {"complete", "incomplete", "violated"}:
            raise AuthorityDataError("memory-version graph has an invalid status")
        if self.alias_policy not in _ALIAS_POLICIES:
            raise AuthorityDataError("memory-version graph has an invalid alias policy")
        if tuple(sorted(set(self.transition_summary_ids))) != self.transition_summary_ids:
            raise AuthorityDataError("transition-summary identities are noncanonical")
        for rows, attribute, context in (
            (self.alias_components, "component_id", "alias components"),
            (self.versions, "version_id", "memory versions"),
            (self.merges, "merge_id", "memory merges"),
            (self.access_versions, "link_id", "memory-access links"),
            (self.unknown_write_kills, "kill_id", "unknown-write kills"),
            (self.issues, "issue_id", "memory-graph issues"),
        ):
            _unique_ids(rows, attribute, context)
            if tuple(sorted(rows, key=lambda row: getattr(row, attribute))) != rows:
                raise AuthorityDataError(f"{context} are not canonically ordered")
        component_ids = {row.component_id for row in self.alias_components}
        _validate_disjoint_alias_components(self.alias_components)
        if any(row.component_id not in component_ids for row in self.versions):
            raise AuthorityDataError("memory version references an unknown alias component")
        if any(row.component_id not in component_ids for row in self.merges):
            raise AuthorityDataError("memory merge references an unknown alias component")
        version_ids = {row.version_id for row in self.versions} | {row.merge_id for row in self.merges}
        for row in self.versions:
            if any(value not in version_ids for value in row.predecessor_version_ids):
                raise AuthorityDataError("memory version references an unknown predecessor")
        for row in self.merges:
            if any(value.version_id not in version_ids for value in row.incoming):
                raise AuthorityDataError("memory merge references an unknown incoming version")
        if any(
            row.component_id not in component_ids
            or row.version_before not in version_ids
            or row.version_after not in version_ids
            for row in self.access_versions
        ):
            raise AuthorityDataError("memory-access link references an unknown graph node")
        if any(
            row.affected_scope == "finite_components"
            and any(component not in component_ids for component in row.affected_component_ids)
            for row in self.unknown_write_kills
        ):
            raise AuthorityDataError("unknown-write kill references an unknown alias component")
        if (self.status == "complete") != (not self.issues):
            raise AuthorityDataError("memory-version status does not match its issues")
        if self.status == "violated" and not any(row.status == "violated" for row in self.issues):
            raise AuthorityDataError("violated memory graph contains no violation")
        _check_id(self.graph_id, "memory-version-graph", self.identity_payload())

    def identity_payload(self) -> dict[str, Any]:
        return {
            "root_independent": True,
            "partition_authority": "optimization_only",
            "status": self.status,
            "binary": self.binary.to_payload(),
            "transition_summary_ids": list(self.transition_summary_ids),
            "alias_policy": self.alias_policy,
            "alias_components": [row.to_payload() for row in self.alias_components],
            "versions": [row.to_payload() for row in self.versions],
            "merges": [row.to_payload() for row in self.merges],
            "access_versions": [row.to_payload() for row in self.access_versions],
            "unknown_write_kills": [row.to_payload() for row in self.unknown_write_kills],
            "issues": [row.to_payload() for row in self.issues],
        }

    def to_payload(self) -> dict[str, Any]:
        return {"format": MEMORY_VERSION_GRAPH_V2_FORMAT, "id": self.graph_id, **self.identity_payload()}

    @classmethod
    def parse(cls, value: Any) -> "MemoryVersionGraphV2":
        row = _object(
            value,
            {
                "format", "id", "root_independent", "partition_authority", "status", "binary",
                "transition_summary_ids", "alias_policy", "alias_components", "versions", "merges",
                "access_versions", "unknown_write_kills", "issues",
            },
            "memory-version graph",
        )
        if (
            row["format"] != MEMORY_VERSION_GRAPH_V2_FORMAT
            or row["root_independent"] is not True
            or row["partition_authority"] != "optimization_only"
        ):
            raise AuthorityDataError("memory-version graph has invalid format or authority scope")
        return cls(
            graph_id=_text(row["id"], "memory-version graph ID"),
            status=_text(row["status"], "memory-version graph status"),
            binary=BinaryBinding.parse(row["binary"]),
            transition_summary_ids=_string_tuple(row["transition_summary_ids"], "transition-summary IDs"),
            alias_policy=_text(row["alias_policy"], "memory alias policy"),
            alias_components=tuple(MemoryAliasComponentV2.parse(item) for item in _array(row["alias_components"], "alias components")),
            versions=tuple(MemoryVersionV2.parse(item) for item in _array(row["versions"], "memory versions")),
            merges=tuple(MemoryMergeV2.parse(item) for item in _array(row["merges"], "memory merges")),
            access_versions=tuple(MemoryAccessVersionV2.parse(item) for item in _array(row["access_versions"], "memory-access links")),
            unknown_write_kills=tuple(UnknownWriteKillV2.parse(item) for item in _array(row["unknown_write_kills"], "unknown-write kills")),
            issues=tuple(MemoryGraphIssueV2.parse(item) for item in _array(row["issues"], "memory-graph issues")),
        )


def derive_memory_version_graph_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    binary: BinaryBinding,
    transition_summaries: Sequence[TransitionSummaryV2 | Mapping[str, Any]] | None = None,
    unknown_alias_policy: str = "fail_closed",
) -> MemoryVersionGraphV2:
    """Derive conservative versions and joins from exact structural units."""

    if unknown_alias_policy not in _ALIAS_POLICIES:
        raise MemoryVersionGraphV2Error("unknown alias policy must be fail_closed or merge_all")
    try:
        by_id = _unit_index(units)
        if binary.machine_ir_sha256 != machine_ir_sha256(units):
            raise MemoryVersionGraphV2Error(
                "binary binding does not match the exact machine-IR inventory"
            )
        summaries = _checked_summaries(
            units=units,
            binary=binary,
            submitted=transition_summaries,
        )
        accesses = tuple(
            access
            for summary in summaries
            for access in summary.memory_accesses
        )
        ranges_by_access = {
            access.access_id: _concrete_ranges(access)
            for access in accesses
        }
        address_class_by_access = {
            access.access_id: _address_class(access)
            for access in accesses
        }
        components = _alias_components(
            accesses,
            ranges_by_access=ranges_by_access,
            address_class_by_access=address_class_by_access,
            merge_unknown=(unknown_alias_policy == "merge_all"),
        )
        component_by_access_lists: dict[str, list[str]] = {
            access.access_id: [] for access in accesses
        }
        for component in components:
            for access_id in component.access_ids:
                component_by_access_lists[access_id].append(
                    component.component_id
                )
        component_by_access = {
            access_id: tuple(sorted(component_ids))
            for access_id, component_ids in component_by_access_lists.items()
        }
        predecessors, control_issues = _direct_predecessors(by_id, summaries)
        versions, merges, links, kills = _version_nodes(
            summaries=summaries,
            components=components,
            component_by_access=component_by_access,
            address_class_by_access=address_class_by_access,
            ranges_by_access=ranges_by_access,
            predecessors=predecessors,
        )
        issues = list(control_issues)
        for summary in summaries:
            if summary.status != "complete":
                issues.append(MemoryGraphIssueV2.create(
                    status="incomplete",
                    code="transition_summary_incomplete",
                    subject_id=summary.summary_id,
                    detail={
                        "unsupported_effect_ids": [
                            row.effect_id for row in summary.unsupported_effects
                        ],
                    },
                ))
            for exit_record in summary.exits:
                if exit_record.category not in {"call", "external", "callback"}:
                    continue
                issues.append(MemoryGraphIssueV2.create(
                    status="incomplete",
                    code="call_memory_effect_requires_checked_summary",
                    subject_id=exit_record.exit_id,
                    detail={
                        "category": exit_record.category,
                        "transfer_kind": exit_record.transfer_kind,
                    },
                ))
        for access in accesses:
            address_class = address_class_by_access[access.access_id]
            if address_class != "unknown":
                continue
            code = (
                "unknown_write_alias"
                if access.memory_kind in {"write", "read_write"}
                else "unknown_read_alias"
            )
            issues.append(MemoryGraphIssueV2.create(
                status="incomplete",
                code=code,
                subject_id=access.access_id,
                detail={
                    "policy": unknown_alias_policy,
                    "address_class": address_class,
                    "address": access.address.to_value(),
                    "affected_scope": "all_components",
                },
            ))
        issues = sorted({row.issue_id: row for row in issues}.values(), key=lambda row: row.issue_id)
        status = "violated" if any(row.status == "violated" for row in issues) else (
            "incomplete" if issues else "complete"
        )
        fields = {
            "status": status,
            "binary": binary,
            "transition_summary_ids": tuple(sorted(row.summary_id for row in summaries)),
            "alias_policy": unknown_alias_policy,
            "alias_components": tuple(sorted(components, key=lambda row: row.component_id)),
            "versions": tuple(sorted(versions, key=lambda row: row.version_id)),
            "merges": tuple(sorted(merges, key=lambda row: row.merge_id)),
            "access_versions": tuple(sorted(links, key=lambda row: row.link_id)),
            "unknown_write_kills": tuple(sorted(kills, key=lambda row: row.kill_id)),
            "issues": tuple(issues),
        }
        identity = _graph_identity_payload(**fields)
        return MemoryVersionGraphV2(
            graph_id=_node_id("memory-version-graph", identity),
            **fields,
        )
    except (AuthorityDataError, TransitionSummaryV2Error, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, MemoryVersionGraphV2Error):
            raise
        raise MemoryVersionGraphV2Error(f"cannot derive memory-version graph: {exc}") from exc


def check_memory_version_graph_v2(
    value: MemoryVersionGraphV2 | Mapping[str, Any],
    *,
    units: Sequence[Mapping[str, Any]],
    binary: BinaryBinding,
    transition_summaries: Sequence[TransitionSummaryV2 | Mapping[str, Any]] | None = None,
    unknown_alias_policy: str = "fail_closed",
) -> MemoryVersionGraphV2:
    """Rebuild the graph from exact units and reject stale partition data."""

    try:
        submitted = value if isinstance(value, MemoryVersionGraphV2) else MemoryVersionGraphV2.parse(value)
        expected = derive_memory_version_graph_v2(
            units=units,
            binary=binary,
            transition_summaries=transition_summaries,
            unknown_alias_policy=unknown_alias_policy,
        )
        if submitted != expected:
            raise MemoryVersionGraphV2Error(
                "memory-version graph contradicts exact transition summaries"
            )
        return submitted
    except AuthorityDataError as exc:
        raise MemoryVersionGraphV2Error(f"memory-version graph is malformed: {exc}") from exc


validate_memory_version_graph_v2 = check_memory_version_graph_v2


def _checked_summaries(
    *,
    units: Sequence[Mapping[str, Any]],
    binary: BinaryBinding,
    submitted: Sequence[TransitionSummaryV2 | Mapping[str, Any]] | None,
) -> tuple[TransitionSummaryV2, ...]:
    if submitted is None:
        return tuple(derive_transition_summary_v2(row, binary=binary) for row in units)
    parsed: dict[str, TransitionSummaryV2] = {}
    for raw in submitted:
        summary = raw if isinstance(raw, TransitionSummaryV2) else TransitionSummaryV2.parse(raw)
        if summary.unit.unit_id in parsed:
            raise MemoryVersionGraphV2Error("transition summaries duplicate a unit")
        parsed[summary.unit.unit_id] = summary
    expected_ids = {str(row.get("id")) for row in units}
    if set(parsed) != expected_ids:
        raise MemoryVersionGraphV2Error("transition summaries do not cover the exact unit inventory")
    return tuple(
        check_transition_summary_v2(parsed[str(row["id"])], unit_row=row, binary=binary)
        for row in units
    )


def _concrete_ranges(access: TransitionMemoryAccessV2) -> tuple[ConcreteByteRangeV2, ...]:
    address = constant_u32(access.address.to_value())
    if address is None or address + access.width_bytes > 1 << 32:
        return ()
    return (ConcreteByteRangeV2.create(address, address + access.width_bytes),)


def _address_class(access: TransitionMemoryAccessV2) -> str:
    address = access.address.to_value()
    if constant_u32(address) is not None:
        return "concrete"
    if affine_register_offset(address, "esp") is not None:
        return "stack_frame"
    if affine_special_offset(address, "fs_base") is not None:
        return "tls"
    return "unknown"


def _alias_components(
    accesses: Sequence[TransitionMemoryAccessV2],
    *,
    ranges_by_access: Mapping[str, tuple[ConcreteByteRangeV2, ...]],
    address_class_by_access: Mapping[str, str],
    merge_unknown: bool,
) -> tuple[MemoryAliasComponentV2, ...]:
    exact = [access for access in accesses if ranges_by_access[access.access_id]]
    ordered = sorted(
        exact,
        key=lambda access: (
            ranges_by_access[access.access_id][0].start,
            ranges_by_access[access.access_id][0].end,
            access.access_id,
        ),
    )
    groups: list[list[TransitionMemoryAccessV2]] = []
    current: list[TransitionMemoryAccessV2] = []
    current_end = -1
    for access in ordered:
        memory_range = ranges_by_access[access.access_id][0]
        if current and memory_range.start >= current_end:
            groups.append(current)
            current = []
            current_end = -1
        current.append(access)
        current_end = max(current_end, memory_range.end)
    if current:
        groups.append(current)
    symbolic = [access for access in accesses if not ranges_by_access[access.access_id]]
    if merge_unknown and symbolic:
        all_ranges = [item for access in exact for item in ranges_by_access[access.access_id]]
        return (MemoryAliasComponentV2.create(
            ranges=all_ranges,
            access_ids=[access.access_id for access in accesses],
            address_class="unknown",
            contains_unknown_address=True,
        ),)
    result = [
        MemoryAliasComponentV2.create(
            ranges=[item for access in rows for item in ranges_by_access[access.access_id]],
            access_ids=[access.access_id for access in rows],
            address_class="concrete",
            contains_unknown_address=False,
        )
        for rows in groups
    ]
    for address_class in ("stack_frame", "tls", "unknown"):
        rows = [
            access for access in symbolic
            if address_class_by_access[access.access_id] == address_class
        ]
        if rows:
            result.append(MemoryAliasComponentV2.create(
                ranges=(),
                access_ids=[access.access_id for access in rows],
                address_class=address_class,
                contains_unknown_address=True,
            ))
    return tuple(sorted(result, key=lambda row: row.component_id))


def _validate_disjoint_alias_components(
    components: Sequence[MemoryAliasComponentV2],
) -> None:
    """Reject an optimization partition that places overlapping bytes apart."""

    ranges = sorted(
        (
            memory_range.start,
            memory_range.end,
            component.component_id,
        )
        for component in components
        for memory_range in component.ranges
    )
    active_component: str | None = None
    active_end = -1
    for start, end, component_id in ranges:
        if start >= active_end:
            active_component = component_id
            active_end = end
            continue
        if component_id != active_component:
            raise AuthorityDataError(
                "distinct alias components contain overlapping concrete ranges"
            )
        active_end = max(active_end, end)


def _direct_predecessors(
    units: Mapping[str, Mapping[str, Any]],
    summaries: Sequence[TransitionSummaryV2],
) -> tuple[dict[str, tuple[str, ...]], tuple[MemoryGraphIssueV2, ...]]:
    by_start = {summary.unit.rva_start: summary.unit.unit_id for summary in summaries}
    if len(by_start) != len(summaries):
        raise MemoryVersionGraphV2Error(
            "machine-IR units contain duplicate structural entry RVAs"
        )
    predecessors: dict[str, set[str]] = {unit_id: set() for unit_id in units}
    issues: list[MemoryGraphIssueV2] = []
    for unit_id, row in units.items():
        control = row.get("control")
        targets = control.get("direct_targets") if isinstance(control, Mapping) else None
        if not isinstance(targets, list):
            issues.append(MemoryGraphIssueV2.create(
                status="violated",
                code="direct_control_inventory_missing",
                subject_id=unit_id,
                detail={},
            ))
            continue
        for target in targets:
            if not isinstance(target, int) or isinstance(target, bool) or target not in by_start:
                issues.append(MemoryGraphIssueV2.create(
                    status="incomplete",
                    code="direct_control_target_unbound",
                    subject_id=unit_id,
                    detail={"target_rva": target},
                ))
                continue
            predecessors[by_start[target]].add(unit_id)
    for summary in summaries:
        if any(row.transfer_kind in {"indirect_call", "indirect_jump"} for row in summary.exits):
            issues.append(MemoryGraphIssueV2.create(
                status="incomplete",
                code="indirect_control_requires_target_certificate",
                subject_id=summary.unit.unit_id,
                detail={},
            ))
    return (
        {unit_id: tuple(sorted(values)) for unit_id, values in predecessors.items()},
        tuple(issues),
    )


def _version_nodes(
    *,
    summaries: Sequence[TransitionSummaryV2],
    components: Sequence[MemoryAliasComponentV2],
    component_by_access: Mapping[str, tuple[str, ...]],
    address_class_by_access: Mapping[str, str],
    ranges_by_access: Mapping[str, tuple[ConcreteByteRangeV2, ...]],
    predecessors: Mapping[str, tuple[str, ...]],
) -> tuple[
    tuple[MemoryVersionV2, ...],
    tuple[MemoryMergeV2, ...],
    tuple[MemoryAccessVersionV2, ...],
    tuple[UnknownWriteKillV2, ...],
]:
    summary_by_unit = {row.unit.unit_id: row for row in summaries}
    initial = {
        component.component_id: MemoryVersionV2.create(
            component_id=component.component_id,
            kind="initial",
            defining_access_id=None,
            predecessor_version_ids=(),
        )
        for component in components
    }

    accesses_by_unit_component: dict[
        tuple[str, str], list[TransitionMemoryAccessV2]
    ] = {}
    for summary in summaries:
        for access in summary.memory_accesses:
            for component_id in component_by_access[access.access_id]:
                accesses_by_unit_component.setdefault(
                    (summary.unit.unit_id, component_id), []
                ).append(access)

    def writing_accesses(
        unit_id: str, component_id: str
    ) -> list[TransitionMemoryAccessV2]:
        return [
            access
            for access in accesses_by_unit_component.get(
                (unit_id, component_id), ()
            )
            if access.memory_kind in {"write", "read_write"}
        ]

    merge_by_key: dict[tuple[str, str], MemoryMergeV2] = {}
    entry_cache: dict[tuple[str, str], str] = {}
    visiting: set[tuple[str, str]] = set()
    forced_merge_keys: set[tuple[str, str]] = set()

    def merge_id(component_id: str, unit_id: str) -> str:
        return _node_id("memory-merge", {
            "component_id": component_id,
            "cutpoint": summary_by_unit[unit_id].unit.to_payload(),
        })

    def terminal_version_id(component_id: str, unit_id: str) -> str:
        writes = writing_accesses(unit_id, component_id)
        if writes:
            access = writes[-1]
            kind = (
                "write"
                if ranges_by_access[access.access_id]
                else "unknown_write_kill"
            )
            return _node_id("memory-version", {
                "component_id": component_id,
                "kind": kind,
                "defining_access_id": access.access_id,
            })
        return entry_version_id(component_id, unit_id)

    def entry_version_id(component_id: str, unit_id: str) -> str:
        key = (component_id, unit_id)
        cached = entry_cache.get(key)
        if cached is not None:
            return cached
        if key in visiting:
            # Represent a loop-carried value with a phi-style self reference.
            # The surrounding invocation constructs the merge and adds any
            # incoming versions from outside the cycle.
            forced_merge_keys.add(key)
            return merge_id(component_id, unit_id)
        visiting.add(key)
        incoming_units = predecessors[unit_id]
        if not incoming_units:
            result = initial[component_id].version_id
        else:
            incoming = tuple(
                MemoryMergeInputV2(
                    predecessor_unit_id=predecessor,
                    version_id=terminal_version_id(
                        component_id, predecessor
                    ),
                )
                for predecessor in incoming_units
            )
            if len(incoming) == 1 and key not in forced_merge_keys:
                result = incoming[0].version_id
            else:
                merge = MemoryMergeV2.create(
                    component_id=component_id,
                    cutpoint=summary_by_unit[unit_id].unit,
                    incoming=incoming,
                )
                merge_by_key[key] = merge
                result = merge.merge_id
        visiting.remove(key)
        entry_cache[key] = result
        return result

    versions: list[MemoryVersionV2] = list(initial.values())
    links: list[MemoryAccessVersionV2] = []
    kills: list[UnknownWriteKillV2] = []
    for (unit_id, component_id), unit_accesses in sorted(
        accesses_by_unit_component.items()
    ):
        current = entry_version_id(component_id, unit_id)
        for access in unit_accesses:
            before = current
            if access.memory_kind in {"write", "read_write"}:
                kind = "write" if ranges_by_access[access.access_id] else "unknown_write_kill"
                version = MemoryVersionV2.create(
                    component_id=component_id,
                    kind=kind,
                    defining_access_id=access.access_id,
                    predecessor_version_ids=(before,),
                )
                versions.append(version)
                current = version.version_id
                if kind == "unknown_write_kill":
                    address_class = address_class_by_access[access.access_id]
                    affected_scope = (
                        "all_components"
                        if address_class == "unknown"
                        else "finite_components"
                    )
                    kills.append(UnknownWriteKillV2.create(
                        access_id=access.access_id,
                        binding=access.binding,
                        affected_scope=affected_scope,
                        affected_component_ids=(
                            ()
                            if affected_scope == "all_components"
                            else component_by_access[access.access_id]
                        ),
                        reason="address expression has no exact concrete byte range",
                    ))
            links.append(MemoryAccessVersionV2.create(
                access_id=access.access_id,
                component_id=component_id,
                ranges=ranges_by_access[access.access_id],
                version_before=before,
                version_after=current,
            ))
    return (
        tuple({row.version_id: row for row in versions}.values()),
        tuple(merge_by_key.values()),
        tuple({row.link_id: row for row in links}.values()),
        tuple({row.kill_id: row for row in kills}.values()),
    )


def _unit_index(units: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for row in units:
        if not isinstance(row, Mapping):
            raise MemoryVersionGraphV2Error("machine-IR unit inventory contains a non-object")
        unit_id = _text(row.get("id"), "machine-IR unit ID")
        if unit_id in result:
            raise MemoryVersionGraphV2Error("machine-IR unit IDs are duplicated")
        result[unit_id] = row
    return result


def _graph_identity_payload(**fields: Any) -> dict[str, Any]:
    return {
        "root_independent": True,
        "partition_authority": "optimization_only",
        "status": fields["status"],
        "binary": fields["binary"].to_payload(),
        "transition_summary_ids": list(fields["transition_summary_ids"]),
        "alias_policy": fields["alias_policy"],
        "alias_components": [row.to_payload() for row in fields["alias_components"]],
        "versions": [row.to_payload() for row in fields["versions"]],
        "merges": [row.to_payload() for row in fields["merges"]],
        "access_versions": [row.to_payload() for row in fields["access_versions"]],
        "unknown_write_kills": [row.to_payload() for row in fields["unknown_write_kills"]],
        "issues": [row.to_payload() for row in fields["issues"]],
    }


def _node_id(prefix: str, payload: Any) -> str:
    return f"{prefix}:{hashlib.sha256(canonical_json_bytes(payload)).hexdigest()[:24]}"


def _check_id(value: str, prefix: str, payload: Any) -> None:
    if value != _node_id(prefix, payload):
        raise AuthorityDataError(f"{prefix} ID is stale")


def _text(value: Any, context: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise AuthorityDataError(f"{context} must be bounded nonempty text")
    return value


def _uint(value: Any, context: str, *, maximum: int = 0xFFFFFFFF) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        raise AuthorityDataError(f"{context} must be an unsigned integer")
    return value


def _boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise AuthorityDataError(f"{context} must be Boolean")
    return value


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise AuthorityDataError(f"{context} must be an object with string keys")
    return value


def _object(value: Any, fields: set[str], context: str) -> Mapping[str, Any]:
    row = _mapping(value, context)
    if set(row) != fields:
        raise AuthorityDataError(f"{context} has noncanonical fields")
    return row


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise AuthorityDataError(f"{context} must be an array")
    return value


def _string_tuple(value: Any, context: str) -> tuple[str, ...]:
    rows = tuple(_text(item, context) for item in _array(value, context))
    if tuple(sorted(set(rows))) != rows:
        raise AuthorityDataError(f"{context} must be sorted and unique")
    return rows


def _unique_ids(rows: Sequence[Any], attribute: str, context: str) -> None:
    values = [getattr(row, attribute) for row in rows]
    if len(values) != len(set(values)):
        raise AuthorityDataError(f"{context} contain duplicate identities")


__all__ = [
    "MEMORY_VERSION_GRAPH_V2_FORMAT",
    "ConcreteByteRangeV2",
    "MemoryAccessVersionV2",
    "MemoryAliasComponentV2",
    "MemoryGraphIssueV2",
    "MemoryMergeInputV2",
    "MemoryMergeV2",
    "MemoryVersionGraphV2",
    "MemoryVersionGraphV2Error",
    "MemoryVersionV2",
    "UnknownWriteKillV2",
    "check_memory_version_graph_v2",
    "derive_memory_version_graph_v2",
    "validate_memory_version_graph_v2",
]
