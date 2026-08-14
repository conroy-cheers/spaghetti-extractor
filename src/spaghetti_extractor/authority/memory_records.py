"""Native typed records for SCC-local memory-version authority."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from ..artifact_set_v3 import CanonicalValueV3, canonical_json_bytes_v3
from ..phase_framework_v3 import RecordCodecV3
from ._schema import (
    boolean,
    canonical_strings,
    digest,
    fail,
    sequence,
    strict_object,
    text,
    uint,
)
from .transition_records import (
    TransitionBinaryBindingV3,
    TransitionEventBindingV3,
    TransitionUnitBindingV3,
)


MEMORY_VERSION_RECORD_V3_SCHEMA = "spaghetti-extractor-memory-version-record-v3"
MEMORY_VERSIONS_ARTIFACT_KIND_V3 = "memory-versions-v3"

_ALIAS_POLICIES = frozenset({"fail_closed", "merge_all"})
_ADDRESS_CLASSES = frozenset({"concrete", "stack_frame", "tls", "unknown"})
_VERSION_KINDS = frozenset({"initial", "write", "unknown_write_kill"})


def _node_id(prefix: str, payload: Any) -> str:
    return f"{prefix}:{hashlib.sha256(canonical_json_bytes_v3(payload)).hexdigest()[:24]}"


def _require_id(value: str, prefix: str, payload: Any, context: str) -> None:
    expected = _node_id(prefix, payload)
    if value != expected:
        fail(
            "stale_record_id",
            f"{context} ID {value!r} does not bind its payload",
            f"recreate it as {expected!r}",
        )


def _parse_unit_binding(value: Any) -> TransitionUnitBindingV3:
    row = strict_object(
        value,
        {
            "kind",
            "binary",
            "unit_id",
            "rva_start",
            "rva_end",
            "unit_sha256",
            "instruction_bytes_sha256",
        },
        "memory cutpoint binding",
    )
    if row["kind"] != "unit":
        fail(
            "record_schema_mismatch",
            "memory cutpoint does not use a unit binding",
            "bind the merge to its exact transition unit",
        )
    binary = strict_object(
        row["binary"], {"pe_sha256", "machine_ir_sha256"}, "memory binary binding"
    )
    return TransitionUnitBindingV3(
        TransitionBinaryBindingV3(
            digest(binary["pe_sha256"], "memory PE SHA-256"),
            digest(binary["machine_ir_sha256"], "memory unit-IR SHA-256"),
        ),
        text(row["unit_id"], "memory unit ID", maximum=256),
        uint(row["rva_start"], "memory unit start RVA"),
        uint(row["rva_end"], "memory unit end RVA"),
        digest(row["unit_sha256"], "memory unit SHA-256"),
        digest(
            row["instruction_bytes_sha256"], "memory instruction-bytes SHA-256"
        ),
    )


@dataclass(frozen=True, order=True)
class ConcreteByteRangeV3:
    range_id: str
    start: int
    end: int

    def __post_init__(self) -> None:
        uint(self.start, "memory range start")
        uint(self.end, "memory range end", maximum=1 << 32)
        if self.end <= self.start:
            fail(
                "record_schema_mismatch",
                "memory range is empty or reversed",
                "emit a nonempty half-open byte range",
            )
        _require_id(self.range_id, "memory-range", self.identity_payload(), "memory range")

    def identity_payload(self) -> dict[str, int]:
        return {"start": self.start, "end": self.end}

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.range_id, **self.identity_payload()}

    @classmethod
    def create(cls, start: int, end: int) -> "ConcreteByteRangeV3":
        payload = {"start": start, "end": end}
        return cls(_node_id("memory-range", payload), start, end)

    @classmethod
    def parse(cls, value: Any) -> "ConcreteByteRangeV3":
        row = strict_object(value, {"id", "start", "end"}, "concrete memory range")
        return cls(
            text(row["id"], "memory range ID"),
            uint(row["start"], "memory range start"),
            uint(row["end"], "memory range end", maximum=1 << 32),
        )


@dataclass(frozen=True, order=True)
class MemoryAliasComponentV3:
    component_id: str
    ranges: tuple[ConcreteByteRangeV3, ...]
    access_ids: tuple[str, ...]
    address_class: str
    contains_unknown_address: bool

    def __post_init__(self) -> None:
        if self.address_class not in _ADDRESS_CLASSES:
            fail(
                "record_schema_mismatch",
                f"invalid memory address class {self.address_class!r}",
                "use concrete, stack_frame, tls, or unknown",
            )
        if not self.ranges and self.address_class == "concrete":
            fail(
                "record_schema_mismatch",
                "concrete alias component has no byte range",
                "include every exact range assigned to the component",
            )
        if (self.address_class == "concrete") == self.contains_unknown_address:
            fail(
                "record_schema_mismatch",
                "alias component address class contradicts its unknown marker",
                "mark only symbolic components as containing unknown addresses",
            )
        if self.ranges != tuple(sorted(set(self.ranges), key=lambda row: (row.start, row.end))):
            fail(
                "noncanonical_record_order",
                "alias-component ranges are not sorted and unique",
                "sort and deduplicate ranges by start and end",
            )
        if self.access_ids != tuple(sorted(set(self.access_ids))):
            fail(
                "noncanonical_record_order",
                "alias-component accesses are not sorted and unique",
                "sort and deduplicate access IDs",
            )
        _require_id(
            self.component_id,
            "alias-component",
            self.subject_payload(),
            "alias component",
        )

    def subject_payload(self) -> dict[str, Any]:
        return {
            "ranges": [row.to_payload() for row in self.ranges],
            "address_class": self.address_class,
            "contains_unknown_address": self.contains_unknown_address,
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.component_id, **self.subject_payload(), "access_ids": list(self.access_ids)}

    @classmethod
    def create(
        cls,
        *,
        ranges: tuple[ConcreteByteRangeV3, ...],
        access_ids: tuple[str, ...],
        address_class: str,
        contains_unknown_address: bool,
    ) -> "MemoryAliasComponentV3":
        canonical_ranges = tuple(sorted(set(ranges), key=lambda row: (row.start, row.end)))
        payload = {
            "ranges": [row.to_payload() for row in canonical_ranges],
            "address_class": address_class,
            "contains_unknown_address": contains_unknown_address,
        }
        return cls(
            _node_id("alias-component", payload),
            canonical_ranges,
            tuple(sorted(set(access_ids))),
            address_class,
            contains_unknown_address,
        )

    @classmethod
    def parse(cls, value: Any) -> "MemoryAliasComponentV3":
        row = strict_object(
            value,
            {"id", "ranges", "access_ids", "address_class", "contains_unknown_address"},
            "memory alias component",
        )
        return cls(
            text(row["id"], "alias component ID"),
            tuple(ConcreteByteRangeV3.parse(item) for item in sequence(row["ranges"], "alias ranges")),
            canonical_strings(row["access_ids"], "alias access IDs"),
            text(row["address_class"], "alias address class"),
            boolean(row["contains_unknown_address"], "alias unknown marker"),
        )


@dataclass(frozen=True, order=True)
class MemoryVersionV3:
    version_id: str
    component_id: str
    kind: str
    defining_access_id: str | None
    predecessor_version_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        text(self.component_id, "memory-version component ID")
        if self.kind not in _VERSION_KINDS:
            fail(
                "record_schema_mismatch",
                f"invalid memory-version kind {self.kind!r}",
                "use initial, write, or unknown_write_kill",
            )
        if self.kind == "initial":
            if self.defining_access_id is not None or self.predecessor_version_ids:
                fail(
                    "record_schema_mismatch",
                    "initial memory version has a predecessor or defining write",
                    "emit an origin node without predecessors",
                )
        else:
            text(self.defining_access_id, "memory-version defining access ID")
            if len(self.predecessor_version_ids) != 1:
                fail(
                    "record_schema_mismatch",
                    "write memory version does not have one local predecessor",
                    "bind the exact version preceding the write",
                )
        if self.predecessor_version_ids != tuple(sorted(set(self.predecessor_version_ids))):
            fail(
                "noncanonical_record_order",
                "memory-version predecessors are not sorted and unique",
                "sort and deduplicate predecessor IDs",
            )
        _require_id(self.version_id, "memory-version", self.subject_payload(), "memory version")

    def subject_payload(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "kind": self.kind,
            "defining_access_id": self.defining_access_id,
        }

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.version_id, **self.subject_payload(), "predecessor_version_ids": list(self.predecessor_version_ids)}

    @classmethod
    def create(
        cls,
        *,
        component_id: str,
        kind: str,
        defining_access_id: str | None,
        predecessor_version_ids: tuple[str, ...],
    ) -> "MemoryVersionV3":
        payload = {
            "component_id": component_id,
            "kind": kind,
            "defining_access_id": defining_access_id,
        }
        return cls(
            _node_id("memory-version", payload),
            component_id,
            kind,
            defining_access_id,
            tuple(sorted(set(predecessor_version_ids))),
        )

    @classmethod
    def parse(cls, value: Any) -> "MemoryVersionV3":
        row = strict_object(
            value,
            {"id", "component_id", "kind", "defining_access_id", "predecessor_version_ids"},
            "memory version",
        )
        defining = row["defining_access_id"]
        return cls(
            text(row["id"], "memory version ID"),
            text(row["component_id"], "memory-version component ID"),
            text(row["kind"], "memory-version kind"),
            None if defining is None else text(defining, "memory defining access ID"),
            canonical_strings(row["predecessor_version_ids"], "memory predecessor IDs"),
        )


@dataclass(frozen=True, order=True)
class MemoryMergeInputV3:
    predecessor_unit_id: str
    version_id: str

    def __post_init__(self) -> None:
        text(self.predecessor_unit_id, "merge predecessor unit ID")
        text(self.version_id, "merge predecessor version ID")

    def to_payload(self) -> dict[str, str]:
        return {"predecessor_unit_id": self.predecessor_unit_id, "version_id": self.version_id}

    @classmethod
    def parse(cls, value: Any) -> "MemoryMergeInputV3":
        row = strict_object(value, {"predecessor_unit_id", "version_id"}, "memory merge input")
        return cls(
            text(row["predecessor_unit_id"], "merge predecessor unit ID"),
            text(row["version_id"], "merge predecessor version ID"),
        )


@dataclass(frozen=True, order=True)
class MemoryMergeV3:
    merge_id: str
    component_id: str
    cutpoint: TransitionUnitBindingV3
    incoming: tuple[MemoryMergeInputV3, ...]

    def __post_init__(self) -> None:
        text(self.component_id, "memory-merge component ID")
        if not self.incoming:
            fail(
                "record_schema_mismatch",
                "memory merge has no incoming versions",
                "include each exact predecessor version",
            )
        if self.incoming != tuple(sorted(self.incoming, key=lambda row: row.predecessor_unit_id)):
            fail(
                "noncanonical_record_order",
                "memory merge inputs are not sorted by predecessor",
                "sort merge inputs by predecessor unit ID",
            )
        if len({row.predecessor_unit_id for row in self.incoming}) != len(self.incoming):
            fail(
                "duplicate_record_id",
                "memory merge repeats a predecessor",
                "emit one incoming version per predecessor",
            )
        _require_id(self.merge_id, "memory-merge", self.subject_payload(), "memory merge")

    def subject_payload(self) -> dict[str, Any]:
        return {"component_id": self.component_id, "cutpoint": self.cutpoint.to_payload()}

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.merge_id, **self.subject_payload(), "incoming": [row.to_payload() for row in self.incoming]}

    @classmethod
    def create(
        cls,
        *,
        component_id: str,
        cutpoint: TransitionUnitBindingV3,
        incoming: tuple[MemoryMergeInputV3, ...],
    ) -> "MemoryMergeV3":
        payload = {"component_id": component_id, "cutpoint": cutpoint.to_payload()}
        return cls(
            _node_id("memory-merge", payload),
            component_id,
            cutpoint,
            tuple(sorted(incoming, key=lambda row: row.predecessor_unit_id)),
        )

    @classmethod
    def parse(cls, value: Any) -> "MemoryMergeV3":
        row = strict_object(value, {"id", "component_id", "cutpoint", "incoming"}, "memory merge")
        return cls(
            text(row["id"], "memory merge ID"),
            text(row["component_id"], "memory-merge component ID"),
            _parse_unit_binding(row["cutpoint"]),
            tuple(MemoryMergeInputV3.parse(item) for item in sequence(row["incoming"], "memory merge inputs")),
        )


@dataclass(frozen=True, order=True)
class UnknownWriteKillV3:
    kill_id: str
    access_id: str
    binding: TransitionEventBindingV3
    affected_scope: str
    affected_component_ids: tuple[str, ...]
    reason: str

    def __post_init__(self) -> None:
        text(self.access_id, "unknown-write access ID")
        if self.affected_scope not in {"all_components", "finite_components"}:
            fail(
                "record_schema_mismatch",
                f"invalid unknown-write scope {self.affected_scope!r}",
                "use all_components or finite_components",
            )
        if self.affected_component_ids != tuple(sorted(set(self.affected_component_ids))):
            fail(
                "noncanonical_record_order",
                "unknown-write component IDs are not sorted and unique",
                "sort and deduplicate component IDs",
            )
        if self.affected_scope == "all_components" and self.affected_component_ids:
            fail(
                "record_schema_mismatch",
                "all-components write kill redundantly enumerates components",
                "leave affected_component_ids empty",
            )
        if self.affected_scope == "finite_components" and not self.affected_component_ids:
            fail(
                "record_schema_mismatch",
                "finite-components write kill has no component",
                "include each affected alias component",
            )
        text(self.reason, "unknown-write reason")
        _require_id(self.kill_id, "unknown-write-kill", self.identity_payload(), "unknown-write kill")

    def identity_payload(self) -> dict[str, Any]:
        return {
            "access_id": self.access_id,
            "binding": self.binding.to_full_payload(),
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
        binding: TransitionEventBindingV3,
        affected_scope: str,
        affected_component_ids: tuple[str, ...] = (),
        reason: str,
    ) -> "UnknownWriteKillV3":
        components = tuple(sorted(set(affected_component_ids)))
        payload = {
            "access_id": access_id,
            "binding": binding.to_full_payload(),
            "affected_scope": affected_scope,
            "affected_component_ids": list(components),
            "reason": reason,
        }
        return cls(
            _node_id("unknown-write-kill", payload),
            access_id,
            binding,
            affected_scope,
            components,
            reason,
        )

    @classmethod
    def parse(
        cls, value: Any
    ) -> "UnknownWriteKillV3":
        row = strict_object(
            value,
            {"id", "access_id", "binding", "affected_scope", "affected_component_ids", "reason"},
            "unknown-write kill",
        )
        binding_row = strict_object(
            row["binding"],
            {
                "kind",
                "unit",
                "event_index",
                "event_kind",
                "instruction_rva",
                "event_sha256",
            },
            "unknown-write event binding",
        )
        if binding_row["kind"] != "event":
            fail(
                "record_schema_mismatch",
                "unknown-write kill does not use an event binding",
                "bind the kill to the exact memory-write event",
            )
        unit = _parse_unit_binding(binding_row["unit"])
        compact_binding = {
            key: binding_row[key]
            for key in (
                "event_index",
                "event_kind",
                "instruction_rva",
                "event_sha256",
            )
        }
        return cls(
            text(row["id"], "unknown-write kill ID"),
            text(row["access_id"], "unknown-write access ID"),
            TransitionEventBindingV3.parse(compact_binding, unit=unit),
            text(row["affected_scope"], "unknown-write scope"),
            canonical_strings(row["affected_component_ids"], "unknown-write component IDs"),
            text(row["reason"], "unknown-write reason"),
        )


@dataclass(frozen=True, order=True)
class MemoryAccessVersionV3:
    link_id: str
    access_id: str
    component_id: str
    ranges: tuple[ConcreteByteRangeV3, ...]
    version_before: str
    version_after: str

    def __post_init__(self) -> None:
        text(self.access_id, "memory-access link access ID")
        text(self.component_id, "memory-access link component ID")
        if self.ranges != tuple(sorted(set(self.ranges), key=lambda row: (row.start, row.end))):
            fail(
                "noncanonical_record_order",
                "memory-access ranges are not sorted and unique",
                "sort and deduplicate concrete ranges",
            )
        text(self.version_before, "memory-access version before")
        text(self.version_after, "memory-access version after")
        _require_id(self.link_id, "memory-access-version", self.identity_payload(), "memory-access link")

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
        ranges: tuple[ConcreteByteRangeV3, ...],
        version_before: str,
        version_after: str,
    ) -> "MemoryAccessVersionV3":
        canonical_ranges = tuple(sorted(set(ranges), key=lambda row: (row.start, row.end)))
        payload = {
            "access_id": access_id,
            "component_id": component_id,
            "ranges": [row.to_payload() for row in canonical_ranges],
            "version_before": version_before,
            "version_after": version_after,
        }
        return cls(
            _node_id("memory-access-version", payload),
            access_id,
            component_id,
            canonical_ranges,
            version_before,
            version_after,
        )

    @classmethod
    def parse(cls, value: Any) -> "MemoryAccessVersionV3":
        row = strict_object(
            value,
            {"id", "access_id", "component_id", "ranges", "version_before", "version_after"},
            "memory-access version link",
        )
        return cls(
            text(row["id"], "memory-access link ID"),
            text(row["access_id"], "memory-access ID"),
            text(row["component_id"], "memory-access component ID"),
            tuple(ConcreteByteRangeV3.parse(item) for item in sequence(row["ranges"], "memory-access ranges")),
            text(row["version_before"], "memory-access version before"),
            text(row["version_after"], "memory-access version after"),
        )


@dataclass(frozen=True, order=True)
class MemoryGraphIssueV3:
    issue_id: str
    status: str
    code: str
    subject_id: str
    detail: CanonicalValueV3

    def __post_init__(self) -> None:
        if self.status not in {"incomplete", "violated"}:
            fail(
                "record_schema_mismatch",
                f"invalid memory issue status {self.status!r}",
                "use incomplete or violated",
            )
        text(self.code, "memory issue code", maximum=128)
        text(self.subject_id, "memory issue subject")
        _require_id(self.issue_id, "memory-graph-issue", self.identity_payload(), "memory issue")

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
    def create(
        cls, *, status: str, code: str, subject_id: str, detail: Any
    ) -> "MemoryGraphIssueV3":
        canonical = CanonicalValueV3.of(detail)
        payload = {
            "status": status,
            "code": code,
            "subject_id": subject_id,
            "detail": canonical.to_value(),
        }
        return cls(_node_id("memory-graph-issue", payload), status, code, subject_id, canonical)

    @classmethod
    def parse(cls, value: Any) -> "MemoryGraphIssueV3":
        row = strict_object(value, {"id", "status", "code", "subject_id", "detail"}, "memory issue")
        return cls(
            text(row["id"], "memory issue ID"),
            text(row["status"], "memory issue status"),
            text(row["code"], "memory issue code", maximum=128),
            text(row["subject_id"], "memory issue subject"),
            CanonicalValueV3.of(row["detail"]),
        )


@dataclass(frozen=True)
class MemoryVersionRecordV3:
    """One checked memory-version graph for one dependency SCC."""

    record_id: str
    graph_id: str
    status: str
    binary: TransitionBinaryBindingV3
    transition_summary_ids: tuple[str, ...]
    alias_policy: str
    alias_components: tuple[MemoryAliasComponentV3, ...]
    versions: tuple[MemoryVersionV3, ...]
    merges: tuple[MemoryMergeV3, ...]
    access_versions: tuple[MemoryAccessVersionV3, ...]
    unknown_write_kills: tuple[UnknownWriteKillV3, ...]
    issues: tuple[MemoryGraphIssueV3, ...]

    @property
    def record_kind(self) -> str:
        return "scc_graph"

    @property
    def binary_pe_sha256(self) -> str:
        return self.binary.pe_sha256

    @property
    def binary_machine_ir_sha256(self) -> str:
        return self.binary.unit_ir_sha256

    def __post_init__(self) -> None:
        text(self.record_id, "memory-version record ID")
        if self.status not in {"complete", "incomplete", "violated"}:
            fail(
                "record_schema_mismatch",
                f"invalid memory graph status {self.status!r}",
                "use complete, incomplete, or violated",
            )
        if self.alias_policy not in _ALIAS_POLICIES:
            fail(
                "record_schema_mismatch",
                f"invalid alias policy {self.alias_policy!r}",
                "use fail_closed or merge_all",
            )
        if self.transition_summary_ids != tuple(sorted(set(self.transition_summary_ids))):
            fail(
                "noncanonical_record_order",
                "transition-summary IDs are not sorted and unique",
                "sort and deduplicate summary IDs",
            )
        for rows, attribute, label in (
            (self.alias_components, "component_id", "alias components"),
            (self.versions, "version_id", "memory versions"),
            (self.merges, "merge_id", "memory merges"),
            (self.access_versions, "link_id", "memory-access links"),
            (self.unknown_write_kills, "kill_id", "unknown-write kills"),
            (self.issues, "issue_id", "memory issues"),
        ):
            identifiers = tuple(getattr(row, attribute) for row in rows)
            if len(identifiers) != len(set(identifiers)) or rows != tuple(
                sorted(rows, key=lambda row: getattr(row, attribute))
            ):
                fail(
                    "noncanonical_record_order",
                    f"{label} are not sorted and unique",
                    f"sort and deduplicate {label} by stable ID",
                )
        _validate_disjoint_components(self.alias_components)
        component_ids = {row.component_id for row in self.alias_components}
        if any(row.component_id not in component_ids for row in (*self.versions, *self.merges, *self.access_versions)):
            fail(
                "memory_graph_binding_mismatch",
                "memory graph node references an unknown alias component",
                "derive every node from the checked component inventory",
            )
        version_ids = {row.version_id for row in self.versions} | {row.merge_id for row in self.merges}
        if any(
            predecessor not in version_ids
            for row in self.versions
            for predecessor in row.predecessor_version_ids
        ) or any(
            incoming.version_id not in version_ids
            for row in self.merges
            for incoming in row.incoming
        ) or any(
            row.version_before not in version_ids or row.version_after not in version_ids
            for row in self.access_versions
        ):
            fail(
                "memory_graph_binding_mismatch",
                "memory graph references an unknown version node",
                "regenerate the complete SCC-local version graph",
            )
        if any(
            row.affected_scope == "finite_components"
            and any(component not in component_ids for component in row.affected_component_ids)
            for row in self.unknown_write_kills
        ):
            fail(
                "memory_graph_binding_mismatch",
                "unknown-write kill references an unknown component",
                "bind the kill to the checked alias inventory",
            )
        if (self.status == "complete") != (not self.issues):
            fail(
                "record_schema_mismatch",
                "memory graph status does not match its issues",
                "mark a graph complete exactly when it has no issues",
            )
        if self.status == "violated" and not any(row.status == "violated" for row in self.issues):
            fail(
                "record_schema_mismatch",
                "violated memory graph has no violated issue",
                "preserve the contradictory issue that caused violation",
            )
        _require_id(self.graph_id, "memory-version-graph", self.identity_payload(), "memory graph")

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

    @classmethod
    def create(
        cls,
        *,
        record_id: str,
        status: str,
        binary: TransitionBinaryBindingV3,
        transition_summary_ids: tuple[str, ...],
        alias_policy: str,
        alias_components: tuple[MemoryAliasComponentV3, ...],
        versions: tuple[MemoryVersionV3, ...],
        merges: tuple[MemoryMergeV3, ...],
        access_versions: tuple[MemoryAccessVersionV3, ...],
        unknown_write_kills: tuple[UnknownWriteKillV3, ...],
        issues: tuple[MemoryGraphIssueV3, ...],
    ) -> "MemoryVersionRecordV3":
        fields: dict[str, Any] = {
            "status": status,
            "binary": binary,
            "transition_summary_ids": tuple(sorted(set(transition_summary_ids))),
            "alias_policy": alias_policy,
            "alias_components": tuple(sorted(alias_components, key=lambda row: row.component_id)),
            "versions": tuple(sorted(versions, key=lambda row: row.version_id)),
            "merges": tuple(sorted(merges, key=lambda row: row.merge_id)),
            "access_versions": tuple(sorted(access_versions, key=lambda row: row.link_id)),
            "unknown_write_kills": tuple(sorted(unknown_write_kills, key=lambda row: row.kill_id)),
            "issues": tuple(sorted(issues, key=lambda row: row.issue_id)),
        }
        identity = {
            "root_independent": True,
            "partition_authority": "optimization_only",
            "status": fields["status"],
            "binary": binary.to_payload(),
            "transition_summary_ids": list(fields["transition_summary_ids"]),
            "alias_policy": fields["alias_policy"],
            "alias_components": [
                row.to_payload() for row in fields["alias_components"]
            ],
            "versions": [row.to_payload() for row in fields["versions"]],
            "merges": [row.to_payload() for row in fields["merges"]],
            "access_versions": [
                row.to_payload() for row in fields["access_versions"]
            ],
            "unknown_write_kills": [
                row.to_payload() for row in fields["unknown_write_kills"]
            ],
            "issues": [row.to_payload() for row in fields["issues"]],
        }
        return cls(
            record_id=record_id,
            graph_id=_node_id("memory-version-graph", identity),
            **fields,  # type: ignore[arg-type]
        )


def _validate_disjoint_components(components: tuple[MemoryAliasComponentV3, ...]) -> None:
    ranges = sorted(
        (memory_range.start, memory_range.end, component.component_id)
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
            fail(
                "memory_alias_partition_overlap",
                "distinct alias components contain overlapping concrete ranges",
                "merge overlapping byte ranges into one component",
            )
        active_end = max(active_end, end)


def _encode_memory_record(value: MemoryVersionRecordV3) -> dict[str, Any]:
    return {
        "schema": MEMORY_VERSION_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "kind": value.record_kind,
        "graph_id": value.graph_id,
        "status": value.status,
        "binary_pe_sha256": value.binary.pe_sha256,
        "binary_machine_ir_sha256": value.binary.unit_ir_sha256,
        "transition_summary_ids": list(value.transition_summary_ids),
        "alias_policy": value.alias_policy,
        "alias_components": [row.to_payload() for row in value.alias_components],
        "versions": [row.to_payload() for row in value.versions],
        "merges": [row.to_payload() for row in value.merges],
        "access_versions": [row.to_payload() for row in value.access_versions],
        "unknown_write_kills": [row.to_payload() for row in value.unknown_write_kills],
        "issues": [row.to_payload() for row in value.issues],
    }


def _decode_memory_record(value: Any) -> MemoryVersionRecordV3:
    row = strict_object(
        value,
        {
            "schema", "id", "kind", "graph_id", "status", "binary_pe_sha256",
            "binary_machine_ir_sha256", "transition_summary_ids", "alias_policy",
            "alias_components", "versions", "merges", "access_versions",
            "unknown_write_kills", "issues",
        },
        "memory-version record",
    )
    if row["schema"] != MEMORY_VERSION_RECORD_V3_SCHEMA or row["kind"] != "scc_graph":
        fail(
            "wrong_record_schema",
            "record is not an SCC-local memory-version-record-v3",
            "use MEMORY_VERSION_CODEC_V3 with memory-versions-v3 artifacts",
        )
    binary = TransitionBinaryBindingV3(
        digest(row["binary_pe_sha256"], "memory PE SHA-256"),
        digest(row["binary_machine_ir_sha256"], "memory unit-IR SHA-256"),
    )
    merges = tuple(MemoryMergeV3.parse(item) for item in sequence(row["merges"], "memory merges"))
    return MemoryVersionRecordV3(
        record_id=text(row["id"], "memory record ID"),
        graph_id=text(row["graph_id"], "memory graph ID"),
        status=text(row["status"], "memory graph status"),
        binary=binary,
        transition_summary_ids=canonical_strings(row["transition_summary_ids"], "transition-summary IDs"),
        alias_policy=text(row["alias_policy"], "memory alias policy"),
        alias_components=tuple(MemoryAliasComponentV3.parse(item) for item in sequence(row["alias_components"], "alias components")),
        versions=tuple(MemoryVersionV3.parse(item) for item in sequence(row["versions"], "memory versions")),
        merges=merges,
        access_versions=tuple(MemoryAccessVersionV3.parse(item) for item in sequence(row["access_versions"], "memory-access links")),
        unknown_write_kills=tuple(
            UnknownWriteKillV3.parse(item)
            for item in sequence(row["unknown_write_kills"], "unknown-write kills")
        ),
        issues=tuple(MemoryGraphIssueV3.parse(item) for item in sequence(row["issues"], "memory issues")),
    )


MEMORY_VERSION_CODEC_V3 = RecordCodecV3[MemoryVersionRecordV3](
    decode=_decode_memory_record,
    encode=_encode_memory_record,
)


__all__ = [
    "ConcreteByteRangeV3",
    "MEMORY_VERSION_CODEC_V3",
    "MEMORY_VERSION_RECORD_V3_SCHEMA",
    "MEMORY_VERSIONS_ARTIFACT_KIND_V3",
    "MemoryAccessVersionV3",
    "MemoryAliasComponentV3",
    "MemoryGraphIssueV3",
    "MemoryMergeInputV3",
    "MemoryMergeV3",
    "MemoryVersionRecordV3",
    "MemoryVersionV3",
    "UnknownWriteKillV3",
]
