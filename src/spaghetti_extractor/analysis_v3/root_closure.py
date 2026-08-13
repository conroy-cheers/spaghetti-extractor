"""Conditional launch roots and exact global rooted-control closure."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    CanonicalValueV3,
    RecordDependencyV3,
)
from ..phase_framework_v3 import PhaseContextV3, RecordCodecV3, reduce
from ._schema import (
    canonical_strings,
    digest,
    fail,
    mapping,
    optional_text,
    require_record_ids,
    require_stable_id,
    sequence,
    sorted_records,
    stable_id,
    strict_object,
    text,
)
from .authority_common import (
    PrimaryBlockerV3,
    aggregate_blockers_v3,
    blocker_payload_v3,
    canonical_dependencies_v3,
    decode_dependencies_v3,
    encode_dependencies_v3,
    manifest_blocker_v3,
    validate_authority_decision_v3,
)
from .callbacks import (
    CALLBACK_AUTHORITY_ARTIFACT_KIND_V3,
    CALLBACK_AUTHORITY_CODEC_V3,
    CallbackAuthorityV3,
)
from .semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    SemanticIndexRecordV3,
)
from .target_certificates import (
    INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
    IndirectTargetCertificateV3,
    flatten_indirect_target_certificates_v3,
)


LAUNCH_ROOT_EVIDENCE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-launch-root-evidence-record-v3"
)
LAUNCH_ROOT_EVIDENCE_ARTIFACT_KIND_V3 = "launch-root-evidence-v3"
LAUNCH_ROOT_CLOSURE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-launch-root-closure-record-v3"
)
LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3 = "launch-root-closure-v3"

_STATIC_ROOT_KINDS = frozenset(
    {"pe_entrypoint", "pe_export", "pe_tls_callback"}
)
_ROOT_KINDS = _STATIC_ROOT_KINDS | {"event_callback"}


def launch_root_id_v3(root_kind: str, identity: str, unit_id: str) -> str:
    return stable_id(
        "launch-root-v3",
        {"root_kind": root_kind, "identity": identity, "unit_id": unit_id},
    )


@dataclass(frozen=True)
class LaunchRootEvidenceV3:
    record_id: str
    root_kind: str
    identity: str
    unit_id: str
    unit_sha256: str
    entry_state: CanonicalValueV3 | None
    callback_id: str | None
    status: str
    primary_blocker: PrimaryBlockerV3 | None

    def __post_init__(self) -> None:
        if self.root_kind not in _ROOT_KINDS:
            fail(
                "record_schema_mismatch",
                f"launch root kind is {self.root_kind!r}",
                "use an exact PE root or event_callback",
            )
        text(self.identity, "launch root identity")
        text(self.unit_id, "launch root unit ID")
        digest(self.unit_sha256, "launch root unit SHA-256")
        require_stable_id(
            self.record_id,
            "launch-root-v3",
            {
                "root_kind": self.root_kind,
                "identity": self.identity,
                "unit_id": self.unit_id,
            },
            "launch root",
        )
        if self.root_kind == "event_callback":
            if self.callback_id is None:
                fail(
                    "callback_root_binding_missing",
                    "event callback root has no callback authority ID",
                    "bind the exact callback-authority record",
                )
        elif self.callback_id is not None:
            fail(
                "callback_root_binding_contradiction",
                "static launch root names callback authority",
                "clear callback_id for PE roots",
            )
        if self.status not in {"complete", "incomplete", "violated"}:
            fail(
                "record_schema_mismatch",
                f"launch root status is {self.status!r}",
                "use complete, incomplete, or violated",
            )
        if self.status == "complete":
            if self.entry_state is None or self.primary_blocker is not None:
                fail(
                    "fail_open_launch_root",
                    "complete launch root lacks entry state or has a blocker",
                    "bind exact entry state and clear the blocker",
                )
            if not mapping(self.entry_state.to_value(), "launch root entry state"):
                fail(
                    "record_schema_mismatch",
                    "complete launch root entry state is empty",
                    "bind at least one exact or explicit assumption",
                )
        elif self.entry_state is not None or self.primary_blocker is None:
            fail(
                "fail_open_launch_root",
                "non-complete launch root retains entry authority or lacks a blocker",
                "clear entry state and provide the matching blocker",
            )
        if self.primary_blocker is not None and self.primary_blocker.status != self.status:
            fail(
                "fail_open_launch_root",
                "launch root blocker disagrees with its status",
                "use one matching fail-closed status",
            )


def _encode_launch_root(value: LaunchRootEvidenceV3) -> dict[str, Any]:
    return {
        "schema": LAUNCH_ROOT_EVIDENCE_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "root_kind": value.root_kind,
        "identity": value.identity,
        "unit_id": value.unit_id,
        "unit_sha256": value.unit_sha256,
        "entry_state": (
            None if value.entry_state is None else value.entry_state.to_value()
        ),
        "callback_id": value.callback_id,
        "status": value.status,
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
    }


def _decode_launch_root(value: Any) -> LaunchRootEvidenceV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "root_kind",
            "identity",
            "unit_id",
            "unit_sha256",
            "entry_state",
            "callback_id",
            "status",
            "primary_blocker",
        },
        "launch root evidence",
    )
    if row["schema"] != LAUNCH_ROOT_EVIDENCE_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not launch-root-evidence-record-v3",
            "use LAUNCH_ROOT_EVIDENCE_CODEC_V3 with matching evidence",
        )
    return LaunchRootEvidenceV3(
        record_id=text(row["id"], "launch root ID"),
        root_kind=text(row["root_kind"], "launch root kind"),
        identity=text(row["identity"], "launch root identity"),
        unit_id=text(row["unit_id"], "launch root unit ID"),
        unit_sha256=digest(row["unit_sha256"], "launch root unit SHA-256"),
        entry_state=(
            None
            if row["entry_state"] is None
            else CanonicalValueV3.of(row["entry_state"])
        ),
        callback_id=optional_text(row["callback_id"], "launch root callback ID"),
        status=text(row["status"], "launch root status"),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
    )


LAUNCH_ROOT_EVIDENCE_CODEC_V3 = RecordCodecV3[LaunchRootEvidenceV3](
    decode=_decode_launch_root,
    encode=_encode_launch_root,
)


@dataclass(frozen=True, order=True)
class RootedControlEdgeV3:
    edge_id: str
    source_unit_id: str
    target_unit_id: str
    edge_kind: str
    authority_record_id: str

    def __post_init__(self) -> None:
        text(self.source_unit_id, "rooted edge source unit ID")
        text(self.target_unit_id, "rooted edge target unit ID")
        if self.edge_kind not in {"direct", "internal_call", "recovered_indirect"}:
            fail(
                "record_schema_mismatch",
                f"rooted edge kind is {self.edge_kind!r}",
                "use direct, internal_call, or recovered_indirect",
            )
        text(self.authority_record_id, "rooted edge authority record ID")
        require_stable_id(
            self.edge_id,
            "rooted-edge-v3",
            self.identity_payload,
            "rooted control edge",
        )

    @property
    def identity_payload(self) -> dict[str, str]:
        return {
            "source_unit_id": self.source_unit_id,
            "target_unit_id": self.target_unit_id,
            "edge_kind": self.edge_kind,
            "authority_record_id": self.authority_record_id,
        }

    @classmethod
    def create(
        cls,
        source_unit_id: str,
        target_unit_id: str,
        edge_kind: str,
        authority_record_id: str,
    ) -> "RootedControlEdgeV3":
        identity = {
            "source_unit_id": source_unit_id,
            "target_unit_id": target_unit_id,
            "edge_kind": edge_kind,
            "authority_record_id": authority_record_id,
        }
        return cls(
            stable_id("rooted-edge-v3", identity),
            source_unit_id,
            target_unit_id,
            edge_kind,
            authority_record_id,
        )

    def to_payload(self) -> dict[str, str]:
        return {"id": self.edge_id, **self.identity_payload}

    @classmethod
    def parse(cls, value: Any) -> "RootedControlEdgeV3":
        row = strict_object(
            value,
            {
                "id",
                "source_unit_id",
                "target_unit_id",
                "edge_kind",
                "authority_record_id",
            },
            "rooted control edge",
        )
        return cls(
            edge_id=text(row["id"], "rooted edge ID"),
            source_unit_id=text(row["source_unit_id"], "rooted edge source"),
            target_unit_id=text(row["target_unit_id"], "rooted edge target"),
            edge_kind=text(row["edge_kind"], "rooted edge kind"),
            authority_record_id=text(
                row["authority_record_id"], "rooted edge authority record ID"
            ),
        )


@dataclass(frozen=True)
class LaunchRootClosureV3:
    record_id: str
    status: str
    authorizing: bool
    submitted_root_ids: tuple[str, ...]
    admitted_root_ids: tuple[str, ...]
    reachable_unit_ids: tuple[str, ...]
    edges: tuple[RootedControlEdgeV3, ...]
    frontier_ids: tuple[str, ...]
    primary_blocker: PrimaryBlockerV3 | None
    dependencies: tuple[RecordDependencyV3, ...]
    _reachable_unit_id_set: frozenset[str] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        require_stable_id(
            self.record_id,
            "launch-root-closure-v3",
            {
                "submitted_root_ids": list(self.submitted_root_ids),
                "dependency_records": [row.to_payload() for row in self.dependencies],
            },
            "launch-root closure",
        )
        for values, context in (
            (self.submitted_root_ids, "submitted launch roots"),
            (self.admitted_root_ids, "admitted launch roots"),
            (self.reachable_unit_ids, "reachable unit IDs"),
            (self.frontier_ids, "rooted frontier IDs"),
        ):
            if values != tuple(sorted(set(values))):
                fail(
                    "noncanonical_record_order",
                    f"{context} are duplicated or unsorted",
                    "sort and deduplicate stable IDs",
                )
        if not set(self.admitted_root_ids) <= set(self.submitted_root_ids):
            fail(
                "root_closure_contradiction",
                "admitted roots are not a subset of submitted roots",
                "admit only independently checked root records",
            )
        if self.edges != tuple(sorted(set(self.edges))):
            fail(
                "noncanonical_record_order",
                "rooted control edges are duplicated or unsorted",
                "sort and deduplicate exact edges",
            )
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=self.dependencies,
            context="launch/root closure",
        )
        object.__setattr__(
            self, "_reachable_unit_id_set", frozenset(self.reachable_unit_ids)
        )

    def contains_reachable_unit(self, unit_id: str) -> bool:
        """Use the checked closure through its compact immutable index."""

        return unit_id in self._reachable_unit_id_set


def _encode_root_closure(value: LaunchRootClosureV3) -> dict[str, Any]:
    return {
        "schema": LAUNCH_ROOT_CLOSURE_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "status": value.status,
        "authorizing": value.authorizing,
        "submitted_root_ids": list(value.submitted_root_ids),
        "admitted_root_ids": list(value.admitted_root_ids),
        "reachable_unit_ids": list(value.reachable_unit_ids),
        "edges": [row.to_payload() for row in value.edges],
        "frontier_ids": list(value.frontier_ids),
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
        "dependencies": encode_dependencies_v3(value.dependencies),
    }


def _decode_root_closure(value: Any) -> LaunchRootClosureV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "status",
            "authorizing",
            "submitted_root_ids",
            "admitted_root_ids",
            "reachable_unit_ids",
            "edges",
            "frontier_ids",
            "primary_blocker",
            "dependencies",
        },
        "launch/root closure",
    )
    if row["schema"] != LAUNCH_ROOT_CLOSURE_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not launch-root-closure-record-v3",
            "use LAUNCH_ROOT_CLOSURE_CODEC_V3 with matching artifacts",
        )
    authorizing = row["authorizing"]
    if not isinstance(authorizing, bool):
        fail(
            "record_schema_mismatch",
            "root closure authorizing field is not Boolean",
            "emit true or false",
        )
    return LaunchRootClosureV3(
        record_id=text(row["id"], "launch/root closure ID"),
        status=text(row["status"], "launch/root closure status"),
        authorizing=authorizing,
        submitted_root_ids=canonical_strings(
            row["submitted_root_ids"], "submitted launch roots"
        ),
        admitted_root_ids=canonical_strings(
            row["admitted_root_ids"], "admitted launch roots"
        ),
        reachable_unit_ids=canonical_strings(
            row["reachable_unit_ids"], "reachable unit IDs"
        ),
        edges=tuple(
            RootedControlEdgeV3.parse(item)
            for item in sequence(row["edges"], "rooted control edges")
        ),
        frontier_ids=canonical_strings(row["frontier_ids"], "rooted frontiers"),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
        dependencies=decode_dependencies_v3(row["dependencies"]),
    )


LAUNCH_ROOT_CLOSURE_CODEC_V3 = RecordCodecV3[LaunchRootClosureV3](
    decode=_decode_root_closure,
    encode=_encode_root_closure,
)


def _callback_index(
    records: tuple[ArtifactRecordV3, ...],
) -> dict[str, CallbackAuthorityV3]:
    result: dict[str, CallbackAuthorityV3] = {}
    for record in records:
        inventory = CALLBACK_AUTHORITY_CODEC_V3.read(record).value
        for callback in inventory.callbacks:
            if callback.callback_id in result:
                fail(
                    "duplicate_callback_authority",
                    f"callback {callback.callback_id!r} appears in multiple records",
                    "emit each callback under exactly one source-unit inventory",
                )
            result[callback.callback_id] = callback
    return result


def _admit_roots(
    roots: tuple[LaunchRootEvidenceV3, ...],
    exact_by_id: Mapping[str, SemanticIndexRecordV3],
    callbacks: Mapping[str, CallbackAuthorityV3],
) -> tuple[tuple[LaunchRootEvidenceV3, ...], tuple[PrimaryBlockerV3, ...]]:
    admitted: list[LaunchRootEvidenceV3] = []
    blockers: list[PrimaryBlockerV3] = []
    for root in roots:
        dependency = RecordDependencyV3("launch_roots", root.record_id)
        exact = exact_by_id.get(root.unit_id)
        if exact is None or exact.unit_sha256 != root.unit_sha256:
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "launch_root_unit_contradiction",
                    dependency.input_name,
                    dependency.record_id,
                )
            )
            continue
        if root.status != "complete":
            blockers.append(
                PrimaryBlockerV3(
                    "violated" if root.status == "violated" else "incomplete",
                    (
                        root.primary_blocker.code
                        if root.primary_blocker is not None
                        else "launch_root_incomplete"
                    ),
                    dependency.input_name,
                    dependency.record_id,
                )
            )
            continue
        if root.root_kind == "event_callback":
            callback = callbacks.get(str(root.callback_id))
            if (
                callback is None
                or callback.status != "complete"
                or callback.target_unit_id != root.unit_id
                or callback.target_unit_sha256 != root.unit_sha256
                or callback.entry_state != root.entry_state
            ):
                blockers.append(
                    PrimaryBlockerV3(
                        "violated" if callback is not None else "incomplete",
                        "callback_root_authority_contradiction",
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
        admitted.append(root)
    return tuple(admitted), tuple(blockers)


def _exact_edges(
    semantic_units: tuple[SemanticIndexRecordV3, ...],
) -> tuple[
    dict[str, set[RootedControlEdgeV3]],
    dict[str, list[PrimaryBlockerV3]],
    dict[str, tuple[str, ...]],
]:
    by_rva = {row.rva_start: row.record_id for row in semantic_units}
    successors: dict[str, set[RootedControlEdgeV3]] = {
        row.record_id: set() for row in semantic_units
    }
    blockers: dict[str, list[PrimaryBlockerV3]] = {
        row.record_id: [] for row in semantic_units
    }
    indirect_exits: dict[str, list[str]] = {
        row.record_id: [] for row in semantic_units
    }
    for exact in semantic_units:
        unit_id = exact.record_id
        for target_rva in exact.direct_target_rvas:
            target_id = by_rva.get(target_rva)
            if target_id is None:
                blockers[unit_id].append(
                    PrimaryBlockerV3("incomplete", "direct_target_unresolved")
                )
                continue
            successors[unit_id].add(
                RootedControlEdgeV3.create(
                    unit_id, target_id, "direct", exact.record_id
                )
            )
        indirect_exits[unit_id].extend(
            row.exit_id for row in exact.indirect_exits
        )
        for call in exact.internal_calls:
            target_id = (
                by_rva.get(call.target_rva)
                if call.target_rva is not None
                else None
            )
            if target_id is None:
                blockers[unit_id].append(
                    PrimaryBlockerV3("incomplete", "internal_call_target_unresolved")
                )
            else:
                successors[unit_id].add(
                    RootedControlEdgeV3.create(
                        unit_id, target_id, "internal_call", exact.record_id
                    )
                )
    return (
        successors,
        blockers,
        {
            unit_id: tuple(sorted(set(exit_ids)))
            for unit_id, exit_ids in indirect_exits.items()
        },
    )


def _derive_root_closure(context: PhaseContextV3) -> LaunchRootClosureV3:
    exact_records = sorted_records(context.records("semantic_index"))
    callback_records = sorted_records(context.records("callbacks"))
    root_records = sorted_records(context.records("launch_roots"))
    target_records = sorted_records(context.records("target_certificates"))
    if not exact_records:
        fail(
            "empty_structural_universe",
            "launch/root closure has no exact units",
            "provide the complete exact-unit artifact",
        )
    exact_units = tuple(SEMANTIC_INDEX_CODEC_V3.read(row).value for row in exact_records)
    exact_by_id = {row.record_id: row for row in exact_units}
    callbacks = _callback_index(callback_records)
    roots = tuple(LAUNCH_ROOT_EVIDENCE_CODEC_V3.read(row).value for row in root_records)
    targets = flatten_indirect_target_certificates_v3(target_records)
    dependencies = [
        *(RecordDependencyV3("semantic_index", row.record_id) for row in exact_records),
        *(RecordDependencyV3("callbacks", row.record_id) for row in callback_records),
        *(RecordDependencyV3("launch_roots", row.record_id) for row in root_records),
        *(
            RecordDependencyV3("target_certificates", row.record_id)
            for row in target_records
        ),
    ]
    admitted, root_blockers = _admit_roots(roots, exact_by_id, callbacks)
    blockers: list[PrimaryBlockerV3] = list(root_blockers)
    for input_name, code in (
        ("callbacks", "callback_authority_artifact_not_complete"),
        ("semantic_index", "semantic_index_artifact_not_complete"),
        ("launch_roots", "launch_root_artifact_not_complete"),
        (
            "target_certificates",
            "indirect_target_certificate_artifact_not_complete",
        ),
    ):
        dependency = next(
            (row for row in dependencies if row.input_name == input_name), None
        )
        manifest_blocker = manifest_blocker_v3(
            context, input_name, code, dependency
        )
        if manifest_blocker is not None:
            blockers.append(manifest_blocker)
    if not roots:
        blockers.append(PrimaryBlockerV3("incomplete", "launch_root_inventory_empty"))
    elif not admitted and not blockers:
        blockers.append(PrimaryBlockerV3("incomplete", "no_launch_root_admitted"))
    successors, exact_blockers, expected_exits = _exact_edges(exact_units)
    target_by_id: dict[str, IndirectTargetCertificateV3] = {}
    expected_exit_ids = {
        exit_id for exit_ids in expected_exits.values() for exit_id in exit_ids
    }
    for target in targets:
        if (
            target.source_unit_id not in exact_by_id
            or target.exit_id not in expected_exit_ids
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "indirect_target_certificate_not_exact",
                    "target_certificates",
                    target.source_unit_id,
                )
            )
            continue
        target_by_id[target.exit_id] = target

    reachable: set[str] = set()
    edges: set[RootedControlEdgeV3] = set()
    frontiers: set[str] = set()
    pending = sorted({root.unit_id for root in admitted}, reverse=True)
    while pending:
        unit_id = pending.pop()
        if unit_id in reachable:
            continue
        reachable.add(unit_id)
        blockers.extend(exact_blockers[unit_id])
        local_edges = set(successors[unit_id])
        for exit_id in expected_exits[unit_id]:
            dependency = RecordDependencyV3("target_certificates", unit_id)
            target = target_by_id.get(exit_id)
            if target is None:
                dependencies.append(dependency)
                frontiers.add(exit_id)
                blockers.append(
                    PrimaryBlockerV3(
                        "incomplete",
                        "indirect_target_certificate_missing",
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            if target.status != "complete" or not target.authorizing:
                frontiers.add(target.exit_id)
                blockers.append(
                    PrimaryBlockerV3(
                        "violated" if target.status == "violated" else "incomplete",
                        (
                            target.primary_blocker.code
                            if target.primary_blocker is not None
                            else "reachable_indirect_target_frontier"
                        ),
                        dependency.input_name,
                        dependency.record_id,
                    )
                )
                continue
            for target_unit_id in target.target_unit_ids:
                if target_unit_id not in exact_by_id:
                    frontiers.add(target.exit_id)
                    blockers.append(
                        PrimaryBlockerV3(
                            "violated",
                            "certified_target_unit_unknown",
                            dependency.input_name,
                            dependency.record_id,
                        )
                    )
                    continue
                local_edges.add(
                    RootedControlEdgeV3.create(
                        unit_id,
                        target_unit_id,
                        "recovered_indirect",
                        target.certificate_id,
                    )
                )
        edges.update(local_edges)
        pending.extend(
            sorted(
                {row.target_unit_id for row in local_edges} - reachable,
                reverse=True,
            )
        )
    primary = aggregate_blockers_v3(blockers)
    status = "complete" if primary is None else primary.status
    submitted_ids = tuple(sorted(row.record_id for row in roots))
    canonical_dependencies = canonical_dependencies_v3(dependencies)
    record_id = stable_id(
        "launch-root-closure-v3",
        {
            "submitted_root_ids": list(submitted_ids),
            "dependency_records": [row.to_payload() for row in canonical_dependencies],
        },
    )
    return LaunchRootClosureV3(
        record_id=record_id,
        status=status,
        authorizing=status == "complete",
        submitted_root_ids=submitted_ids,
        admitted_root_ids=tuple(sorted(row.record_id for row in admitted)),
        reachable_unit_ids=tuple(sorted(reachable)),
        edges=tuple(sorted(edges)),
        frontier_ids=tuple(sorted(frontiers)),
        primary_blocker=primary,
        dependencies=canonical_dependencies,
    )


def _transform_root_closure(context: PhaseContextV3) -> ArtifactRecordV3:
    value = _derive_root_closure(context)
    return LAUNCH_ROOT_CLOSURE_CODEC_V3.write(
        value.record_id, value, dependencies=value.dependencies
    )


def check_launch_root_closure_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    expected = _derive_root_closure(context)
    outputs = sorted_records(reader.iter_records())
    require_record_ids(outputs, (expected.record_id,), "launch/root closure")
    submitted = LAUNCH_ROOT_CLOSURE_CODEC_V3.read(outputs[0]).value
    if submitted != expected:
        fail(
            "launch_root_closure_contradiction",
            "launch/root closure is stale for its exact inputs",
            "rerun the global root-closure reduction",
        )
    if outputs[0].dependencies != expected.dependencies:
        fail(
            "incomplete_record_dependencies",
            "launch/root closure has stale exact dependencies",
            "let LAUNCH_ROOT_CLOSURE_PHASE_V3 attach the full closure",
        )


LAUNCH_ROOT_CLOSURE_PHASE_V3 = reduce(
    name="launch-root-closure-v3",
    version="2",
    input_artifact_kinds={
        "callbacks": CALLBACK_AUTHORITY_ARTIFACT_KIND_V3,
        "launch_roots": LAUNCH_ROOT_EVIDENCE_ARTIFACT_KIND_V3,
        "semantic_index": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
        "target_certificates": INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
    },
    output_artifact_kind=LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
    transform=_transform_root_closure,
    completeness=check_launch_root_closure_completeness_v3,
)


__all__ = [
    "LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3",
    "LAUNCH_ROOT_CLOSURE_CODEC_V3",
    "LAUNCH_ROOT_CLOSURE_PHASE_V3",
    "LAUNCH_ROOT_CLOSURE_RECORD_V3_SCHEMA",
    "LAUNCH_ROOT_EVIDENCE_ARTIFACT_KIND_V3",
    "LAUNCH_ROOT_EVIDENCE_CODEC_V3",
    "LAUNCH_ROOT_EVIDENCE_RECORD_V3_SCHEMA",
    "LaunchRootClosureV3",
    "LaunchRootEvidenceV3",
    "RootedControlEdgeV3",
    "check_launch_root_closure_completeness_v3",
    "launch_root_id_v3",
]
