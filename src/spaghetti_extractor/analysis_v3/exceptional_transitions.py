"""Per-unit checked exceptional transitions over launch/root closure."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    CanonicalValueV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..phase_framework_v3 import PhaseContextV3, RecordCodecV3, map_units
from ._schema import (
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
    uint,
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
from .root_closure import (
    LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
    LAUNCH_ROOT_CLOSURE_CODEC_V3,
    LaunchRootClosureV3,
)
from .semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    FaultOccurrenceV3,
    SemanticIndexRecordV3,
)


EXCEPTION_EVIDENCE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-exception-evidence-record-v3"
)
EXCEPTION_EVIDENCE_ARTIFACT_KIND_V3 = "exception-evidence-v3"
EXCEPTIONAL_TRANSITION_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-exceptional-transition-record-v3"
)
EXCEPTIONAL_TRANSITIONS_ARTIFACT_KIND_V3 = "exceptional-transitions-v3"


def exceptional_transition_id_v3(
    unit_id: str, fault_index: int, fault_sha256: str
) -> str:
    return stable_id(
        "exceptional-transition-v3",
        {
            "unit_id": unit_id,
            "fault_index": fault_index,
            "fault_sha256": fault_sha256,
        },
    )


@dataclass(frozen=True)
class ExceptionEvidenceV3:
    record_id: str
    unit_id: str
    unit_sha256: str
    fault_index: int
    fault_sha256: str
    status: str
    disposition: str | None
    handler_unit_id: str | None
    handler_unit_sha256: str | None
    guard: CanonicalValueV3 | None
    primary_blocker: PrimaryBlockerV3 | None

    def __post_init__(self) -> None:
        text(self.unit_id, "exception evidence unit ID")
        digest(self.unit_sha256, "exception evidence unit SHA-256")
        uint(self.fault_index, "exception evidence fault index")
        digest(self.fault_sha256, "exception evidence fault SHA-256")
        require_stable_id(
            self.record_id,
            "exceptional-transition-v3",
            {
                "unit_id": self.unit_id,
                "fault_index": self.fault_index,
                "fault_sha256": self.fault_sha256,
            },
            "exception evidence",
        )
        if self.status not in {"complete", "incomplete", "violated"}:
            fail(
                "record_schema_mismatch",
                f"exception evidence status is {self.status!r}",
                "use complete, incomplete, or violated",
            )
        if self.status == "complete":
            if (
                self.disposition not in {"handled", "terminates"}
                or self.guard is None
                or self.primary_blocker is not None
            ):
                fail(
                    "fail_open_exception_evidence",
                    "complete exception evidence lacks disposition/guard or has a blocker",
                    "bind a handled or terminating transition and clear the blocker",
                )
            mapping(self.guard.to_value(), "exception transition guard")
            if self.disposition == "handled":
                if self.handler_unit_id is None or self.handler_unit_sha256 is None:
                    fail(
                        "exception_handler_binding_missing",
                        "handled exception has no exact handler unit binding",
                        "bind the handler unit ID and content SHA-256",
                    )
            elif self.handler_unit_id is not None or self.handler_unit_sha256 is not None:
                fail(
                    "exception_handler_binding_contradiction",
                    "terminating exception names a handler unit",
                    "clear handler fields for a terminating transition",
                )
        elif any(
            value is not None
            for value in (
                self.disposition,
                self.handler_unit_id,
                self.handler_unit_sha256,
                self.guard,
            )
        ) or self.primary_blocker is None:
            fail(
                "fail_open_exception_evidence",
                "non-complete exception evidence retains transition authority or lacks a blocker",
                "clear transition fields and provide the matching blocker",
            )
        if self.handler_unit_sha256 is not None:
            digest(self.handler_unit_sha256, "exception handler unit SHA-256")
        if self.primary_blocker is not None and self.primary_blocker.status != self.status:
            fail(
                "fail_open_exception_evidence",
                "exception evidence blocker disagrees with its status",
                "use one matching fail-closed status",
            )


def _encode_exception_evidence(value: ExceptionEvidenceV3) -> dict[str, Any]:
    return {
        "schema": EXCEPTION_EVIDENCE_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "unit_id": value.unit_id,
        "unit_sha256": value.unit_sha256,
        "fault_index": value.fault_index,
        "fault_sha256": value.fault_sha256,
        "status": value.status,
        "disposition": value.disposition,
        "handler_unit_id": value.handler_unit_id,
        "handler_unit_sha256": value.handler_unit_sha256,
        "guard": None if value.guard is None else value.guard.to_value(),
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
    }


def _decode_exception_evidence(value: Any) -> ExceptionEvidenceV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "unit_id",
            "unit_sha256",
            "fault_index",
            "fault_sha256",
            "status",
            "disposition",
            "handler_unit_id",
            "handler_unit_sha256",
            "guard",
            "primary_blocker",
        },
        "exception evidence",
    )
    if row["schema"] != EXCEPTION_EVIDENCE_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not exception-evidence-record-v3",
            "use EXCEPTION_EVIDENCE_CODEC_V3 with exception-evidence-v3",
        )
    return ExceptionEvidenceV3(
        record_id=text(row["id"], "exception evidence ID"),
        unit_id=text(row["unit_id"], "exception evidence unit ID"),
        unit_sha256=digest(
            row["unit_sha256"], "exception evidence unit SHA-256"
        ),
        fault_index=uint(row["fault_index"], "exception evidence fault index"),
        fault_sha256=digest(
            row["fault_sha256"], "exception evidence fault SHA-256"
        ),
        status=text(row["status"], "exception evidence status"),
        disposition=optional_text(
            row["disposition"], "exception evidence disposition"
        ),
        handler_unit_id=optional_text(
            row["handler_unit_id"], "exception handler unit ID"
        ),
        handler_unit_sha256=(
            None
            if row["handler_unit_sha256"] is None
            else digest(
                row["handler_unit_sha256"], "exception handler unit SHA-256"
            )
        ),
        guard=(
            None if row["guard"] is None else CanonicalValueV3.of(row["guard"])
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
    )


EXCEPTION_EVIDENCE_CODEC_V3 = RecordCodecV3[ExceptionEvidenceV3](
    decode=_decode_exception_evidence,
    encode=_encode_exception_evidence,
)


@dataclass(frozen=True)
class ExceptionalTransitionV3:
    transition_id: str
    unit_id: str
    fault_index: int
    fault_sha256: str
    status: str
    authorizing: bool
    disposition: str | None
    handler_unit_id: str | None
    guard: CanonicalValueV3 | None
    primary_blocker: PrimaryBlockerV3 | None

    def __post_init__(self) -> None:
        require_stable_id(
            self.transition_id,
            "exceptional-transition-v3",
            {
                "unit_id": self.unit_id,
                "fault_index": self.fault_index,
                "fault_sha256": self.fault_sha256,
            },
            "exceptional transition",
        )
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=(
                ()
                if self.primary_blocker is None
                or self.primary_blocker.dependency is None
                else (self.primary_blocker.dependency,)
            ),
            context=f"exceptional transition {self.transition_id!r}",
        )
        if self.status == "complete":
            if self.disposition not in {"handled", "terminates"} or self.guard is None:
                fail(
                    "fail_open_exception_transition",
                    "complete exceptional transition lacks checked semantics",
                    "bind a disposition and guard",
                )
            if (self.disposition == "handled") != (self.handler_unit_id is not None):
                fail(
                    "exception_handler_binding_contradiction",
                    "exception disposition disagrees with handler binding",
                    "bind a handler only for handled transitions",
                )
        elif any(
            value is not None
            for value in (self.disposition, self.handler_unit_id, self.guard)
        ):
            fail(
                "fail_open_exception_transition",
                "non-complete exceptional transition retains authority",
                "clear disposition, handler, and guard",
            )


@dataclass(frozen=True)
class ExceptionalTransitionRecordV3:
    record_id: str
    unit_sha256: str
    status: str
    authorizing: bool
    reachable: bool
    transitions: tuple[ExceptionalTransitionV3, ...]
    primary_blocker: PrimaryBlockerV3 | None
    dependencies: tuple[RecordDependencyV3, ...]

    def __post_init__(self) -> None:
        text(self.record_id, "exceptional-transition source unit ID")
        digest(self.unit_sha256, "exceptional-transition source unit SHA-256")
        if self.transitions != tuple(
            sorted(set(self.transitions), key=lambda row: row.transition_id)
        ):
            fail(
                "noncanonical_record_order",
                "exceptional transitions are duplicated or unsorted",
                "sort and deduplicate transitions by stable ID",
            )
        if any(row.unit_id != self.record_id for row in self.transitions):
            fail(
                "exception_unit_contradiction",
                "exceptional-transition inventory mixes source units",
                "place each transition under its exact source unit record",
            )
        if not self.reachable and self.transitions:
            fail(
                "fail_open_exception_reachability",
                "unreachable unit retains exceptional transitions",
                "emit transitions only for units in checked root closure",
            )
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=self.dependencies,
            context=f"exceptional-transition inventory {self.record_id!r}",
        )


def _transition_payload(value: ExceptionalTransitionV3) -> dict[str, Any]:
    return {
        "id": value.transition_id,
        "unit_id": value.unit_id,
        "fault_index": value.fault_index,
        "fault_sha256": value.fault_sha256,
        "status": value.status,
        "authorizing": value.authorizing,
        "disposition": value.disposition,
        "handler_unit_id": value.handler_unit_id,
        "guard": None if value.guard is None else value.guard.to_value(),
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
    }


def _parse_transition(value: Any) -> ExceptionalTransitionV3:
    row = strict_object(
        value,
        {
            "id",
            "unit_id",
            "fault_index",
            "fault_sha256",
            "status",
            "authorizing",
            "disposition",
            "handler_unit_id",
            "guard",
            "primary_blocker",
        },
        "exceptional transition",
    )
    authorizing = row["authorizing"]
    if not isinstance(authorizing, bool):
        fail(
            "record_schema_mismatch",
            "exceptional transition authorizing field is not Boolean",
            "emit true or false",
        )
    return ExceptionalTransitionV3(
        transition_id=text(row["id"], "exceptional-transition ID"),
        unit_id=text(row["unit_id"], "exceptional-transition unit ID"),
        fault_index=uint(row["fault_index"], "exceptional-transition fault index"),
        fault_sha256=digest(
            row["fault_sha256"], "exceptional-transition fault SHA-256"
        ),
        status=text(row["status"], "exceptional-transition status"),
        authorizing=authorizing,
        disposition=optional_text(
            row["disposition"], "exceptional-transition disposition"
        ),
        handler_unit_id=optional_text(
            row["handler_unit_id"], "exception handler unit ID"
        ),
        guard=(
            None if row["guard"] is None else CanonicalValueV3.of(row["guard"])
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
    )


def _encode_exception_record(value: ExceptionalTransitionRecordV3) -> dict[str, Any]:
    return {
        "schema": EXCEPTIONAL_TRANSITION_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "unit_sha256": value.unit_sha256,
        "status": value.status,
        "authorizing": value.authorizing,
        "reachable": value.reachable,
        "transitions": [_transition_payload(row) for row in value.transitions],
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
        "dependencies": encode_dependencies_v3(value.dependencies),
    }


def _decode_exception_record(value: Any) -> ExceptionalTransitionRecordV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "unit_sha256",
            "status",
            "authorizing",
            "reachable",
            "transitions",
            "primary_blocker",
            "dependencies",
        },
        "exceptional-transition record",
    )
    if row["schema"] != EXCEPTIONAL_TRANSITION_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not exceptional-transition-record-v3",
            "use EXCEPTIONAL_TRANSITION_CODEC_V3 with matching artifacts",
        )
    authorizing = row["authorizing"]
    reachable = row["reachable"]
    if not isinstance(authorizing, bool) or not isinstance(reachable, bool):
        fail(
            "record_schema_mismatch",
            "exceptional-transition Boolean fields are malformed",
            "emit exact authorizing and reachable Booleans",
        )
    return ExceptionalTransitionRecordV3(
        record_id=text(row["id"], "exceptional-transition source unit ID"),
        unit_sha256=digest(
            row["unit_sha256"], "exceptional-transition source unit SHA-256"
        ),
        status=text(row["status"], "exceptional-transition inventory status"),
        authorizing=authorizing,
        reachable=reachable,
        transitions=tuple(
            _parse_transition(item)
            for item in sequence(row["transitions"], "exceptional transitions")
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
        dependencies=decode_dependencies_v3(row["dependencies"]),
    )


EXCEPTIONAL_TRANSITION_CODEC_V3 = RecordCodecV3[ExceptionalTransitionRecordV3](
    decode=_decode_exception_record,
    encode=_encode_exception_record,
)


def _root_closure(context: PhaseContextV3) -> tuple[ArtifactRecordV3, LaunchRootClosureV3]:
    records = tuple(
        context.typed_records("root_closure", LAUNCH_ROOT_CLOSURE_CODEC_V3)
    )
    require_record_ids(
        (row.source for row in records),
        (records[0].record_id,) if len(records) == 1 else (),
        "exception root closure",
    )
    if len(records) != 1:
        fail(
            "incomplete_root_closure",
            f"exception analysis requires one root closure, observed {len(records)}",
            "rerun LAUNCH_ROOT_CLOSURE_PHASE_V3",
        )
    return records[0].source, records[0].value


def _record_or_none(
    context: PhaseContextV3, input_name: str, record_id: str
) -> ArtifactRecordV3 | None:
    return context.optional_record(input_name, record_id)


def _checked_transition(
    context: PhaseContextV3,
    *,
    semantic_index: SemanticIndexRecordV3,
    closure_record_id: str,
    closure: LaunchRootClosureV3,
    fault: FaultOccurrenceV3,
) -> tuple[ExceptionalTransitionV3, tuple[RecordDependencyV3, ...]]:
    fault_index = fault.index
    fault_sha256 = fault.fault_sha256
    transition_id = exceptional_transition_id_v3(
        semantic_index.record_id, fault_index, fault_sha256
    )
    evidence_dependency = RecordDependencyV3("exception_evidence", transition_id)
    dependencies: list[RecordDependencyV3] = [evidence_dependency]
    evidence_source = _record_or_none(
        context, evidence_dependency.input_name, evidence_dependency.record_id
    )
    if closure.status != "complete":
        blocker: PrimaryBlockerV3 | None = PrimaryBlockerV3(
            "violated" if closure.status == "violated" else "incomplete",
            "root_closure_not_complete",
            "root_closure",
            closure_record_id,
        )
    elif evidence_source is None:
        blocker = PrimaryBlockerV3(
            "incomplete",
            "exception_evidence_missing",
            evidence_dependency.input_name,
            evidence_dependency.record_id,
        )
    elif (
        manifest_blocker := manifest_blocker_v3(
            context,
            evidence_dependency.input_name,
            "exception_evidence_artifact_not_complete",
            evidence_dependency,
        )
    ) is not None:
        blocker = manifest_blocker
    else:
        evidence = EXCEPTION_EVIDENCE_CODEC_V3.read(evidence_source).value
        if (
            evidence.record_id != transition_id
            or evidence.unit_id != semantic_index.record_id
            or evidence.unit_sha256 != semantic_index.unit_sha256
            or evidence.fault_index != fault_index
            or evidence.fault_sha256 != fault_sha256
        ):
            blocker = PrimaryBlockerV3(
                "violated",
                "exception_evidence_binding_contradiction",
                evidence_dependency.input_name,
                evidence_dependency.record_id,
            )
        elif evidence.status != "complete":
            blocker = PrimaryBlockerV3(
                "violated" if evidence.status == "violated" else "incomplete",
                (
                    evidence.primary_blocker.code
                    if evidence.primary_blocker is not None
                    else "exception_evidence_incomplete"
                ),
                evidence_dependency.input_name,
                evidence_dependency.record_id,
            )
        elif evidence.disposition == "handled":
            assert evidence.handler_unit_id is not None
            handler_dependency = RecordDependencyV3(
                "semantic_index", evidence.handler_unit_id
            )
            dependencies.append(handler_dependency)
            handler_source = _record_or_none(
                context, handler_dependency.input_name, handler_dependency.record_id
            )
            if handler_source is None:
                blocker = PrimaryBlockerV3(
                    "violated",
                    "exception_handler_unit_missing",
                    handler_dependency.input_name,
                    handler_dependency.record_id,
                )
            else:
                handler = SEMANTIC_INDEX_CODEC_V3.read(handler_source).value
                blocker = (
                    None
                    if handler.unit_sha256 == evidence.handler_unit_sha256
                    else PrimaryBlockerV3(
                        "violated",
                        "exception_handler_binding_contradiction",
                        handler_dependency.input_name,
                        handler_dependency.record_id,
                    )
                )
        else:
            blocker = None
    complete = blocker is None
    disposition = None
    handler_unit_id = None
    guard = None
    if complete:
        assert evidence_source is not None
        evidence = EXCEPTION_EVIDENCE_CODEC_V3.read(evidence_source).value
        disposition = evidence.disposition
        handler_unit_id = evidence.handler_unit_id
        guard = evidence.guard
    return (
        ExceptionalTransitionV3(
            transition_id=transition_id,
            unit_id=semantic_index.record_id,
            fault_index=fault_index,
            fault_sha256=fault_sha256,
            status="complete" if complete else blocker.status,
            authorizing=complete,
            disposition=disposition,
            handler_unit_id=handler_unit_id,
            guard=guard,
            primary_blocker=blocker,
        ),
        canonical_dependencies_v3(dependencies),
    )


def _derive_exception_record(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ExceptionalTransitionRecordV3:
    semantic_index = context.typed_record(
        "semantic_index", source.record_id, SEMANTIC_INDEX_CODEC_V3
    ).value
    closure_source, closure = _root_closure(context)
    dependencies = [
        RecordDependencyV3("semantic_index", semantic_index.record_id),
        RecordDependencyV3("root_closure", closure_source.record_id),
    ]
    reachable = closure.contains_reachable_unit(semantic_index.record_id)
    blockers: list[PrimaryBlockerV3] = []
    for input_name, dependency, code in (
        (
            "semantic_index",
            dependencies[0],
            "semantic_index_artifact_not_complete",
        ),
        (
            "root_closure",
            dependencies[1],
            "root_closure_artifact_not_complete",
        ),
    ):
        manifest_blocker = manifest_blocker_v3(
            context, input_name, code, dependency
        )
        if manifest_blocker is not None:
            blockers.append(manifest_blocker)
    if closure.status != "complete":
        blockers.append(
            PrimaryBlockerV3(
                "violated" if closure.status == "violated" else "incomplete",
                "root_closure_not_complete",
                "root_closure",
                closure_source.record_id,
            )
        )
    transitions: list[ExceptionalTransitionV3] = []
    if reachable:
        for fault in semantic_index.faults:
            transition, exact_dependencies = _checked_transition(
                context,
                semantic_index=semantic_index,
                closure_record_id=closure_source.record_id,
                closure=closure,
                fault=fault,
            )
            transitions.append(transition)
            dependencies.extend(exact_dependencies)
            if transition.primary_blocker is not None:
                blockers.append(transition.primary_blocker)
    primary = aggregate_blockers_v3(blockers)
    status = "complete" if primary is None else primary.status
    return ExceptionalTransitionRecordV3(
        record_id=semantic_index.record_id,
        unit_sha256=semantic_index.unit_sha256,
        status=status,
        authorizing=status == "complete",
        reachable=reachable,
        transitions=tuple(sorted(transitions, key=lambda row: row.transition_id)),
        primary_blocker=primary,
        dependencies=canonical_dependencies_v3(dependencies),
    )


def _transform_exceptional_transitions(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    value = _derive_exception_record(context, source)
    return EXCEPTIONAL_TRANSITION_CODEC_V3.write(
        source.record_id, value, dependencies=value.dependencies
    )


def _all_exact_fault_ids(
    context: PhaseContextV3,
    semantic_records: tuple[ArtifactRecordV3, ...],
) -> set[str]:
    result: set[str] = set()
    for source in semantic_records:
        semantic_index = context.typed_record(
            "semantic_index", source.record_id, SEMANTIC_INDEX_CODEC_V3
        ).value
        for fault in semantic_index.faults:
            result.add(
                exceptional_transition_id_v3(
                    semantic_index.record_id, fault.index, fault.fault_sha256
                )
            )
    return result


def check_exceptional_transitions_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    semantic_records = sorted_records(context.records("semantic_index"))
    outputs = sorted_records(reader.iter_records())
    require_record_ids(
        outputs,
        (row.record_id for row in semantic_records),
        "exceptional-transition inventories",
    )
    for source, output in zip(semantic_records, outputs, strict=True):
        expected = _derive_exception_record(context, source)
        submitted = EXCEPTIONAL_TRANSITION_CODEC_V3.read(output).value
        if submitted != expected:
            fail(
                "exceptional_transition_contradiction",
                f"exceptional transitions for {output.record_id!r} are stale",
                "rerun exceptional-transition analysis from exact inputs",
            )
        if output.dependencies != expected.dependencies:
            fail(
                "incomplete_record_dependencies",
                f"exceptional transitions for {output.record_id!r} have stale dependencies",
                "let EXCEPTIONAL_TRANSITIONS_PHASE_V3 attach exact dependencies",
            )
    if context.manifest("exception_evidence").record_count == 0:
        return
    evidence_records = sorted_records(context.records("exception_evidence"))
    known_ids = _all_exact_fault_ids(context, semantic_records)
    unknown = sorted({row.record_id for row in evidence_records} - known_ids)
    if unknown:
        fail(
            "unknown_exception_evidence",
            f"exception evidence names absent exact fault sites {unknown!r}",
            "remove stale evidence or regenerate it from exact fault records",
        )


EXCEPTIONAL_TRANSITIONS_PHASE_V3 = map_units(
    name="exceptional-transitions-v3",
    version="1",
    source_input="semantic_index",
    input_artifact_kinds={
        "exception_evidence": EXCEPTION_EVIDENCE_ARTIFACT_KIND_V3,
        "root_closure": LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
        "semantic_index": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    },
    output_artifact_kind=EXCEPTIONAL_TRANSITIONS_ARTIFACT_KIND_V3,
    transform=_transform_exceptional_transitions,
    completeness=check_exceptional_transitions_completeness_v3,
)


__all__ = [
    "EXCEPTIONAL_TRANSITION_CODEC_V3",
    "EXCEPTIONAL_TRANSITION_RECORD_V3_SCHEMA",
    "EXCEPTIONAL_TRANSITIONS_ARTIFACT_KIND_V3",
    "EXCEPTIONAL_TRANSITIONS_PHASE_V3",
    "EXCEPTION_EVIDENCE_ARTIFACT_KIND_V3",
    "EXCEPTION_EVIDENCE_CODEC_V3",
    "EXCEPTION_EVIDENCE_RECORD_V3_SCHEMA",
    "ExceptionEvidenceV3",
    "ExceptionalTransitionRecordV3",
    "ExceptionalTransitionV3",
    "check_exceptional_transitions_completeness_v3",
    "exceptional_transition_id_v3",
]
