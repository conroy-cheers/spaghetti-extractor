"""Checked reverse index of exact internal-call entry frames.

External thunk and callback analysis needs facts from callers that frequently
live in another structural pack.  Re-scanning a pack-local transition input is
both incomplete and expensive.  This phase checks the complete transition
inventory once and exports one compact, keyed record per semantic unit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..artifacts.artifact_set import (
    ArtifactRecordV3,
    CanonicalValueV3,
    RecordDependencyV3,
)
from ..artifacts.io import ArtifactSetReaderV3
from ..artifacts.phases import PhaseContextV3, RecordCodecV3, reduce
from ._schema import (
    digest,
    fail,
    mapping,
    require_record_ids,
    sequence,
    sorted_records,
    strict_object,
    text,
    uint,
)
from .semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    SemanticIndexRecordV3,
)
from .transition_records import (
    TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionSummaryRecordV3,
)


INCOMING_CALL_FRAME_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-incoming-call-frame-record-v3"
)
INCOMING_CALL_FRAMES_ARTIFACT_KIND_V3 = "incoming-call-frames-v3"


@dataclass(frozen=True)
class IncomingCallFrameV3:
    """Exact caller-side state at one direct internal call boundary."""

    source_unit_id: str
    source_unit_sha256: str
    source_event_index: int
    source_status: str
    event: CanonicalValueV3
    ordered_events: tuple[CanonicalValueV3, ...]

    def __post_init__(self) -> None:
        text(self.source_unit_id, "incoming-call source unit ID")
        digest(self.source_unit_sha256, "incoming-call source unit SHA-256")
        uint(self.source_event_index, "incoming-call source event index")
        if self.source_status not in {"complete", "incomplete"}:
            fail(
                "record_schema_mismatch",
                f"incoming-call source status is {self.source_status!r}",
                "use complete or incomplete",
            )
        event = mapping(self.event.to_value(), "incoming-call exact event")
        if event.get("kind") != "internal_call":
            fail(
                "incoming_call_frame_contradiction",
                "incoming-call frame does not bind an internal_call event",
                "derive frames only from exact internal-call exits",
            )

    @property
    def order_key(self) -> tuple[str, int]:
        return self.source_unit_id, self.source_event_index

    def to_payload(self) -> dict[str, Any]:
        return {
            "source_unit_id": self.source_unit_id,
            "source_unit_sha256": self.source_unit_sha256,
            "source_event_index": self.source_event_index,
            "source_status": self.source_status,
            "event": self.event.to_value(),
            "ordered_events": [row.to_value() for row in self.ordered_events],
        }

    @classmethod
    def parse(cls, value: Any) -> "IncomingCallFrameV3":
        row = strict_object(
            value,
            {
                "source_unit_id",
                "source_unit_sha256",
                "source_event_index",
                "source_status",
                "event",
                "ordered_events",
            },
            "incoming-call frame",
        )
        return cls(
            source_unit_id=text(
                row["source_unit_id"], "incoming-call source unit ID"
            ),
            source_unit_sha256=digest(
                row["source_unit_sha256"],
                "incoming-call source unit SHA-256",
            ),
            source_event_index=uint(
                row["source_event_index"], "incoming-call source event index"
            ),
            source_status=text(
                row["source_status"], "incoming-call source status"
            ),
            event=CanonicalValueV3.of(row["event"]),
            ordered_events=tuple(
                CanonicalValueV3.of(item)
                for item in sequence(
                    row["ordered_events"], "incoming-call ordered events"
                )
            ),
        )


@dataclass(frozen=True)
class IncomingCallFrameRecordV3:
    """Complete incoming direct-call inventory for one semantic unit."""

    record_id: str
    unit_sha256: str
    rva_start: int
    frames: tuple[IncomingCallFrameV3, ...]

    def __post_init__(self) -> None:
        text(self.record_id, "incoming-call target unit ID")
        digest(self.unit_sha256, "incoming-call target unit SHA-256")
        uint(self.rva_start, "incoming-call target RVA")
        if self.frames != tuple(
            sorted(set(self.frames), key=lambda row: row.order_key)
        ):
            fail(
                "noncanonical_record_order",
                "incoming-call frames are duplicated or unsorted",
                "sort and deduplicate frames by source unit and event index",
            )


def _encode(value: IncomingCallFrameRecordV3) -> dict[str, Any]:
    return {
        "schema": INCOMING_CALL_FRAME_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "unit_sha256": value.unit_sha256,
        "rva_start": value.rva_start,
        "frames": [row.to_payload() for row in value.frames],
    }


def _decode(value: Any) -> IncomingCallFrameRecordV3:
    row = strict_object(
        value,
        {"schema", "id", "unit_sha256", "rva_start", "frames"},
        "incoming-call frame record",
    )
    if row["schema"] != INCOMING_CALL_FRAME_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not an incoming-call-frame-record-v3",
            "use INCOMING_CALL_FRAME_CODEC_V3 with incoming-call-frames-v3",
        )
    return IncomingCallFrameRecordV3(
        record_id=text(row["id"], "incoming-call target unit ID"),
        unit_sha256=digest(
            row["unit_sha256"], "incoming-call target unit SHA-256"
        ),
        rva_start=uint(row["rva_start"], "incoming-call target RVA"),
        frames=tuple(
            IncomingCallFrameV3.parse(item)
            for item in sequence(row["frames"], "incoming-call frames")
        ),
    )


INCOMING_CALL_FRAME_CODEC_V3 = RecordCodecV3[IncomingCallFrameRecordV3](
    decode=_decode,
    encode=_encode,
)


def _checked_inputs(
    context: PhaseContextV3,
) -> tuple[
    tuple[SemanticIndexRecordV3, ...],
    dict[str, TransitionSummaryRecordV3],
]:
    semantic = tuple(
        SEMANTIC_INDEX_CODEC_V3.read(source).value
        for source in sorted_records(context.records("semantic_index"))
    )
    transition_sources = tuple(
        sorted_records(context.records("transition_summaries"))
    )
    transitions = {
        row.record_id: row
        for row in (
            TRANSITION_SUMMARY_CODEC_V3.read(source).value
            for source in transition_sources
        )
    }
    require_record_ids(
        transition_sources,
        (row.record_id for row in semantic),
        "incoming-call transition inventories",
    )
    starts = [row.rva_start for row in semantic]
    if len(set(starts)) != len(starts):
        fail(
            "semantic_unit_rva_ambiguous",
            "semantic units share an entry RVA in the incoming-call index",
            "repair the exact semantic index",
        )
    return semantic, transitions


def _derive_records(context: PhaseContextV3) -> tuple[ArtifactRecordV3, ...]:
    semantic, transitions = _checked_inputs(context)
    target_by_rva = {row.rva_start: row for row in semantic}
    frames_by_target: dict[str, list[IncomingCallFrameV3]] = {
        row.record_id: [] for row in semantic
    }
    dependencies_by_target: dict[str, set[RecordDependencyV3]] = {
        row.record_id: {
            RecordDependencyV3("semantic_index", row.record_id)
        }
        for row in semantic
    }
    semantic_by_id = {row.record_id: row for row in semantic}
    for source in semantic:
        summary = transitions[source.record_id]
        if (
            summary.unit_id != source.record_id
            or summary.unit_sha256 != source.unit_sha256
            or summary.pe_sha256 != source.pe_sha256
            or summary.unit_ir_sha256 != source.unit_ir_sha256
            or summary.rva_start != source.rva_start
            or summary.rva_end != source.rva_end
        ):
            fail(
                "transition_summary_unit_contradiction",
                f"transition summary {source.record_id!r} contradicts its semantic unit",
                "regenerate checked transition summaries",
            )
        ordered_events = tuple(row.exact_record for row in summary.ordered_events)
        for exit_row in summary.exits:
            if (
                exit_row.source_kind != "external_event"
                or exit_row.source_index is None
                or exit_row.transfer_kind != "internal_call"
            ):
                continue
            event = mapping(
                exit_row.exact_record.to_value(), "exact internal-call event"
            )
            target_rva = event.get("target_rva")
            target = (
                target_by_rva.get(target_rva)
                if isinstance(target_rva, int)
                and not isinstance(target_rva, bool)
                else None
            )
            if target is None:
                continue
            frames_by_target[target.record_id].append(
                IncomingCallFrameV3(
                    source_unit_id=source.record_id,
                    source_unit_sha256=source.unit_sha256,
                    source_event_index=exit_row.source_index,
                    source_status=(
                        "complete"
                        if source.unit_status == "qualified"
                        and summary.status == "complete"
                        else "incomplete"
                    ),
                    event=exit_row.exact_record,
                    ordered_events=ordered_events,
                )
            )
            dependencies_by_target[target.record_id].update(
                {
                    RecordDependencyV3("semantic_index", source.record_id),
                    RecordDependencyV3(
                        "transition_summaries", source.record_id
                    ),
                }
            )
    result: list[ArtifactRecordV3] = []
    for record_id in sorted(frames_by_target):
        target = semantic_by_id[record_id]
        value = IncomingCallFrameRecordV3(
            record_id=record_id,
            unit_sha256=target.unit_sha256,
            rva_start=target.rva_start,
            frames=tuple(
                sorted(
                    set(frames_by_target[record_id]),
                    key=lambda row: row.order_key,
                )
            ),
        )
        result.append(
            INCOMING_CALL_FRAME_CODEC_V3.write(
                record_id,
                value,
                dependencies=tuple(sorted(dependencies_by_target[record_id])),
            )
        )
    return tuple(result)


def check_incoming_call_frames_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    expected = _derive_records(context)
    submitted = tuple(sorted_records(reader.iter_records()))
    require_record_ids(
        submitted,
        (row.record_id for row in expected),
        "incoming-call frame inventories",
    )
    for actual, wanted in zip(submitted, expected, strict=True):
        if actual != wanted:
            fail(
                "incoming_call_frame_index_contradiction",
                f"incoming-call frame record {actual.record_id!r} is stale",
                "regenerate the index from exact semantic and transition artifacts",
            )


INCOMING_CALL_FRAMES_PHASE_V3 = reduce(
    name="incoming-call-frames-v3",
    version="1",
    input_artifact_kinds={
        "semantic_index": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
        "transition_summaries": TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    },
    output_artifact_kind=INCOMING_CALL_FRAMES_ARTIFACT_KIND_V3,
    transform=_derive_records,
    completeness=check_incoming_call_frames_completeness_v3,
    dependency_scope="artifact",
)


__all__ = [
    "INCOMING_CALL_FRAME_CODEC_V3",
    "INCOMING_CALL_FRAME_RECORD_V3_SCHEMA",
    "INCOMING_CALL_FRAMES_ARTIFACT_KIND_V3",
    "INCOMING_CALL_FRAMES_PHASE_V3",
    "IncomingCallFrameRecordV3",
    "IncomingCallFrameV3",
    "check_incoming_call_frames_completeness_v3",
]
