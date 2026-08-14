"""Compact checked semantic facts shared by downstream authority phases."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    CanonicalValueV3,
    canonical_sha256_v3,
)
from ..phase_framework_v3 import PhaseContextV3, RecordCodecV3, map_units
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
from .exact_units import EXACT_UNIT_CODEC_V3, ExactUnitV3
from .identities import indirect_exit_id_v3


SEMANTIC_INDEX_RECORD_V3_SCHEMA = "spaghetti-extractor-semantic-index-record-v3"
SEMANTIC_INDEX_ARTIFACT_KIND_V3 = "semantic-index-v3"


@dataclass(frozen=True, order=True)
class InstructionOccurrenceV3:
    index: int
    instruction_sha256: str
    rva_start: int
    rva_end: int

    def __post_init__(self) -> None:
        uint(self.index, "instruction occurrence index")
        digest(self.instruction_sha256, "instruction occurrence SHA-256")
        uint(self.rva_start, "instruction occurrence start RVA")
        uint(self.rva_end, "instruction occurrence end RVA")
        if self.rva_end <= self.rva_start:
            fail(
                "record_schema_mismatch",
                "instruction occurrence has an empty or reversed span",
                "regenerate the semantic index from exact-unit authority",
            )

    def to_payload(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "instruction_sha256": self.instruction_sha256,
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
        }

    @classmethod
    def parse(cls, value: Any) -> "InstructionOccurrenceV3":
        row = strict_object(
            value,
            {"index", "instruction_sha256", "rva_start", "rva_end"},
            "instruction occurrence",
        )
        return cls(
            uint(row["index"], "instruction occurrence index"),
            digest(row["instruction_sha256"], "instruction occurrence SHA-256"),
            uint(row["rva_start"], "instruction occurrence start RVA"),
            uint(row["rva_end"], "instruction occurrence end RVA"),
        )


@dataclass(frozen=True, order=True)
class FaultOccurrenceV3:
    index: int
    fault_sha256: str

    def __post_init__(self) -> None:
        uint(self.index, "fault occurrence index")
        digest(self.fault_sha256, "fault occurrence SHA-256")

    def to_payload(self) -> dict[str, Any]:
        return {"index": self.index, "fault_sha256": self.fault_sha256}

    @classmethod
    def parse(cls, value: Any) -> "FaultOccurrenceV3":
        row = strict_object(value, {"index", "fault_sha256"}, "fault occurrence")
        return cls(
            uint(row["index"], "fault occurrence index"),
            digest(row["fault_sha256"], "fault occurrence SHA-256"),
        )


@dataclass(frozen=True, order=True)
class InternalCallOccurrenceV3:
    event_index: int
    target_rva: int | None

    def __post_init__(self) -> None:
        uint(self.event_index, "internal-call event index")
        if self.target_rva is not None:
            uint(self.target_rva, "internal-call target RVA")

    def to_payload(self) -> dict[str, Any]:
        return {"event_index": self.event_index, "target_rva": self.target_rva}

    @classmethod
    def parse(cls, value: Any) -> "InternalCallOccurrenceV3":
        row = strict_object(value, {"event_index", "target_rva"}, "internal call")
        target = row["target_rva"]
        return cls(
            uint(row["event_index"], "internal-call event index"),
            None if target is None else uint(target, "internal-call target RVA"),
        )


@dataclass(frozen=True)
class IndirectExitOccurrenceV3:
    exit_id: str
    event_index: int | None
    transfer_kind: str
    target_expression: CanonicalValueV3

    def __post_init__(self) -> None:
        text(self.exit_id, "indirect-exit ID")
        if self.event_index is not None:
            uint(self.event_index, "indirect-exit event index")
        text(self.transfer_kind, "indirect-exit transfer kind")

    def to_payload(self) -> dict[str, Any]:
        return {
            "exit_id": self.exit_id,
            "event_index": self.event_index,
            "transfer_kind": self.transfer_kind,
            "target_expression": self.target_expression.to_value(),
        }

    @classmethod
    def parse(cls, value: Any) -> "IndirectExitOccurrenceV3":
        row = strict_object(
            value,
            {"exit_id", "event_index", "transfer_kind", "target_expression"},
            "indirect exit",
        )
        event_index = row["event_index"]
        return cls(
            text(row["exit_id"], "indirect-exit ID"),
            None
            if event_index is None
            else uint(event_index, "indirect-exit event index"),
            text(row["transfer_kind"], "indirect-exit transfer kind"),
            CanonicalValueV3.of(row["target_expression"]),
        )


@dataclass(frozen=True)
class SemanticIndexRecordV3:
    record_id: str
    unit_sha256: str
    pe_sha256: str
    unit_ir_sha256: str
    rva_start: int
    rva_end: int
    unit_status: str
    instructions: tuple[InstructionOccurrenceV3, ...]
    faults: tuple[FaultOccurrenceV3, ...]
    direct_target_rvas: tuple[int, ...]
    internal_calls: tuple[InternalCallOccurrenceV3, ...]
    indirect_exits: tuple[IndirectExitOccurrenceV3, ...]

    def __post_init__(self) -> None:
        text(self.record_id, "semantic-index unit ID")
        digest(self.unit_sha256, "semantic-index unit SHA-256")
        digest(self.pe_sha256, "semantic-index PE SHA-256")
        digest(self.unit_ir_sha256, "semantic-index unit-IR SHA-256")
        uint(self.rva_start, "semantic-index start RVA")
        uint(self.rva_end, "semantic-index end RVA")
        if self.rva_end <= self.rva_start:
            fail(
                "record_schema_mismatch",
                "semantic-index unit has an empty or reversed span",
                "regenerate it from exact-unit authority",
            )
        text(self.unit_status, "semantic-index unit status")
        if self.instructions != tuple(
            sorted(set(self.instructions), key=lambda row: row.index)
        ) or tuple(row.index for row in self.instructions) != tuple(
            range(len(self.instructions))
        ):
            fail(
                "noncanonical_record_order",
                "semantic-index instructions are duplicated, unsorted, or non-contiguous",
                "preserve exact instruction order",
            )
        if self.faults != tuple(sorted(set(self.faults), key=lambda row: row.index)):
            fail(
                "noncanonical_record_order",
                "semantic-index faults are duplicated or unsorted",
                "preserve exact fault order",
            )
        if self.direct_target_rvas != tuple(sorted(set(self.direct_target_rvas))):
            fail(
                "noncanonical_record_order",
                "semantic-index direct targets are duplicated or unsorted",
                "sort and deduplicate direct target RVAs",
            )
        if self.internal_calls != tuple(
            sorted(set(self.internal_calls), key=lambda row: row.event_index)
        ):
            fail(
                "noncanonical_record_order",
                "semantic-index internal calls are duplicated or unsorted",
                "preserve exact external-event order",
            )
        if self.indirect_exits != tuple(
            sorted(self.indirect_exits, key=lambda row: row.exit_id)
        ) or len({row.exit_id for row in self.indirect_exits}) != len(
            self.indirect_exits
        ):
            fail(
                "noncanonical_record_order",
                "semantic-index indirect exits are duplicated or unsorted",
                "sort exact indirect exits by stable ID",
            )


def _encode(value: SemanticIndexRecordV3) -> dict[str, Any]:
    return {
        "schema": SEMANTIC_INDEX_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "unit_sha256": value.unit_sha256,
        "pe_sha256": value.pe_sha256,
        "unit_ir_sha256": value.unit_ir_sha256,
        "rva_start": value.rva_start,
        "rva_end": value.rva_end,
        "unit_status": value.unit_status,
        "instructions": [row.to_payload() for row in value.instructions],
        "faults": [row.to_payload() for row in value.faults],
        "direct_target_rvas": list(value.direct_target_rvas),
        "internal_calls": [row.to_payload() for row in value.internal_calls],
        "indirect_exits": [row.to_payload() for row in value.indirect_exits],
    }


def _decode(value: Any) -> SemanticIndexRecordV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "unit_sha256",
            "pe_sha256",
            "unit_ir_sha256",
            "rva_start",
            "rva_end",
            "unit_status",
            "instructions",
            "faults",
            "direct_target_rvas",
            "internal_calls",
            "indirect_exits",
        },
        "semantic-index record",
    )
    if row["schema"] != SEMANTIC_INDEX_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not a semantic-index-record-v3",
            "use SEMANTIC_INDEX_CODEC_V3 only with semantic-index-v3 artifacts",
        )
    return SemanticIndexRecordV3(
        record_id=text(row["id"], "semantic-index unit ID"),
        unit_sha256=digest(row["unit_sha256"], "semantic-index unit SHA-256"),
        pe_sha256=digest(row["pe_sha256"], "semantic-index PE SHA-256"),
        unit_ir_sha256=digest(row["unit_ir_sha256"], "semantic-index unit-IR SHA-256"),
        rva_start=uint(row["rva_start"], "semantic-index start RVA"),
        rva_end=uint(row["rva_end"], "semantic-index end RVA"),
        unit_status=text(row["unit_status"], "semantic-index unit status"),
        instructions=tuple(
            InstructionOccurrenceV3.parse(item)
            for item in sequence(row["instructions"], "semantic-index instructions")
        ),
        faults=tuple(
            FaultOccurrenceV3.parse(item)
            for item in sequence(row["faults"], "semantic-index faults")
        ),
        direct_target_rvas=tuple(
            uint(item, "semantic-index direct target RVA")
            for item in sequence(
                row["direct_target_rvas"], "semantic-index direct targets"
            )
        ),
        internal_calls=tuple(
            InternalCallOccurrenceV3.parse(item)
            for item in sequence(row["internal_calls"], "semantic-index internal calls")
        ),
        indirect_exits=tuple(
            IndirectExitOccurrenceV3.parse(item)
            for item in sequence(row["indirect_exits"], "semantic-index indirect exits")
        ),
    )


SEMANTIC_INDEX_CODEC_V3 = RecordCodecV3[SemanticIndexRecordV3](
    decode=_decode,
    encode=_encode,
)


def semantic_universe_sha256_v3(
    records: Iterable[SemanticIndexRecordV3],
) -> str:
    """Identify the complete checked unit universe without carrying raw IR."""

    rows = tuple(sorted(records, key=lambda row: row.record_id))
    if not rows or len({row.record_id for row in rows}) != len(rows):
        fail(
            "invalid_semantic_universe",
            "semantic-index universe is empty or repeats unit IDs",
            "provide one checked semantic record for every structural unit",
        )
    pe_sha256s = {row.pe_sha256 for row in rows}
    if len(pe_sha256s) != 1:
        fail(
            "semantic_index_binary_mismatch",
            "semantic-index universe mixes PE identities",
            "partition semantic records by their authoritative PE binding",
        )
    return canonical_sha256_v3(
        {
            "pe_sha256": rows[0].pe_sha256,
            "units": [
                {"id": row.record_id, "unit_ir_sha256": row.unit_ir_sha256}
                for row in rows
            ],
        }
    )


def _indirect_exit(
    exact: ExactUnitV3,
    *,
    event_index: int | None,
    transfer_kind: Any,
    target_expression: Any,
) -> IndirectExitOccurrenceV3:
    kind = text(transfer_kind, "exact indirect-exit kind")
    identity = {
        "source_unit_id": exact.unit_id,
        "source_rva": exact.rva_start,
        "source_event_index": event_index,
        "kind": kind,
        "target_expression": target_expression,
    }
    return IndirectExitOccurrenceV3(
        exit_id=indirect_exit_id_v3(identity),
        event_index=event_index,
        transfer_kind=kind,
        target_expression=CanonicalValueV3.of(target_expression),
    )


def derive_semantic_index_v3(exact: ExactUnitV3) -> SemanticIndexRecordV3:
    unit = mapping(exact.unit.to_value(), "exact semantic-index unit")
    instructions: list[InstructionOccurrenceV3] = []
    cursor = exact.rva_start
    for index, raw_value in enumerate(
        sequence(unit.get("instructions"), "exact instructions")
    ):
        raw = mapping(raw_value, "exact instruction")
        start = uint(raw.get("rva_start"), "exact instruction start RVA")
        end = uint(raw.get("rva_end"), "exact instruction end RVA")
        if start != cursor or end > exact.rva_end or end <= start:
            fail(
                "exact_instruction_inventory_contradiction",
                f"instruction {index} in {exact.unit_id!r} does not partition its unit span",
                "repair the exact decode before producing semantic indexes",
            )
        cursor = end
        instructions.append(
            InstructionOccurrenceV3(index, canonical_sha256_v3(raw), start, end)
        )
    # Preserve an empty decoder inventory as checked evidence.  Downstream ISA
    # qualification rejects a reachable empty unit; aborting this projection
    # would hide that useful fail-closed frontier from the authority graph.
    if instructions and cursor != exact.rva_end:
        fail(
            "exact_instruction_inventory_contradiction",
            f"instructions in {exact.unit_id!r} do not cover its exact span",
            "repair the exact decode before producing semantic indexes",
        )
    control = mapping(unit.get("control"), "exact unit control")
    direct_targets = tuple(
        sorted(
            {
                uint(item, "exact direct target RVA")
                for item in sequence(
                    control.get("direct_targets"), "exact direct targets"
                )
            }
        )
    )
    semantics = mapping(unit.get("semantics"), "exact unit semantics")
    faults = tuple(
        FaultOccurrenceV3(index, canonical_sha256_v3(mapping(raw, "exact fault")))
        for index, raw in enumerate(sequence(semantics.get("faults"), "exact faults"))
    )
    outcome = mapping(semantics.get("outcome"), "exact unit outcome")
    exits: list[IndirectExitOccurrenceV3] = []
    if control.get("has_indirect_target") is True:
        exits.append(
            _indirect_exit(
                exact,
                event_index=None,
                transfer_kind=control.get("kind"),
                target_expression=outcome.get("target"),
            )
        )
    calls: list[InternalCallOccurrenceV3] = []
    for event_index, raw_value in enumerate(
        sequence(semantics.get("external_events"), "exact external events")
    ):
        raw = mapping(raw_value, "exact external event")
        kind = raw.get("kind")
        if kind == "internal_call":
            target = raw.get("target_rva")
            calls.append(
                InternalCallOccurrenceV3(
                    event_index,
                    target
                    if isinstance(target, int) and not isinstance(target, bool) and target >= 0
                    else None,
                )
            )
        elif kind in {"indirect_call", "indirect_jump"}:
            exits.append(
                _indirect_exit(
                    exact,
                    event_index=event_index,
                    transfer_kind=kind,
                    target_expression=raw.get("target"),
                )
            )
    return SemanticIndexRecordV3(
        record_id=exact.unit_id,
        unit_sha256=exact.unit_sha256,
        pe_sha256=exact.pe_sha256,
        unit_ir_sha256=exact.unit_ir_sha256,
        rva_start=exact.rva_start,
        rva_end=exact.rva_end,
        unit_status=text(unit.get("status"), "exact unit status"),
        instructions=tuple(instructions),
        faults=faults,
        direct_target_rvas=direct_targets,
        internal_calls=tuple(calls),
        indirect_exits=tuple(sorted(exits, key=lambda row: row.exit_id)),
    )


def _transform(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    exact = context.typed_record("exact_units", source, EXACT_UNIT_CODEC_V3).value
    return SEMANTIC_INDEX_CODEC_V3.write(
        source.record_id, derive_semantic_index_v3(exact)
    )


def check_semantic_index_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    exact_records = sorted_records(context.records("exact_units"))
    outputs = sorted_records(reader.iter_records())
    require_record_ids(
        outputs,
        (row.record_id for row in exact_records),
        "semantic-index records",
    )
    for exact_source, output in zip(exact_records, outputs, strict=True):
        expected = derive_semantic_index_v3(
            context.typed_record(
                "exact_units", exact_source.record_id, EXACT_UNIT_CODEC_V3
            ).value
        )
        submitted = SEMANTIC_INDEX_CODEC_V3.read(output).value
        if submitted != expected:
            fail(
                "semantic_index_contradiction",
                f"semantic index for {output.record_id!r} is stale",
                "rebuild it from exact-unit authority",
            )
        if (
            len(output.dependencies) != 1
            or output.dependencies[0].input_name != "exact_units"
            or output.dependencies[0].record_id != output.record_id
        ):
            fail(
                "incomplete_record_dependencies",
                f"semantic index {output.record_id!r} lacks its exact-unit dependency",
                "let the map_units runner attach its exact source",
            )


SEMANTIC_INDEX_PHASE_V3 = map_units(
    name="semantic-index-v3",
    version="1",
    source_input="exact_units",
    input_artifact_kinds={"exact_units": "exact-units-v3"},
    output_artifact_kind=SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    transform=_transform,
    completeness=check_semantic_index_completeness_v3,
)


__all__ = [
    "FaultOccurrenceV3",
    "IndirectExitOccurrenceV3",
    "InstructionOccurrenceV3",
    "InternalCallOccurrenceV3",
    "SEMANTIC_INDEX_ARTIFACT_KIND_V3",
    "SEMANTIC_INDEX_CODEC_V3",
    "SEMANTIC_INDEX_PHASE_V3",
    "SEMANTIC_INDEX_RECORD_V3_SCHEMA",
    "SemanticIndexRecordV3",
    "check_semantic_index_completeness_v3",
    "derive_semantic_index_v3",
    "semantic_universe_sha256_v3",
]
