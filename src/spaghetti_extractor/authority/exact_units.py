"""Typed exact-unit records and their recordized authority phase."""

from __future__ import annotations

import hashlib
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
    sorted_records,
    strict_object,
    text,
    uint,
)


EXACT_UNIT_RECORD_V3_SCHEMA = "spaghetti-extractor-exact-unit-record-v3"
EXACT_UNITS_ARTIFACT_KIND_V3 = "exact-units-v3"


@dataclass(frozen=True)
class ExactUnitV3:
    """One canonical machine-IR unit bound only to its source and PE."""

    record_id: str
    unit_id: str
    pe_sha256: str
    unit_ir_sha256: str
    unit_sha256: str
    instruction_bytes_sha256: str
    rva_start: int
    rva_end: int
    unit: CanonicalValueV3

    def __post_init__(self) -> None:
        text(self.record_id, "exact-unit record ID")
        text(self.unit_id, "exact-unit unit ID")
        if self.record_id != self.unit_id:
            fail(
                "stale_record_id",
                f"exact-unit record {self.record_id!r} does not use unit ID {self.unit_id!r}",
                "use the canonical machine-IR unit ID as the artifact record ID",
            )
        digest(self.pe_sha256, "exact-unit PE SHA-256")
        digest(self.unit_ir_sha256, "exact-unit source IR SHA-256")
        digest(self.unit_sha256, "exact-unit content SHA-256")
        digest(
            self.instruction_bytes_sha256,
            "exact-unit instruction-byte SHA-256",
        )
        uint(self.rva_start, "exact-unit start RVA")
        uint(self.rva_end, "exact-unit end RVA")
        if self.rva_end <= self.rva_start:
            fail(
                "record_schema_mismatch",
                f"exact unit {self.unit_id!r} has an empty or reversed RVA span",
                "repair the canonical machine-IR source span",
            )
        row = mapping(self.unit.to_value(), "exact-unit canonical unit")
        if row.get("id") != self.unit_id:
            fail(
                "unit_binding_mismatch",
                f"exact-unit payload ID does not equal {self.unit_id!r}",
                "regenerate the exact unit from its canonical source record",
            )
        # CanonicalValueV3 has already validated that ``data`` is the unique
        # canonical encoding.  Hash those authoritative bytes rather than
        # normalizing and serializing the full machine-IR tree again.
        canonical_unit_sha256 = hashlib.sha256(self.unit.data).hexdigest()
        if canonical_unit_sha256 != self.unit_ir_sha256:
            fail(
                "stale_unit_ir_digest",
                f"exact-unit source digest for {self.unit_id!r} does not bind its payload",
                "regenerate the exact unit from its canonical source record",
            )
        if canonical_unit_sha256 != self.unit_sha256:
            fail(
                "stale_unit_digest",
                f"exact-unit digest for {self.unit_id!r} does not bind its payload",
                "regenerate the exact-unit artifact",
            )
        source = mapping(row.get("source"), "exact-unit source")
        original = mapping(source.get("original"), "exact-unit original span")
        if (
            original.get("rva_start") != self.rva_start
            or original.get("rva_end") != self.rva_end
            or source.get("instruction_bytes_sha256")
            != self.instruction_bytes_sha256
        ):
            fail(
                "unit_binding_mismatch",
                f"exact-unit binding for {self.unit_id!r} contradicts its source payload",
                "derive span and byte identities directly from the canonical unit",
            )

    @property
    def binary_payload(self) -> dict[str, str]:
        return {
            "pe_sha256": self.pe_sha256,
            "unit_ir_sha256": self.unit_ir_sha256,
        }

    @classmethod
    def create(
        cls,
        unit: Mapping[str, Any],
        *,
        pe_sha256: str,
    ) -> "ExactUnitV3":
        unit_id = text(unit.get("id"), "machine-IR unit ID")
        source = mapping(unit.get("source"), "machine-IR unit source")
        original = mapping(source.get("original"), "machine-IR original span")
        canonical_unit = CanonicalValueV3.of(unit)
        unit_ir_sha256 = hashlib.sha256(canonical_unit.data).hexdigest()
        return cls(
            record_id=unit_id,
            unit_id=unit_id,
            pe_sha256=pe_sha256,
            unit_ir_sha256=unit_ir_sha256,
            unit_sha256=unit_ir_sha256,
            instruction_bytes_sha256=digest(
                source.get("instruction_bytes_sha256"),
                "machine-IR instruction-byte SHA-256",
            ),
            rva_start=uint(original.get("rva_start"), "machine-IR unit start RVA"),
            rva_end=uint(original.get("rva_end"), "machine-IR unit end RVA"),
            unit=canonical_unit,
        )


def _encode_exact_unit(value: ExactUnitV3) -> dict[str, Any]:
    return {
        "schema": EXACT_UNIT_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "unit_id": value.unit_id,
        "binary": value.binary_payload,
        "unit_sha256": value.unit_sha256,
        "instruction_bytes_sha256": value.instruction_bytes_sha256,
        "rva_start": value.rva_start,
        "rva_end": value.rva_end,
        "unit": value.unit.to_value(),
    }


def _decode_exact_unit(value: Any) -> ExactUnitV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "unit_id",
            "binary",
            "unit_sha256",
            "instruction_bytes_sha256",
            "rva_start",
            "rva_end",
            "unit",
        },
        "exact-unit record",
    )
    if row["schema"] != EXACT_UNIT_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not an exact-unit-record-v3",
            "use EXACT_UNIT_CODEC_V3 only with exact-units-v3 artifacts",
        )
    binary = strict_object(
        row["binary"], {"pe_sha256", "unit_ir_sha256"}, "exact-unit binary"
    )
    return ExactUnitV3(
        record_id=text(row["id"], "exact-unit record ID"),
        unit_id=text(row["unit_id"], "exact-unit unit ID"),
        pe_sha256=digest(binary["pe_sha256"], "exact-unit PE SHA-256"),
        unit_ir_sha256=digest(
            binary["unit_ir_sha256"], "exact-unit source IR SHA-256"
        ),
        unit_sha256=digest(row["unit_sha256"], "exact-unit content SHA-256"),
        instruction_bytes_sha256=digest(
            row["instruction_bytes_sha256"],
            "exact-unit instruction-byte SHA-256",
        ),
        rva_start=uint(row["rva_start"], "exact-unit start RVA"),
        rva_end=uint(row["rva_end"], "exact-unit end RVA"),
        unit=CanonicalValueV3.of(row["unit"]),
    )


EXACT_UNIT_CODEC_V3 = RecordCodecV3[ExactUnitV3](
    decode=_decode_exact_unit,
    encode=_encode_exact_unit,
)


def exact_universe_sha256_v3(units: Iterable[ExactUnitV3]) -> str:
    """Identify a complete exact-unit universe without coupling local records."""

    rows = tuple(sorted(units, key=lambda row: row.unit_id))
    if not rows or len({row.unit_id for row in rows}) != len(rows):
        fail(
            "invalid_exact_universe",
            "exact-unit universe is empty or repeats unit IDs",
            "provide one checked exact-unit record for every structural unit",
        )
    pe_sha256s = {row.pe_sha256 for row in rows}
    if len(pe_sha256s) != 1:
        fail(
            "exact_unit_binary_mismatch",
            "exact-unit universe mixes PE identities",
            "partition exact units by their authoritative PE binding",
        )
    return canonical_sha256_v3(
        {
            "pe_sha256": rows[0].pe_sha256,
            "units": [
                {
                    "id": row.unit_id,
                    "unit_ir_sha256": row.unit_ir_sha256,
                }
                for row in rows
            ],
        }
    )


def _pe_sha256(context: PhaseContextV3) -> str:
    manifest = context.manifest("machine_ir")
    if manifest.status != "complete":
        fail(
            "incomplete_exact_input",
            f"machine_ir artifact status is {manifest.status!r}",
            "qualify the complete machine-IR artifact before exact-unit projection",
        )
    bindings = tuple(row for row in manifest.bindings if row.name == "binary")
    if len(bindings) != 1:
        fail(
            "missing_binary_binding",
            "machine_ir artifact must have exactly one binding named 'binary'",
            "bind the exact PE SHA-256 as the binary binding",
        )
    return bindings[0].sha256


def _derive_exact_unit(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ExactUnitV3:
    row = mapping(source.value.to_value(), "canonical machine-IR unit")
    if row.get("id") != source.record_id:
        fail(
            "unit_record_id_mismatch",
            f"machine-IR record {source.record_id!r} contains unit ID {row.get('id')!r}",
            "use each canonical unit ID as its artifact record ID",
        )
    return ExactUnitV3.create(
        row,
        pe_sha256=_pe_sha256(context),
    )


def _transform_exact_unit(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    exact = _derive_exact_unit(context, source)
    return EXACT_UNIT_CODEC_V3.write(source.record_id, exact)


def check_exact_units_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    sources = sorted_records(context.records("machine_ir"))
    if not sources:
        fail(
            "empty_structural_universe",
            "machine_ir artifact contains no exact units",
            "emit the complete canonical machine-IR unit inventory",
        )
    outputs = sorted_records(reader.iter_records())
    require_record_ids(outputs, (row.record_id for row in sources), "exact units")
    sources_by_id = {row.record_id: row for row in sources}
    expected_pe_sha256 = _pe_sha256(context)
    for output in outputs:
        typed = EXACT_UNIT_CODEC_V3.read(output).value
        source = sources_by_id[output.record_id]
        # Parsing ``typed`` has already checked its canonical payload digest,
        # source span, instruction bytes, and envelope.  Bind that payload to
        # the exact upstream record by byte identity instead of running the
        # same projection constructor a second time.
        if (
            typed.record_id != source.record_id
            or typed.pe_sha256 != expected_pe_sha256
            or typed.unit.data != source.value.data
        ):
            fail(
                "exact_unit_contradiction",
                f"exact-unit record {output.record_id!r} contradicts machine_ir",
                "discard and rebuild the exact-unit artifact",
            )
        if (
            len(output.dependencies) != 1
            or output.dependencies[0].input_name != "machine_ir"
            or output.dependencies[0].record_id != output.record_id
        ):
            fail(
                "incomplete_record_dependencies",
                f"exact-unit record {output.record_id!r} lacks its same-ID source dependency",
                "let the map_units runner attach only the source dependency",
            )


EXACT_UNITS_PHASE_V3 = map_units(
    name="exact-units-v3",
    version="1",
    source_input="machine_ir",
    input_artifact_kinds={"machine_ir": "machine-ir-v3-input"},
    output_artifact_kind=EXACT_UNITS_ARTIFACT_KIND_V3,
    transform=_transform_exact_unit,
    completeness=check_exact_units_completeness_v3,
)


__all__ = [
    "EXACT_UNIT_CODEC_V3",
    "EXACT_UNIT_RECORD_V3_SCHEMA",
    "EXACT_UNITS_ARTIFACT_KIND_V3",
    "EXACT_UNITS_PHASE_V3",
    "ExactUnitV3",
    "check_exact_units_completeness_v3",
    "exact_universe_sha256_v3",
]
