"""Exact implementation-capability coverage for every machine-IR unit."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactV3Error,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..phase_framework_v3 import PhaseContextV3, RecordCodecV3, map_units
from ._schema import (
    canonical_strings,
    digest,
    fail,
    require_record_ids,
    sorted_records,
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
from .isa_qualification import (
    ISA_QUALIFICATION_ARTIFACT_KIND_V3,
    ISA_QUALIFICATION_CODEC_V3,
)
from .semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
)


IMPLEMENTATION_CAPABILITY_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-implementation-capability-record-v3"
)
IMPLEMENTATION_CAPABILITIES_ARTIFACT_KIND_V3 = "implementation-capabilities-v3"
FALLBACK_COVERAGE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-fallback-coverage-record-v3"
)
FALLBACK_COVERAGE_ARTIFACT_KIND_V3 = "fallback-coverage-v3"

ImplementationKindV3 = Literal["machine_ir_fallback", "portable_replacement"]


@dataclass(frozen=True)
class ImplementationCapabilityV3:
    """Exact implementation evidence for one structural machine-IR unit."""

    record_id: str
    capability_id: str
    implementation_kind: ImplementationKindV3
    implementation_sha256: str
    pe_sha256: str
    unit_ir_sha256: str
    unit_id: str
    unit_sha256: str
    selected_form_ids: tuple[str, ...]
    capability_sha256: str

    def __post_init__(self) -> None:
        text(self.record_id, "implementation-capability record ID")
        text(self.unit_id, "implementation-capability unit ID")
        if self.record_id != self.unit_id:
            fail(
                "stale_record_id",
                "implementation capability does not use its exact unit ID",
                "use the structural unit ID as the capability record ID",
            )
        text(self.capability_id, "implementation capability ID")
        if self.implementation_kind not in {
            "machine_ir_fallback",
            "portable_replacement",
        }:
            fail(
                "record_schema_mismatch",
                f"implementation kind is {self.implementation_kind!r}",
                "use machine_ir_fallback or portable_replacement",
            )
        digest(self.implementation_sha256, "implementation SHA-256")
        digest(self.pe_sha256, "implementation-capability PE SHA-256")
        digest(
            self.unit_ir_sha256,
            "implementation-capability unit-IR SHA-256",
        )
        digest(self.unit_sha256, "implementation-capability unit SHA-256")
        if self.selected_form_ids != tuple(sorted(set(self.selected_form_ids))):
            fail(
                "noncanonical_record_order",
                "implementation selected-form IDs are duplicated or unsorted",
                "sort and deduplicate selected form IDs",
            )
        for form_id in self.selected_form_ids:
            text(form_id, "implementation selected-form ID")
        digest(self.capability_sha256, "implementation capability SHA-256")

    @property
    def capability_payload(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "implementation_kind": self.implementation_kind,
            "implementation_sha256": self.implementation_sha256,
            "binary": {
                "pe_sha256": self.pe_sha256,
                "unit_ir_sha256": self.unit_ir_sha256,
            },
            "unit": {"id": self.unit_id, "sha256": self.unit_sha256},
            "selected_form_ids": list(self.selected_form_ids),
        }


def implementation_capability_sha256_v3(
    value: ImplementationCapabilityV3,
) -> str:
    return canonical_sha256_v3(value.capability_payload)


def _encode_implementation_capability(
    value: ImplementationCapabilityV3,
) -> dict[str, Any]:
    return {
        "schema": IMPLEMENTATION_CAPABILITY_RECORD_V3_SCHEMA,
        "id": value.record_id,
        **value.capability_payload,
        "capability_sha256": value.capability_sha256,
    }


def _decode_implementation_capability(value: Any) -> ImplementationCapabilityV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "capability_id",
            "implementation_kind",
            "implementation_sha256",
            "binary",
            "unit",
            "selected_form_ids",
            "capability_sha256",
        },
        "implementation capability",
    )
    if row["schema"] != IMPLEMENTATION_CAPABILITY_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not an implementation-capability record v3",
            "use IMPLEMENTATION_CAPABILITY_CODEC_V3 with matching evidence",
        )
    binary = strict_object(
        row["binary"],
        {"pe_sha256", "unit_ir_sha256"},
        "implementation-capability binary binding",
    )
    unit = strict_object(
        row["unit"],
        {"id", "sha256"},
        "implementation-capability unit binding",
    )
    implementation_kind = text(
        row["implementation_kind"], "implementation kind"
    )
    return ImplementationCapabilityV3(
        record_id=text(row["id"], "implementation-capability record ID"),
        capability_id=text(row["capability_id"], "implementation capability ID"),
        implementation_kind=implementation_kind,  # type: ignore[arg-type]
        implementation_sha256=digest(
            row["implementation_sha256"], "implementation SHA-256"
        ),
        pe_sha256=digest(
            binary["pe_sha256"], "implementation-capability PE SHA-256"
        ),
        unit_ir_sha256=digest(
            binary["unit_ir_sha256"],
            "implementation-capability unit-IR SHA-256",
        ),
        unit_id=text(unit["id"], "implementation-capability unit ID"),
        unit_sha256=digest(
            unit["sha256"], "implementation-capability unit SHA-256"
        ),
        selected_form_ids=canonical_strings(
            row["selected_form_ids"], "implementation selected-form IDs"
        ),
        capability_sha256=digest(
            row["capability_sha256"], "implementation capability SHA-256"
        ),
    )


IMPLEMENTATION_CAPABILITY_CODEC_V3 = RecordCodecV3[ImplementationCapabilityV3](
    decode=_decode_implementation_capability,
    encode=_encode_implementation_capability,
)


@dataclass(frozen=True)
class FallbackCoverageRecordV3:
    record_id: str
    unit_sha256: str
    pe_sha256: str
    unit_ir_sha256: str
    status: str
    authorizing: bool
    selected_form_ids: tuple[str, ...]
    capability_id: str | None
    capability_sha256: str | None
    implementation_kind: ImplementationKindV3 | None
    implementation_sha256: str | None
    primary_blocker: PrimaryBlockerV3 | None
    dependencies: tuple[RecordDependencyV3, ...]

    def __post_init__(self) -> None:
        text(self.record_id, "fallback-coverage unit ID")
        digest(self.unit_sha256, "fallback-coverage unit SHA-256")
        digest(self.pe_sha256, "fallback-coverage PE SHA-256")
        digest(self.unit_ir_sha256, "fallback-coverage unit-IR SHA-256")
        if self.selected_form_ids != tuple(sorted(set(self.selected_form_ids))):
            fail(
                "noncanonical_record_order",
                "fallback selected-form IDs are duplicated or unsorted",
                "sort and deduplicate selected form IDs",
            )
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=self.dependencies,
            context=f"fallback coverage {self.record_id!r}",
        )
        authority_fields = (
            self.capability_id,
            self.capability_sha256,
            self.implementation_kind,
            self.implementation_sha256,
        )
        if self.status == "complete":
            if any(value is None for value in authority_fields):
                fail(
                    "fail_open_fallback_coverage",
                    "complete fallback coverage lacks implementation authority",
                    "bind one exact implementation capability",
                )
            text(self.capability_id, "fallback capability ID")
            digest(self.capability_sha256, "fallback capability SHA-256")
            digest(self.implementation_sha256, "fallback implementation SHA-256")
            if self.implementation_kind not in {
                "machine_ir_fallback",
                "portable_replacement",
            }:
                fail(
                    "record_schema_mismatch",
                    "fallback coverage has an invalid implementation kind",
                    "use one supported implementation kind",
                )
        elif self.selected_form_ids or any(
            value is not None for value in authority_fields
        ):
            fail(
                "fail_open_fallback_coverage",
                "non-complete fallback coverage retains implementation authority",
                "clear selected forms and implementation fields",
            )


def _encode_fallback_record(value: FallbackCoverageRecordV3) -> dict[str, Any]:
    return {
        "schema": FALLBACK_COVERAGE_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "unit_sha256": value.unit_sha256,
        "pe_sha256": value.pe_sha256,
        "unit_ir_sha256": value.unit_ir_sha256,
        "status": value.status,
        "authorizing": value.authorizing,
        "selected_form_ids": list(value.selected_form_ids),
        "capability_id": value.capability_id,
        "capability_sha256": value.capability_sha256,
        "implementation_kind": value.implementation_kind,
        "implementation_sha256": value.implementation_sha256,
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
        "dependencies": encode_dependencies_v3(value.dependencies),
    }


def _decode_fallback_record(value: Any) -> FallbackCoverageRecordV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "unit_sha256",
            "pe_sha256",
            "unit_ir_sha256",
            "status",
            "authorizing",
            "selected_form_ids",
            "capability_id",
            "capability_sha256",
            "implementation_kind",
            "implementation_sha256",
            "primary_blocker",
            "dependencies",
        },
        "fallback-coverage record",
    )
    if row["schema"] != FALLBACK_COVERAGE_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not a fallback-coverage record v3",
            "use FALLBACK_COVERAGE_CODEC_V3 with matching artifacts",
        )
    authorizing = row["authorizing"]
    if not isinstance(authorizing, bool):
        fail(
            "record_schema_mismatch",
            "fallback-coverage authorizing field is not Boolean",
            "emit true or false",
        )
    kind = row["implementation_kind"]
    if kind is not None:
        kind = text(kind, "fallback implementation kind")
    return FallbackCoverageRecordV3(
        record_id=text(row["id"], "fallback-coverage unit ID"),
        unit_sha256=digest(
            row["unit_sha256"], "fallback-coverage unit SHA-256"
        ),
        pe_sha256=digest(row["pe_sha256"], "fallback-coverage PE SHA-256"),
        unit_ir_sha256=digest(
            row["unit_ir_sha256"], "fallback-coverage unit-IR SHA-256"
        ),
        status=text(row["status"], "fallback-coverage status"),
        authorizing=authorizing,
        selected_form_ids=canonical_strings(
            row["selected_form_ids"], "fallback selected-form IDs"
        ),
        capability_id=(
            None
            if row["capability_id"] is None
            else text(row["capability_id"], "fallback capability ID")
        ),
        capability_sha256=(
            None
            if row["capability_sha256"] is None
            else digest(row["capability_sha256"], "fallback capability SHA-256")
        ),
        implementation_kind=kind,  # type: ignore[arg-type]
        implementation_sha256=(
            None
            if row["implementation_sha256"] is None
            else digest(
                row["implementation_sha256"],
                "fallback implementation SHA-256",
            )
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
        dependencies=decode_dependencies_v3(row["dependencies"]),
    )


FALLBACK_COVERAGE_CODEC_V3 = RecordCodecV3[FallbackCoverageRecordV3](
    decode=_decode_fallback_record,
    encode=_encode_fallback_record,
)


def _record_or_none(
    context: PhaseContextV3, input_name: str, record_id: str
) -> ArtifactRecordV3 | None:
    try:
        return context.record(input_name, record_id)
    except ArtifactV3Error as exc:
        if exc.code == "missing_record":
            return None
        raise


def _derive_fallback_record(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> FallbackCoverageRecordV3:
    semantic_index = SEMANTIC_INDEX_CODEC_V3.read(source).value
    dependencies = [
        RecordDependencyV3("semantic_index", semantic_index.record_id)
    ]
    blockers: list[PrimaryBlockerV3] = []
    exact_manifest_blocker = manifest_blocker_v3(
        context,
        "semantic_index",
        "semantic_index_artifact_not_complete",
        dependencies[0],
    )
    if exact_manifest_blocker is not None:
        blockers.append(exact_manifest_blocker)

    isa_dependency = RecordDependencyV3(
        "isa_qualification", semantic_index.record_id
    )
    capability_dependency = RecordDependencyV3(
        "implementation_capabilities", semantic_index.record_id
    )
    dependencies.extend((isa_dependency, capability_dependency))
    isa_source = _record_or_none(
        context, isa_dependency.input_name, isa_dependency.record_id
    )
    capability_source = _record_or_none(
        context, capability_dependency.input_name, capability_dependency.record_id
    )
    for input_name, dependency, code in (
        (
            "isa_qualification",
            isa_dependency,
            "isa_qualification_artifact_not_complete",
        ),
        (
            "implementation_capabilities",
            capability_dependency,
            "implementation_capabilities_artifact_not_complete",
        ),
    ):
        blocker = manifest_blocker_v3(context, input_name, code, dependency)
        if blocker is not None:
            blockers.append(blocker)
    if isa_source is None:
        blockers.append(
            PrimaryBlockerV3(
                "incomplete",
                "isa_qualification_record_missing",
                isa_dependency.input_name,
                isa_dependency.record_id,
            )
        )
    if capability_source is None:
        blockers.append(
            PrimaryBlockerV3(
                "incomplete",
                "implementation_capability_missing",
                capability_dependency.input_name,
                capability_dependency.record_id,
            )
        )

    selected_form_ids: tuple[str, ...] = ()
    isa = None
    if isa_source is not None:
        isa = ISA_QUALIFICATION_CODEC_V3.read(isa_source).value
        if (
            isa.record_id != semantic_index.record_id
            or isa.unit_sha256 != semantic_index.unit_sha256
            or isa.pe_sha256 != semantic_index.pe_sha256
            or isa.unit_ir_sha256 != semantic_index.unit_ir_sha256
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "isa_qualification_binding_contradiction",
                    isa_dependency.input_name,
                    isa_dependency.record_id,
                )
            )
        elif isa.status != "complete" or not isa.authorizing:
            blockers.append(
                PrimaryBlockerV3(
                    "violated" if isa.status == "violated" else "incomplete",
                    (
                        isa.primary_blocker.code
                        if isa.primary_blocker is not None
                        else "isa_qualification_not_complete"
                    ),
                    isa_dependency.input_name,
                    isa_dependency.record_id,
                )
            )
        else:
            selected_form_ids = tuple(
                sorted({row.form_id for row in isa.selections})
            )

    capability = None
    if capability_source is not None:
        capability = IMPLEMENTATION_CAPABILITY_CODEC_V3.read(
            capability_source
        ).value
        if (
            capability.unit_id != semantic_index.record_id
            or capability.unit_sha256 != semantic_index.unit_sha256
            or capability.pe_sha256 != semantic_index.pe_sha256
            or capability.unit_ir_sha256 != semantic_index.unit_ir_sha256
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "implementation_capability_binding_contradiction",
                    capability_dependency.input_name,
                    capability_dependency.record_id,
                )
            )
        elif (
            capability.capability_sha256
            != implementation_capability_sha256_v3(capability)
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated",
                    "implementation_capability_hash_mismatch",
                    capability_dependency.input_name,
                    capability_dependency.record_id,
                )
            )
        elif isa is not None and isa.status == "complete":
            selected_capability_ids = {
                row.fallback_capability_id for row in isa.selections
            }
            if (
                capability.selected_form_ids != selected_form_ids
                or selected_capability_ids
                not in ({capability.capability_id}, set())
            ):
                blockers.append(
                    PrimaryBlockerV3(
                        "violated",
                        "implementation_capability_form_mismatch",
                        capability_dependency.input_name,
                        capability_dependency.record_id,
                    )
                )

    primary = aggregate_blockers_v3(blockers)
    status = "complete" if primary is None else primary.status
    complete_capability = capability if status == "complete" else None
    return FallbackCoverageRecordV3(
        record_id=semantic_index.record_id,
        unit_sha256=semantic_index.unit_sha256,
        pe_sha256=semantic_index.pe_sha256,
        unit_ir_sha256=semantic_index.unit_ir_sha256,
        status=status,
        authorizing=status == "complete",
        selected_form_ids=selected_form_ids if status == "complete" else (),
        capability_id=(
            None
            if complete_capability is None
            else complete_capability.capability_id
        ),
        capability_sha256=(
            None
            if complete_capability is None
            else complete_capability.capability_sha256
        ),
        implementation_kind=(
            None
            if complete_capability is None
            else complete_capability.implementation_kind
        ),
        implementation_sha256=(
            None
            if complete_capability is None
            else complete_capability.implementation_sha256
        ),
        primary_blocker=primary,
        dependencies=canonical_dependencies_v3(dependencies),
    )


def _transform_fallback_coverage(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    value = _derive_fallback_record(context, source)
    return FALLBACK_COVERAGE_CODEC_V3.write(
        source.record_id, value, dependencies=value.dependencies
    )


def check_fallback_coverage_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    semantic_records = sorted_records(context.records("semantic_index"))
    outputs = sorted_records(reader.iter_records())
    require_record_ids(
        outputs,
        (row.record_id for row in semantic_records),
        "fallback-coverage records",
    )
    for source, output in zip(semantic_records, outputs, strict=True):
        expected = _derive_fallback_record(context, source)
        submitted = FALLBACK_COVERAGE_CODEC_V3.read(output).value
        if submitted != expected:
            fail(
                "fallback_coverage_contradiction",
                f"fallback coverage for {output.record_id!r} is stale",
                "rerun fallback coverage from exact v3 evidence",
            )
        if output.dependencies != expected.dependencies:
            fail(
                "incomplete_record_dependencies",
                f"fallback coverage for {output.record_id!r} has stale dependencies",
                "let FALLBACK_COVERAGE_PHASE_V3 attach exact dependencies",
            )
    exact_ids = {row.record_id for row in semantic_records}
    capability_records = sorted_records(
        context.records("implementation_capabilities")
    )
    unknown = sorted({row.record_id for row in capability_records} - exact_ids)
    if unknown:
        fail(
            "unknown_implementation_capability",
            f"implementation capabilities name absent exact units {unknown!r}",
            "remove stale capability records or regenerate the exact inventory",
        )


FALLBACK_COVERAGE_PHASE_V3 = map_units(
    name="fallback-coverage-v3",
    version="1",
    source_input="semantic_index",
    input_artifact_kinds={
        "implementation_capabilities": IMPLEMENTATION_CAPABILITIES_ARTIFACT_KIND_V3,
        "isa_qualification": ISA_QUALIFICATION_ARTIFACT_KIND_V3,
        "semantic_index": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    },
    output_artifact_kind=FALLBACK_COVERAGE_ARTIFACT_KIND_V3,
    transform=_transform_fallback_coverage,
    completeness=check_fallback_coverage_completeness_v3,
    unit_aligned_inputs=("isa_qualification",),
)


__all__ = [
    "FALLBACK_COVERAGE_ARTIFACT_KIND_V3",
    "FALLBACK_COVERAGE_CODEC_V3",
    "FALLBACK_COVERAGE_PHASE_V3",
    "FALLBACK_COVERAGE_RECORD_V3_SCHEMA",
    "IMPLEMENTATION_CAPABILITIES_ARTIFACT_KIND_V3",
    "IMPLEMENTATION_CAPABILITY_CODEC_V3",
    "IMPLEMENTATION_CAPABILITY_RECORD_V3_SCHEMA",
    "FallbackCoverageRecordV3",
    "ImplementationCapabilityV3",
    "check_fallback_coverage_completeness_v3",
    "implementation_capability_sha256_v3",
]
