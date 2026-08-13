"""Exact per-unit ISA qualification authority for the v3 graph."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..phase_framework_v3 import PhaseContextV3, RecordCodecV3, map_units
from ._schema import (
    canonical_strings,
    digest,
    fail,
    mapping,
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
    InstructionOccurrenceV3,
    SemanticIndexRecordV3,
)


ISA_QUALIFICATION_EVIDENCE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-isa-qualification-evidence-record-v3"
)
ISA_QUALIFICATION_EVIDENCE_ARTIFACT_KIND_V3 = (
    "isa-qualification-evidence-v3"
)
ISA_QUALIFICATION_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-isa-qualification-record-v3"
)
ISA_QUALIFICATION_ARTIFACT_KIND_V3 = "isa-qualification-v3"

OracleVerdictV3 = Literal["qualified", "incomplete", "disputed", "vetoed"]


def isa_occurrence_id_v3(
    unit_id: str, instruction_index: int, instruction_sha256: str
) -> str:
    return stable_id(
        "isa-occurrence-v3",
        {
            "unit_id": unit_id,
            "instruction_index": instruction_index,
            "instruction_sha256": instruction_sha256,
        },
    )


@dataclass(frozen=True, order=True)
class ISAOracleObservationV3:
    oracle_id: str
    verdict: OracleVerdictV3
    observation_sha256: str

    def __post_init__(self) -> None:
        text(self.oracle_id, "ISA oracle ID")
        if self.verdict not in {
            "qualified",
            "incomplete",
            "disputed",
            "vetoed",
        }:
            fail(
                "record_schema_mismatch",
                f"ISA oracle verdict is {self.verdict!r}",
                "use qualified, incomplete, disputed, or vetoed",
            )
        digest(self.observation_sha256, "ISA oracle observation SHA-256")

    def to_payload(self) -> dict[str, str]:
        return {
            "oracle_id": self.oracle_id,
            "verdict": self.verdict,
            "observation_sha256": self.observation_sha256,
        }

    @classmethod
    def parse(cls, value: Any) -> "ISAOracleObservationV3":
        row = strict_object(
            value,
            {"oracle_id", "verdict", "observation_sha256"},
            "ISA oracle observation",
        )
        verdict = text(row["verdict"], "ISA oracle verdict")
        return cls(
            oracle_id=text(row["oracle_id"], "ISA oracle ID"),
            verdict=verdict,  # type: ignore[arg-type]
            observation_sha256=digest(
                row["observation_sha256"],
                "ISA oracle observation SHA-256",
            ),
        )


@dataclass(frozen=True)
class ISAQualificationEvidenceV3:
    """Raw decoder, selection, and oracle evidence for one exact instruction."""

    record_id: str
    unit_id: str
    unit_sha256: str
    pe_sha256: str
    unit_ir_sha256: str
    instruction_index: int
    instruction_sha256: str
    rva_start: int
    rva_end: int
    decoded_form_id: str
    selected_form_id: str
    semantic_form: str
    classifier_sha256: str
    semantic_kernel_sha256: str
    fallback_capability_id: str
    qualification_sha256: str
    oracle_observations: tuple[ISAOracleObservationV3, ...]

    def __post_init__(self) -> None:
        require_stable_id(
            self.record_id,
            "isa-occurrence-v3",
            {
                "unit_id": self.unit_id,
                "instruction_index": self.instruction_index,
                "instruction_sha256": self.instruction_sha256,
            },
            "ISA qualification evidence",
        )
        text(self.unit_id, "ISA evidence unit ID")
        digest(self.unit_sha256, "ISA evidence unit SHA-256")
        digest(self.pe_sha256, "ISA evidence PE SHA-256")
        digest(self.unit_ir_sha256, "ISA evidence unit-IR SHA-256")
        uint(self.instruction_index, "ISA evidence instruction index")
        digest(self.instruction_sha256, "ISA evidence instruction SHA-256")
        uint(self.rva_start, "ISA evidence instruction start RVA")
        uint(self.rva_end, "ISA evidence instruction end RVA")
        if self.rva_end <= self.rva_start:
            fail(
                "record_schema_mismatch",
                "ISA evidence has an empty or reversed instruction span",
                "bind the exact nonempty instruction span",
            )
        for value, context in (
            (self.decoded_form_id, "decoded ISA form ID"),
            (self.selected_form_id, "selected ISA form ID"),
            (self.semantic_form, "ISA semantic form"),
            (self.fallback_capability_id, "ISA fallback capability ID"),
        ):
            text(value, context)
        digest(self.classifier_sha256, "ISA classifier SHA-256")
        digest(self.semantic_kernel_sha256, "ISA semantic-kernel SHA-256")
        digest(self.qualification_sha256, "ISA qualification SHA-256")
        if self.oracle_observations != tuple(sorted(set(self.oracle_observations))):
            fail(
                "noncanonical_record_order",
                "ISA oracle observations are duplicated or unsorted",
                "sort and deduplicate observations by oracle ID",
            )
        if len({row.oracle_id for row in self.oracle_observations}) != len(
            self.oracle_observations
        ):
            fail(
                "duplicate_oracle_observation",
                "ISA qualification evidence repeats an oracle ID",
                "emit exactly one observation for each selected oracle",
            )

    @property
    def qualification_payload(self) -> dict[str, Any]:
        return {
            "binary": {
                "pe_sha256": self.pe_sha256,
                "unit_ir_sha256": self.unit_ir_sha256,
            },
            "unit": {"id": self.unit_id, "sha256": self.unit_sha256},
            "instruction": {
                "index": self.instruction_index,
                "sha256": self.instruction_sha256,
                "rva_start": self.rva_start,
                "rva_end": self.rva_end,
            },
            "decoded_form_id": self.decoded_form_id,
            "selected_form_id": self.selected_form_id,
            "semantic_form": self.semantic_form,
            "classifier_sha256": self.classifier_sha256,
            "semantic_kernel_sha256": self.semantic_kernel_sha256,
            "fallback_capability_id": self.fallback_capability_id,
            "oracle_observations": [
                row.to_payload() for row in self.oracle_observations
            ],
        }


def isa_qualification_sha256_v3(value: ISAQualificationEvidenceV3) -> str:
    return canonical_sha256_v3(value.qualification_payload)


def _encode_isa_evidence(value: ISAQualificationEvidenceV3) -> dict[str, Any]:
    return {
        "schema": ISA_QUALIFICATION_EVIDENCE_RECORD_V3_SCHEMA,
        "id": value.record_id,
        **value.qualification_payload,
        "qualification_sha256": value.qualification_sha256,
    }


def _decode_isa_evidence(value: Any) -> ISAQualificationEvidenceV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "binary",
            "unit",
            "instruction",
            "decoded_form_id",
            "selected_form_id",
            "semantic_form",
            "classifier_sha256",
            "semantic_kernel_sha256",
            "fallback_capability_id",
            "oracle_observations",
            "qualification_sha256",
        },
        "ISA qualification evidence",
    )
    if row["schema"] != ISA_QUALIFICATION_EVIDENCE_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not ISA qualification evidence v3",
            "use ISA_QUALIFICATION_EVIDENCE_CODEC_V3 with matching evidence",
        )
    binary = strict_object(
        row["binary"],
        {"pe_sha256", "unit_ir_sha256"},
        "ISA evidence binary binding",
    )
    unit = strict_object(
        row["unit"], {"id", "sha256"}, "ISA evidence unit binding"
    )
    instruction = strict_object(
        row["instruction"],
        {"index", "sha256", "rva_start", "rva_end"},
        "ISA evidence instruction binding",
    )
    return ISAQualificationEvidenceV3(
        record_id=text(row["id"], "ISA evidence record ID"),
        unit_id=text(unit["id"], "ISA evidence unit ID"),
        unit_sha256=digest(unit["sha256"], "ISA evidence unit SHA-256"),
        pe_sha256=digest(binary["pe_sha256"], "ISA evidence PE SHA-256"),
        unit_ir_sha256=digest(
            binary["unit_ir_sha256"],
            "ISA evidence unit-IR SHA-256",
        ),
        instruction_index=uint(
            instruction["index"], "ISA evidence instruction index"
        ),
        instruction_sha256=digest(
            instruction["sha256"], "ISA evidence instruction SHA-256"
        ),
        rva_start=uint(
            instruction["rva_start"], "ISA evidence instruction start RVA"
        ),
        rva_end=uint(
            instruction["rva_end"], "ISA evidence instruction end RVA"
        ),
        decoded_form_id=text(row["decoded_form_id"], "decoded ISA form ID"),
        selected_form_id=text(row["selected_form_id"], "selected ISA form ID"),
        semantic_form=text(row["semantic_form"], "ISA semantic form"),
        classifier_sha256=digest(
            row["classifier_sha256"], "ISA classifier SHA-256"
        ),
        semantic_kernel_sha256=digest(
            row["semantic_kernel_sha256"], "ISA semantic-kernel SHA-256"
        ),
        fallback_capability_id=text(
            row["fallback_capability_id"], "ISA fallback capability ID"
        ),
        qualification_sha256=digest(
            row["qualification_sha256"], "ISA qualification SHA-256"
        ),
        oracle_observations=tuple(
            ISAOracleObservationV3.parse(item)
            for item in sequence(
                row["oracle_observations"], "ISA oracle observations"
            )
        ),
    )


ISA_QUALIFICATION_EVIDENCE_CODEC_V3 = RecordCodecV3[
    ISAQualificationEvidenceV3
](decode=_decode_isa_evidence, encode=_encode_isa_evidence)


@dataclass(frozen=True, order=True)
class ISAFormSelectionV3:
    occurrence_id: str
    unit_id: str
    instruction_index: int
    instruction_sha256: str
    rva_start: int
    rva_end: int
    form_id: str
    semantic_form: str
    qualification_sha256: str
    fallback_capability_id: str
    oracle_ids: tuple[str, ...]
    selection_sha256: str

    def __post_init__(self) -> None:
        text(self.unit_id, "ISA selection unit ID")
        uint(self.instruction_index, "ISA selection instruction index")
        digest(self.instruction_sha256, "ISA selection instruction SHA-256")
        uint(self.rva_start, "ISA selection instruction start RVA")
        uint(self.rva_end, "ISA selection instruction end RVA")
        text(self.form_id, "ISA selection form ID")
        text(self.semantic_form, "ISA selection semantic form")
        digest(self.qualification_sha256, "ISA selection qualification SHA-256")
        text(self.fallback_capability_id, "ISA selection fallback capability ID")
        if (
            self.oracle_ids != tuple(sorted(set(self.oracle_ids)))
            or not self.oracle_ids
        ):
            fail(
                "noncanonical_record_order",
                "ISA selection oracle IDs must be nonempty, sorted, and unique",
                "retain the exact qualified oracle inventory",
            )
        require_stable_id(
            self.occurrence_id,
            "isa-occurrence-v3",
            {
                "unit_id": self.unit_id,
                "instruction_index": self.instruction_index,
                "instruction_sha256": self.instruction_sha256,
            },
            "ISA form selection",
        )
        digest(self.selection_sha256, "ISA selection SHA-256")
        if self.selection_sha256 != canonical_sha256_v3(self.identity_payload):
            fail(
                "stale_selection_hash",
                "ISA form selection SHA-256 does not bind its exact fields",
                "recreate the selection from checked qualification evidence",
            )

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "occurrence_id": self.occurrence_id,
            "unit_id": self.unit_id,
            "instruction_index": self.instruction_index,
            "instruction_sha256": self.instruction_sha256,
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
            "form_id": self.form_id,
            "semantic_form": self.semantic_form,
            "qualification_sha256": self.qualification_sha256,
            "fallback_capability_id": self.fallback_capability_id,
            "oracle_ids": list(self.oracle_ids),
        }


def _selection_payload(value: ISAFormSelectionV3) -> dict[str, Any]:
    return {**value.identity_payload, "selection_sha256": value.selection_sha256}


def _parse_selection(value: Any) -> ISAFormSelectionV3:
    row = strict_object(
        value,
        {
            "occurrence_id",
            "unit_id",
            "instruction_index",
            "instruction_sha256",
            "rva_start",
            "rva_end",
            "form_id",
            "semantic_form",
            "qualification_sha256",
            "fallback_capability_id",
            "oracle_ids",
            "selection_sha256",
        },
        "ISA form selection",
    )
    return ISAFormSelectionV3(
        occurrence_id=text(row["occurrence_id"], "ISA occurrence ID"),
        unit_id=text(row["unit_id"], "ISA selection unit ID"),
        instruction_index=uint(
            row["instruction_index"], "ISA selection instruction index"
        ),
        instruction_sha256=digest(
            row["instruction_sha256"], "ISA selection instruction SHA-256"
        ),
        rva_start=uint(row["rva_start"], "ISA selection start RVA"),
        rva_end=uint(row["rva_end"], "ISA selection end RVA"),
        form_id=text(row["form_id"], "ISA selection form ID"),
        semantic_form=text(row["semantic_form"], "ISA semantic form"),
        qualification_sha256=digest(
            row["qualification_sha256"], "ISA qualification SHA-256"
        ),
        fallback_capability_id=text(
            row["fallback_capability_id"], "ISA fallback capability ID"
        ),
        oracle_ids=canonical_strings(row["oracle_ids"], "ISA oracle IDs"),
        selection_sha256=digest(
            row["selection_sha256"], "ISA selection SHA-256"
        ),
    )


@dataclass(frozen=True)
class ISAQualificationRecordV3:
    record_id: str
    unit_sha256: str
    pe_sha256: str
    unit_ir_sha256: str
    reachable: bool | None
    status: str
    authorizing: bool
    selections: tuple[ISAFormSelectionV3, ...]
    primary_blocker: PrimaryBlockerV3 | None
    dependencies: tuple[RecordDependencyV3, ...]

    def __post_init__(self) -> None:
        text(self.record_id, "ISA qualification unit ID")
        digest(self.unit_sha256, "ISA qualification unit SHA-256")
        digest(self.pe_sha256, "ISA qualification PE SHA-256")
        digest(self.unit_ir_sha256, "ISA qualification unit-IR SHA-256")
        if self.reachable is not None and not isinstance(self.reachable, bool):
            fail(
                "record_schema_mismatch",
                "ISA qualification reachability is not Boolean or null",
                "emit checked reachability or null when root closure is unavailable",
            )
        if self.selections != tuple(
            sorted(set(self.selections), key=lambda row: row.instruction_index)
        ):
            fail(
                "noncanonical_record_order",
                "ISA form selections are duplicated or unsorted",
                "sort selections by exact instruction index",
            )
        if len({row.instruction_index for row in self.selections}) != len(
            self.selections
        ) or any(row.unit_id != self.record_id for row in self.selections):
            fail(
                "isa_selection_unit_contradiction",
                "ISA selections duplicate an instruction or mix exact units",
                "bind each exact instruction once under its owning unit",
            )
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=self.dependencies,
            context=f"ISA qualification {self.record_id!r}",
        )
        if self.status != "complete" and self.selections:
            fail(
                "fail_open_isa_qualification",
                "non-complete ISA qualification retains selected forms",
                "clear all selected forms until every exact occurrence qualifies",
            )
        if self.status == "complete" and self.reachable is None:
            fail(
                "fail_open_isa_qualification",
                "complete ISA qualification lacks checked reachability",
                "bind the complete launch/root closure",
            )


def _encode_isa_record(value: ISAQualificationRecordV3) -> dict[str, Any]:
    return {
        "schema": ISA_QUALIFICATION_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "unit_sha256": value.unit_sha256,
        "pe_sha256": value.pe_sha256,
        "unit_ir_sha256": value.unit_ir_sha256,
        "reachable": value.reachable,
        "status": value.status,
        "authorizing": value.authorizing,
        "selections": [_selection_payload(row) for row in value.selections],
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
        "dependencies": encode_dependencies_v3(value.dependencies),
    }


def _decode_isa_record(value: Any) -> ISAQualificationRecordV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "unit_sha256",
            "pe_sha256",
            "unit_ir_sha256",
            "reachable",
            "status",
            "authorizing",
            "selections",
            "primary_blocker",
            "dependencies",
        },
        "ISA qualification record",
    )
    if row["schema"] != ISA_QUALIFICATION_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not an ISA qualification record v3",
            "use ISA_QUALIFICATION_CODEC_V3 with matching artifacts",
        )
    authorizing = row["authorizing"]
    reachable = row["reachable"]
    if not isinstance(authorizing, bool) or (
        reachable is not None and not isinstance(reachable, bool)
    ):
        fail(
            "record_schema_mismatch",
            "ISA qualification Boolean fields are malformed",
            "emit exact authorizing and reachable values",
        )
    return ISAQualificationRecordV3(
        record_id=text(row["id"], "ISA qualification unit ID"),
        unit_sha256=digest(
            row["unit_sha256"], "ISA qualification unit SHA-256"
        ),
        pe_sha256=digest(row["pe_sha256"], "ISA qualification PE SHA-256"),
        unit_ir_sha256=digest(
            row["unit_ir_sha256"], "ISA qualification unit-IR SHA-256"
        ),
        reachable=reachable,
        status=text(row["status"], "ISA qualification status"),
        authorizing=authorizing,
        selections=tuple(
            _parse_selection(item)
            for item in sequence(row["selections"], "ISA form selections")
        ),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
        dependencies=decode_dependencies_v3(row["dependencies"]),
    )


ISA_QUALIFICATION_CODEC_V3 = RecordCodecV3[ISAQualificationRecordV3](
    decode=_decode_isa_record,
    encode=_encode_isa_record,
)


def _record_or_none(
    context: PhaseContextV3, input_name: str, record_id: str
) -> ArtifactRecordV3 | None:
    return context.optional_record(input_name, record_id)


def _root_closure(
    context: PhaseContextV3,
) -> tuple[
    ArtifactRecordV3 | None,
    LaunchRootClosureV3 | None,
    PrimaryBlockerV3 | None,
]:
    records = tuple(
        context.typed_records("root_closure", LAUNCH_ROOT_CLOSURE_CODEC_V3)
    )
    if not records:
        return None, None, PrimaryBlockerV3("incomplete", "root_closure_missing")
    if len(records) != 1:
        return None, None, PrimaryBlockerV3("violated", "root_closure_ambiguous")
    source = records[0].source
    closure = records[0].value
    manifest_blocker = manifest_blocker_v3(
        context,
        "root_closure",
        "root_closure_artifact_not_complete",
        RecordDependencyV3("root_closure", source.record_id),
    )
    if manifest_blocker is not None:
        return source, closure, manifest_blocker
    if closure.status != "complete" or not closure.authorizing:
        return (
            source,
            closure,
            PrimaryBlockerV3(
                "violated" if closure.status == "violated" else "incomplete",
                "root_closure_not_complete",
                "root_closure",
                source.record_id,
            ),
        )
    return source, closure, None


def _checked_selection(
    context: PhaseContextV3,
    *,
    semantic_index: SemanticIndexRecordV3,
    instruction: InstructionOccurrenceV3,
) -> tuple[ISAFormSelectionV3 | None, PrimaryBlockerV3 | None, RecordDependencyV3]:
    instruction_index = instruction.index
    instruction_sha256 = instruction.instruction_sha256
    occurrence_id = isa_occurrence_id_v3(
        semantic_index.record_id, instruction_index, instruction_sha256
    )
    dependency = RecordDependencyV3("isa_evidence", occurrence_id)
    source = _record_or_none(context, dependency.input_name, dependency.record_id)
    if source is None:
        return (
            None,
            PrimaryBlockerV3(
                "incomplete",
                "isa_qualification_evidence_missing",
                dependency.input_name,
                dependency.record_id,
            ),
            dependency,
        )
    evidence = ISA_QUALIFICATION_EVIDENCE_CODEC_V3.read(source).value
    binding_mismatch = (
        evidence.unit_id != semantic_index.record_id
        or evidence.unit_sha256 != semantic_index.unit_sha256
        or evidence.pe_sha256 != semantic_index.pe_sha256
        or evidence.unit_ir_sha256 != semantic_index.unit_ir_sha256
        or evidence.instruction_index != instruction_index
        or evidence.instruction_sha256 != instruction_sha256
        or evidence.rva_start != instruction.rva_start
        or evidence.rva_end != instruction.rva_end
    )
    if binding_mismatch:
        return (
            None,
            PrimaryBlockerV3(
                "violated",
                "isa_evidence_binding_contradiction",
                dependency.input_name,
                dependency.record_id,
            ),
            dependency,
        )
    if evidence.qualification_sha256 != isa_qualification_sha256_v3(evidence):
        return (
            None,
            PrimaryBlockerV3(
                "violated",
                "isa_qualification_hash_mismatch",
                dependency.input_name,
                dependency.record_id,
            ),
            dependency,
        )
    if evidence.decoded_form_id != evidence.selected_form_id:
        return (
            None,
            PrimaryBlockerV3(
                "violated",
                "isa_selected_form_mismatch",
                dependency.input_name,
                dependency.record_id,
            ),
            dependency,
        )
    if not evidence.oracle_observations:
        return (
            None,
            PrimaryBlockerV3(
                "incomplete",
                "isa_oracle_evidence_missing",
                dependency.input_name,
                dependency.record_id,
            ),
            dependency,
        )
    verdicts = {row.verdict for row in evidence.oracle_observations}
    if verdicts & {"disputed", "vetoed"}:
        return (
            None,
            PrimaryBlockerV3(
                "violated",
                "isa_oracle_disputed",
                dependency.input_name,
                dependency.record_id,
            ),
            dependency,
        )
    if verdicts != {"qualified"}:
        return (
            None,
            PrimaryBlockerV3(
                "incomplete",
                "isa_oracle_qualification_incomplete",
                dependency.input_name,
                dependency.record_id,
            ),
            dependency,
        )
    identity = {
        "occurrence_id": occurrence_id,
        "unit_id": semantic_index.record_id,
        "instruction_index": instruction_index,
        "instruction_sha256": instruction_sha256,
        "rva_start": evidence.rva_start,
        "rva_end": evidence.rva_end,
        "form_id": evidence.selected_form_id,
        "semantic_form": evidence.semantic_form,
        "qualification_sha256": evidence.qualification_sha256,
        "fallback_capability_id": evidence.fallback_capability_id,
        "oracle_ids": [row.oracle_id for row in evidence.oracle_observations],
    }
    return (
        ISAFormSelectionV3(
            occurrence_id=occurrence_id,
            unit_id=semantic_index.record_id,
            instruction_index=instruction_index,
            instruction_sha256=instruction_sha256,
            rva_start=evidence.rva_start,
            rva_end=evidence.rva_end,
            form_id=evidence.selected_form_id,
            semantic_form=evidence.semantic_form,
            qualification_sha256=evidence.qualification_sha256,
            fallback_capability_id=evidence.fallback_capability_id,
            oracle_ids=tuple(row.oracle_id for row in evidence.oracle_observations),
            selection_sha256=canonical_sha256_v3(identity),
        ),
        None,
        dependency,
    )


def _derive_isa_record(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ISAQualificationRecordV3:
    semantic_index = context.typed_record(
        "semantic_index", source.record_id, SEMANTIC_INDEX_CODEC_V3
    ).value
    dependencies = [RecordDependencyV3("semantic_index", source.record_id)]
    blockers: list[PrimaryBlockerV3] = []
    exact_manifest_blocker = manifest_blocker_v3(
        context,
        "semantic_index",
        "semantic_index_artifact_not_complete",
        dependencies[0],
    )
    if exact_manifest_blocker is not None:
        blockers.append(exact_manifest_blocker)
    closure_source, closure, closure_blocker = _root_closure(context)
    if closure_source is not None:
        dependencies.append(
            RecordDependencyV3("root_closure", closure_source.record_id)
        )
    if closure_blocker is not None:
        blockers.append(closure_blocker)
    evidence_manifest_blocker = manifest_blocker_v3(
        context, "isa_evidence", "isa_evidence_artifact_not_complete"
    )
    if evidence_manifest_blocker is not None:
        blockers.append(evidence_manifest_blocker)
    reachable = (
        None
        if closure is None or closure.status != "complete"
        else closure.contains_reachable_unit(semantic_index.record_id)
    )
    selections: list[ISAFormSelectionV3] = []
    if reachable is True:
        instructions = semantic_index.instructions
        if not instructions:
            blockers.append(
                PrimaryBlockerV3("violated", "reachable_unit_has_no_instructions")
            )
        cursor = semantic_index.rva_start
        for instruction in instructions:
            if instruction.rva_start != cursor:
                blockers.append(
                    PrimaryBlockerV3(
                        "violated", "exact_instruction_inventory_contradiction"
                    )
                )
                continue
            cursor = instruction.rva_end
            selection, blocker, dependency = _checked_selection(
                context,
                semantic_index=semantic_index,
                instruction=instruction,
            )
            dependencies.append(dependency)
            if blocker is not None:
                blockers.append(blocker)
            elif selection is not None:
                selections.append(selection)
        if cursor != semantic_index.rva_end:
            blockers.append(
                PrimaryBlockerV3(
                    "violated", "exact_instruction_inventory_contradiction"
                )
            )
    primary = aggregate_blockers_v3(blockers)
    status = "complete" if primary is None else primary.status
    return ISAQualificationRecordV3(
        record_id=semantic_index.record_id,
        unit_sha256=semantic_index.unit_sha256,
        pe_sha256=semantic_index.pe_sha256,
        unit_ir_sha256=semantic_index.unit_ir_sha256,
        reachable=reachable,
        status=status,
        authorizing=status == "complete",
        selections=(
            tuple(sorted(selections, key=lambda row: row.instruction_index))
            if status == "complete"
            else ()
        ),
        primary_blocker=primary,
        dependencies=canonical_dependencies_v3(dependencies),
    )


def _transform_isa_qualification(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    value = _derive_isa_record(context, source)
    return ISA_QUALIFICATION_CODEC_V3.write(
        source.record_id, value, dependencies=value.dependencies
    )


def _known_occurrence_ids(
    context: PhaseContextV3,
    semantic_records: tuple[ArtifactRecordV3, ...],
) -> set[str]:
    result: set[str] = set()
    for source in semantic_records:
        semantic_index = context.typed_record(
            "semantic_index", source.record_id, SEMANTIC_INDEX_CODEC_V3
        ).value
        for instruction in semantic_index.instructions:
            result.add(
                isa_occurrence_id_v3(
                    semantic_index.record_id,
                    instruction.index,
                    instruction.instruction_sha256,
                )
            )
    return result


def check_isa_qualification_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    semantic_records = sorted_records(context.records("semantic_index"))
    outputs = sorted_records(reader.iter_records())
    require_record_ids(
        outputs,
        (row.record_id for row in semantic_records),
        "ISA qualification records",
    )
    for source, output in zip(semantic_records, outputs, strict=True):
        expected = _derive_isa_record(context, source)
        submitted = ISA_QUALIFICATION_CODEC_V3.read(output).value
        if submitted != expected:
            fail(
                "isa_qualification_contradiction",
                f"ISA qualification for {output.record_id!r} is stale",
                "rerun ISA qualification from exact v3 evidence",
            )
        if output.dependencies != expected.dependencies:
            fail(
                "incomplete_record_dependencies",
                f"ISA qualification for {output.record_id!r} has stale dependencies",
                "let ISA_QUALIFICATION_PHASE_V3 attach exact dependencies",
            )
    if context.manifest("isa_evidence").record_count == 0:
        return
    evidence_records = sorted_records(context.records("isa_evidence"))
    unknown = sorted(
        {row.record_id for row in evidence_records}
        - _known_occurrence_ids(context, semantic_records)
    )
    if unknown:
        fail(
            "unknown_isa_evidence",
            f"ISA evidence names absent exact instructions {unknown!r}",
            "remove stale evidence or regenerate it from exact unit spans",
        )


ISA_QUALIFICATION_PHASE_V3 = map_units(
    name="isa-qualification-v3",
    version="1",
    source_input="semantic_index",
    input_artifact_kinds={
        "isa_evidence": ISA_QUALIFICATION_EVIDENCE_ARTIFACT_KIND_V3,
        "root_closure": LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
        "semantic_index": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    },
    output_artifact_kind=ISA_QUALIFICATION_ARTIFACT_KIND_V3,
    transform=_transform_isa_qualification,
    completeness=check_isa_qualification_completeness_v3,
)


__all__ = [
    "ISA_QUALIFICATION_ARTIFACT_KIND_V3",
    "ISA_QUALIFICATION_CODEC_V3",
    "ISA_QUALIFICATION_EVIDENCE_ARTIFACT_KIND_V3",
    "ISA_QUALIFICATION_EVIDENCE_CODEC_V3",
    "ISA_QUALIFICATION_EVIDENCE_RECORD_V3_SCHEMA",
    "ISA_QUALIFICATION_PHASE_V3",
    "ISA_QUALIFICATION_RECORD_V3_SCHEMA",
    "ISAFormSelectionV3",
    "ISAOracleObservationV3",
    "ISAQualificationEvidenceV3",
    "ISAQualificationRecordV3",
    "check_isa_qualification_completeness_v3",
    "isa_occurrence_id_v3",
    "isa_qualification_sha256_v3",
]
