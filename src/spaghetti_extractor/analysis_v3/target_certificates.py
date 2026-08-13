"""Checked finite-target authority for exact indirect control transfers.

Structural target recovery is deliberately only a proposal.  This phase binds
that proposal to the exact target expression and independently checked
transition, memory, and invariant evidence before any downstream authority may
consume it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
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
    AnalysisV3Error,
    boolean,
    canonical_json_rows,
    canonical_sort,
    canonical_strings,
    digest,
    fail,
    mapping,
    optional_text,
    optional_uint,
    require_record_ids,
    sequence,
    sorted_records,
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
from .inductive_records import (
    INDUCTIVE_INPUT_CODEC_V3,
    InductiveCutpointV3,
    InvariantFactV3,
)
from .memory_records import MEMORY_VERSION_CODEC_V3, MemoryVersionRecordV3
from .semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    IndirectExitOccurrenceV3,
    SemanticIndexRecordV3,
)
from .structural_targets import (
    STRUCTURAL_TARGETS_ARTIFACT_KIND_V3,
    STRUCTURAL_TARGET_UNIT_CODEC_V3,
    StructuralTargetProposalV3,
)
from .transition_records import (
    TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionSummaryRecordV3,
)


TARGET_EVALUATION_EVIDENCE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-indirect-target-evaluation-evidence-record-v3"
)
TARGET_EVALUATION_EVIDENCE_ARTIFACT_KIND_V3 = (
    "indirect-target-evaluation-evidence-v3"
)
INDIRECT_TARGET_CERTIFICATE_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-indirect-target-certificate-record-v3"
)
INDIRECT_TARGET_CERTIFICATE_UNIT_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-indirect-target-certificate-unit-record-v3"
)
INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3 = (
    "indirect-target-certificates-v3"
)

_EVALUATION_METHODS = frozenset(
    {"exact_constant", "inductive_finite_values", "checked_indexed_pe_table"}
)
_INDEXED_PE_TABLE_CERTIFICATE_KIND_V3 = "checked-indexed-pe-table-v3"


def _canonical_values(values: Iterable[CanonicalValueV3]) -> tuple[CanonicalValueV3, ...]:
    return tuple(sorted(set(values), key=lambda row: row.data))


@dataclass(frozen=True)
class TargetEvaluationEvidenceV3:
    """Untrusted proposal describing how an exact expression is bounded."""

    record_id: str
    source_unit_id: str
    source_rva: int
    source_event_index: int | None
    transfer_kind: str
    target_expression_sha256: str
    evaluation_method: str
    memory_record_id: str
    inductive_fact_id: str | None
    target_unit_ids: tuple[str, ...]
    external_targets: tuple[CanonicalValueV3, ...]
    evaluation_certificate: CanonicalValueV3 | None
    evidence_sha256: str

    def __post_init__(self) -> None:
        text(self.record_id, "target-evaluation evidence ID")
        text(self.source_unit_id, "target-evaluation source unit ID")
        uint(self.source_rva, "target-evaluation source RVA")
        optional_uint(self.source_event_index, "target-evaluation event index")
        if self.transfer_kind not in {"indirect_call", "indirect_jump"}:
            fail(
                "record_schema_mismatch",
                f"target evidence has invalid transfer kind {self.transfer_kind!r}",
                "bind an exact indirect call or jump",
            )
        digest(self.target_expression_sha256, "target-expression SHA-256")
        if self.evaluation_method not in _EVALUATION_METHODS:
            fail(
                "record_schema_mismatch",
                f"target evidence has unsupported method {self.evaluation_method!r}",
                "use exact_constant or inductive_finite_values",
            )
        text(self.memory_record_id, "target-evaluation memory record ID")
        optional_text(self.inductive_fact_id, "target-evaluation invariant fact ID")
        if self.evaluation_method == "exact_constant" and self.inductive_fact_id is not None:
            fail(
                "record_schema_mismatch",
                "constant target evidence references an invariant fact",
                "clear inductive_fact_id for an exact constant expression",
            )
        if self.evaluation_method == "inductive_finite_values" and self.inductive_fact_id is None:
            fail(
                "record_schema_mismatch",
                "finite target evidence has no invariant fact",
                "bind the exact finite cutpoint fact",
            )
        if self.evaluation_method == "checked_indexed_pe_table":
            if self.inductive_fact_id is not None:
                fail(
                    "record_schema_mismatch",
                    "indexed PE-table evidence references an invariant fact",
                    "carry the checked table proof in evaluation_certificate",
                )
            if self.external_targets:
                fail(
                    "record_schema_mismatch",
                    "indexed PE-table evidence contains external targets",
                    "indexed PE tables currently authorize only exact internal units",
                )
            if self.evaluation_certificate is None:
                fail(
                    "record_schema_mismatch",
                    "indexed PE-table evidence has no checked certificate",
                    "include the exact table, selector, and target bindings",
                )
        elif self.evaluation_certificate is not None:
            fail(
                "record_schema_mismatch",
                "non-indexed target evidence contains an indexed certificate",
                "clear evaluation_certificate or use checked_indexed_pe_table",
            )
        if self.target_unit_ids != tuple(sorted(set(self.target_unit_ids))):
            fail(
                "noncanonical_record_order",
                "target-evaluation unit IDs are not sorted and unique",
                "sort and deduplicate target unit IDs",
            )
        for unit_id in self.target_unit_ids:
            text(unit_id, "target-evaluation target unit ID")
        if self.external_targets != _canonical_values(self.external_targets):
            fail(
                "noncanonical_record_order",
                "target-evaluation external alternatives are not canonical",
                "sort and deduplicate external alternatives",
            )
        if not (self.target_unit_ids or self.external_targets):
            fail(
                "record_schema_mismatch",
                "target-evaluation evidence has an empty finite target set",
                "include every claimed internal and external alternative",
            )
        digest(self.evidence_sha256, "target-evaluation evidence SHA-256")
        expected = canonical_sha256_v3(self.identity_payload())
        if self.evidence_sha256 != expected:
            fail(
                "stale_record_id",
                "target-evaluation evidence digest does not bind its payload",
                f"recreate it with evidence_sha256={expected}",
            )

    def identity_payload(self) -> dict[str, Any]:
        return {
            "id": self.record_id,
            "source_unit_id": self.source_unit_id,
            "source_rva": self.source_rva,
            "source_event_index": self.source_event_index,
            "transfer_kind": self.transfer_kind,
            "target_expression_sha256": self.target_expression_sha256,
            "evaluation_method": self.evaluation_method,
            "memory_record_id": self.memory_record_id,
            "inductive_fact_id": self.inductive_fact_id,
            "target_unit_ids": list(self.target_unit_ids),
            "external_targets": canonical_json_rows(self.external_targets),
            "evaluation_certificate": (
                None
                if self.evaluation_certificate is None
                else self.evaluation_certificate.to_value()
            ),
        }

    @classmethod
    def create(
        cls,
        *,
        record_id: str,
        source_unit_id: str,
        source_rva: int,
        source_event_index: int | None,
        transfer_kind: str,
        target_expression: Any,
        evaluation_method: str,
        memory_record_id: str,
        inductive_fact_id: str | None,
        target_unit_ids: Iterable[str] = (),
        external_targets: Iterable[Any] = (),
        evaluation_certificate: Any | None = None,
    ) -> "TargetEvaluationEvidenceV3":
        units = tuple(sorted(set(target_unit_ids)))
        external = canonical_sort(external_targets)
        payload = {
            "id": record_id,
            "source_unit_id": source_unit_id,
            "source_rva": source_rva,
            "source_event_index": source_event_index,
            "transfer_kind": transfer_kind,
            "target_expression_sha256": canonical_sha256_v3(target_expression),
            "evaluation_method": evaluation_method,
            "memory_record_id": memory_record_id,
            "inductive_fact_id": inductive_fact_id,
            "target_unit_ids": list(units),
            "external_targets": canonical_json_rows(external),
            "evaluation_certificate": evaluation_certificate,
        }
        return cls(
            record_id,
            source_unit_id,
            source_rva,
            source_event_index,
            transfer_kind,
            payload["target_expression_sha256"],
            evaluation_method,
            memory_record_id,
            inductive_fact_id,
            units,
            external,
            (
                None
                if evaluation_certificate is None
                else CanonicalValueV3.of(evaluation_certificate)
            ),
            canonical_sha256_v3(payload),
        )


def _encode_evidence(value: TargetEvaluationEvidenceV3) -> dict[str, Any]:
    return {
        "schema": TARGET_EVALUATION_EVIDENCE_RECORD_V3_SCHEMA,
        **value.identity_payload(),
        "evidence_sha256": value.evidence_sha256,
    }


def _decode_evidence(value: Any) -> TargetEvaluationEvidenceV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "source_unit_id",
            "source_rva",
            "source_event_index",
            "transfer_kind",
            "target_expression_sha256",
            "evaluation_method",
            "memory_record_id",
            "inductive_fact_id",
            "target_unit_ids",
            "external_targets",
            "evaluation_certificate",
            "evidence_sha256",
        },
        "target-evaluation evidence",
    )
    if row["schema"] != TARGET_EVALUATION_EVIDENCE_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not target-evaluation-evidence-v3",
            "use TARGET_EVALUATION_EVIDENCE_CODEC_V3 with matching evidence",
        )
    return TargetEvaluationEvidenceV3(
        record_id=text(row["id"], "target-evaluation evidence ID"),
        source_unit_id=text(row["source_unit_id"], "target-evaluation source unit"),
        source_rva=uint(row["source_rva"], "target-evaluation source RVA"),
        source_event_index=(
            None
            if row["source_event_index"] is None
            else uint(row["source_event_index"], "target-evaluation event index")
        ),
        transfer_kind=text(row["transfer_kind"], "target-evaluation transfer kind"),
        target_expression_sha256=digest(
            row["target_expression_sha256"], "target-expression SHA-256"
        ),
        evaluation_method=text(row["evaluation_method"], "target-evaluation method"),
        memory_record_id=text(row["memory_record_id"], "target memory record ID"),
        inductive_fact_id=optional_text(
            row["inductive_fact_id"], "target invariant fact ID"
        ),
        target_unit_ids=canonical_strings(
            row["target_unit_ids"], "target-evaluation target unit IDs"
        ),
        external_targets=canonical_sort(
            sequence(row["external_targets"], "target external alternatives")
        ),
        evaluation_certificate=(
            None
            if row["evaluation_certificate"] is None
            else CanonicalValueV3.of(row["evaluation_certificate"])
        ),
        evidence_sha256=digest(row["evidence_sha256"], "target evidence SHA-256"),
    )


TARGET_EVALUATION_EVIDENCE_CODEC_V3 = RecordCodecV3[TargetEvaluationEvidenceV3](
    decode=_decode_evidence,
    encode=_encode_evidence,
)


@dataclass(frozen=True)
class IndirectTargetCertificateV3:
    certificate_id: str
    exit_id: str
    source_unit_id: str
    source_unit_sha256: str
    source_rva: int
    source_event_index: int | None
    transfer_kind: str
    target_expression: CanonicalValueV3
    target_expression_sha256: str
    status: str
    authorizing: bool
    target_unit_ids: tuple[str, ...]
    external_targets: tuple[CanonicalValueV3, ...]
    evaluation_method: str | None
    evidence_sha256: str | None
    dependencies: tuple[RecordDependencyV3, ...]
    primary_blocker: PrimaryBlockerV3 | None
    certificate_sha256: str

    def __post_init__(self) -> None:
        text(self.certificate_id, "indirect-target certificate ID")
        text(self.exit_id, "indirect-target exit ID")
        text(self.source_unit_id, "indirect-target source unit")
        digest(self.source_unit_sha256, "indirect-target source unit SHA-256")
        uint(self.source_rva, "indirect-target source RVA")
        optional_uint(self.source_event_index, "indirect-target event index")
        if self.transfer_kind not in {"indirect_call", "indirect_jump"}:
            fail(
                "record_schema_mismatch",
                f"certificate has invalid transfer kind {self.transfer_kind!r}",
                "bind an exact indirect call or jump",
            )
        digest(self.target_expression_sha256, "certificate target-expression SHA-256")
        if self.target_expression_sha256 != canonical_sha256_v3(
            self.target_expression.to_value()
        ):
            fail(
                "target_expression_binding_mismatch",
                "certificate expression digest is stale",
                "bind the exact canonical target expression",
            )
        if self.target_unit_ids != tuple(sorted(set(self.target_unit_ids))):
            fail(
                "noncanonical_record_order",
                "certificate target unit IDs are not sorted and unique",
                "sort and deduplicate internal target IDs",
            )
        if self.external_targets != _canonical_values(self.external_targets):
            fail(
                "noncanonical_record_order",
                "certificate external targets are not canonical",
                "sort and deduplicate external targets",
            )
        if self.status != "complete" and (self.target_unit_ids or self.external_targets):
            fail(
                "fail_open_authority_status",
                "non-complete target certificate retains target authority",
                "clear target alternatives until evaluation is checked",
            )
        if self.status == "complete" and not (
            self.target_unit_ids or self.external_targets
        ):
            fail(
                "fail_open_authority_status",
                "complete target certificate has an empty target set",
                "include every checked finite alternative",
            )
        if (self.evaluation_method is None) != (self.evidence_sha256 is None):
            fail(
                "record_schema_mismatch",
                "target certificate has a partial evaluation witness",
                "bind both evaluation method and evidence digest, or neither",
            )
        if self.evaluation_method is not None and self.evaluation_method not in _EVALUATION_METHODS:
            fail(
                "record_schema_mismatch",
                "target certificate has an unsupported evaluation method",
                "use a checker-supported target evaluation method",
            )
        if self.evidence_sha256 is not None:
            digest(self.evidence_sha256, "target certificate evidence SHA-256")
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=self.dependencies,
            context="indirect-target certificate",
        )
        expected_id = "indirect-target-certificate:" + canonical_sha256_v3(
            self.binding_payload()
        )[:24]
        if self.certificate_id != expected_id:
            fail(
                "stale_record_id",
                "indirect-target certificate ID does not bind its exact exit",
                f"recreate it as {expected_id!r}",
            )
        expected_sha = canonical_sha256_v3(self.decision_payload())
        if self.certificate_sha256 != expected_sha:
            fail(
                "stale_record_id",
                "indirect-target certificate digest does not bind its decision",
                f"recreate it with certificate_sha256={expected_sha}",
            )

    def binding_payload(self) -> dict[str, Any]:
        return {
            "exit_id": self.exit_id,
            "source_unit_id": self.source_unit_id,
            "source_unit_sha256": self.source_unit_sha256,
            "source_rva": self.source_rva,
            "source_event_index": self.source_event_index,
            "transfer_kind": self.transfer_kind,
            "target_expression": self.target_expression.to_value(),
            "target_expression_sha256": self.target_expression_sha256,
        }

    def decision_payload(self) -> dict[str, Any]:
        return {
            "id": self.certificate_id,
            **self.binding_payload(),
            "status": self.status,
            "authorizing": self.authorizing,
            "target_unit_ids": list(self.target_unit_ids),
            "external_targets": canonical_json_rows(self.external_targets),
            "evaluation_method": self.evaluation_method,
            "evidence_sha256": self.evidence_sha256,
            "dependencies": encode_dependencies_v3(self.dependencies),
            "primary_blocker": blocker_payload_v3(self.primary_blocker),
        }

    @classmethod
    def create(
        cls,
        *,
        occurrence: IndirectExitOccurrenceV3,
        source: SemanticIndexRecordV3,
        status: str,
        target_unit_ids: Iterable[str] = (),
        external_targets: Iterable[CanonicalValueV3] = (),
        evaluation_method: str | None,
        evidence_sha256: str | None,
        dependencies: Iterable[RecordDependencyV3],
        primary_blocker: PrimaryBlockerV3 | None,
    ) -> "IndirectTargetCertificateV3":
        binding = {
            "exit_id": occurrence.exit_id,
            "source_unit_id": source.record_id,
            "source_unit_sha256": source.unit_sha256,
            "source_rva": source.rva_start,
            "source_event_index": occurrence.event_index,
            "transfer_kind": occurrence.transfer_kind,
            "target_expression": occurrence.target_expression.to_value(),
            "target_expression_sha256": canonical_sha256_v3(
                occurrence.target_expression.to_value()
            ),
        }
        certificate_id = "indirect-target-certificate:" + canonical_sha256_v3(
            binding
        )[:24]
        units = tuple(sorted(set(target_unit_ids))) if status == "complete" else ()
        external = (
            _canonical_values(external_targets) if status == "complete" else ()
        )
        deps = canonical_dependencies_v3(dependencies)
        decision = {
            "id": certificate_id,
            **binding,
            "status": status,
            "authorizing": status == "complete",
            "target_unit_ids": list(units),
            "external_targets": canonical_json_rows(external),
            "evaluation_method": evaluation_method,
            "evidence_sha256": evidence_sha256,
            "dependencies": encode_dependencies_v3(deps),
            "primary_blocker": blocker_payload_v3(primary_blocker),
        }
        return cls(
            certificate_id=certificate_id,
            exit_id=occurrence.exit_id,
            source_unit_id=source.record_id,
            source_unit_sha256=source.unit_sha256,
            source_rva=source.rva_start,
            source_event_index=occurrence.event_index,
            transfer_kind=occurrence.transfer_kind,
            target_expression=occurrence.target_expression,
            target_expression_sha256=binding["target_expression_sha256"],
            status=status,
            authorizing=status == "complete",
            target_unit_ids=units,
            external_targets=external,
            evaluation_method=evaluation_method,
            evidence_sha256=evidence_sha256,
            dependencies=deps,
            primary_blocker=primary_blocker,
            certificate_sha256=canonical_sha256_v3(decision),
        )


def _encode_certificate(value: IndirectTargetCertificateV3) -> dict[str, Any]:
    return {
        "schema": INDIRECT_TARGET_CERTIFICATE_RECORD_V3_SCHEMA,
        **value.decision_payload(),
        "certificate_sha256": value.certificate_sha256,
    }


def _decode_certificate(value: Any) -> IndirectTargetCertificateV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "exit_id",
            "source_unit_id",
            "source_unit_sha256",
            "source_rva",
            "source_event_index",
            "transfer_kind",
            "target_expression",
            "target_expression_sha256",
            "status",
            "authorizing",
            "target_unit_ids",
            "external_targets",
            "evaluation_method",
            "evidence_sha256",
            "dependencies",
            "primary_blocker",
            "certificate_sha256",
        },
        "indirect-target certificate",
    )
    if row["schema"] != INDIRECT_TARGET_CERTIFICATE_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not an indirect-target-certificate-record-v3",
            "use INDIRECT_TARGET_CERTIFICATE_CODEC_V3 with matching records",
        )
    blocker = (
        None
        if row["primary_blocker"] is None
        else PrimaryBlockerV3.parse(row["primary_blocker"])
    )
    authorizing = boolean(row["authorizing"], "target certificate authorizing")
    return IndirectTargetCertificateV3(
        certificate_id=text(row["id"], "target certificate ID"),
        exit_id=text(row["exit_id"], "target certificate exit ID"),
        source_unit_id=text(row["source_unit_id"], "target certificate source unit"),
        source_unit_sha256=digest(row["source_unit_sha256"], "target source SHA-256"),
        source_rva=uint(row["source_rva"], "target source RVA"),
        source_event_index=(
            None
            if row["source_event_index"] is None
            else uint(row["source_event_index"], "target event index")
        ),
        transfer_kind=text(row["transfer_kind"], "target transfer kind"),
        target_expression=CanonicalValueV3.of(row["target_expression"]),
        target_expression_sha256=digest(
            row["target_expression_sha256"], "target expression SHA-256"
        ),
        status=text(row["status"], "target certificate status"),
        authorizing=authorizing,
        target_unit_ids=canonical_strings(
            row["target_unit_ids"], "target certificate unit IDs"
        ),
        external_targets=canonical_sort(
            sequence(row["external_targets"], "target certificate external targets")
        ),
        evaluation_method=optional_text(
            row["evaluation_method"], "target evaluation method"
        ),
        evidence_sha256=(
            None
            if row["evidence_sha256"] is None
            else digest(row["evidence_sha256"], "target evidence SHA-256")
        ),
        dependencies=decode_dependencies_v3(row["dependencies"]),
        primary_blocker=blocker,
        certificate_sha256=digest(
            row["certificate_sha256"], "target certificate SHA-256"
        ),
    )


INDIRECT_TARGET_CERTIFICATE_CODEC_V3 = RecordCodecV3[IndirectTargetCertificateV3](
    decode=_decode_certificate,
    encode=_encode_certificate,
)


@dataclass(frozen=True)
class IndirectTargetCertificateUnitV3:
    record_id: str
    source_unit_id: str
    unit_sha256: str
    status: str
    authorizing: bool
    certificates: tuple[IndirectTargetCertificateV3, ...]
    dependencies: tuple[RecordDependencyV3, ...]
    primary_blocker: PrimaryBlockerV3 | None

    def __post_init__(self) -> None:
        if self.record_id != self.source_unit_id:
            fail(
                "stale_record_id",
                "target-certificate unit record does not use its source unit ID",
                "preserve the semantic-index unit ID",
            )
        digest(self.unit_sha256, "target-certificate unit SHA-256")
        if self.certificates != tuple(
            sorted(self.certificates, key=lambda row: row.exit_id)
        ) or len({row.exit_id for row in self.certificates}) != len(self.certificates):
            fail(
                "noncanonical_record_order",
                "target certificates are duplicated or unsorted",
                "sort exact certificates by exit ID",
            )
        if any(row.source_unit_id != self.source_unit_id for row in self.certificates):
            fail(
                "target_certificate_unit_mismatch",
                "target-certificate unit contains a foreign exit",
                "partition target certificates by exact source unit",
            )
        validate_authority_decision_v3(
            status=self.status,
            authorizing=self.authorizing,
            primary_blocker=self.primary_blocker,
            dependencies=self.dependencies,
            context="indirect-target certificate unit",
        )
        expected = aggregate_blockers_v3(
            row.primary_blocker
            for row in self.certificates
            if row.primary_blocker is not None
        )
        if self.primary_blocker != expected:
            fail(
                "target_certificate_decision_contradiction",
                "unit target-certificate status does not summarize its certificates",
                "derive the unit decision from all exact indirect exits",
            )


def _encode_unit(value: IndirectTargetCertificateUnitV3) -> dict[str, Any]:
    return {
        "schema": INDIRECT_TARGET_CERTIFICATE_UNIT_RECORD_V3_SCHEMA,
        "id": value.record_id,
        "source_unit_id": value.source_unit_id,
        "unit_sha256": value.unit_sha256,
        "status": value.status,
        "authorizing": value.authorizing,
        "certificates": [_encode_certificate(row) for row in value.certificates],
        "dependencies": encode_dependencies_v3(value.dependencies),
        "primary_blocker": blocker_payload_v3(value.primary_blocker),
    }


def _decode_unit(value: Any) -> IndirectTargetCertificateUnitV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "source_unit_id",
            "unit_sha256",
            "status",
            "authorizing",
            "certificates",
            "dependencies",
            "primary_blocker",
        },
        "indirect-target certificate unit",
    )
    if row["schema"] != INDIRECT_TARGET_CERTIFICATE_UNIT_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not an indirect-target-certificate-unit-record-v3",
            "use INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3 with matching records",
        )
    return IndirectTargetCertificateUnitV3(
        record_id=text(row["id"], "target-certificate unit ID"),
        source_unit_id=text(row["source_unit_id"], "target-certificate source unit"),
        unit_sha256=digest(row["unit_sha256"], "target-certificate unit SHA-256"),
        status=text(row["status"], "target-certificate unit status"),
        authorizing=boolean(row["authorizing"], "target-certificate unit authority"),
        certificates=tuple(
            sorted(
                (
                    _decode_certificate(item)
                    for item in sequence(row["certificates"], "target certificates")
                ),
                key=lambda item: item.exit_id,
            )
        ),
        dependencies=decode_dependencies_v3(row["dependencies"]),
        primary_blocker=(
            None
            if row["primary_blocker"] is None
            else PrimaryBlockerV3.parse(row["primary_blocker"])
        ),
    )


INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3 = RecordCodecV3[
    IndirectTargetCertificateUnitV3
](decode=_decode_unit, encode=_encode_unit)


def _record_or_none(
    context: PhaseContextV3, input_name: str, record_id: str
) -> ArtifactRecordV3 | None:
    return context.optional_record(input_name, record_id)


def _target_expression_subject(expression: Any) -> tuple[str | None, tuple[int, int] | None]:
    if not isinstance(expression, Mapping):
        return None, None
    if expression.get("op") == "reg" and isinstance(expression.get("name"), str):
        return f"register:{expression['name']}", None
    if expression.get("op") != "load":
        return None, None
    width = expression.get("width")
    address = expression.get("address")
    if (
        not isinstance(width, int)
        or isinstance(width, bool)
        or width <= 0
        or not isinstance(address, Mapping)
        or address.get("op") != "const"
        or not isinstance(address.get("value"), int)
        or isinstance(address.get("value"), bool)
    ):
        return None, None
    start = int(address["value"])
    end = start + width
    if not 0 <= start < end <= 1 << 32:
        return None, None
    return f"memory-range:{start}:{end}", (start, end)


def _finite_values(fact: InvariantFactV3) -> tuple[Any, ...] | None:
    predicate = mapping(fact.predicate.to_value(), "target invariant predicate")
    if predicate.get("kind") == "exact":
        return (predicate.get("value"),)
    if predicate.get("kind") == "finite":
        return tuple(sequence(predicate.get("values"), "target finite invariant values"))
    return None


def _external_machine_value(value: CanonicalValueV3) -> int | None:
    row = value.to_value()
    if not isinstance(row, Mapping):
        return None
    machine_value = row.get("machine_target_value")
    if (
        not isinstance(machine_value, int)
        or isinstance(machine_value, bool)
        or not 0 <= machine_value < 1 << 32
    ):
        return None
    return machine_value


def _checked_target_values(
    context: PhaseContextV3,
    evidence: TargetEvaluationEvidenceV3,
) -> tuple[tuple[int, ...], list[PrimaryBlockerV3], list[RecordDependencyV3]]:
    values: list[int] = []
    blockers: list[PrimaryBlockerV3] = []
    dependencies: list[RecordDependencyV3] = []
    for unit_id in evidence.target_unit_ids:
        dependency = RecordDependencyV3("semantic_index_global", unit_id)
        target_record = _record_or_none(context, dependency.input_name, unit_id)
        if target_record is None:
            blockers.append(
                PrimaryBlockerV3(
                    "violated", "indirect_target_unit_unknown"
                )
            )
            continue
        dependencies.append(dependency)
        target = SEMANTIC_INDEX_CODEC_V3.read(target_record).value
        values.append(target.rva_start)
    for target in evidence.external_targets:
        machine_value = _external_machine_value(target)
        if machine_value is None:
            blockers.append(
                PrimaryBlockerV3("incomplete", "external_target_membership_unproven")
            )
        else:
            values.append(machine_value)
    if len(values) != len(set(values)):
        blockers.append(
            PrimaryBlockerV3("incomplete", "indirect_target_value_mapping_ambiguous")
        )
    return tuple(sorted(set(values))), blockers, dependencies


def _checked_indexed_pe_table_blockers(
    context: PhaseContextV3,
    *,
    evidence: TargetEvaluationEvidenceV3,
    semantic: SemanticIndexRecordV3,
    occurrence: IndirectExitOccurrenceV3,
) -> list[PrimaryBlockerV3]:
    """Recheck the compact binding exported by the exact PE-table provider.

    Exact PE-byte, section, guard, and alias checking happens in the dedicated
    provider.  This phase checks that its immutable certificate still names
    this exact exit and the exact semantic-index targets consumed by graph
    composition.  The provider artifact itself is content-addressed and binds
    the PE, semantic index, transitions, and structural proposal manifests.
    """

    if evidence.evaluation_certificate is None:
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_missing")
        ]
    try:
        certificate = mapping(
            evidence.evaluation_certificate.to_value(),
            "indexed PE-table target certificate",
        )
    except AnalysisV3Error:
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_malformed")
        ]
    required = {
        "kind",
        "exit_id",
        "source_unit_id",
        "source_rva",
        "source_event_index",
        "transfer_kind",
        "target_expression_sha256",
        "image_base",
        "table_rva",
        "entry_width",
        "entry_count",
        "table_sha256",
        "selector_sha256",
        "predecessors",
        "entries",
        "target_unit_ids",
    }
    if set(certificate) != required:
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_malformed")
        ]
    if (
        certificate["kind"] != _INDEXED_PE_TABLE_CERTIFICATE_KIND_V3
        or certificate["exit_id"] != occurrence.exit_id
        or certificate["source_unit_id"] != semantic.record_id
        or certificate["source_rva"] != semantic.rva_start
        or certificate["source_event_index"] != occurrence.event_index
        or certificate["transfer_kind"] != occurrence.transfer_kind
        or certificate["target_expression_sha256"]
        != canonical_sha256_v3(occurrence.target_expression.to_value())
        or certificate["entry_width"] != 4
    ):
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_contradiction")
        ]
    scalar_uints = ("image_base", "table_rva", "entry_count")
    if any(
        not isinstance(certificate[field], int)
        or isinstance(certificate[field], bool)
        or certificate[field] < 0
        for field in scalar_uints
    ):
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_malformed")
        ]
    if certificate["entry_count"] <= 0:
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_malformed")
        ]
    for field in ("table_sha256", "selector_sha256"):
        value = certificate[field]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            return [
                PrimaryBlockerV3("violated", "indexed_target_certificate_malformed")
            ]
    raw_targets = certificate["target_unit_ids"]
    raw_entries = certificate["entries"]
    raw_predecessors = certificate["predecessors"]
    if (
        not isinstance(raw_targets, list)
        or any(not isinstance(row, str) or not row for row in raw_targets)
        or raw_targets != sorted(set(raw_targets))
        or tuple(raw_targets) != evidence.target_unit_ids
        or not isinstance(raw_entries, list)
        or len(raw_entries) != certificate["entry_count"]
        or not isinstance(raw_predecessors, list)
        or not raw_predecessors
    ):
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_contradiction")
        ]
    entry_targets: set[str] = set()
    for expected_index, row in enumerate(raw_entries):
        if not isinstance(row, Mapping) or set(row) != {
            "index",
            "entry_rva",
            "target_rva",
            "target_unit_id",
        }:
            return [
                PrimaryBlockerV3("violated", "indexed_target_certificate_malformed")
            ]
        target_id = row["target_unit_id"]
        target_record = (
            None
            if not isinstance(target_id, str)
            else _record_or_none(context, "semantic_index_global", target_id)
        )
        if (
            row["index"] != expected_index
            or not isinstance(row["entry_rva"], int)
            or isinstance(row["entry_rva"], bool)
            or not isinstance(row["target_rva"], int)
            or isinstance(row["target_rva"], bool)
            or target_record is None
        ):
            return [
                PrimaryBlockerV3("violated", "indexed_target_certificate_contradiction")
            ]
        target = SEMANTIC_INDEX_CODEC_V3.read(target_record).value
        if target.rva_start != row["target_rva"]:
            return [
                PrimaryBlockerV3("violated", "indexed_target_certificate_contradiction")
            ]
        entry_targets.add(target_id)
    if entry_targets != set(evidence.target_unit_ids):
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_contradiction")
        ]
    for row in raw_predecessors:
        if not isinstance(row, Mapping) or set(row) != {
            "source_unit_id",
            "guard_sha256",
            "upper_exclusive",
            "support_unit_ids",
            "support_summary_ids",
        }:
            return [
                PrimaryBlockerV3("violated", "indexed_target_certificate_malformed")
            ]
        if (
            not isinstance(row["source_unit_id"], str)
            or _record_or_none(
                context, "semantic_index_global", row["source_unit_id"]
            ) is None
            or not isinstance(row["guard_sha256"], str)
            or len(row["guard_sha256"]) != 64
            or row["upper_exclusive"] != certificate["entry_count"]
            or not isinstance(row["support_unit_ids"], list)
            or row["support_unit_ids"] != sorted(set(row["support_unit_ids"]))
            or row["source_unit_id"] not in row["support_unit_ids"]
            or any(
                not isinstance(unit_id, str)
                or _record_or_none(context, "semantic_index_global", unit_id) is None
                for unit_id in row["support_unit_ids"]
            )
            or not isinstance(row["support_summary_ids"], list)
            or row["support_summary_ids"] != sorted(set(row["support_summary_ids"]))
            or not row["support_summary_ids"]
            or any(not isinstance(summary_id, str) for summary_id in row["support_summary_ids"])
        ):
            return [
                PrimaryBlockerV3("violated", "indexed_target_certificate_contradiction")
            ]
    return []


def _transition_binds_occurrence(
    summary: TransitionSummaryRecordV3, occurrence: IndirectExitOccurrenceV3
) -> bool:
    candidates = tuple(
        row
        for row in summary.exits
        if row.transfer_kind == occurrence.transfer_kind
        and (
            (occurrence.event_index is None and row.source_kind == "outcome")
            or (
                occurrence.event_index is not None
                and row.source_kind == "external_event"
                and row.source_index == occurrence.event_index
            )
        )
    )
    if len(candidates) != 1:
        return False
    exact = candidates[0].exact_record.to_value()
    return isinstance(exact, Mapping) and CanonicalValueV3.of(
        exact.get("target")
    ) == occurrence.target_expression


def _memory_blockers(
    memory: MemoryVersionRecordV3,
    *,
    semantic: SemanticIndexRecordV3,
    summary: TransitionSummaryRecordV3,
    memory_range: tuple[int, int] | None,
) -> list[PrimaryBlockerV3]:
    blockers: list[PrimaryBlockerV3] = []
    if memory.binary.pe_sha256 != semantic.pe_sha256:
        blockers.append(PrimaryBlockerV3("violated", "target_memory_binary_contradiction"))
    if summary.summary_id not in memory.transition_summary_ids:
        blockers.append(
            PrimaryBlockerV3("violated", "target_memory_transition_inventory_contradiction")
        )
    if memory_range is None:
        # Register and exact-value target proofs do not consume a memory alias
        # component. SCC-local memory frontiers therefore cannot invalidate
        # them; their register/call dependencies are checked by inductive
        # authority instead.
        return blockers
    start, end = memory_range
    components = tuple(
        component
        for component in memory.alias_components
        if any(row.start <= start and end <= row.end for row in component.ranges)
    )
    if len(components) != 1:
        blockers.append(
            PrimaryBlockerV3("incomplete", "target_memory_component_not_unique")
        )
        return blockers
    component_id = components[0].component_id
    component_access_ids = set(components[0].access_ids)
    unresolved = tuple(
        row
        for row in memory.issues
        if row.code != "indirect_control_requires_target_certificate"
        and not (
            row.code == "unknown_read_alias"
            and row.subject_id not in component_access_ids
        )
    )
    if unresolved:
        blockers.append(
            PrimaryBlockerV3(
                "violated"
                if any(row.status == "violated" for row in unresolved)
                else "incomplete",
                "target_memory_evidence_not_complete",
                "memory_versions",
                memory.record_id,
            )
        )
    if components[0].contains_unknown_address:
        blockers.append(PrimaryBlockerV3("incomplete", "target_memory_evidence_tainted"))
    if any(
        kill.affected_scope == "all_components"
        or component_id in kill.affected_component_ids
        for kill in memory.unknown_write_kills
    ):
        blockers.append(PrimaryBlockerV3("incomplete", "target_memory_evidence_tainted"))
    return blockers


def _derive_certificate(
    context: PhaseContextV3,
    *,
    semantic: SemanticIndexRecordV3,
    summary: TransitionSummaryRecordV3,
    proposal: StructuralTargetProposalV3 | None,
    occurrence: IndirectExitOccurrenceV3,
) -> IndirectTargetCertificateV3:
    dependencies: list[RecordDependencyV3] = [
        RecordDependencyV3("semantic_index", semantic.record_id),
        RecordDependencyV3("structural_targets", semantic.record_id),
        RecordDependencyV3("transition_summaries", summary.record_id),
    ]
    blockers: list[PrimaryBlockerV3] = []
    for input_name, code in (
        ("semantic_index", "target_semantic_artifact_not_complete"),
        ("structural_targets", "structural_target_artifact_not_complete"),
        ("transition_summaries", "target_transition_artifact_not_complete"),
    ):
        blocker = manifest_blocker_v3(context, input_name, code)
        if blocker is not None:
            blockers.append(blocker)
    # Partial evidence packs are expected: independently checked exits remain
    # useful while unrelated exits are unresolved.  A contradicted pack still
    # poisons every consumer because its integrity cannot be established.
    target_evidence_manifest = context.manifest("target_evidence")
    if target_evidence_manifest.status == "violated":
        blockers.append(
            PrimaryBlockerV3(
                "violated", "target_evaluation_evidence_artifact_not_complete"
            )
        )
    if not _transition_binds_occurrence(summary, occurrence):
        blockers.append(PrimaryBlockerV3("violated", "target_transition_binding_contradiction"))
    if proposal is None:
        blockers.append(
            PrimaryBlockerV3(
                "violated", "indirect_target_inventory_contradiction", "structural_targets", semantic.record_id
            )
        )
    elif (
        proposal.source_unit_id != semantic.record_id
        or proposal.source_rva != semantic.rva_start
        or proposal.source_event_index != occurrence.event_index
        or proposal.transfer_kind != occurrence.transfer_kind
    ):
        blockers.append(
            PrimaryBlockerV3(
                "violated", "indirect_target_binding_contradiction", "structural_targets", semantic.record_id
            )
        )

    evidence_record = _record_or_none(context, "target_evidence", occurrence.exit_id)
    evidence: TargetEvaluationEvidenceV3 | None = None
    if evidence_record is None:
        blockers.append(
            PrimaryBlockerV3("incomplete", "target_evaluation_evidence_missing")
        )
    else:
        dependencies.append(RecordDependencyV3("target_evidence", occurrence.exit_id))
        evidence = TARGET_EVALUATION_EVIDENCE_CODEC_V3.read(evidence_record).value
        if (
            evidence.record_id != occurrence.exit_id
            or evidence.source_unit_id != semantic.record_id
            or evidence.source_rva != semantic.rva_start
            or evidence.source_event_index != occurrence.event_index
            or evidence.transfer_kind != occurrence.transfer_kind
            or evidence.target_expression_sha256
            != canonical_sha256_v3(occurrence.target_expression.to_value())
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated", "target_evaluation_binding_contradiction", "target_evidence", occurrence.exit_id
                )
            )
        if proposal is not None and proposal.status == "recovered" and (
            evidence.target_unit_ids != proposal.target_unit_ids
            or evidence.external_targets != proposal.external_targets
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated", "target_evaluation_inventory_contradiction", "target_evidence", occurrence.exit_id
                )
                )

    if (
        proposal is not None
        and proposal.status != "recovered"
        and (
            proposal.status == "violated"
            or evidence is None
        )
    ):
        blockers.append(
            PrimaryBlockerV3(
                "violated" if proposal.status == "violated" else "incomplete",
                proposal.issue_codes[0]
                if proposal.issue_codes
                else "indirect_target_not_recovered",
                "structural_targets",
                semantic.record_id,
            )
        )

    if evidence is not None:
        expression_subject, memory_range = _target_expression_subject(
            occurrence.target_expression.to_value()
        )
        if evidence.evaluation_method != "checked_indexed_pe_table":
            memory_dependency = RecordDependencyV3(
                "memory_versions", evidence.memory_record_id
            )
            dependencies.append(memory_dependency)
            memory_record = _record_or_none(
                context, memory_dependency.input_name, memory_dependency.record_id
            )
            if memory_record is None:
                blockers.append(
                    PrimaryBlockerV3(
                        "incomplete", "target_memory_evidence_missing", memory_dependency.input_name, memory_dependency.record_id
                    )
                )
            else:
                memory = MEMORY_VERSION_CODEC_V3.read(memory_record).value
                blockers.extend(
                    _memory_blockers(
                        memory,
                        semantic=semantic,
                        summary=summary,
                        memory_range=memory_range,
                    )
                )
        checked_values, value_blockers, target_dependencies = _checked_target_values(
            context, evidence
        )
        blockers.extend(value_blockers)
        dependencies.extend(target_dependencies)
        if evidence.evaluation_method == "exact_constant":
            raw = occurrence.target_expression.to_value()
            if (
                not isinstance(raw, Mapping)
                or raw.get("op") != "const"
                or not isinstance(raw.get("value"), int)
                or isinstance(raw.get("value"), bool)
            ):
                blockers.append(
                    PrimaryBlockerV3("violated", "constant_target_expression_contradiction")
                )
            elif checked_values != (raw["value"],):
                blockers.append(
                    PrimaryBlockerV3("violated", "constant_target_membership_contradiction")
                )
        elif evidence.evaluation_method == "inductive_finite_values":
            if expression_subject is None:
                blockers.append(
                    PrimaryBlockerV3("incomplete", "target_expression_subject_unsupported")
                )
            inductive_record = _record_or_none(
                context, "inductive_inputs", semantic.record_id
            )
            if inductive_record is None:
                blockers.append(
                    PrimaryBlockerV3("incomplete", "target_inductive_cutpoint_missing")
                )
            else:
                dependencies.append(
                    RecordDependencyV3("inductive_inputs", semantic.record_id)
                )
                cutpoint = INDUCTIVE_INPUT_CODEC_V3.read(inductive_record).value
                if not isinstance(cutpoint, InductiveCutpointV3):
                    blockers.append(
                        PrimaryBlockerV3("violated", "target_inductive_record_contradiction")
                    )
                else:
                    facts = tuple(
                        row
                        for row in cutpoint.invariant.facts
                        if row.fact_id == evidence.inductive_fact_id
                    )
                    if len(facts) != 1:
                        blockers.append(
                            PrimaryBlockerV3(
                                "incomplete" if not facts else "violated",
                                "target_inductive_fact_missing" if not facts else "target_inductive_fact_ambiguous",
                            )
                        )
                    else:
                        fact = facts[0]
                        if fact.subject != expression_subject:
                            blockers.append(
                                PrimaryBlockerV3("violated", "target_inductive_subject_contradiction")
                            )
                        values = _finite_values(fact)
                        if values is None:
                            blockers.append(
                                PrimaryBlockerV3("incomplete", "target_inductive_fact_not_finite")
                            )
                        elif (
                            any(not isinstance(row, int) or isinstance(row, bool) for row in values)
                            or tuple(sorted(set(values))) != checked_values
                        ):
                            blockers.append(
                                PrimaryBlockerV3("violated", "target_inductive_membership_contradiction")
                            )
        else:
            if evidence.evaluation_certificate is not None:
                raw_indexed = evidence.evaluation_certificate.to_value()
                if isinstance(raw_indexed, Mapping):
                    raw_predecessors = raw_indexed.get("predecessors")
                    if isinstance(raw_predecessors, list):
                        dependencies.extend(
                            RecordDependencyV3("semantic_index_global", source_id)
                            for row in raw_predecessors
                            if isinstance(row, Mapping)
                            for source_id in row.get("support_unit_ids", [])
                            if isinstance(source_id, str)
                            and source_id
                        )
            blockers.extend(
                _checked_indexed_pe_table_blockers(
                    context,
                    evidence=evidence,
                    semantic=semantic,
                    occurrence=occurrence,
                )
            )

    primary = aggregate_blockers_v3(blockers)
    status = "complete" if primary is None else primary.status
    return IndirectTargetCertificateV3.create(
        occurrence=occurrence,
        source=semantic,
        status=status,
        target_unit_ids=(
            () if evidence is None else evidence.target_unit_ids
        ),
        external_targets=(
            () if evidence is None else evidence.external_targets
        ),
        evaluation_method=(None if evidence is None else evidence.evaluation_method),
        evidence_sha256=(None if evidence is None else evidence.evidence_sha256),
        dependencies=dependencies,
        primary_blocker=primary,
    )


def _derive_unit(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> IndirectTargetCertificateUnitV3:
    semantic = context.typed_record(
        "semantic_index", source, SEMANTIC_INDEX_CODEC_V3
    ).value
    summary_record = context.record("transition_summaries", semantic.record_id)
    summary = context.typed_record(
        "transition_summaries", summary_record, TRANSITION_SUMMARY_CODEC_V3
    ).value
    target_record = context.record("structural_targets", semantic.record_id)
    target_unit = context.typed_record(
        "structural_targets", target_record, STRUCTURAL_TARGET_UNIT_CODEC_V3
    ).value
    proposal_by_id = {row.record_id: row for row in target_unit.proposals}
    expected_ids = {row.exit_id for row in semantic.indirect_exits}
    proposal_ids = set(proposal_by_id)
    certificates = tuple(
        _derive_certificate(
            context,
            semantic=semantic,
            summary=summary,
            proposal=proposal_by_id.get(occurrence.exit_id),
            occurrence=occurrence,
        )
        for occurrence in semantic.indirect_exits
    )
    dependencies = canonical_dependencies_v3(
        dependency
        for certificate in certificates
        for dependency in certificate.dependencies
    )
    if not certificates:
        dependencies = canonical_dependencies_v3(
            (
                RecordDependencyV3("semantic_index", semantic.record_id),
                RecordDependencyV3("structural_targets", semantic.record_id),
                RecordDependencyV3("transition_summaries", semantic.record_id),
            )
        )
    blockers = [
        row.primary_blocker
        for row in certificates
        if row.primary_blocker is not None
    ]
    if expected_ids != proposal_ids:
        blockers.append(
            PrimaryBlockerV3(
                "violated",
                "indirect_target_inventory_contradiction",
                "structural_targets",
                semantic.record_id,
            )
        )
    primary = aggregate_blockers_v3(blockers)
    status = "complete" if primary is None else primary.status
    return IndirectTargetCertificateUnitV3(
        record_id=semantic.record_id,
        source_unit_id=semantic.record_id,
        unit_sha256=semantic.unit_sha256,
        status=status,
        authorizing=status == "complete",
        certificates=certificates,
        dependencies=dependencies,
        primary_blocker=primary,
    )


def _transform_unit(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    value = _derive_unit(context, source)
    return INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.write(
        value.record_id, value
    )


def check_indirect_target_certificates_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    outputs = sorted_records(reader.iter_records())
    require_record_ids(
        outputs,
        (row.record_id for row in context.records("semantic_index")),
        "indirect-target certificate units",
    )
    expected_evidence_ids: set[str] = set()
    for output in outputs:
        source = context.record("semantic_index", output.record_id)
        expected = _derive_unit(context, source)
        submitted = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(output).value
        if submitted != expected:
            fail(
                "indirect_target_certificate_contradiction",
                f"target-certificate unit {output.record_id!r} is stale",
                "rerun target-certificate checking from exact inputs",
            )
        if output.dependencies != expected.dependencies:
            fail(
                "incomplete_record_dependencies",
                f"target-certificate unit {output.record_id!r} has stale dependencies",
                "let the phase attach every exact semantic, memory, invariant, and target dependency",
            )
        expected_evidence_ids.update(row.exit_id for row in expected.certificates)
    evidence_ids = {
        row.record_id for row in context.records("target_evidence")
    }
    unknown = sorted(evidence_ids - expected_evidence_ids)
    if unknown:
        fail(
            "unknown_target_evaluation_evidence",
            f"target evidence names absent exact exits {unknown!r}",
            "remove stale evidence or bind it to an exact semantic indirect exit",
        )


def flatten_indirect_target_certificates_v3(
    records: Iterable[ArtifactRecordV3],
) -> tuple[IndirectTargetCertificateV3, ...]:
    certificates = tuple(
        certificate
        for record in sorted_records(records)
        for certificate in INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(record).value.certificates
    )
    if len({row.exit_id for row in certificates}) != len(certificates):
        fail(
            "duplicate_indirect_target_certificate",
            "target-certificate units repeat an exact exit",
            "repair the exact source-unit partition",
        )
    return tuple(sorted(certificates, key=lambda row: row.exit_id))


INDIRECT_TARGET_CERTIFICATES_PHASE_V3 = map_units(
    name="indirect-target-certificates-v3",
    version="1",
    source_input="semantic_index",
    input_artifact_kinds={
        "inductive_inputs": "inductive-inputs-v3",
        "memory_versions": "memory-versions-v3",
        "semantic_index": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
        "semantic_index_global": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
        "structural_targets": STRUCTURAL_TARGETS_ARTIFACT_KIND_V3,
        "target_evidence": TARGET_EVALUATION_EVIDENCE_ARTIFACT_KIND_V3,
        "transition_summaries": TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    },
    output_artifact_kind=INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
    transform=_transform_unit,
    completeness=check_indirect_target_certificates_completeness_v3,
    unit_aligned_inputs=("structural_targets", "transition_summaries"),
)


__all__ = [
    "INDIRECT_TARGET_CERTIFICATE_CODEC_V3",
    "INDIRECT_TARGET_CERTIFICATE_RECORD_V3_SCHEMA",
    "INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3",
    "INDIRECT_TARGET_CERTIFICATE_UNIT_RECORD_V3_SCHEMA",
    "INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3",
    "INDIRECT_TARGET_CERTIFICATES_PHASE_V3",
    "IndirectTargetCertificateUnitV3",
    "IndirectTargetCertificateV3",
    "TARGET_EVALUATION_EVIDENCE_ARTIFACT_KIND_V3",
    "TARGET_EVALUATION_EVIDENCE_CODEC_V3",
    "TARGET_EVALUATION_EVIDENCE_RECORD_V3_SCHEMA",
    "TargetEvaluationEvidenceV3",
    "check_indirect_target_certificates_completeness_v3",
    "flatten_indirect_target_certificates_v3",
]
