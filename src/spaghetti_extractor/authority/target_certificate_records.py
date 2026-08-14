"""Target-certificate wire schemas, immutable records, and codecs."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    CanonicalValueV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..phase_framework_v3 import RecordCodecV3
from ._schema import (
    boolean,
    canonical_json_rows,
    canonical_sort,
    canonical_strings,
    digest,
    fail,
    optional_text,
    optional_uint,
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
    validate_authority_decision_v3,
)
from .semantic_index import IndirectExitOccurrenceV3, SemanticIndexRecordV3


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


__all__ = [
    "INDIRECT_TARGET_CERTIFICATE_CODEC_V3",
    "INDIRECT_TARGET_CERTIFICATE_RECORD_V3_SCHEMA",
    "INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3",
    "INDIRECT_TARGET_CERTIFICATE_UNIT_RECORD_V3_SCHEMA",
    "INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3",
    "IndirectTargetCertificateUnitV3",
    "IndirectTargetCertificateV3",
    "TARGET_EVALUATION_EVIDENCE_ARTIFACT_KIND_V3",
    "TARGET_EVALUATION_EVIDENCE_CODEC_V3",
    "TARGET_EVALUATION_EVIDENCE_RECORD_V3_SCHEMA",
    "TargetEvaluationEvidenceV3",
    "flatten_indirect_target_certificates_v3",
]
