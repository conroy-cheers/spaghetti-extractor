"""Typed qualification records for portable source and library owners.

Implementation discovery and semantic qualification are intentionally separate.
This module represents the checked result consumed by the ownership ledger; it
does not infer qualification from a source binding or a library-recognition
record.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from functools import cached_property
from typing import Any, Mapping, Sequence

from .authority_bindings_v2 import (
    AuthorityDataError,
    _array,
    _object,
    _sha256,
    _text,
    canonical_json,
    canonical_json_bytes,
)


LIFT_QUALIFICATION_V1_FORMAT = "spaghetti-extractor-lift-qualification-v1"


class QualificationSubjectKindV1(str, Enum):
    SOURCE_PROJECT = "source_project"
    LIBRARY_ISLAND = "library_island"
    LINKED_RUNTIME = "linked_runtime"


class QualificationAssuranceClassV1(str, Enum):
    CHECKED_SEMANTIC_REFINEMENT = "checked_semantic_refinement"
    VALIDATION_BACKED_RECONSTRUCTION = "validation_backed_reconstruction"
    PINNED_RUNTIME_SUBSTITUTION = "pinned_runtime_substitution"


class QualificationStatusV1(str, Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    VIOLATED = "violated"


@dataclass(frozen=True, order=True)
class QualificationEvidenceV1:
    evidence_class: str
    artifact_kind: str
    artifact_id: str
    artifact_sha256: str
    status: QualificationStatusV1

    def __post_init__(self) -> None:
        _text(self.evidence_class, "qualification evidence class", maximum=128)
        _text(self.artifact_kind, "qualification artifact kind", maximum=128)
        _text(self.artifact_id, "qualification artifact ID", maximum=512)
        _sha256(self.artifact_sha256, "qualification artifact SHA-256")
        if not isinstance(self.status, QualificationStatusV1):
            raise AuthorityDataError("qualification evidence status must be typed")

    def to_payload(self) -> dict[str, str]:
        return {
            "evidence_class": self.evidence_class,
            "artifact_kind": self.artifact_kind,
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "status": self.status.value,
        }

    @classmethod
    def parse(cls, value: Any) -> "QualificationEvidenceV1":
        row = _object(
            value,
            {
                "evidence_class",
                "artifact_kind",
                "artifact_id",
                "artifact_sha256",
                "status",
            },
            "qualification evidence",
        )
        try:
            status = QualificationStatusV1(row["status"])
        except (TypeError, ValueError) as exc:
            raise AuthorityDataError("qualification evidence has invalid status") from exc
        return cls(
            evidence_class=_text(row["evidence_class"], "qualification evidence class"),
            artifact_kind=_text(row["artifact_kind"], "qualification artifact kind"),
            artifact_id=_text(row["artifact_id"], "qualification artifact ID"),
            artifact_sha256=_sha256(
                row["artifact_sha256"], "qualification artifact SHA-256"
            ),
            status=status,
        )


_REQUIRED_EVIDENCE = {
    (
        QualificationSubjectKindV1.SOURCE_PROJECT,
        QualificationAssuranceClassV1.CHECKED_SEMANTIC_REFINEMENT,
    ): frozenset(
        {
            "boundary_coverage",
            "component_semantics",
            "interface_contract",
            "source_call_coverage",
        }
    ),
    (
        QualificationSubjectKindV1.SOURCE_PROJECT,
        QualificationAssuranceClassV1.VALIDATION_BACKED_RECONSTRUCTION,
    ): frozenset(
        {
            "boundary_coverage",
            "candidate_behavior",
            "dependency_envelope",
            "reconstruction_assumptions",
            "source_call_coverage",
        }
    ),
    (
        QualificationSubjectKindV1.LIBRARY_ISLAND,
        QualificationAssuranceClassV1.CHECKED_SEMANTIC_REFINEMENT,
    ): frozenset(
        {
            "abi_contract",
            "boundary_coverage",
            "component_semantics",
            "library_identity",
        }
    ),
    (
        QualificationSubjectKindV1.LINKED_RUNTIME,
        QualificationAssuranceClassV1.PINNED_RUNTIME_SUBSTITUTION,
    ): frozenset(
        {
            "candidate_behavior",
            "dependency_envelope",
            "linked_unit_coverage",
            "reconstruction_assumptions",
            "runtime_lock",
        }
    ),
}


@dataclass(frozen=True)
class LiftQualificationV1:
    subject_kind: QualificationSubjectKindV1
    assurance_class: QualificationAssuranceClassV1
    subject_id: str
    implementation_sha256: str
    unit_ids: tuple[str, ...]
    evidence: tuple[QualificationEvidenceV1, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.subject_kind, QualificationSubjectKindV1):
            raise AuthorityDataError("qualification subject kind must be typed")
        if not isinstance(
            self.assurance_class, QualificationAssuranceClassV1
        ):
            raise AuthorityDataError(
                "qualification assurance class must be typed"
            )
        if (self.subject_kind, self.assurance_class) not in _REQUIRED_EVIDENCE:
            raise AuthorityDataError(
                "qualification assurance class is invalid for its subject"
            )
        _text(self.subject_id, "qualification subject ID", maximum=512)
        _sha256(self.implementation_sha256, "qualified implementation SHA-256")
        if not self.unit_ids or self.unit_ids != tuple(sorted(set(self.unit_ids))):
            raise AuthorityDataError(
                "qualification unit IDs must be nonempty, sorted, and unique"
            )
        for unit_id in self.unit_ids:
            _text(unit_id, "qualification unit ID", maximum=512)
        if self.evidence != tuple(
            sorted(
                set(self.evidence),
                key=lambda row: (
                    row.evidence_class,
                    row.artifact_kind,
                    row.artifact_id,
                    row.artifact_sha256,
                ),
            )
        ):
            raise AuthorityDataError(
                "qualification evidence must be sorted and unique"
            )
        classes = [row.evidence_class for row in self.evidence]
        if len(classes) != len(set(classes)):
            raise AuthorityDataError(
                "qualification evidence repeats an evidence class"
            )

    @property
    def required_evidence_classes(self) -> frozenset[str]:
        return _REQUIRED_EVIDENCE[
            (self.subject_kind, self.assurance_class)
        ]

    @property
    def proves_semantics(self) -> bool:
        return (
            self.assurance_class
            is QualificationAssuranceClassV1.CHECKED_SEMANTIC_REFINEMENT
            and self.status is QualificationStatusV1.COMPLETE
        )

    @cached_property
    def missing_evidence_classes(self) -> tuple[str, ...]:
        observed = {row.evidence_class for row in self.evidence}
        return tuple(sorted(self.required_evidence_classes - observed))

    @cached_property
    def status(self) -> QualificationStatusV1:
        if any(row.status is QualificationStatusV1.VIOLATED for row in self.evidence):
            return QualificationStatusV1.VIOLATED
        if self.missing_evidence_classes or any(
            row.status is not QualificationStatusV1.COMPLETE for row in self.evidence
        ):
            return QualificationStatusV1.INCOMPLETE
        return QualificationStatusV1.COMPLETE

    def _core_payload(self) -> dict[str, Any]:
        return {
            "format": LIFT_QUALIFICATION_V1_FORMAT,
            "schema_version": 1,
            "subject": {
                "kind": self.subject_kind.value,
                "assurance_class": self.assurance_class.value,
                "id": self.subject_id,
                "implementation_sha256": self.implementation_sha256,
                "unit_ids": list(self.unit_ids),
            },
            "status": self.status.value,
            "proves_semantics": self.proves_semantics,
            "required_evidence_classes": sorted(self.required_evidence_classes),
            "missing_evidence_classes": list(self.missing_evidence_classes),
            "evidence": [row.to_payload() for row in self.evidence],
        }

    @cached_property
    def qualification_id(self) -> str:
        return "lift-qualification-v1:" + hashlib.sha256(
            canonical_json_bytes(self._core_payload())
        ).hexdigest()

    def to_payload(self) -> dict[str, Any]:
        return {**self._core_payload(), "qualification_id": self.qualification_id}

    def to_json(self) -> str:
        return canonical_json(self.to_payload())

    @classmethod
    def create(
        cls,
        *,
        subject_kind: QualificationSubjectKindV1,
        assurance_class: QualificationAssuranceClassV1,
        subject_id: str,
        implementation_sha256: str,
        unit_ids: Sequence[str],
        evidence: Sequence[QualificationEvidenceV1],
    ) -> "LiftQualificationV1":
        return cls(
            subject_kind=subject_kind,
            assurance_class=assurance_class,
            subject_id=subject_id,
            implementation_sha256=implementation_sha256,
            unit_ids=tuple(sorted(set(unit_ids))),
            evidence=tuple(
                sorted(
                    set(evidence),
                    key=lambda row: (
                        row.evidence_class,
                        row.artifact_kind,
                        row.artifact_id,
                        row.artifact_sha256,
                    ),
                )
            ),
        )

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "LiftQualificationV1":
        row = _object(
            value,
            {
                "format",
                "schema_version",
                "qualification_id",
                "subject",
                "status",
                "proves_semantics",
                "required_evidence_classes",
                "missing_evidence_classes",
                "evidence",
            },
            "lift qualification",
        )
        if row["format"] != LIFT_QUALIFICATION_V1_FORMAT or row["schema_version"] != 1:
            raise AuthorityDataError("only lift-qualification-v1 is supported")
        subject = _object(
            row["subject"],
            {
                "kind",
                "assurance_class",
                "id",
                "implementation_sha256",
                "unit_ids",
            },
            "qualification subject",
        )
        try:
            subject_kind = QualificationSubjectKindV1(subject["kind"])
        except (TypeError, ValueError) as exc:
            raise AuthorityDataError("qualification has invalid subject kind") from exc
        try:
            assurance_class = QualificationAssuranceClassV1(
                subject["assurance_class"]
            )
        except (TypeError, ValueError) as exc:
            raise AuthorityDataError(
                "qualification has invalid assurance class"
            ) from exc
        result = cls.create(
            subject_kind=subject_kind,
            assurance_class=assurance_class,
            subject_id=_text(subject["id"], "qualification subject ID"),
            implementation_sha256=_sha256(
                subject["implementation_sha256"],
                "qualified implementation SHA-256",
            ),
            unit_ids=tuple(
                _text(item, "qualification unit ID")
                for item in _array(subject["unit_ids"], "qualification unit IDs")
            ),
            evidence=tuple(
                QualificationEvidenceV1.parse(item)
                for item in _array(row["evidence"], "qualification evidence")
            ),
        )
        if result.to_payload() != value:
            raise AuthorityDataError(
                "qualification status, evidence inventory, or ID is stale"
            )
        return result


__all__ = [
    "LIFT_QUALIFICATION_V1_FORMAT",
    "LiftQualificationV1",
    "QualificationAssuranceClassV1",
    "QualificationEvidenceV1",
    "QualificationStatusV1",
    "QualificationSubjectKindV1",
]
