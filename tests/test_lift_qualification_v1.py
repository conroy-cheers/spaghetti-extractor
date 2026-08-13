from __future__ import annotations

import unittest
import hashlib

from spaghetti_extractor.authority_bindings_v2 import AuthorityDataError
from spaghetti_extractor.lift_qualification_v1 import (
    LiftQualificationV1,
    QualificationAssuranceClassV1,
    QualificationEvidenceV1,
    QualificationStatusV1,
    QualificationSubjectKindV1,
)


def _evidence(name: str, status: QualificationStatusV1 = QualificationStatusV1.COMPLETE) -> QualificationEvidenceV1:
    return QualificationEvidenceV1(
        evidence_class=name,
        artifact_kind=f"{name}-v1",
        artifact_id=name,
        artifact_sha256=hashlib.sha256(name.encode("ascii")).hexdigest(),
        status=status,
    )


class LiftQualificationV1Tests(unittest.TestCase):
    def test_complete_source_qualification_requires_every_evidence_family(self) -> None:
        qualification = LiftQualificationV1.create(
            subject_kind=QualificationSubjectKindV1.SOURCE_PROJECT,
            assurance_class=(
                QualificationAssuranceClassV1.CHECKED_SEMANTIC_REFINEMENT
            ),
            subject_id="fixture",
            implementation_sha256="a" * 64,
            unit_ids=("unit",),
            evidence=tuple(
                _evidence(name)
                for name in (
                    "boundary_coverage",
                    "component_semantics",
                    "interface_contract",
                    "source_call_coverage",
                )
            ),
        )
        self.assertIs(qualification.status, QualificationStatusV1.COMPLETE)
        self.assertEqual(
            LiftQualificationV1.parse(qualification.to_payload()), qualification
        )

    def test_missing_or_violated_evidence_fails_closed(self) -> None:
        incomplete = LiftQualificationV1.create(
            subject_kind=QualificationSubjectKindV1.SOURCE_PROJECT,
            assurance_class=(
                QualificationAssuranceClassV1.CHECKED_SEMANTIC_REFINEMENT
            ),
            subject_id="fixture",
            implementation_sha256="a" * 64,
            unit_ids=("unit",),
            evidence=(_evidence("boundary_coverage"),),
        )
        self.assertIs(incomplete.status, QualificationStatusV1.INCOMPLETE)
        self.assertIn("component_semantics", incomplete.missing_evidence_classes)

        violated = LiftQualificationV1.create(
            subject_kind=QualificationSubjectKindV1.LIBRARY_ISLAND,
            assurance_class=(
                QualificationAssuranceClassV1.CHECKED_SEMANTIC_REFINEMENT
            ),
            subject_id="library",
            implementation_sha256="b" * 64,
            unit_ids=("unit",),
            evidence=(
                _evidence("abi_contract", QualificationStatusV1.VIOLATED),
            ),
        )
        self.assertIs(violated.status, QualificationStatusV1.VIOLATED)

    def test_stale_status_or_id_is_rejected(self) -> None:
        qualification = LiftQualificationV1.create(
            subject_kind=QualificationSubjectKindV1.SOURCE_PROJECT,
            assurance_class=(
                QualificationAssuranceClassV1.VALIDATION_BACKED_RECONSTRUCTION
            ),
            subject_id="fixture",
            implementation_sha256="a" * 64,
            unit_ids=("unit",),
            evidence=(),
        )
        payload = qualification.to_payload()
        payload["status"] = "complete"
        with self.assertRaisesRegex(AuthorityDataError, "stale"):
            LiftQualificationV1.parse(payload)


if __name__ == "__main__":
    unittest.main()
