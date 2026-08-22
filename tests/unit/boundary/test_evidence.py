from __future__ import annotations

import unittest

from spaghetti_extractor.boundary import (
    BoundaryEvidenceReceiptV1,
    BoundaryFactSetV1,
    BoundaryFactV1,
    BoundaryModelError,
    BoundaryRequirementV1,
)
from tests.unit.boundary._support import subject


class BoundaryEvidenceTests(unittest.TestCase):
    binary = "a" * 64

    def facts(self, producer_class: str, producer_id: str, rows: tuple[BoundaryFactV1, ...]) -> BoundaryFactSetV1:
        return BoundaryFactSetV1.create(
            producer_class=producer_class,
            producer_id=producer_id,
            subject=subject(),
            binary_sha256=self.binary,
            facts=rows,
        )

    def test_complementary_partial_sources_resolve_fieldwise(self) -> None:
        requirements = (
            BoundaryRequirementV1.create(
                key="argument.0.location", legal_values=["stack+4"],
                rule_ids=["ia32.stack"], requires_observation=True,
            ),
            BoundaryRequirementV1.create(
                key="stack.cleanup", legal_values=["caller"],
                rule_ids=["cdecl.cleanup"], requires_observation=False,
            ),
        )
        receipt = BoundaryEvidenceReceiptV1.reconcile(
            subject=subject(),
            binary_sha256=self.binary,
            requirements=requirements,
            fact_sets=(
                self.facts(
                    "machine_observation", "decoded-call",
                    (BoundaryFactV1.create(key="argument.0.location", state="exact", values=["stack+4"]),),
                ),
                self.facts(
                    "dialect_rule", "pe32-cdecl",
                    (BoundaryFactV1.create(key="stack.cleanup", state="exact", values=["caller"]),),
                ),
            ),
        )
        self.assertEqual(receipt.status, "complete")

    def test_proposal_only_does_not_satisfy_observation(self) -> None:
        receipt = BoundaryEvidenceReceiptV1.reconcile(
            subject=subject(), binary_sha256=self.binary,
            requirements=(BoundaryRequirementV1.create(
                key="result.location", legal_values=["eax"],
                rule_ids=["ia32.result"], requires_observation=True,
            ),),
            fact_sets=(self.facts(
                "compiler_proposal", "clang-probe",
                (BoundaryFactV1.create(key="result.location", state="exact", values=["eax"]),),
            ),),
        )
        self.assertEqual(receipt.status, "incomplete")
        self.assertEqual(receipt.obligations[0].code, "authoritative_boundary_evidence_missing")

    def test_disagreement_is_a_violation(self) -> None:
        requirement = BoundaryRequirementV1.create(
            key="stack.cleanup", legal_values=["caller", "callee"],
            rule_ids=["ia32.cleanup"], requires_observation=True,
        )
        receipt = BoundaryEvidenceReceiptV1.reconcile(
            subject=subject(), binary_sha256=self.binary,
            requirements=(requirement,),
            fact_sets=(
                self.facts("machine_observation", "site-a", (BoundaryFactV1.create(key="stack.cleanup", state="exact", values=["caller"]),)),
                self.facts("checked_authority", "site-b", (BoundaryFactV1.create(key="stack.cleanup", state="exact", values=["callee"]),)),
            ),
        )
        self.assertEqual(receipt.status, "violated")

    def test_cross_subject_evidence_is_rejected(self) -> None:
        source = BoundaryFactSetV1.create(
            producer_class="machine_observation", producer_id="other",
            subject={"kind": "function", "id": "other", "image_selector": "main-image"},
            binary_sha256=self.binary,
            facts=(BoundaryFactV1.create(key="stack.cleanup", state="exact", values=["caller"]),),
        )
        with self.assertRaisesRegex(BoundaryModelError, "another subject"):
            BoundaryEvidenceReceiptV1.reconcile(
                subject=subject(), binary_sha256=self.binary,
                requirements=(BoundaryRequirementV1.create(
                    key="stack.cleanup", legal_values=["caller"],
                    rule_ids=["cdecl.cleanup"], requires_observation=True,
                ),), fact_sets=(source,),
            )


if __name__ == "__main__":
    unittest.main()
