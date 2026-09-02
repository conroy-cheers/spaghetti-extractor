from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.qualified_platform.isa_form_inventory import (
    default_qualified_platform_isa_form_inventory_path,
    load_qualified_platform_isa_form_inventory_v1,
)
from spaghetti_extractor.qualified_platform.isa_surface_review import (
    QualifiedPlatformISASurfaceReviewError,
    isa_surface_review_payload_v1,
)


class QualifiedPlatformISASurfaceReviewTests(unittest.TestCase):
    def test_full_classifier_is_accounted_by_a_finite_exact_allowlist(self) -> None:
        inventory = load_qualified_platform_isa_form_inventory_v1(
            default_qualified_platform_isa_form_inventory_path()
        )
        review = isa_surface_review_payload_v1(inventory)
        self.assertEqual(review["status"], "complete")
        self.assertEqual(
            review["role"], "reviewed_finite_supported_allowlist"
        )
        self.assertEqual(
            review["counts"],
            {
                "constructors": 95,
                "constructors_with_listed_forms": 85,
                "unsupported_constructors": 10,
                "listed_forms": 450,
            },
        )
        self.assertEqual(
            review["selection_policy"]["unlisted_form"],
            "reject_as_unsupported",
        )
        self.assertFalse(
            review["selection_policy"]["target_occurrence_claims"]
        )

    def test_unknown_constructor_fails_closed(self) -> None:
        inventory = load_qualified_platform_isa_form_inventory_v1(
            default_qualified_platform_isa_form_inventory_path()
        )
        changed = copy.deepcopy(inventory)
        changed["forms"][0]["semantic_form"] = (
            "SpaghettiExtractor.ISA.Formal.InstructionSemanticForm.invented"
        )
        with self.assertRaisesRegex(
            QualifiedPlatformISASurfaceReviewError, "unknown constructor"
        ):
            isa_surface_review_payload_v1(changed)


if __name__ == "__main__":
    unittest.main()
