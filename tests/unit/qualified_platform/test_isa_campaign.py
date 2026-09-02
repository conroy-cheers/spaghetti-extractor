from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.isa.catalog_enrichment import (
    validate_side_isa_catalog_proposal,
)
from spaghetti_extractor.isa.semantic_forms import (
    lean_semantic_form_classifier_sha256,
    lean_semantic_form_id,
)
from spaghetti_extractor.qualified_platform.isa_campaign import (
    QUALIFIED_PLATFORM_ISA_CATALOG_ADAPTER_V1,
    build_qualified_platform_isa_catalog_proposal_v1,
)
from spaghetti_extractor.qualified_platform.isa_form_inventory import (
    write_qualified_platform_isa_form_inventory_v1,
)


class QualifiedPlatformISACampaignTests(unittest.TestCase):
    def test_proposal_is_intrinsic_and_accepted_by_one_enrichment_path(self) -> None:
        semantic_form = "SpaghettiExtractor.ISA.Formal.InstructionSemanticForm.nop"
        classifier = lean_semantic_form_classifier_sha256()
        with tempfile.TemporaryDirectory() as temporary:
            inventory = Path(temporary) / "inventory.json"
            write_qualified_platform_isa_form_inventory_v1(
                forms=[{
                    "form_id": lean_semantic_form_id(
                        semantic_form, classifier_sha256=classifier
                    ),
                    "semantic_form": semantic_form,
                    "representative_instruction_hex": "90",
                }],
                out=inventory,
            )
            proposal = build_qualified_platform_isa_catalog_proposal_v1(
                inventory_path=inventory
            )

        parsed = validate_side_isa_catalog_proposal(proposal)
        self.assertEqual(parsed["forms"], proposal["forms"])
        self.assertEqual(
            parsed["encodings"][0]["encoding_id"],
            proposal["encodings"][0]["encoding_id"],
        )
        self.assertEqual(
            proposal["source"]["adapter"],
            QUALIFIED_PLATFORM_ISA_CATALOG_ADAPTER_V1,
        )
        self.assertNotIn("side_isa_artifacts", proposal["source"])
        self.assertEqual(proposal["counts"]["forms"], 1)
        self.assertEqual(proposal["counts"]["occurrences"], 1)
        self.assertTrue(
            proposal["encodings"][0]["source_occurrence_ids"][0].startswith(
                "qualified-platform-isa-form:"
            )
        )


if __name__ == "__main__":
    unittest.main()
