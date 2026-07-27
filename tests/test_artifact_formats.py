from __future__ import annotations

import unittest

from spaghetti_extractor.artifact_formats import (
    INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT,
    NORMALIZED_BEHAVIOR_FORMAT,
    RELATIONAL_NIX_BUILD_REPORT_FORMAT,
    RELATIONAL_PHASE_FORMAT,
    SEMANTIC_IR_FORMAT,
    SEMANTIC_TRANSFER_CONTRACT_FORMAT,
    STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT,
)
from spaghetti_extractor.relational.analyses.callsite import (
    NORMALIZED_BEHAVIOR_FORMAT as CALLSITE_NORMALIZED_BEHAVIOR_FORMAT,
)
from spaghetti_extractor.relational.lean.static_machine_import_contracts import (
    STATIC_MACHINE_IMPORT_FORMAT,
)
from spaghetti_extractor.relational.report import (
    STAGE_A_NIX_BUILD_REPORT_FORMAT,
)
from spaghetti_extractor.stage_b_state_machine import (
    STAGE_A_SEMANTIC_IR_MODEL,
    STAGE_A_SEMANTIC_TRANSFER_FORMAT,
)


class ArtifactFormatTests(unittest.TestCase):
    def test_cross_stage_public_aliases_use_canonical_formats(self) -> None:
        self.assertEqual(
            STATIC_MACHINE_IMPORT_FORMAT,
            STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT,
        )
        self.assertEqual(
            STAGE_A_SEMANTIC_IR_MODEL,
            SEMANTIC_IR_FORMAT,
        )
        self.assertEqual(
            STAGE_A_SEMANTIC_TRANSFER_FORMAT,
            SEMANTIC_TRANSFER_CONTRACT_FORMAT,
        )
        self.assertEqual(
            CALLSITE_NORMALIZED_BEHAVIOR_FORMAT,
            NORMALIZED_BEHAVIOR_FORMAT,
        )
        self.assertEqual(
            STAGE_A_NIX_BUILD_REPORT_FORMAT,
            RELATIONAL_NIX_BUILD_REPORT_FORMAT,
        )

    def test_formats_are_generic_and_versioned(self) -> None:
        shared_formats = (
            INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT,
            NORMALIZED_BEHAVIOR_FORMAT,
            RELATIONAL_NIX_BUILD_REPORT_FORMAT,
            RELATIONAL_PHASE_FORMAT,
            SEMANTIC_IR_FORMAT,
            SEMANTIC_TRANSFER_CONTRACT_FORMAT,
            STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT,
        )
        self.assertTrue(all(value.endswith("-v1") for value in shared_formats))
        self.assertNotIn("gnu-hello", RELATIONAL_PHASE_FORMAT)


if __name__ == "__main__":
    unittest.main()
