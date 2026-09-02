from __future__ import annotations

import unittest

from spaghetti_extractor.isa.semantic_forms import (
    lean_semantic_form_classifier_sha256,
    lean_semantic_form_id,
)
from spaghetti_extractor.qualified_platform.migration_parity import (
    reduce_qualified_platform_migration_decisions_v1,
)


class QualifiedPlatformMigrationParityTests(unittest.TestCase):
    def _row(self, name: str, status: str, encoded: str) -> dict[str, object]:
        semantic_form = (
            "SpaghettiExtractor.ISA.Formal.InstructionSemanticForm." + name
        )
        return {
            "form_id": lean_semantic_form_id(
                semantic_form,
                classifier_sha256=lean_semantic_form_classifier_sha256(),
            ),
            "semantic_form": semantic_form,
            "status": status,
            "qualification_sha256": encoded[0] * 64,
            "instruction_hexes": [encoded],
        }

    def test_reducer_unions_forms_and_keeps_corpus_hashes_noncanonical(self) -> None:
        nop_a = self._row("nop", "qualified", "90")
        nop_b = {**nop_a, "qualification_sha256": "f" * 64}
        ret = self._row("ret", "disputed", "c3")
        forms, blockers = reduce_qualified_platform_migration_decisions_v1({
            "alpha": [nop_a, ret],
            "beta": [nop_b],
        })
        self.assertEqual(blockers, [])
        self.assertEqual(len(forms), 2)
        nop = next(row for row in forms if row["semantic_form"].endswith(".nop"))
        self.assertEqual(nop["status"], "qualified")
        self.assertEqual(nop["campaign_ids"], ["alpha", "beta"])
        self.assertEqual(len(nop["qualification_variants"]), 2)
        self.assertNotIn("qualification_sha256", nop)

    def test_reducer_vetoes_a_target_local_status_disagreement(self) -> None:
        qualified = self._row("nop", "qualified", "90")
        disputed = {
            **qualified,
            "status": "disputed",
            "qualification_sha256": "f" * 64,
        }
        forms, blockers = reduce_qualified_platform_migration_decisions_v1({
            "alpha": [qualified],
            "beta": [disputed],
        })
        self.assertEqual(forms[0]["status"], "disputed")
        self.assertEqual(
            [row["kind"] for row in blockers],
            ["qualification_status_conflict"],
        )


if __name__ == "__main__":
    unittest.main()
