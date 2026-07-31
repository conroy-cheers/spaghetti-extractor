from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.interpreter_semantic_refinement import (
    RELATIONAL_INTERPRETER_SEMANTIC_REFINEMENT_FORMAT,
    relational_interpreter_semantic_refinement_bundle_sources,
    relational_interpreter_semantic_refinement_inventory,
)
from tests.test_stage_a_relational_interpreter_normalization_generation import (
    _ret_row,
)


class StageARelationalInterpreterSemanticRefinementGenerationTests(unittest.TestCase):
    def test_emits_universal_refinement_theorems_in_matching_shards(self) -> None:
        first = _ret_row()
        second = copy.deepcopy(first)
        second["id"] = "semantic-transfer:ret-two"
        second["original"] = {"rva_start": 0x2000, "rva_end": 0x2001, "size": 1}
        second["instructions"][0]["rva"] = 0x2000  # type: ignore[index]
        sources = relational_interpreter_semantic_refinement_bundle_sources(
            [first, second],
            pe_module="StageA.GeneratedGnuHelloOriginalPE",
            shard_size=1,
        )

        self.assertEqual(
            sorted(sources),
            [
                "GeneratedInterpreterSemanticRefinementBundle",
                "GeneratedInterpreterSemanticRefinementShard0000",
                "GeneratedInterpreterSemanticRefinementShard0001",
            ],
        )
        first_source = sources["GeneratedInterpreterSemanticRefinementShard0000"]
        self.assertIn(
            "import StageA.GeneratedInterpreterNormalizationShard0000Data",
            first_source,
        )
        self.assertIn(
            "theorem exactNormalizedTransferSemanticRefinement0", first_source
        )
        self.assertIn(
            "theorem exactNormalizedTransferFusedMachineRefinement0", first_source
        )
        self.assertIn("intro state environment", first_source)
        self.assertIn("exactRvaBytes originalPe 4096 1", first_source)
        self.assertIn(
            "executableSpanInstructionWindow originalPe 4096 4097", first_source
        )
        self.assertIn("ExactSemanticTransferFusedMachineRefinement", first_source)
        self.assertIn("normalizeSymbolicBehavior_fields", first_source)
        self.assertIn("semanticTransferRefinesOfExactExecution", first_source)
        self.assertIn(
            "exactNormalizedTransferFusedMachineRefinementTheorems",
            sources["GeneratedInterpreterSemanticRefinementBundle"],
        )
        self.assertNotIn("pass-must-be-ignored", first_source)
        self.assertNotIn("\n+      ", "".join(sources.values()))
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertNotIn(marker, "".join(sources.values()))

        inventory = relational_interpreter_semantic_refinement_inventory(
            sources, transfer_count=2
        )
        self.assertEqual(
            inventory["format"], RELATIONAL_INTERPRETER_SEMANTIC_REFINEMENT_FORMAT
        )
        self.assertEqual(inventory["status"], "lean_check_required")
        self.assertFalse(inventory["proof_authority"])
        self.assertEqual(inventory["theorem_count"], 2)
        self.assertEqual(inventory["fused_theorem_count"], 2)
        self.assertEqual(inventory["shard_count"], 2)

    def test_rejects_invalid_sharding_and_unsupported_rows(self) -> None:
        with self.assertRaisesRegex(StageAInputError, "shard_size"):
            relational_interpreter_semantic_refinement_bundle_sources(
                [_ret_row()],
                pe_module="StageA.GeneratedGnuHelloOriginalPE",
                shard_size=0,
            )
        malformed = _ret_row()
        malformed["outcome"] = {"kind": "return"}
        with self.assertRaisesRegex(StageAInputError, "ordinary normalization transfer"):
            relational_interpreter_semantic_refinement_bundle_sources(
                [malformed], pe_module="StageA.GeneratedGnuHelloOriginalPE"
            )

    def test_inventory_rejects_missing_theorem(self) -> None:
        sources = relational_interpreter_semantic_refinement_bundle_sources(
            [_ret_row()], pe_module="StageA.GeneratedGnuHelloOriginalPE"
        )
        sources["GeneratedInterpreterSemanticRefinementShard0000"] = sources[
            "GeneratedInterpreterSemanticRefinementShard0000"
        ].replace("theorem exactNormalizedTransferSemanticRefinement0", "theorem missing")
        with self.assertRaisesRegex(StageAInputError, "changed cardinality"):
            relational_interpreter_semantic_refinement_inventory(
                sources, transfer_count=1
            )

        sources = relational_interpreter_semantic_refinement_bundle_sources(
            [_ret_row()], pe_module="StageA.GeneratedGnuHelloOriginalPE"
        )
        sources["GeneratedInterpreterSemanticRefinementShard0000"] = sources[
            "GeneratedInterpreterSemanticRefinementShard0000"
        ].replace(
            "theorem exactNormalizedTransferFusedMachineRefinement0",
            "theorem missingFused",
        )
        with self.assertRaisesRegex(
            StageAInputError, "fused semantic refinement.*cardinality"
        ):
            relational_interpreter_semantic_refinement_inventory(
                sources, transfer_count=1
            )


if __name__ == "__main__":
    unittest.main()
