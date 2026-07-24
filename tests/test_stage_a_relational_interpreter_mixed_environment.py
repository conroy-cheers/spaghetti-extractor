from __future__ import annotations

import re
import unittest
from pathlib import Path


class StageARelationalInterpreterMixedEnvironmentTests(unittest.TestCase):
    def test_exact_external_bridge_is_fail_closed_and_path_derived(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterMixedEnvironment.lean"
        ).read_text(encoding="utf-8")

        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        self.assertNotIn("status", source.lower())
        self.assertIn("contract.externalBoundariesRelated", source)
        self.assertIn("ExactOneToOneMixedExternalEnvironmentsRefine", source)
        self.assertIn("MixedExternalFrameBoundaryRelated", source)
        self.assertIn("originalFirst.trans originalSecond", source)
        self.assertIn("exactNativeWorldStepIsNonempty", source)
        self.assertIn("candidate_blocked_is_unrelated", source)
        self.assertIn("MixedExternalCallbackFrontier", source)
        self.assertIn("causesRelated : originalCause = candidateCause", source)

    def test_action_relation_has_only_exact_return_and_termination_cases(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterMixedEnvironment.lean"
        ).read_text(encoding="utf-8")
        relation = source.split(
            "def MixedExternalEnvironmentActionsRelated", maxsplit=1
        )[1].split("/-- A profile-level exact 1:1", maxsplit=1)[0]

        self.assertIn(".returned originalResult, .returned candidateResult", relation)
        self.assertIn(".terminated originalWorld, .terminated candidateWorld", relation)
        self.assertIn("| _, _ => False", relation)
        self.assertNotIn(".blocked", relation)
        self.assertNotIn(".callback", relation)


if __name__ == "__main__":
    unittest.main()
