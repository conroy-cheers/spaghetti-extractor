from __future__ import annotations

import unittest
from pathlib import Path


class StageARelationalInterpreterKernelRunResultClosureTests(
    unittest.TestCase
):
    def test_source_keeps_the_producer_frontier_explicit(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelRunResultClosure.lean"
        ).read_text(encoding="utf-8")

        for fragment in (
            "callResultEncodingResidual_iff_responseMachinePayloadHolds",
            "callResultEncodingResidualOfResponseRelated",
            "establishedCallResultEncodingResidual",
            "establishedOperationResultEvidence",
            "RunFunctionNativeLocalSemantics.execute",
            "consumer-side closure",
            "would be circular",
        ):
            self.assertIn(fragment, source)
        for forbidden in (
            "axiom ",
            "native_decide",
            "sorry",
            "unsafe ",
            "GNU",
            "jq",
        ):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("0x", source)

    def test_projection_uses_the_typed_concrete_response_only(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelRunResultClosure.lean"
        ).read_text(encoding="utf-8")

        self.assertIn("ABIResponseFacts", source)
        self.assertIn("related.payload", source)
        self.assertIn("phase.responseRelated", source)
        self.assertNotIn("acceptance", source.lower())
        self.assertNotIn("acceptance_authority", source)
        self.assertNotIn("report :=", source)
        self.assertNotIn("status :=", source)


if __name__ == "__main__":
    unittest.main()
