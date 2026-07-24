from __future__ import annotations

import unittest
from pathlib import Path


class StageARelationalInterpreterKernelInvokeResultClosureTests(
    unittest.TestCase
):
    def test_source_closes_all_exact_invoke_arm_consumers(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelInvokeResultClosure.lean"
        ).read_text(encoding="utf-8")

        for fragment in (
            "callResultEncodingResidualOfInvokeResponseRelated",
            "InvokeCallNativeInternalCompletion",
            "InvokeCallNativeExternalHelperArmExecution",
            "InvokeCallNativeIndirectCompletion",
            "internalCompletionCallResultEncodingResidual",
            "internalCompletionOperationResultEvidence",
            "externalHelperExecutionCallResultEncodingResidual",
            "externalHelperExecutionOperationResultEvidence",
            "indirectCompletionCallResultEncodingResidual",
            "indirectCompletionOperationResultEvidence",
            "consumer-side closure",
            "would be circular",
            "strengthen the",
            "Invoke arm assemblers",
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

    def test_projection_uses_only_typed_concrete_arm_evidence(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelInvokeResultClosure.lean"
        ).read_text(encoding="utf-8")

        self.assertIn("ABIResponseFacts", source)
        self.assertIn("related.payload", source)
        self.assertIn("completion.responseRelated", source)
        self.assertIn("refinement.complete", source)
        self.assertNotIn("acceptance", source.lower())
        self.assertNotIn("acceptance_authority", source)
        self.assertNotIn("report :=", source)
        self.assertNotIn("status :=", source)
        self.assertNotIn("(state :", source.split(
            "def internalCompletionCallResultEncodingResidual",
            maxsplit=1,
        )[1])


if __name__ == "__main__":
    unittest.main()
