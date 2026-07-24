from __future__ import annotations

import unittest
from pathlib import Path


class StageARelationalInterpreterKernelRunProducerResultClosureTests(
    unittest.TestCase
):
    def test_run_core_retains_exact_result_indexed_terminal_evidence(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelRun.lean"
        ).read_text(encoding="utf-8")

        for fragment in (
            "RunFunctionNativeResultIndexedLocalSemantics",
            "RunFunctionNativeResultIndexedLoopResult",
            "unavailableEncoding",
            "terminalEncoding",
            "resultEncoding result terminalState",
            "RunFunctionNativeResultIndexedLocalSemantics.execute",
            "encoding := tailResult.encoding",
        ):
            self.assertIn(fragment, source)

    def test_producer_closure_precedes_environment_certificate(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelRunProducerResultClosure.lean"
        ).read_text(encoding="utf-8")

        for fragment in (
            "runFunctionCDeclSuffixPreservesResult",
            "ExactRunFunctionCDeclSuffixResultPreservation",
            "symbolic.returnedStateExact",
            "behavior.registers.eax == .inputReg .eax",
            "behavior.writes.isEmpty",
            "CallResultEncodingResidual.preserveThroughExactCDeclSuffix",
            "RunFunctionNativeResultIndexedLoopResult.operationResultEvidence",
        ):
            self.assertIn(fragment, source)
        self.assertNotIn("EnvironmentClosedCDeclEpilogueCertificate.", source)

    def test_producer_source_has_no_unchecked_authority(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelRunProducerResultClosure.lean"
        ).read_text(encoding="utf-8")

        for forbidden in (
            "axiom ",
            "native_decide",
            "sorry",
            "unsafe ",
            "GNU",
            "jq",
            "report :=",
            "status :=",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
