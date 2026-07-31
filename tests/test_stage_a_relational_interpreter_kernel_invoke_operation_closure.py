from __future__ import annotations

import unittest
from pathlib import Path


class StageARelationalInterpreterKernelInvokeOperationClosureTests(
    unittest.TestCase
):
    def test_closure_derives_broad_authorities_from_exact_producers(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelInvokeOperationClosure.lean"
        ).read_text(encoding="utf-8")

        for declaration in (
            "structure InvokeCallNativeExternalResultClosure",
            "theorem InvokeCallNativeExternalResultClosure.endpointExact",
            "def InvokeCallNativeExternalArmClosure.environmentRefinement",
            "def InvokeCallNativeExternalArmClosure.branchAuthority",
            "structure InvokeCallNativeInternalExactAssembly",
            "def InvokeCallNativeInternalExactAssembly.completion",
            "def InvokeCallNativeCheckedInternalArmClosure.branchAuthority",
            "structure InvokeCallNativeIndirectExactAssembly",
            "def InvokeCallNativeIndirectExactAssembly.completion",
            "def InvokeCallNativeCheckedIndirectArmClosure.branchAuthority",
            "structure InvokeCallNativeCheckedArmClosures",
        ):
            self.assertIn(declaration, source)

        for exact_dependency in (
            "EnvironmentClosedCDeclEpilogueCertificate",
            "exactSegmentTopLevelCdeclReturnedState",
            "epilogueStartExact",
            "epilogueFuelExact",
            "RunFunctionNativeCheckedOperationCertificate",
            "CheckedRunFunctionDerivation",
        ):
            self.assertIn(exact_dependency, source)

        for forbidden in (
            "axiom ",
            "native_decide",
            "sorry",
            "unsafe ",
            "status :=",
            "acceptance_authority",
            "GNU",
            "jq",
        ):
            self.assertNotIn(forbidden, source)

    def test_completion_does_not_bootstrap_from_response_relation(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelInvokeOperationClosure.lean"
        ).read_text(encoding="utf-8")

        for name in (
            "InvokeCallNativeInternalExactAssembly.completion",
            "InvokeCallNativeIndirectExactAssembly.completion",
        ):
            body = source.split(f"def {name}", 1)[1].split("\n}\n", 1)[0]
            self.assertIn("certificate.responseRelated", body)
            self.assertIn("certificate.memoryFrame", body)
            self.assertNotIn("completion.responseRelated", body)
            self.assertNotIn("related.payload", body)


if __name__ == "__main__":
    unittest.main()
