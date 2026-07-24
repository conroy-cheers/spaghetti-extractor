from __future__ import annotations

import re
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_x87_execution import (
    interpreter_kernel_x87_execution_lean_snippet,
)


class StageAInterpreterKernelX87ExecutionTests(unittest.TestCase):
    def test_generic_kernel_theorem_has_exact_endpoint_boundary(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (
            root
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelX87Execution.lean"
        ).read_text(encoding="utf-8")

        for required in (
            "ExactNativeX87ReplayKernelProgramBinding",
            "ExactNativeX87ReplayKernelEndpointCertificate",
            "ExactNativeX87ReplayKernelEndpointAuthority",
            "callRun",
            "entryRun",
            "instructionRun",
            "captureRun",
            "returnRun",
            "callTarget",
            "handlerResult",
            "frameEffect",
            "toKernelReduction",
            "kernelExecution",
        ):
            self.assertIn(required, source)

        self.assertEqual(source.count("runRelatedSteps program.transitionSystem"), 5)
        self.assertNotIn("NonemptyRelatedPath", source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_generated_interface_inhabits_kernel_goal_once(self) -> None:
        snippet = interpreter_kernel_x87_execution_lean_snippet()

        self.assertEqual(
            snippet.count(
                "def GeneratedX87ReplayBridgeKernelEndpointAuthorityGoal"
            ),
            1,
        )
        self.assertEqual(
            snippet.count("theorem generatedX87ReplayBridgeKernelExecution"),
            1,
        )
        self.assertIn("exact authority.kernelExecution", snippet)
        self.assertNotIn("RuntimeGoal", snippet)
        self.assertNotIn('"status"', snippet)


if __name__ == "__main__":
    unittest.main()
