from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_relational_interpreter_kernel_step_program_lookup_call_closure_kernel import (
    _copy_module_closure,
)


@unittest.skipUnless(shutil.which("lean"), "Lean is required")
class StageARelationalInterpreterKernelProgramLookupNativeWorldBridgeKernelTests(
    unittest.TestCase
):
    def test_exact_native_world_bridge_compiles_without_unapproved_axioms(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            module = "RelationalInterpreterKernelProgramLookupNativeWorldBridge"
            source = (source_root / f"{module}.lean").read_text(encoding="utf-8")
            for forbidden in (
                "sorry",
                "native_decide",
                "generatedLaunchWorld",
                "submittedEndpoint",
            ):
                self.assertNotIn(forbidden, source)
            _copy_module_closure(source_root, stage_a, module)
            result = _run_lean_relational(
                root,
                bundle=module,
                command_timeout_seconds=300,
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])
        for theorem in (
            "runProgramLookupNativeFuel_returned_empty_to_nativeWorld",
            "programLookupNativeLocalSemantics_constructsNativeFuel",
            "programLookupNativeLocalSemantics_programLookupRefinesUsingNativeWorld",
            "KernelOperationFrameParametricCertificate.refinesSubroutine",
        ):
            self.assertIn(theorem, result["stdout"])


if __name__ == "__main__":
    unittest.main()
