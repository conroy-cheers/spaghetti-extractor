from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_relational_interpreter_kernel_step_program_lookup_call_closure_kernel import (
    _copy_module_closure,
)


_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)


@unittest.skipUnless(shutil.which("lean"), "Lean is required")
class StageARelationalInterpreterKernelStepWorldProgramLookupKernelTests(
    unittest.TestCase
):
    def test_world_indexed_nested_lookup_compiles_without_unapproved_axioms(
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
            module = "RelationalInterpreterKernelStepWorldProgramLookup"
            source = (source_root / f"{module}.lean").read_text(
                encoding="utf-8"
            )
            for forbidden in (
                "sorry",
                "native_decide",
                "generatedLaunchWorld",
                "submittedEndpoint",
                "submittedStatus",
            ):
                self.assertNotIn(forbidden, source)
            for required in (
                "KernelOperationABIFrame",
                "NativeWorldSubroutineDispatches",
                "responseRelated",
                "memoryFrame",
                "InterpreterStepNativeWorldCheckedActionLoopAuthority",
                "InterpreterStepNativeWorldExactActionClosure",
                "refinesCheckedFamily",
            ):
                self.assertIn(required, source)
            _copy_module_closure(source_root, stage_a, module)
            result = _run_lean_relational(
                root,
                bundle=module,
                command_timeout_seconds=300,
            )

        self.assertEqual(result["status"], "checked", result)
        output = str(result["stdout"]) + str(result["stderr"])
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        for match in _AXIOMS.findall(output):
            axioms = {
                item.strip() for item in match.split(",") if item.strip()
            }
            self.assertLessEqual(axioms, _APPROVED_AXIOMS)
        for theorem in (
            "InterpreterStepNativeWorldProgramLookupCallerFrame.lookupResult",
            "InterpreterStepNativeWorldProgramLookupCallerFrame.lookupPhase",
            "InterpreterStepNativeWorldProgramLookupCallAuthority.lookup",
            "InterpreterStepNativeWorldExactActionClosure.toAuthority",
            "InterpreterStepNativeWorldCheckedOperationCertificate.refinesDerivation",
            "InterpreterStepNativeWorldCheckedOperationCertificate.refines",
            "InterpreterStepNativeWorldCheckedOperationCertificate.refinesCheckedFamily",
        ):
            self.assertIn(theorem, output)


if __name__ == "__main__":
    unittest.main()
