from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_kernel_step_program_lookup_exact_computation import (
    InterpreterKernelStepProgramLookupExactComputationPlan,
    relational_interpreter_kernel_step_program_lookup_exact_computation_source,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)


def _copy_module_closure(source_root: Path, destination: Path, module: str) -> None:
    pending = [module]
    copied: set[str] = set()
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        source = source_root / f"{current}.lean"
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(text))


@unittest.skipUnless(shutil.which("lean"), "Lean is required")
class StageARelationalInterpreterKernelStepProgramLookupExactComputationKernelTests(
    unittest.TestCase
):
    def _assert_checked(self, result: dict[str, object]) -> str:
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
        return output

    def test_exact_computation_layer_compiles_without_unapproved_axioms(
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
            module = (
                "RelationalInterpreterKernelStepProgramLookupExactComputation"
            )
            _copy_module_closure(source_root, stage_a, module)
            result = _run_lean_relational(root, bundle=module)

        output = self._assert_checked(result)
        for theorem in (
            "ExactNativeWorldReplay.segmentAfter",
            "ExactInterpreterStepHelperReplay.endpointExact",
            "ExactInterpreterStepHelperReplay.toSubroutine",
            "ExactInterpreterStepProgramLookupCallReplay.chunkAfter",
            "ExactInterpreterStepProgramLookupReturnReplay.toReturn",
            "ExecutorClosedInterpreterStepProgramLookupCallerFrame.toClosed",
        ):
            self.assertIn(theorem, output)

    def test_generated_binding_module_compiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterKernelStepProgramLookupExactComputation",
            )
            (stage_a / "FakeClosure.lean").write_text(
                "namespace StageA.FakeClosure\nend StageA.FakeClosure\n",
                encoding="ascii",
            )
            plan = InterpreterKernelStepProgramLookupExactComputationPlan(
                candidate_path=Path("candidate.exe"),
                candidate_sha256="0" * 64,
                candidate_size=1,
                closure_plan_path=Path("closure.json"),
                closure_plan_sha256="1" * 64,
                call_site_rva=0x2300,
                call_block_rva=0x22F0,
                target_rva=0x1800,
                continuation_rva=0x2305,
            )
            (stage_a / "GeneratedExactTest.lean").write_text(
                relational_interpreter_kernel_step_program_lookup_exact_computation_source(
                    plan,
                    generated_closure_module="StageA.FakeClosure",
                ),
                encoding="ascii",
            )
            result = _run_lean_relational(
                root,
                bundle="GeneratedExactTest",
            )

        output = self._assert_checked(result)
        self.assertIn("generatedExactComputationBindings", output)


if __name__ == "__main__":
    unittest.main()
