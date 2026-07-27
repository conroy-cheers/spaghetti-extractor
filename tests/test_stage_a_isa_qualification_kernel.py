from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES


class StageAISAQualificationKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_instruction_forms_are_reconstructed_by_the_formal_decoder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src"
                / "spaghetti_extractor"
                / "lean"
                / "StageA"
            )
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )

            (stage_a / "ISAQualificationKernel.lean").write_text(
                """import StageA.ISAQualification

namespace StageA.ISAQualificationKernelTests

open StageA.Formal

def addForm : Option InstructionSemanticForm := do
  let decoded <- decodeInstructionExact [0x01, 0xd8]
  pure decoded.instruction.semanticForm

def addImmediateForm : Option InstructionSemanticForm := do
  let decoded <- decodeInstructionExact [0x05, 1, 0, 0, 0]
  pure decoded.instruction.semanticForm

def x87OneForm : Option InstructionSemanticForm := do
  let decoded <- decodeInstructionExact [0xd9, 0xe8]
  pure decoded.instruction.semanticForm

def leaveForm : Option InstructionSemanticForm := do
  let decoded <- decodeInstructionExact [0xc9]
  pure decoded.instruction.semanticForm

example : addForm = some (.binary .add .register .register) := by decide
example : addImmediateForm = some (.binary .add .register .immediate) := by decide
example : leaveForm = some .leave := by decide
example : (match x87OneForm with
    | some (.x87LoadConstant _) => true
    | _ => false) = true := by decide

end StageA.ISAQualificationKernelTests
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir,
                bundle="ISAQualificationKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
