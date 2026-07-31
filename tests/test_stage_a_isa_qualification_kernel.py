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

def semanticForm (bytes : Bytes) : Option InstructionSemanticForm := do
  let decoded <- decodeInstructionExact bytes
  pure decoded.instruction.semanticForm

def semanticFormForProfile (profile : X86CPUProfile)
    (bytes : Bytes) : Option InstructionSemanticForm := do
  let decoded <- decodeInstructionExactForProfile profile bytes
  pure decoded.instruction.semanticForm

example : addForm = some (.binary .add .register .register) := by decide
example : addImmediateForm = some (.binary .add .register .immediate) := by decide
example : leaveForm = some .leave := by decide
example : semanticForm [0x9c] = some .pushFlags := by decide
example : semanticForm [0x60] = some .pushAll := by decide
example : semanticForm [0x61] = some .popAll := by decide
example : semanticForm [0x9d] = some .popFlags := by decide
example : semanticForm [0xfc] = some .clearDirection := by decide
example : semanticForm [0x6a, 0x80] =
    some (.pushOperand .immediate) := by decide
example : semanticForm [0x68, 0x78, 0x56, 0x34, 0x12] =
    some (.pushOperand .immediate) := by decide
example : semanticForm [0x64, 0xa1, 0x30, 0, 0, 0] =
    some (.movFs32 {
      hasBase := false
      hasIndex := false
      scaleShift := 0
      hasDisplacement := true
    }) := by decide
example : semanticForm [0xdd, 0x70, 0x20] =
    some (.x87SaveState {
      hasBase := true
      hasIndex := false
      scaleShift := 0
      hasDisplacement := true
    }) := by decide
example : semanticForm [0xdd, 0x60, 0x20] =
    some (.x87RestoreState {
      hasBase := true
      hasIndex := false
      scaleShift := 0
      hasDisplacement := true
    }) := by decide
example : semanticForm [0xf3, 0xab] = some (.storeDwords true) := by decide
example : semanticForm [0x66, 0xd1, 0xe8] =
    some (.shiftWidth .word .right .register (.immediate 1)) := by decide
example : semanticForm [0x66, 0x0b, 0xc1] =
    some (.binaryWidth .word .or .register .register) := by decide
example : semanticFormForProfile .i686 [0xf3, 0x0f, 0xbc, 0xc2] =
    some (.bitScan .forward .register) := by decide
example : semanticFormForProfile .haswell [0xf3, 0x0f, 0xbc, 0xc2] =
    some (.bitScan (.trailingZeroCount .haswell) .register) := by decide
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
