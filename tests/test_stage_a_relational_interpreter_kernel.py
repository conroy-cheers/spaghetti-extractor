from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


class StageARelationalInterpreterKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_structural_soundness_and_macro_step_are_kernel_checked(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        source = (source_root / "RelationalInterpreter.lean").read_text(
            encoding="utf-8"
        )
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in ("X87", "Formal", "RelationalInterpreter"):
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            (stage_a / "RelationalInterpreterKernel.lean").write_text(
                """import StageA.RelationalInterpreter

namespace StageA.RelationalInterpreterKernel

open StageA.Formal StageA.Relational.Interpreter

def zeroMachine : InterpreterMachine := {
  registers := fun _ => BitVec.ofNat 32 0
  flags := fun _ => BitVec.ofNat 32 0
  memory := fun _ => BitVec.ofNat 8 0
  eflags := BitVec.ofNat 32 0
}

def deterministicEnvironment : StageA.Relational.Interpreter.Environment := {
  undefinedValue := fun slot => BitVec.ofNat 32 slot
  invokeCall := fun _ state => { status := .ok, state := state }
}

def failingEnvironment : StageA.Relational.Interpreter.Environment := {
  undefinedValue := fun slot => BitVec.ofNat 32 slot
  invokeCall := fun _ state => {
    status := .externalFault
    state := state.setRegister .eax (BitVec.ofNat 32 99)
  }
}

def arithmeticRecord : ProgramRecord := {
  sourceRva := 4096
  wordNodes := [
    { op := 0, arity := 0, aux := 0, immediate := 7, args := [] }
  ]
  x87Nodes := []
  calls := []
  actions := [
    { op := 0, arity := 1, aux := 0, args := [0] },
    { op := 6, arity := 1, aux := 0, args := [0] },
    { op := 18, arity := 0, aux := 0, args := [] },
    { op := 22, arity := 1, aux := 0, args := [0] }
  ]
}

example : arithmeticRecord.checked = true := by decide

example : arithmeticRecord.StructurallyValid :=
  arithmeticRecord.structurallyValid_of_checked (by decide)

example :
    (arithmeticRecord.interpret deterministicEnvironment zeroMachine).map
      (fun result => result.completion) =
        some (.returned (BitVec.ofNat 32 7)) := by
  native_decide

def memoryRecord : ProgramRecord := {
  sourceRva := 6144
  wordNodes := [
    { op := 0, arity := 0, aux := 0, immediate := 256, args := [] },
    { op := 0, arity := 0, aux := 0, immediate := 42, args := [] },
    { op := 9, arity := 1, aux := 4, immediate := 0, args := [0] }
  ]
  x87Nodes := []
  calls := []
  actions := [
    { op := 0, arity := 1, aux := 0, args := [0] },
    { op := 0, arity := 1, aux := 0, args := [1] },
    { op := 2, arity := 2, aux := 4, args := [0, 1] },
    { op := 0, arity := 1, aux := 0, args := [2] },
    { op := 22, arity := 1, aux := 0, args := [2] }
  ]
}

example : memoryRecord.checked = true := by decide

example :
    (memoryRecord.interpret deterministicEnvironment zeroMachine).map
      (fun result => (result.events.length, result.completion)) =
        some (2, .returned (BitVec.ofNat 32 42)) := by
  native_decide

def externalRecord : ProgramRecord := {
  sourceRva := 8192
  wordNodes := [
    { op := 0, arity := 0, aux := 0, immediate := 256, args := [] },
    { op := 0, arity := 0, aux := 0, immediate := 512, args := [] },
    { op := 0, arity := 0, aux := 0, immediate := 1, args := [] },
    { op := 4, arity := 0, aux := 0, immediate := 0, args := [] }
  ]
  x87Nodes := []
  calls := [{
    kind := 0
    instructionRva := 8192
    callIndex := 1
    targetNode := none
    targetRva := 0
    returnRva := 8197
    dll := some "example.dll"
    symbol := some "Operation"
    ordinal := none
    registerNodes := [0, 0, 0, 0, 0, 0, 0, 0]
    flagNodes := [3, 3, 3, 3, 3, 3]
    argumentNodes := [2]
    stackInputs := [
      { offset := 0, width := 4, valueNode := 2 }
    ]
  }]
  actions := [
    { op := 0, arity := 1, aux := 0, args := [0] },
    { op := 0, arity := 1, aux := 0, args := [1] },
    { op := 0, arity := 1, aux := 0, args := [2] },
    { op := 0, arity := 1, aux := 0, args := [3] },
    { op := 5, arity := 4, aux := 0, args := [0, 1, 2, 3] },
    { op := 4, arity := 1, aux := 0, args := [0] },
    { op := 7, arity := 1, aux := 1, args := [2] },
    { op := 18, arity := 0, aux := 0, args := [] },
    { op := 24, arity := 0, aux := 0, args := [] }
  ]
}

example : externalRecord.checked = true := by decide

example :
    (externalRecord.interpret deterministicEnvironment zeroMachine).map
      (fun result => (result.events.length, result.completion)) =
        some (2, .externalJump) := by
  native_decide

example :
    (externalRecord.interpret failingEnvironment zeroMachine).map
      (fun result =>
        (result.state.registers .eax, result.events.length, result.completion)) =
      some (BitVec.ofNat 32 99, 2, .externalFault) := by
  native_decide

def x87Record : ProgramRecord := {
  arithmeticRecord with
  x87Nodes := [
    { op := 0, arity := 0, aux := 0, immediate := 0, args := [] }
  ]
}

def unknownOpcodeRecord : ProgramRecord := {
  arithmeticRecord with
  wordNodes := [
    { op := 71, arity := 0, aux := 0, immediate := 0, args := [] }
  ]
}

def unevaluatedReferenceRecord : ProgramRecord := {
  arithmeticRecord with
  actions := [
    { op := 6, arity := 1, aux := 0, args := [0] },
    { op := 22, arity := 1, aux := 0, args := [0] }
  ]
}

example : x87Record.checked = false := by decide
example : unknownOpcodeRecord.checked = false := by decide
example : unevaluatedReferenceRecord.checked = false := by decide

example (record : ProgramRecord) (checked : record.checked = true)
    (environment : StageA.Relational.Interpreter.Environment)
    (state : InterpreterMachine) :
    exists transfer,
      record.decode = some transfer ∧
      transfer.checked = true ∧
      record.interpret environment state = transfer.execute environment state :=
  record.checked_macroStep_semantic_correspondence checked environment state

#print axioms ProgramRecord.structurallyValid_of_checked
#print axioms ProgramRecord.macroStep_semantic_correspondence
#print axioms ProgramRecord.macroStep_exported_correspondence
#print axioms ProgramRecord.checked_macroStep_semantic_correspondence

end StageA.RelationalInterpreterKernel
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
