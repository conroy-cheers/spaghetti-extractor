from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


def _copy_module_closure(
    source_root: Path, destination: Path, module: str
) -> None:
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


class StageARelationalAccessFaultQualificationKernelTests(
    unittest.TestCase
):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_typed_access_fault_qualification_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src"
            / "spaghetti_extractor"
            / "lean"
            / "StageA"
        )
        source = (
            source_root / "RelationalAccessFaultQualification.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalAccessFaultQualification",
            )
            (stage_a / "RelationalAccessFaultQualificationKernel.lean").write_text(
                _POSITIVE_FIXTURE,
                encoding="utf-8",
            )
            accepted = _run_lean_relational(
                root,
                bundle="RelationalAccessFaultQualificationKernel",
            )

            (
                stage_a
                / "RelationalAccessFaultQualificationTrueOnlyRejected.lean"
            ).write_text(
                _TRUE_ONLY_REJECTION_FIXTURE,
                encoding="utf-8",
            )
            rejected = _run_lean_relational(
                root,
                bundle="RelationalAccessFaultQualificationTrueOnlyRejected",
            )

        self.assertEqual(accepted["status"], "checked", accepted)
        self.assertNotIn("sorryAx", accepted["stdout"])
        self.assertEqual(rejected["status"], "failed", rejected)
        rejection_output = str(rejected["stdout"]) + str(rejected["stderr"])
        self.assertIn("TypedAccessFaultQualification", rejection_output)
        self.assertIn("True", rejection_output)


_POSITIVE_FIXTURE = r"""import StageA.RelationalAccessFaultQualification

namespace StageA.RelationalAccessFaultQualificationKernel

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterTransfer
open StageA.Relational.InterpreterX87
open StageA.Relational.AccessFaultQualification

def pe : PE32 := {
  bytes := ByteTree.ofBytes [0x90]
  peOffset := 0
  entrypointRva := 0x1000
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 0x1001
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{
    virtualSize := 1
    virtualAddress := 0x1000
    rawSize := 1
    rawPointer := 0
    characteristics := 0x60000020
  }]
}

def context : StaticProofContext := {
  originalPe := pe
  candidatePe := pe
  originalImportCertificate := { descriptors := [] }
  candidateImportCertificate := { descriptors := [] }
  originalRelocations := []
  candidateRelocations := []
  codeMap := {
    entries := .leaf []
    originalAddresses := .leaf []
    candidateAddresses := .leaf []
  }
  dataMap := {
    entries := #[]
    originalOrder := []
    candidateOrder := []
  }
  roots := []
  observations := {}
}

def region : RegionRelation := {
  id := 7
  original := { start := 0x1000, size := 1 }
  candidate := { start := 0x1000, size := 1 }
  root := true
  inputs := []
  outputs := []
  targets := []
}

def occurrence : InstructionFormOccurrence := {
  offset := 0x1000
  size := 1
  bytes := [0x90]
  form := .nop
}

def transfer : SemanticTransfer := {
  sourceRva := 0x1000
  wordNodes := []
  calls := []
  body := []
  outcome := .fallthrough 0x1001
}

def record : ProgramRecord := {
  sourceRva := 0x1000
  wordNodes := []
  x87Nodes := []
  calls := []
  actions := [{ op := 19, arity := 1, aux := 0, args := [0x1001] }]
}

def formCertificate : AccessFaultFormCertificate := {
  occurrence := occurrence
  footprint := []
  permittedFaults := [.notFault]
}

def regionCertificate : AccessFaultRegionCertificate := {
  regionId := 7
  forms := [formCertificate]
}

example : transfer.checked = true := by decide
example : record.decode = some transfer := by decide
example :
    formCertificate.checked .original context region record transfer = true := by
  decide
example :
    regionCertificate.checked .original context region [record] [transfer] =
      true := by
  decide

def callTransfer : SemanticTransfer := {
  transfer with body := [.call 0]
}

def copyTransfer : SemanticTransfer := {
  transfer with body := [.repMovsd 0 0 0 0]
}

def malformedLoadTransfer : SemanticTransfer := {
  transfer with
  wordNodes := [{ op := .load, aux := 3, immediate := 0, args := [] }]
  body := [.evalWord 0]
}

example : accessFaultShapeChecked callTransfer = true := by decide
example : accessFaultShapeChecked copyTransfer = true := by decide
example :
    permittedFaultClasses callTransfer =
      [.notFault, .divideError, .memoryFault, .externalFault,
        .unimplemented] := by
  decide
example : accessFaultShapeChecked malformedLoadTransfer = false := by decide

def Admissible
    (_environment : StageA.Relational.Interpreter.Environment)
    (_state : InterpreterMachine) : Prop :=
  True

def qualification :
    TypedAccessFaultQualification Admissible formCertificate .original context
      RelationalWorld.empty region record transfer := {
  decodedChecked := by decide
  transitionsChecked := by
    intro environment state result admissible executed
    simp [transfer, SemanticTransfer.execute, SemanticTransfer.executeBody,
      SemanticOutcome.complete, halted] at executed
    subst result
    rfl
}

example :
    DecodedAccessFaultFormSemantics formCertificate .original context region
      record transfer :=
  qualification.decodedSemantics

example (environment : StageA.Relational.Interpreter.Environment)
    (state : InterpreterMachine) (result : MacroResult)
    (executed : transfer.execute environment state = some result) :
    TransitionAccessFaultSemantics formCertificate .original context
      RelationalWorld.empty result :=
  qualification.transitionSemantics environment state result True.intro executed

def x87Pe : PE32 := {
  pe with
  bytes := ByteTree.ofBytes [0xd9, 0xe8]
  sizeOfImage := 0x1002
  sections := [{
    virtualSize := 2
    virtualAddress := 0x1000
    rawSize := 2
    rawPointer := 0
    characteristics := 0x60000020
  }]
}

def x87Context : StaticProofContext := {
  context with
  originalPe := x87Pe
  candidatePe := x87Pe
}

def x87Region : RegionRelation := {
  region with
  original := { start := 0x1000, size := 2 }
  candidate := { start := 0x1000, size := 2 }
}

def x87Certificate : X87AccessFaultFormCertificate := {
  occurrence := {
    offset := 0x1000
    size := 2
    bytes := [0xd9, 0xe8]
    form := .x87LoadConstant 302222231531620438900736
  }
}

example : x87Certificate.checked .original x87Context x87Region = true := by
  decide

def X87Admissible (world : RelationalWorld) (state : MachineState) : Prop :=
  ∀ result,
    executeX87Singleton x87Context.originalPe x87Certificate.record state =
      some result ->
    x87TransitionAccessFaultChecked x87Certificate .original x87Context world
      result = true

def x87Qualification (world : RelationalWorld) :
    TypedX87AccessFaultQualification (X87Admissible world) x87Certificate
      .original x87Context world x87Region := {
  decodedChecked := by decide
  transitionsChecked := by
    intro state result admissible executed
    exact admissible result executed
}

example :
    DecodedX87AccessFaultFormSemantics x87Certificate .original x87Context
      x87Region :=
  (x87Qualification RelationalWorld.empty).decodedSemantics

example (state : MachineState) (result : StepResult)
    (admissible : X87Admissible RelationalWorld.empty state)
    (executed :
      executeX87Singleton x87Context.originalPe x87Certificate.record state =
        some result) :
    X87TransitionAccessFaultSemantics x87Certificate .original x87Context
      RelationalWorld.empty state result :=
  (x87Qualification RelationalWorld.empty).transitionSemantics state result
    admissible executed

#print axioms AccessFaultFormCertificate.checked_sound
#print axioms accessFaultFormBindingsChecked_sound
#print axioms AccessFaultRegionCertificate.checked_sound
#print axioms faultCompletion_eq_faultClassIsFault
#print axioms transitionAccessFaultChecked_sound
#print axioms TypedAccessFaultQualification.decodedSemantics
#print axioms TypedAccessFaultQualification.transitionSemantics
#print axioms X87AccessFaultFormCertificate.checked_sound
#print axioms x87MemoryEffectsAccessDomainChecked_sound
#print axioms x87TransitionAccessFaultChecked_sound
#print axioms TypedX87AccessFaultQualification.decodedSemantics
#print axioms TypedX87AccessFaultQualification.transitionSemantics

end StageA.RelationalAccessFaultQualificationKernel
"""


_TRUE_ONLY_REJECTION_FIXTURE = (
    r"""import StageA.RelationalAccessFaultQualification

namespace StageA.RelationalAccessFaultQualificationTrueOnlyRejected

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.AccessFaultQualification

variable
  (StateAdmissible :
    StageA.Relational.Interpreter.Environment -> InterpreterMachine -> Prop)
  (certificate : AccessFaultFormCertificate)
  (side : RelationalSide)
  (context : StaticProofContext)
  (world : RelationalWorld)
  (region : RegionRelation)
  (record : ProgramRecord)
  (transfer : SemanticTransfer)

theorem trueOnly : True := True.intro

def rejected :
    TypedAccessFaultQualification StateAdmissible certificate side context
      world region record transfer :=
  trueOnly

end StageA.RelationalAccessFaultQualificationTrueOnlyRejected
"""
)


if __name__ == "__main__":
    unittest.main()
