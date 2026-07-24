from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


class StageARelationalInterpreterX87KernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_exact_x87_schedule_and_composition_are_kernel_checked(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        source = (source_root / "RelationalInterpreterX87.lean").read_text(
            encoding="utf-8"
        )
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in source_root.glob("*.lean"):
                shutil.copyfile(module, stage_a / module.name)
            (stage_a / "RelationalInterpreterX87Kernel.lean").write_text(
                _FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterX87Kernel"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


_FIXTURE = r"""import StageA.RelationalInterpreterX87

namespace StageA.RelationalInterpreterX87Kernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterKernelData

def emptyDigest : String :=
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def instructionDigest : String :=
  "852df74fff31b328b40e1bb1b4ad5d8baba06f81bef9371e7f0ddb597d97e8b4"

def pe : PE32 := {
  bytes := ByteTree.ofBytes [0xd9, 0xe8]
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 2
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{
    virtualSize := 2
    virtualAddress := 0
    rawSize := 2
    rawPointer := 0
    characteristics := 0x60000020
  }]
}

def record : RawInstructionRecord := {
  index := 0
  kind := 1
  span := { start := 0, size := 2 }
  bytes := [0xd9, 0xe8]
  bytesSha256 := instructionDigest
  canonicalBytes := []
  recordSha256 := emptyDigest
  transferBytesSha256 := instructionDigest
}

def replayAction : RawReplayAction := {
  opcode := 25
  replayIndex := 0
  span := record.span
  instructionBytes := record.bytes
  instructionBytesSha256 := instructionDigest
  transferBytesSha256 := instructionDigest
  contractSha256 := emptyDigest
}

def schedule : RawInstructionSchedule := {
  sourceRva := 0
  transferBytes := [0xd9, 0xe8]
  transferBytesSha256 := instructionDigest
  contractCanonicalBytes := []
  contractSha256 := emptyDigest
  scheduleCanonicalBytes := []
  scheduleSha256 := emptyDigest
  records := [record]
  replayActions := [replayAction]
}

example : schedule.basicChecked = true := by native_decide
example : schedule.exactPEChecked pe = true := by native_decide
example : schedule.semanticClassesChecked pe = true := by native_decide

def checked : CheckedInstructionSchedule schedule pe := {
  orderAndReplay := by decide
  exactPEBytes := by decide
  semanticClasses := by decide
}

def exactCertificate : ExactInterpreterX87ScheduleCertificate pe schedule := {
  scheduleChecked := checked
  ordinaryExecutable := by native_decide
  replayOpcode25 := by native_decide
}

def exactReplayActionWitness : ExactInterpreterX87ReplayActionWitness pe := {
  schedule
  certificate := exactCertificate
  record
  action := replayAction
  recordMember := by decide
  actionMember := by decide
  recordClass := by decide
  actionFound := by decide
}

example (state : MachineState) :
    executeX87Singleton pe record state =
      executeReplayOpcode25 pe schedule record state :=
  exactReplayActionWitness.stepRefines state

def candidateReplay : RawX87Replay := {
  imageBase := pe.imageBase
  rvaStart := replayAction.span.start
  rvaEnd := replayAction.span.stop
  instructionCount := 1
  instructionBytes := replayAction.instructionBytes
  instructionBytesSha256 := replayAction.instructionBytesSha256
  transferInstructionBytesSha256 := replayAction.transferBytesSha256
  contractSha256 := replayAction.contractSha256
  checkedDecoder := checkedX87DecoderName
  checkedExecutor := checkedX87ExecutorName
}

example : candidateReplayDescriptorForAction pe replayAction = candidateReplay := by
  rfl

example (state : MachineState) :
    reviewedExpectedCandidateReplay pe candidateReplay state =
      expectedCandidateReplay pe schedule candidateReplay state := by
  rfl

def candidateEntry : CompiledProgramRecord := {
  record := {
    sourceRva := schedule.sourceRva
    wordNodes := []
    x87Nodes := []
    calls := []
    actions := [{ op := 25, arity := 1, aux := 0, args := [0] }]
  }
  x87Replays := [candidateReplay]
}

example : CandidateReplayRecordChecked pe schedule candidateEntry = true := by
  native_decide

def malformedCandidateEntry : CompiledProgramRecord := {
  candidateEntry with
  x87Replays := [{ candidateReplay with instructionBytes := [0xd9, 0xee] }]
}

example : CandidateReplayRecordChecked pe schedule malformedCandidateEntry = false := by
  native_decide

def candidateHandler : CandidateReplayHandler :=
  fun replay state => expectedCandidateReplay pe schedule replay state

def candidateBinding :
    ExactCandidateX87ReplayBinding pe schedule candidateEntry candidateHandler := {
  originalSchedule := exactCertificate
  candidateMetadata := by native_decide
  handlerRefines := by intros; rfl
}

example (state : MachineState) :
    runExactAuthoritative pe schedule state =
      runExactInterpreter pe schedule state :=
  exactCertificate.macroStepRefines state

def ordinary : OrdinaryStep := fun _ _ => none
def replay : ReplayStep := fun _ state => executeX87Singleton pe record state

def certificate : InterpreterX87ScheduleCertificate pe schedule ordinary ordinary replay := {
  scheduleChecked := checked
  ordinaryRefines := by
    intro candidate member ordinaryClass state
    simp [schedule] at member
    subst candidate
    simp [RawInstructionRecord.decodeClass, record] at ordinaryClass
    rfl
  replayPresent := by
    intro candidate member x87Class
    simp [schedule] at member
    subst candidate
    exact ⟨replayAction, by native_decide⟩
  replayRefines := by
    intro candidate member x87Class action actionFound state
    simp [schedule] at member
    subst candidate
    rfl
}

example (state : MachineState) :
    runAuthoritative pe ordinary schedule state =
      runInterpreter ordinary replay schedule state :=
  certificate.macroStepRefines state

example (state : MachineState) (result : StepResult)
    (executed : executeX87Singleton pe record state = some result) :
    PhysicalX87FieldsEstablished result :=
  (executeX87Singleton_witness pe record state result executed).physicalFields

example (state : MachineState) (result : StepResult)
    (executed : executeX87Singleton pe record state = some result) :
    ∃ (descriptor : StageA.Relational.X87.DecodedCommand)
      (behavior : RelationalBehavior) (effect : StageA.X87.MachineEffect),
      result.memoryEffects =
        x87ReadEffects descriptor state ++ x87WriteEffects effect ∧
      result.faults = behavior.x87Fault.toList.map .x87 ∧
      result.control = .fallthrough record.span.stop ∧
      result.calls = [] := by
  let witness := executeX87Singleton_witness pe record state result executed
  exact ⟨witness.descriptor, witness.behavior, witness.effect,
    witness.orderedMemoryEffects, witness.exactFault,
    witness.exactControl, witness.noCalls⟩

#print axioms executeX87Singleton_witness
#print axioms InterpreterX87ScheduleCertificate.stepRefines
#print axioms InterpreterX87ScheduleCertificate.macroStepRefines
#print axioms ExactInterpreterX87ScheduleCertificate.stepRefines
#print axioms ExactInterpreterX87ScheduleCertificate.macroStepRefines
#print axioms ExactInterpreterX87ReplayActionWitness.stepRefines
#print axioms ExactCandidateX87ReplayBinding.replayRefines

end StageA.RelationalInterpreterX87Kernel
"""


if __name__ == "__main__":
    unittest.main()
