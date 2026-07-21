from tests.stage_a_relational_support import *


class StageAAffineLinkedMemoryTests(StageARelationalTestBase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for linked memory proofs")
    def test_paired_stack_spill_preserves_disjoint_dormant_tail(self):
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
            shutil.copyfile(
                source_root / "RelationalAffineLinkedMemory.lean",
                stage_a / "RelationalAffineLinkedMemory.lean",
            )
            (stage_a / "AffineLinkedMemoryFixture.lean").write_text(
                """import StageA.RelationalAffineLinkedMemory

namespace StageA.AffineLinkedMemoryFixture

open StageA.Formal StageA.Relational

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def originalSpillBehavior : NormalizedSymbolicBehavior := {
  registers := initialSymbolic.registers
  x87 := initialSymbolic.x87
  writes := [((Expr.inputReg .esp).offset 8, .inputReg .eax)]
  flags := initialSymbolic.flags
  outcome := .jump 0
}

def candidateSpillBehavior : NormalizedSymbolicBehavior := {
  registers := initialSymbolic.registers
  x87 := initialSymbolic.x87
  writes := [((Expr.inputReg .esp).offset 12, .inputReg .ebx)]
  flags := initialSymbolic.flags
  outcome := .jump 0
}

def spillWrites : PairedDecodedWritesClaim := {
  writes := [{
    originalAddress := (Expr.inputReg .esp).offset 8
    originalValue := .inputReg .eax
    candidateAddress := (Expr.inputReg .esp).offset 12
    candidateValue := .inputReg .ebx
  }]
}

def wrongSpillValue : PairedDecodedWritesClaim := {
  spillWrites with writes := [{
    originalAddress := (Expr.inputReg .esp).offset 8
    originalValue := .inputReg .ecx
    candidateAddress := (Expr.inputReg .esp).offset 12
    candidateValue := .inputReg .ebx
  }]
}

def wrongSpillAddress : PairedDecodedWritesClaim := {
  spillWrites with writes := [{
    originalAddress := (Expr.inputReg .esp).offset 4
    originalValue := .inputReg .eax
    candidateAddress := (Expr.inputReg .esp).offset 12
    candidateValue := .inputReg .ebx
  }]
}

example : spillWrites.checked originalSpillBehavior candidateSpillBehavior = true := by
  native_decide

example : wrongSpillValue.checked originalSpillBehavior candidateSpillBehavior = false := by
  native_decide

example : wrongSpillAddress.checked originalSpillBehavior candidateSpillBehavior = false := by
  native_decide

example (original candidate : MachineState) :
    spillWrites.ConcreteWritesExact originalSpillBehavior candidateSpillBehavior
      original candidate := by
  exact spillWrites.concreteWritesExact_of_checked originalSpillBehavior
    candidateSpillBehavior original candidate (by native_decide)

def activeFrame : RelationalRuntimeCallFrame := {
  continuationTargetId := 0
  originalReturnAddress := BitVec.ofNat 32 17
  candidateReturnAddress := BitVec.ofNat 32 29
  originalStackAddress := BitVec.ofNat 32 4096
  candidateStackAddress := BitVec.ofNat 32 8192
  protectedBytes := 32
}

def dormantFrame : RelationalRuntimeCallFrame := {
  continuationTargetId := 1
  originalReturnAddress := BitVec.ofNat 32 37
  candidateReturnAddress := BitVec.ofNat 32 41
  originalStackAddress := BitVec.ofNat 32 4352
  candidateStackAddress := BitVec.ofNat 32 8448
  protectedBytes := 32
}

def activeInventory : ReturnSlotOffsetInventory := {
  locations := [ReturnSlotOffsetPair.zero]
  exactWords := [{ originalOffset := 16, candidateOffset := 20 }]
}

def dormantInventory : ReturnSlotOffsetInventory := {
  locations := [ReturnSlotOffsetPair.zero]
  exactWords := [{ originalOffset := 8, candidateOffset := 8 }]
}

def dormantLink : RelationalRuntimeCallFrameLink := {
  callSourceTargetId := 0
  suspendedInventory := dormantInventory
  originalGap := 256
  candidateGap := 256
}

def originalSpill : List (Word × Word) :=
  [(BitVec.ofNat 32 4104, BitVec.ofNat 32 101)]

def candidateSpill : List (Word × Word) :=
  [(BitVec.ofNat 32 8204, BitVec.ofNat 32 203)]

example : relationalLinkedStackWritesAvoidChecked activeFrame [dormantFrame]
    activeInventory [dormantLink] originalSpill candidateSpill = true := by
  native_decide

def originalDormantClobber : List (Word × Word) :=
  [(BitVec.ofNat 32 4352, BitVec.ofNat 32 101)]

example : relationalLinkedStackWritesAvoidChecked activeFrame [dormantFrame]
    activeInventory [dormantLink] originalDormantClobber candidateSpill = false := by
  native_decide

theorem stackSpillPreservesDormantFrame
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (holds : RelationalLinkedRuntimeCallStackHolds context beforeOriginal
      beforeCandidate [activeFrame, dormantFrame] [0, 1]
      (some activeInventory) [dormantLink])
    (targetHolds : activeInventory.holds activeFrame afterOriginal.registers
      afterCandidate.registers)
    (originalMemory : afterOriginal.memory =
      applyConcreteWrites beforeOriginal.memory originalSpill)
    (candidateMemory : afterCandidate.memory =
      applyConcreteWrites beforeCandidate.memory candidateSpill) :
    RelationalLinkedRuntimeCallStackHolds context afterOriginal afterCandidate
      [activeFrame, dormantFrame] [0, 1]
      (some activeInventory) [dormantLink] := by
  exact RelationalLinkedRuntimeCallStackHolds.afterPairedWrites context
    beforeOriginal beforeCandidate afterOriginal afterCandidate activeFrame
    [dormantFrame] 0 [1] [dormantLink] activeInventory activeInventory
    originalSpill candidateSpill holds (by native_decide) targetHolds rfl
    (by native_decide) originalMemory candidateMemory

end StageA.AffineLinkedMemoryFixture
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir, bundle="AffineLinkedMemoryFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
