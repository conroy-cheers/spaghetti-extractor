from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_runtime_value_carry_kernel import _copy_module_closure


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARuntimeIndirectEffectsKernelTests(unittest.TestCase):
    def test_checked_world_range_separates_static_image_word(self) -> None:
        source_root = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "spaghetti_extractor"
            / "lean"
            / "StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary) / "lean"
            stage_a = lean_dir / "StageA"
            stage_a.mkdir(parents=True)
            _copy_module_closure(
                source_root, stage_a, "RelationalRuntimeIndirectEffects"
            )
            (stage_a / "RuntimeIndirectEffectsKernel.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                lean_dir, bundle="RuntimeIndirectEffectsKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)


_KERNEL_FIXTURE = r"""import StageA.RelationalRuntimeIndirectEffects

namespace StageA.Relational.RuntimeIndirectEffectsKernel

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalMixedBridge
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.ReachableStaticPointerSlot
open StageA.Relational.RuntimeIndirectEffects

def pe : PE32 := {
  bytes := ByteTree.ofBytes []
  peOffset := 0
  entrypointRva := 0x1000
  imageBase := 0x400000
  sectionAlignment := 0x1000
  fileAlignment := 0x200
  sizeOfImage := 0x3000
  sizeOfHeaders := 0x200
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := []
}

def externalRange : DynamicAddressRangePair := {
  id := 1
  originalBase := BitVec.ofNat 32 0x700000
  candidateBase := BitVec.ofNat 32 0x800000
  size := 0x100
}

def overlappingRange : DynamicAddressRangePair := {
  id := 2
  originalBase := BitVec.ofNat 32 0x402000
  candidateBase := BitVec.ofNat 32 0x402000
  size := 0x100
}

example : mixedRangeDisjointFromImages pe pe externalRange = true := by
  native_decide

example : mixedRangeDisjointFromImages pe pe overlappingRange = false := by
  native_decide

example :
    Write32AvoidsWord (BitVec.ofNat 32 0x402000)
      (BitVec.ofNat 32 0x700004) := by
  apply write32AvoidsStaticWord_of_mixedRange_original
    (originalPe := pe) (candidatePe := pe) (range := externalRange)
  · native_decide
  · exact wholeSpanContainedChecked_sound _ _ _ _ (by native_decide)
  · native_decide
  · native_decide

example :
    AccessSpanContained externalRange.originalBase.toNat externalRange.size
      (externalRange.originalBase + BitVec.ofNat 32 4).toNat 4 := by
  apply originalRangeOffsetAccessContained
    (originalPe := pe) (candidatePe := pe)
  · native_decide
  · native_decide

example :
    WriteSpanAvoidsWord (BitVec.ofNat 32 0x402000)
      (BitVec.ofNat 32 0x700004) .byte := by
  apply writeSpanAvoidsStaticWord_of_mixedRange_original .byte
    (originalPe := pe) (candidatePe := pe) (range := externalRange)
  · native_decide
  · exact wholeSpanContainedChecked_sound _ _ _ _ (by native_decide)
  · native_decide
  · native_decide

example :
    WriteSpanAvoidsWord (BitVec.ofNat 32 0x402000)
      (BitVec.ofNat 32 0x700006) .word := by
  apply writeSpanAvoidsStaticWord_of_mixedRange_original .word
    (originalPe := pe) (candidatePe := pe) (range := externalRange)
  · native_decide
  · exact wholeSpanContainedChecked_sound _ _ _ _ (by native_decide)
  · native_decide
  · native_decide

example : MachineCallMemoryEffectFootprintBounded .argumentRanges :=
  machineCallMemoryEffectFootprintBoundedChecked_sound rfl

#print axioms write32AvoidsStaticWord_of_mixedRange_original
#print axioms writeSpanAvoidsStaticWord_of_mixedRange_original
#print axioms write32AvoidsReachableStaticSlot_of_worldRange
#print axioms writeSpanAvoidsReachableStaticSlot_of_worldRange
#print axioms originalRangeOffsetAccessContained
#print axioms write32AvoidsReachableStaticSlot_of_worldRangeOffset
#print axioms completeWriteFootprintTransition_preserves

end StageA.Relational.RuntimeIndirectEffectsKernel
"""


if __name__ == "__main__":
    unittest.main()
