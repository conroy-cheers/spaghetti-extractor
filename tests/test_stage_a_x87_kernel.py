from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


class StageAX87KernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for x87 kernel proofs")
    def test_structural_profile_is_checked_by_lean(self):
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
            shutil.copyfile(source_root / "X87.lean", stage_a / "X87.lean")
            shutil.copyfile(
                source_root / "RelationalX87.lean",
                stage_a / "RelationalX87.lean",
            )
            shutil.copyfile(source_root / "Formal.lean", stage_a / "Formal.lean")
            shutil.copyfile(
                source_root / "RelationalX87Decode.lean",
                stage_a / "RelationalX87Decode.lean",
            )
            shutil.copyfile(
                source_root / "RelationalX87StateOnlyDecode.lean",
                stage_a / "RelationalX87StateOnlyDecode.lean",
            )
            (stage_a / "X87KernelCheck.lean").write_text(
                """
import StageA.RelationalX87Decode
import StageA.RelationalX87StateOnlyDecode

namespace StageA.X87KernelCheck

open StageA.X87
open StageA.Relational.X87

def physical : PhysicalState := {
  slots := Vector.replicate 8 .empty
  control := BitVec.ofNat 16 0x037f
  status := BitVec.ofNat 16 0
  pendingException := false
  lastOpcode := BitVec.ofNat 11 0
  instructionPointer := BitVec.ofNat 32 0x401000
  codeSelector := BitVec.ofNat 16 0
  dataPointer := BitVec.ofNat 32 0x402000
  dataSelector := BitVec.ofNat 16 0
}

def definedness : Definedness := {
  slotMasks := Vector.replicate 8 (BitVec.ofNat 80 0)
  statusMask := BitVec.ofNat 16 0
  eflagsMask := BitVec.ofNat 32 0
  storeMask := BitVec.ofNat 80 0
  registerMask := BitVec.ofNat 32 0
}

def faultingWait : Response := {
  nextState := physical
  store := none
  register := none
  eflagsValue := BitVec.ofNat 32 0
  eflagsWriteMask := BitVec.ofNat 32 0
  definedness
  fault := some .floatingPoint
}

def float80Input : StepInput := {
  operandBits := BitVec.ofNat 80 0
  operandBytes := 10
  opcode := BitVec.ofNat 11 0x2ed
  instructionPointer := BitVec.ofNat 32 0x401000
  codeSelector := BitVec.ofNat 16 0x1b
  dataPointer := BitVec.ofNat 32 0x402000
  dataSelector := BitVec.ofNat 16 0x23
}

def relocatedPhysical : PhysicalState := {
  physical with
  instructionPointer := BitVec.ofNat 32 0x402000
  dataPointer := BitVec.ofNat 32 0x404000
}

def relocatedFloat80Input : StepInput := {
  float80Input with
  instructionPointer := BitVec.ofNat 32 0x402000
  dataPointer := BitVec.ofNat 32 0x404000
}

def relocation : AddressRelation := {
  code := fun original candidate =>
    candidate = original + BitVec.ofNat 32 0x1000
  data := fun original candidate =>
    candidate = original + BitVec.ofNat 32 0x2000
}

example : LoadFormat.float80.byteWidth = 10 := by decide
example : StoreFormat.float80.byteWidth = 10 := by decide
example :
    Command.expectedStoreKind .storeControl = some .controlWord := by decide
example :
    Command.eflagsWriteMask (.compareStack .ordered .eflags 1 false) =
      BitVec.ofNat 32 0x8d5 := by decide
example : float80Input.validFor (.loadMemory .float80) := by
  simp [StepInput.validFor, float80Input, Command.expectedOperandBytes,
    LoadFormat.byteWidth]
example : ¬ faultingWait.structurallyValid .wait .noWait := by
  simp [Response.structurallyValid, faultingWait]
example : StateRelated relocation physical relocatedPhysical := by
  simp [StateRelated, MetadataRelated, relocation, physical, relocatedPhysical,
    PhysicalState.core, PhysicalState.metadata]
example : InputRelated relocation float80Input relocatedFloat80Input := by
  simp [InputRelated, relocation, float80Input, relocatedFloat80Input,
    StepInput.operand]
example (semantics : Semantics) :
    ResponseRelated relocation
      (semantics.execute (.loadMemory .float80) .waiting physical float80Input)
      (semantics.execute (.loadMemory .float80) .waiting relocatedPhysical
        relocatedFloat80Input) := by
  apply execute_related
  · simp [StateRelated, MetadataRelated, relocation, physical,
      relocatedPhysical, PhysicalState.core, PhysicalState.metadata]
  · simp [InputRelated, relocation, float80Input, relocatedFloat80Input,
      StepInput.operand]
example :
    (decodeCommandExact [0xd9, 0xe8]).map (fun decoded =>
      (decoded.command, decoded.waitMode, decoded.opcode.toNat, decoded.size)) =
      some (.loadConstant (BitVec.ofNat 80
        (0x3fff * (2 ^ 64) + (2 ^ 63))), .waiting, 0x1e8, 2) := by decide
example :
    (decodeCommandExact [0xd8, 0xd1]).map (fun decoded => decoded.command) =
      some (.compareStack .ordered .status 1 false) := by decide
example :
    (decodeCommandExact [0xda, 0x4d, 0x20]).map (fun decoded => decoded.command) =
      some (.binaryMemory .multiply .int32) := by decide
example :
    (decodeCommandExact [0xda, 0x64, 0x24, 0x04]).map
        (fun decoded => decoded.command) =
      some (.binaryMemory .subtract .int32) := by decide
example :
    (decodeCommandExact [0xdc, 0x1d, 0x58, 0x50, 0x41, 0x00]).map
        (fun decoded => decoded.command) =
      some (.compareMemory .ordered .float64 true) := by decide
example :
    (decodeCommandExact [0xd9, 0xfe]).map (fun decoded => decoded.command) =
      some (.unary .sine) := by decide
example :
    (decodeCommandExact [0xd9, 0xff]).map (fun decoded => decoded.command) =
      some (.unary .cosine) := by decide
example :
    (decodeCommandExact [0xdb, 0xe3]).map (fun decoded =>
      (decoded.command, decoded.waitMode)) = some (.initialize, .noWait) := by decide
example :
    (decodeCommandExact [0x9b]).map (fun decoded =>
      (decoded.command, decoded.waitMode)) = some (.wait, .waiting) := by decide
example :
    StageA.Relational.X87StateOnly.instructionChecked .x87Wait = true := by
  decide
example :
    StageA.Relational.X87StateOnly.instructionChecked
      (.x87CompareStack .ordered .status 1 false) = true := by
  decide
example :
    StageA.Relational.X87StateOnly.instructionChecked
      (.x87CompareStack .ordered .eflags 1 false) = false := by
  decide
example :
    StageA.Relational.X87StateOnly.instructionChecked .x87StoreStatusAx =
      false := by
  decide

end StageA.X87KernelCheck
""",
                encoding="utf-8",
            )

            kernel = _run_lean_relational(lean_dir, bundle="RelationalX87Decode")
            self.assertEqual(kernel["status"], "checked", kernel)
            result = _run_lean_relational(lean_dir, bundle="X87KernelCheck")
            self.assertEqual(result["status"], "checked", result)
            self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
