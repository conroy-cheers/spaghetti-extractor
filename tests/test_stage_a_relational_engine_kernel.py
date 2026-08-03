from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_ANALYSIS_KERNEL_MODULES


class StageARelationalEngineKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_semantic_engine_representation_foundation_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src"
            / "spaghetti_extractor"
            / "lean"
            / "StageA"
        )
        module_source = source_root / "RelationalEngine.lean"
        source = module_source.read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            for module in RELATIONAL_ANALYSIS_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            shutil.copyfile(module_source, stage_a / module_source.name)

            (stage_a / "RelationalEngineKernel.lean").write_text(
                """import StageA.RelationalEngine

namespace StageA.RelationalEngineKernel

open StageA.Formal StageA.Relational.Engine

def eaxField : EngineFieldLayout := { field := .register .eax, offset := 0, alignment := 4 }
def ebxField : EngineFieldLayout := { field := .register .ebx, offset := 4, alignment := 4 }
def ecxField : EngineFieldLayout := { field := .register .ecx, offset := 8, alignment := 4 }
def edxField : EngineFieldLayout := { field := .register .edx, offset := 12, alignment := 4 }
def esiField : EngineFieldLayout := { field := .register .esi, offset := 16, alignment := 4 }
def ediField : EngineFieldLayout := { field := .register .edi, offset := 20, alignment := 4 }
def ebpField : EngineFieldLayout := { field := .register .ebp, offset := 24, alignment := 4 }
def espField : EngineFieldLayout := { field := .register .esp, offset := 28, alignment := 4 }
def flagsField : EngineFieldLayout := { field := .eflags, offset := 32, alignment := 4 }
def carryField : EngineFieldLayout := { field := .flag 0, offset := 36, alignment := 4 }
def fsBaseField : EngineFieldLayout := { field := .fsBase, offset := 40, alignment := 4 }
def x87ControlField : EngineFieldLayout := { field := .x87Control, offset := 44, alignment := 2 }
def x87StatusField : EngineFieldLayout := { field := .x87Status, offset := 46, alignment := 2 }
def x87PendingField : EngineFieldLayout :=
  { field := .x87PendingException, offset := 48, alignment := 1 }
def x87OpcodeField : EngineFieldLayout :=
  { field := .x87LastOpcode, offset := 50, alignment := 2 }
def x87InstructionField : EngineFieldLayout :=
  { field := .x87InstructionPointer, offset := 52, alignment := 4 }
def x87CodeSelectorField : EngineFieldLayout :=
  { field := .x87CodeSelector, offset := 56, alignment := 2 }
def x87DataField : EngineFieldLayout :=
  { field := .x87DataPointer, offset := 60, alignment := 4 }
def x87DataSelectorField : EngineFieldLayout :=
  { field := .x87DataSelector, offset := 64, alignment := 2 }
def originalRvaField : EngineFieldLayout :=
  { field := .originalRva, offset := 68, alignment := 4 }

def x87StackField (index : Nat) : EngineFieldLayout :=
  { field := .x87Stack index, offset := 72 + index * 16, alignment := 2 }
def x87EmptyField (index : Nat) : EngineFieldLayout :=
  { field := .x87Empty index, offset := 82 + index * 16, alignment := 2 }
def x87TagField (index : Nat) : EngineFieldLayout :=
  { field := .x87Tag index, offset := 86 + index * 16, alignment := 1 }

def x87Fields : List EngineFieldLayout :=
  (List.range 8).map x87StackField ++
    (List.range 8).map x87EmptyField ++
    (List.range 8).map x87TagField

def layout : EngineLayout := {
  stateSize := 200
  x87StackSlots := 8
  fields := [eaxField, ebxField, ecxField, edxField, esiField, ediField,
    ebpField, espField, flagsField, carryField, fsBaseField, x87ControlField,
    x87StatusField, x87PendingField, x87OpcodeField, x87InstructionField,
    x87CodeSelectorField, x87DataField, x87DataSelectorField,
    originalRvaField] ++ x87Fields
}

def duplicateLayout : EngineLayout := { layout with fields := eaxField :: layout.fields }
def overlappingLayout : EngineLayout := {
  layout with
  fields := { flagsField with offset := 2 } :: layout.fields.erase flagsField
}
def misalignedLayout : EngineLayout := {
  layout with
  fields := { flagsField with offset := 33 } :: layout.fields.erase flagsField
}
def outOfBoundsLayout : EngineLayout := { layout with stateSize := 198 }

example : layout.checked = true := by decide
example : duplicateLayout.checked = false := by decide
example : overlappingLayout.checked = false := by decide
example : misalignedLayout.checked = false := by decide
example : outOfBoundsLayout.checked = false := by decide
example : layout.Valid := EngineLayout.valid_of_checked layout (by decide)

def engineBase : Word := BitVec.ofNat 32 0x1000
def memoryAddress (address : Word) : Option Word :=
  if address.toNat < 0x1000 then
    some (address + BitVec.ofNat 32 0x200000)
  else none
def codeAddress (address : Word) : Option Word :=
  some (address + BitVec.ofNat 32 0x400000)
def dataAddress (address : Word) : Option Word :=
  some (address + BitVec.ofNat 32 0x200000)
def rep : EngineRep := {
  layout
  engineBase
  memoryAddress
  codeAddress
  dataAddress
  x87Semantics := StageA.X87.defaultSemantics
}
def controlRelated (originalRva candidateControl : Nat) : Prop :=
  candidateControl = originalRva + 1

example (original candidate : MachineState) (originalRva candidateControl : Nat)
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate) :
    readBytes candidate.memory (eaxField.address engineBase) 4 =
      encodeLittleEndian 4 original.registers.eax.toNat := by
  exact related.read_register eaxField (by simp [rep, layout]) .eax rfl

example (original candidate : MachineState) (originalRva candidateControl : Nat)
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate) :
    readBytes candidate.memory (flagsField.address engineBase) 4 =
        encodeLittleEndian 4 original.eflags.toNat ∧
      readBytes candidate.memory (carryField.address engineBase) 4 =
        encodeLittleEndian 4 (original.eflags.extractLsb' 0 1).toNat := by
  constructor
  · exact related.read_flags flagsField (by simp [rep, layout]) rfl
  · exact related.read_flag carryField (by simp [rep, layout]) 0 rfl

example (original candidate : MachineState) (originalRva candidateControl : Nat)
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (value : StageA.X87.Word)
    (occupied : original.x87Physical.logicalSlot 1 =
      .occupied .special value) :
    readBytes candidate.memory ((x87StackField 1).address engineBase) 10 =
        encodeLittleEndian 10 value.toNat ∧
      readBytes candidate.memory ((x87EmptyField 1).address engineBase) 4 =
        encodeLittleEndian 4 0 ∧
      readBytes candidate.memory ((x87TagField 1).address engineBase) 1 =
        encodeLittleEndian 1 2 := by
  constructor
  · exact related.read_x87_stack_occupied (x87StackField 1)
      (by decide) 1 rfl .special value occupied
  constructor
  · simpa [occupied, x87SlotEmpty] using related.read_x87_empty
      (x87EmptyField 1) (by decide) 1 rfl
  · simpa [occupied, x87SlotTag] using related.read_x87_tag
      (x87TagField 1) (by decide) 1 rfl

example (original candidate : MachineState) (originalRva candidateControl : Nat)
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (empty : original.x87Physical.logicalSlot 2 = .empty) :
    readBytes candidate.memory ((x87StackField 2).address engineBase) 10 =
        encodeLittleEndian 10 0 ∧
      readBytes candidate.memory ((x87EmptyField 2).address engineBase) 4 =
        encodeLittleEndian 4 1 ∧
      readBytes candidate.memory ((x87TagField 2).address engineBase) 1 =
        encodeLittleEndian 1 3 := by
  constructor
  · simpa [empty, x87SlotValue] using related.read_x87_stack
      (x87StackField 2) (by decide) 2 rfl
  constructor
  · simpa [empty, x87SlotEmpty] using related.read_x87_empty
      (x87EmptyField 2) (by decide) 2 rfl
  · simpa [empty, x87SlotTag] using related.read_x87_tag
      (x87TagField 2) (by decide) 2 rfl

example (original candidate : MachineState) (originalRva candidateControl : Nat)
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate) :
    readBytes candidate.memory (x87ControlField.address engineBase) 2 =
        encodeLittleEndian 2 original.x87Physical.control.toNat ∧
      readBytes candidate.memory (x87StatusField.address engineBase) 2 =
        encodeLittleEndian 2 original.x87Physical.status.toNat ∧
      readBytes candidate.memory (x87PendingField.address engineBase) 1 =
        encodeLittleEndian 1 (boolValue original.x87Physical.pendingException) ∧
      readBytes candidate.memory (x87OpcodeField.address engineBase) 2 =
        encodeLittleEndian 2 original.x87Physical.lastOpcode.toNat := by
  exact ⟨related.read_x87_control x87ControlField (by simp [rep, layout]) rfl,
    related.read_x87_status x87StatusField (by simp [rep, layout]) rfl,
    related.read_x87_pending_exception x87PendingField
      (by simp [rep, layout]) rfl,
    related.read_x87_last_opcode x87OpcodeField (by simp [rep, layout]) rfl⟩

example (original candidate : MachineState) (originalRva candidateControl : Nat)
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate) :
    (∃ mapped,
        codeAddress original.x87Physical.instructionPointer = some mapped ∧
        readBytes candidate.memory (x87InstructionField.address engineBase) 4 =
          encodeLittleEndian 4 mapped.toNat) ∧
      (∃ mapped,
        dataAddress original.x87Physical.dataPointer = some mapped ∧
        readBytes candidate.memory (x87DataField.address engineBase) 4 =
          encodeLittleEndian 4 mapped.toNat) := by
  constructor
  · simpa [rep] using related.read_x87_instruction_pointer x87InstructionField
      (by simp [rep, layout]) rfl
  · simpa [rep] using related.read_x87_data_pointer x87DataField
      (by simp [rep, layout]) rfl

example (original candidate : MachineState) (originalRva candidateControl : Nat)
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate) :
    readBytes candidate.memory (x87CodeSelectorField.address engineBase) 2 =
        encodeLittleEndian 2 original.x87Physical.codeSelector.toNat ∧
      readBytes candidate.memory (x87DataSelectorField.address engineBase) 2 =
        encodeLittleEndian 2 original.x87Physical.dataSelector.toNat := by
  exact ⟨related.read_x87_code_selector x87CodeSelectorField
      (by simp [rep, layout]) rfl,
    related.read_x87_data_selector x87DataSelectorField
      (by simp [rep, layout]) rfl⟩

example (original candidate : MachineState) (originalRva candidateControl : Nat)
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate) :
    original.x87Semantics = candidate.x87Semantics ∧
      rep.x87Semantics.Complies :=
  ⟨related.shared_x87_semantics, related.x87_semantics_qualified⟩

example (original candidate : MachineState) (originalRva candidateControl : Nat)
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate) :
    readBytes candidate.memory (originalRvaField.address engineBase) 4 =
      encodeLittleEndian 4 originalRva := by
  exact related.read_original_rva originalRvaField (by simp [rep, layout]) rfl

example (original candidate : MachineState) (originalRva candidateControl : Nat)
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate) (address mappedAddress : Word)
    (mapped : memoryAddress address = some mappedAddress) :
    candidate.memory mappedAddress = original.memory address :=
  related.read_mapped_memory address mappedAddress (by simpa [rep] using mapped)

example (original candidate : MachineState) (originalRva candidateControl : Nat)
    (related : StateRelated rep controlRelated
      originalRva candidateControl original candidate)
    (scratchAddress : Word)
    (unobserved : \u00ac CandidateAddressObserved rep scratchAddress) :
    StateRelated rep controlRelated originalRva
      candidateControl original
      { candidate with memory := (StageA.Relational.Memory.write8
          candidate.memory scratchAddress 0xff) } :=
  related.write_candidate_scratch_byte scratchAddress 0xff unobserved

def resultRelation : MacroStepResultRelation Nat :=
  representationResultRelation rep controlRelated

def identitySemantics : MacroStepSemantics Nat := {
  originalStep := Eq
  candidateStep := Eq
}

example : MacroStepSimulation identitySemantics resultRelation := by
  intro originalBefore candidateBefore candidateAfter related candidateStep
  subst candidateAfter
  exact \u27e8originalBefore, rfl, related\u27e9

#print axioms EngineLayout.valid_of_checked
#print axioms StateRelated.read_mapped_field
#print axioms StateRelated.read_register
#print axioms StateRelated.read_x87_stack_occupied
#print axioms StateRelated.read_x87_instruction_pointer
#print axioms StateRelated.shared_x87_semantics
#print axioms StateRelated.read_mapped_memory
#print axioms StateRelated.preserve_candidate_scratch
#print axioms StateRelated.write_candidate_scratch_byte

end StageA.RelationalEngineKernel
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir,
                bundle="RelationalEngineKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
