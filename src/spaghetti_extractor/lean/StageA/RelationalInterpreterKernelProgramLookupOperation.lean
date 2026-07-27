import StageA.RelationalInterpreterKernelLookupABI

namespace StageA.Relational.InterpreterKernelProgramLookupOperation

open StageA.Formal
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelSummary
open StageA.Relational.SymbolicSoundness

/-! Small checked adapters used when closing a concrete `programLookup`
operation.  The generated module still supplies the exact PE and records; these
definitions only turn finite Boolean checks into the propositions consumed by
`KernelFunctionSummaryCore`. -/

def exactDecodeInventoryChecked (pe : StageA.Formal.PE32) :
    List KernelInstruction -> Bool
  | [] => true
  | instruction :: tail =>
      (instruction.decode? pe).isSome && exactDecodeInventoryChecked pe tail

theorem exactDecodeInventoryChecked_sound
    (pe : StageA.Formal.PE32) (instructions : List KernelInstruction)
    (checked : exactDecodeInventoryChecked pe instructions = true) :
    ExactDecodeInventory pe instructions := by
  intro instruction member
  induction instructions with
  | nil => simp at member
  | cons head tail induction =>
      simp only [exactDecodeInventoryChecked, Bool.and_eq_true] at checked
      rcases List.mem_cons.mp member with rfl | inTail
      · cases decoded : KernelInstruction.decode? pe instruction with
        | none => simp [decoded] at checked
        | some value => exact ⟨value, rfl⟩
      · exact induction checked.2 inTail

/-- Adjacent comparisons are enough for natural-number keys and reduce in
linear time.  Deciding `List.Pairwise` directly repeats comparisons against
every suffix and is quadratic for large generated program tables. -/
def sourceRvasAdjacentSortedChecked : List ProgramRecord -> Bool
  | [] | [_] => true
  | left :: right :: tail =>
      decide (left.sourceRva < right.sourceRva) &&
        sourceRvasAdjacentSortedChecked (right :: tail)

theorem sourceRvasAdjacentSortedChecked_sound
    (records : List ProgramRecord)
    (checked : sourceRvasAdjacentSortedChecked records = true) :
    sourceRvasStrictlySorted records := by
  induction records with
  | nil => simp [sourceRvasStrictlySorted]
  | cons head tail induction =>
      cases tail with
      | nil => simp [sourceRvasStrictlySorted]
      | cons next rest =>
          simp only [sourceRvasAdjacentSortedChecked, Bool.and_eq_true,
            decide_eq_true_eq] at checked
          have tailSorted := induction checked.2
          simp only [sourceRvasStrictlySorted, List.pairwise_cons] at tailSorted ⊢
          constructor
          · intro value member
            rcases List.mem_cons.mp member with rfl | inRest
            · exact checked.1
            · exact Nat.lt_trans checked.1 (tailSorted.1 value inRest)
          · exact tailSorted

theorem option_eq_some_get {alpha : Type} (value : Option alpha)
    (present : value.isSome = true) : value = some (value.get present) := by
  cases value <;> simp_all

#print axioms exactDecodeInventoryChecked_sound
#print axioms sourceRvasAdjacentSortedChecked_sound
#print axioms option_eq_some_get

end StageA.Relational.InterpreterKernelProgramLookupOperation
