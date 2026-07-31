import StageA.RelationalInterpreterKernelData

namespace StageA.Relational.InterpreterKernelProgramIndex

open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernelData

/-!
# Indexed semantic-program lookup

The semantic interpreter uses source-RVA lookup while the compiled interpreter
returns a pointer into its fixed-stride PE table.  This small module is the
canonical bridge between those views.  It intentionally depends only on the
program-record kernel so action proofs do not import the larger ProgramLookup
summary stack.
-/

def sourceRvasStrictlySorted (records : List ProgramRecord) : Prop :=
  records.Pairwise fun left right => left.sourceRva < right.sourceRva

def lookupProgramRecordWithIndexAux :
    List ProgramRecord -> Nat -> Nat -> Option (Nat × ProgramRecord)
  | [], _, _ => none
  | record :: tail, sourceRva, index =>
      if record.sourceRva == sourceRva then some (index, record)
      else lookupProgramRecordWithIndexAux tail sourceRva (index + 1)

def lookupProgramRecordWithIndex? (records : List ProgramRecord)
    (sourceRva : Nat) : Option (Nat × ProgramRecord) :=
  lookupProgramRecordWithIndexAux records sourceRva 0

def lookupProgramRecordIndex? (records : List ProgramRecord)
    (sourceRva : Nat) : Option Nat :=
  (lookupProgramRecordWithIndex? records sourceRva).map Prod.fst

theorem lookupProgramRecordWithIndexAux_recordExact
    (records : List ProgramRecord) (sourceRva index : Nat) :
    (lookupProgramRecordWithIndexAux records sourceRva index).map Prod.snd =
      records.find? (fun record => record.sourceRva == sourceRva) := by
  induction records generalizing index with
  | nil => rfl
  | cons record tail induction =>
      simp only [lookupProgramRecordWithIndexAux, List.find?_cons]
      by_cases same : (record.sourceRva == sourceRva) = true
      · simp [same]
      · simp [same, induction (index := index + 1)]

theorem lookupProgramRecordWithIndex?_recordExact
    (records : List ProgramRecord) (sourceRva : Nat) :
    (lookupProgramRecordWithIndex? records sourceRva).map Prod.snd =
      lookupProgramRecord records sourceRva :=
  lookupProgramRecordWithIndexAux_recordExact records sourceRva 0

theorem lookupProgramRecordWithIndex?_exists_of_lookup
    (lookupExact : lookupProgramRecord records sourceRva = some record) :
    ∃ index,
      lookupProgramRecordWithIndex? records sourceRva = some (index, record) := by
  have recordExact :=
    lookupProgramRecordWithIndex?_recordExact records sourceRva
  rw [lookupExact] at recordExact
  cases indexedExact :
      lookupProgramRecordWithIndex? records sourceRva with
  | none =>
      simp [indexedExact] at recordExact
  | some indexed =>
      rcases indexed with ⟨index, indexedRecord⟩
      simp [indexedExact] at recordExact
      subst indexedRecord
      exact ⟨index, rfl⟩

#print axioms lookupProgramRecordWithIndex?_recordExact
#print axioms lookupProgramRecordWithIndex?_exists_of_lookup

end StageA.Relational.InterpreterKernelProgramIndex
