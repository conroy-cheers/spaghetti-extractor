import StageA.RelationalInterpreterNormalization
import StageA.RelationalSymbolicSoundness

namespace StageA.Relational.InterpreterSemanticRefinement

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterTransfer
open StageA.Relational.InterpreterNormalization

/-!
This module is the stable proof boundary used by generated ordinary-transfer
refinement shards.  Generated sources supply exact PE-byte and import-table
facts plus a reduced equality between the typed semantic transfer and the
reviewed exact instruction runner.  No extractor status is represented here.
-/

/-- Reduce the public refinement goal to exact sequential execution after the
PE path and import table have both been checked by Lean. -/
theorem semanticTransferRefinesOfExactExecution
    (pe : PE32) (imports : List PEImport)
    (path : ExactNormalizedTransferPath) (transfer : SemanticTransfer)
    (pathChecked : path.exactDecodeChecked pe = true)
    (importsParsed : parseImports pe = some imports)
    (execution : forall state environment,
      transfer.execute environment (machineFromFormal state) =
        runExactDecodedInstructions pe imports path environment 0
          path.instructions state []) :
    SemanticTransferRefinesExactPath pe path transfer := by
  intro state environment
  rw [runExactNormalizedPath_of_checked pe path imports pathChecked
    importsParsed]
  exact execution state environment

/-- Replacing one defined architectural flag with the value already present in
that bit leaves the full EFLAGS word unchanged. -/
theorem updateObservedFlag (word : Word) (index : Nat)
    (inRange : index < 32) :
    updateFlag word index (some (word.extractLsb' index 1 == 1#1)) = word := by
  apply BitVec.eq_of_getElem_eq
  intro query queryInRange
  have maskEq :
      (BitVec.ofNat 32 (2 ^ index))[query] = decide (query = index) := by
    simp [BitVec.getElem_twoPow queryInRange, inRange]
  by_cases observed : word.extractLsb' index 1 == 1#1
  · have observedTrue : word.extractLsb' index 1 == 1#1 := observed
    unfold updateFlag
    rw [maskEq]
    simp only [observedTrue, if_true, BitVec.getElem_or queryInRange]
    by_cases same : query = index
    · subst query
      simp [BitVec.getElem_eq_extractLsb' word index inRange, observedTrue]
    · simp [same]
  · have observedFalse : (word.extractLsb' index 1 == 1#1) = false := by
      cases value : word.extractLsb' index 1 == 1#1 <;> simp_all
    unfold updateFlag
    rw [maskEq]
    simp only [observedFalse, if_false, BitVec.getElem_and queryInRange,
      BitVec.getElem_not queryInRange]
    by_cases same : query = index
    · subst query
      simp [BitVec.getElem_eq_extractLsb' word index inRange, observedFalse]
    · simp [BitVec.getElem_twoPow queryInRange, same]

/-- The initial symbolic flag record observes exactly the architecturally
defined input bits and therefore reconstructs the original EFLAGS word. -/
@[simp] theorem reconstructedInputFlags (word : Word) :
    updateFlag
      (updateFlag
        (updateFlag
          (updateFlag
            (updateFlag (updateFlag word 0
              (some (word.extractLsb' 0 1 == 1#1))) 2
              (some (word.extractLsb' 2 1 == 1#1))) 4 none) 6
            (some (word.extractLsb' 6 1 == 1#1))) 7
          (some (word.extractLsb' 7 1 == 1#1))) 11
        (some (word.extractLsb' 11 1 == 1#1)) = word := by
  rw [updateObservedFlag word 0 (by omega)]
  rw [updateObservedFlag word 2 (by omega)]
  change updateFlag
    (updateFlag (updateFlag word 6
      (some (word.extractLsb' 6 1 == 1#1))) 7
      (some (word.extractLsb' 7 1 == 1#1))) 11
      (some (word.extractLsb' 11 1 == 1#1)) = word
  rw [updateObservedFlag word 6 (by omega)]
  rw [updateObservedFlag word 7 (by omega)]
  rw [updateObservedFlag word 11 (by omega)]

end StageA.Relational.InterpreterSemanticRefinement
