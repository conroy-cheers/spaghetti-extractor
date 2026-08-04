import StageA.RelationalInterpreterMixedLaunchOperationRankedRoute

namespace StageA.Relational.InterpreterMixedLaunchLexicographicInvariant

open StageA.Relational.InterpreterMixedLaunchOperationRankedRoute

/-!
# Checked lexicographic launch-loop ranks

Validation wrappers commonly combine an outer finite table walk with an inner
search.  This module turns the pair

`(recordCount - recordIndex, lookupRank)`

into the natural rank consumed by `ExactNativeSilentRankedRoute`.  Generated
artifacts may propose the two counters and one of the two transition kinds,
but the Boolean checker enforces all bounds and the generic theorem proves the
strict decrease.
-/

structure LexicographicLoopRankSpec where
  recordCount : Nat
  lookupRankBound : Nat
deriving Repr, DecidableEq

structure LexicographicLoopRankState where
  recordIndex : Nat
  lookupRank : Nat
deriving Repr, DecidableEq

def LexicographicLoopRankSpec.stateChecked
    (spec : LexicographicLoopRankSpec)
    (state : LexicographicLoopRankState) : Bool :=
  state.recordIndex <= spec.recordCount &&
    state.lookupRank <= spec.lookupRankBound

def LexicographicLoopRankSpec.rank
    (spec : LexicographicLoopRankSpec)
    (state : LexicographicLoopRankState) : Nat :=
  (spec.recordCount - state.recordIndex) *
      (spec.lookupRankBound + 1) +
    state.lookupRank

inductive LexicographicLoopStep where
  | inner
  | outer
deriving Repr, DecidableEq

/-- A checked inner step retains the record index and decreases the search
rank.  A checked outer step advances exactly one record and may reset the
search rank to any value within its declared bound. -/
def LexicographicLoopRankSpec.stepChecked
    (spec : LexicographicLoopRankSpec)
    (kind : LexicographicLoopStep)
    (before after : LexicographicLoopRankState) : Bool :=
  spec.stateChecked before &&
    spec.stateChecked after &&
    match kind with
    | .inner =>
        after.recordIndex == before.recordIndex &&
          after.lookupRank < before.lookupRank
    | .outer =>
        before.recordIndex < spec.recordCount &&
          after.recordIndex == before.recordIndex + 1

theorem LexicographicLoopRankSpec.stateChecked_sound
    (spec : LexicographicLoopRankSpec)
    (state : LexicographicLoopRankState)
    (checked : spec.stateChecked state = true) :
    state.recordIndex <= spec.recordCount /\
      state.lookupRank <= spec.lookupRankBound := by
  simpa [LexicographicLoopRankSpec.stateChecked, Bool.and_eq_true] using
    checked

theorem LexicographicLoopRankSpec.stepChecked_rank_decreases
    (spec : LexicographicLoopRankSpec)
    (kind : LexicographicLoopStep)
    (before after : LexicographicLoopRankState)
    (checked : spec.stepChecked kind before after = true) :
    spec.rank after < spec.rank before := by
  cases kind with
  | inner =>
      simp only [LexicographicLoopRankSpec.stepChecked, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at checked
      rcases checked with
        ⟨⟨beforeChecked, afterChecked⟩, recordIndexExact, lookupDecreases⟩
      have beforeBounds := spec.stateChecked_sound before beforeChecked
      have afterBounds := spec.stateChecked_sound after afterChecked
      simp only [LexicographicLoopRankSpec.rank]
      rw [recordIndexExact]
      omega
  | outer =>
      simp only [LexicographicLoopRankSpec.stepChecked, Bool.and_eq_true,
        decide_eq_true_eq, beq_iff_eq] at checked
      rcases checked with
        ⟨⟨beforeChecked, afterChecked⟩, beforeInside, recordIndexExact⟩
      have beforeBounds := spec.stateChecked_sound before beforeChecked
      have afterBounds := spec.stateChecked_sound after afterChecked
      simp only [LexicographicLoopRankSpec.rank]
      rw [recordIndexExact]
      have remainingExact :
          spec.recordCount - before.recordIndex =
            (spec.recordCount - (before.recordIndex + 1)) + 1 := by
        omega
      rw [remainingExact, Nat.add_mul]
      omega

#print axioms LexicographicLoopRankSpec.stateChecked_sound
#print axioms LexicographicLoopRankSpec.stepChecked_rank_decreases

end StageA.Relational.InterpreterMixedLaunchLexicographicInvariant
