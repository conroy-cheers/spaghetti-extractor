import StageA.RelationalMachine
import Lean.Elab.Tactic.Omega

namespace StageA.Relational

open StageA.Formal

theorem indexedBoolRangeHolds_append (predicate : Nat -> Bool) (left right : Span)
    (adjacent : right.start = left.stop)
    (leftHolds : IndexedBoolRangeHolds predicate left)
    (rightHolds : IndexedBoolRangeHolds predicate right) :
    IndexedBoolRangeHolds predicate {
      start := left.start
      size := left.size + right.size
    } := by
  intro offset before
  change offset < left.size + right.size at before
  by_cases inLeft : offset < left.size
  · exact leftHolds offset inLeft
  · have rightOffsetBefore : offset - left.size < right.size := by omega
    have rightValue := rightHolds (offset - left.size) rightOffsetBefore
    simp only [Span.stop] at adjacent
    rw [adjacent] at rightValue
    have address :
        left.start + left.size + (offset - left.size) = left.start + offset := by
      omega
    simpa [address] using rightValue

theorem indexedNatFold_append (value : Nat -> Nat) (start leftSize rightSize total : Nat) :
    indexedNatFold value start (leftSize + rightSize) total =
      indexedNatFold value (start + leftSize) rightSize
        (indexedNatFold value start leftSize total) := by
  induction leftSize generalizing start total with
  | zero => simp [indexedNatFold]
  | succ leftSize ih =>
      rw [Nat.succ_add]
      simp only [indexedNatFold]
      rw [ih]
      congr 1
      omega

theorem indexedNatRangeFoldHolds_append (value : Nat -> Nat) (left right : Span)
    (before middle after : Nat)
    (adjacent : right.start = left.stop)
    (leftHolds : IndexedNatRangeFoldHolds value left before middle)
    (rightHolds : IndexedNatRangeFoldHolds value right middle after) :
    IndexedNatRangeFoldHolds value {
      start := left.start
      size := left.size + right.size
    } before after := by
  unfold IndexedNatRangeFoldHolds at leftHolds rightHolds ⊢
  change indexedNatFold value left.start (left.size + right.size) before = after
  rw [indexedNatFold_append, leftHolds]
  simp only [Span.stop] at adjacent
  rw [← adjacent]
  exact rightHolds

end StageA.Relational
