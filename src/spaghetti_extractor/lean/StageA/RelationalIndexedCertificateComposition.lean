import StageA.RelationalStaticTree

namespace StageA.Relational

open StageA.Formal

/-- Completeness companion to `indexedBoolRangesValid_sound`.  Generated
shards check bounded ranges independently; this theorem reconstructs the
original Boolean certificate without evaluating its predicate again. -/
theorem indexedBoolRangesValid_of_coverage_and_holds
    (predicate : Nat -> Bool) (size : Nat) :
    forall cursor ranges,
      indexedRangesCover size cursor ranges = true ->
      AllIndexedBoolRangesHold predicate ranges ->
      indexedBoolRangesValid predicate size cursor ranges = true := by
  intro cursor ranges
  induction ranges generalizing cursor with
  | nil =>
      intro coverage _
      simpa [indexedRangesCover, indexedBoolRangesValid] using coverage
  | cons span spans ih =>
      intro coverage holds
      simp only [indexedRangesCover, Bool.and_eq_true, beq_iff_eq] at coverage
      rcases coverage with
        ⟨⟨⟨nonempty, starts⟩, bounded⟩, tailCoverage⟩
      rcases holds with ⟨headHolds, tailHolds⟩
      simp only [indexedBoolRangesValid, Bool.and_eq_true, beq_iff_eq]
      refine ⟨⟨⟨⟨nonempty, starts⟩, bounded⟩, ?_⟩,
        ih span.stop tailCoverage tailHolds⟩
      simp only [List.all_eq_true]
      intro offset member
      exact headHolds offset (List.mem_range.mp member)

theorem IndexedBoolCertificate.checked_of_ranges
    (predicate : Nat -> Bool) (size : Nat)
    (certificate : IndexedBoolCertificate)
    (coverage : indexedRangesCover size 0 certificate.ranges = true)
    (rangesHold : AllIndexedBoolRangesHold predicate certificate.ranges) :
    certificate.checked predicate size = true :=
  indexedBoolRangesValid_of_coverage_and_holds predicate size 0
    certificate.ranges coverage rangesHold

/-- Turn one global pointwise proof into the range-oriented representation
used by the compatibility checker. -/
theorem allIndexedBoolRangesHold_of_coverage_and_holds
    (predicate : Nat -> Bool) (size : Nat) :
    forall cursor ranges,
      indexedRangesCover size cursor ranges = true ->
      (forall index, cursor <= index -> index < size ->
        predicate index = true) ->
      AllIndexedBoolRangesHold predicate ranges := by
  intro cursor ranges
  induction ranges generalizing cursor with
  | nil => intro _ _; trivial
  | cons span spans ih =>
      intro coverage holds
      simp only [indexedRangesCover, Bool.and_eq_true, beq_iff_eq,
        decide_eq_true_eq] at coverage
      rcases coverage with
        ⟨⟨⟨nonempty, starts⟩, bounded⟩, tailCoverage⟩
      constructor
      · intro offset before
        apply holds
        · rw [← starts]
          omega
        · have offsetStop : span.start + offset < span.stop := by
            simp only [Span.stop]
            omega
          exact Nat.lt_of_lt_of_le offsetStop bounded
      · apply ih span.stop tailCoverage
        intro index after before
        apply holds index
        · have cursorStop : cursor <= span.stop := by
            rw [← starts]
            simp [Span.stop]
          exact Nat.le_trans cursorStop after
        · exact before

/-- Reconstruct the Boolean representation from the proof-oriented
`IndexedBoolCertificate.Holds` interface.  Coverage remains checked
independently, so neither gaps nor overlapping ranges can be hidden. -/
theorem IndexedBoolCertificate.checked_of_holds
    (predicate : Nat -> Bool) (size : Nat)
    (certificate : IndexedBoolCertificate)
    (coverage : indexedRangesCover size 0 certificate.ranges = true)
    (holds : certificate.Holds predicate size) :
    certificate.checked predicate size = true := by
  apply certificate.checked_of_ranges predicate size coverage
  apply allIndexedBoolRangesHold_of_coverage_and_holds
    predicate size 0 certificate.ranges coverage
  intro index _ before
  exact holds index before

/-- Compose checked finite-index shards without reducing either child.  The
only new obligations are the branch metadata and AVL-height bounds. -/
theorem FiniteIndex.structurallyValid_branch
    (leafCapacity totalSize leftSize : Nat)
    (left right : FiniteIndex α)
    (leftValid : left.structurallyValid leafCapacity = true)
    (rightValid : right.structurallyValid leafCapacity = true)
    (totalSizeExact : totalSize = left.size + right.size)
    (leftSizeExact : leftSize = left.size)
    (leftNonempty : left.size != 0)
    (rightNonempty : right.size != 0)
    (leftHeightBound : left.height <= right.height + 1)
    (rightHeightBound : right.height <= left.height + 1) :
    (FiniteIndex.branch totalSize leftSize left right).structurallyValid
      leafCapacity = true := by
  simp only [FiniteIndex.structurallyValid, Bool.and_eq_true] at leftValid rightValid
  rcases leftValid with ⟨⟨⟨leftSizes, leftLeaves⟩, leftBranches⟩,
    leftBalanced⟩
  rcases rightValid with ⟨⟨⟨rightSizes, rightLeaves⟩, rightBranches⟩,
    rightBalanced⟩
  simp only [FiniteIndex.structurallyValid, FiniteIndex.sizesSound,
    FiniteIndex.leavesBounded, FiniteIndex.branchesNonempty,
    FiniteIndex.balanced, Bool.and_eq_true, beq_iff_eq, bne_iff_ne,
    decide_eq_true_eq] at leftNonempty rightNonempty ⊢
  exact ⟨⟨⟨
    ⟨⟨⟨totalSizeExact, leftSizeExact⟩, leftSizes⟩, rightSizes⟩,
    ⟨leftLeaves, rightLeaves⟩⟩,
    ⟨⟨⟨leftNonempty, rightNonempty⟩, leftBranches⟩, rightBranches⟩⟩,
    ⟨⟨⟨leftHeightBound, rightHeightBound⟩, leftBalanced⟩,
      rightBalanced⟩⟩

end StageA.Relational
