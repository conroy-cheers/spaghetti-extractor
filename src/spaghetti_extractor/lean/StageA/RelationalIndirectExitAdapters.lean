import StageA.RelationalStackFixedCodePointer

namespace StageA.Relational

open StageA.Formal
open StageA.Relational.ValueProvenance

namespace IndirectExitAdapters

def immutableCallIndirectCertificate
    (claim : ImmutableIndirectCallTargetClaim) :
    IndirectExitCertificate := {
  finiteAlternativeBudget := 1
  target := {
    original := immutableWordReadExpression claim.originalAssembledRead
      claim.originalAddress claim.originalWrites
    candidate := immutableWordReadExpression claim.candidateAssembledRead
      claim.candidateAddress claim.candidateWrites
    source := .immutableImageWord claim.originalAddress claim.candidateAddress
    origin := { alternatives := [.staticCodeTarget claim.targetId 0] }
  }
  destinations := [.internalCode claim.targetId]
  transfer := .call claim.continuationTargetId
}

theorem immutableCallTargetEvaluation
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImmutableIndirectCallTargetClaim)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true) :
    (immutableCallIndirectCertificate claim).TargetEvaluation context
      sourceInvariant := by
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
      simp [ImmutableIndirectCallTargetClaim.checked, targetResult] at checked
  | some target =>
      have closed := immutableIndirectCallTargetsClosed_of_checked context
        sourceInvariant originalBehavior candidateBehavior claim checked
      simp only [ImmutableIndirectCallTargetsClosed, targetResult] at closed
      have checkedRows := checked
      simp only [ImmutableIndirectCallTargetClaim.checked, targetResult,
        Bool.and_eq_true, beq_iff_eq] at checkedRows
      rcases checkedRows with
        ⟨⟨⟨⟨⟨⟨_originalImageWord, _candidateImageWord⟩, _mappedWord⟩,
          originalOutcome⟩, candidateOutcome⟩, _originalSeparated⟩,
          _candidateSeparated⟩
      intro world originalState candidateState related
      rcases closed world originalState candidateState related with
        ⟨originalTarget, candidateTarget, originalEvaluated, candidateEvaluated,
          originalMatches, candidateMatches⟩
      have originalValue :
          (immutableWordReadExpression claim.originalAssembledRead
            claim.originalAddress claim.originalWrites).eval originalState =
              originalTarget := by
        rw [originalOutcome] at originalEvaluated
        simpa [NormalizedOutcomeExpr.eval] using originalEvaluated
      have candidateValue :
          (immutableWordReadExpression claim.candidateAssembledRead
            claim.candidateAddress claim.candidateWrites).eval candidateState =
              candidateTarget := by
        rw [candidateOutcome] at candidateEvaluated
        simpa [NormalizedOutcomeExpr.eval] using candidateEvaluated
      constructor
      · refine ⟨.staticCodeTarget claim.targetId 0, ?_, ?_⟩
        · simp [immutableCallIndirectCertificate]
        · refine ⟨target, targetResult, Or.inl ⟨rfl, ?_, ?_⟩⟩
          · simpa [immutableCallIndirectCertificate, originalValue] using
              originalMatches
          · simpa [immutableCallIndirectCertificate, candidateValue] using
              candidateMatches
      · refine ⟨.internalCode claim.targetId, ?_, target, targetResult, ?_, ?_⟩
        · simp [immutableCallIndirectCertificate]
        · simpa [immutableCallIndirectCertificate, originalValue] using
            originalMatches
        · simpa [immutableCallIndirectCertificate, candidateValue] using
            candidateMatches

def checkedImmutableCallIndirectCertificate
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImmutableIndirectCallTargetClaim)
    (legacyChecked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (genericChecked :
      (immutableCallIndirectCertificate claim).checked context = true) :
    CheckedIndirectExitCertificate context sourceInvariant
      originalBehavior candidateBehavior := {
  certificate := immutableCallIndirectCertificate claim
  staticChecked := genericChecked
  outcomeChecked := by
    have rows := legacyChecked
    cases targetResult : context.codeMap.get? claim.targetId with
    | none =>
        simp [ImmutableIndirectCallTargetClaim.checked, targetResult] at rows
    | some target =>
        simp only [ImmutableIndirectCallTargetClaim.checked, targetResult,
          Bool.and_eq_true, beq_iff_eq] at rows
        rcases rows with
          ⟨⟨⟨⟨⟨⟨_originalImageWord, _candidateImageWord⟩, _mappedWord⟩,
            originalOutcome⟩, candidateOutcome⟩, _originalSeparated⟩,
            _candidateSeparated⟩
        simp [immutableCallIndirectCertificate,
          IndirectExitCertificate.outcomeChecked, originalOutcome,
          candidateOutcome]
  targetEvaluation := immutableCallTargetEvaluation context sourceInvariant
    originalBehavior candidateBehavior claim legacyChecked
}

def staticWordSlotIndirectCertificate
    (claim : StaticWordSlotIndirectCallTargetClaim) :
    IndirectExitCertificate := {
  finiteAlternativeBudget := 1
  target := {
    original := immutableWordReadExpression claim.originalAssembledRead
      claim.originalAddress claim.originalWrites
    candidate := immutableWordReadExpression claim.candidateAssembledRead
      claim.candidateAddress claim.candidateWrites
    source := .staticWord claim.slot.id
    origin := { alternatives := [.staticCodeTarget claim.targetId 0] }
  }
  destinations := [.internalCode claim.targetId]
  transfer := .call claim.continuationTargetId
}

theorem staticWordSlotTargetEvaluation
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StaticWordSlotIndirectCallTargetClaim)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true) :
    (staticWordSlotIndirectCertificate claim).TargetEvaluation context
      sourceInvariant := by
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
      simp [StaticWordSlotIndirectCallTargetClaim.checked, targetResult] at checked
  | some target =>
      have closed := staticWordSlotIndirectCallTargetsClosed_of_checked context
        sourceInvariant originalBehavior candidateBehavior claim checked
      simp only [StaticWordSlotIndirectCallTargetsClosed, targetResult] at closed
      have checkedRows := checked
      simp only [StaticWordSlotIndirectCallTargetClaim.checked, targetResult,
        Bool.and_eq_true, beq_iff_eq] at checkedRows
      rcases checkedRows with
        ⟨⟨⟨⟨⟨⟨⟨_slotMember, _slotRelation⟩, _originalAddress⟩,
          _candidateAddress⟩, originalOutcome⟩, candidateOutcome⟩,
          _originalSeparated⟩, _candidateSeparated⟩
      intro world originalState candidateState related
      rcases closed world originalState candidateState related with
        ⟨originalTarget, candidateTarget, originalEvaluated, candidateEvaluated,
          originalMatches, candidateMatches⟩
      have originalValue :
          (immutableWordReadExpression claim.originalAssembledRead
            claim.originalAddress claim.originalWrites).eval originalState =
              originalTarget := by
        rw [originalOutcome] at originalEvaluated
        simpa [NormalizedOutcomeExpr.eval] using originalEvaluated
      have candidateValue :
          (immutableWordReadExpression claim.candidateAssembledRead
            claim.candidateAddress claim.candidateWrites).eval candidateState =
              candidateTarget := by
        rw [candidateOutcome] at candidateEvaluated
        simpa [NormalizedOutcomeExpr.eval] using candidateEvaluated
      constructor
      · refine ⟨.staticCodeTarget claim.targetId 0, ?_, ?_⟩
        · simp [staticWordSlotIndirectCertificate]
        · refine ⟨target, targetResult, Or.inl ⟨rfl, ?_, ?_⟩⟩
          · simpa [staticWordSlotIndirectCertificate,
              originalValue] using originalMatches
          · simpa [staticWordSlotIndirectCertificate,
              candidateValue] using candidateMatches
      · refine ⟨.internalCode claim.targetId, ?_, target, targetResult, ?_, ?_⟩
        · simp [staticWordSlotIndirectCertificate]
        · simpa [staticWordSlotIndirectCertificate,
            originalValue] using originalMatches
        · simpa [staticWordSlotIndirectCertificate,
            candidateValue] using candidateMatches

def checkedStaticWordSlotIndirectCertificate
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StaticWordSlotIndirectCallTargetClaim)
    (legacyChecked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (genericChecked :
      (staticWordSlotIndirectCertificate claim).checked context = true) :
    CheckedIndirectExitCertificate context sourceInvariant
      originalBehavior candidateBehavior := {
  certificate := staticWordSlotIndirectCertificate claim
  staticChecked := genericChecked
  outcomeChecked := by
    have rows := legacyChecked
    cases targetResult : context.codeMap.get? claim.targetId with
    | none =>
        simp [StaticWordSlotIndirectCallTargetClaim.checked, targetResult] at rows
    | some target =>
        simp only [StaticWordSlotIndirectCallTargetClaim.checked, targetResult,
          Bool.and_eq_true, beq_iff_eq] at rows
        rcases rows with
          ⟨⟨⟨⟨⟨⟨⟨_slotMember, _slotRelation⟩, _originalAddress⟩,
            _candidateAddress⟩, originalOutcome⟩, candidateOutcome⟩,
            _originalSeparated⟩, _candidateSeparated⟩
        simp [staticWordSlotIndirectCertificate,
          IndirectExitCertificate.outcomeChecked, originalOutcome,
          candidateOutcome]
  targetEvaluation := staticWordSlotTargetEvaluation context sourceInvariant
    originalBehavior candidateBehavior claim legacyChecked
}

def staticWordSlotJumpIndirectCertificate
    (claim : StaticWordSlotIndirectJumpTargetClaim) :
    IndirectExitCertificate := {
  finiteAlternativeBudget := 1
  target := {
    original := immutableWordReadExpression claim.originalAssembledRead
      claim.originalAddress claim.originalWrites
    candidate := immutableWordReadExpression claim.candidateAssembledRead
      claim.candidateAddress claim.candidateWrites
    source := .staticWord claim.slot.id
    origin := { alternatives := [.staticCodeTarget claim.targetId 0] }
  }
  destinations := [.internalCode claim.targetId]
  transfer := .jump
}

theorem staticWordSlotJumpTargetEvaluation
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StaticWordSlotIndirectJumpTargetClaim)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true) :
    (staticWordSlotJumpIndirectCertificate claim).TargetEvaluation context
      sourceInvariant := by
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
      simp [StaticWordSlotIndirectJumpTargetClaim.checked, targetResult] at checked
  | some target =>
      have closed := staticWordSlotIndirectJumpTargetsClosed_of_checked context
        sourceInvariant originalBehavior candidateBehavior claim checked
      simp only [StaticWordSlotIndirectJumpTargetsClosed, targetResult] at closed
      have checkedRows := checked
      simp only [StaticWordSlotIndirectJumpTargetClaim.checked, targetResult,
        Bool.and_eq_true, beq_iff_eq] at checkedRows
      rcases checkedRows with
        ⟨⟨⟨⟨⟨⟨⟨⟨⟨_slotMember, _slotRelation⟩, _originalAddress⟩,
          _candidateAddress⟩, _originalAliases⟩, _candidateAliases⟩,
          originalOutcome⟩, candidateOutcome⟩, _originalSeparated⟩,
          _candidateSeparated⟩
      intro world originalState candidateState related
      have evaluated := closed world originalState candidateState related
      have originalValue :
          (immutableWordReadExpression claim.originalAssembledRead
            claim.originalAddress claim.originalWrites).eval originalState =
              BitVec.ofNat 32
                (context.originalPe.imageBase + target.originalRva) := by
        rw [originalOutcome] at evaluated
        simpa [NormalizedOutcomeExpr.eval] using evaluated.1
      have candidateValue :
          (immutableWordReadExpression claim.candidateAssembledRead
            claim.candidateAddress claim.candidateWrites).eval candidateState =
              BitVec.ofNat 32
                (context.candidatePe.imageBase + target.candidateRva) := by
        rw [candidateOutcome] at evaluated
        simpa [NormalizedOutcomeExpr.eval] using evaluated.2
      constructor
      · refine ⟨.staticCodeTarget claim.targetId 0, ?_, target, targetResult,
          Or.inl ⟨rfl, ?_, ?_⟩⟩
        · simp [staticWordSlotJumpIndirectCertificate]
        · simp [staticWordSlotJumpIndirectCertificate, originalValue,
            codeAddressMatches]
        · simp [staticWordSlotJumpIndirectCertificate, candidateValue,
            codeAddressMatches]
      · refine ⟨.internalCode claim.targetId, ?_, target, targetResult, ?_, ?_⟩
        · simp [staticWordSlotJumpIndirectCertificate]
        · simp [staticWordSlotJumpIndirectCertificate, originalValue,
            codeAddressMatches]
        · simp [staticWordSlotJumpIndirectCertificate, candidateValue,
            codeAddressMatches]

def checkedStaticWordSlotJumpIndirectCertificate
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StaticWordSlotIndirectJumpTargetClaim)
    (legacyChecked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (genericChecked :
      (staticWordSlotJumpIndirectCertificate claim).checked context = true) :
    CheckedIndirectExitCertificate context sourceInvariant
      originalBehavior candidateBehavior := {
  certificate := staticWordSlotJumpIndirectCertificate claim
  staticChecked := genericChecked
  outcomeChecked := by
    have rows := legacyChecked
    cases targetResult : context.codeMap.get? claim.targetId with
    | none =>
        simp [StaticWordSlotIndirectJumpTargetClaim.checked, targetResult] at rows
    | some target =>
        simp only [StaticWordSlotIndirectJumpTargetClaim.checked, targetResult,
          Bool.and_eq_true, beq_iff_eq] at rows
        rcases rows with
          ⟨⟨⟨⟨⟨⟨⟨⟨⟨_slotMember, _slotRelation⟩, _originalAddress⟩,
            _candidateAddress⟩, _originalAliases⟩, _candidateAliases⟩,
            originalOutcome⟩, candidateOutcome⟩, _originalSeparated⟩,
            _candidateSeparated⟩
        simp [staticWordSlotJumpIndirectCertificate,
          IndirectExitCertificate.outcomeChecked, originalOutcome,
          candidateOutcome]
  targetEvaluation := staticWordSlotJumpTargetEvaluation context sourceInvariant
    originalBehavior candidateBehavior claim legacyChecked
}

def immutableJumpIndirectCertificate
    (claim : ImmutableIndirectJumpTargetClaim) :
    IndirectExitCertificate := {
  finiteAlternativeBudget := 1
  target := {
    original := immutableWordReadExpression claim.originalAssembledRead
      claim.originalAddress claim.originalWrites
    candidate := immutableWordReadExpression claim.candidateAssembledRead
      claim.candidateAddress claim.candidateWrites
    source := .immutableImageWord claim.originalAddress claim.candidateAddress
    origin := { alternatives := [.staticCodeTarget claim.targetId 0] }
  }
  destinations := [.internalCode claim.targetId]
  transfer := .jump
}

theorem immutableJumpTargetEvaluation
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImmutableIndirectJumpTargetClaim)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true) :
    (immutableJumpIndirectCertificate claim).TargetEvaluation context
      sourceInvariant := by
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
      simp [ImmutableIndirectJumpTargetClaim.checked, targetResult] at checked
  | some target =>
      have closed := immutableIndirectJumpTargetsClosed_of_checked context
        sourceInvariant originalBehavior candidateBehavior claim checked
      simp only [ImmutableIndirectJumpTargetsClosed, targetResult] at closed
      intro world originalState candidateState related
      have evaluated := closed world originalState candidateState related
      have checkedRows := checked
      simp only [ImmutableIndirectJumpTargetClaim.checked, targetResult,
        Bool.and_eq_true, beq_iff_eq] at checkedRows
      rcases checkedRows with
        ⟨⟨⟨⟨⟨⟨_originalImageWord, _candidateImageWord⟩, _mappedWord⟩,
          originalOutcome⟩, candidateOutcome⟩, _originalSeparated⟩,
          _candidateSeparated⟩
      have originalValue :
          (immutableWordReadExpression claim.originalAssembledRead
            claim.originalAddress claim.originalWrites).eval originalState =
              BitVec.ofNat 32
                (context.originalPe.imageBase + target.originalRva) := by
        rw [originalOutcome] at evaluated
        simpa [NormalizedOutcomeExpr.eval] using evaluated.1
      have candidateValue :
          (immutableWordReadExpression claim.candidateAssembledRead
            claim.candidateAddress claim.candidateWrites).eval candidateState =
              BitVec.ofNat 32
                (context.candidatePe.imageBase + target.candidateRva) := by
        rw [candidateOutcome] at evaluated
        simpa [NormalizedOutcomeExpr.eval] using evaluated.2
      constructor
      · refine ⟨.staticCodeTarget claim.targetId 0, ?_, ?_⟩
        · simp [immutableJumpIndirectCertificate]
        · refine ⟨target, targetResult, Or.inl ⟨rfl, ?_, ?_⟩⟩
          · simp [immutableJumpIndirectCertificate, originalValue,
              codeAddressMatches]
          · simp [immutableJumpIndirectCertificate, candidateValue,
              codeAddressMatches]
      · refine ⟨.internalCode claim.targetId, ?_, target, targetResult, ?_, ?_⟩
        · simp [immutableJumpIndirectCertificate]
        · simp [immutableJumpIndirectCertificate, originalValue,
            codeAddressMatches]
        · simp [immutableJumpIndirectCertificate, candidateValue,
            codeAddressMatches]

def checkedImmutableJumpIndirectCertificate
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImmutableIndirectJumpTargetClaim)
    (legacyChecked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (genericChecked :
      (immutableJumpIndirectCertificate claim).checked context = true) :
    CheckedIndirectExitCertificate context sourceInvariant
      originalBehavior candidateBehavior := {
  certificate := immutableJumpIndirectCertificate claim
  staticChecked := genericChecked
  outcomeChecked := by
    have rows := legacyChecked
    cases targetResult : context.codeMap.get? claim.targetId with
    | none =>
        simp [ImmutableIndirectJumpTargetClaim.checked, targetResult] at rows
    | some target =>
        simp only [ImmutableIndirectJumpTargetClaim.checked, targetResult,
          Bool.and_eq_true, beq_iff_eq] at rows
        rcases rows with
          ⟨⟨⟨⟨⟨⟨_originalImageWord, _candidateImageWord⟩, _mappedWord⟩,
            originalOutcome⟩, candidateOutcome⟩, _originalSeparated⟩,
            _candidateSeparated⟩
        simp [immutableJumpIndirectCertificate,
          IndirectExitCertificate.outcomeChecked, originalOutcome,
          candidateOutcome]
  targetEvaluation := immutableJumpTargetEvaluation context sourceInvariant
    originalBehavior candidateBehavior claim legacyChecked
}

def fixedAddressJumpIndirectCertificate
    (claim : FixedCodeAddressIndirectJumpTargetClaim) :
    IndirectExitCertificate := {
  finiteAlternativeBudget := 1
  target := {
    original := .constant claim.originalTarget
    candidate := .constant claim.candidateTarget
    source := .exactExpression
    origin := { alternatives := [.staticCodeTarget claim.targetId 0] }
  }
  destinations := [.internalCode claim.targetId]
  transfer := .jump
}

theorem fixedAddressJumpTargetEvaluation
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : FixedCodeAddressIndirectJumpTargetClaim)
    (checked : claim.checked context originalBehavior candidateBehavior = true) :
    (fixedAddressJumpIndirectCertificate claim).TargetEvaluation context
      sourceInvariant := by
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
      simp [FixedCodeAddressIndirectJumpTargetClaim.checked, targetResult] at checked
  | some target =>
      simp only [FixedCodeAddressIndirectJumpTargetClaim.checked, targetResult,
        Bool.and_eq_true, beq_iff_eq] at checked
      rcases checked with
        ⟨⟨⟨originalTarget, candidateTarget⟩, _originalOutcome⟩,
          _candidateOutcome⟩
      intro world originalState candidateState _related
      constructor
      · refine ⟨.staticCodeTarget claim.targetId 0, ?_, ?_⟩
        · simp [fixedAddressJumpIndirectCertificate]
        · refine ⟨target, targetResult, Or.inl ⟨rfl, ?_, ?_⟩⟩
          · simp [fixedAddressJumpIndirectCertificate, originalTarget, Expr.eval,
              codeAddressMatches]
          · simp [fixedAddressJumpIndirectCertificate, candidateTarget, Expr.eval,
              codeAddressMatches]
      · refine ⟨.internalCode claim.targetId, ?_, target, targetResult, ?_, ?_⟩
        · simp [fixedAddressJumpIndirectCertificate]
        · simp [fixedAddressJumpIndirectCertificate, originalTarget, Expr.eval,
            codeAddressMatches]
        · simp [fixedAddressJumpIndirectCertificate, candidateTarget, Expr.eval,
            codeAddressMatches]

def checkedFixedAddressJumpIndirectCertificate
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : FixedCodeAddressIndirectJumpTargetClaim)
    (legacyChecked : claim.checked context originalBehavior
      candidateBehavior = true)
    (genericChecked :
      (fixedAddressJumpIndirectCertificate claim).checked context = true) :
    CheckedIndirectExitCertificate context sourceInvariant
      originalBehavior candidateBehavior := {
  certificate := fixedAddressJumpIndirectCertificate claim
  staticChecked := genericChecked
  outcomeChecked := by
    have rows := legacyChecked
    cases targetResult : context.codeMap.get? claim.targetId with
    | none =>
        simp [FixedCodeAddressIndirectJumpTargetClaim.checked, targetResult] at rows
    | some target =>
        simp only [FixedCodeAddressIndirectJumpTargetClaim.checked, targetResult,
          Bool.and_eq_true, beq_iff_eq] at rows
        rcases rows with
          ⟨⟨⟨_originalTarget, _candidateTarget⟩, originalOutcome⟩,
            candidateOutcome⟩
        simp [fixedAddressJumpIndirectCertificate,
          IndirectExitCertificate.outcomeChecked, originalOutcome,
          candidateOutcome]
  targetEvaluation := fixedAddressJumpTargetEvaluation context sourceInvariant
    originalBehavior candidateBehavior claim legacyChecked
}

def boundedTableCallTargetAtoms
    (claim : BoundedImmutableCodePointerTableCallClaim) :
    List ValueOriginAtom :=
  (claim.rows.map fun row => .staticCodeTarget row.targetId 0).eraseDups

def boundedTableCallDestinations
    (claim : BoundedImmutableCodePointerTableCallClaim) :
    List IndirectDestination :=
  (claim.rows.map fun row => .internalCode row.targetId).eraseDups

def boundedTableCallIndirectCertificate
    (claim : BoundedImmutableCodePointerTableCallClaim) :
    IndirectExitCertificate := {
  finiteAlternativeBudget := max 1 claim.rows.length
  target := {
    original := claim.originalTargetExpression
    candidate := claim.candidateTargetExpression
    source := .immutableImageWord claim.originalBase claim.candidateBase
    origin := { alternatives := boundedTableCallTargetAtoms claim }
  }
  destinations := boundedTableCallDestinations claim
  transfer := .call claim.continuationTargetId
}

theorem boundedTableCallTargetEvaluation
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableCodePointerTableCallClaim)
    (structurallyValid : context.StructurallyValid)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true) :
    (boundedTableCallIndirectCertificate claim).TargetEvaluation context
      sourceInvariant := by
  have closed := boundedImmutableCodePointerTableCallTargetsClosed_of_checked
    context sourceInvariant originalBehavior candidateBehavior claim
      structurallyValid checked
  have checkedRows := checked
  simp only [BoundedImmutableCodePointerTableCallClaim.checked,
    Bool.and_eq_true] at checkedRows
  have behaviorChecked := checkedRows.2
  simp only [BoundedImmutableCodePointerTableCallClaim.behaviorChecked,
    Bool.and_eq_true, beq_iff_eq] at behaviorChecked
  intro world originalState candidateState related
  rcases closed.2 world originalState candidateState related with
    ⟨row, target, originalTarget, candidateTarget, rowMember, targetResult,
      _rowChecked, originalOutcome, candidateOutcome, _originalGuard,
      _candidateGuard, originalMatches, candidateMatches⟩
  have originalValue :
      claim.originalTargetExpression.eval originalState = originalTarget := by
    rw [behaviorChecked.1] at originalOutcome
    simpa [NormalizedOutcomeExpr.eval] using originalOutcome
  have candidateValue :
      claim.candidateTargetExpression.eval candidateState = candidateTarget := by
    rw [behaviorChecked.2] at candidateOutcome
    simpa [NormalizedOutcomeExpr.eval] using candidateOutcome
  have atomMember :
      ValueOriginAtom.staticCodeTarget row.targetId 0 ∈
        boundedTableCallTargetAtoms claim := by
    apply List.mem_eraseDups.mpr
    exact List.mem_map.mpr ⟨row, rowMember, rfl⟩
  have destinationMember :
      IndirectDestination.internalCode row.targetId ∈
        boundedTableCallDestinations claim := by
    apply List.mem_eraseDups.mpr
    exact List.mem_map.mpr ⟨row, rowMember, rfl⟩
  constructor
  · refine ⟨.staticCodeTarget row.targetId 0, atomMember, target,
      targetResult, Or.inl ⟨rfl, ?_, ?_⟩⟩
    · simpa [boundedTableCallIndirectCertificate, originalValue] using
        originalMatches
    · simpa [boundedTableCallIndirectCertificate, candidateValue] using
        candidateMatches
  · refine ⟨.internalCode row.targetId, destinationMember, target,
      targetResult, ?_, ?_⟩
    · simpa [boundedTableCallIndirectCertificate, originalValue] using
        originalMatches
    · simpa [boundedTableCallIndirectCertificate, candidateValue] using
        candidateMatches

def checkedBoundedTableCallIndirectCertificate
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableCodePointerTableCallClaim)
    (structurallyValid : context.StructurallyValid)
    (legacyChecked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (genericChecked :
      (boundedTableCallIndirectCertificate claim).checked context = true) :
    CheckedIndirectExitCertificate context sourceInvariant
      originalBehavior candidateBehavior := {
  certificate := boundedTableCallIndirectCertificate claim
  staticChecked := genericChecked
  outcomeChecked := by
    have rows := legacyChecked
    simp only [BoundedImmutableCodePointerTableCallClaim.checked,
      Bool.and_eq_true] at rows
    have behaviorChecked := rows.2
    simp only [BoundedImmutableCodePointerTableCallClaim.behaviorChecked,
      Bool.and_eq_true, beq_iff_eq] at behaviorChecked
    simp [boundedTableCallIndirectCertificate,
      IndirectExitCertificate.outcomeChecked, behaviorChecked.1,
      behaviorChecked.2]
  targetEvaluation := boundedTableCallTargetEvaluation context sourceInvariant
    originalBehavior candidateBehavior claim structurallyValid legacyChecked
}

def boundedTableJumpTargetAtoms
    (claim : BoundedImmutableRelocationTableJumpControlClaim) :
    List ValueOriginAtom :=
  (claim.table.finiteTargetIds.map fun targetId =>
    .staticCodeTarget targetId 0).eraseDups

def boundedTableJumpDestinations
    (claim : BoundedImmutableRelocationTableJumpControlClaim) :
    List IndirectDestination :=
  (claim.table.finiteTargetIds.map fun targetId =>
    .internalCode targetId).eraseDups

def boundedTableJumpIndirectCertificate
    (claim : BoundedImmutableRelocationTableJumpControlClaim) :
    IndirectExitCertificate := {
  finiteAlternativeBudget := max 1 claim.table.finiteTargetIds.length
  target := {
    original := immutableCodePointerTableTargetExpression claim.table.originalBase
      claim.table.originalIndex
    candidate := immutableCodePointerTableTargetExpression claim.table.candidateBase
      claim.table.candidateIndex
    source := .immutableImageWord claim.table.originalBase claim.table.candidateBase
    origin := { alternatives := boundedTableJumpTargetAtoms claim }
  }
  destinations := boundedTableJumpDestinations claim
  transfer := .jump
}

theorem boundedTableJumpTargetEvaluation
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableRelocationTableJumpControlClaim)
    (structurallyValid : context.StructurallyValid)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true) :
    (boundedTableJumpIndirectCertificate claim).TargetEvaluation context
      sourceInvariant := by
  have closed := boundedImmutableRelocationTableJumpTargetsClosed_of_checked
    context sourceInvariant originalBehavior candidateBehavior claim
      structurallyValid checked
  have checkedRows := checked
  simp only [BoundedImmutableRelocationTableJumpControlClaim.checked,
    Bool.and_eq_true, decide_eq_true_eq] at checkedRows
  have behaviorChecked := checkedRows.2
  simp only [BoundedImmutableRelocationTableJumpControlClaim.behaviorChecked,
    Bool.and_eq_true, beq_iff_eq] at behaviorChecked
  rcases structurallyValid with
    ⟨_, _, _, _, _, _, indexedValid, _⟩
  intro world originalState candidateState related
  rcases closed.2 world originalState candidateState related with
    ⟨targetId, target, originalTarget, candidateTarget, targetIdMember,
      targetFind, originalOutcome, candidateOutcome, originalGuard,
      candidateGuard⟩
  have targetMember : target ∈ context.codeMap.entries.toList :=
    List.mem_of_find?_eq_some targetFind
  have targetIdChecked : target.id == targetId := by
    exact List.find?_some
      (p := fun item : CodeTargetPair => item.id == targetId)
      (a := target) targetFind
  have targetIdEqual : target.id = targetId :=
    beq_iff_eq.mp targetIdChecked
  have targetResult :
      context.codeMap.get? targetId = some target := by
    have byTargetId :=
      context.codeMap.get?_eq_some_of_mem context.originalPe context.candidatePe
        indexedValid target targetMember
    simpa [targetIdEqual] using byTargetId
  have originalValue :
      (immutableCodePointerTableTargetExpression claim.table.originalBase
        claim.table.originalIndex).eval originalState = originalTarget := by
    rw [behaviorChecked.1] at originalOutcome
    simpa [NormalizedOutcomeExpr.eval] using originalOutcome
  have candidateValue :
      (immutableCodePointerTableTargetExpression claim.table.candidateBase
        claim.table.candidateIndex).eval candidateState = candidateTarget := by
    rw [behaviorChecked.2] at candidateOutcome
    simpa [NormalizedOutcomeExpr.eval] using candidateOutcome
  have originalMatches :
      codeAddressMatches context.originalPe.imageBase target.originalRva
        target.originalAliases originalTarget = true := by
    rw [codeTargetProductGuard_eval_true] at originalGuard
    simpa [originalValue] using originalGuard
  have candidateMatches :
      codeAddressMatches context.candidatePe.imageBase target.candidateRva
        target.candidateAliases candidateTarget = true := by
    rw [codeTargetProductGuard_eval_true] at candidateGuard
    simpa [candidateValue] using candidateGuard
  have atomMember :
      ValueOriginAtom.staticCodeTarget targetId 0 ∈
        boundedTableJumpTargetAtoms claim := by
    apply List.mem_eraseDups.mpr
    exact List.mem_map.mpr ⟨targetId, targetIdMember, rfl⟩
  have destinationMember :
      IndirectDestination.internalCode targetId ∈
        boundedTableJumpDestinations claim := by
    apply List.mem_eraseDups.mpr
    exact List.mem_map.mpr ⟨targetId, targetIdMember, rfl⟩
  constructor
  · refine ⟨.staticCodeTarget targetId 0, atomMember, target, targetResult,
      Or.inl ⟨rfl, ?_, ?_⟩⟩
    · simpa [boundedTableJumpIndirectCertificate, originalValue] using
        originalMatches
    · simpa [boundedTableJumpIndirectCertificate, candidateValue] using
        candidateMatches
  · refine ⟨.internalCode targetId, destinationMember, target, targetResult,
      ?_, ?_⟩
    · simpa [boundedTableJumpIndirectCertificate, originalValue] using
        originalMatches
    · simpa [boundedTableJumpIndirectCertificate, candidateValue] using
        candidateMatches

def checkedBoundedTableJumpIndirectCertificate
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableRelocationTableJumpControlClaim)
    (structurallyValid : context.StructurallyValid)
    (legacyChecked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (genericChecked :
      (boundedTableJumpIndirectCertificate claim).checked context = true) :
    CheckedIndirectExitCertificate context sourceInvariant
      originalBehavior candidateBehavior := {
  certificate := boundedTableJumpIndirectCertificate claim
  staticChecked := genericChecked
  outcomeChecked := by
    have rows := legacyChecked
    simp only [BoundedImmutableRelocationTableJumpControlClaim.checked,
      Bool.and_eq_true, decide_eq_true_eq] at rows
    have behaviorChecked := rows.2
    simp only [BoundedImmutableRelocationTableJumpControlClaim.behaviorChecked,
      Bool.and_eq_true, beq_iff_eq] at behaviorChecked
    simp [boundedTableJumpIndirectCertificate,
      IndirectExitCertificate.outcomeChecked, behaviorChecked.1,
      behaviorChecked.2]
  targetEvaluation := boundedTableJumpTargetEvaluation context sourceInvariant
    originalBehavior candidateBehavior claim structurallyValid legacyChecked
}

def fixedRegisterIndirectCertificate
    (claim : FixedCodePointerRegisterIndirectCallClaim) :
    IndirectExitCertificate := {
  finiteAlternativeBudget := 1
  target := {
    original := .inputReg claim.originalRegister
    candidate := .inputReg claim.candidateRegister
    source := .register claim.originalRegister claim.candidateRegister
    origin := { alternatives := [.staticCodeTarget claim.targetId 0] }
  }
  destinations := [.internalCode claim.targetId]
  transfer := .call claim.continuationTargetId
}

/-- The register-storage adapter consumes the same finite target proposition as
the old register-specific rule.  Indexed-map validity is supplied once by the
canonical static context, not by a per-register lookup authority. -/
theorem fixedRegisterTargetEvaluation
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : FixedCodePointerRegisterIndirectCallClaim)
    (structurallyValid : context.StructurallyValid)
    (checked : claim.checked sourceInvariant originalBehavior
      candidateBehavior = true) :
    (fixedRegisterIndirectCertificate claim).TargetEvaluation context
      sourceInvariant := by
  have closed := fixedCodePointerRegisterIndirectCallTargetsClosed_of_checked
    context sourceInvariant originalBehavior candidateBehavior claim checked
  rcases structurallyValid with
    ⟨_, _, _, _, _, _, indexedValid, _⟩
  have sizesSound : context.codeMap.entries.sizesSound = true := by
    have structural := indexedValid.1
    simp only [FiniteIndex.structurallyValid, Bool.and_eq_true] at structural
    exact structural.1.1.1
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
      have listResult : context.codeMap.entries.toList[claim.targetId]? = none := by
        rw [← FiniteIndex.get?_eq_toList_get? context.codeMap.entries
          claim.targetId sizesSound]
        exact targetResult
      intro world originalState candidateState related
      rcases closed world originalState candidateState related with
        ⟨originalTarget, candidateTarget, _, _, fixed⟩
      simp [fixedCodePointerRelated, listResult] at fixed
  | some target =>
      have listResult :
          context.codeMap.entries.toList[claim.targetId]? = some target := by
        rw [← FiniteIndex.get?_eq_toList_get? context.codeMap.entries
          claim.targetId sizesSound]
        exact targetResult
      have checkedRows := checked
      simp only [FixedCodePointerRegisterIndirectCallClaim.checked,
        Bool.and_eq_true, beq_iff_eq] at checkedRows
      intro world originalState candidateState related
      rcases closed world originalState candidateState related with
        ⟨originalTarget, candidateTarget, originalEvaluated, candidateEvaluated,
          fixed⟩
      simp only [fixedCodePointerRelated, listResult, Bool.and_eq_true,
        beq_iff_eq] at fixed
      have originalValue :
          originalState.registers.get claim.originalRegister = originalTarget := by
        rw [checkedRows.1.2] at originalEvaluated
        simpa [NormalizedOutcomeExpr.eval] using originalEvaluated
      have candidateValue :
          candidateState.registers.get claim.candidateRegister = candidateTarget := by
        rw [checkedRows.2] at candidateEvaluated
        simpa [NormalizedOutcomeExpr.eval] using candidateEvaluated
      constructor
      · refine ⟨.staticCodeTarget claim.targetId 0, ?_, ?_⟩
        · simp [fixedRegisterIndirectCertificate]
        · refine ⟨target, targetResult, Or.inl ⟨rfl, ?_, ?_⟩⟩
          · simpa [fixedRegisterIndirectCertificate, Expr.eval,
              originalValue] using fixed.2.1
          · simpa [fixedRegisterIndirectCertificate, Expr.eval,
              candidateValue] using fixed.2.2
      · refine ⟨.internalCode claim.targetId, ?_, target, targetResult, ?_, ?_⟩
        · simp [fixedRegisterIndirectCertificate]
        · simpa [fixedRegisterIndirectCertificate, Expr.eval,
            originalValue] using fixed.2.1
        · simpa [fixedRegisterIndirectCertificate, Expr.eval,
            candidateValue] using fixed.2.2

def checkedFixedRegisterIndirectCertificate
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : FixedCodePointerRegisterIndirectCallClaim)
    (structurallyValid : context.StructurallyValid)
    (legacyChecked : claim.checked sourceInvariant originalBehavior
      candidateBehavior = true)
    (genericChecked :
      (fixedRegisterIndirectCertificate claim).checked context = true) :
    CheckedIndirectExitCertificate context sourceInvariant
      originalBehavior candidateBehavior := {
  certificate := fixedRegisterIndirectCertificate claim
  staticChecked := genericChecked
  outcomeChecked := by
    have rows := legacyChecked
    simp only [FixedCodePointerRegisterIndirectCallClaim.checked,
      Bool.and_eq_true, beq_iff_eq] at rows
    rcases rows with
      ⟨⟨_relationMember, originalOutcome⟩, candidateOutcome⟩
    simp [fixedRegisterIndirectCertificate,
      IndirectExitCertificate.outcomeChecked, originalOutcome,
      candidateOutcome]
  targetEvaluation := fixedRegisterTargetEvaluation context sourceInvariant
    originalBehavior candidateBehavior claim structurallyValid legacyChecked
}

def importRegisterIndirectCertificate
    (claim : ImportRegisterIndirectCallClaim) :
    IndirectExitCertificate := {
  finiteAlternativeBudget := 1
  target := {
    original := .inputReg claim.originalRegister
    candidate := .inputReg claim.candidateRegister
    source := .importAddress claim.imported
    origin := { alternatives := [.importTarget claim.imported] }
  }
  destinations := [.imported claim.imported]
  transfer := .call claim.continuationTargetId
}

theorem importRegisterTargetEvaluation
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterIndirectCallClaim)
    (checked : claim.checked sourceInvariant originalBehavior
      candidateBehavior = true) :
    (importRegisterIndirectCertificate claim).TargetEvaluation context
      sourceInvariant := by
  have closed := importRegisterIndirectCallTargetsClosed_of_checked context
    sourceInvariant originalBehavior candidateBehavior claim checked
  have checkedRows := checked
  simp only [ImportRegisterIndirectCallClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checkedRows
  intro world originalState candidateState related
  rcases closed world originalState candidateState related with
    ⟨binding, bindingMember, identity, originalOutcome, candidateOutcome⟩
  have originalValue :
      originalState.registers.get claim.originalRegister =
        binding.originalAddress := by
    rw [checkedRows.1.2] at originalOutcome
    simpa [NormalizedOutcomeExpr.eval, Expr.eval] using originalOutcome
  have candidateValue :
      candidateState.registers.get claim.candidateRegister =
        binding.candidateAddress := by
    rw [checkedRows.2] at candidateOutcome
    simpa [NormalizedOutcomeExpr.eval, Expr.eval] using candidateOutcome
  constructor
  · refine ⟨.importTarget claim.imported, ?_, binding, bindingMember, identity,
      ?_, ?_⟩
    · simp [importRegisterIndirectCertificate]
    · simpa [importRegisterIndirectCertificate, Expr.eval] using originalValue
    · simpa [importRegisterIndirectCertificate, Expr.eval] using candidateValue
  · refine ⟨.imported claim.imported, ?_, binding, bindingMember, identity,
      ?_, ?_⟩
    · simp [importRegisterIndirectCertificate]
    · simpa [importRegisterIndirectCertificate, Expr.eval] using originalValue
    · simpa [importRegisterIndirectCertificate, Expr.eval] using candidateValue

def checkedImportRegisterIndirectCertificate
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterIndirectCallClaim)
    (legacyChecked : claim.checked sourceInvariant originalBehavior
      candidateBehavior = true)
    (genericChecked :
      (importRegisterIndirectCertificate claim).checked context = true) :
    CheckedIndirectExitCertificate context sourceInvariant
      originalBehavior candidateBehavior := {
  certificate := importRegisterIndirectCertificate claim
  staticChecked := genericChecked
  outcomeChecked := by
    have rows := legacyChecked
    simp only [ImportRegisterIndirectCallClaim.checked, Bool.and_eq_true,
      beq_iff_eq] at rows
    simp [importRegisterIndirectCertificate,
      IndirectExitCertificate.outcomeChecked, rows.1.2, rows.2]
  targetEvaluation := importRegisterTargetEvaluation context sourceInvariant
    originalBehavior candidateBehavior claim legacyChecked
}

theorem importRegisterTargetEvaluation_of_closed
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterIndirectCallClaim)
    (originalOutcome :
      originalBehavior.outcome = .indirectCall (.inputReg claim.originalRegister)
        claim.continuationTargetId)
    (candidateOutcome :
      candidateBehavior.outcome = .indirectCall (.inputReg claim.candidateRegister)
        claim.continuationTargetId)
    (closed : ImportRegisterIndirectCallTargetsClosed context sourceInvariant
      originalBehavior candidateBehavior claim) :
    (importRegisterIndirectCertificate claim).TargetEvaluation context
      sourceInvariant := by
  intro world originalState candidateState related
  rcases closed world originalState candidateState related with
    ⟨binding, bindingMember, identity, originalEvaluated, candidateEvaluated⟩
  have originalValue :
      originalState.registers.get claim.originalRegister =
        binding.originalAddress := by
    rw [originalOutcome] at originalEvaluated
    simpa [NormalizedOutcomeExpr.eval, Expr.eval] using originalEvaluated
  have candidateValue :
      candidateState.registers.get claim.candidateRegister =
        binding.candidateAddress := by
    rw [candidateOutcome] at candidateEvaluated
    simpa [NormalizedOutcomeExpr.eval, Expr.eval] using candidateEvaluated
  constructor
  · refine ⟨.importTarget claim.imported, ?_, binding, bindingMember, identity,
      ?_, ?_⟩
    · simp [importRegisterIndirectCertificate]
    · simpa [importRegisterIndirectCertificate, Expr.eval] using originalValue
    · simpa [importRegisterIndirectCertificate, Expr.eval] using candidateValue
  · refine ⟨.imported claim.imported, ?_, binding, bindingMember, identity,
      ?_, ?_⟩
    · simp [importRegisterIndirectCertificate]
    · simpa [importRegisterIndirectCertificate, Expr.eval] using originalValue
    · simpa [importRegisterIndirectCertificate, Expr.eval] using candidateValue

def checkedImportRegisterIndirectCertificate_of_closed
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ImportRegisterIndirectCallClaim)
    (originalOutcome :
      originalBehavior.outcome = .indirectCall (.inputReg claim.originalRegister)
        claim.continuationTargetId)
    (candidateOutcome :
      candidateBehavior.outcome = .indirectCall (.inputReg claim.candidateRegister)
        claim.continuationTargetId)
    (closed : ImportRegisterIndirectCallTargetsClosed context sourceInvariant
      originalBehavior candidateBehavior claim)
    (genericChecked :
      (importRegisterIndirectCertificate claim).checked context = true) :
    CheckedIndirectExitCertificate context sourceInvariant
      originalBehavior candidateBehavior := {
  certificate := importRegisterIndirectCertificate claim
  staticChecked := genericChecked
  outcomeChecked := by
    simp [importRegisterIndirectCertificate,
      IndirectExitCertificate.outcomeChecked, originalOutcome,
      candidateOutcome]
  targetEvaluation := importRegisterTargetEvaluation_of_closed context
    sourceInvariant originalBehavior candidateBehavior claim originalOutcome
      candidateOutcome closed
}

def stackFixedIndirectCertificate
    (claim : StackSlotFixedCodePointerIndirectCallClaim) :
    IndirectExitCertificate := {
  finiteAlternativeBudget := 1
  target := {
    original := claim.originalTarget
    candidate := claim.candidateTarget
    source := .stackExpression claim.originalSlotAddress claim.candidateSlotAddress
    origin := { alternatives := [.staticCodeTarget claim.targetId 0] }
  }
  destinations := [.internalCode claim.targetId]
  transfer := .call claim.continuationTargetId
}

theorem stackFixedTargetEvaluation
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackSlotFixedCodePointerIndirectCallClaim)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true) :
    (stackFixedIndirectCertificate claim).TargetEvaluation context
      sourceInvariant := by
  intro world originalState candidateState related
  have evidence := claim.evidence_of_checked context world sourceInvariant
    originalBehavior candidateBehavior checked originalState candidateState related
  have checkedRows := checked
  simp only [StackSlotFixedCodePointerIndirectCallClaim.checked,
    Bool.and_eq_true] at checkedRows
  have targetRows := checkedRows.1.1.1
  simp only [StackSlotFixedCodePointerIndirectCallClaim.targetChecked,
    Bool.and_eq_true, decide_eq_true_eq] at targetRows
  rcases targetRows with
    ⟨⟨⟨⟨_originalFits, _candidateFits⟩, _targetKnown⟩,
      targetPairMatches⟩, _continuationFound⟩
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
      simp [codeTargetAddressPairMatches, targetResult] at targetPairMatches
  | some target =>
      simp only [codeTargetAddressPairMatches, targetResult, Bool.and_eq_true,
        beq_iff_eq] at targetPairMatches
      constructor
      · refine ⟨.staticCodeTarget claim.targetId 0, ?_, ?_⟩
        · simp [stackFixedIndirectCertificate]
        · refine ⟨target, targetResult, Or.inl ⟨rfl, ?_, ?_⟩⟩
          · simpa [stackFixedIndirectCertificate,
              evidence.originalTargetExact] using targetPairMatches.2.1.1
          · simpa [stackFixedIndirectCertificate,
              evidence.candidateTargetExact] using targetPairMatches.2.1.2
      · refine ⟨.internalCode claim.targetId, ?_, target, targetResult, ?_, ?_⟩
        · simp [stackFixedIndirectCertificate]
        · simpa [stackFixedIndirectCertificate,
            evidence.originalTargetExact] using targetPairMatches.2.1.1
        · simpa [stackFixedIndirectCertificate,
            evidence.candidateTargetExact] using targetPairMatches.2.1.2

def checkedStackFixedIndirectCertificate
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackSlotFixedCodePointerIndirectCallClaim)
    (legacyChecked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (genericChecked :
      (stackFixedIndirectCertificate claim).checked context = true) :
    CheckedIndirectExitCertificate context sourceInvariant
      originalBehavior candidateBehavior := {
  certificate := stackFixedIndirectCertificate claim
  staticChecked := genericChecked
  outcomeChecked := by
    have rows := legacyChecked
    simp only [StackSlotFixedCodePointerIndirectCallClaim.checked,
      Bool.and_eq_true] at rows
    have outcomes := rows.2
    simp only [StackSlotFixedCodePointerIndirectCallClaim.outcomesChecked,
      Bool.and_eq_true, beq_iff_eq] at outcomes
    simp [stackFixedIndirectCertificate,
      IndirectExitCertificate.outcomeChecked, outcomes.1, outcomes.2]
  targetEvaluation := stackFixedTargetEvaluation context sourceInvariant
    originalBehavior candidateBehavior claim legacyChecked
}

def dynamicRangeIndirectCertificate
    (context : StaticProofContext) (claim : DynamicRangeIndirectCallClaim) :
    IndirectExitCertificate := {
  finiteAlternativeBudget := context.codeMap.entries.size
  target := {
    original := claim.originalTargetExpression
    candidate := claim.candidateTargetExpression
    source := .dynamicExpression
      (.add (.inputReg claim.rangeRelation.original)
        (.constant claim.wordOffset))
      (.add (.inputReg claim.rangeRelation.candidate)
        (.constant claim.wordOffset))
    origin := {
      alternatives := context.codeMap.entries.toList.map fun target =>
        .staticCodeTarget target.id 0
    }
  }
  destinations := context.codeMap.entries.toList.map fun target =>
    .internalCode target.id
  transfer := .call claim.continuationTargetId
}

theorem dynamicRangeTargetEvaluation
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicRangeIndirectCallClaim)
    (structurallyValid : context.StructurallyValid)
    (checked : claim.checked sourceInvariant originalBehavior
      candidateBehavior = true) :
    (dynamicRangeIndirectCertificate context claim).TargetEvaluation context
      sourceInvariant := by
  have closed := dynamicRangeIndirectCallFiniteTargetsClosed_of_checked
    sourceInvariant originalBehavior candidateBehavior claim checked
  have checkedRows := checked
  simp only [DynamicRangeIndirectCallClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checkedRows
  rcases structurallyValid with
    ⟨_, _, _, _, _, _, indexedValid, _⟩
  intro world originalState candidateState related
  rcases closed context world originalState candidateState related with
    ⟨originalTarget, candidateTarget, target, originalOutcome,
      candidateOutcome, targetMember, originalMatches, candidateMatches⟩
  have targetResult :
      context.codeMap.get? target.id = some target :=
    context.codeMap.get?_eq_some_of_mem context.originalPe context.candidatePe
      indexedValid target targetMember
  have originalValue :
      claim.originalTargetExpression.eval originalState = originalTarget := by
    rw [checkedRows.1.2] at originalOutcome
    simpa [NormalizedOutcomeExpr.eval] using originalOutcome
  have candidateValue :
      claim.candidateTargetExpression.eval candidateState = candidateTarget := by
    rw [checkedRows.2] at candidateOutcome
    simpa [NormalizedOutcomeExpr.eval] using candidateOutcome
  constructor
  · refine ⟨.staticCodeTarget target.id 0, ?_, target, targetResult,
      Or.inl ⟨rfl, ?_, ?_⟩⟩
    · exact List.mem_map.mpr ⟨target, targetMember, rfl⟩
    · simpa [dynamicRangeIndirectCertificate, originalValue] using originalMatches
    · simpa [dynamicRangeIndirectCertificate, candidateValue] using candidateMatches
  · refine ⟨.internalCode target.id, ?_, target, targetResult, ?_, ?_⟩
    · exact List.mem_map.mpr ⟨target, targetMember, rfl⟩
    · simpa [dynamicRangeIndirectCertificate, originalValue] using originalMatches
    · simpa [dynamicRangeIndirectCertificate, candidateValue] using candidateMatches

def checkedDynamicRangeIndirectCertificate
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DynamicRangeIndirectCallClaim)
    (structurallyValid : context.StructurallyValid)
    (legacyChecked : claim.checked sourceInvariant originalBehavior
      candidateBehavior = true)
    (genericChecked :
      (dynamicRangeIndirectCertificate context claim).checked context = true) :
    CheckedIndirectExitCertificate context sourceInvariant
      originalBehavior candidateBehavior := {
  certificate := dynamicRangeIndirectCertificate context claim
  staticChecked := genericChecked
  outcomeChecked := by
    have rows := legacyChecked
    simp only [DynamicRangeIndirectCallClaim.checked, Bool.and_eq_true,
      beq_iff_eq] at rows
    simp [dynamicRangeIndirectCertificate,
      DynamicRangeIndirectCallClaim.originalTargetExpression,
      DynamicRangeIndirectCallClaim.candidateTargetExpression,
      IndirectExitCertificate.outcomeChecked, rows.1.2, rows.2]
  targetEvaluation := dynamicRangeTargetEvaluation context sourceInvariant
    originalBehavior candidateBehavior claim structurallyValid legacyChecked
}

end IndirectExitAdapters

end StageA.Relational
