import StageA.RelationalComposition

namespace StageA.Relational

open StageA.Formal

/-- The modular IA-32 offset represented by a stack adjustment. -/
def StackAdjustment.wordOffset : StackAdjustment -> Word
  | .identity => BitVec.ofNat 32 0
  | .add amount => BitVec.ofNat 32 amount
  | .subtract amount => (0 : Word) - BitVec.ofNat 32 amount

/-- Reuse the generic register-offset write-frame checker for stack-relative
writes.  The conversion is exact: it preserves both the symbolic address and
the modular IA-32 offset. -/
def StackAdjustment.writeWitness : StackAdjustment -> RegisterOffsetWitness
  | .identity => .input
  | .add amount => .addRight .input amount
  | .subtract amount => .subRight .input amount

@[simp] theorem StackAdjustment.writeWitness_expression
    (adjustment : StackAdjustment) (register : Reg) :
    adjustment.writeWitness.expression register = adjustment.expression register := by
  cases adjustment <;>
    simp [StackAdjustment.writeWitness, StackAdjustment.expression,
      RegisterOffsetWitness.expression]

@[simp] theorem StackAdjustment.writeWitness_offset
    (adjustment : StackAdjustment) :
    adjustment.writeWitness.offset = adjustment.wordOffset := by
  cases adjustment <;>
    simp [StackAdjustment.writeWitness, StackAdjustment.wordOffset,
      RegisterOffsetWitness.offset]

@[simp] theorem StackAdjustment.eval_expression
    (adjustment : StackAdjustment) (register : Reg) (state : MachineState) :
    (adjustment.expression register).eval state =
      state.registers.get register + adjustment.wordOffset := by
  cases adjustment <;>
    simp [StackAdjustment.expression, StackAdjustment.wordOffset, Expr.eval,
      BitVec.sub_eq_add_neg, BitVec.add_assoc]

/-- A complete per-side inventory of normalized stack-relative writes made by
the segment before its indirect-call outcome. -/
structure PairedStackDisjointWriteSet where
  original : List StackAdjustment
  candidate : List StackAdjustment
deriving Repr, DecidableEq

def PairedStackDisjointWriteSet.checked
    (writes : PairedStackDisjointWriteSet)
    (read : PairedStackRead32ValueClaim)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Bool :=
  registerOffsetWitnessesAvoidWord read.window.originalRegister
      read.adjustment.wordOffset
      (writes.original.map StackAdjustment.writeWitness)
      originalBehavior.writes &&
    registerOffsetWitnessesAvoidWord read.window.candidateRegister
      read.adjustment.wordOffset
      (writes.candidate.map StackAdjustment.writeWitness)
      candidateBehavior.writes

/-- A stack-carried fixed code pointer used by paired indirect calls.  Concrete
addresses are retained because image bases and layouts may differ. -/
structure StackSlotFixedCodePointerIndirectCallClaim where
  stackRead : PairedStackRead32ValueClaim
  targetId : Nat
  originalTargetAddress : Nat
  candidateTargetAddress : Nat
  continuationTargetId : Nat
  writes : PairedStackDisjointWriteSet := { original := [], candidate := [] }
deriving Repr, DecidableEq

def StackSlotFixedCodePointerIndirectCallClaim.originalSlotAddress
    (claim : StackSlotFixedCodePointerIndirectCallClaim) : Expr :=
  claim.stackRead.adjustment.expression claim.stackRead.window.originalRegister

def StackSlotFixedCodePointerIndirectCallClaim.candidateSlotAddress
    (claim : StackSlotFixedCodePointerIndirectCallClaim) : Expr :=
  claim.stackRead.adjustment.expression claim.stackRead.window.candidateRegister

def StackSlotFixedCodePointerIndirectCallClaim.originalTarget
    (claim : StackSlotFixedCodePointerIndirectCallClaim) : Expr :=
  .read32 claim.originalSlotAddress

def StackSlotFixedCodePointerIndirectCallClaim.candidateTarget
    (claim : StackSlotFixedCodePointerIndirectCallClaim) : Expr :=
  .read32 claim.candidateSlotAddress

/-- This predicate is source-state evidence.  It pins each stack read to the
exact concrete address selected from the same code-map target ID. -/
def StackSlotFixedCodePointerIndirectCallClaim.targetPredicate
    (claim : StackSlotFixedCodePointerIndirectCallClaim) : PairedStatePredicate := {
  original := .equal claim.originalTarget (.constant claim.originalTargetAddress)
  candidate := .equal claim.candidateTarget (.constant claim.candidateTargetAddress)
}

def StackSlotFixedCodePointerIndirectCallClaim.targetChecked
    (context : StaticProofContext)
    (claim : StackSlotFixedCodePointerIndirectCallClaim) : Bool :=
  decide (claim.originalTargetAddress < 2 ^ 32) &&
    decide (claim.candidateTargetAddress < 2 ^ 32) &&
    knownIndirectCodeTargetChecked context claim.targetId &&
    codeTargetAddressPairMatches context claim.targetId
      (BitVec.ofNat 32 claim.originalTargetAddress)
      (BitVec.ofNat 32 claim.candidateTargetAddress) &&
    (context.codeMap.get? claim.continuationTargetId).isSome

def StackSlotFixedCodePointerIndirectCallClaim.sourceChecked
    (sourceInvariant : StateInvariant)
    (claim : StackSlotFixedCodePointerIndirectCallClaim) : Bool :=
  claim.stackRead.checked sourceInvariant claim.originalTarget claim.candidateTarget &&
    sourceInvariant.predicates.contains claim.targetPredicate

def StackSlotFixedCodePointerIndirectCallClaim.outcomesChecked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackSlotFixedCodePointerIndirectCallClaim) : Bool :=
  originalBehavior.outcome ==
      .indirectCall claim.originalTarget claim.continuationTargetId &&
    candidateBehavior.outcome ==
      .indirectCall claim.candidateTarget claim.continuationTargetId

def StackSlotFixedCodePointerIndirectCallClaim.checked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackSlotFixedCodePointerIndirectCallClaim) : Bool :=
  claim.targetChecked context && claim.sourceChecked sourceInvariant &&
    claim.writes.checked claim.stackRead originalBehavior candidateBehavior &&
    claim.outcomesChecked originalBehavior candidateBehavior

/-- Semantic evidence recovered from one checked finite claim. -/
structure StackSlotFixedCodePointerIndirectCallEvidence
    (context : StaticProofContext) (world : RelationalWorld)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackSlotFixedCodePointerIndirectCallClaim)
    (original candidate : MachineState) : Prop where
  originalTargetExact :
    claim.originalTarget.eval original = BitVec.ofNat 32 claim.originalTargetAddress
  candidateTargetExact :
    claim.candidateTarget.eval candidate = BitVec.ofNat 32 claim.candidateTargetAddress
  targetsRelated :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (claim.originalTarget.eval original) (claim.candidateTarget.eval candidate) = true
  originalTargetResolved :
    resolveMappedCodeTarget false context.originalPe.imageBase
      context.codeMap.entries.toList (claim.originalTarget.eval original) =
        some claim.targetId
  candidateTargetResolved :
    resolveMappedCodeTarget true context.candidatePe.imageBase
      context.codeMap.entries.toList (claim.candidateTarget.eval candidate) =
        some claim.targetId
  continuationTargetPresent :
    (context.codeMap.get? claim.continuationTargetId).isSome = true
  originalOutcomeExact :
    (originalBehavior.eval original).outcome =
      .indirectCall (BitVec.ofNat 32 claim.originalTargetAddress)
        claim.continuationTargetId
  candidateOutcomeExact :
    (candidateBehavior.eval candidate).outcome =
      .indirectCall (BitVec.ofNat 32 claim.candidateTargetAddress)
        claim.continuationTargetId
  outcomesRelated :
    StageA.Relational.outcomesRelated context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world)
      (originalBehavior.eval original).outcome
      (candidateBehavior.eval candidate).outcome = true
  originalWritesAvoidSlot :
    WritesAvoidWord (claim.originalSlotAddress.eval original)
      (originalBehavior.eval original).writes
  candidateWritesAvoidSlot :
    WritesAvoidWord (claim.candidateSlotAddress.eval candidate)
      (candidateBehavior.eval candidate).writes

theorem StackSlotFixedCodePointerIndirectCallClaim.evidence_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackSlotFixedCodePointerIndirectCallClaim)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (original candidate : MachineState)
    (related : StateRel context world sourceInvariant original candidate) :
    StackSlotFixedCodePointerIndirectCallEvidence context world originalBehavior
      candidateBehavior claim original candidate := by
  simp only [StackSlotFixedCodePointerIndirectCallClaim.checked,
    Bool.and_eq_true] at checked
  rcases checked with
    ⟨⟨⟨targetChecked, sourceChecked⟩, writesChecked⟩, outcomesChecked⟩
  simp only [StackSlotFixedCodePointerIndirectCallClaim.sourceChecked,
    Bool.and_eq_true] at sourceChecked
  rcases sourceChecked with ⟨stackReadChecked, predicateMember⟩
  have predicateHolds := pairedStatePredicatesHold_member
    sourceInvariant.predicates claim.targetPredicate original candidate
    (List.contains_iff_mem.mp predicateMember)
    (related.predicatesHold context world sourceInvariant original candidate)
  simp only [StackSlotFixedCodePointerIndirectCallClaim.targetPredicate,
    PairedStatePredicate.holds, Bool.and_eq_true, BoolExpr.eval,
    List.all_nil, decide_eq_true_eq, Expr.eval] at predicateHolds
  rcases predicateHolds with
    ⟨⟨originalTargetExact, candidateTargetExact⟩, _exactReads⟩
  have targetsRelated := claim.stackRead.related_of_checked context world
    sourceInvariant claim.originalTarget claim.candidateTarget stackReadChecked
    original candidate related

  simp only [StackSlotFixedCodePointerIndirectCallClaim.targetChecked,
    Bool.and_eq_true, decide_eq_true_eq] at targetChecked
  rcases targetChecked with
    ⟨⟨⟨⟨_originalFits, _candidateFits⟩, targetKnown⟩,
      targetPairMatches⟩, continuationFound⟩
  cases targetResult : context.codeMap.get? claim.targetId with
  | none =>
      simp [codeTargetAddressPairMatches, targetResult] at targetPairMatches
  | some target =>
      have targetPair := targetPairMatches
      simp only [codeTargetAddressPairMatches, targetResult, Bool.and_eq_true,
        beq_iff_eq] at targetPair
      have originalAddressMatches := targetPair.2.1.1
      have candidateAddressMatches := targetPair.2.1.2
      have originalResolvedAddress := knownIndirectCodeTargetResolved context
        claim.targetId false (BitVec.ofNat 32 claim.originalTargetAddress)
        targetKnown (by simpa [targetResult] using originalAddressMatches)
      have candidateResolvedAddress := knownIndirectCodeTargetResolved context
        claim.targetId true (BitVec.ofNat 32 claim.candidateTargetAddress)
        targetKnown (by simpa [targetResult] using candidateAddressMatches)
      have targetMember : target ∈ context.codeMap.entries.toList :=
        FiniteIndex.get?_eq_some_implies_mem_toList context.codeMap.entries
          claim.targetId target targetResult
      have targetContains :
          context.codeMap.entries.toList.contains target = true :=
        List.contains_iff_mem.mpr targetMember

      simp only [StackSlotFixedCodePointerIndirectCallClaim.outcomesChecked,
        Bool.and_eq_true, beq_iff_eq] at outcomesChecked
      rcases outcomesChecked with ⟨originalOutcomeShape, candidateOutcomeShape⟩
      have originalOutcomeExact :
          (originalBehavior.eval original).outcome =
            .indirectCall (BitVec.ofNat 32 claim.originalTargetAddress)
              claim.continuationTargetId := by
        simp [NormalizedSymbolicBehavior.eval_outcome, originalOutcomeShape,
          NormalizedOutcomeExpr.eval, originalTargetExact]
      have candidateOutcomeExact :
          (candidateBehavior.eval candidate).outcome =
            .indirectCall (BitVec.ofNat 32 claim.candidateTargetAddress)
              claim.continuationTargetId := by
        simp [NormalizedSymbolicBehavior.eval_outcome, candidateOutcomeShape,
          NormalizedOutcomeExpr.eval, candidateTargetExact]
      have relatedOutcomes := knownIndirectCallOutcomesRelated context claim.targetId
        context.codeMap.entries.toList (context.relationalValueTargets world)
        (BitVec.ofNat 32 claim.originalTargetAddress)
        (BitVec.ofNat 32 claim.candidateTargetAddress)
        claim.continuationTargetId targetKnown
        (by simpa [targetResult] using targetContains)
        (by simpa [targetResult] using originalAddressMatches)
        (by simpa [targetResult] using candidateAddressMatches)

      simp only [PairedStackDisjointWriteSet.checked, Bool.and_eq_true]
          at writesChecked
      have originalWritesClosed := registerOffsetWitnessesAvoidWordClosed_of_checked
        claim.stackRead.window.originalRegister claim.stackRead.adjustment.wordOffset
        (claim.writes.original.map StackAdjustment.writeWitness)
        originalBehavior.writes writesChecked.1
      have candidateWritesClosed := registerOffsetWitnessesAvoidWordClosed_of_checked
        claim.stackRead.window.candidateRegister claim.stackRead.adjustment.wordOffset
        (claim.writes.candidate.map StackAdjustment.writeWitness)
        candidateBehavior.writes writesChecked.2
      have originalWritesAvoid := registerOffsetWitnessesAvoidWord_of_closed
        claim.stackRead.window.originalRegister claim.stackRead.adjustment.wordOffset
        (claim.writes.original.map StackAdjustment.writeWitness)
        originalBehavior.writes original originalWritesClosed
      have candidateWritesAvoid := registerOffsetWitnessesAvoidWord_of_closed
        claim.stackRead.window.candidateRegister claim.stackRead.adjustment.wordOffset
        (claim.writes.candidate.map StackAdjustment.writeWitness)
        candidateBehavior.writes candidate candidateWritesClosed

      refine {
        originalTargetExact := originalTargetExact
        candidateTargetExact := candidateTargetExact
        targetsRelated := targetsRelated
        originalTargetResolved := ?_
        candidateTargetResolved := ?_
        continuationTargetPresent := continuationFound
        originalOutcomeExact := originalOutcomeExact
        candidateOutcomeExact := candidateOutcomeExact
        outcomesRelated := ?_
        originalWritesAvoidSlot := ?_
        candidateWritesAvoidSlot := ?_
      }
      · rw [originalTargetExact]
        exact originalResolvedAddress
      · rw [candidateTargetExact]
        exact candidateResolvedAddress
      · rw [originalOutcomeExact, candidateOutcomeExact]
        exact relatedOutcomes
      · simpa [StackSlotFixedCodePointerIndirectCallClaim.originalSlotAddress]
          using originalWritesAvoid
      · simpa [StackSlotFixedCodePointerIndirectCallClaim.candidateSlotAddress]
          using candidateWritesAvoid

end StageA.Relational
