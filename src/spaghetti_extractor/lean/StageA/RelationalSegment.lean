import StageA.RelationalInvariant

namespace StageA.Relational

open StageA.Formal

inductive RelationalSegmentExit where
  | internal (targetId : Nat)
  | external (imported : ExternalTarget)
  | returned
  | fault
deriving Repr, DecidableEq

def PureOutcome.segmentExit : PureOutcome -> Option RelationalSegmentExit
  | .jump target => some (.internal target)
  | .branch condition taken fallthrough =>
      some (.internal (if condition then taken else fallthrough))
  | .call target _ => some (.internal target)
  | .externalCall imported _ _ | .externalJump imported _ =>
      some (.external imported)
  | .bulkCopy _ _ _ _ continuation | .checkedContinue true continuation |
      .atomicCompareExchange _ _ _ continuation => some (.internal continuation)
  | .returned _ => some .returned
  | .checkedContinue false _ => some .fault
  | .indirectCall _ _ | .indirectJump _ => none

def PureOutcome.segmentExitFor (context : StaticProofContext) (candidate : Bool) :
    PureOutcome -> Option RelationalSegmentExit
  | .indirectCall target _ | .indirectJump target => do
      let imageBase := if candidate then context.candidatePe.imageBase
        else context.originalPe.imageBase
      let targetId <- resolveMappedCodeTarget candidate imageBase
        context.codeMap.entries.toList target
      pure (.internal targetId)
  | outcome => outcome.segmentExit

structure RelationalSegmentEdge where
  sourceTargetId : Nat
  exit : RelationalSegmentExit
  originalSpan : Span
  candidateSpan : Span
  localCodeTargetIds : List Nat := []
  localValueTargetIds : List Nat := []
  originalGuard : BoolExpr := .equal (.constant 0) (.constant 0)
  candidateGuard : BoolExpr := .equal (.constant 0) (.constant 0)
deriving Repr, DecidableEq

def SegmentTransitionClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true →
            match evalBehavior false localCodeTargets originalState originalBehavior,
                evalBehavior true localCodeTargets candidateState candidateBehavior with
            | some originalResult, some candidateResult =>
                originalResult.outcome.segmentExitFor context false = some edge.exit ∧
                  candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
                  outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                      localCodeTargets localValues
                      originalResult.outcome candidateResult.outcome = true ∧
                  match edge.exit with
                  | .internal _ =>
                      StateRel context world targetInvariant
                        (originalResult.nextMachineState originalState)
                        (candidateResult.nextMachineState candidateState)
                  | .external _ | .returned | .fault => True
            | _, _ => False)
  | _, _ => False

def NoWriteSegmentShapeClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true →
            ∃ originalResult candidateResult,
              evalBehavior false localCodeTargets originalState originalBehavior =
                  some originalResult ∧
              evalBehavior true localCodeTargets candidateState candidateBehavior =
                  some candidateResult ∧
              originalResult.writes = [] ∧ candidateResult.writes = [] ∧
                originalResult.outcome.segmentExitFor context false = some edge.exit ∧
                candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
                outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                  localCodeTargets localValues originalResult.outcome candidateResult.outcome = true)
  | _, _ => False

def DirectCallSegmentShapeClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (sourceWindow : StackWindowPair) (stackAmount : Nat)
    (originalReturnAddress candidateReturnAddress : Word)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true →
            ∃ originalResult candidateResult,
              evalBehavior false localCodeTargets originalState originalBehavior =
                  some originalResult ∧
              evalBehavior true localCodeTargets candidateState candidateBehavior =
                  some candidateResult ∧
              originalResult.writes = [
                (originalState.registers.get sourceWindow.originalRegister -
                  BitVec.ofNat 32 stackAmount, originalReturnAddress)] ∧
              candidateResult.writes = [
                (candidateState.registers.get sourceWindow.candidateRegister -
                  BitVec.ofNat 32 stackAmount, candidateReturnAddress)] ∧
              originalResult.outcome.segmentExitFor context false = some edge.exit ∧
              candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
              outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                localCodeTargets localValues originalResult.outcome
                  candidateResult.outcome = true)
  | _, _ => False

inductive PairedStackWordValueWitness where
  | exactInputs
  | registerArgument (claim : RegisterArgumentClaim)
  | mappedCodeTarget (targetId : Nat)
  | mappedDataTarget (targetId : Nat)
  | dynamicRange (relation : DynamicRegisterRangeRelation)
deriving Repr, DecidableEq

structure PairedStackWordValueClaim where
  original : Expr
  candidate : Expr
  witness : PairedStackWordValueWitness
deriving Repr, DecidableEq

def _root_.StageA.Formal.Expr.constantNat? : Expr -> Option Nat
  | .constant value => some value
  | _ => none

theorem _root_.StageA.Formal.Expr.eval_of_constantNat?
    (expression : Expr) (value : Nat)
    (checked : expression.constantNat? = some value) (state : MachineState) :
    expression.eval state = BitVec.ofNat 32 value := by
  cases expression <;> simp_all [Expr.constantNat?, Expr.eval]

def PairedStackWordValueClaim.checked (context : StaticProofContext)
    (sourceInvariant : StateInvariant)
    (claim : PairedStackWordValueClaim) : Bool :=
  match claim.witness with
  | .exactInputs =>
      claim.original == claim.candidate &&
        claim.original.exactInputs sourceInvariant.registerRelations
  | .registerArgument registerClaim =>
      registerClaim.checked sourceInvariant claim.original claim.candidate
  | .mappedCodeTarget targetId =>
      match claim.original.constantNat?, claim.candidate.constantNat? with
      | some original, some candidate =>
          codeTargetAddressPairMatches context targetId (BitVec.ofNat 32 original)
              (BitVec.ofNat 32 candidate) &&
            ((BitVec.ofNat 32 original == BitVec.ofNat 32 0) ==
              (BitVec.ofNat 32 candidate == BitVec.ofNat 32 0))
      | _, _ => false
  | .mappedDataTarget targetId =>
      match claim.original.constantNat?, claim.candidate.constantNat? with
      | some original, some candidate =>
          dataTargetAddressPairMatches context targetId (BitVec.ofNat 32 original)
              (BitVec.ofNat 32 candidate) &&
            ((BitVec.ofNat 32 original == BitVec.ofNat 32 0) ==
              (BitVec.ofNat 32 candidate == BitVec.ofNat 32 0))
      | _, _ => false
  | .dynamicRange relation =>
      sourceInvariant.dynamicRegisterRangeRelations.contains relation &&
        relation.originalOffset == 0 && relation.candidateOffset == 0 &&
        claim.original == .inputReg relation.original &&
        claim.candidate == .inputReg relation.candidate

theorem PairedStackWordValueClaim.related_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (claim : PairedStackWordValueClaim)
    (checked : claim.checked context sourceInvariant = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (claim.original.eval originalState) (claim.candidate.eval candidateState) = true := by
  rcases claim with ⟨originalValue, candidateValue, witness⟩
  cases witness with
  | exactInputs =>
      simp only [PairedStackWordValueClaim.checked, Bool.and_eq_true,
        beq_iff_eq] at checked
      have valuesEqual := checked.1
      have safe := checked.2
      rcases related with ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
      rcases relatedCore with
        ⟨registers, _, _, _, _, _dynamicWords, undefinedValue, _, _, fsBase⟩
      have evaluationsEqual := Expr.eval_eq_of_exactInputs
        context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        sourceInvariant.registerRelations originalState candidateState originalValue
        registers undefinedValue fsBase safe
      rw [← valuesEqual]
      rw [evaluationsEqual]
      exact wordRelated_self context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world) _
  | registerArgument registerClaim =>
      exact registerArgumentWordsRelated_of_checked context world sourceInvariant
        originalValue candidateValue registerClaim checked originalState candidateState related
  | mappedCodeTarget targetId =>
      unfold PairedStackWordValueClaim.checked at checked
      cases originalResult : originalValue.constantNat? with
      | none => simp [originalResult] at checked
      | some originalWord =>
          cases candidateResult : candidateValue.constantNat? with
          | none => simp [originalResult, candidateResult] at checked
          | some candidateWord =>
              simp only [originalResult, candidateResult, Bool.and_eq_true,
                beq_iff_eq] at checked
              rw [originalValue.eval_of_constantNat? originalWord originalResult,
                candidateValue.eval_of_constantNat? candidateWord candidateResult]
              exact codeTargetIdAddresses_wordRelated context world targetId
                (BitVec.ofNat 32 originalWord) (BitVec.ofNat 32 candidateWord)
                checked.1 checked.2
  | mappedDataTarget targetId =>
      unfold PairedStackWordValueClaim.checked at checked
      cases originalResult : originalValue.constantNat? with
      | none => simp [originalResult] at checked
      | some originalWord =>
          cases candidateResult : candidateValue.constantNat? with
          | none => simp [originalResult, candidateResult] at checked
          | some candidateWord =>
              simp only [originalResult, candidateResult, Bool.and_eq_true,
                beq_iff_eq] at checked
              rw [originalValue.eval_of_constantNat? originalWord originalResult,
                candidateValue.eval_of_constantNat? candidateWord candidateResult]
              exact dataTargetIdAddresses_wordRelated context world targetId
                (BitVec.ofNat 32 originalWord) (BitVec.ofNat 32 candidateWord)
                checked.1 checked.2
  | dynamicRange relation =>
      simp only [PairedStackWordValueClaim.checked, Bool.and_eq_true,
        beq_iff_eq] at checked
      rcases checked with
        ⟨⟨⟨⟨relationMember, originalOffset⟩, candidateOffset⟩,
          originalValue⟩, candidateValue⟩
      have dynamicRanges := related.dynamicRegisterRangesHold context world
        sourceInvariant originalState candidateState
      simp only [dynamicRegisterRangeRelationsHold, List.all_eq_true]
        at dynamicRanges
      have relationHolds := dynamicRanges relation
        (List.contains_iff_mem.mp relationMember)
      rw [originalValue, candidateValue]
      simp only [Expr.eval]
      exact relation.relatedWord_of_zero_offsets context world
        originalState.registers candidateState.registers related.1 originalOffset
        candidateOffset relationHolds

def PairedStackWordValueClaim.staticRelationCompatible
    (claim : PairedStackWordValueClaim) (relation : StaticWordRelationKind) : Bool :=
  match relation, claim.witness with
  | .exact, .exactInputs => true
  | .exact, .registerArgument registerClaim =>
      registerClaim.relation.relation == .exact
  | .relatedWord, _ => true
  | .codePointer, .mappedCodeTarget _ => true
  | .fixedCodePointer targetId, .mappedCodeTarget witnessTargetId =>
      targetId == witnessTargetId
  | .dataPointer, .mappedDataTarget _ => true
  | _, _ => false

theorem PairedStackWordValueClaim.staticRelationHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (claim : PairedStackWordValueClaim)
    (relation : StaticWordRelationKind)
    (checked : claim.checked context sourceInvariant = true)
    (compatible : claim.staticRelationCompatible relation = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    relation.holds context world (claim.original.eval originalState)
      (claim.candidate.eval candidateState) = true := by
  rcases claim with ⟨originalValue, candidateValue, witness⟩
  cases relation with
  | relatedWord =>
      exact PairedStackWordValueClaim.related_of_checked context world sourceInvariant
        ⟨originalValue, candidateValue, witness⟩ checked originalState candidateState
          related
  | exact =>
      cases witness with
      | exactInputs =>
          simp only [PairedStackWordValueClaim.checked, Bool.and_eq_true,
            beq_iff_eq] at checked
          rcases related with
            ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
          rcases relatedCore with
            ⟨registers, _, _, _, _, _, undefinedValue, _, _, fsBase⟩
          have evaluationsEqual := Expr.eval_eq_of_exactInputs
            context.originalPe.imageBase context.candidatePe.imageBase
            context.codeMap.entries.toList (context.relationalValueTargets world)
            sourceInvariant.registerRelations originalState candidateState originalValue
            registers undefinedValue fsBase checked.2
          simp only [StaticWordRelationKind.holds, beq_iff_eq]
          calc
            originalValue.eval originalState = originalValue.eval candidateState :=
              evaluationsEqual
            _ = candidateValue.eval candidateState := by rw [checked.1]
      | registerArgument registerClaim =>
          simp only [PairedStackWordValueClaim.staticRelationCompatible,
            beq_iff_eq] at compatible
          have evaluationsEqual := registerArgumentWordsEqual_of_checked_exact
            context world sourceInvariant originalValue candidateValue registerClaim checked
            compatible originalState candidateState related
          simpa [StaticWordRelationKind.holds, evaluationsEqual]
      | mappedCodeTarget targetId =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | mappedDataTarget targetId =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | dynamicRange relation =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
  | codePointer =>
      cases witness with
      | exactInputs =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | registerArgument registerClaim =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | mappedCodeTarget targetId =>
          unfold PairedStackWordValueClaim.checked at checked
          cases originalResult : originalValue.constantNat? with
          | none => simp [originalResult] at checked
          | some originalWord =>
              cases candidateResult : candidateValue.constantNat? with
              | none => simp [originalResult, candidateResult] at checked
              | some candidateWord =>
                  simp only [originalResult, candidateResult, Bool.and_eq_true,
                    beq_iff_eq] at checked
                  rw [originalValue.eval_of_constantNat? originalWord originalResult,
                    candidateValue.eval_of_constantNat? candidateWord candidateResult]
                  simp only [StaticWordRelationKind.holds, Bool.or_eq_true]
                  exact Or.inr (codeTargetIdAddresses_codePointerRelated context targetId
                    (BitVec.ofNat 32 originalWord) (BitVec.ofNat 32 candidateWord)
                    checked.1)
      | mappedDataTarget targetId =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | dynamicRange relation =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
  | fixedCodePointer expectedTargetId =>
      cases witness with
      | exactInputs =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | registerArgument registerClaim =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | mappedCodeTarget targetId =>
          simp only [PairedStackWordValueClaim.staticRelationCompatible,
            beq_iff_eq] at compatible
          subst expectedTargetId
          unfold PairedStackWordValueClaim.checked at checked
          cases originalResult : originalValue.constantNat? with
          | none => simp [originalResult] at checked
          | some originalWord =>
              cases candidateResult : candidateValue.constantNat? with
              | none => simp [originalResult, candidateResult] at checked
              | some candidateWord =>
                  simp only [originalResult, candidateResult, Bool.and_eq_true,
                    beq_iff_eq] at checked
                  rw [originalValue.eval_of_constantNat? originalWord originalResult,
                    candidateValue.eval_of_constantNat? candidateWord candidateResult]
                  exact checked.1
      | mappedDataTarget targetId =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | dynamicRange relation =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
  | dataPointer =>
      cases witness with
      | exactInputs =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | registerArgument registerClaim =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | mappedCodeTarget targetId =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | mappedDataTarget targetId =>
          unfold PairedStackWordValueClaim.checked at checked
          cases originalResult : originalValue.constantNat? with
          | none => simp [originalResult] at checked
          | some originalWord =>
              cases candidateResult : candidateValue.constantNat? with
              | none => simp [originalResult, candidateResult] at checked
              | some candidateWord =>
                  simp only [originalResult, candidateResult, Bool.and_eq_true,
                    beq_iff_eq] at checked
                  rw [originalValue.eval_of_constantNat? originalWord originalResult,
                    candidateValue.eval_of_constantNat? candidateWord candidateResult]
                  simp only [StaticWordRelationKind.holds, Bool.or_eq_true]
                  exact Or.inr (dataTargetIdAddresses_mappedValueRelated context world
                    targetId (BitVec.ofNat 32 originalWord)
                    (BitVec.ofNat 32 candidateWord) checked.1)
      | dynamicRange relation =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible

def PairedStackWordValueClaim.dynamicRelationCompatible
    (claim : PairedStackWordValueClaim) (relation : DynamicWordRelationKind) : Bool :=
  match relation, claim.witness with
  | .relatedWord, _ => true
  | .codePointer, .mappedCodeTarget _ => true
  | .dataPointer, .mappedDataTarget _ => true
  | _, _ => false

theorem PairedStackWordValueClaim.dynamicRelationHolds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (claim : PairedStackWordValueClaim)
    (owner : DynamicAddressRangePair) (relation : DynamicWordRelationKind)
    (checked : claim.checked context sourceInvariant = true)
    (compatible : claim.dynamicRelationCompatible relation = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    relation.valuesHold context world owner (claim.original.eval originalState)
      (claim.candidate.eval candidateState) = true := by
  rcases claim with ⟨originalValue, candidateValue, witness⟩
  cases relation with
  | relatedWord =>
      exact PairedStackWordValueClaim.related_of_checked context world sourceInvariant
        ⟨originalValue, candidateValue, witness⟩ checked originalState candidateState
          related
  | codePointer =>
      cases witness with
      | exactInputs =>
          simp [PairedStackWordValueClaim.dynamicRelationCompatible] at compatible
      | registerArgument registerClaim =>
          simp [PairedStackWordValueClaim.dynamicRelationCompatible] at compatible
      | mappedCodeTarget targetId =>
          unfold PairedStackWordValueClaim.checked at checked
          cases originalResult : originalValue.constantNat? with
          | none => simp [originalResult] at checked
          | some originalWord =>
              cases candidateResult : candidateValue.constantNat? with
              | none => simp [originalResult, candidateResult] at checked
              | some candidateWord =>
                  simp only [originalResult, candidateResult, Bool.and_eq_true,
                    beq_iff_eq] at checked
                  rw [originalValue.eval_of_constantNat? originalWord originalResult,
                    candidateValue.eval_of_constantNat? candidateWord candidateResult]
                  exact codeTargetIdAddresses_codePointerRelated context targetId
                    (BitVec.ofNat 32 originalWord) (BitVec.ofNat 32 candidateWord)
                    checked.1
      | mappedDataTarget targetId =>
          simp [PairedStackWordValueClaim.dynamicRelationCompatible] at compatible
      | dynamicRange dynamicRelation =>
          simp [PairedStackWordValueClaim.dynamicRelationCompatible] at compatible
  | dataPointer =>
      cases witness with
      | exactInputs =>
          simp [PairedStackWordValueClaim.dynamicRelationCompatible] at compatible
      | registerArgument registerClaim =>
          simp [PairedStackWordValueClaim.dynamicRelationCompatible] at compatible
      | mappedCodeTarget targetId =>
          simp [PairedStackWordValueClaim.dynamicRelationCompatible] at compatible
      | mappedDataTarget targetId =>
          unfold PairedStackWordValueClaim.checked at checked
          cases originalResult : originalValue.constantNat? with
          | none => simp [originalResult] at checked
          | some originalWord =>
              cases candidateResult : candidateValue.constantNat? with
              | none => simp [originalResult, candidateResult] at checked
              | some candidateWord =>
                  simp only [originalResult, candidateResult, Bool.and_eq_true,
                    beq_iff_eq] at checked
                  rw [originalValue.eval_of_constantNat? originalWord originalResult,
                    candidateValue.eval_of_constantNat? candidateWord candidateResult]
                  exact dataTargetIdAddresses_mappedValueRelated context world targetId
                    (BitVec.ofNat 32 originalWord) (BitVec.ofNat 32 candidateWord)
                    checked.1
      | dynamicRange dynamicRelation =>
          simp [PairedStackWordValueClaim.dynamicRelationCompatible] at compatible
  | nullableDynamicPointer =>
      cases witness <;>
        simp [PairedStackWordValueClaim.dynamicRelationCompatible] at compatible

structure PairedStackWordWriteClaim where
  window : StackWindowPair
  amount : Nat
  value : PairedStackWordValueClaim
deriving Repr, DecidableEq

def PairedStackWordWriteClaim.originalAddress
    (claim : PairedStackWordWriteClaim) : Expr :=
  .add (.inputReg claim.window.originalRegister) (.constant claim.amount)

def PairedStackWordWriteClaim.candidateAddress
    (claim : PairedStackWordWriteClaim) : Expr :=
  .add (.inputReg claim.window.candidateRegister) (.constant claim.amount)

def PairedStackWordWriteClaim.checked (context : StaticProofContext)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : PairedStackWordWriteClaim) : Bool :=
  claim.amount % 4 == 0 &&
    claim.amount + 4 <= claim.window.bytesAbove &&
    originalBehavior.writes == [(claim.originalAddress, claim.value.original)] &&
    candidateBehavior.writes == [(claim.candidateAddress, claim.value.candidate)] &&
    claim.value.checked context sourceInvariant

def PairedStackWordWriteSegmentShapeClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (claim : PairedStackWordWriteClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true →
            ∃ originalResult candidateResult,
              evalBehavior false localCodeTargets originalState originalBehavior =
                  some originalResult ∧
              evalBehavior true localCodeTargets candidateState candidateBehavior =
                  some candidateResult ∧
              originalResult.writes = [
                (claim.originalAddress.eval originalState,
                  claim.value.original.eval originalState)] ∧
              candidateResult.writes = [
                (claim.candidateAddress.eval candidateState,
                  claim.value.candidate.eval candidateState)] ∧
              originalResult.outcome.segmentExitFor context false = some edge.exit ∧
              candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
              outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                localCodeTargets localValues originalResult.outcome
                  candidateResult.outcome = true)
  | _, _ => False

structure DynamicStackRangeSpillClaim where
  sourceRelation : DynamicRegisterRangeRelation
  targetRelation : DynamicStackRangeRelation
deriving Repr, DecidableEq

def DynamicStackRangeSpillClaim.checked
    (sourceInvariant targetInvariant : StateInvariant)
    (writeClaim : PairedStackWordWriteClaim)
    (claim : DynamicStackRangeSpillClaim) : Bool :=
  sourceInvariant.dynamicRegisterRangeRelations.contains claim.sourceRelation &&
    sourceInvariant.stackWindows.contains writeClaim.window &&
    targetInvariant.dynamicStackRangeRelations.contains claim.targetRelation &&
    targetInvariant.stackWindows.contains claim.targetRelation.window &&
    claim.targetRelation.window == writeClaim.window &&
    claim.targetRelation.stackOffset == writeClaim.amount &&
    claim.targetRelation.originalOffset == claim.sourceRelation.originalOffset &&
    claim.targetRelation.candidateOffset == claim.sourceRelation.candidateOffset &&
    claim.targetRelation.requiredWords.all claim.sourceRelation.requiredWords.contains &&
    claim.targetRelation.activeWords.all claim.sourceRelation.activeWords.contains &&
    claim.targetRelation.activeWords.all claim.targetRelation.requiredWords.contains &&
    writeClaim.value.original == .inputReg claim.sourceRelation.original &&
    writeClaim.value.candidate == .inputReg claim.sourceRelation.candidate

def PairedStackWordWriteOutputBasePreserved
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (writeClaim : PairedStackWordWriteClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds with
  | some localCodeTargets =>
      ∀ originalState candidateState originalResult candidateResult,
        evalBehavior false localCodeTargets originalState originalBehavior =
            some originalResult →
        evalBehavior true localCodeTargets candidateState candidateBehavior =
            some candidateResult →
        originalResult.registers.get writeClaim.window.originalRegister =
            originalState.registers.get writeClaim.window.originalRegister ∧
          candidateResult.registers.get writeClaim.window.candidateRegister =
            candidateState.registers.get writeClaim.window.candidateRegister
  | none => False

theorem PairedStackWordWriteClaim.valueRelated_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : PairedStackWordWriteClaim)
    (checked : claim.checked context sourceInvariant originalBehavior candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (claim.value.original.eval originalState)
      (claim.value.candidate.eval candidateState) = true := by
  simp only [PairedStackWordWriteClaim.checked, Bool.and_eq_true,
    beq_iff_eq, decide_eq_true_eq] at checked
  exact claim.value.related_of_checked context world sourceInvariant checked.2
    originalState candidateState related

def pairedStackWordAddress (register : Reg) (amount : Nat) : Expr :=
  if amount = 0 then .inputReg register
  else .add (.inputReg register) (.constant amount)

def pairedDynamicWordAddress (register : Reg) (amount : Nat) : Expr :=
  if amount = 0 then .inputReg register
  else .add (.inputReg register) (.constant amount)

theorem pairedStackWordAddress_eval (register : Reg) (amount : Nat)
    (state : MachineState) :
    (pairedStackWordAddress register amount).eval state =
      state.registers.get register + BitVec.ofNat 32 amount := by
  by_cases zero : amount = 0
  · subst amount
    simp [pairedStackWordAddress, Expr.eval]
  · simp [pairedStackWordAddress, zero, Expr.eval]

theorem pairedDynamicWordAddress_eval (register : Reg) (amount : Nat)
    (state : MachineState) :
    (pairedDynamicWordAddress register amount).eval state =
      state.registers.get register + BitVec.ofNat 32 amount := by
  by_cases zero : amount = 0
  · subst amount
    simp [pairedDynamicWordAddress, Expr.eval]
  · simp [pairedDynamicWordAddress, zero, Expr.eval]

structure PairedStackWordWriteItem where
  amount : Nat
  value : PairedStackWordValueClaim
deriving Repr, DecidableEq

def PairedStackWordWriteItem.originalAddress (window : StackWindowPair)
    (item : PairedStackWordWriteItem) : Expr :=
  pairedStackWordAddress window.originalRegister item.amount

def PairedStackWordWriteItem.candidateAddress (window : StackWindowPair)
    (item : PairedStackWordWriteItem) : Expr :=
  pairedStackWordAddress window.candidateRegister item.amount

def PairedStackWordWriteItem.checked (context : StaticProofContext)
    (sourceInvariant : StateInvariant)
    (window : StackWindowPair) (item : PairedStackWordWriteItem) : Bool :=
  item.amount % 4 == 0 &&
    item.amount + 4 <= window.bytesAbove &&
    item.value.checked context sourceInvariant

structure PairedStackWordWritesClaim where
  window : StackWindowPair
  writes : List PairedStackWordWriteItem
deriving Repr, DecidableEq

def PairedStackWordWritesClaim.originalSymbolicWrites
    (claim : PairedStackWordWritesClaim) : List (Expr × Expr) :=
  claim.writes.map fun item =>
    (item.originalAddress claim.window, item.value.original)

def PairedStackWordWritesClaim.candidateSymbolicWrites
    (claim : PairedStackWordWritesClaim) : List (Expr × Expr) :=
  claim.writes.map fun item =>
    (item.candidateAddress claim.window, item.value.candidate)

def PairedStackWordWritesClaim.originalWrites
    (claim : PairedStackWordWritesClaim) (state : MachineState) : List (Word × Word) :=
  claim.writes.map fun item =>
    ((item.originalAddress claim.window).eval state, item.value.original.eval state)

def PairedStackWordWritesClaim.candidateWrites
    (claim : PairedStackWordWritesClaim) (state : MachineState) : List (Word × Word) :=
  claim.writes.map fun item =>
    ((item.candidateAddress claim.window).eval state, item.value.candidate.eval state)

def PairedStackWordWritesClaim.checked (context : StaticProofContext)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : PairedStackWordWritesClaim) : Bool :=
  !claim.writes.isEmpty &&
    claim.writes.all
      (PairedStackWordWriteItem.checked context sourceInvariant claim.window) &&
    originalBehavior.writes == claim.originalSymbolicWrites &&
    candidateBehavior.writes == claim.candidateSymbolicWrites

def PairedStackWordWritesSegmentShapeClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (claim : PairedStackWordWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true →
            ∃ originalResult candidateResult,
              evalBehavior false localCodeTargets originalState originalBehavior =
                  some originalResult ∧
              evalBehavior true localCodeTargets candidateState candidateBehavior =
                  some candidateResult ∧
              originalResult.writes = claim.originalWrites originalState ∧
              candidateResult.writes = claim.candidateWrites candidateState ∧
              originalResult.outcome.segmentExitFor context false = some edge.exit ∧
              candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
              outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                localCodeTargets localValues originalResult.outcome
                  candidateResult.outcome = true)
  | _, _ => False

def StaticProofContext.staticWordRelationSlotById
    (context : StaticProofContext) (slotId : Nat) : Option StaticWordRelationSlotPair :=
  context.staticWordRelationSlots.find? fun slot => slot.id == slotId

def StaticProofContext.staticDynamicPointerSlotById
    (context : StaticProofContext) (slotId : Nat) : Option StaticDynamicPointerSlotPair :=
  context.staticDynamicPointerSlots.find? fun slot => slot.id == slotId

inductive PairedPreparedWordWriteItem where
  | stack (window : StackWindowPair) (amount : Nat)
      (value : PairedStackWordValueClaim)
  | staticWord (slotId originalAddress candidateAddress : Nat)
      (value : PairedStackWordValueClaim)
  | dynamicWord (sourceRelation : DynamicRegisterRangeRelation)
      (relation : DynamicWordRelation) (originalAmount candidateAmount : Nat)
      (value : PairedStackWordValueClaim)
  | staticDynamicPointer (slotId originalAddress candidateAddress : Nat)
      (sourceRelation : DynamicRegisterRangeRelation)
      (value : PairedStackWordValueClaim)
deriving Repr, DecidableEq

def PairedPreparedWordWriteItem.kind :
    PairedPreparedWordWriteItem -> PreparedWordWriteKind
  | .stack _ _ _ => .stack
  | .staticWord _ _ _ _ => .staticWord
  | .dynamicWord _ _ _ _ _ => .dynamicWord
  | .staticDynamicPointer _ _ _ _ _ => .staticDynamicPointer

def PairedPreparedWordWriteItem.originalAddress :
    PairedPreparedWordWriteItem -> Expr
  | .stack window amount _ => pairedStackWordAddress window.originalRegister amount
  | .staticWord _ originalAddress _ _ => .constant originalAddress
  | .dynamicWord source _ originalAmount _ _ =>
      pairedDynamicWordAddress source.original originalAmount
  | .staticDynamicPointer _ originalAddress _ _ _ => .constant originalAddress

def PairedPreparedWordWriteItem.candidateAddress :
    PairedPreparedWordWriteItem -> Expr
  | .stack window amount _ => pairedStackWordAddress window.candidateRegister amount
  | .staticWord _ _ candidateAddress _ => .constant candidateAddress
  | .dynamicWord source _ _ candidateAmount _ =>
      pairedDynamicWordAddress source.candidate candidateAmount
  | .staticDynamicPointer _ _ candidateAddress _ _ => .constant candidateAddress

def PairedPreparedWordWriteItem.value :
    PairedPreparedWordWriteItem -> PairedStackWordValueClaim
  | .stack _ _ value | .staticWord _ _ _ value |
      .dynamicWord _ _ _ _ value | .staticDynamicPointer _ _ _ _ value => value

def PairedPreparedWordWriteItem.checked (context : StaticProofContext)
    (sourceInvariant : StateInvariant) : PairedPreparedWordWriteItem -> Bool
  | .stack window amount value =>
      sourceInvariant.stackWindows.contains window &&
        amount % 4 == 0 && amount + 4 <= window.bytesAbove &&
        value.checked context sourceInvariant
  | .staticWord slotId originalAddress candidateAddress value =>
      match context.staticWordRelationSlotById slotId with
      | none => false
      | some slot =>
          slot.originalAddress == BitVec.ofNat 32 originalAddress &&
            slot.candidateAddress == BitVec.ofNat 32 candidateAddress &&
            value.checked context sourceInvariant &&
            value.staticRelationCompatible slot.relation
  | .dynamicWord source relation originalAmount candidateAmount value =>
      sourceInvariant.dynamicRegisterRangeRelations.contains source &&
        source.requiredWords.contains relation &&
        source.originalOffset + originalAmount == relation.offset &&
        source.candidateOffset + candidateAmount == relation.offset &&
        value.checked context sourceInvariant &&
        value.dynamicRelationCompatible relation.kind
  | .staticDynamicPointer slotId originalAddress candidateAddress source value =>
      match context.staticDynamicPointerSlotById slotId with
      | none => false
      | some slot =>
          slot.originalAddress == BitVec.ofNat 32 originalAddress &&
            slot.candidateAddress == BitVec.ofNat 32 candidateAddress &&
            sourceInvariant.dynamicRegisterRangeRelations.contains source &&
            source.originalOffset == 0 && source.candidateOffset == 0 &&
            slot.requiredWords.all source.requiredWords.contains &&
            value == {
              original := .inputReg source.original
              candidate := .inputReg source.candidate
              witness := .dynamicRange source
            } && value.checked context sourceInvariant

structure PairedPreparedWordWritesClaim where
  writes : List PairedPreparedWordWriteItem
deriving Repr, DecidableEq

def PairedPreparedWordWritesClaim.originalSymbolicWrites
    (claim : PairedPreparedWordWritesClaim) : List (Expr × Expr) :=
  claim.writes.map fun item => (item.originalAddress, item.value.original)

def PairedPreparedWordWritesClaim.candidateSymbolicWrites
    (claim : PairedPreparedWordWritesClaim) : List (Expr × Expr) :=
  claim.writes.map fun item => (item.candidateAddress, item.value.candidate)

def PairedPreparedWordWritesClaim.originalWrites
    (claim : PairedPreparedWordWritesClaim) (state : MachineState) :
    List (Word × Word) :=
  claim.writes.map fun item =>
    (item.originalAddress.eval state, item.value.original.eval state)

def PairedPreparedWordWritesClaim.candidateWrites
    (claim : PairedPreparedWordWritesClaim) (state : MachineState) :
    List (Word × Word) :=
  claim.writes.map fun item =>
    (item.candidateAddress.eval state, item.value.candidate.eval state)

def PairedPreparedWordWritesClaim.checked (context : StaticProofContext)
    (sourceInvariant : StateInvariant) (claim : PairedPreparedWordWritesClaim) : Bool :=
  !claim.writes.isEmpty &&
    claim.writes.all (PairedPreparedWordWriteItem.checked context sourceInvariant)

structure PreparedDynamicStackRangeSpillClaim where
  sourceRelation : DynamicRegisterRangeRelation
  targetRelation : DynamicStackRangeRelation
  window : StackWindowPair
  amount : Nat
  suffix : List PairedPreparedWordWriteItem
deriving Repr, DecidableEq

def PreparedDynamicStackRangeSpillClaim.value
    (claim : PreparedDynamicStackRangeSpillClaim) : PairedStackWordValueClaim := {
  original := .inputReg claim.sourceRelation.original
  candidate := .inputReg claim.sourceRelation.candidate
  witness := .dynamicRange claim.sourceRelation
}

def PreparedDynamicStackRangeSpillClaim.item
    (claim : PreparedDynamicStackRangeSpillClaim) : PairedPreparedWordWriteItem :=
  .stack claim.window claim.amount claim.value

def PreparedDynamicStackRangeSpillClaim.checked
    (sourceInvariant targetInvariant : StateInvariant)
    (writesClaim : PairedPreparedWordWritesClaim)
    (claim : PreparedDynamicStackRangeSpillClaim) : Bool :=
  writesClaim.writes == claim.item :: claim.suffix &&
    claim.suffix.all (fun item => item.kind != .stack) &&
    sourceInvariant.dynamicRegisterRangeRelations.contains claim.sourceRelation &&
    sourceInvariant.stackWindows.contains claim.window &&
    targetInvariant.dynamicStackRangeRelations.contains claim.targetRelation &&
    targetInvariant.stackWindows.contains claim.targetRelation.window &&
    claim.targetRelation.window == claim.window &&
    claim.targetRelation.stackOffset == claim.amount &&
    claim.targetRelation.originalOffset == claim.sourceRelation.originalOffset &&
    claim.targetRelation.candidateOffset == claim.sourceRelation.candidateOffset &&
    claim.targetRelation.requiredWords.all claim.sourceRelation.requiredWords.contains &&
    claim.targetRelation.activeWords.all claim.sourceRelation.activeWords.contains &&
    claim.targetRelation.activeWords.all claim.targetRelation.requiredWords.contains

def PairedPreparedWordWritesOutputBasePreserved
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (spillClaim : PreparedDynamicStackRangeSpillClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds with
  | some localCodeTargets =>
      ∀ originalState candidateState originalResult candidateResult,
        evalBehavior false localCodeTargets originalState originalBehavior =
            some originalResult →
        evalBehavior true localCodeTargets candidateState candidateBehavior =
            some candidateResult →
        originalResult.registers.get spillClaim.window.originalRegister =
            originalState.registers.get spillClaim.window.originalRegister ∧
          candidateResult.registers.get spillClaim.window.candidateRegister =
            candidateState.registers.get spillClaim.window.candidateRegister
  | none => False

def PairedPreparedWordWritesSegmentShapeClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (claim : PairedPreparedWordWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true →
            ∃ originalResult candidateResult,
              evalBehavior false localCodeTargets originalState originalBehavior =
                  some originalResult ∧
              evalBehavior true localCodeTargets candidateState candidateBehavior =
                  some candidateResult ∧
              originalResult.writes = claim.originalWrites originalState ∧
              candidateResult.writes = claim.candidateWrites candidateState ∧
              originalResult.outcome.segmentExitFor context false = some edge.exit ∧
              candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
              outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                localCodeTargets localValues originalResult.outcome
                  candidateResult.outcome = true)
  | _, _ => False

structure DirectCallPreparedWritesClaim where
  preparedWrites : PairedPreparedWordWritesClaim
  returnWindow : StackWindowPair
  stackAmount : Nat
  calleeTargetId : Nat
  continuationTargetId : Nat
  originalReturnAddress : Nat
  candidateReturnAddress : Nat
deriving Repr, DecidableEq

def DirectCallPreparedWritesClaim.originalPushAddress
    (claim : DirectCallPreparedWritesClaim) : Expr :=
  .add (.inputReg claim.returnWindow.originalRegister)
    (.constant (2 ^ 32 - claim.stackAmount))

def DirectCallPreparedWritesClaim.candidatePushAddress
    (claim : DirectCallPreparedWritesClaim) : Expr :=
  .add (.inputReg claim.returnWindow.candidateRegister)
    (.constant (2 ^ 32 - claim.stackAmount))

def DirectCallPreparedWritesClaim.originalSymbolicWrites
    (claim : DirectCallPreparedWritesClaim) : List (Expr × Expr) :=
  claim.preparedWrites.originalSymbolicWrites ++ [
    (claim.originalPushAddress, .constant claim.originalReturnAddress)]

def DirectCallPreparedWritesClaim.candidateSymbolicWrites
    (claim : DirectCallPreparedWritesClaim) : List (Expr × Expr) :=
  claim.preparedWrites.candidateSymbolicWrites ++ [
    (claim.candidatePushAddress, .constant claim.candidateReturnAddress)]

def DirectCallPreparedWritesClaim.originalWrites
    (claim : DirectCallPreparedWritesClaim) (state : MachineState) :
    List (Word × Word) :=
  claim.preparedWrites.originalWrites state ++ [
    (claim.originalPushAddress.eval state,
      BitVec.ofNat 32 claim.originalReturnAddress)]

def DirectCallPreparedWritesClaim.candidateWrites
    (claim : DirectCallPreparedWritesClaim) (state : MachineState) :
    List (Word × Word) :=
  claim.preparedWrites.candidateWrites state ++ [
    (claim.candidatePushAddress.eval state,
      BitVec.ofNat 32 claim.candidateReturnAddress)]

def DirectCallPreparedWritesClaim.frameChecked (context : StaticProofContext)
    (sourceInvariant : StateInvariant) (claim : DirectCallPreparedWritesClaim) : Bool :=
  sourceInvariant.stackWindows.contains claim.returnWindow &&
    4 <= claim.stackAmount && claim.stackAmount % 4 == 0 &&
    claim.stackAmount < 2 ^ 32 &&
    claim.stackAmount <= claim.returnWindow.bytesBelow &&
    (context.codeMap.get? claim.calleeTargetId).isSome &&
    codeTargetAddressPairMatches context claim.continuationTargetId
      (BitVec.ofNat 32 claim.originalReturnAddress)
      (BitVec.ofNat 32 claim.candidateReturnAddress) &&
    ((BitVec.ofNat 32 claim.originalReturnAddress == BitVec.ofNat 32 0) ==
      (BitVec.ofNat 32 claim.candidateReturnAddress == BitVec.ofNat 32 0))

def DirectCallPreparedWritesClaim.behaviorChecked
    (claim : DirectCallPreparedWritesClaim)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Bool :=
  originalBehavior.outcome ==
      .call claim.calleeTargetId claim.continuationTargetId &&
    candidateBehavior.outcome ==
      .call claim.calleeTargetId claim.continuationTargetId &&
    originalBehavior.registers.esp == claim.originalPushAddress &&
    candidateBehavior.registers.esp == claim.candidatePushAddress &&
    originalBehavior.writes == claim.originalSymbolicWrites &&
    candidateBehavior.writes == claim.candidateSymbolicWrites

def DirectCallPreparedWritesClaim.checked (context : StaticProofContext)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DirectCallPreparedWritesClaim) : Bool :=
  claim.preparedWrites.checked context sourceInvariant &&
    claim.frameChecked context sourceInvariant &&
    claim.behaviorChecked originalBehavior candidateBehavior

def DirectCallPreparedWritesSegmentShapeClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (claim : DirectCallPreparedWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true →
            ∃ originalResult candidateResult,
              evalBehavior false localCodeTargets originalState originalBehavior =
                  some originalResult ∧
              evalBehavior true localCodeTargets candidateState candidateBehavior =
                  some candidateResult ∧
              originalResult.writes = claim.originalWrites originalState ∧
              candidateResult.writes = claim.candidateWrites candidateState ∧
              originalResult.outcome.segmentExitFor context false = some edge.exit ∧
              candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
              outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                localCodeTargets localValues originalResult.outcome
                  candidateResult.outcome = true)
  | _, _ => False

structure DirectCallStackWritesClaim where
  stackWrites : PairedStackWordWritesClaim
  stackAmount : Nat
  calleeTargetId : Nat
  continuationTargetId : Nat
  originalReturnAddress : Nat
  candidateReturnAddress : Nat
deriving Repr, DecidableEq

def DirectCallStackWritesClaim.originalPushAddress
    (claim : DirectCallStackWritesClaim) : Expr :=
  .add (.inputReg claim.stackWrites.window.originalRegister)
    (.constant (2 ^ 32 - claim.stackAmount))

def DirectCallStackWritesClaim.candidatePushAddress
    (claim : DirectCallStackWritesClaim) : Expr :=
  .add (.inputReg claim.stackWrites.window.candidateRegister)
    (.constant (2 ^ 32 - claim.stackAmount))

def DirectCallStackWritesClaim.originalSymbolicWrites
    (claim : DirectCallStackWritesClaim) : List (Expr × Expr) :=
  claim.stackWrites.originalSymbolicWrites ++ [
    (claim.originalPushAddress, .constant claim.originalReturnAddress)]

def DirectCallStackWritesClaim.candidateSymbolicWrites
    (claim : DirectCallStackWritesClaim) : List (Expr × Expr) :=
  claim.stackWrites.candidateSymbolicWrites ++ [
    (claim.candidatePushAddress, .constant claim.candidateReturnAddress)]

def DirectCallStackWritesClaim.originalWrites
    (claim : DirectCallStackWritesClaim) (state : MachineState) :
    List (Word × Word) :=
  claim.stackWrites.originalWrites state ++ [
    (claim.originalPushAddress.eval state,
      BitVec.ofNat 32 claim.originalReturnAddress)]

def DirectCallStackWritesClaim.candidateWrites
    (claim : DirectCallStackWritesClaim) (state : MachineState) :
    List (Word × Word) :=
  claim.stackWrites.candidateWrites state ++ [
    (claim.candidatePushAddress.eval state,
      BitVec.ofNat 32 claim.candidateReturnAddress)]

def DirectCallStackWritesClaim.preparedWritesChecked
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (claim : DirectCallStackWritesClaim) : Bool :=
  !claim.stackWrites.writes.isEmpty &&
    claim.stackWrites.writes.all
      (PairedStackWordWriteItem.checked context sourceInvariant
        claim.stackWrites.window)

def DirectCallStackWritesClaim.frameChecked (context : StaticProofContext)
    (claim : DirectCallStackWritesClaim) : Bool :=
  4 <= claim.stackAmount && claim.stackAmount % 4 == 0 &&
    claim.stackAmount < 2 ^ 32 &&
    claim.stackAmount <= claim.stackWrites.window.bytesBelow &&
    (context.codeMap.get? claim.calleeTargetId).isSome &&
    codeTargetAddressPairMatches context claim.continuationTargetId
      (BitVec.ofNat 32 claim.originalReturnAddress)
      (BitVec.ofNat 32 claim.candidateReturnAddress) &&
    ((BitVec.ofNat 32 claim.originalReturnAddress == BitVec.ofNat 32 0) ==
      (BitVec.ofNat 32 claim.candidateReturnAddress == BitVec.ofNat 32 0))

def DirectCallStackWritesClaim.behaviorChecked
    (claim : DirectCallStackWritesClaim)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Bool :=
  originalBehavior.outcome ==
      .call claim.calleeTargetId claim.continuationTargetId &&
    candidateBehavior.outcome ==
      .call claim.calleeTargetId claim.continuationTargetId &&
    originalBehavior.registers.esp == claim.originalPushAddress &&
    candidateBehavior.registers.esp == claim.candidatePushAddress &&
    originalBehavior.writes == claim.originalSymbolicWrites &&
    candidateBehavior.writes == claim.candidateSymbolicWrites

def DirectCallStackWritesClaim.checked (context : StaticProofContext)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : DirectCallStackWritesClaim) : Bool :=
  claim.preparedWritesChecked context sourceInvariant &&
    claim.frameChecked context &&
    claim.behaviorChecked originalBehavior candidateBehavior

def DirectCallStackWritesSegmentShapeClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (claim : DirectCallStackWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true →
            ∃ originalResult candidateResult,
              evalBehavior false localCodeTargets originalState originalBehavior =
                  some originalResult ∧
              evalBehavior true localCodeTargets candidateState candidateBehavior =
                  some candidateResult ∧
              originalResult.writes = claim.originalWrites originalState ∧
              candidateResult.writes = claim.candidateWrites candidateState ∧
              originalResult.outcome.segmentExitFor context false = some edge.exit ∧
              candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
              outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                localCodeTargets localValues originalResult.outcome
                  candidateResult.outcome = true)
  | _, _ => False

theorem DirectCallStackWritesClaim.returnAddressesRelated_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (claim : DirectCallStackWritesClaim)
    (checked : claim.frameChecked context = true) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (BitVec.ofNat 32 claim.originalReturnAddress)
      (BitVec.ofNat 32 claim.candidateReturnAddress) = true := by
  simp only [DirectCallStackWritesClaim.frameChecked, Bool.and_eq_true,
    decide_eq_true_eq, beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨_stackAtLeast, _stackAligned⟩, _stackFits⟩, _enoughBelow⟩,
      _calleePresent⟩, continuationPair⟩, zeroAgreement⟩
  exact codeTargetIdAddresses_wordRelated context world claim.continuationTargetId
    (BitVec.ofNat 32 claim.originalReturnAddress)
    (BitVec.ofNat 32 claim.candidateReturnAddress) continuationPair zeroAgreement

theorem PairedStackWordWriteItem.valueRelated_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (window : StackWindowPair)
    (item : PairedStackWordWriteItem)
    (checked : item.checked context sourceInvariant window = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (item.value.original.eval originalState)
      (item.value.candidate.eval candidateState) = true := by
  simp only [PairedStackWordWriteItem.checked, Bool.and_eq_true,
    decide_eq_true_eq] at checked
  exact item.value.related_of_checked context world sourceInvariant checked.2
    originalState candidateState related

theorem pairedStackWordUpdates_of_checkedItems
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (window : StackWindowPair)
    (items : List PairedStackWordWriteItem)
    (originalState candidateState : MachineState)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world originalState.registers
      candidateState.registers = true)
    (itemsChecked :
      items.all (PairedStackWordWriteItem.checked context sourceInvariant window) = true)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    ∃ updates : List (PairedStackWordUpdate context world),
      updates.map PairedStackWordUpdate.originalWrite =
          items.map (fun item =>
            ((item.originalAddress window).eval originalState,
              item.value.original.eval originalState)) ∧
        updates.map PairedStackWordUpdate.candidateWrite =
          items.map (fun item =>
            ((item.candidateAddress window).eval candidateState,
              item.value.candidate.eval candidateState)) := by
  induction items with
  | nil => exact ⟨[], rfl, rfl⟩
  | cons item rest induction =>
      simp only [List.all_cons, Bool.and_eq_true] at itemsChecked
      have itemChecked := itemsChecked.1
      have itemCheckedForValue := itemChecked
      have restChecked := itemsChecked.2
      simp only [PairedStackWordWriteItem.checked, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at itemChecked
      have amountAligned := itemChecked.1.1
      have enoughAbove := itemChecked.1.2
      rcases pairedStackWordLocation_above_window context world window
          originalState.registers candidateState.registers rangesValid windowHolds
          item.amount amountAligned enoughAbove with
        ⟨location, originalLocation, candidateLocation⟩
      have locationValid : location.range.disjointFromImages context = true := by
        have validRows := rangesValid
        simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
          List.all_eq_true] at validRows
        exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
      have valuesRelated := item.valueRelated_of_checked context world sourceInvariant
        window itemCheckedForValue originalState candidateState related
      rcases induction restChecked with ⟨updates, originalUpdates, candidateUpdates⟩
      let update : PairedStackWordUpdate context world := {
        location
        locationValid
        originalValue := item.value.original.eval originalState
        candidateValue := item.value.candidate.eval candidateState
        valuesRelated
      }
      refine ⟨update :: updates, ?_, ?_⟩
      · simp only [List.map_cons]
        rw [originalUpdates]
        congr 1
        simp [update, PairedStackWordUpdate.originalWrite,
          PairedStackWordWriteItem.originalAddress, pairedStackWordAddress_eval,
          originalLocation]
      · simp only [List.map_cons]
        rw [candidateUpdates]
        congr 1
        simp [update, PairedStackWordUpdate.candidateWrite,
          PairedStackWordWriteItem.candidateAddress, pairedStackWordAddress_eval,
          candidateLocation]

theorem pairedPreparedWordUpdates_of_checkedItems
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (items : List PairedPreparedWordWriteItem)
    (originalState candidateState : MachineState)
    (rangesValid : world.stackRangesValid context = true)
    (itemsChecked : items.all
      (PairedPreparedWordWriteItem.checked context sourceInvariant) = true)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    ∃ updates : List (PairedPreparedWordUpdate context world),
      updates.map PairedPreparedWordUpdate.originalWrite =
          items.map (fun item =>
            (item.originalAddress.eval originalState,
              item.value.original.eval originalState)) ∧
        updates.map PairedPreparedWordUpdate.candidateWrite =
          items.map (fun item =>
            (item.candidateAddress.eval candidateState,
              item.value.candidate.eval candidateState)) ∧
        updates.map PairedPreparedWordUpdate.kind =
          items.map PairedPreparedWordWriteItem.kind := by
  have relatedForWindows := related
  rcases relatedForWindows with
    ⟨_, _, _, _, _, _, _, _, relatedCore, _⟩
  rcases relatedCore with
    ⟨_, _, _, inputStackWindows, _, _, _, _, _, _⟩
  simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
  induction items with
  | nil => exact ⟨[], rfl, rfl, rfl⟩
  | cons item rest induction =>
      simp only [List.all_cons, Bool.and_eq_true] at itemsChecked
      have itemChecked := itemsChecked.1
      have restChecked := itemsChecked.2
      rcases induction restChecked with
        ⟨updates, originalUpdates, candidateUpdates, updateKinds⟩
      cases item with
      | stack window amount value =>
          simp only [PairedPreparedWordWriteItem.checked, Bool.and_eq_true,
            beq_iff_eq, decide_eq_true_eq] at itemChecked
          rcases itemChecked with
            ⟨⟨⟨windowMember, amountAligned⟩, enoughAbove⟩, valueChecked⟩
          have windowHolds := inputStackWindows window
            (List.contains_iff_mem.mp windowMember)
          rcases pairedStackWordLocation_above_window context world window
              originalState.registers candidateState.registers rangesValid windowHolds
              amount amountAligned enoughAbove with
            ⟨location, originalLocation, candidateLocation⟩
          have locationValid : location.range.disjointFromImages context = true := by
            have validRows := rangesValid
            simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
              List.all_eq_true] at validRows
            exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
          have valuesRelated := PairedStackWordValueClaim.related_of_checked
            context world sourceInvariant value valueChecked originalState candidateState
            related
          let stackUpdate : PairedStackWordUpdate context world := {
            location
            locationValid
            originalValue := value.original.eval originalState
            candidateValue := value.candidate.eval candidateState
            valuesRelated
          }
          let update : PairedPreparedWordUpdate context world := .stack stackUpdate
          refine ⟨update :: updates, ?_, ?_, ?_⟩
          · simp only [List.map_cons]
            rw [originalUpdates]
            congr 1
            simp [update, stackUpdate, PairedPreparedWordUpdate.originalWrite,
              PairedStackWordUpdate.originalWrite,
              PairedPreparedWordWriteItem.originalAddress,
              PairedPreparedWordWriteItem.value, pairedStackWordAddress_eval,
              originalLocation]
          · simp only [List.map_cons]
            rw [candidateUpdates]
            congr 1
            simp [update, stackUpdate, PairedPreparedWordUpdate.candidateWrite,
              PairedStackWordUpdate.candidateWrite,
              PairedPreparedWordWriteItem.candidateAddress,
              PairedPreparedWordWriteItem.value, pairedStackWordAddress_eval,
              candidateLocation]
          · simp [update, PairedPreparedWordUpdate.kind,
              PairedPreparedWordWriteItem.kind, updateKinds]

      | staticWord slotId originalAddress candidateAddress value =>
          unfold PairedPreparedWordWriteItem.checked at itemChecked
          cases slotResult : context.staticWordRelationSlotById slotId with
          | none => simp [slotResult] at itemChecked
          | some slot =>
              simp only [slotResult, Bool.and_eq_true, beq_iff_eq] at itemChecked
              rcases itemChecked with
                ⟨⟨⟨originalAddressExact, candidateAddressExact⟩, valueChecked⟩,
                  compatible⟩
              have slotMember : slot ∈ context.staticWordRelationSlots := by
                unfold StaticProofContext.staticWordRelationSlotById at slotResult
                exact List.mem_of_find?_eq_some slotResult
              have valuesRelated :=
                PairedStackWordValueClaim.staticRelationHolds_of_checked
                  context world sourceInvariant value slot.relation valueChecked compatible
                  originalState candidateState related
              let location : PairedStaticWordLocation context := {
                slot
                slotMember
                originalAddress := slot.originalAddress
                candidateAddress := slot.candidateAddress
                originalAddressExact := rfl
                candidateAddressExact := rfl
              }
              let staticUpdate : PairedStaticWordUpdate context world := {
                location
                originalValue := value.original.eval originalState
                candidateValue := value.candidate.eval candidateState
                valuesRelated
              }
              let update : PairedPreparedWordUpdate context world :=
                .staticWord staticUpdate
              refine ⟨update :: updates, ?_, ?_, ?_⟩
              · simp only [List.map_cons]
                rw [originalUpdates]
                congr 1
                simp [update, staticUpdate, location,
                  PairedPreparedWordUpdate.originalWrite,
                  PairedStaticWordUpdate.originalWrite,
                  PairedPreparedWordWriteItem.originalAddress,
                  PairedPreparedWordWriteItem.value, Expr.eval,
                  originalAddressExact]
              · simp only [List.map_cons]
                rw [candidateUpdates]
                congr 1
                simp [update, staticUpdate, location,
                  PairedPreparedWordUpdate.candidateWrite,
                  PairedStaticWordUpdate.candidateWrite,
                  PairedPreparedWordWriteItem.candidateAddress,
                  PairedPreparedWordWriteItem.value, Expr.eval,
                  candidateAddressExact]
              · simp [update, PairedPreparedWordUpdate.kind,
                  PairedPreparedWordWriteItem.kind, updateKinds]
      | dynamicWord source relation originalAmount candidateAmount value =>
          simp only [PairedPreparedWordWriteItem.checked, Bool.and_eq_true,
            beq_iff_eq] at itemChecked
          rcases itemChecked with
            ⟨⟨⟨⟨⟨sourceMember, relationRequired⟩, originalOffsetExact⟩,
              candidateOffsetExact⟩, valueChecked⟩, compatible⟩
          have sourceDynamic := related.dynamicRegisterRangesHold context world
            sourceInvariant originalState candidateState
          simp only [dynamicRegisterRangeRelationsHold, List.all_eq_true]
            at sourceDynamic
          have sourceRelationHolds := sourceDynamic source
            (List.contains_iff_mem.mp sourceMember)
          simp only [DynamicRegisterRangeRelation.holds, List.any_eq_true,
            Bool.and_eq_true, beq_iff_eq] at sourceRelationHolds
          rcases sourceRelationHolds with
            ⟨range, rangeMember,
              ⟨⟨⟨sourceOriginalValue, sourceCandidateValue⟩,
                sourceRequiredWords⟩, _sourceActiveWords⟩⟩
          have relationMember : relation ∈ range.wordRelations := by
            simp only [List.all_eq_true] at sourceRequiredWords
            exact List.contains_iff_mem.mp
              (sourceRequiredWords relation (List.contains_iff_mem.mp relationRequired))
          have originalLocation :
              (pairedDynamicWordAddress source.original originalAmount).eval
                  originalState =
                range.originalBase + BitVec.ofNat 32 relation.offset := by
            rw [pairedDynamicWordAddress_eval, sourceOriginalValue]
            rw [BitVec.add_assoc, ← BitVec.ofNat_add, originalOffsetExact]
          have candidateLocation :
              (pairedDynamicWordAddress source.candidate candidateAmount).eval
                  candidateState =
                range.candidateBase + BitVec.ofNat 32 relation.offset := by
            rw [pairedDynamicWordAddress_eval, sourceCandidateValue]
            rw [BitVec.add_assoc, ← BitVec.ofNat_add, candidateOffsetExact]
          have valuesRelated :=
            PairedStackWordValueClaim.dynamicRelationHolds_of_checked
              context world sourceInvariant value range relation.kind valueChecked
              compatible originalState candidateState related
          let location : PairedDynamicWordLocation world := {
            range
            relation
            rangeMember
            relationMember
            originalAddress :=
              (pairedDynamicWordAddress source.original originalAmount).eval originalState
            candidateAddress :=
              (pairedDynamicWordAddress source.candidate candidateAmount).eval candidateState
            originalAddressExact := originalLocation
            candidateAddressExact := candidateLocation
          }
          let dynamicUpdate : PairedDynamicWordUpdate context world := {
            location
            originalValue := value.original.eval originalState
            candidateValue := value.candidate.eval candidateState
            valuesRelated
          }
          let update : PairedPreparedWordUpdate context world :=
            .dynamicWord dynamicUpdate
          refine ⟨update :: updates, ?_, ?_, ?_⟩
          · simp only [List.map_cons]
            rw [originalUpdates]
            congr 1
          · simp only [List.map_cons]
            rw [candidateUpdates]
            congr 1
          · simp [update, PairedPreparedWordUpdate.kind,
              PairedPreparedWordWriteItem.kind, updateKinds]
      | staticDynamicPointer slotId originalAddress candidateAddress source value =>
          unfold PairedPreparedWordWriteItem.checked at itemChecked
          cases slotResult : context.staticDynamicPointerSlotById slotId with
          | none => simp [slotResult] at itemChecked
          | some slot =>
              simp only [slotResult, Bool.and_eq_true, beq_iff_eq] at itemChecked
              rcases itemChecked with
                ⟨⟨⟨⟨⟨⟨⟨originalAddressExact, candidateAddressExact⟩,
                  sourceMember⟩, sourceOriginalOffset⟩, sourceCandidateOffset⟩,
                  requiredSubset⟩, valueExact⟩, valueChecked⟩
              have slotMember : slot ∈ context.staticDynamicPointerSlots := by
                unfold StaticProofContext.staticDynamicPointerSlotById at slotResult
                exact List.mem_of_find?_eq_some slotResult
              have sourceDynamic := related.dynamicRegisterRangesHold context world
                sourceInvariant originalState candidateState
              simp only [dynamicRegisterRangeRelationsHold, List.all_eq_true]
                at sourceDynamic
              have sourceRelationHolds := sourceDynamic source
                (List.contains_iff_mem.mp sourceMember)
              simp only [DynamicRegisterRangeRelation.holds, List.any_eq_true,
                Bool.and_eq_true, beq_iff_eq] at sourceRelationHolds
              rcases sourceRelationHolds with
                ⟨range, rangeMember,
                  ⟨⟨⟨sourceOriginalValue, sourceCandidateValue⟩,
                    sourceRequiredWords⟩, _sourceActiveWords⟩⟩
              have sourceOriginalBase :
                  originalState.registers.get source.original = range.originalBase := by
                simpa [sourceOriginalOffset] using sourceOriginalValue
              have sourceCandidateBase :
                  candidateState.registers.get source.candidate = range.candidateBase := by
                simpa [sourceCandidateOffset] using sourceCandidateValue
              have requiredWords :
                  slot.requiredWords.all range.wordRelations.contains = true := by
                simp only [List.all_eq_true] at requiredSubset sourceRequiredWords ⊢
                intro word wordMember
                exact sourceRequiredWords word
                  (List.contains_iff_mem.mp (requiredSubset word wordMember))
              let location : PairedStaticDynamicPointerLocation context := {
                slot
                slotMember
                originalAddress := slot.originalAddress
                candidateAddress := slot.candidateAddress
                originalAddressExact := rfl
                candidateAddressExact := rfl
              }
              let pointerUpdate : PairedStaticDynamicPointerUpdate context world := {
                location
                range
                rangeMember
                requiredWords
              }
              let update : PairedPreparedWordUpdate context world :=
                .staticDynamicPointer pointerUpdate
              refine ⟨update :: updates, ?_, ?_, ?_⟩
              · simp only [List.map_cons]
                rw [originalUpdates]
                congr 1
                simp [update, pointerUpdate, location,
                  PairedPreparedWordUpdate.originalWrite,
                  PairedStaticDynamicPointerUpdate.originalWrite,
                  PairedPreparedWordWriteItem.originalAddress,
                  PairedPreparedWordWriteItem.value, Expr.eval,
                  originalAddressExact, valueExact, sourceOriginalBase]
              · simp only [List.map_cons]
                rw [candidateUpdates]
                congr 1
                simp [update, pointerUpdate, location,
                  PairedPreparedWordUpdate.candidateWrite,
                  PairedStaticDynamicPointerUpdate.candidateWrite,
                  PairedPreparedWordWriteItem.candidateAddress,
                  PairedPreparedWordWriteItem.value, Expr.eval,
                  candidateAddressExact, valueExact, sourceCandidateBase]
              · simp [update, PairedPreparedWordUpdate.kind,
                  PairedPreparedWordWriteItem.kind, updateKinds]

theorem pairedPreparedWordWritesSpillReadsBack
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (writesClaim : PairedPreparedWordWritesClaim)
    (spillClaim : PreparedDynamicStackRangeSpillClaim)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (contextValid : context.StructurallyValid)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (writesChecked : writesClaim.checked context sourceInvariant = true)
    (spillChecked :
      spillClaim.checked sourceInvariant targetInvariant writesClaim = true)
    (originalWrites :
      originalBehavior.writes = writesClaim.originalWrites originalState)
    (candidateWrites :
      candidateBehavior.writes = writesClaim.candidateWrites candidateState) :
    Memory.read32 (originalBehavior.nextMachineState originalState).memory
        (originalState.registers.get spillClaim.window.originalRegister +
          BitVec.ofNat 32 spillClaim.amount) =
          originalState.registers.get spillClaim.sourceRelation.original ∧
      Memory.read32 (candidateBehavior.nextMachineState candidateState).memory
        (candidateState.registers.get spillClaim.window.candidateRegister +
          BitVec.ofNat 32 spillClaim.amount) =
          candidateState.registers.get spillClaim.sourceRelation.candidate := by
  simp only [PairedPreparedWordWritesClaim.checked, Bool.and_eq_true]
    at writesChecked
  have itemsChecked := writesChecked.2
  simp only [PreparedDynamicStackRangeSpillClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at spillChecked
  rcases spillChecked with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨writesExact, suffixNonStack⟩,
      _sourceRelationMember⟩, _sourceWindowMember⟩, _targetRelationMember⟩,
      _targetWindowMember⟩, _targetWindowExact⟩, _targetStackOffsetExact⟩,
      _targetOriginalOffsetExact⟩, _targetCandidateOffsetExact⟩,
      _requiredWordsSubset⟩, _sourceActiveWordsSubset⟩, _activeWordsSubset⟩
  have worldValid := related.1
  have stackRangesValid := related.2.1
  have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
    rcases contextValid with
      ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _⟩
    exact slotsValid
  rcases pairedPreparedWordUpdates_of_checkedItems context world sourceInvariant
      writesClaim.writes originalState candidateState stackRangesValid itemsChecked
      related with
    ⟨updates, originalUpdateWrites, candidateUpdateWrites, updateKinds⟩
  rw [writesExact] at originalUpdateWrites candidateUpdateWrites updateKinds
  cases updates with
  | nil => simp [PreparedDynamicStackRangeSpillClaim.item] at updateKinds
  | cons first rest =>
      cases first with
      | staticWord update =>
          simp [PreparedDynamicStackRangeSpillClaim.item,
            PairedPreparedWordUpdate.kind,
            PairedPreparedWordWriteItem.kind] at updateKinds
      | dynamicWord update =>
          simp [PreparedDynamicStackRangeSpillClaim.item,
            PairedPreparedWordUpdate.kind,
            PairedPreparedWordWriteItem.kind] at updateKinds
      | staticDynamicPointer update =>
          simp [PreparedDynamicStackRangeSpillClaim.item,
            PairedPreparedWordUpdate.kind,
            PairedPreparedWordWriteItem.kind] at updateKinds
      | stack spillUpdate =>
          have originalUpdateWritesAll := originalUpdateWrites
          have candidateUpdateWritesAll := candidateUpdateWrites
          simp only [List.map_cons] at originalUpdateWrites candidateUpdateWrites
          injection originalUpdateWrites with originalHead originalTail
          injection candidateUpdateWrites with candidateHead candidateTail
          injection updateKinds with _headKind restKinds
          have originalAddressExact := congrArg Prod.fst originalHead
          have originalValueExact := congrArg Prod.snd originalHead
          have candidateAddressExact := congrArg Prod.fst candidateHead
          have candidateValueExact := congrArg Prod.snd candidateHead
          simp only [PairedPreparedWordUpdate.originalWrite,
            PairedStackWordUpdate.originalWrite,
            PreparedDynamicStackRangeSpillClaim.item,
            PreparedDynamicStackRangeSpillClaim.value,
            PairedPreparedWordWriteItem.originalAddress,
            PairedPreparedWordWriteItem.value, pairedStackWordAddress_eval,
            Expr.eval] at originalAddressExact originalValueExact
          simp only [PairedPreparedWordUpdate.candidateWrite,
            PairedStackWordUpdate.candidateWrite,
            PreparedDynamicStackRangeSpillClaim.item,
            PreparedDynamicStackRangeSpillClaim.value,
            PairedPreparedWordWriteItem.candidateAddress,
            PairedPreparedWordWriteItem.value, pairedStackWordAddress_eval,
            Expr.eval] at candidateAddressExact candidateValueExact
          have restAllNonStack :
              rest.all (fun update => update.kind != .stack) = true := by
            have suffixKinds :
                (spillClaim.suffix.map PairedPreparedWordWriteItem.kind).all
                    (fun kind => kind != .stack) = true := by
              simpa only [List.all_map] using suffixNonStack
            have restKindsHold :
                (rest.map PairedPreparedWordUpdate.kind).all
                    (fun kind => kind != .stack) = true := by
              rw [restKinds]
              exact suffixKinds
            simpa only [List.all_map] using restKindsHold
          have suffixAvoids :=
            pairedPreparedWordUpdatesAvoidStackLocation_of_all_nonStack
              context world worldValid stackRangesValid
              (by
                rcases contextValid with
                  ⟨_, _, _, _, _, _, _, _, pointerSlotsValid, _, _, _, _, _⟩
                exact pointerSlotsValid)
              staticWordSlotsValid
              spillUpdate.location spillUpdate.locationValid rest restAllNonStack
          have originalFits := DynamicAddressRangePair.wordAddress_fits context false
            spillUpdate.location.range spillUpdate.locationValid
            spillUpdate.location.offset spillUpdate.location.inside
          have candidateFits := DynamicAddressRangePair.wordAddress_fits context true
            spillUpdate.location.range spillUpdate.locationValid
            spillUpdate.location.offset spillUpdate.location.inside
          have originalRead :
              Memory.read32
                  (applyConcreteWrites
                    (originalState.memory.write32 spillUpdate.location.originalAddress
                      spillUpdate.originalValue)
                    (rest.map PairedPreparedWordUpdate.originalWrite))
                  spillUpdate.location.originalAddress =
                spillUpdate.originalValue := by
            rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ suffixAvoids.1]
            rw [spillUpdate.location.originalAddressExact]
            exact Memory.read32_write32_same_of_fits originalState.memory
              (spillUpdate.location.range.originalBase +
                BitVec.ofNat 32 spillUpdate.location.offset)
              spillUpdate.originalValue originalFits
          have candidateRead :
              Memory.read32
                  (applyConcreteWrites
                    (candidateState.memory.write32 spillUpdate.location.candidateAddress
                      spillUpdate.candidateValue)
                    (rest.map PairedPreparedWordUpdate.candidateWrite))
                  spillUpdate.location.candidateAddress =
                spillUpdate.candidateValue := by
            rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ suffixAvoids.2]
            rw [spillUpdate.location.candidateAddressExact]
            exact Memory.read32_write32_same_of_fits candidateState.memory
              (spillUpdate.location.range.candidateBase +
                BitVec.ofNat 32 spillUpdate.location.offset)
              spillUpdate.candidateValue candidateFits
          constructor
          · rw [show (originalBehavior.nextMachineState originalState).memory =
                applyConcreteWrites originalState.memory originalBehavior.writes by rfl]
            rw [originalWrites]
            unfold PairedPreparedWordWritesClaim.originalWrites
            rw [writesExact, ← originalUpdateWritesAll]
            change Memory.read32
              (applyConcreteWrites originalState.memory
                (spillUpdate.originalWrite ::
                  rest.map PairedPreparedWordUpdate.originalWrite)) _ = _
            rw [show applyConcreteWrites originalState.memory
                (spillUpdate.originalWrite ::
                  rest.map PairedPreparedWordUpdate.originalWrite) =
              applyConcreteWrites
                (originalState.memory.write32 spillUpdate.location.originalAddress
                  spillUpdate.originalValue)
                (rest.map PairedPreparedWordUpdate.originalWrite) by rfl]
            rw [← originalAddressExact, ← originalValueExact]
            exact originalRead
          · rw [show (candidateBehavior.nextMachineState candidateState).memory =
                applyConcreteWrites candidateState.memory candidateBehavior.writes by rfl]
            rw [candidateWrites]
            unfold PairedPreparedWordWritesClaim.candidateWrites
            rw [writesExact, ← candidateUpdateWritesAll]
            change Memory.read32
              (applyConcreteWrites candidateState.memory
                (spillUpdate.candidateWrite ::
                  rest.map PairedPreparedWordUpdate.candidateWrite)) _ = _
            rw [show applyConcreteWrites candidateState.memory
                (spillUpdate.candidateWrite ::
                  rest.map PairedPreparedWordUpdate.candidateWrite) =
              applyConcreteWrites
                (candidateState.memory.write32 spillUpdate.location.candidateAddress
                  spillUpdate.candidateValue)
                (rest.map PairedPreparedWordUpdate.candidateWrite) by rfl]
            rw [← candidateAddressExact, ← candidateValueExact]
            exact candidateRead

def NoWriteSegmentStateTransferClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds with
  | some localCodeTargets =>
      ∀ world originalState candidateState originalResult candidateResult,
        StateRel context world sourceInvariant originalState candidateState →
        evalBehavior false localCodeTargets originalState originalBehavior =
            some originalResult →
        evalBehavior true localCodeTargets candidateState candidateBehavior =
            some candidateResult →
        edge.originalGuard.eval originalState = true →
        registerRelationsHold context.originalPe.imageBase context.candidatePe.imageBase
              context.codeMap.entries.toList (context.relationalValueTargets world)
              targetInvariant.registerRelations originalResult.registers
              candidateResult.registers = true ∧
          boundsRelated targetInvariant.bounds originalResult.registers
              candidateResult.registers = true ∧
          addressSeparationsRelated targetInvariant.addressSeparations
              originalResult.registers candidateResult.registers = true ∧
          stackWindowsRelated world targetInvariant.stackWindows
              originalResult.registers candidateResult.registers = true ∧
          (originalResult.nextMachineState originalState).x87 =
              (candidateResult.nextMachineState candidateState).x87 ∧
          flagsRelated targetInvariant.flagBits originalResult.eflags
              candidateResult.eflags = true
  | none => False

def NoWriteSegmentImportTransferClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds with
  | some localCodeTargets =>
      ∀ world originalState candidateState originalResult candidateResult,
        StateRel context world sourceInvariant originalState candidateState →
        evalBehavior false localCodeTargets originalState originalBehavior =
            some originalResult →
        evalBehavior true localCodeTargets candidateState candidateBehavior =
            some candidateResult →
        importRegisterRelationsHold world targetInvariant.importRegisterRelations
          originalResult.registers candidateResult.registers = true
  | none => False

def NoWriteSegmentDynamicTransferClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds with
  | some localCodeTargets =>
      ∀ world originalState candidateState originalResult candidateResult,
        StateRel context world sourceInvariant originalState candidateState →
        evalBehavior false localCodeTargets originalState originalBehavior =
            some originalResult →
        evalBehavior true localCodeTargets candidateState candidateBehavior =
            some candidateResult →
        edge.originalGuard.eval originalState = true →
        activeDynamicRegisterRangeRelationsHold context world
          targetInvariant.dynamicRegisterRangeRelations
          (originalResult.nextMachineState originalState)
          (candidateResult.nextMachineState candidateState) = true
  | none => False

def NoWriteSegmentDynamicStackTransferClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds with
  | some localCodeTargets =>
      ∀ world originalState candidateState originalResult candidateResult,
        StateRel context world sourceInvariant originalState candidateState →
        evalBehavior false localCodeTargets originalState originalBehavior =
            some originalResult →
        evalBehavior true localCodeTargets candidateState candidateBehavior =
            some candidateResult →
        edge.originalGuard.eval originalState = true →
        activeDynamicStackRangeRelationsHold context world
          targetInvariant.dynamicStackRangeRelations
          (originalResult.nextMachineState originalState)
          (candidateResult.nextMachineState candidateState) = true
  | none => False

theorem noWriteSegmentDynamicStackTransferClosed_of_empty
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (targetEmpty : targetInvariant.dynamicStackRangeRelations = []) :
    NoWriteSegmentDynamicStackTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior := by
  unfold NoWriteSegmentDynamicStackTransferClosed
  rw [localCodeTargetsResolved]
  simp [targetEmpty, activeDynamicStackRangeRelationsHold]

theorem pairedStackWordFinalWriteReadsBack_amount
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (sourceWindow : StackWindowPair)
    (stackAmount : Nat)
    (originalValue candidateValue : Word)
    (originalPrefix candidatePrefix : List (Word × Word))
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (sourceWindowMember : sourceWindow ∈ sourceInvariant.stackWindows)
    (stackAmountAtLeastWord : 4 <= stackAmount)
    (stackAmountAligned : stackAmount % 4 = 0)
    (sourceWindowEnoughBelow : stackAmount <= sourceWindow.bytesBelow)
    (originalWrites : originalBehavior.writes = originalPrefix ++ [
      (originalState.registers.get sourceWindow.originalRegister -
        BitVec.ofNat 32 stackAmount,
        originalValue)])
    (candidateWrites : candidateBehavior.writes = candidatePrefix ++ [
      (candidateState.registers.get sourceWindow.candidateRegister -
        BitVec.ofNat 32 stackAmount,
        candidateValue)]) :
    Memory.read32 (originalBehavior.nextMachineState originalState).memory
        (originalState.registers.get sourceWindow.originalRegister -
          BitVec.ofNat 32 stackAmount) =
          originalValue ∧
      Memory.read32 (candidateBehavior.nextMachineState candidateState).memory
        (candidateState.registers.get sourceWindow.candidateRegister -
          BitVec.ofNat 32 stackAmount) =
          candidateValue := by
  rcases related with
    ⟨_worldValid, stackRangesValid, _stackMemory, _importsStatic, _importsComplete,
      _importsMemory, _originalImmutable, _candidateImmutable, relatedCore,
      _inputImportRegisters⟩
  rcases relatedCore with
    ⟨_inputRegisters, _inputBounds, _inputSeparations, inputStackWindows,
      _inputMemory, _inputDynamicMemory, _inputUndefined, _inputX87, _inputFlags,
      _inputFsBase⟩
  simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
  have sourceWindowHolds := inputStackWindows sourceWindow sourceWindowMember
  rcases pairedStackWordLocation_below_window_amount context world sourceWindow
      originalState.registers candidateState.registers stackRangesValid
      sourceWindowHolds stackAmount stackAmountAtLeastWord stackAmountAligned
      sourceWindowEnoughBelow with
    ⟨location, originalLocation, candidateLocation⟩
  have locationValid : location.range.disjointFromImages context = true := by
    have validRows := stackRangesValid
    simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
      List.all_eq_true] at validRows
    exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
  have originalFits := DynamicAddressRangePair.wordAddress_fits context false
    location.range locationValid location.offset location.inside
  have candidateFits := DynamicAddressRangePair.wordAddress_fits context true
    location.range locationValid location.offset location.inside
  constructor
  · simp only [RelationalBehavior.nextMachineState, originalWrites,
      applyConcreteWrites, List.foldl_append, List.foldl]
    rw [originalLocation.symm.trans location.originalAddressExact]
    exact Memory.read32_write32_same_of_fits
      (originalPrefix.foldl
        (fun current write => current.write32 write.1 write.2)
        originalState.memory)
      (location.range.originalBase + BitVec.ofNat 32 location.offset)
      originalValue originalFits
  · simp only [RelationalBehavior.nextMachineState, candidateWrites,
      applyConcreteWrites, List.foldl_append, List.foldl]
    rw [candidateLocation.symm.trans location.candidateAddressExact]
    exact Memory.read32_write32_same_of_fits
      (candidatePrefix.foldl
        (fun current write => current.write32 write.1 write.2)
        candidateState.memory)
      (location.range.candidateBase + BitVec.ofNat 32 location.offset)
      candidateValue candidateFits

theorem pairedStackWordWriteReadsBack_amount
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (sourceWindow : StackWindowPair)
    (stackAmount : Nat)
    (originalValue candidateValue : Word)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (sourceWindowMember : sourceWindow ∈ sourceInvariant.stackWindows)
    (stackAmountAtLeastWord : 4 <= stackAmount)
    (stackAmountAligned : stackAmount % 4 = 0)
    (sourceWindowEnoughBelow : stackAmount <= sourceWindow.bytesBelow)
    (originalWrites : originalBehavior.writes = [
      (originalState.registers.get sourceWindow.originalRegister -
        BitVec.ofNat 32 stackAmount,
        originalValue)])
    (candidateWrites : candidateBehavior.writes = [
      (candidateState.registers.get sourceWindow.candidateRegister -
        BitVec.ofNat 32 stackAmount,
        candidateValue)]) :
    Memory.read32 (originalBehavior.nextMachineState originalState).memory
        (originalState.registers.get sourceWindow.originalRegister -
          BitVec.ofNat 32 stackAmount) =
          originalValue ∧
      Memory.read32 (candidateBehavior.nextMachineState candidateState).memory
        (candidateState.registers.get sourceWindow.candidateRegister -
          BitVec.ofNat 32 stackAmount) =
          candidateValue := by
  rcases related with
    ⟨_worldValid, stackRangesValid, _stackMemory, _importsStatic, _importsComplete,
      _importsMemory, _originalImmutable, _candidateImmutable, relatedCore,
      _inputImportRegisters⟩
  rcases relatedCore with
    ⟨_inputRegisters, _inputBounds, _inputSeparations, inputStackWindows,
      _inputMemory, _inputDynamicMemory, _inputUndefined, _inputX87, _inputFlags,
      _inputFsBase⟩
  simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
  have sourceWindowHolds := inputStackWindows sourceWindow sourceWindowMember
  rcases pairedStackWordLocation_below_window_amount context world sourceWindow
      originalState.registers candidateState.registers stackRangesValid
      sourceWindowHolds stackAmount stackAmountAtLeastWord stackAmountAligned
      sourceWindowEnoughBelow with
    ⟨location, originalLocation, candidateLocation⟩
  have locationValid : location.range.disjointFromImages context = true := by
    have validRows := stackRangesValid
    simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
      List.all_eq_true] at validRows
    exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
  have originalFits := DynamicAddressRangePair.wordAddress_fits context false
    location.range locationValid location.offset location.inside
  have candidateFits := DynamicAddressRangePair.wordAddress_fits context true
    location.range locationValid location.offset location.inside
  constructor
  · simp only [RelationalBehavior.nextMachineState, originalWrites,
      applyConcreteWrites, List.foldl]
    rw [originalLocation.symm.trans location.originalAddressExact]
    exact Memory.read32_write32_same_of_fits originalState.memory
      (location.range.originalBase + BitVec.ofNat 32 location.offset)
      originalValue originalFits
  · simp only [RelationalBehavior.nextMachineState, candidateWrites,
      applyConcreteWrites, List.foldl]
    rw [candidateLocation.symm.trans location.candidateAddressExact]
    exact Memory.read32_write32_same_of_fits candidateState.memory
      (location.range.candidateBase + BitVec.ofNat 32 location.offset)
      candidateValue candidateFits

theorem pairedStackWordWriteReadsBack_above_amount
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (sourceWindow : StackWindowPair)
    (stackOffset : Nat)
    (originalValue candidateValue : Word)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (sourceWindowMember : sourceWindow ∈ sourceInvariant.stackWindows)
    (stackOffsetAligned : stackOffset % 4 = 0)
    (sourceWindowEnoughAbove : stackOffset + 4 <= sourceWindow.bytesAbove)
    (originalWrites : originalBehavior.writes = [
      (originalState.registers.get sourceWindow.originalRegister +
        BitVec.ofNat 32 stackOffset,
        originalValue)])
    (candidateWrites : candidateBehavior.writes = [
      (candidateState.registers.get sourceWindow.candidateRegister +
        BitVec.ofNat 32 stackOffset,
        candidateValue)]) :
    Memory.read32 (originalBehavior.nextMachineState originalState).memory
        (originalState.registers.get sourceWindow.originalRegister +
          BitVec.ofNat 32 stackOffset) = originalValue ∧
      Memory.read32 (candidateBehavior.nextMachineState candidateState).memory
        (candidateState.registers.get sourceWindow.candidateRegister +
          BitVec.ofNat 32 stackOffset) = candidateValue := by
  rcases related with
    ⟨_worldValid, stackRangesValid, _stackMemory, _importsStatic, _importsComplete,
      _importsMemory, _originalImmutable, _candidateImmutable, relatedCore,
      _inputImportRegisters⟩
  rcases relatedCore with
    ⟨_inputRegisters, _inputBounds, _inputSeparations, inputStackWindows,
      _inputMemory, _inputDynamicMemory, _inputUndefined, _inputX87, _inputFlags,
      _inputFsBase⟩
  simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
  have sourceWindowHolds := inputStackWindows sourceWindow sourceWindowMember
  rcases pairedStackWordLocation_above_window context world sourceWindow
      originalState.registers candidateState.registers stackRangesValid
      sourceWindowHolds stackOffset stackOffsetAligned sourceWindowEnoughAbove with
    ⟨location, originalLocation, candidateLocation⟩
  have locationValid : location.range.disjointFromImages context = true := by
    have validRows := stackRangesValid
    simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
      List.all_eq_true] at validRows
    exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
  have originalFits := DynamicAddressRangePair.wordAddress_fits context false
    location.range locationValid location.offset location.inside
  have candidateFits := DynamicAddressRangePair.wordAddress_fits context true
    location.range locationValid location.offset location.inside
  constructor
  · simp only [RelationalBehavior.nextMachineState, originalWrites,
      applyConcreteWrites, List.foldl]
    rw [originalLocation.symm.trans location.originalAddressExact]
    exact Memory.read32_write32_same_of_fits originalState.memory
      (location.range.originalBase + BitVec.ofNat 32 location.offset)
      originalValue originalFits
  · simp only [RelationalBehavior.nextMachineState, candidateWrites,
      applyConcreteWrites, List.foldl]
    rw [candidateLocation.symm.trans location.candidateAddressExact]
    exact Memory.read32_write32_same_of_fits candidateState.memory
      (location.range.candidateBase + BitVec.ofNat 32 location.offset)
      candidateValue candidateFits

theorem pairedStackWordWriteReadsBack
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (sourceWindow : StackWindowPair)
    (originalValue candidateValue : Word)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (sourceWindowMember : sourceWindow ∈ sourceInvariant.stackWindows)
    (sourceWindowEnoughBelow : 4 <= sourceWindow.bytesBelow)
    (originalWrites : originalBehavior.writes = [
      (originalState.registers.get sourceWindow.originalRegister - BitVec.ofNat 32 4,
        originalValue)])
    (candidateWrites : candidateBehavior.writes = [
      (candidateState.registers.get sourceWindow.candidateRegister - BitVec.ofNat 32 4,
        candidateValue)]) :
    Memory.read32 (originalBehavior.nextMachineState originalState).memory
        (originalState.registers.get sourceWindow.originalRegister - BitVec.ofNat 32 4) =
          originalValue ∧
      Memory.read32 (candidateBehavior.nextMachineState candidateState).memory
        (candidateState.registers.get sourceWindow.candidateRegister - BitVec.ofNat 32 4) =
          candidateValue := by
  exact pairedStackWordWriteReadsBack_amount context world sourceInvariant sourceWindow
    4 originalValue candidateValue originalState candidateState originalBehavior
    candidateBehavior related sourceWindowMember (by decide) (by decide)
    sourceWindowEnoughBelow originalWrites candidateWrites

theorem noWriteSegmentDynamicStackTransferClosed_of_spill
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (writeClaim : PairedStackWordWriteClaim)
    (spillClaim : DynamicStackRangeSpillClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (writeClaimChecked :
      writeClaim.checked context sourceInvariant originalNormalized
        candidateNormalized = true)
    (spillClaimChecked :
      spillClaim.checked sourceInvariant targetInvariant writeClaim = true)
    (targetInventory :
      targetInvariant.dynamicStackRangeRelations = [spillClaim.targetRelation])
    (shape : PairedStackWordWriteSegmentShapeClosed context edge sourceInvariant
      writeClaim originalBehavior candidateBehavior)
    (basePreserved : PairedStackWordWriteOutputBasePreserved context edge
      writeClaim originalBehavior candidateBehavior) :
    NoWriteSegmentDynamicStackTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior := by
  unfold NoWriteSegmentDynamicStackTransferClosed
  rw [localCodeTargetsResolved]
  unfold PairedStackWordWriteSegmentShapeClosed at shape
  rw [localCodeTargetsResolved, localValuesResolved] at shape
  unfold PairedStackWordWriteOutputBasePreserved at basePreserved
  rw [localCodeTargetsResolved] at basePreserved
  simp only [PairedStackWordWriteClaim.checked, Bool.and_eq_true,
    beq_iff_eq, decide_eq_true_eq] at writeClaimChecked
  simp only [DynamicStackRangeSpillClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at spillClaimChecked
  rcases spillClaimChecked with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨sourceRelationMember, sourceWindowMember⟩,
      targetRelationMember⟩, targetWindowMember⟩, targetWindowExact⟩,
      targetStackOffsetExact⟩, targetOriginalOffsetExact⟩,
      targetCandidateOffsetExact⟩, requiredWordsSubset⟩,
      sourceActiveWordsSubset⟩, activeWordsSubset⟩, originalValueExact⟩,
      candidateValueExact⟩
  have writeOffsetAligned := writeClaimChecked.1.1.1.1
  have sourceWindowEnoughAbove := writeClaimChecked.1.1.1.2
  intro world originalState candidateState originalResult candidateResult related
    originalEval candidateEval guardTrue
  have relatedForShape := related
  have relatedForReadback := related
  rcases shape world originalState candidateState relatedForShape with
    ⟨_guardsAgree, shapeClosed⟩
  rcases shapeClosed guardTrue with
    ⟨shapeOriginalResult, shapeCandidateResult, shapeOriginalEval,
      shapeCandidateEval, shapeOriginalWrites, shapeCandidateWrites,
      _originalExit, _candidateExit, _outcomes⟩
  rw [originalEval] at shapeOriginalEval
  rw [candidateEval] at shapeCandidateEval
  have originalResultExact : originalResult = shapeOriginalResult :=
    Option.some.inj shapeOriginalEval
  have candidateResultExact : candidateResult = shapeCandidateResult :=
    Option.some.inj shapeCandidateEval
  subst shapeOriginalResult
  subst shapeCandidateResult
  have outputBases := basePreserved originalState candidateState originalResult
    candidateResult originalEval candidateEval
  have sourceDynamic := related.activeDynamicRegisterRangesHold context world
    sourceInvariant originalState candidateState
  simp only [activeDynamicRegisterRangeRelationsHold, List.all_eq_true]
    at sourceDynamic
  have sourceRelationHolds := sourceDynamic spillClaim.sourceRelation
    (List.contains_iff_mem.mp sourceRelationMember)
  simp only [DynamicRegisterRangeRelation.activeHolds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at sourceRelationHolds
  rcases sourceRelationHolds with
    ⟨range, rangeMember,
      ⟨⟨⟨⟨sourceOriginalValue, sourceCandidateValue⟩,
        sourceRequiredWords⟩, _sourceActiveWords⟩, sourceWordsHold⟩⟩
  have originalWrites : originalResult.writes = [
      (originalState.registers.get writeClaim.window.originalRegister +
        BitVec.ofNat 32 writeClaim.amount,
        originalState.registers.get spillClaim.sourceRelation.original)] := by
    simpa [PairedStackWordWriteClaim.originalAddress, Expr.eval,
      originalValueExact] using shapeOriginalWrites
  have candidateWrites : candidateResult.writes = [
      (candidateState.registers.get writeClaim.window.candidateRegister +
        BitVec.ofNat 32 writeClaim.amount,
        candidateState.registers.get spillClaim.sourceRelation.candidate)] := by
    simpa [PairedStackWordWriteClaim.candidateAddress, Expr.eval,
      candidateValueExact] using shapeCandidateWrites
  have readsBack := pairedStackWordWriteReadsBack_above_amount context world
    sourceInvariant writeClaim.window writeClaim.amount
    (originalState.registers.get spillClaim.sourceRelation.original)
    (candidateState.registers.get spillClaim.sourceRelation.candidate)
    originalState candidateState originalResult candidateResult relatedForReadback
    (List.contains_iff_mem.mp sourceWindowMember) writeOffsetAligned
    sourceWindowEnoughAbove originalWrites candidateWrites
  have stackRangesValid : world.stackRangesValid context = true := related.2.1
  have sourceWindows := relatedForReadback
  rcases sourceWindows with
    ⟨_, _, _, _, _, _, _, _, sourceCore, _⟩
  have sourceWindowRelations := sourceCore.2.2.2.1
  simp only [stackWindowsRelated, List.all_eq_true] at sourceWindowRelations
  have sourceWindowHolds := sourceWindowRelations writeClaim.window
    (List.contains_iff_mem.mp sourceWindowMember)
  rcases pairedStackWordLocation_above_window context world writeClaim.window
      originalState.registers candidateState.registers stackRangesValid
      sourceWindowHolds writeClaim.amount writeOffsetAligned sourceWindowEnoughAbove with
    ⟨location, originalLocation, candidateLocation⟩
  have locationValid : location.range.disjointFromImages context = true := by
    have validRows := stackRangesValid
    simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
      List.all_eq_true] at validRows
    exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
  have valueRelated := writeClaim.value.related_of_checked context world
    sourceInvariant writeClaimChecked.2 originalState candidateState related
  let update : PairedStackWordUpdate context world := {
    location := location
    locationValid := locationValid
    originalValue := writeClaim.value.original.eval originalState
    candidateValue := writeClaim.value.candidate.eval candidateState
    valuesRelated := valueRelated
  }
  have targetWordsBefore := dynamicWordRequirementsHold_mono context world range
    spillClaim.sourceRelation.activeWords spillClaim.targetRelation.activeWords
    originalState.memory candidateState.memory sourceActiveWordsSubset sourceWordsHold
  have worldDynamicValid : world.dynamicRangesValid context = true := by
    have valid := related.1
    simp only [RelationalWorld.valid, Bool.and_eq_true] at valid
    exact valid.1.1.1.1
  have outputWords := dynamicWordRequirementsHold_after_stack_update context world
    range spillClaim.targetRelation.activeWords originalState.memory
    candidateState.memory update worldDynamicValid rangeMember targetWordsBefore
  rw [originalLocation, candidateLocation] at outputWords
  simp only [update, originalValueExact, candidateValueExact, Expr.eval]
    at outputWords
  have outputWordsExact : dynamicWordRequirementsHold context world range
      spillClaim.targetRelation.activeWords
      (originalResult.nextMachineState originalState).memory
      (candidateResult.nextMachineState candidateState).memory = true := by
    simpa [RelationalBehavior.nextMachineState, originalWrites, candidateWrites,
      applyConcreteWrites] using outputWords
  rw [targetInventory]
  simp only [activeDynamicStackRangeRelationsHold, List.all_cons, List.all_nil,
    Bool.and_true]
  unfold DynamicStackRangeRelation.activeHolds
  simp only [Bool.and_eq_true, List.any_eq_true, beq_iff_eq]
  refine ⟨?_, range, rangeMember, ?_⟩
  · rw [targetWindowExact]
    change writeClaim.window.holds world originalResult.registers
      candidateResult.registers = true
    unfold StackWindowPair.holds
    rw [outputBases.1, outputBases.2]
    simpa only [StackWindowPair.holds] using sourceWindowHolds
  · refine ⟨⟨⟨⟨?_, ?_⟩, ?_⟩, activeWordsSubset⟩, outputWordsExact⟩
    · rw [targetWindowExact, targetStackOffsetExact]
      change Memory.read32 (originalResult.nextMachineState originalState).memory
        (originalResult.registers.get writeClaim.window.originalRegister +
          BitVec.ofNat 32 writeClaim.amount) = _
      rw [outputBases.1, readsBack.1,
        sourceOriginalValue, targetOriginalOffsetExact]
    · rw [targetWindowExact, targetStackOffsetExact]
      change Memory.read32 (candidateResult.nextMachineState candidateState).memory
        (candidateResult.registers.get writeClaim.window.candidateRegister +
          BitVec.ofNat 32 writeClaim.amount) = _
      rw [outputBases.2, readsBack.2,
        sourceCandidateValue, targetCandidateOffsetExact]
    · simp only [List.all_eq_true] at sourceRequiredWords requiredWordsSubset ⊢
      intro word targetWordMember
      exact sourceRequiredWords word
        (List.contains_iff_mem.mp (requiredWordsSubset word targetWordMember))

theorem noWriteSegmentDynamicStackTransferClosed_of_prepared_spill
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (writesClaim : PairedPreparedWordWritesClaim)
    (spillClaim : PreparedDynamicStackRangeSpillClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (writesChecked : writesClaim.checked context sourceInvariant = true)
    (spillChecked :
      spillClaim.checked sourceInvariant targetInvariant writesClaim = true)
    (targetInventory :
      targetInvariant.dynamicStackRangeRelations = [spillClaim.targetRelation])
    (shape : PairedPreparedWordWritesSegmentShapeClosed context edge sourceInvariant
      writesClaim originalBehavior candidateBehavior)
    (basePreserved : PairedPreparedWordWritesOutputBasePreserved context edge
      spillClaim originalBehavior candidateBehavior) :
    NoWriteSegmentDynamicStackTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior := by
  unfold NoWriteSegmentDynamicStackTransferClosed
  rw [localCodeTargetsResolved]
  unfold PairedPreparedWordWritesSegmentShapeClosed at shape
  rw [localCodeTargetsResolved, localValuesResolved] at shape
  unfold PairedPreparedWordWritesOutputBasePreserved at basePreserved
  rw [localCodeTargetsResolved] at basePreserved
  have spillCheckedForReadback := spillChecked
  simp only [PreparedDynamicStackRangeSpillClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at spillChecked
  rcases spillChecked with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨_writesExact, _suffixNonStack⟩,
      sourceRelationMember⟩, sourceWindowMember⟩, _targetRelationMember⟩,
      _targetWindowMember⟩, targetWindowExact⟩, targetStackOffsetExact⟩,
      targetOriginalOffsetExact⟩, targetCandidateOffsetExact⟩,
      requiredWordsSubset⟩, sourceActiveWordsSubset⟩, activeWordsSubset⟩
  intro world originalState candidateState originalResult candidateResult related
    originalEval candidateEval guardTrue
  have relatedForShape := related
  have relatedForReadback := related
  rcases shape world originalState candidateState relatedForShape with
    ⟨_guardsAgree, shapeClosed⟩
  rcases shapeClosed guardTrue with
    ⟨shapeOriginalResult, shapeCandidateResult, shapeOriginalEval,
      shapeCandidateEval, shapeOriginalWrites, shapeCandidateWrites,
      _originalExit, _candidateExit, _outcomes⟩
  rw [originalEval] at shapeOriginalEval
  rw [candidateEval] at shapeCandidateEval
  have originalResultExact : originalResult = shapeOriginalResult :=
    Option.some.inj shapeOriginalEval
  have candidateResultExact : candidateResult = shapeCandidateResult :=
    Option.some.inj shapeCandidateEval
  subst shapeOriginalResult
  subst shapeCandidateResult
  have outputBases := basePreserved originalState candidateState originalResult
    candidateResult originalEval candidateEval
  have sourceDynamic := related.activeDynamicRegisterRangesHold context world
    sourceInvariant originalState candidateState
  simp only [activeDynamicRegisterRangeRelationsHold, List.all_eq_true]
    at sourceDynamic
  have sourceRelationHolds := sourceDynamic spillClaim.sourceRelation
    (List.contains_iff_mem.mp sourceRelationMember)
  simp only [DynamicRegisterRangeRelation.activeHolds, List.any_eq_true,
    Bool.and_eq_true, beq_iff_eq] at sourceRelationHolds
  rcases sourceRelationHolds with
    ⟨range, rangeMember,
      ⟨⟨⟨⟨sourceOriginalValue, sourceCandidateValue⟩,
        sourceRequiredWords⟩, _sourceActiveWords⟩, sourceWordsHold⟩⟩
  have readsBack := pairedPreparedWordWritesSpillReadsBack context world
    sourceInvariant targetInvariant writesClaim spillClaim originalState candidateState
    originalResult candidateResult contextValid relatedForReadback writesChecked
    spillCheckedForReadback
    shapeOriginalWrites shapeCandidateWrites
  have writesRows := writesChecked
  simp only [PairedPreparedWordWritesClaim.checked, Bool.and_eq_true] at writesRows
  have stackRangesValid : world.stackRangesValid context = true := related.2.1
  rcases pairedPreparedWordUpdates_of_checkedItems context world sourceInvariant
      writesClaim.writes originalState candidateState stackRangesValid writesRows.2
      related with
    ⟨updates, originalUpdateWrites, candidateUpdateWrites, _updateKinds⟩
  have targetWordsBefore := dynamicWordRequirementsHold_mono context world range
    spillClaim.sourceRelation.activeWords spillClaim.targetRelation.activeWords
    originalState.memory candidateState.memory sourceActiveWordsSubset sourceWordsHold
  have worldDynamicValid : world.dynamicRangesValid context = true := by
    have valid := related.1
    simp only [RelationalWorld.valid, Bool.and_eq_true] at valid
    exact valid.1.1.1.1
  have staticPointerSlotsValid : staticDynamicPointerSlotsValid context = true := by
    rcases contextValid with
      ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _⟩
    exact slotsValid
  have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
    rcases contextValid with
      ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _⟩
    exact slotsValid
  have sourceActiveAvailable : spillClaim.targetRelation.activeWords.all
      range.wordRelations.contains = true := by
    simp only [List.all_eq_true] at sourceRequiredWords requiredWordsSubset activeWordsSubset ⊢
    intro word wordMember
    exact sourceRequiredWords word
      (List.contains_iff_mem.mp (requiredWordsSubset word
        (List.contains_iff_mem.mp (activeWordsSubset word wordMember))))
  have outputWords := dynamicWordRequirementsHold_after_prepared_updates
    context world range spillClaim.targetRelation.activeWords originalState.memory
    candidateState.memory updates worldDynamicValid staticPointerSlotsValid
    staticWordSlotsValid rangeMember sourceActiveAvailable targetWordsBefore
  rw [originalUpdateWrites, candidateUpdateWrites] at outputWords
  have outputWordsExact : dynamicWordRequirementsHold context world range
      spillClaim.targetRelation.activeWords
      (originalResult.nextMachineState originalState).memory
      (candidateResult.nextMachineState candidateState).memory = true := by
    simpa [RelationalBehavior.nextMachineState, shapeOriginalWrites,
      shapeCandidateWrites] using outputWords
  rw [targetInventory]
  simp only [activeDynamicStackRangeRelationsHold, List.all_cons, List.all_nil,
    Bool.and_true]
  unfold DynamicStackRangeRelation.activeHolds
  simp only [Bool.and_eq_true, List.any_eq_true, beq_iff_eq]
  refine ⟨?_, range, rangeMember, ?_⟩
  · rw [targetWindowExact]
    have sourceWindows := relatedForReadback
    rcases sourceWindows with
      ⟨_, _, _, _, _, _, _, _, sourceCore, _⟩
    have sourceWindowRelations := sourceCore.2.2.2.1
    simp only [stackWindowsRelated, List.all_eq_true] at sourceWindowRelations
    have sourceWindowHolds := sourceWindowRelations spillClaim.window
      (List.contains_iff_mem.mp sourceWindowMember)
    change spillClaim.window.holds world originalResult.registers
      candidateResult.registers = true
    unfold StackWindowPair.holds
    rw [outputBases.1, outputBases.2]
    simpa only [StackWindowPair.holds] using sourceWindowHolds
  · refine ⟨⟨⟨⟨?_, ?_⟩, ?_⟩, activeWordsSubset⟩, outputWordsExact⟩
    · rw [targetWindowExact, targetStackOffsetExact]
      change Memory.read32 (originalResult.nextMachineState originalState).memory
        (originalResult.registers.get spillClaim.window.originalRegister +
          BitVec.ofNat 32 spillClaim.amount) = _
      rw [outputBases.1, readsBack.1,
        sourceOriginalValue, targetOriginalOffsetExact]
    · rw [targetWindowExact, targetStackOffsetExact]
      change Memory.read32 (candidateResult.nextMachineState candidateState).memory
        (candidateResult.registers.get spillClaim.window.candidateRegister +
          BitVec.ofNat 32 spillClaim.amount) = _
      rw [outputBases.2, readsBack.2,
        sourceCandidateValue, targetCandidateOffsetExact]
    · simp only [List.all_eq_true] at sourceRequiredWords requiredWordsSubset ⊢
      intro word targetWordMember
      exact sourceRequiredWords word
        (List.contains_iff_mem.mp (requiredWordsSubset word targetWordMember))

theorem StateRel.afterNoWriteEvaluation
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (originalWrites : originalBehavior.writes = [])
    (candidateWrites : candidateBehavior.writes = [])
    (registers : registerRelationsHold context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world) targetInvariant.registerRelations
      originalBehavior.registers candidateBehavior.registers = true)
    (bounds : boundsRelated targetInvariant.bounds originalBehavior.registers
      candidateBehavior.registers = true)
    (separations : addressSeparationsRelated targetInvariant.addressSeparations
      originalBehavior.registers candidateBehavior.registers = true)
    (stackWindows : stackWindowsRelated world targetInvariant.stackWindows
      originalBehavior.registers candidateBehavior.registers = true)
    (x87 : (originalBehavior.nextMachineState originalState).x87 =
      (candidateBehavior.nextMachineState candidateState).x87)
    (flags : flagsRelated targetInvariant.flagBits originalBehavior.eflags
      candidateBehavior.eflags = true)
    (importRegisters : importRegisterRelationsHold world
      targetInvariant.importRegisterRelations originalBehavior.registers
      candidateBehavior.registers = true)
    (dynamicRegisters : activeDynamicRegisterRangeRelationsHold context world
      targetInvariant.dynamicRegisterRangeRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (dynamicStacks : activeDynamicStackRangeRelationsHold context world
      targetInvariant.dynamicStackRangeRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true) :
    StateRel context world targetInvariant
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) := by
  rcases related with
    ⟨worldStatic, stackRangesValid, stackMemory, importsStatic, importsComplete,
      importsMemory, originalImmutable, candidateImmutable, relatedCore,
      _inputImportRegisters⟩
  rcases relatedCore with
    ⟨_, _, _, _, inputMemory, inputDynamicWords, inputUndefined, _, _, inputFsBase⟩
  refine ⟨worldStatic, stackRangesValid, ?_, importsStatic, importsComplete,
    ?_, ?_, ?_, ?_, ?_⟩
  · simpa [RelationalBehavior.nextMachineState, originalWrites,
      candidateWrites] using stackMemory
  · simpa [RelationalBehavior.nextMachineState, originalWrites,
      candidateWrites] using importsMemory
  · simpa [RelationalBehavior.nextMachineState, originalWrites] using originalImmutable
  · simpa [RelationalBehavior.nextMachineState, candidateWrites] using candidateImmutable
  · refine ⟨registers, bounds, separations, stackWindows, ?_, ?_, ?_, x87, ?_, ?_⟩
    · simpa [RelationalBehavior.nextMachineState, originalWrites,
        candidateWrites] using
        ordinaryMemoryRelated_after_no_writes context world
          context.codeMap.entries.toList (context.relationalValueTargets world)
          originalState.memory candidateState.memory inputMemory
    · let originalNext := originalBehavior.nextMachineState originalState
      let candidateNext := candidateBehavior.nextMachineState candidateState
      have outputDynamicRegisters : activeDynamicRegisterRangeRelationsHold
          context world targetInvariant.dynamicRegisterRangeRelations originalNext
          candidateNext = true := by
        simpa [originalNext, candidateNext] using dynamicRegisters
      have outputDynamicStacks : activeDynamicStackRangeRelationsHold context world
          targetInvariant.dynamicStackRangeRelations originalNext candidateNext = true := by
        simpa [originalNext, candidateNext] using dynamicStacks
      exact {
        staticPointerSlots := by
          simpa [originalNext, candidateNext, RelationalBehavior.nextMachineState,
            originalWrites, candidateWrites] using inputDynamicWords.staticPointerSlots
        staticWordSlots := by
          simpa [originalNext, candidateNext, RelationalBehavior.nextMachineState,
            originalWrites, candidateWrites] using inputDynamicWords.staticWordSlots
        active := {
          registerRanges := outputDynamicRegisters
          stackRanges := outputDynamicStacks
        }
      }
    · simpa [RelationalBehavior.nextMachineState] using inputUndefined
    · simpa [RelationalBehavior.nextMachineState] using flags
    · simpa [RelationalBehavior.nextMachineState] using inputFsBase
  · exact ⟨by simpa [RelationalBehavior.nextMachineState] using importRegisters,
      dynamicRegisterRangeRelationsHold_of_active context world
        targetInvariant.dynamicRegisterRangeRelations _ _ dynamicRegisters,
      dynamicStackRangeRelationsHold_of_active context world
        targetInvariant.dynamicStackRangeRelations _ _ dynamicStacks⟩

theorem StateRel.afterPairedMemoryFamiliesUpdate
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (originalWrites candidateWrites : List (Word × Word))
    (related : StateRel context world sourceInvariant originalState candidateState)
    (originalWritesExact : originalBehavior.writes = originalWrites)
    (candidateWritesExact : candidateBehavior.writes = candidateWrites)
    (memoryFamilies : RelationalMemoryFamiliesHold context world
      (applyConcreteWrites originalState.memory originalWrites)
      (applyConcreteWrites candidateState.memory candidateWrites))
    (registers : registerRelationsHold context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world) targetInvariant.registerRelations
      originalBehavior.registers candidateBehavior.registers = true)
    (bounds : boundsRelated targetInvariant.bounds originalBehavior.registers
      candidateBehavior.registers = true)
    (separations : addressSeparationsRelated targetInvariant.addressSeparations
      originalBehavior.registers candidateBehavior.registers = true)
    (stackWindows : stackWindowsRelated world targetInvariant.stackWindows
      originalBehavior.registers candidateBehavior.registers = true)
    (x87 : (originalBehavior.nextMachineState originalState).x87 =
      (candidateBehavior.nextMachineState candidateState).x87)
    (flags : flagsRelated targetInvariant.flagBits originalBehavior.eflags
      candidateBehavior.eflags = true)
    (importRegisters : importRegisterRelationsHold world
      targetInvariant.importRegisterRelations originalBehavior.registers
      candidateBehavior.registers = true)
    (dynamicRegisters : activeDynamicRegisterRangeRelationsHold context world
      targetInvariant.dynamicRegisterRangeRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (dynamicStacks : activeDynamicStackRangeRelationsHold context world
      targetInvariant.dynamicStackRangeRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true) :
    StateRel context world targetInvariant
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) := by
  rcases related with
    ⟨worldStatic, stackRangesValid, _stackMemory, importsStatic, importsComplete,
      _importsMemory, _originalImmutable, _candidateImmutable, relatedCore,
      _inputImportRegisters⟩
  rcases relatedCore with
    ⟨_, _, _, _, _inputMemory, _inputDynamicWords, inputUndefined, _, _,
      inputFsBase⟩
  refine ⟨worldStatic, stackRangesValid, ?_, importsStatic, importsComplete,
    ?_, ?_, ?_, ?_, ?_⟩
  · simpa [RelationalBehavior.nextMachineState, originalWritesExact,
      candidateWritesExact] using memoryFamilies.stackRanges
  · simpa [RelationalBehavior.nextMachineState, originalWritesExact,
      candidateWritesExact] using memoryFamilies.importAddresses
  · simpa [RelationalBehavior.nextMachineState, originalWritesExact] using
      memoryFamilies.originalImmutable
  · simpa [RelationalBehavior.nextMachineState, candidateWritesExact] using
      memoryFamilies.candidateImmutable
  · refine ⟨registers, bounds, separations, stackWindows, ?_, ?_, ?_, x87, ?_, ?_⟩
    · simpa [RelationalBehavior.nextMachineState, originalWritesExact,
        candidateWritesExact] using memoryFamilies.ordinary
    · let originalNext := originalBehavior.nextMachineState originalState
      let candidateNext := candidateBehavior.nextMachineState candidateState
      have outputDynamicRegisters : activeDynamicRegisterRangeRelationsHold
          context world targetInvariant.dynamicRegisterRangeRelations originalNext
          candidateNext = true := by
        simpa [originalNext, candidateNext] using dynamicRegisters
      have outputDynamicStacks : activeDynamicStackRangeRelationsHold context world
          targetInvariant.dynamicStackRangeRelations originalNext candidateNext = true := by
        simpa [originalNext, candidateNext] using dynamicStacks
      exact {
        staticPointerSlots := by
          simpa [originalNext, candidateNext, RelationalBehavior.nextMachineState,
            originalWritesExact, candidateWritesExact] using
            memoryFamilies.staticPointerSlots
        staticWordSlots := by
          simpa [originalNext, candidateNext, RelationalBehavior.nextMachineState,
            originalWritesExact, candidateWritesExact] using
            memoryFamilies.staticWordSlots
        active := {
          registerRanges := outputDynamicRegisters
          stackRanges := outputDynamicStacks
        }
      }
    · simpa [RelationalBehavior.nextMachineState] using inputUndefined
    · simpa [RelationalBehavior.nextMachineState] using flags
    · simpa [RelationalBehavior.nextMachineState] using inputFsBase
  · exact ⟨by simpa [RelationalBehavior.nextMachineState] using importRegisters,
      dynamicRegisterRangeRelationsHold_of_active context world
        targetInvariant.dynamicRegisterRangeRelations _ _ dynamicRegisters,
      dynamicStackRangeRelationsHold_of_active context world
        targetInvariant.dynamicStackRangeRelations _ _ dynamicStacks⟩

theorem segmentTransitionClosed_of_no_write_with_transfers
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (shape : NoWriteSegmentShapeClosed context edge sourceInvariant
      originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicStackTransfer : NoWriteSegmentDynamicStackTransferClosed context edge
      sourceInvariant targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  unfold SegmentTransitionClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  unfold NoWriteSegmentShapeClosed at shape
  rw [localCodeTargetsResolved, localValuesResolved] at shape
  unfold NoWriteSegmentStateTransferClosed at stateTransfer
  rw [localCodeTargetsResolved] at stateTransfer
  unfold NoWriteSegmentImportTransferClosed at importTransfer
  rw [localCodeTargetsResolved] at importTransfer
  unfold NoWriteSegmentDynamicTransferClosed at dynamicTransfer
  rw [localCodeTargetsResolved] at dynamicTransfer
  unfold NoWriteSegmentDynamicStackTransferClosed at dynamicStackTransfer
  rw [localCodeTargetsResolved] at dynamicStackTransfer
  intro world originalState candidateState related
  have relatedForShape := related
  have relatedForTransfer := related
  have relatedForImports := related
  have relatedForDynamic := related
  rcases shape world originalState candidateState relatedForShape with
    ⟨guardsAgree, shapeClosed⟩
  refine ⟨guardsAgree, ?_⟩
  intro guardTrue
  rcases shapeClosed guardTrue with
    ⟨originalResult, candidateResult, originalEval, candidateEval, originalWrites,
      candidateWrites, originalExit, candidateExit, outcomes⟩
  rw [originalEval, candidateEval]
  refine ⟨originalExit, candidateExit, outcomes, ?_⟩
  cases edge.exit with
  | internal target =>
      rcases stateTransfer world originalState candidateState originalResult
          candidateResult related originalEval candidateEval guardTrue with
        ⟨registers, bounds, separations, stackWindows, x87, flags⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      have outputDynamicStack := dynamicStackTransfer world originalState candidateState
        originalResult candidateResult related originalEval candidateEval guardTrue
      exact StateRel.afterNoWriteEvaluation context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        relatedForTransfer originalWrites candidateWrites registers bounds separations
        stackWindows x87 flags outputImports outputDynamic outputDynamicStack
  | external imported => trivial
  | returned => trivial
  | fault => trivial

theorem segmentTransitionClosed_of_direct_call_with_transfers
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (sourceWindow : StackWindowPair) (stackAmount : Nat)
    (originalReturnAddress candidateReturnAddress : Word)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : sourceWindow ∈ sourceInvariant.stackWindows)
    (stackAmountAtLeastWord : 4 <= stackAmount)
    (stackAmountAligned : stackAmount % 4 = 0)
    (sourceWindowEnoughBelow : stackAmount <= sourceWindow.bytesBelow)
    (returnAddressesRelated : ∀ world,
      wordRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        originalReturnAddress candidateReturnAddress = true)
    (shape : DirectCallSegmentShapeClosed context edge sourceInvariant sourceWindow
      stackAmount originalReturnAddress candidateReturnAddress originalBehavior
      candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicStackTransfer : NoWriteSegmentDynamicStackTransferClosed context edge
      sourceInvariant targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  unfold SegmentTransitionClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  unfold DirectCallSegmentShapeClosed at shape
  rw [localCodeTargetsResolved, localValuesResolved] at shape
  unfold NoWriteSegmentStateTransferClosed at stateTransfer
  rw [localCodeTargetsResolved] at stateTransfer
  unfold NoWriteSegmentImportTransferClosed at importTransfer
  rw [localCodeTargetsResolved] at importTransfer
  unfold NoWriteSegmentDynamicTransferClosed at dynamicTransfer
  rw [localCodeTargetsResolved] at dynamicTransfer
  unfold NoWriteSegmentDynamicStackTransferClosed at dynamicStackTransfer
  rw [localCodeTargetsResolved] at dynamicStackTransfer
  intro world originalState candidateState related
  have relatedForShape := related
  have relatedForTransfer := related
  have relatedForImports := related
  have relatedForDynamic := related
  have relatedForDynamicStack := related
  rcases shape world originalState candidateState relatedForShape with
    ⟨guardsAgree, shapeClosed⟩
  refine ⟨guardsAgree, ?_⟩
  intro guardTrue
  rcases shapeClosed guardTrue with
    ⟨originalResult, candidateResult, originalEval, candidateEval,
      originalWrites, candidateWrites, originalExit, candidateExit, outcomes⟩
  rw [originalEval, candidateEval]
  refine ⟨originalExit, candidateExit, outcomes, ?_⟩
  cases edge.exit with
  | internal target =>
      rcases relatedForTransfer with
        ⟨worldValid, stackRangesValid, stackMemory, importsStatic, _importsComplete,
          importsMemory, originalImmutable, candidateImmutable, relatedCore,
          _inputImportRegisters⟩
      rcases relatedCore with
        ⟨_, _, _, inputStackWindows, inputMemory, inputDynamicMemory,
          _inputUndefined, _, _, _inputFsBase⟩
      simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
      have sourceWindowHolds := inputStackWindows sourceWindow sourceWindowMember
      rcases pairedStackWordLocation_below_window_amount context world sourceWindow
          originalState.registers candidateState.registers stackRangesValid
          sourceWindowHolds stackAmount stackAmountAtLeastWord stackAmountAligned
          sourceWindowEnoughBelow with
        ⟨location, originalLocation, candidateLocation⟩
      have originalWriteAddress :
          originalState.registers.get sourceWindow.originalRegister -
              BitVec.ofNat 32 stackAmount =
            location.range.originalBase + BitVec.ofNat 32 location.offset :=
        originalLocation.symm.trans location.originalAddressExact
      have candidateWriteAddress :
          candidateState.registers.get sourceWindow.candidateRegister -
              BitVec.ofNat 32 stackAmount =
            location.range.candidateBase + BitVec.ofNat 32 location.offset :=
        candidateLocation.symm.trans location.candidateAddressExact
      have locationValid : location.range.disjointFromImages context = true := by
        have validRows := stackRangesValid
        simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
          List.all_eq_true] at validRows
        exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
      have worldDynamicValid : world.dynamicRangesValid context = true := by
        have valid := worldValid
        simp only [RelationalWorld.valid, Bool.and_eq_true] at valid
        exact valid.1.1.1.1
      have staticSlotsValid : staticDynamicPointerSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _⟩
        exact slotsValid
      have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _⟩
        exact slotsValid
      have outputMemoryFamilies :=
        RelationalMemoryFamiliesHold.afterPairedStackWordWrite context world
          originalState.memory candidateState.memory stackRangesValid importsStatic
          worldDynamicValid staticSlotsValid staticWordSlotsValid location locationValid
          originalReturnAddress
          candidateReturnAddress (returnAddressesRelated world) {
            stackRanges := stackMemory
            importAddresses := importsMemory
            originalImmutable := originalImmutable
            candidateImmutable := candidateImmutable
            ordinary := inputMemory
            staticPointerSlots := inputDynamicMemory.staticPointerSlots
            staticWordSlots := inputDynamicMemory.staticWordSlots
          }
      rw [location.originalAddressExact, location.candidateAddressExact]
        at outputMemoryFamilies
      rcases stateTransfer world originalState candidateState originalResult
          candidateResult related originalEval candidateEval guardTrue with
        ⟨registers, bounds, separations, stackWindows, x87, flags⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      have outputDynamicStack := dynamicStackTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamicStack originalEval candidateEval
        guardTrue
      apply StateRel.afterPairedMemoryFamiliesUpdate context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        [(originalState.registers.get sourceWindow.originalRegister -
            BitVec.ofNat 32 stackAmount,
          originalReturnAddress)]
        [(candidateState.registers.get sourceWindow.candidateRegister -
            BitVec.ofNat 32 stackAmount,
          candidateReturnAddress)] related originalWrites candidateWrites
      · simpa [applyConcreteWrites, originalWriteAddress, candidateWriteAddress] using
          outputMemoryFamilies
      · exact registers
      · exact bounds
      · exact separations
      · exact stackWindows
      · exact x87
      · exact flags
      · exact outputImports
      · exact outputDynamic
      · exact outputDynamicStack
  | external imported => trivial
  | returned => trivial
  | fault => trivial

theorem segmentTransitionClosed_of_paired_stack_word_write_with_transfers
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : PairedStackWordWriteClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : claim.window ∈ sourceInvariant.stackWindows)
    (claimChecked :
      claim.checked context sourceInvariant originalNormalized candidateNormalized = true)
    (shape : PairedStackWordWriteSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicStackTransfer : NoWriteSegmentDynamicStackTransferClosed context edge
      sourceInvariant targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  unfold SegmentTransitionClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  unfold PairedStackWordWriteSegmentShapeClosed at shape
  rw [localCodeTargetsResolved, localValuesResolved] at shape
  unfold NoWriteSegmentStateTransferClosed at stateTransfer
  rw [localCodeTargetsResolved] at stateTransfer
  unfold NoWriteSegmentImportTransferClosed at importTransfer
  rw [localCodeTargetsResolved] at importTransfer
  unfold NoWriteSegmentDynamicTransferClosed at dynamicTransfer
  rw [localCodeTargetsResolved] at dynamicTransfer
  unfold NoWriteSegmentDynamicStackTransferClosed at dynamicStackTransfer
  rw [localCodeTargetsResolved] at dynamicStackTransfer
  have claimCheckedForValue := claimChecked
  simp only [PairedStackWordWriteClaim.checked, Bool.and_eq_true,
    beq_iff_eq, decide_eq_true_eq] at claimChecked
  have amountAligned := claimChecked.1.1.1.1
  have enoughAbove := claimChecked.1.1.1.2
  intro world originalState candidateState related
  have relatedForShape := related
  have relatedForMemory := related
  have relatedForImports := related
  have relatedForDynamic := related
  have relatedForDynamicStack := related
  rcases shape world originalState candidateState relatedForShape with
    ⟨guardsAgree, shapeClosed⟩
  refine ⟨guardsAgree, ?_⟩
  intro guardTrue
  rcases shapeClosed guardTrue with
    ⟨originalResult, candidateResult, originalEval, candidateEval,
      originalWrites, candidateWrites, originalExit, candidateExit, outcomes⟩
  rw [originalEval, candidateEval]
  refine ⟨originalExit, candidateExit, outcomes, ?_⟩
  cases edge.exit with
  | internal target =>
      rcases relatedForMemory with
        ⟨worldValid, stackRangesValid, stackMemory, importsStatic, _importsComplete,
          importsMemory, originalImmutable, candidateImmutable, relatedCore,
          _inputImportRegisters⟩
      rcases relatedCore with
        ⟨_, _, _, inputStackWindows, inputMemory, inputDynamicMemory,
          _inputUndefined, _, _, _inputFsBase⟩
      simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
      have sourceWindowHolds := inputStackWindows claim.window sourceWindowMember
      rcases pairedStackWordLocation_above_window context world claim.window
          originalState.registers candidateState.registers stackRangesValid
          sourceWindowHolds claim.amount amountAligned enoughAbove with
        ⟨location, originalLocation, candidateLocation⟩
      have originalWriteAddress :
          claim.originalAddress.eval originalState =
            location.range.originalBase + BitVec.ofNat 32 location.offset := by
        simpa [PairedStackWordWriteClaim.originalAddress, Expr.eval] using
          originalLocation.symm.trans location.originalAddressExact
      have candidateWriteAddress :
          claim.candidateAddress.eval candidateState =
            location.range.candidateBase + BitVec.ofNat 32 location.offset := by
        simpa [PairedStackWordWriteClaim.candidateAddress, Expr.eval] using
          candidateLocation.symm.trans location.candidateAddressExact
      have locationValid : location.range.disjointFromImages context = true := by
        have validRows := stackRangesValid
        simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
          List.all_eq_true] at validRows
        exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
      have worldDynamicValid : world.dynamicRangesValid context = true := by
        have valid := worldValid
        simp only [RelationalWorld.valid, Bool.and_eq_true] at valid
        exact valid.1.1.1.1
      have staticSlotsValid : staticDynamicPointerSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _⟩
        exact slotsValid
      have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _⟩
        exact slotsValid
      have valuesRelated := claim.valueRelated_of_checked context world
        sourceInvariant originalNormalized candidateNormalized claimCheckedForValue
        originalState candidateState related
      have outputMemoryFamilies :=
        RelationalMemoryFamiliesHold.afterPairedStackWordWrite context world
          originalState.memory candidateState.memory stackRangesValid importsStatic
          worldDynamicValid staticSlotsValid staticWordSlotsValid location locationValid
          (claim.value.original.eval originalState)
          (claim.value.candidate.eval candidateState)
          valuesRelated {
            stackRanges := stackMemory
            importAddresses := importsMemory
            originalImmutable := originalImmutable
            candidateImmutable := candidateImmutable
            ordinary := inputMemory
            staticPointerSlots := inputDynamicMemory.staticPointerSlots
            staticWordSlots := inputDynamicMemory.staticWordSlots
          }
      rw [location.originalAddressExact, location.candidateAddressExact]
        at outputMemoryFamilies
      rcases stateTransfer world originalState candidateState originalResult
          candidateResult related originalEval candidateEval guardTrue with
        ⟨registers, bounds, separations, stackWindows, x87, flags⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      have outputDynamicStack := dynamicStackTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamicStack originalEval candidateEval
        guardTrue
      apply StateRel.afterPairedMemoryFamiliesUpdate context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        [(claim.originalAddress.eval originalState,
          claim.value.original.eval originalState)]
        [(claim.candidateAddress.eval candidateState,
          claim.value.candidate.eval candidateState)]
        related originalWrites candidateWrites
      · simpa [applyConcreteWrites, originalWriteAddress, candidateWriteAddress] using
          outputMemoryFamilies
      · exact registers
      · exact bounds
      · exact separations
      · exact stackWindows
      · exact x87
      · exact flags
      · exact outputImports
      · exact outputDynamic
      · exact outputDynamicStack
  | external imported => trivial
  | returned => trivial
  | fault => trivial

theorem segmentTransitionClosed_of_paired_stack_word_write_with_spill
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (writeClaim : PairedStackWordWriteClaim)
    (spillClaim : DynamicStackRangeSpillClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : writeClaim.window ∈ sourceInvariant.stackWindows)
    (writeClaimChecked :
      writeClaim.checked context sourceInvariant originalNormalized
        candidateNormalized = true)
    (spillClaimChecked :
      spillClaim.checked sourceInvariant targetInvariant writeClaim = true)
    (targetInventory :
      targetInvariant.dynamicStackRangeRelations = [spillClaim.targetRelation])
    (shape : PairedStackWordWriteSegmentShapeClosed context edge sourceInvariant
      writeClaim originalBehavior candidateBehavior)
    (basePreserved : PairedStackWordWriteOutputBasePreserved context edge
      writeClaim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_paired_stack_word_write_with_transfers context edge
    sourceInvariant targetInvariant writeClaim originalBehavior candidateBehavior
    originalNormalized candidateNormalized localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved contextValid sourceWindowMember
    writeClaimChecked shape stateTransfer importTransfer dynamicTransfer
  exact noWriteSegmentDynamicStackTransferClosed_of_spill context edge
    sourceInvariant targetInvariant writeClaim spillClaim originalBehavior
    candidateBehavior originalNormalized candidateNormalized localCodeTargets
    localValues localCodeTargetsResolved localValuesResolved writeClaimChecked
    spillClaimChecked targetInventory shape basePreserved

theorem segmentTransitionClosed_of_paired_stack_word_writes_with_transfers
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : PairedStackWordWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : claim.window ∈ sourceInvariant.stackWindows)
    (claimChecked :
      claim.checked context sourceInvariant originalNormalized candidateNormalized = true)
    (shape : PairedStackWordWritesSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = []) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  unfold SegmentTransitionClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  unfold PairedStackWordWritesSegmentShapeClosed at shape
  rw [localCodeTargetsResolved, localValuesResolved] at shape
  unfold NoWriteSegmentStateTransferClosed at stateTransfer
  rw [localCodeTargetsResolved] at stateTransfer
  unfold NoWriteSegmentImportTransferClosed at importTransfer
  rw [localCodeTargetsResolved] at importTransfer
  unfold NoWriteSegmentDynamicTransferClosed at dynamicTransfer
  rw [localCodeTargetsResolved] at dynamicTransfer
  simp only [PairedStackWordWritesClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at claimChecked
  have itemsChecked := claimChecked.1.1.2
  intro world originalState candidateState related
  have relatedForShape := related
  have relatedForMemory := related
  have relatedForImports := related
  have relatedForDynamic := related
  rcases shape world originalState candidateState relatedForShape with
    ⟨guardsAgree, shapeClosed⟩
  refine ⟨guardsAgree, ?_⟩
  intro guardTrue
  rcases shapeClosed guardTrue with
    ⟨originalResult, candidateResult, originalEval, candidateEval,
      originalWrites, candidateWrites, originalExit, candidateExit, outcomes⟩
  rw [originalEval, candidateEval]
  refine ⟨originalExit, candidateExit, outcomes, ?_⟩
  cases edge.exit with
  | internal target =>
      rcases relatedForMemory with
        ⟨worldValid, stackRangesValid, stackMemory, importsStatic, _importsComplete,
          importsMemory, originalImmutable, candidateImmutable, relatedCore,
          _inputImportRegisters⟩
      rcases relatedCore with
        ⟨_, _, _, inputStackWindows, inputMemory, inputDynamicMemory,
          _inputUndefined, _, _, _inputFsBase⟩
      simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
      have sourceWindowHolds := inputStackWindows claim.window sourceWindowMember
      rcases pairedStackWordUpdates_of_checkedItems context world sourceInvariant
          claim.window claim.writes originalState candidateState stackRangesValid
          sourceWindowHolds itemsChecked related with
        ⟨updates, originalUpdateWrites, candidateUpdateWrites⟩
      change updates.map PairedStackWordUpdate.originalWrite =
        claim.originalWrites originalState at originalUpdateWrites
      change updates.map PairedStackWordUpdate.candidateWrite =
        claim.candidateWrites candidateState at candidateUpdateWrites
      have worldDynamicValid : world.dynamicRangesValid context = true := by
        have valid := worldValid
        simp only [RelationalWorld.valid, Bool.and_eq_true] at valid
        exact valid.1.1.1.1
      have staticSlotsValid : staticDynamicPointerSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _⟩
        exact slotsValid
      have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _⟩
        exact slotsValid
      have outputMemoryFamilies :=
        RelationalMemoryFamiliesHold.afterPairedStackWordUpdates context world
          stackRangesValid importsStatic worldDynamicValid staticSlotsValid
          staticWordSlotsValid updates
          originalState.memory candidateState.memory {
            stackRanges := stackMemory
            importAddresses := importsMemory
            originalImmutable := originalImmutable
            candidateImmutable := candidateImmutable
            ordinary := inputMemory
            staticPointerSlots := inputDynamicMemory.staticPointerSlots
            staticWordSlots := inputDynamicMemory.staticWordSlots
          }
      rw [originalUpdateWrites, candidateUpdateWrites] at outputMemoryFamilies
      rcases stateTransfer world originalState candidateState originalResult
          candidateResult related originalEval candidateEval guardTrue with
        ⟨registers, bounds, separations, stackWindows, x87, flags⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      apply StateRel.afterPairedMemoryFamiliesUpdate context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        (claim.originalWrites originalState) (claim.candidateWrites candidateState)
        related originalWrites candidateWrites outputMemoryFamilies registers bounds
        separations stackWindows x87 flags outputImports outputDynamic
        (by simp [targetDynamicStackRelationsEmpty, activeDynamicStackRangeRelationsHold])
  | external imported => trivial
  | returned => trivial
  | fault => trivial

theorem segmentTransitionClosed_of_paired_prepared_word_writes_with_transfers
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : PairedPreparedWordWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (claimChecked : claim.checked context sourceInvariant = true)
    (shape : PairedPreparedWordWritesSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicStackTransfer : NoWriteSegmentDynamicStackTransferClosed context edge
      sourceInvariant targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  unfold SegmentTransitionClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  unfold PairedPreparedWordWritesSegmentShapeClosed at shape
  rw [localCodeTargetsResolved, localValuesResolved] at shape
  unfold NoWriteSegmentStateTransferClosed at stateTransfer
  rw [localCodeTargetsResolved] at stateTransfer
  unfold NoWriteSegmentImportTransferClosed at importTransfer
  rw [localCodeTargetsResolved] at importTransfer
  unfold NoWriteSegmentDynamicTransferClosed at dynamicTransfer
  rw [localCodeTargetsResolved] at dynamicTransfer
  unfold NoWriteSegmentDynamicStackTransferClosed at dynamicStackTransfer
  rw [localCodeTargetsResolved] at dynamicStackTransfer
  simp only [PairedPreparedWordWritesClaim.checked, Bool.and_eq_true]
    at claimChecked
  have itemsChecked := claimChecked.2
  intro world originalState candidateState related
  have relatedForShape := related
  have relatedForMemory := related
  have relatedForImports := related
  have relatedForDynamic := related
  have relatedForDynamicStack := related
  rcases shape world originalState candidateState relatedForShape with
    ⟨guardsAgree, shapeClosed⟩
  refine ⟨guardsAgree, ?_⟩
  intro guardTrue
  rcases shapeClosed guardTrue with
    ⟨originalResult, candidateResult, originalEval, candidateEval,
      originalWrites, candidateWrites, originalExit, candidateExit, outcomes⟩
  rw [originalEval, candidateEval]
  refine ⟨originalExit, candidateExit, outcomes, ?_⟩
  cases edge.exit with
  | internal target =>
      rcases relatedForMemory with
        ⟨worldValid, stackRangesValid, stackMemory, importsStatic, _importsComplete,
          importsMemory, originalImmutable, candidateImmutable, relatedCore,
          _inputImportRegisters⟩
      rcases relatedCore with
        ⟨_, _, _, _inputStackWindows, inputMemory, inputDynamicMemory,
          _inputUndefined, _, _, _inputFsBase⟩
      rcases pairedPreparedWordUpdates_of_checkedItems context world sourceInvariant
          claim.writes originalState candidateState stackRangesValid itemsChecked related with
        ⟨updates, originalUpdateWrites, candidateUpdateWrites, _updateKinds⟩
      change updates.map PairedPreparedWordUpdate.originalWrite =
        claim.originalWrites originalState at originalUpdateWrites
      change updates.map PairedPreparedWordUpdate.candidateWrite =
        claim.candidateWrites candidateState at candidateUpdateWrites
      have worldDynamicValid : world.dynamicRangesValid context = true := by
        have valid := worldValid
        simp only [RelationalWorld.valid, Bool.and_eq_true] at valid
        exact valid.1.1.1.1
      have staticSlotsValid : staticDynamicPointerSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _⟩
        exact slotsValid
      have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _⟩
        exact slotsValid
      have outputMemoryFamilies :=
        RelationalMemoryFamiliesHold.afterPairedPreparedWordUpdates context world
          stackRangesValid importsStatic worldDynamicValid staticSlotsValid
          staticWordSlotsValid updates originalState.memory candidateState.memory {
            stackRanges := stackMemory
            importAddresses := importsMemory
            originalImmutable := originalImmutable
            candidateImmutable := candidateImmutable
            ordinary := inputMemory
            staticPointerSlots := inputDynamicMemory.staticPointerSlots
            staticWordSlots := inputDynamicMemory.staticWordSlots
          }
      rw [originalUpdateWrites, candidateUpdateWrites] at outputMemoryFamilies
      rcases stateTransfer world originalState candidateState originalResult
          candidateResult related originalEval candidateEval guardTrue with
        ⟨registers, bounds, separations, stackWindows, x87, flags⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      have outputDynamicStack := dynamicStackTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamicStack originalEval candidateEval
        guardTrue
      apply StateRel.afterPairedMemoryFamiliesUpdate context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        (claim.originalWrites originalState) (claim.candidateWrites candidateState)
        related originalWrites candidateWrites outputMemoryFamilies registers bounds
        separations stackWindows x87 flags outputImports outputDynamic outputDynamicStack
  | external imported => trivial
  | returned => trivial
  | fault => trivial

theorem segmentTransitionClosed_of_direct_call_stack_writes_with_transfers
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : DirectCallStackWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : claim.stackWrites.window ∈ sourceInvariant.stackWindows)
    (claimChecked :
      claim.checked context sourceInvariant originalNormalized candidateNormalized = true)
    (shape : DirectCallStackWritesSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = []) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  unfold SegmentTransitionClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  unfold DirectCallStackWritesSegmentShapeClosed at shape
  rw [localCodeTargetsResolved, localValuesResolved] at shape
  unfold NoWriteSegmentStateTransferClosed at stateTransfer
  rw [localCodeTargetsResolved] at stateTransfer
  unfold NoWriteSegmentImportTransferClosed at importTransfer
  rw [localCodeTargetsResolved] at importTransfer
  unfold NoWriteSegmentDynamicTransferClosed at dynamicTransfer
  rw [localCodeTargetsResolved] at dynamicTransfer
  simp only [DirectCallStackWritesClaim.checked, Bool.and_eq_true] at claimChecked
  have preparedAndFrame := claimChecked.1
  have preparedChecked := preparedAndFrame.1
  have frameChecked := preparedAndFrame.2
  simp only [DirectCallStackWritesClaim.preparedWritesChecked, Bool.and_eq_true]
    at preparedChecked
  have itemsChecked := preparedChecked.2
  simp only [DirectCallStackWritesClaim.frameChecked, Bool.and_eq_true,
    decide_eq_true_eq, beq_iff_eq] at frameChecked
  rcases frameChecked with
    ⟨⟨⟨⟨⟨⟨stackAtLeast, stackAligned⟩, stackFits⟩, enoughBelow⟩,
      _calleePresent⟩, continuationPair⟩, zeroAgreement⟩
  intro world originalState candidateState related
  have relatedForShape := related
  have relatedForMemory := related
  have relatedForImports := related
  have relatedForDynamic := related
  rcases shape world originalState candidateState relatedForShape with
    ⟨guardsAgree, shapeClosed⟩
  refine ⟨guardsAgree, ?_⟩
  intro guardTrue
  rcases shapeClosed guardTrue with
    ⟨originalResult, candidateResult, originalEval, candidateEval,
      originalWrites, candidateWrites, originalExit, candidateExit, outcomes⟩
  rw [originalEval, candidateEval]
  refine ⟨originalExit, candidateExit, outcomes, ?_⟩
  cases edge.exit with
  | internal target =>
      rcases relatedForMemory with
        ⟨worldValid, stackRangesValid, stackMemory, importsStatic, _importsComplete,
          importsMemory, originalImmutable, candidateImmutable, relatedCore,
          _inputImportRegisters⟩
      rcases relatedCore with
        ⟨_, _, _, inputStackWindows, inputMemory, inputDynamicMemory,
          _inputUndefined, _, _, _inputFsBase⟩
      simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
      have sourceWindowHolds :=
        inputStackWindows claim.stackWrites.window sourceWindowMember
      rcases pairedStackWordUpdates_of_checkedItems context world sourceInvariant
          claim.stackWrites.window claim.stackWrites.writes originalState candidateState
          stackRangesValid sourceWindowHolds itemsChecked related with
        ⟨preparedUpdates, originalPreparedWrites, candidatePreparedWrites⟩
      change preparedUpdates.map PairedStackWordUpdate.originalWrite =
        claim.stackWrites.originalWrites originalState at originalPreparedWrites
      change preparedUpdates.map PairedStackWordUpdate.candidateWrite =
        claim.stackWrites.candidateWrites candidateState at candidatePreparedWrites
      rcases pairedStackWordLocation_below_window_amount context world
          claim.stackWrites.window originalState.registers candidateState.registers
          stackRangesValid sourceWindowHolds claim.stackAmount stackAtLeast
          stackAligned enoughBelow with
        ⟨returnLocation, originalReturnLocation, candidateReturnLocation⟩
      have returnLocationValid :
          returnLocation.range.disjointFromImages context = true := by
        have validRows := stackRangesValid
        simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
          List.all_eq_true] at validRows
        exact (validRows.1.1.2 returnLocation.range
          returnLocation.rangeMember).1.1.1
      have returnValuesRelated :=
        codeTargetIdAddresses_wordRelated context world claim.continuationTargetId
          (BitVec.ofNat 32 claim.originalReturnAddress)
          (BitVec.ofNat 32 claim.candidateReturnAddress) continuationPair
          zeroAgreement
      let returnUpdate : PairedStackWordUpdate context world := {
        location := returnLocation
        locationValid := returnLocationValid
        originalValue := BitVec.ofNat 32 claim.originalReturnAddress
        candidateValue := BitVec.ofNat 32 claim.candidateReturnAddress
        valuesRelated := returnValuesRelated
      }
      have originalPushAddress : claim.originalPushAddress.eval originalState =
          returnLocation.originalAddress := by
        rw [originalReturnLocation]
        simp [DirectCallStackWritesClaim.originalPushAddress, Expr.eval,
          word_add_ia32_twos_complement _ claim.stackAmount stackFits]
      have candidatePushAddress : claim.candidatePushAddress.eval candidateState =
          returnLocation.candidateAddress := by
        rw [candidateReturnLocation]
        simp [DirectCallStackWritesClaim.candidatePushAddress, Expr.eval,
          word_add_ia32_twos_complement _ claim.stackAmount stackFits]
      let updates := preparedUpdates ++ [returnUpdate]
      have originalUpdateWrites : updates.map PairedStackWordUpdate.originalWrite =
          claim.originalWrites originalState := by
        simp [updates, DirectCallStackWritesClaim.originalWrites,
          originalPreparedWrites, returnUpdate, PairedStackWordUpdate.originalWrite,
          originalPushAddress]
      have candidateUpdateWrites : updates.map PairedStackWordUpdate.candidateWrite =
          claim.candidateWrites candidateState := by
        simp [updates, DirectCallStackWritesClaim.candidateWrites,
          candidatePreparedWrites, returnUpdate, PairedStackWordUpdate.candidateWrite,
          candidatePushAddress]
      have worldDynamicValid : world.dynamicRangesValid context = true := by
        have valid := worldValid
        simp only [RelationalWorld.valid, Bool.and_eq_true] at valid
        exact valid.1.1.1.1
      have staticSlotsValid : staticDynamicPointerSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _⟩
        exact slotsValid
      have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _⟩
        exact slotsValid
      have outputMemoryFamilies :=
        RelationalMemoryFamiliesHold.afterPairedStackWordUpdates context world
          stackRangesValid importsStatic worldDynamicValid staticSlotsValid
          staticWordSlotsValid updates
          originalState.memory candidateState.memory {
            stackRanges := stackMemory
            importAddresses := importsMemory
            originalImmutable := originalImmutable
            candidateImmutable := candidateImmutable
            ordinary := inputMemory
            staticPointerSlots := inputDynamicMemory.staticPointerSlots
            staticWordSlots := inputDynamicMemory.staticWordSlots
          }
      rw [originalUpdateWrites, candidateUpdateWrites] at outputMemoryFamilies
      rcases stateTransfer world originalState candidateState originalResult
          candidateResult related originalEval candidateEval guardTrue with
        ⟨registers, bounds, separations, stackWindows, x87, flags⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      apply StateRel.afterPairedMemoryFamiliesUpdate context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        (claim.originalWrites originalState) (claim.candidateWrites candidateState)
        related originalWrites candidateWrites outputMemoryFamilies registers bounds
        separations stackWindows x87 flags outputImports outputDynamic
        (by simp [targetDynamicStackRelationsEmpty, activeDynamicStackRangeRelationsHold])
  | external imported => trivial
  | returned => trivial
  | fault => trivial

theorem segmentTransitionClosed_of_direct_call_prepared_writes_with_transfers
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : DirectCallPreparedWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (claimChecked :
      claim.checked context sourceInvariant originalNormalized candidateNormalized = true)
    (shape : DirectCallPreparedWritesSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = []) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  unfold SegmentTransitionClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  unfold DirectCallPreparedWritesSegmentShapeClosed at shape
  rw [localCodeTargetsResolved, localValuesResolved] at shape
  unfold NoWriteSegmentStateTransferClosed at stateTransfer
  rw [localCodeTargetsResolved] at stateTransfer
  unfold NoWriteSegmentImportTransferClosed at importTransfer
  rw [localCodeTargetsResolved] at importTransfer
  unfold NoWriteSegmentDynamicTransferClosed at dynamicTransfer
  rw [localCodeTargetsResolved] at dynamicTransfer
  simp only [DirectCallPreparedWritesClaim.checked, Bool.and_eq_true] at claimChecked
  have preparedChecked := claimChecked.1.1
  have frameChecked := claimChecked.1.2
  simp only [PairedPreparedWordWritesClaim.checked, Bool.and_eq_true]
    at preparedChecked
  have itemsChecked := preparedChecked.2
  simp only [DirectCallPreparedWritesClaim.frameChecked, Bool.and_eq_true,
    decide_eq_true_eq, beq_iff_eq] at frameChecked
  rcases frameChecked with
    ⟨⟨⟨⟨⟨⟨⟨returnWindowMember, stackAtLeast⟩, stackAligned⟩, stackFits⟩,
      enoughBelow⟩, _calleePresent⟩, continuationPair⟩, zeroAgreement⟩
  intro world originalState candidateState related
  have relatedForShape := related
  have relatedForMemory := related
  have relatedForImports := related
  have relatedForDynamic := related
  rcases shape world originalState candidateState relatedForShape with
    ⟨guardsAgree, shapeClosed⟩
  refine ⟨guardsAgree, ?_⟩
  intro guardTrue
  rcases shapeClosed guardTrue with
    ⟨originalResult, candidateResult, originalEval, candidateEval,
      originalWrites, candidateWrites, originalExit, candidateExit, outcomes⟩
  rw [originalEval, candidateEval]
  refine ⟨originalExit, candidateExit, outcomes, ?_⟩
  cases edge.exit with
  | internal target =>
      rcases relatedForMemory with
        ⟨worldValid, stackRangesValid, stackMemory, importsStatic, _importsComplete,
          importsMemory, originalImmutable, candidateImmutable, relatedCore,
          _inputImportRegisters⟩
      rcases relatedCore with
        ⟨_, _, _, inputStackWindows, inputMemory, inputDynamicMemory,
          _inputUndefined, _, _, _inputFsBase⟩
      simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
      have returnWindowHolds := inputStackWindows claim.returnWindow
        (List.contains_iff_mem.mp returnWindowMember)
      rcases pairedPreparedWordUpdates_of_checkedItems context world sourceInvariant
          claim.preparedWrites.writes originalState candidateState stackRangesValid
          itemsChecked related with
        ⟨preparedUpdates, originalPreparedWrites, candidatePreparedWrites,
          _preparedUpdateKinds⟩
      change preparedUpdates.map PairedPreparedWordUpdate.originalWrite =
        claim.preparedWrites.originalWrites originalState at originalPreparedWrites
      change preparedUpdates.map PairedPreparedWordUpdate.candidateWrite =
        claim.preparedWrites.candidateWrites candidateState at candidatePreparedWrites
      rcases pairedStackWordLocation_below_window_amount context world
          claim.returnWindow originalState.registers candidateState.registers
          stackRangesValid returnWindowHolds claim.stackAmount stackAtLeast
          stackAligned enoughBelow with
        ⟨returnLocation, originalReturnLocation, candidateReturnLocation⟩
      have returnLocationValid :
          returnLocation.range.disjointFromImages context = true := by
        have validRows := stackRangesValid
        simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
          List.all_eq_true] at validRows
        exact (validRows.1.1.2 returnLocation.range
          returnLocation.rangeMember).1.1.1
      have returnValuesRelated :=
        codeTargetIdAddresses_wordRelated context world claim.continuationTargetId
          (BitVec.ofNat 32 claim.originalReturnAddress)
          (BitVec.ofNat 32 claim.candidateReturnAddress) continuationPair
          zeroAgreement
      let returnStackUpdate : PairedStackWordUpdate context world := {
        location := returnLocation
        locationValid := returnLocationValid
        originalValue := BitVec.ofNat 32 claim.originalReturnAddress
        candidateValue := BitVec.ofNat 32 claim.candidateReturnAddress
        valuesRelated := returnValuesRelated
      }
      let returnUpdate : PairedPreparedWordUpdate context world :=
        .stack returnStackUpdate
      have originalPushAddress : claim.originalPushAddress.eval originalState =
          returnLocation.originalAddress := by
        rw [originalReturnLocation]
        simp [DirectCallPreparedWritesClaim.originalPushAddress, Expr.eval,
          word_add_ia32_twos_complement _ claim.stackAmount stackFits]
      have candidatePushAddress : claim.candidatePushAddress.eval candidateState =
          returnLocation.candidateAddress := by
        rw [candidateReturnLocation]
        simp [DirectCallPreparedWritesClaim.candidatePushAddress, Expr.eval,
          word_add_ia32_twos_complement _ claim.stackAmount stackFits]
      let updates := preparedUpdates ++ [returnUpdate]
      have originalUpdateWrites :
          updates.map PairedPreparedWordUpdate.originalWrite =
            claim.originalWrites originalState := by
        simp [updates, DirectCallPreparedWritesClaim.originalWrites,
          originalPreparedWrites, returnUpdate, returnStackUpdate,
          PairedPreparedWordUpdate.originalWrite,
          PairedStackWordUpdate.originalWrite, originalPushAddress]
      have candidateUpdateWrites :
          updates.map PairedPreparedWordUpdate.candidateWrite =
            claim.candidateWrites candidateState := by
        simp [updates, DirectCallPreparedWritesClaim.candidateWrites,
          candidatePreparedWrites, returnUpdate, returnStackUpdate,
          PairedPreparedWordUpdate.candidateWrite,
          PairedStackWordUpdate.candidateWrite, candidatePushAddress]
      have worldDynamicValid : world.dynamicRangesValid context = true := by
        have valid := worldValid
        simp only [RelationalWorld.valid, Bool.and_eq_true] at valid
        exact valid.1.1.1.1
      have staticSlotsValid : staticDynamicPointerSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _⟩
        exact slotsValid
      have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _⟩
        exact slotsValid
      have outputMemoryFamilies :=
        RelationalMemoryFamiliesHold.afterPairedPreparedWordUpdates context world
          stackRangesValid importsStatic worldDynamicValid staticSlotsValid
          staticWordSlotsValid updates originalState.memory candidateState.memory {
            stackRanges := stackMemory
            importAddresses := importsMemory
            originalImmutable := originalImmutable
            candidateImmutable := candidateImmutable
            ordinary := inputMemory
            staticPointerSlots := inputDynamicMemory.staticPointerSlots
            staticWordSlots := inputDynamicMemory.staticWordSlots
          }
      rw [originalUpdateWrites, candidateUpdateWrites] at outputMemoryFamilies
      rcases stateTransfer world originalState candidateState originalResult
          candidateResult related originalEval candidateEval guardTrue with
        ⟨registers, bounds, separations, stackWindows, x87, flags⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      apply StateRel.afterPairedMemoryFamiliesUpdate context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        (claim.originalWrites originalState) (claim.candidateWrites candidateState)
        related originalWrites candidateWrites outputMemoryFamilies registers bounds
        separations stackWindows x87 flags outputImports outputDynamic
        (by simp [targetDynamicStackRelationsEmpty, activeDynamicStackRangeRelationsHold])
  | external imported => trivial
  | returned => trivial
  | fault => trivial

theorem segmentTransitionClosed_of_direct_call
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (sourceWindow : StackWindowPair) (stackAmount : Nat)
    (originalReturnAddress candidateReturnAddress : Word)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : sourceWindow ∈ sourceInvariant.stackWindows)
    (stackAmountAtLeastWord : 4 <= stackAmount)
    (stackAmountAligned : stackAmount % 4 = 0)
    (sourceWindowEnoughBelow : stackAmount <= sourceWindow.bytesBelow)
    (returnAddressesRelated : ∀ world,
      wordRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        originalReturnAddress candidateReturnAddress = true)
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = [])
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = [])
    (shape : DirectCallSegmentShapeClosed context edge sourceInvariant sourceWindow
      stackAmount originalReturnAddress candidateReturnAddress originalBehavior
      candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_direct_call_with_transfers context edge
    sourceInvariant targetInvariant sourceWindow stackAmount originalReturnAddress
    candidateReturnAddress originalBehavior candidateBehavior localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved contextValid sourceWindowMember
    stackAmountAtLeastWord stackAmountAligned sourceWindowEnoughBelow
    returnAddressesRelated shape stateTransfer
  · unfold NoWriteSegmentImportTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval
    simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  · unfold NoWriteSegmentDynamicTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval guardTrue
    simp [targetDynamicRelationsEmpty, activeDynamicRegisterRangeRelationsHold]
  · exact noWriteSegmentDynamicStackTransferClosed_of_empty context edge
      sourceInvariant targetInvariant originalBehavior candidateBehavior
      localCodeTargets localCodeTargetsResolved targetDynamicStackRelationsEmpty

theorem segmentTransitionClosed_of_direct_call_stack_writes
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : DirectCallStackWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : claim.stackWrites.window ∈ sourceInvariant.stackWindows)
    (claimChecked :
      claim.checked context sourceInvariant originalNormalized candidateNormalized = true)
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = [])
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = [])
    (shape : DirectCallStackWritesSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_direct_call_stack_writes_with_transfers context edge
    sourceInvariant targetInvariant claim originalBehavior candidateBehavior
    originalNormalized candidateNormalized localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved contextValid sourceWindowMember
    claimChecked shape stateTransfer
  · unfold NoWriteSegmentImportTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval
    simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  · unfold NoWriteSegmentDynamicTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval guardTrue
    simp [targetDynamicRelationsEmpty, activeDynamicRegisterRangeRelationsHold]
  · exact targetDynamicStackRelationsEmpty

theorem segmentTransitionClosed_of_direct_call_prepared_writes
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : DirectCallPreparedWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (claimChecked :
      claim.checked context sourceInvariant originalNormalized candidateNormalized = true)
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = [])
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = [])
    (shape : DirectCallPreparedWritesSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_direct_call_prepared_writes_with_transfers
    context edge sourceInvariant targetInvariant claim originalBehavior candidateBehavior
    originalNormalized candidateNormalized localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved contextValid claimChecked shape
    stateTransfer
  · unfold NoWriteSegmentImportTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval
    simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  · unfold NoWriteSegmentDynamicTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval guardTrue
    simp [targetDynamicRelationsEmpty, activeDynamicRegisterRangeRelationsHold]
  · exact targetDynamicStackRelationsEmpty

theorem segmentTransitionClosed_of_no_write_with_imports
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (shape : NoWriteSegmentShapeClosed context edge sourceInvariant
      originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = [])
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = []) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_no_write_with_transfers context edge sourceInvariant
    targetInvariant originalBehavior candidateBehavior localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved shape stateTransfer importTransfer
  unfold NoWriteSegmentDynamicTransferClosed
  rw [localCodeTargetsResolved]
  intro world originalState candidateState originalResult candidateResult related
    originalEval candidateEval _guardTrue
  simp [targetDynamicRelationsEmpty, activeDynamicRegisterRangeRelationsHold]
  exact noWriteSegmentDynamicStackTransferClosed_of_empty context edge
    sourceInvariant targetInvariant originalBehavior candidateBehavior
    localCodeTargets localCodeTargetsResolved targetDynamicStackRelationsEmpty

theorem segmentTransitionClosed_of_no_write_with_dynamic
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = [])
    (shape : NoWriteSegmentShapeClosed context edge sourceInvariant
      originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_no_write_with_transfers context edge sourceInvariant
    targetInvariant originalBehavior candidateBehavior localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved shape stateTransfer
  · unfold NoWriteSegmentImportTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval
    simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  · exact dynamicTransfer
  · exact noWriteSegmentDynamicStackTransferClosed_of_empty context edge
      sourceInvariant targetInvariant originalBehavior candidateBehavior
      localCodeTargets localCodeTargetsResolved targetDynamicStackRelationsEmpty

theorem segmentTransitionClosed_of_no_write_with_imports_and_dynamic
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (shape : NoWriteSegmentShapeClosed context edge sourceInvariant
      originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = []) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_no_write_with_transfers context edge sourceInvariant
    targetInvariant originalBehavior candidateBehavior localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved shape stateTransfer importTransfer
    dynamicTransfer
  exact noWriteSegmentDynamicStackTransferClosed_of_empty context edge sourceInvariant
    targetInvariant originalBehavior candidateBehavior localCodeTargets
    localCodeTargetsResolved targetDynamicStackRelationsEmpty

theorem segmentTransitionClosed_of_no_write
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = [])
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = [])
    (shape : NoWriteSegmentShapeClosed context edge sourceInvariant
      originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_no_write_with_imports context edge sourceInvariant
    targetInvariant originalBehavior candidateBehavior localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved shape stateTransfer
  unfold NoWriteSegmentImportTransferClosed
  rw [localCodeTargetsResolved]
  intro world originalState candidateState originalResult candidateResult related
    originalEval candidateEval
  simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  exact targetDynamicRelationsEmpty
  exact targetDynamicStackRelationsEmpty

theorem segmentTransitionClosed_of_paired_stack_word_write
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : PairedStackWordWriteClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : claim.window ∈ sourceInvariant.stackWindows)
    (claimChecked :
      claim.checked context sourceInvariant originalNormalized candidateNormalized = true)
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = [])
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = [])
    (shape : PairedStackWordWriteSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_paired_stack_word_write_with_transfers context edge
    sourceInvariant targetInvariant claim originalBehavior candidateBehavior
    originalNormalized candidateNormalized localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved contextValid sourceWindowMember
    claimChecked shape stateTransfer
  · unfold NoWriteSegmentImportTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval
    simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  · unfold NoWriteSegmentDynamicTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval guardTrue
    simp [targetDynamicRelationsEmpty, activeDynamicRegisterRangeRelationsHold]
  · exact noWriteSegmentDynamicStackTransferClosed_of_empty context edge
      sourceInvariant targetInvariant originalBehavior candidateBehavior
      localCodeTargets localCodeTargetsResolved targetDynamicStackRelationsEmpty

theorem segmentTransitionClosed_of_paired_stack_word_writes
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : PairedStackWordWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (sourceWindowMember : claim.window ∈ sourceInvariant.stackWindows)
    (claimChecked :
      claim.checked context sourceInvariant originalNormalized candidateNormalized = true)
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = [])
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = [])
    (shape : PairedStackWordWritesSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_paired_stack_word_writes_with_transfers context edge
    sourceInvariant targetInvariant claim originalBehavior candidateBehavior
    originalNormalized candidateNormalized localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved contextValid sourceWindowMember
    claimChecked shape stateTransfer
  · unfold NoWriteSegmentImportTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval
    simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  · unfold NoWriteSegmentDynamicTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval guardTrue
    simp [targetDynamicRelationsEmpty, activeDynamicRegisterRangeRelationsHold]
  · exact targetDynamicStackRelationsEmpty

theorem segmentTransitionClosed_of_paired_prepared_word_writes
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : PairedPreparedWordWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (claimChecked : claim.checked context sourceInvariant = true)
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = [])
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = [])
    (shape : PairedPreparedWordWritesSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_paired_prepared_word_writes_with_transfers
    context edge sourceInvariant targetInvariant claim originalBehavior
    candidateBehavior localCodeTargets localValues localCodeTargetsResolved
    localValuesResolved contextValid claimChecked shape stateTransfer
  · unfold NoWriteSegmentImportTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval
    simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  · unfold NoWriteSegmentDynamicTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval guardTrue
    simp [targetDynamicRelationsEmpty, activeDynamicRegisterRangeRelationsHold]
  · exact noWriteSegmentDynamicStackTransferClosed_of_empty context edge
      sourceInvariant targetInvariant originalBehavior candidateBehavior
      localCodeTargets localCodeTargetsResolved targetDynamicStackRelationsEmpty

theorem segmentTransitionClosed_of_paired_prepared_word_writes_with_dynamic
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : PairedPreparedWordWritesClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (claimChecked : claim.checked context sourceInvariant = true)
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = [])
    (shape : PairedPreparedWordWritesSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_paired_prepared_word_writes_with_transfers
    context edge sourceInvariant targetInvariant claim originalBehavior
    candidateBehavior localCodeTargets localValues localCodeTargetsResolved
    localValuesResolved contextValid claimChecked shape stateTransfer
  · unfold NoWriteSegmentImportTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval
    simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  · exact dynamicTransfer
  · exact noWriteSegmentDynamicStackTransferClosed_of_empty context edge
      sourceInvariant targetInvariant originalBehavior candidateBehavior
      localCodeTargets localCodeTargetsResolved targetDynamicStackRelationsEmpty

theorem segmentTransitionClosed_of_paired_prepared_word_writes_with_dynamic_spill
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : PairedPreparedWordWritesClaim)
    (spillClaim : PreparedDynamicStackRangeSpillClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (claimChecked : claim.checked context sourceInvariant = true)
    (spillChecked :
      spillClaim.checked sourceInvariant targetInvariant claim = true)
    (targetDynamicStackInventory :
      targetInvariant.dynamicStackRangeRelations = [spillClaim.targetRelation])
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (shape : PairedPreparedWordWritesSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (basePreserved : PairedPreparedWordWritesOutputBasePreserved context edge
      spillClaim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_paired_prepared_word_writes_with_transfers
    context edge sourceInvariant targetInvariant claim originalBehavior
    candidateBehavior localCodeTargets localValues localCodeTargetsResolved
    localValuesResolved contextValid claimChecked shape stateTransfer
  · unfold NoWriteSegmentImportTransferClosed
    rw [localCodeTargetsResolved]
    intro world originalState candidateState originalResult candidateResult related
      originalEval candidateEval
    simp [targetImportRelationsEmpty, importRegisterRelationsHold]
  · exact dynamicTransfer
  · exact noWriteSegmentDynamicStackTransferClosed_of_prepared_spill context edge
      sourceInvariant targetInvariant claim spillClaim originalBehavior
      candidateBehavior localCodeTargets localValues localCodeTargetsResolved
      localValuesResolved contextValid claimChecked spillChecked
      targetDynamicStackInventory shape basePreserved

theorem segmentTransitionClosed_of_paired_prepared_word_writes_with_spill
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (claim : PairedPreparedWordWritesClaim)
    (spillClaim : PreparedDynamicStackRangeSpillClaim)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (contextValid : context.StructurallyValid)
    (claimChecked : claim.checked context sourceInvariant = true)
    (spillChecked :
      spillClaim.checked sourceInvariant targetInvariant claim = true)
    (targetDynamicStackInventory :
      targetInvariant.dynamicStackRangeRelations = [spillClaim.targetRelation])
    (targetImportRelationsEmpty : targetInvariant.importRegisterRelations = [])
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = [])
    (shape : PairedPreparedWordWritesSegmentShapeClosed context edge sourceInvariant
      claim originalBehavior candidateBehavior)
    (basePreserved : PairedPreparedWordWritesOutputBasePreserved context edge
      spillClaim originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_paired_prepared_word_writes_with_dynamic_spill
    context edge sourceInvariant targetInvariant claim spillClaim originalBehavior
    candidateBehavior localCodeTargets localValues localCodeTargetsResolved
    localValuesResolved contextValid claimChecked spillChecked
    targetDynamicStackInventory targetImportRelationsEmpty shape basePreserved
    stateTransfer
  unfold NoWriteSegmentDynamicTransferClosed
  rw [localCodeTargetsResolved]
  intro world originalState candidateState originalResult candidateResult related
    originalEval candidateEval guardTrue
  simp [targetDynamicRelationsEmpty, activeDynamicRegisterRangeRelationsHold]

def RelationalSegmentRefinement (context : StaticProofContext)
    (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant) : Prop :=
  ∃ originalBehavior candidateBehavior,
    regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
      context.machineImportCallContracts edge.originalSpan = some originalBehavior ∧
    regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
      context.machineImportCallContracts edge.candidateSpan = some candidateBehavior ∧
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior

theorem relationalSegmentRefinement_of_decoded
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalDecoded : regionBehaviorWithMachineCallContracts context.originalPe
      context.originalImports context.machineImportCallContracts
      edge.originalSpan = some originalBehavior)
    (candidateDecoded : regionBehaviorWithMachineCallContracts context.candidatePe
      context.candidateImports context.machineImportCallContracts
      edge.candidateSpan = some candidateBehavior)
    (transition : SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior) :
    RelationalSegmentRefinement context edge sourceInvariant targetInvariant :=
  ⟨originalBehavior, candidateBehavior, originalDecoded, candidateDecoded, transition⟩

end StageA.Relational
