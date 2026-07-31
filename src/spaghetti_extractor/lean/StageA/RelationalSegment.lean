import StageA.RelationalExactExpr
import StageA.RelationalX87Machine

namespace StageA.Relational

open StageA.Formal

theorem StateRel.withX87Physical
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (original candidate : MachineState)
    (originalPhysical candidatePhysical : StageA.X87.PhysicalState)
    (related : StateRel context world invariant original candidate)
    (physical : StageA.Relational.X87.StateRelated
      (x87AddressRelation context world) originalPhysical candidatePhysical) :
    StateRel context world invariant
      { original with x87Physical := originalPhysical }
      { candidate with x87Physical := candidatePhysical } := by
  rcases related with
    ⟨worldValid, stackRangesValid, stackMemory, importsStatic, importsComplete,
      importsMemory, originalImmutable, candidateImmutable, core, trailing⟩
  rcases core with
    ⟨registers, bounds, separations, stackWindows, memory, dynamicMemory,
      undefinedValue, x87, flags, fsBase⟩
  have dynamicMemory' : RelationalDynamicMemoryHold context world invariant
      { original with x87Physical := originalPhysical }
      { candidate with x87Physical := candidatePhysical } := by
    refine {
      staticPointerSlots := dynamicMemory.staticPointerSlots
      staticWordSlots := dynamicMemory.staticWordSlots
      active := ?_
    }
    constructor
    · simpa [activeDynamicRegisterRangeRelationsHold,
        DynamicRegisterRangeRelation.activeHolds] using
        dynamicMemory.active.registerRanges
    · simpa [activeDynamicStackRangeRelationsHold,
        DynamicStackRangeRelation.activeHolds] using
        dynamicMemory.active.stackRanges
  have trailing' :
      importRegisterRelationsHold world invariant.importRegisterRelations
          original.registers candidate.registers = true ∧
        registerValueOriginRelationsHold context world
          invariant.registerValueOriginRelations original.registers
          candidate.registers = true ∧
        memoryValueOriginRelationsHold context world
          invariant.memoryValueOriginRelations
          { original with x87Physical := originalPhysical }
          { candidate with x87Physical := candidatePhysical } = true ∧
        dynamicRegisterRangeRelationsHold world invariant.dynamicRegisterRangeRelations
          original.registers candidate.registers = true ∧
        dynamicStackRangeRelationsHold world invariant.dynamicStackRangeRelations
          { original with x87Physical := originalPhysical }
          { candidate with x87Physical := candidatePhysical } = true ∧
        pairedStatePredicatesHold invariant.predicates
          { original with x87Physical := originalPhysical }
          { candidate with x87Physical := candidatePhysical } = true := by
    rcases trailing with
      ⟨importRegisters, originRegisters, memoryOrigins, dynamicRegisters,
        dynamicStacks, predicates⟩
    refine ⟨importRegisters, originRegisters, ?_, dynamicRegisters, ?_, ?_⟩
    · have originalAgreement : MachineExpressionAgreement original
          { original with x87Physical := originalPhysical } := by
        exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩
      have candidateAgreement : MachineExpressionAgreement candidate
          { candidate with x87Physical := candidatePhysical } := by
        exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩
      simp only [memoryValueOriginRelationsHold, List.all_eq_true] at memoryOrigins ⊢
      intro relation member
      have source := memoryOrigins relation member
      simp only [MemoryValueOriginRelation.holds, List.any_eq_true] at source ⊢
      rcases source with ⟨origin, originMember, originMatches⟩
      refine ⟨origin, originMember, ?_⟩
      rw [← Expr.eval_eq_of_expressionAgreement original
          { original with x87Physical := originalPhysical }
          originalAgreement relation.originalAddress]
      rw [← Expr.eval_eq_of_expressionAgreement candidate
          { candidate with x87Physical := candidatePhysical }
          candidateAgreement relation.candidateAddress]
      exact originMatches
    · simpa [dynamicStackRangeRelationsHold, DynamicStackRangeRelation.holds] using
        dynamicStacks
    · have originalAgreement : MachineExpressionAgreement original
          { original with x87Physical := originalPhysical } := by
        exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩
      have candidateAgreement : MachineExpressionAgreement candidate
          { candidate with x87Physical := candidatePhysical } := by
        exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩
      simp only [pairedStatePredicatesHold, List.all_eq_true] at predicates ⊢
      intro predicate member
      have source := predicates predicate member
      simp only [PairedStatePredicate.holds, Bool.and_eq_true,
        List.all_eq_true] at source ⊢
      refine ⟨?_, ?_⟩
      · constructor
        · rw [← BoolExpr.eval_eq_of_expressionAgreement original
            { original with x87Physical := originalPhysical }
            originalAgreement predicate.original]
          exact source.1.1
        · rw [← BoolExpr.eval_eq_of_expressionAgreement candidate
            { candidate with x87Physical := candidatePhysical }
            candidateAgreement predicate.candidate]
          exact source.1.2
      · intro read readMember
        have sourceRead := source.2 read readMember
        have originalAddress := Expr.eval_eq_of_expressionAgreement original
          { original with x87Physical := originalPhysical }
          originalAgreement read.originalAddress
        have candidateAddress := Expr.eval_eq_of_expressionAgreement candidate
          { candidate with x87Physical := candidatePhysical }
          candidateAgreement read.candidateAddress
        simp only [PairedExactMemoryRead.holds, Bool.and_eq_true,
          beq_iff_eq] at sourceRead ⊢
        rw [← originalAddress, ← candidateAddress]
        simpa [MachineState.readX87Word] using sourceRead
  refine ⟨worldValid, stackRangesValid, stackMemory, importsStatic,
    importsComplete, importsMemory, originalImmutable, candidateImmutable, ?_, trailing'⟩
  exact ⟨registers, bounds, separations, stackWindows, memory, dynamicMemory',
    undefinedValue, ⟨x87.1, physical, x87.2.2⟩, flags, fsBase⟩

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
  | .callUnmappedReturn target => some (.internal target)
  | .externalCall imported _ _ | .externalJump imported _ =>
      some (.external imported)
  | .bulkCopy _ _ _ _ continuation | .bulkFill _ _ _ _ continuation |
      .checkedContinue true continuation |
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

def codeTargetAddresses (candidate : Bool) (imageBase : Nat)
    (target : CodeTargetPair) : List Word :=
  BitVec.ofNat 32 (imageBase + if candidate then target.candidateRva else target.originalRva) ::
    (if candidate then target.candidateAliases else target.originalAliases).map fun alias =>
      BitVec.ofNat 32 (imageBase + alias.rva)

theorem codeAddressMatches_iff_mem_codeTargetAddresses (candidate : Bool)
    (imageBase : Nat) (target : CodeTargetPair) (value : Word) :
    codeAddressMatches imageBase
        (if candidate then target.candidateRva else target.originalRva)
        (if candidate then target.candidateAliases else target.originalAliases) value = true ↔
      value ∈ codeTargetAddresses candidate imageBase target := by
  cases candidate with
  | false =>
      simp only [codeTargetAddresses, codeAddressMatches, if_false, Bool.or_eq_true,
        beq_iff_eq, List.mem_cons, List.mem_map, List.any_eq_true]
      constructor
      · intro found
        rcases found with found | ⟨alias, member, found⟩
        · exact Or.inl found
        · exact Or.inr ⟨alias, member, found.symm⟩
      · intro found
        rcases found with found | ⟨alias, member, found⟩
        · exact Or.inl found
        · exact Or.inr ⟨alias, member, found.symm⟩
  | true =>
      simp only [codeTargetAddresses, codeAddressMatches, if_true, Bool.or_eq_true,
        beq_iff_eq, List.mem_cons, List.mem_map, List.any_eq_true]
      constructor
      · intro found
        rcases found with found | ⟨alias, member, found⟩
        · exact Or.inl found
        · exact Or.inr ⟨alias, member, found.symm⟩
      · intro found
        rcases found with found | ⟨alias, member, found⟩
        · exact Or.inl found
        · exact Or.inr ⟨alias, member, found.symm⟩

theorem StaticCodeMap.resolveRawEip_of_codeAddressMatches
    (candidate : Bool) (originalPe candidatePe : PE32)
    (mapping : StaticCodeMap)
    (indexed : mapping.IndexedValid originalPe candidatePe)
    (targetId : Nat) (target : CodeTargetPair) (value : Word)
    (targetFound : mapping.get? targetId = some target)
    (addressMatches : codeAddressMatches
      (if candidate then candidatePe.imageBase else originalPe.imageBase)
      (if candidate then target.candidateRva else target.originalRva)
      (if candidate then target.candidateAliases else target.originalAliases)
      value = true) :
    mapping.resolveRawEip candidate
      (if candidate then candidatePe.imageBase else originalPe.imageBase)
      value = some targetId := by
  have targetBefore : targetId < mapping.entries.size :=
    FiniteIndex.get?_eq_some_implies_lt_size
      mapping.entries targetId target targetFound
  rcases indexed with
    ⟨_entriesStructural, _originalStructural, _candidateStructural,
      _entriesValid, _originalSize, _candidateSize, _originalAddresses,
      _candidateAddresses, originalRoundTrips, candidateRoundTrips⟩
  cases candidate with
  | false =>
      have checked := originalRoundTrips targetId targetBefore
      simp only [StaticCodeMap.targetAddressesRoundTripAt, targetFound, if_false,
        Bool.and_eq_true, beq_iff_eq, List.all_eq_true] at checked
      simp only [codeAddressMatches, if_false, Bool.or_eq_true, beq_iff_eq,
        List.any_eq_true] at addressMatches
      rcases addressMatches with canonical | ⟨alias, member, aliasAddress⟩
      · simpa [canonical] using checked.1
      · rw [aliasAddress]
        exact checked.2 alias member
  | true =>
      have checked := candidateRoundTrips targetId targetBefore
      simp only [StaticCodeMap.targetAddressesRoundTripAt, targetFound, if_true,
        Bool.and_eq_true, beq_iff_eq, List.all_eq_true] at checked
      simp only [codeAddressMatches, if_true, Bool.or_eq_true, beq_iff_eq,
        List.any_eq_true] at addressMatches
      rcases addressMatches with canonical | ⟨alias, member, aliasAddress⟩
      · simpa [canonical] using checked.1
      · rw [aliasAddress]
        exact checked.2 alias member

theorem StaticCodeMap.resolveRawEip_of_codeAddressMatchesAt
    (candidate : Bool) (originalPe candidatePe : PE32)
    (mapping : StaticCodeMap)
    (indexed : mapping.IndexedValid originalPe candidatePe)
    (targetId : Nat) (value : Word)
    (addressMatches : match mapping.get? targetId with
      | none => false
      | some target =>
          codeAddressMatches
            (if candidate then candidatePe.imageBase else originalPe.imageBase)
            (if candidate then target.candidateRva else target.originalRva)
            (if candidate then target.candidateAliases else target.originalAliases)
            value) :
    mapping.resolveRawEip candidate
      (if candidate then candidatePe.imageBase else originalPe.imageBase)
      value = some targetId := by
  cases targetResult : mapping.get? targetId with
  | none => simp [targetResult] at addressMatches
  | some target =>
      exact mapping.resolveRawEip_of_codeAddressMatches candidate
        originalPe candidatePe indexed targetId target value targetResult
        (by simpa [targetResult] using addressMatches)

def knownIndirectCodeTargetChecked (context : StaticProofContext)
    (targetId : Nat) : Bool :=
  match context.codeMap.get? targetId with
  | none => false
  | some target =>
      ((codeTargetAddresses false context.originalPe.imageBase target).all fun address =>
        resolveMappedCodeTarget false context.originalPe.imageBase
          context.codeMap.entries.toList address == some targetId && address != 0) &&
      ((codeTargetAddresses true context.candidatePe.imageBase target).all fun address =>
        resolveMappedCodeTarget true context.candidatePe.imageBase
          context.codeMap.entries.toList address == some targetId && address != 0)

theorem knownIndirectCodeTargetResolved (context : StaticProofContext)
    (targetId : Nat) (candidate : Bool) (value : Word)
    (checked : knownIndirectCodeTargetChecked context targetId = true)
    (targetMatches : match context.codeMap.get? targetId with
      | none => false
      | some target =>
          codeAddressMatches
            (if candidate then context.candidatePe.imageBase else context.originalPe.imageBase)
            (if candidate then target.candidateRva else target.originalRva)
            (if candidate then target.candidateAliases else target.originalAliases) value) :
    resolveMappedCodeTarget candidate
        (if candidate then context.candidatePe.imageBase else context.originalPe.imageBase)
        context.codeMap.entries.toList value = some targetId := by
  cases targetResult : context.codeMap.get? targetId with
  | none => simp [knownIndirectCodeTargetChecked, targetResult] at checked
  | some target =>
      simp only [knownIndirectCodeTargetChecked, targetResult, Bool.and_eq_true] at checked
      simp only [targetResult] at targetMatches
      have member := (codeAddressMatches_iff_mem_codeTargetAddresses candidate
        (if candidate then context.candidatePe.imageBase else context.originalPe.imageBase)
        target value).mp targetMatches
      cases candidate with
      | false =>
          have holds := List.all_eq_true.mp checked.1 value member
          simp only [Bool.and_eq_true] at holds
          simpa only [if_false, beq_iff_eq] using holds.1
      | true =>
          have holds := List.all_eq_true.mp checked.2 value member
          simp only [Bool.and_eq_true] at holds
          simpa only [if_true, beq_iff_eq] using holds.1

theorem knownIndirectCodeTargetNonzero (context : StaticProofContext)
    (targetId : Nat) (candidate : Bool) (value : Word)
    (checked : knownIndirectCodeTargetChecked context targetId = true)
    (targetMatches : match context.codeMap.get? targetId with
      | none => false
      | some target =>
          codeAddressMatches
            (if candidate then context.candidatePe.imageBase else context.originalPe.imageBase)
            (if candidate then target.candidateRva else target.originalRva)
            (if candidate then target.candidateAliases else target.originalAliases) value) :
    value != 0 := by
  cases targetResult : context.codeMap.get? targetId with
  | none => simp [knownIndirectCodeTargetChecked, targetResult] at checked
  | some target =>
      simp only [knownIndirectCodeTargetChecked, targetResult, Bool.and_eq_true] at checked
      simp only [targetResult] at targetMatches
      have member := (codeAddressMatches_iff_mem_codeTargetAddresses candidate
        (if candidate then context.candidatePe.imageBase else context.originalPe.imageBase)
        target value).mp targetMatches
      cases candidate with
      | false =>
          have holds := List.all_eq_true.mp checked.1 value member
          simp only [Bool.and_eq_true] at holds
          exact holds.2
      | true =>
          have holds := List.all_eq_true.mp checked.2 value member
          simp only [Bool.and_eq_true] at holds
          exact holds.2

theorem knownIndirectCallOutcomesRelated (context : StaticProofContext)
    (targetId : Nat) (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (originalTarget candidateTarget : Word) (continuationTargetId : Nat)
    (checked : knownIndirectCodeTargetChecked context targetId = true)
    (targetMember : (match context.codeMap.get? targetId with
      | none => false
      | some target => targets.contains target) = true)
    (originalMatches : match context.codeMap.get? targetId with
      | none => false
      | some target => codeAddressMatches context.originalPe.imageBase target.originalRva
          target.originalAliases originalTarget)
    (candidateMatches : match context.codeMap.get? targetId with
      | none => false
      | some target => codeAddressMatches context.candidatePe.imageBase target.candidateRva
          target.candidateAliases candidateTarget) :
    outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase targets values
      (.indirectCall originalTarget continuationTargetId)
      (.indirectCall candidateTarget continuationTargetId) = true := by
  cases targetResult : context.codeMap.get? targetId with
  | none => simp [targetResult] at targetMember
  | some target =>
      simp only [targetResult] at targetMember originalMatches candidateMatches
      have targetMem := List.contains_iff_mem.mp targetMember
      have originalNonzero := knownIndirectCodeTargetNonzero context targetId false
        originalTarget checked (by simpa [targetResult] using originalMatches)
      have candidateNonzero := knownIndirectCodeTargetNonzero context targetId true
        candidateTarget checked (by simpa [targetResult] using candidateMatches)
      have originalNe : originalTarget ≠ 0 := by simpa using originalNonzero
      have candidateNe : candidateTarget ≠ 0 := by simpa using candidateNonzero
      have originalZero :
          (originalTarget == BitVec.ofNat 32 0) = false :=
        beq_eq_false_iff_ne.mpr (by simpa using originalNe)
      have candidateZero :
          (candidateTarget == BitVec.ofNat 32 0) = false :=
        beq_eq_false_iff_ne.mpr (by simpa using candidateNe)
      have codeRelated : codePointerRelated context.originalPe.imageBase
          context.candidatePe.imageBase targets originalTarget candidateTarget = true := by
        simp only [codePointerRelated, List.any_eq_true]
        exact ⟨target, targetMem, by simp [originalMatches, candidateMatches]⟩
      simp only [outcomesRelated, wordRelated]
      rw [originalZero, candidateZero]
      simp [codeRelated]

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

/-- The semantic body of a segment transition with guard agreement supplied by
its composition context.  This is not a standalone refinement certificate:
callers must prove guard equality before the body can be used. -/
def SegmentTransitionBodyClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState =
            edge.candidateGuard.eval candidateState →
          edge.originalGuard.eval originalState = true →
            match evalBehavior false localCodeTargets originalState originalBehavior,
                evalBehavior true localCodeTargets candidateState candidateBehavior with
            | some originalResult, some candidateResult =>
                originalResult.outcome.segmentExitFor context false = some edge.exit ∧
                  candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
                  outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                    localCodeTargets localValues originalResult.outcome
                      candidateResult.outcome = true ∧
                  match edge.exit with
                  | .internal _ =>
                      StateRel context world targetInvariant
                        (originalResult.nextMachineState originalState)
                        (candidateResult.nextMachineState candidateState)
                  | .external _ | .returned | .fault => True
            | _, _ => False
  | _, _ => False

theorem SegmentTransitionClosed.body
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (closed : SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior) :
    SegmentTransitionBodyClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  unfold SegmentTransitionClosed at closed
  unfold SegmentTransitionBodyClosed
  cases codeTargets : context.codeMap.resolveIds edge.localCodeTargetIds with
  | none => simp [codeTargets] at closed
  | some localCodeTargets =>
      cases valueTargets : context.dataMap.resolveIds edge.localValueTargetIds with
      | none => simp [codeTargets, valueTargets] at closed
      | some localValues =>
          simp only [codeTargets, valueTargets] at closed ⊢
          intro world originalState candidateState related _guardsAgree guardTrue
          exact (closed world originalState candidateState related).2 guardTrue

def X87SegmentTransitionClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true →
            match StageA.Relational.X87.executeSingletonCommand false
                context.originalPe edge.originalSpan localCodeTargets originalState,
              StageA.Relational.X87.executeSingletonCommand true
                context.candidatePe edge.candidateSpan localCodeTargets candidateState with
            | some originalResult, some candidateResult =>
                originalResult.x87Fault = candidateResult.x87Fault ∧
                  match originalResult.x87Fault, candidateResult.x87Fault with
                  | some _, some _ => True
                  | none, none =>
                      originalResult.outcome.segmentExitFor context false = some edge.exit ∧
                        candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
                        outcomesRelated context.originalPe.imageBase
                            context.candidatePe.imageBase localCodeTargets localValues
                            originalResult.outcome candidateResult.outcome = true ∧
                        (match edge.exit with
                        | .internal _ =>
                            StateRel context world targetInvariant
                              (originalResult.nextMachineState originalState)
                              (candidateResult.nextMachineState candidateState)
                        | .external _ | .returned | .fault => True) ∧
                        (originalResult.nextMachineState originalState).registers =
                          originalState.registers ∧
                        (candidateResult.nextMachineState candidateState).registers =
                          candidateState.registers ∧
                        (originalResult.nextMachineState originalState).memory =
                          originalState.memory ∧
                        (candidateResult.nextMachineState candidateState).memory =
                          candidateState.memory
                  | _, _ => False
            | _, _ => False)
  | _, _ => False

theorem x87SegmentTransitionClosed_of_nonstoring_singleton
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (descriptor : StageA.Relational.X87.DecodedCommand)
    (localCodeTargets : List CodeTargetPair)
    (localValues : List ValueTargetPair) (targetId : Nat)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (originalDecoded : StageA.Relational.X87.decodeSingletonCommand
      context.originalPe edge.originalSpan = some descriptor)
    (candidateDecoded : StageA.Relational.X87.decodeSingletonCommand
      context.candidatePe edge.candidateSpan = some descriptor)
    (noStore : descriptor.command.expectedStoreKind = none)
    (noRegister : descriptor.command.expectedRegisterTarget = none)
    (noFlags : descriptor.command.eflagsWriteMask = BitVec.ofNat 32 0)
    (modeValid : descriptor.command.waitModeValid descriptor.waitMode)
    (inputsRelated : ∀ world originalState candidateState,
      StateRel context world sourceInvariant originalState candidateState →
        StageA.Relational.X87.InputRelated (x87AddressRelation context world)
          (StageA.Relational.X87.commandStepInput context.originalPe
            edge.originalSpan.start descriptor originalState)
          (StageA.Relational.X87.commandStepInput context.candidatePe
            edge.candidateSpan.start descriptor candidateState))
    (originalInputValid : ∀ state,
      (StageA.Relational.X87.commandStepInput context.originalPe
        edge.originalSpan.start descriptor state).validFor descriptor.command)
    (candidateInputValid : ∀ state,
      (StageA.Relational.X87.commandStepInput context.candidatePe
        edge.candidateSpan.start descriptor state).validFor descriptor.command)
    (originalContinuation : normalizeCodeTarget false localCodeTargets
      edge.originalSpan.stop = some targetId)
    (candidateContinuation : normalizeCodeTarget true localCodeTargets
      edge.candidateSpan.stop = some targetId)
    (edgeExit : edge.exit = .internal targetId)
    (invariantWeakening : StateInvariantWeakening sourceInvariant targetInvariant)
    (originalGuard : edge.originalGuard = .equal (.constant 0) (.constant 0))
    (candidateGuard : edge.candidateGuard = .equal (.constant 0) (.constant 0)) :
    X87SegmentTransitionClosed context edge sourceInvariant targetInvariant := by
  unfold X87SegmentTransitionClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  intro world originalState candidateState related
  have machineX87 := related.machineX87Related context world sourceInvariant
    originalState candidateState
  let originalInput := StageA.Relational.X87.commandStepInput context.originalPe
    edge.originalSpan.start descriptor originalState
  let candidateInput := StageA.Relational.X87.commandStepInput context.candidatePe
    edge.candidateSpan.start descriptor candidateState
  have inputRelation : StageA.Relational.X87.InputRelated
      (x87AddressRelation context world) originalInput candidateInput :=
    inputsRelated world originalState candidateState related
  let originalResponse := originalState.x87Semantics.execute descriptor.command
    descriptor.waitMode originalState.x87Physical originalInput
  let candidateResponse := candidateState.x87Semantics.execute descriptor.command
    descriptor.waitMode candidateState.x87Physical candidateInput
  have responsesRelated : StageA.Relational.X87.ResponseRelated
      (x87AddressRelation context world) originalResponse candidateResponse := by
    have shared := StageA.Relational.X87.execute_related originalState.x87Semantics
      (x87AddressRelation context world) descriptor.command descriptor.waitMode
      originalState.x87Physical candidateState.x87Physical originalInput candidateInput
      machineX87.2.1 inputRelation
    dsimp [originalResponse, candidateResponse]
    rw [← machineX87.2.2]
    exact shared
  have originalResponseValid : originalResponse.structurallyValid
      descriptor.command descriptor.waitMode := by
    exact originalState.x87Semantics.execute_structurallyValid
      originalState.x87Semantics.complies descriptor.command descriptor.waitMode
      originalState.x87Physical originalInput modeValid
      (originalInputValid originalState)
  have candidateResponseValid : candidateResponse.structurallyValid
      descriptor.command descriptor.waitMode := by
    exact candidateState.x87Semantics.execute_structurallyValid
      candidateState.x87Semantics.complies descriptor.command descriptor.waitMode
      candidateState.x87Physical candidateInput modeValid
      (candidateInputValid candidateState)
  rcases originalResponseValid with
    ⟨originalStoreShape, _originalStoreValid, originalRegisterShape,
      originalFlagsMask, _originalDefinedFlags, _originalNoStoreDefined,
      _originalNoRegisterDefined, _originalFaultMode, _originalWaitMode⟩
  rcases candidateResponseValid with
    ⟨candidateStoreShape, _candidateStoreValid, candidateRegisterShape,
      candidateFlagsMask, _candidateDefinedFlags, _candidateNoStoreDefined,
      _candidateNoRegisterDefined, _candidateFaultMode, _candidateWaitMode⟩
  have originalNoStore : originalResponse.store = none := by
    simpa [noStore] using originalStoreShape
  have candidateNoStore : candidateResponse.store = none := by
    simpa [noStore] using candidateStoreShape
  have originalNoRegister : originalResponse.register = none := by
    simpa [noRegister] using originalRegisterShape
  have candidateNoRegister : candidateResponse.register = none := by
    simpa [noRegister] using candidateRegisterShape
  have originalNoFlags : originalResponse.eflagsWriteMask = BitVec.ofNat 32 0 :=
    originalFlagsMask.trans noFlags
  have candidateNoFlags : candidateResponse.eflagsWriteMask = BitVec.ofNat 32 0 :=
    candidateFlagsMask.trans noFlags
  have originalInputChecked : originalInput.checkedFor descriptor.command = true :=
    originalInput.checkedFor_of_valid descriptor.command
      (originalInputValid originalState)
  have candidateInputChecked : candidateInput.checkedFor descriptor.command = true :=
    candidateInput.checkedFor_of_valid descriptor.command
      (candidateInputValid candidateState)
  have waitChecked : descriptor.command.waitModeChecked descriptor.waitMode = true :=
    descriptor.command.waitModeChecked_of_valid descriptor.waitMode modeValid
  have originalResponseChecked :
      originalResponse.checkedFor descriptor.command descriptor.waitMode = true :=
    originalResponse.checkedFor_of_structurallyValid descriptor.command
      descriptor.waitMode ⟨originalStoreShape, _originalStoreValid,
        originalRegisterShape, originalFlagsMask, _originalDefinedFlags,
        _originalNoStoreDefined, _originalNoRegisterDefined,
        _originalFaultMode, _originalWaitMode⟩
  have candidateResponseChecked :
      candidateResponse.checkedFor descriptor.command descriptor.waitMode = true :=
    candidateResponse.checkedFor_of_structurallyValid descriptor.command
      descriptor.waitMode ⟨candidateStoreShape, _candidateStoreValid,
        candidateRegisterShape, candidateFlagsMask, _candidateDefinedFlags,
        _candidateNoStoreDefined, _candidateNoRegisterDefined,
        _candidateFaultMode, _candidateWaitMode⟩
  have originalExecuted : StageA.Relational.X87.executeSingletonCommand false
      context.originalPe edge.originalSpan localCodeTargets originalState =
      some (StageA.Relational.X87.singletonBehavior originalState originalResponse
        none targetId) := by
    simp [StageA.Relational.X87.executeSingletonCommand, originalDecoded,
      originalContinuation, originalInput, originalResponse, originalInputChecked,
      waitChecked, originalResponseChecked, originalNoStore]
  have candidateExecuted : StageA.Relational.X87.executeSingletonCommand true
      context.candidatePe edge.candidateSpan localCodeTargets candidateState =
      some (StageA.Relational.X87.singletonBehavior candidateState candidateResponse
        none targetId) := by
    simp [StageA.Relational.X87.executeSingletonCommand, candidateDecoded,
      candidateContinuation, candidateInput, candidateResponse, candidateInputChecked,
      waitChecked, candidateResponseChecked, candidateNoStore]
  constructor
  · simp [originalGuard, candidateGuard, BoolExpr.eval, Expr.eval]
  · intro _guardTrue
    rw [originalExecuted, candidateExecuted]
    have faultRelated := responsesRelated.2.2.2.2.2.2
    constructor
    · exact faultRelated
    · rw [show (StageA.Relational.X87.singletonBehavior originalState
                originalResponse none targetId).x87Fault = originalResponse.fault by rfl,
          show (StageA.Relational.X87.singletonBehavior candidateState
                candidateResponse none targetId).x87Fault = candidateResponse.fault by rfl]
      rw [← faultRelated]
      cases fault : originalResponse.fault with
      | some _ => trivial
      | none =>
          rw [edgeExit]
          refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
          · simp [StageA.Relational.X87.singletonBehavior,
              PureOutcome.segmentExitFor, PureOutcome.segmentExit]
          · simp [StageA.Relational.X87.singletonBehavior,
              PureOutcome.segmentExitFor, PureOutcome.segmentExit]
          · simp [StageA.Relational.X87.singletonBehavior, outcomesRelated]
          · rw [StageA.Relational.X87.singletonBehavior_nextMachineState_of_state_only
                originalState originalResponse targetId originalNoStore
                originalNoRegister originalNoFlags,
              StageA.Relational.X87.singletonBehavior_nextMachineState_of_state_only
                candidateState candidateResponse targetId candidateNoStore
                candidateNoRegister candidateNoFlags]
            exact StateRel.weakenInvariant context world sourceInvariant
              targetInvariant _ _ invariantWeakening
              (related.withX87Physical context world sourceInvariant
                originalState candidateState originalResponse.nextState
                candidateResponse.nextState responsesRelated.1)
          · rw [StageA.Relational.X87.singletonBehavior_nextMachineState_of_state_only
                originalState originalResponse targetId originalNoStore
                originalNoRegister originalNoFlags]
          · rw [StageA.Relational.X87.singletonBehavior_nextMachineState_of_state_only
                candidateState candidateResponse targetId candidateNoStore
                candidateNoRegister candidateNoFlags]
          · rw [StageA.Relational.X87.singletonBehavior_nextMachineState_of_state_only
                originalState originalResponse targetId originalNoStore
                originalNoRegister originalNoFlags]
          · rw [StageA.Relational.X87.singletonBehavior_nextMachineState_of_state_only
                candidateState candidateResponse targetId candidateNoStore
                candidateNoRegister candidateNoFlags]

theorem x87SegmentTransitionClosed_of_state_only_singleton
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (descriptor : StageA.Relational.X87.DecodedCommand)
    (localCodeTargets : List CodeTargetPair)
    (localValues : List ValueTargetPair) (targetId : Nat)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (originalDecoded : StageA.Relational.X87.decodeSingletonCommand
      context.originalPe edge.originalSpan = some descriptor)
    (candidateDecoded : StageA.Relational.X87.decodeSingletonCommand
      context.candidatePe edge.candidateSpan = some descriptor)
    (noMemory : descriptor.memoryOperand = none)
    (noOperand : descriptor.command.expectedOperandBytes = none)
    (noStore : descriptor.command.expectedStoreKind = none)
    (noRegister : descriptor.command.expectedRegisterTarget = none)
    (noFlags : descriptor.command.eflagsWriteMask = BitVec.ofNat 32 0)
    (modeValid : descriptor.command.waitModeValid descriptor.waitMode)
    (originalContinuation : normalizeCodeTarget false localCodeTargets
      edge.originalSpan.stop = some targetId)
    (candidateContinuation : normalizeCodeTarget true localCodeTargets
      edge.candidateSpan.stop = some targetId)
    (edgeExit : edge.exit = .internal targetId)
    (invariantWeakening : StateInvariantWeakening sourceInvariant targetInvariant)
    (originalGuard : edge.originalGuard = .equal (.constant 0) (.constant 0))
    (candidateGuard : edge.candidateGuard = .equal (.constant 0) (.constant 0))
    (instructionPointersRelated : ∀ world,
      (x87AddressRelation context world).code
        (BitVec.ofNat 32
          (context.originalPe.imageBase + edge.originalSpan.start))
        (BitVec.ofNat 32
          (context.candidatePe.imageBase + edge.candidateSpan.start))) :
    X87SegmentTransitionClosed context edge sourceInvariant targetInvariant := by
  unfold X87SegmentTransitionClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  intro world originalState candidateState related
  have machineX87 := related.machineX87Related context world sourceInvariant
    originalState candidateState
  let originalInput := StageA.Relational.X87.commandStepInput context.originalPe
    edge.originalSpan.start descriptor originalState
  let candidateInput := StageA.Relational.X87.commandStepInput context.candidatePe
    edge.candidateSpan.start descriptor candidateState
  have inputsRelated : StageA.Relational.X87.InputRelated
      (x87AddressRelation context world) originalInput candidateInput := by
    exact StageA.Relational.X87.commandStepInput_related_of_no_memory
      context world descriptor edge.originalSpan.start edge.candidateSpan.start
      originalState candidateState noMemory noOperand machineX87.2.1
      (instructionPointersRelated world)
  have originalInputValid : originalInput.validFor descriptor.command := by
    simp [originalInput, StageA.Relational.X87.commandStepInput,
      StageA.Relational.X87.commandDataAddress, noMemory, noOperand,
      StageA.X87.StepInput.validFor]
  have candidateInputValid : candidateInput.validFor descriptor.command := by
    simp [candidateInput, StageA.Relational.X87.commandStepInput,
      StageA.Relational.X87.commandDataAddress, noMemory, noOperand,
      StageA.X87.StepInput.validFor]
  let originalResponse := originalState.x87Semantics.execute descriptor.command
    descriptor.waitMode originalState.x87Physical originalInput
  let candidateResponse := candidateState.x87Semantics.execute descriptor.command
    descriptor.waitMode candidateState.x87Physical candidateInput
  have responsesRelated : StageA.Relational.X87.ResponseRelated
      (x87AddressRelation context world) originalResponse candidateResponse := by
    have shared := StageA.Relational.X87.execute_related originalState.x87Semantics
      (x87AddressRelation context world) descriptor.command descriptor.waitMode
      originalState.x87Physical candidateState.x87Physical originalInput candidateInput
      machineX87.2.1 inputsRelated
    dsimp [originalResponse, candidateResponse]
    rw [← machineX87.2.2]
    exact shared
  have originalResponseValid : originalResponse.structurallyValid
      descriptor.command descriptor.waitMode := by
    exact originalState.x87Semantics.execute_structurallyValid
      originalState.x87Semantics.complies descriptor.command descriptor.waitMode
      originalState.x87Physical originalInput modeValid originalInputValid
  have candidateResponseValid : candidateResponse.structurallyValid
      descriptor.command descriptor.waitMode := by
    exact candidateState.x87Semantics.execute_structurallyValid
      candidateState.x87Semantics.complies descriptor.command descriptor.waitMode
      candidateState.x87Physical candidateInput modeValid candidateInputValid
  rcases originalResponseValid with
    ⟨originalStoreShape, _originalStoreValid, originalRegisterShape,
      originalFlagsMask, _originalDefinedFlags, _originalNoStoreDefined,
      _originalNoRegisterDefined, _originalFaultMode, _originalWaitMode⟩
  rcases candidateResponseValid with
    ⟨candidateStoreShape, _candidateStoreValid, candidateRegisterShape,
      candidateFlagsMask, _candidateDefinedFlags, _candidateNoStoreDefined,
      _candidateNoRegisterDefined, _candidateFaultMode, _candidateWaitMode⟩
  have originalNoStore : originalResponse.store = none := by
    simpa [noStore] using originalStoreShape
  have candidateNoStore : candidateResponse.store = none := by
    simpa [noStore] using candidateStoreShape
  have originalNoRegister : originalResponse.register = none := by
    simpa [noRegister] using originalRegisterShape
  have candidateNoRegister : candidateResponse.register = none := by
    simpa [noRegister] using candidateRegisterShape
  have originalNoFlags : originalResponse.eflagsWriteMask = BitVec.ofNat 32 0 :=
    originalFlagsMask.trans noFlags
  have candidateNoFlags : candidateResponse.eflagsWriteMask = BitVec.ofNat 32 0 :=
    candidateFlagsMask.trans noFlags
  have originalInputChecked : originalInput.checkedFor descriptor.command = true :=
    originalInput.checkedFor_of_valid descriptor.command originalInputValid
  have candidateInputChecked : candidateInput.checkedFor descriptor.command = true :=
    candidateInput.checkedFor_of_valid descriptor.command candidateInputValid
  have waitChecked : descriptor.command.waitModeChecked descriptor.waitMode = true :=
    descriptor.command.waitModeChecked_of_valid descriptor.waitMode modeValid
  have originalResponseChecked :
      originalResponse.checkedFor descriptor.command descriptor.waitMode = true :=
    originalResponse.checkedFor_of_structurallyValid descriptor.command
      descriptor.waitMode ⟨originalStoreShape, _originalStoreValid,
        originalRegisterShape, originalFlagsMask, _originalDefinedFlags,
        _originalNoStoreDefined, _originalNoRegisterDefined,
        _originalFaultMode, _originalWaitMode⟩
  have candidateResponseChecked :
      candidateResponse.checkedFor descriptor.command descriptor.waitMode = true :=
    candidateResponse.checkedFor_of_structurallyValid descriptor.command
      descriptor.waitMode ⟨candidateStoreShape, _candidateStoreValid,
        candidateRegisterShape, candidateFlagsMask, _candidateDefinedFlags,
        _candidateNoStoreDefined, _candidateNoRegisterDefined,
        _candidateFaultMode, _candidateWaitMode⟩
  have originalExecuted : StageA.Relational.X87.executeSingletonCommand false
      context.originalPe edge.originalSpan localCodeTargets originalState =
      some (StageA.Relational.X87.singletonBehavior originalState originalResponse
        none targetId) := by
    simp [StageA.Relational.X87.executeSingletonCommand, originalDecoded,
      originalContinuation, originalInput, originalResponse, originalInputChecked,
      waitChecked, originalResponseChecked, originalNoStore]
  have candidateExecuted : StageA.Relational.X87.executeSingletonCommand true
      context.candidatePe edge.candidateSpan localCodeTargets candidateState =
      some (StageA.Relational.X87.singletonBehavior candidateState candidateResponse
        none targetId) := by
    simp [StageA.Relational.X87.executeSingletonCommand, candidateDecoded,
      candidateContinuation, candidateInput, candidateResponse, candidateInputChecked,
      waitChecked, candidateResponseChecked, candidateNoStore]
  constructor
  · simp [originalGuard, candidateGuard, BoolExpr.eval, Expr.eval]
  · intro _guardTrue
    rw [originalExecuted, candidateExecuted]
    have faultRelated := responsesRelated.2.2.2.2.2.2
    constructor
    · exact faultRelated
    · rw [show (StageA.Relational.X87.singletonBehavior originalState
                originalResponse none targetId).x87Fault = originalResponse.fault by rfl,
          show (StageA.Relational.X87.singletonBehavior candidateState
                candidateResponse none targetId).x87Fault = candidateResponse.fault by rfl]
      rw [← faultRelated]
      cases fault : originalResponse.fault with
      | some _ => trivial
      | none =>
          rw [edgeExit]
          refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
          · simp [StageA.Relational.X87.singletonBehavior,
              PureOutcome.segmentExitFor, PureOutcome.segmentExit]
          · simp [StageA.Relational.X87.singletonBehavior,
              PureOutcome.segmentExitFor, PureOutcome.segmentExit]
          · simp [StageA.Relational.X87.singletonBehavior, outcomesRelated]
          · rw [StageA.Relational.X87.singletonBehavior_nextMachineState_of_state_only
                originalState originalResponse targetId originalNoStore
                originalNoRegister originalNoFlags,
              StageA.Relational.X87.singletonBehavior_nextMachineState_of_state_only
                candidateState candidateResponse targetId candidateNoStore
                candidateNoRegister candidateNoFlags]
            exact StateRel.weakenInvariant context world sourceInvariant
              targetInvariant _ _ invariantWeakening
              (related.withX87Physical context world sourceInvariant
                originalState candidateState originalResponse.nextState
                candidateResponse.nextState responsesRelated.1)
          · rw [StageA.Relational.X87.singletonBehavior_nextMachineState_of_state_only
                originalState originalResponse targetId originalNoStore
                originalNoRegister originalNoFlags]
          · rw [StageA.Relational.X87.singletonBehavior_nextMachineState_of_state_only
                candidateState candidateResponse targetId candidateNoStore
                candidateNoRegister candidateNoFlags]
          · rw [StageA.Relational.X87.singletonBehavior_nextMachineState_of_state_only
                originalState originalResponse targetId originalNoStore
                originalNoRegister originalNoFlags]
          · rw [StageA.Relational.X87.singletonBehavior_nextMachineState_of_state_only
                candidateState candidateResponse targetId candidateNoStore
                candidateNoRegister candidateNoFlags]

theorem x87SegmentTransitionClosed_of_checked_state_only_singleton
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (localCodeTargets : List CodeTargetPair)
    (localValues : List ValueTargetPair) (targetId : Nat)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (decodedPair : StageA.Relational.X87.decodeSingletonCommand
        context.originalPe edge.originalSpan =
      StageA.Relational.X87.decodeSingletonCommand
        context.candidatePe edge.candidateSpan)
    (commandChecked : StageA.Relational.X87.stateOnlySingletonCommandChecked
      context.originalPe edge.originalSpan = true)
    (originalContinuation : normalizeCodeTarget false localCodeTargets
      edge.originalSpan.stop = some targetId)
    (candidateContinuation : normalizeCodeTarget true localCodeTargets
      edge.candidateSpan.stop = some targetId)
    (edgeExit : edge.exit = .internal targetId)
    (invariantWeakening : StateInvariantWeakening sourceInvariant targetInvariant)
    (originalGuard : edge.originalGuard = .equal (.constant 0) (.constant 0))
    (candidateGuard : edge.candidateGuard = .equal (.constant 0) (.constant 0))
    (instructionPointersRelated : ∀ world,
      (x87AddressRelation context world).code
        (BitVec.ofNat 32
          (context.originalPe.imageBase + edge.originalSpan.start))
        (BitVec.ofNat 32
          (context.candidatePe.imageBase + edge.candidateSpan.start))) :
    X87SegmentTransitionClosed context edge sourceInvariant targetInvariant := by
  cases originalDecoded : StageA.Relational.X87.decodeSingletonCommand
      context.originalPe edge.originalSpan with
  | none =>
      simp [StageA.Relational.X87.stateOnlySingletonCommandChecked,
        originalDecoded] at commandChecked
  | some descriptor =>
      have candidateDecoded : StageA.Relational.X87.decodeSingletonCommand
          context.candidatePe edge.candidateSpan = some descriptor := by
        rw [← decodedPair]
        exact originalDecoded
      simp only [StageA.Relational.X87.stateOnlySingletonCommandChecked,
        originalDecoded, Bool.and_eq_true, Option.isNone_iff_eq_none,
        beq_iff_eq] at commandChecked
      rcases commandChecked with
        ⟨⟨⟨⟨⟨noMemory, noOperand⟩, noStore⟩, noRegister⟩, noFlags⟩,
          waitChecked⟩
      exact x87SegmentTransitionClosed_of_state_only_singleton context edge
        sourceInvariant targetInvariant descriptor localCodeTargets localValues targetId
        localCodeTargetsResolved localValuesResolved originalDecoded candidateDecoded
        noMemory noOperand noStore noRegister noFlags
        (descriptor.command.waitModeValid_of_checked descriptor.waitMode waitChecked)
        originalContinuation candidateContinuation edgeExit invariantWeakening
        originalGuard candidateGuard instructionPointersRelated

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

/-- No-write decoding and exit shape with guard agreement supplied by the
product-composition context. -/
def NoWriteSegmentShapeBodyClosed (context : StaticProofContext)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      ∀ world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState →
        edge.originalGuard.eval originalState =
            edge.candidateGuard.eval candidateState →
          edge.originalGuard.eval originalState = true →
            ∃ originalResult candidateResult,
              evalBehavior false localCodeTargets originalState originalBehavior =
                  some originalResult ∧
              evalBehavior true localCodeTargets candidateState candidateBehavior =
                  some candidateResult ∧
              originalResult.writes = [] ∧ candidateResult.writes = [] ∧
                originalResult.outcome.segmentExitFor context false = some edge.exit ∧
                candidateResult.outcome.segmentExitFor context true = some edge.exit ∧
                outcomesRelated context.originalPe.imageBase context.candidatePe.imageBase
                  localCodeTargets localValues originalResult.outcome
                    candidateResult.outcome = true
  | _, _ => False

theorem NoWriteSegmentShapeClosed.body
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (closed : NoWriteSegmentShapeClosed context edge sourceInvariant
      originalBehavior candidateBehavior) :
    NoWriteSegmentShapeBodyClosed context edge sourceInvariant
      originalBehavior candidateBehavior := by
  unfold NoWriteSegmentShapeClosed at closed
  unfold NoWriteSegmentShapeBodyClosed
  cases codeTargets : context.codeMap.resolveIds edge.localCodeTargetIds with
  | none => simp [codeTargets] at closed
  | some localCodeTargets =>
      cases valueTargets : context.dataMap.resolveIds edge.localValueTargetIds with
      | none => simp [codeTargets, valueTargets] at closed
      | some localValues =>
          simp only [codeTargets, valueTargets] at closed ⊢
          intro world originalState candidateState related _guardsAgree guardTrue
          exact (closed world originalState candidateState related).2 guardTrue

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

structure PairedStackRead32ValueClaim where
  window : StackWindowPair
  adjustment : StackAdjustment
deriving Repr, DecidableEq

def PairedStackRead32ValueClaim.adjustmentChecked
    (claim : PairedStackRead32ValueClaim) : Bool :=
  match claim.adjustment with
  | .identity => decide (4 <= claim.window.bytesAbove)
  | .add amount =>
      decide (amount + 4 <= claim.window.bytesAbove) && amount % 4 == 0
  | .subtract amount =>
      decide (4 <= amount) && decide (amount <= claim.window.bytesBelow) &&
        amount % 4 == 0

def PairedStackRead32ValueClaim.checked (sourceInvariant : StateInvariant)
    (original candidate : Expr) (claim : PairedStackRead32ValueClaim) : Bool :=
  sourceInvariant.stackWindows.contains claim.window && claim.adjustmentChecked &&
    InvariantWP.stackRead32AtAdjustmentMatches claim.adjustment
      claim.window.originalRegister original &&
    InvariantWP.stackRead32AtAdjustmentMatches claim.adjustment
      claim.window.candidateRegister candidate

theorem PairedStackRead32ValueClaim.related_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (original candidate : Expr)
    (claim : PairedStackRead32ValueClaim)
    (checked : claim.checked sourceInvariant original candidate = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (original.eval originalState) (candidate.eval candidateState) = true := by
  rcases claim with ⟨window, adjustment⟩
  simp only [PairedStackRead32ValueClaim.checked, Bool.and_eq_true] at checked
  rcases checked with
    ⟨⟨⟨windowMember, adjustmentChecked⟩, originalMatches⟩,
      candidateMatches⟩
  have originalEval := InvariantWP.stackRead32AtAdjustment_eval_of_matches
    adjustment window.originalRegister original originalState originalMatches
  have candidateEval := InvariantWP.stackRead32AtAdjustment_eval_of_matches
    adjustment window.candidateRegister candidate candidateState candidateMatches
  have readsRelated :
      wordRelated context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world)
        (Memory.read32 originalState.memory
          ((adjustment.expression window.originalRegister).eval originalState))
        (Memory.read32 candidateState.memory
          ((adjustment.expression window.candidateRegister).eval candidateState)) =
        true := by
    cases adjustment with
    | identity =>
        simp only [PairedStackRead32ValueClaim.adjustmentChecked,
          decide_eq_true_eq] at adjustmentChecked
        have read := StateRel.stackMemoryRead32Related context world
          sourceInvariant originalState candidateState window 0 related
          (List.contains_iff_mem.mp windowMember) adjustmentChecked (by decide)
        simpa [StackAdjustment.expression, Expr.eval] using read
    | add amount =>
        simp only [PairedStackRead32ValueClaim.adjustmentChecked,
          Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at adjustmentChecked
        have read := StateRel.stackMemoryRead32Related context world
          sourceInvariant originalState candidateState window amount related
          (List.contains_iff_mem.mp windowMember) adjustmentChecked.1
          adjustmentChecked.2
        simpa [StackAdjustment.expression, Expr.eval] using read
    | subtract amount =>
        simp only [PairedStackRead32ValueClaim.adjustmentChecked,
          Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at adjustmentChecked
        have read := StateRel.stackMemoryRead32BelowRelated context world
          sourceInvariant originalState candidateState window amount related
          (List.contains_iff_mem.mp windowMember) adjustmentChecked.1.1
          adjustmentChecked.1.2 adjustmentChecked.2
        simpa [StackAdjustment.expression, Expr.eval] using read
  rw [originalEval, candidateEval]
  exact readsRelated

structure StackRegisterBoundClaim where
  originalRegister : Reg
  candidateRegister : Reg
  upperExclusive : Nat
  stackRead : PairedStackRead32ValueClaim
deriving Repr, DecidableEq

def StackRegisterBoundClaim.originalAddress (claim : StackRegisterBoundClaim) : Expr :=
  claim.stackRead.adjustment.expression claim.stackRead.window.originalRegister

def StackRegisterBoundClaim.candidateAddress (claim : StackRegisterBoundClaim) : Expr :=
  claim.stackRead.adjustment.expression claim.stackRead.window.candidateRegister

def StackRegisterBoundClaim.originalIndex (claim : StackRegisterBoundClaim) : Expr :=
  .read32 claim.originalAddress

def StackRegisterBoundClaim.candidateIndex (claim : StackRegisterBoundClaim) : Expr :=
  .read32 claim.candidateAddress

def StackRegisterBoundClaim.predicate (claim : StackRegisterBoundClaim) :
    PairedStatePredicate := {
  original := .unsignedLess claim.originalIndex (.constant claim.upperExclusive)
  candidate := .unsignedLess claim.candidateIndex (.constant claim.upperExclusive)
  exactMemoryReads := [{
    originalAddress := claim.originalAddress
    candidateAddress := claim.candidateAddress
    bytes := 4
  }]
}

def StackRegisterBoundClaim.checked (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackRegisterBoundClaim) : Bool :=
  decide (0 < claim.upperExclusive) && decide (claim.upperExclusive < 2 ^ 32) &&
    claim.stackRead.checked sourceInvariant claim.originalIndex claim.candidateIndex &&
    sourceInvariant.predicates.contains claim.predicate &&
    originalBehavior.writes.isEmpty && candidateBehavior.writes.isEmpty &&
    originalBehavior.registers.get claim.originalRegister == claim.originalIndex &&
    candidateBehavior.registers.get claim.candidateRegister == claim.candidateIndex

def StackRegisterBoundClaim.Holds (context : StaticProofContext)
    (world : RelationalWorld) (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackRegisterBoundClaim) (original candidate : MachineState) : Prop :=
  claim.originalIndex.eval original = claim.candidateIndex.eval candidate ∧
    decide (claim.originalIndex.eval original <
      BitVec.ofNat 32 claim.upperExclusive) = true ∧
    decide (claim.candidateIndex.eval candidate <
      BitVec.ofNat 32 claim.upperExclusive) = true ∧
    (originalBehavior.registers.get claim.originalRegister).eval original =
      claim.originalIndex.eval original ∧
    (candidateBehavior.registers.get claim.candidateRegister).eval candidate =
      claim.candidateIndex.eval candidate ∧
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (claim.originalIndex.eval original) (claim.candidateIndex.eval candidate) = true

theorem StackRegisterBoundClaim.holds_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StackRegisterBoundClaim)
    (checked : claim.checked sourceInvariant originalBehavior candidateBehavior = true)
    (original candidate : MachineState)
    (related : StateRel context world sourceInvariant original candidate) :
    claim.Holds context world originalBehavior candidateBehavior original candidate := by
  simp only [StackRegisterBoundClaim.checked, Bool.and_eq_true, decide_eq_true_eq,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨positive, upperFits⟩, stackReadChecked⟩, predicateMember⟩,
      originalWrites⟩, candidateWrites⟩, originalOutput⟩, candidateOutput⟩
  have predicateHolds := pairedStatePredicatesHold_member sourceInvariant.predicates
    claim.predicate original candidate (List.contains_iff_mem.mp predicateMember)
    (related.predicatesHold context world sourceInvariant original candidate)
  simp only [StackRegisterBoundClaim.predicate, PairedStatePredicate.holds,
    Bool.and_eq_true, BoolExpr.eval, Expr.eval] at predicateHolds
  have exactRead := related.exactMemoryRead context world sourceInvariant original candidate
    claim.predicate {
      originalAddress := claim.originalAddress
      candidateAddress := claim.candidateAddress
      bytes := 4
    } (List.contains_iff_mem.mp predicateMember) (by simp [StackRegisterBoundClaim.predicate])
  have exactIndex : claim.originalIndex.eval original = claim.candidateIndex.eval candidate := by
    change original.readX87Word (claim.originalAddress.eval original) 4 =
      candidate.readX87Word (claim.candidateAddress.eval candidate) 4 at exactRead
    have lowWords := congrArg (fun value : BitVec 80 => value.extractLsb' 0 32) exactRead
    change (original.readX87Word (claim.originalAddress.eval original) 4).extractLsb' 0 32 =
      (candidate.readX87Word (claim.candidateAddress.eval candidate) 4).extractLsb' 0 32
      at lowWords
    rw [MachineState.readX87Word_four_extractLsb,
      MachineState.readX87Word_four_extractLsb] at lowWords
    simpa [StackRegisterBoundClaim.originalIndex,
      StackRegisterBoundClaim.candidateIndex, Expr.eval,
      machineStateRead32_eq_memoryRead32] using lowWords
  have stackRelated := claim.stackRead.related_of_checked context world sourceInvariant
    claim.originalIndex claim.candidateIndex stackReadChecked original candidate related
  exact ⟨exactIndex, predicateHolds.1.1, predicateHolds.1.2,
    congrArg (fun expression => expression.eval original) originalOutput,
    congrArg (fun expression => expression.eval candidate) candidateOutput,
    stackRelated⟩

structure PairedExactRegisterOutputClaim where
  output : RegisterRelationPair
  witness : PairedExactExprWitness
deriving Repr, DecidableEq

def PairedExactRegisterOutputClaim.checked (context : StaticProofContext)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : PairedExactRegisterOutputClaim) : Bool :=
  InvariantWP.registerValueRelationAcceptsEqual claim.output.relation &&
    originalBehavior.registers.get claim.output.original ==
      claim.witness.expression .original &&
    candidateBehavior.registers.get claim.output.candidate ==
      claim.witness.expression .candidate &&
    claim.witness.checked context sourceInvariant

theorem PairedExactRegisterOutputClaim.holds_output_of_stateRel
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : PairedExactRegisterOutputClaim)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    claim.output.relation.holds context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world)
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true := by
  simp only [PairedExactRegisterOutputClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨relationAccepted, originalExpression⟩, candidateExpression⟩,
      witnessChecked⟩
  have valuesEqual := claim.witness.eval_equal_of_checked context world
    sourceInvariant originalState candidateState witnessChecked related
  simp only [NormalizedSymbolicBehavior.eval, evalNormalizedRegisters_get]
  rw [originalExpression, candidateExpression]
  exact InvariantWP.RegisterValueRelation.holds_of_eq
    context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList (context.relationalValueTargets world)
    claim.output.relation _ _ relationAccepted valuesEqual

inductive StateRelRegisterOutputClaim where
  | ordinary (claim : InvariantWP.RegisterOutputClaim)
  | pairedExactExpression (claim : PairedExactRegisterOutputClaim)
deriving Repr, DecidableEq

def StateRelRegisterOutputClaim.output : StateRelRegisterOutputClaim →
    RegisterRelationPair
  | .ordinary claim => claim.output
  | .pairedExactExpression claim => claim.output

def StateRelRegisterOutputClaim.checked (context : StaticProofContext)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) :
    StateRelRegisterOutputClaim → Bool
  | .ordinary claim => claim.nonMemoryChecked context region originalBehavior
      candidateBehavior
  | .pairedExactExpression claim => claim.checked context region.inputInvariant
      originalBehavior candidateBehavior

theorem StateRelRegisterOutputClaim.holds_output_of_checked
    (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : StateRelRegisterOutputClaim)
    (checked : claim.checked context region originalBehavior candidateBehavior = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world region.inputInvariant originalState candidateState) :
    claim.output.relation.holds context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world)
      ((originalBehavior.eval originalState).registers.get claim.output.original)
      ((candidateBehavior.eval candidateState).registers.get claim.output.candidate) = true := by
  cases claim with
  | ordinary claim =>
      have allChecked : [claim].all
          (InvariantWP.RegisterOutputClaim.nonMemoryChecked context region
            originalBehavior candidateBehavior) = true := by
        simpa [StateRelRegisterOutputClaim.checked] using checked
      have allHolds := InvariantWP.registerRelationsHold_of_nonMemoryOutputClaims
        context world region originalBehavior candidateBehavior [claim] allChecked
        originalState candidateState related
      simpa [StateRelRegisterOutputClaim.output, registerRelationsHold] using allHolds
  | pairedExactExpression claim =>
      exact claim.holds_output_of_stateRel context world region.inputInvariant
        originalBehavior candidateBehavior
        (by simpa [StateRelRegisterOutputClaim.checked] using checked)
        originalState candidateState related

theorem registerRelationsHold_of_stateRelOutputClaims
    (context : StaticProofContext) (world : RelationalWorld)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claims : List StateRelRegisterOutputClaim)
    (checked : claims.all (StateRelRegisterOutputClaim.checked context region
      originalBehavior candidateBehavior) = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world region.inputInvariant originalState candidateState) :
    registerRelationsHold context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (claims.map StateRelRegisterOutputClaim.output)
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
  induction claims with
  | nil => rfl
  | cons claim tail induction =>
      simp only [List.all_cons, Bool.and_eq_true] at checked
      unfold registerRelationsHold
      simp only [List.map_cons, List.all_cons, Bool.and_eq_true]
      exact ⟨claim.holds_output_of_checked context world region originalBehavior
        candidateBehavior checked.1 originalState candidateState related,
        induction checked.2⟩

inductive PairedStackWordValueWitness where
  | exactInputs
  | exactExpression (witness : PairedExactExprWitness)
  | registerArgument (claim : RegisterArgumentClaim)
  | stackRead32 (claim : PairedStackRead32ValueClaim)
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
  | .exactExpression witness =>
      witness.expression .original == claim.original &&
        witness.expression .candidate == claim.candidate &&
        witness.checked context sourceInvariant
  | .registerArgument registerClaim =>
      registerClaim.checked sourceInvariant claim.original claim.candidate
  | .stackRead32 stackReadClaim =>
      stackReadClaim.checked sourceInvariant claim.original claim.candidate
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
  | exactExpression witness =>
      simp only [PairedStackWordValueClaim.checked, Bool.and_eq_true,
        beq_iff_eq] at checked
      rcases checked with
        ⟨⟨originalExpression, candidateExpression⟩, witnessChecked⟩
      rw [← originalExpression, ← candidateExpression]
      have evaluationsEqual := witness.eval_equal_of_checked context world
        sourceInvariant originalState candidateState witnessChecked related
      rw [evaluationsEqual]
      exact wordRelated_self context.originalPe.imageBase context.candidatePe.imageBase
        context.codeMap.entries.toList (context.relationalValueTargets world) _
  | registerArgument registerClaim =>
      exact registerArgumentWordsRelated_of_checked context world sourceInvariant
        originalValue candidateValue registerClaim checked originalState candidateState related
  | stackRead32 stackReadClaim =>
      exact stackReadClaim.related_of_checked context world sourceInvariant
        originalValue candidateValue checked originalState candidateState related
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
  | .exact, .exactInputs | .exact, .exactExpression _ => true
  | .exact, .registerArgument registerClaim =>
      registerClaim.relation.relation.impliesExact
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
      | exactExpression witness =>
          simp only [PairedStackWordValueClaim.checked, Bool.and_eq_true,
            beq_iff_eq] at checked
          rcases checked with
            ⟨⟨originalExpression, candidateExpression⟩, witnessChecked⟩
          simp only [StaticWordRelationKind.holds, beq_iff_eq]
          rw [← originalExpression, ← candidateExpression]
          exact witness.eval_equal_of_checked context world sourceInvariant
            originalState candidateState witnessChecked related
      | registerArgument registerClaim =>
          simp only [PairedStackWordValueClaim.staticRelationCompatible,
            beq_iff_eq] at compatible
          have evaluationsEqual := registerArgumentWordsEqual_of_checked_exactLike
            context world sourceInvariant originalValue candidateValue registerClaim checked
            compatible originalState candidateState related
          simpa [StaticWordRelationKind.holds, evaluationsEqual]
      | stackRead32 stackReadClaim =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
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
      | exactExpression witness =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | registerArgument registerClaim =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | stackRead32 stackReadClaim =>
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
      | exactExpression witness =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | registerArgument registerClaim =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | stackRead32 stackReadClaim =>
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
      | exactExpression witness =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | registerArgument registerClaim =>
          simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible
      | stackRead32 stackReadClaim =>
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
  | finiteOrigins finiteAlternativeBudget origins =>
      simp [PairedStackWordValueClaim.staticRelationCompatible] at compatible

theorem PairedStackWordValueClaim.eval_equal_of_checked_exact
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (claim : PairedStackWordValueClaim)
    (checked : claim.checked context sourceInvariant = true)
    (compatible : claim.staticRelationCompatible .exact = true)
    (originalState candidateState : MachineState)
    (related : StateRel context world sourceInvariant originalState candidateState) :
    claim.original.eval originalState = claim.candidate.eval candidateState := by
  have exactHolds := claim.staticRelationHolds_of_checked context world
    sourceInvariant .exact checked compatible originalState candidateState related
  simpa [StaticWordRelationKind.holds] using exactHolds

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
      | exactExpression witness =>
          simp [PairedStackWordValueClaim.dynamicRelationCompatible] at compatible
      | registerArgument registerClaim =>
          simp [PairedStackWordValueClaim.dynamicRelationCompatible] at compatible
      | stackRead32 stackReadClaim =>
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
      | exactExpression witness =>
          simp [PairedStackWordValueClaim.dynamicRelationCompatible] at compatible
      | registerArgument registerClaim =>
          simp [PairedStackWordValueClaim.dynamicRelationCompatible] at compatible
      | stackRead32 stackReadClaim =>
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

def pairedStackWordAdjustment? (amount : Nat) : Option StackAdjustment :=
  if amount = 0 then some .identity
  else if amount < 2 ^ 31 then some (.add amount)
  else if amount < 2 ^ 32 then some (.subtract (2 ^ 32 - amount))
  else if amount <= 2 ^ 33 then some (.subtract (2 ^ 33 - amount))
  else if amount = 2 ^ 34 then some (.add 0)
  else none

def StackAdjustment.stackWordChecked (adjustment : StackAdjustment)
    (window : StackWindowPair) : Bool :=
  match adjustment with
  | .identity => decide (4 <= window.bytesAbove)
  | .add amount => decide (amount + 4 <= window.bytesAbove) && amount % 4 == 0
  | .subtract amount =>
      decide (4 <= amount) && decide (amount <= window.bytesBelow) && amount % 4 == 0

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

theorem pairedStackWordLocation_at_adjustment
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (original candidate : MachineState)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world original.registers candidate.registers = true)
    (adjustment : StackAdjustment)
    (adjustmentChecked : adjustment.stackWordChecked window = true) :
    ∃ location : PairedStackWordLocation world,
      location.originalAddress =
          (adjustment.expression window.originalRegister).eval original ∧
        location.candidateAddress =
          (adjustment.expression window.candidateRegister).eval candidate := by
  cases adjustment with
  | identity =>
      simp only [StackAdjustment.stackWordChecked, decide_eq_true_eq]
        at adjustmentChecked
      simpa [StackAdjustment.expression, Expr.eval] using
        pairedStackWordLocation_above_window context world window original.registers
          candidate.registers rangesValid windowHolds 0 (by decide) adjustmentChecked
  | add amount =>
      simp only [StackAdjustment.stackWordChecked, Bool.and_eq_true,
        decide_eq_true_eq, beq_iff_eq] at adjustmentChecked
      simpa [StackAdjustment.expression, Expr.eval] using
        pairedStackWordLocation_above_window context world window original.registers
          candidate.registers rangesValid windowHolds amount adjustmentChecked.2
          adjustmentChecked.1
  | subtract amount =>
      simp only [StackAdjustment.stackWordChecked, Bool.and_eq_true,
        decide_eq_true_eq, beq_iff_eq] at adjustmentChecked
      simpa [StackAdjustment.expression, Expr.eval] using
        pairedStackWordLocation_below_window_amount context world window
          original.registers candidate.registers rangesValid windowHolds amount
          adjustmentChecked.1.1 adjustmentChecked.2 adjustmentChecked.1.2

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

@[simp] def pairedPreparedStackWordAddress (register : Reg) (amount : Nat) : Expr :=
  if amount = 0 then .inputReg register
  else if amount < 2 ^ 32 then .add (.inputReg register) (.constant amount)
  else if amount <= 2 ^ 33 then
    .sub (.inputReg register) (.constant (2 ^ 33 - amount))
  else if amount = 2 ^ 34 then .add (.inputReg register) (.constant 0)
  else .add (.inputReg register) (.constant amount)

@[simp] theorem pairedPreparedStackWordAddress_eval (register : Reg) (amount : Nat)
    (state : MachineState) :
    (pairedPreparedStackWordAddress register amount).eval state =
      state.registers.get register + BitVec.ofNat 32 amount := by
  unfold pairedPreparedStackWordAddress
  split
  · subst amount
    simp [Expr.eval]
  split
  · simp [Expr.eval]
  split <;> rename_i amountAtMost
  · by_cases amountLower : amount = 2 ^ 32
    · subst amount
      simp [Expr.eval]
    by_cases amountUpper : amount = 2 ^ 33
    · subst amount
      simp [Expr.eval]
    · have amountAbove : 2 ^ 32 < amount := by omega
      have subtractionFits : 2 ^ 33 - amount < 2 ^ 32 := by omega
      rw [show (Expr.sub (.inputReg register) (.constant (2 ^ 33 - amount))).eval
          state = state.registers.get register -
            BitVec.ofNat 32 (2 ^ 33 - amount) by rfl]
      rw [← word_add_ia32_twos_complement
        (state.registers.get register) (2 ^ 33 - amount) subtractionFits]
      congr 1
      apply BitVec.eq_of_toNat_eq
      simp only [BitVec.toNat_ofNat]
      rw [Nat.mod_eq_of_lt (by omega :
        2 ^ 32 - (2 ^ 33 - amount) < 2 ^ 32)]
      have amountForm : amount = 2 ^ 32 + (amount - 2 ^ 32) := by omega
      rw [amountForm]
      simp [Nat.mod_eq_of_lt (by omega : amount - 2 ^ 32 < 2 ^ 32)]
      omega
  · split
    · subst amount
      simp [Expr.eval]
    · simp [Expr.eval]

theorem pairedPreparedStackWordAddress_matches_adjustment
    (register : Reg) (amount : Nat) (adjustment : StackAdjustment)
    (decoded : pairedStackWordAdjustment? amount = some adjustment) :
    adjustment.expressionMatches register
      (pairedPreparedStackWordAddress register amount) = true := by
  unfold pairedStackWordAdjustment? at decoded
  unfold pairedPreparedStackWordAddress
  split at decoded
  · injection decoded with adjustmentEq
    subst adjustment
    simp_all [StackAdjustment.expressionMatches, StackAdjustment.expression]
  split at decoded
  · have amountBelowWord : amount < 2 ^ 32 := by omega
    injection decoded with adjustmentEq
    subst adjustment
    simp_all [StackAdjustment.expressionMatches, StackAdjustment.expression]
  split at decoded
  · have amountPositive : 0 < amount := by omega
    have subtractionFits : 2 ^ 32 - amount < 2 ^ 32 := by omega
    have complement : 2 ^ 32 - (2 ^ 32 - amount) = amount := by omega
    injection decoded with adjustmentEq
    subst adjustment
    simp_all [StackAdjustment.expressionMatches, StackAdjustment.expression]
  split at decoded
  · have amountNotBelowWord : ¬amount < 2 ^ 32 := by omega
    injection decoded with adjustmentEq
    subst adjustment
    simp_all [StackAdjustment.expressionMatches, StackAdjustment.expression]
  split at decoded
  · injection decoded with adjustmentEq
    subst adjustment
    simp_all [StackAdjustment.expressionMatches, StackAdjustment.expression]
  · simp_all

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
  | .stack window amount _ =>
      pairedPreparedStackWordAddress window.originalRegister amount
  | .staticWord _ originalAddress _ _ => .constant originalAddress
  | .dynamicWord source _ originalAmount _ _ =>
      pairedDynamicWordAddress source.original originalAmount
  | .staticDynamicPointer _ originalAddress _ _ _ => .constant originalAddress

def PairedPreparedWordWriteItem.candidateAddress :
    PairedPreparedWordWriteItem -> Expr
  | .stack window amount _ =>
      pairedPreparedStackWordAddress window.candidateRegister amount
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
        match pairedStackWordAdjustment? amount with
        | none => false
        | some adjustment =>
            adjustment.stackWordChecked window && value.checked context sourceInvariant
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
  indirect : Bool := false
deriving Repr, DecidableEq

def normalizedCallOutcomeMatches (indirect : Bool) (calleeTargetId : Nat)
    (continuationTargetId : Nat) (outcome : NormalizedOutcomeExpr) : Bool :=
  if indirect then
    match outcome with
    | .indirectCall _ continuation => continuation == continuationTargetId
    | _ => false
  else
    outcome == .call calleeTargetId continuationTargetId

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
  normalizedCallOutcomeMatches claim.indirect claim.calleeTargetId
      claim.continuationTargetId originalBehavior.outcome &&
    normalizedCallOutcomeMatches claim.indirect claim.calleeTargetId
      claim.continuationTargetId candidateBehavior.outcome &&
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
  indirect : Bool := false
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
  normalizedCallOutcomeMatches claim.indirect claim.calleeTargetId
      claim.continuationTargetId originalBehavior.outcome &&
    normalizedCallOutcomeMatches claim.indirect claim.calleeTargetId
      claim.continuationTargetId candidateBehavior.outcome &&
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
          unfold PairedPreparedWordWriteItem.checked at itemChecked
          simp only [Bool.and_eq_true] at itemChecked
          have windowMember := itemChecked.1
          cases adjustmentResult : pairedStackWordAdjustment? amount with
          | none => simp [adjustmentResult] at itemChecked
          | some adjustment =>
            simp only [adjustmentResult, Bool.and_eq_true] at itemChecked
            have adjustmentChecked := itemChecked.2.1
            have valueChecked := itemChecked.2.2
            have windowHolds := inputStackWindows window
              (List.contains_iff_mem.mp windowMember)
            rcases pairedStackWordLocation_at_adjustment context world window
                originalState candidateState rangesValid windowHolds adjustment
                adjustmentChecked with
              ⟨location, originalLocation, candidateLocation⟩
            have originalAddressEval := StackAdjustment.eval_expression_of_matches
              adjustment window.originalRegister
              (pairedPreparedStackWordAddress window.originalRegister amount)
              originalState
              (pairedPreparedStackWordAddress_matches_adjustment
                window.originalRegister amount adjustment adjustmentResult)
            have candidateAddressEval := StackAdjustment.eval_expression_of_matches
              adjustment window.candidateRegister
              (pairedPreparedStackWordAddress window.candidateRegister amount)
              candidateState
              (pairedPreparedStackWordAddress_matches_adjustment
                window.candidateRegister amount adjustment adjustmentResult)
            have locationValid : location.range.disjointFromImages context = true := by
              have validRows := rangesValid
              simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
                List.all_eq_true] at validRows
              exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
            have valuesRelated := PairedStackWordValueClaim.related_of_checked
              context world sourceInvariant value valueChecked originalState
              candidateState related
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
              simp only [update, stackUpdate, PairedPreparedWordUpdate.originalWrite,
                PairedStackWordUpdate.originalWrite,
                PairedPreparedWordWriteItem.originalAddress,
                PairedPreparedWordWriteItem.value]
              rw [originalLocation, ← originalAddressEval]
            · simp only [List.map_cons]
              rw [candidateUpdates]
              simp only [update, stackUpdate, PairedPreparedWordUpdate.candidateWrite,
                PairedStackWordUpdate.candidateWrite,
                PairedPreparedWordWriteItem.candidateAddress,
                PairedPreparedWordWriteItem.value]
              rw [candidateLocation, ← candidateAddressEval]
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
    (originalNoX87 : originalBehavior.x87Effect = none)
    (candidateNoX87 : candidateBehavior.x87Effect = none)
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
            PairedPreparedWordWriteItem.value, pairedPreparedStackWordAddress_eval,
            Expr.eval] at originalAddressExact originalValueExact
          simp only [PairedPreparedWordUpdate.candidateWrite,
            PairedStackWordUpdate.candidateWrite,
            PreparedDynamicStackRangeSpillClaim.item,
            PreparedDynamicStackRangeSpillClaim.value,
            PairedPreparedWordWriteItem.candidateAddress,
            PairedPreparedWordWriteItem.value, pairedPreparedStackWordAddress_eval,
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
                applyConcreteWrites originalState.memory originalBehavior.writes by
                  simp [RelationalBehavior.nextMachineState, originalNoX87]]
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
                applyConcreteWrites candidateState.memory candidateBehavior.writes by
                  simp [RelationalBehavior.nextMachineState, candidateNoX87]]
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
              candidateResult.eflags = true ∧
          registerValueOriginRelationsHold context world
              targetInvariant.registerValueOriginRelations originalResult.registers
              candidateResult.registers = true ∧
          memoryValueOriginRelationsHold context world
              targetInvariant.memoryValueOriginRelations
              (originalResult.nextMachineState originalState)
              (candidateResult.nextMachineState candidateState) = true ∧
          pairedStatePredicatesHold targetInvariant.predicates
              (originalResult.nextMachineState originalState)
              (candidateResult.nextMachineState candidateState) = true
  | none => False

/-- State transfer whose guard agreement is supplied by a linked or otherwise
contextual composition proof.  As with `SegmentTransitionBodyClosed`, this has
no standalone segment-refinement authority. -/
def NoWriteSegmentStateTransferBodyClosed (context : StaticProofContext)
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
        edge.originalGuard.eval originalState =
            edge.candidateGuard.eval candidateState →
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
              candidateResult.eflags = true ∧
          registerValueOriginRelationsHold context world
              targetInvariant.registerValueOriginRelations originalResult.registers
              candidateResult.registers = true ∧
          memoryValueOriginRelationsHold context world
              targetInvariant.memoryValueOriginRelations
              (originalResult.nextMachineState originalState)
              (candidateResult.nextMachineState candidateState) = true ∧
          pairedStatePredicatesHold targetInvariant.predicates
              (originalResult.nextMachineState originalState)
              (candidateResult.nextMachineState candidateState) = true
  | none => False

theorem NoWriteSegmentStateTransferClosed.body
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (closed : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    NoWriteSegmentStateTransferBodyClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior := by
  unfold NoWriteSegmentStateTransferClosed at closed
  unfold NoWriteSegmentStateTransferBodyClosed
  cases targets : context.codeMap.resolveIds edge.localCodeTargetIds with
  | none => simp [targets] at closed
  | some localCodeTargets =>
      simp only [targets] at closed ⊢
      intro world originalState candidateState originalResult candidateResult related
        originalEval candidateEval _guardsAgree guardTrue
      exact closed world originalState candidateState originalResult candidateResult
        related originalEval candidateEval guardTrue

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
    (originalNoX87 : originalBehavior.x87Effect = none)
    (candidateNoX87 : candidateBehavior.x87Effect = none)
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
  · simp only [RelationalBehavior.nextMachineState, originalNoX87, originalWrites,
      applyConcreteWrites, List.foldl_append, List.foldl]
    rw [originalLocation.symm.trans location.originalAddressExact]
    exact Memory.read32_write32_same_of_fits
      (originalPrefix.foldl
        (fun current write => current.write32 write.1 write.2)
        originalState.memory)
      (location.range.originalBase + BitVec.ofNat 32 location.offset)
      originalValue originalFits
  · simp only [RelationalBehavior.nextMachineState, candidateNoX87, candidateWrites,
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
    (originalNoX87 : originalBehavior.x87Effect = none)
    (candidateNoX87 : candidateBehavior.x87Effect = none)
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
  · simp only [RelationalBehavior.nextMachineState, originalNoX87, originalWrites,
      applyConcreteWrites, List.foldl]
    rw [originalLocation.symm.trans location.originalAddressExact]
    exact Memory.read32_write32_same_of_fits originalState.memory
      (location.range.originalBase + BitVec.ofNat 32 location.offset)
      originalValue originalFits
  · simp only [RelationalBehavior.nextMachineState, candidateNoX87, candidateWrites,
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
    (originalNoX87 : originalBehavior.x87Effect = none)
    (candidateNoX87 : candidateBehavior.x87Effect = none)
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
  · simp only [RelationalBehavior.nextMachineState, originalNoX87, originalWrites,
      applyConcreteWrites, List.foldl]
    rw [originalLocation.symm.trans location.originalAddressExact]
    exact Memory.read32_write32_same_of_fits originalState.memory
      (location.range.originalBase + BitVec.ofNat 32 location.offset)
      originalValue originalFits
  · simp only [RelationalBehavior.nextMachineState, candidateNoX87, candidateWrites,
      applyConcreteWrites, List.foldl]
    rw [candidateLocation.symm.trans location.candidateAddressExact]
    exact Memory.read32_write32_same_of_fits candidateState.memory
      (location.range.candidateBase + BitVec.ofNat 32 location.offset)
      candidateValue candidateFits

theorem stackWindowAboveWordsAvoid
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (original candidate : PureState)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world original candidate = true)
    (left right : Nat)
    (leftInside : left + 4 <= window.bytesAbove)
    (rightInside : right + 4 <= window.bytesAbove)
    (disjoint : left + 4 <= right ∨ right + 4 <= left) :
    Write32AvoidsWord
        (original.get window.originalRegister + BitVec.ofNat 32 left)
        (original.get window.originalRegister + BitVec.ofNat 32 right) ∧
      Write32AvoidsWord
        (candidate.get window.candidateRegister + BitVec.ofNat 32 left)
        (candidate.get window.candidateRegister + BitVec.ofNat 32 right) := by
  cases rangeResult : world.stackRanges.find? (fun range =>
      range.id == window.rangeId) with
  | none => simp [StackWindowPair.holds, rangeResult] at windowHolds
  | some range =>
      simp only [StackWindowPair.holds, rangeResult, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at windowHolds
      rcases windowHolds with
        ⟨⟨⟨⟨⟨_originalLower, originalUpper⟩, _candidateLower⟩,
          candidateUpper⟩, _pairedOffset⟩, _alignment⟩
      have validRows := rangesValid
      simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
        List.all_eq_true] at validRows
      have rangeMember := List.mem_of_find?_eq_some rangeResult
      have rangeValid := validRows.1.1.2 range rangeMember
      simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
        Bool.or_eq_true, decide_eq_true_eq] at rangeValid
      rcases rangeValid with
        ⟨⟨⟨disjointFromImages, _originalAligned⟩,
          _candidateAligned⟩, _sizeAligned⟩
      rcases disjointFromImages with
        ⟨⟨⟨⟨_nonempty, originalNoWrap⟩, candidateNoWrap⟩,
          _originalDisjoint⟩, _candidateDisjoint⟩
      have leftSmall : left < 2 ^ 32 := by omega
      have rightSmall : right < 2 ^ 32 := by omega
      have originalLeftBefore :
          (original.get window.originalRegister).toNat + left < 2 ^ 32 := by
        omega
      have originalRightBefore :
          (original.get window.originalRegister).toNat + right < 2 ^ 32 := by
        omega
      have candidateLeftBefore :
          (candidate.get window.candidateRegister).toNat + left < 2 ^ 32 := by
        omega
      have candidateRightBefore :
          (candidate.get window.candidateRegister).toNat + right < 2 ^ 32 := by
        omega
      have originalLeftNat :
          (original.get window.originalRegister + BitVec.ofNat 32 left).toNat =
            (original.get window.originalRegister).toNat + left := by
        simp [BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt leftSmall, Nat.mod_eq_of_lt originalLeftBefore]
      have originalRightNat :
          (original.get window.originalRegister + BitVec.ofNat 32 right).toNat =
            (original.get window.originalRegister).toNat + right := by
        simp [BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt rightSmall, Nat.mod_eq_of_lt originalRightBefore]
      have candidateLeftNat :
          (candidate.get window.candidateRegister + BitVec.ofNat 32 left).toNat =
            (candidate.get window.candidateRegister).toNat + left := by
        simp [BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt leftSmall, Nat.mod_eq_of_lt candidateLeftBefore]
      have candidateRightNat :
          (candidate.get window.candidateRegister + BitVec.ofNat 32 right).toNat =
            (candidate.get window.candidateRegister).toNat + right := by
        simp [BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt rightSmall, Nat.mod_eq_of_lt candidateRightBefore]
      constructor
      · apply write32AvoidsWord_of_nat_disjoint
        · rw [originalLeftNat]
          omega
        · rw [originalRightNat]
          omega
        · rw [originalLeftNat, originalRightNat]
          omega
      · apply write32AvoidsWord_of_nat_disjoint
        · rw [candidateLeftNat]
          omega
        · rw [candidateRightNat]
          omega
        · rw [candidateLeftNat, candidateRightNat]
          omega

theorem stackWindowAboveWordAvoidsBelowWord
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (original candidate : PureState)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world original candidate = true)
    (above below : Nat)
    (aboveInside : above + 4 <= window.bytesAbove)
    (belowAtLeastWord : 4 <= below)
    (belowInside : below <= window.bytesBelow) :
    Write32AvoidsWord
        (original.get window.originalRegister + BitVec.ofNat 32 above)
        (original.get window.originalRegister - BitVec.ofNat 32 below) ∧
      Write32AvoidsWord
        (candidate.get window.candidateRegister + BitVec.ofNat 32 above)
        (candidate.get window.candidateRegister - BitVec.ofNat 32 below) := by
  cases rangeResult : world.stackRanges.find? (fun range =>
      range.id == window.rangeId) with
  | none => simp [StackWindowPair.holds, rangeResult] at windowHolds
  | some range =>
      simp only [StackWindowPair.holds, rangeResult, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at windowHolds
      rcases windowHolds with
        ⟨⟨⟨⟨⟨originalLower, originalUpper⟩, candidateLower⟩,
          candidateUpper⟩, _pairedOffset⟩, _alignment⟩
      have validRows := rangesValid
      simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
        List.all_eq_true] at validRows
      have rangeMember := List.mem_of_find?_eq_some rangeResult
      have rangeValid := validRows.1.1.2 range rangeMember
      simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
        Bool.or_eq_true, decide_eq_true_eq] at rangeValid
      rcases rangeValid with
        ⟨⟨⟨disjointFromImages, _originalAligned⟩,
          _candidateAligned⟩, _sizeAligned⟩
      rcases disjointFromImages with
        ⟨⟨⟨⟨_nonempty, originalNoWrap⟩, candidateNoWrap⟩,
          _originalDisjoint⟩, _candidateDisjoint⟩
      have aboveSmall : above < 2 ^ 32 := by omega
      have belowSmall : below < 2 ^ 32 := by omega
      have originalEnough : below <=
          (original.get window.originalRegister).toNat := by omega
      have candidateEnough : below <=
          (candidate.get window.candidateRegister).toNat := by omega
      have originalAboveBefore :
          (original.get window.originalRegister).toNat + above < 2 ^ 32 := by
        omega
      have candidateAboveBefore :
          (candidate.get window.candidateRegister).toNat + above < 2 ^ 32 := by
        omega
      have originalAboveNat :
          (original.get window.originalRegister + BitVec.ofNat 32 above).toNat =
            (original.get window.originalRegister).toNat + above := by
        simp [BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt aboveSmall, Nat.mod_eq_of_lt originalAboveBefore]
      have candidateAboveNat :
          (candidate.get window.candidateRegister + BitVec.ofNat 32 above).toNat =
            (candidate.get window.candidateRegister).toNat + above := by
        simp [BitVec.toNat_add, BitVec.toNat_ofNat,
          Nat.mod_eq_of_lt aboveSmall, Nat.mod_eq_of_lt candidateAboveBefore]
      have originalBelowNat :
          (original.get window.originalRegister - BitVec.ofNat 32 below).toNat =
            (original.get window.originalRegister).toNat - below := by
        rw [BitVec.toNat_sub_of_le (by
          rw [BitVec.le_def]
          simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt belowSmall])]
        simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt belowSmall]
      have candidateBelowNat :
          (candidate.get window.candidateRegister - BitVec.ofNat 32 below).toNat =
            (candidate.get window.candidateRegister).toNat - below := by
        rw [BitVec.toNat_sub_of_le (by
          rw [BitVec.le_def]
          simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt belowSmall])]
        simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt belowSmall]
      constructor
      · apply write32AvoidsWord_of_nat_disjoint
        · rw [originalAboveNat]
          omega
        · rw [originalBelowNat]
          omega
        · rw [originalAboveNat, originalBelowNat]
          right
          omega
      · apply write32AvoidsWord_of_nat_disjoint
        · rw [candidateAboveNat]
          omega
        · rw [candidateBelowNat]
          omega
        · rw [candidateAboveNat, candidateBelowNat]
          right
          omega

theorem stackWindowLaterWritesAvoidSelected
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (window : StackWindowPair)
    (selected : PairedStackWordWriteItem)
    (later : List PairedStackWordWriteItem)
    (originalState candidateState : MachineState)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world originalState.registers
      candidateState.registers = true)
    (selectedInside : selected.amount + 4 <= window.bytesAbove)
    (laterChecked : later.all
      (PairedStackWordWriteItem.checked context sourceInvariant window) = true)
    (laterDisjoint : later.all (fun item => decide (
      selected.amount + 4 <= item.amount ||
        item.amount + 4 <= selected.amount)) = true) :
    WritesAvoidWord
        (originalState.registers.get window.originalRegister +
          BitVec.ofNat 32 selected.amount)
        (later.map fun item =>
          ((item.originalAddress window).eval originalState,
            item.value.original.eval originalState)) ∧
      WritesAvoidWord
        (candidateState.registers.get window.candidateRegister +
          BitVec.ofNat 32 selected.amount)
        (later.map fun item =>
          ((item.candidateAddress window).eval candidateState,
            item.value.candidate.eval candidateState)) := by
  induction later with
  | nil => simp [WritesAvoidWord]
  | cons item rest induction =>
      simp only [List.all_cons, Bool.and_eq_true] at laterChecked laterDisjoint
      have itemChecked := laterChecked.1
      simp only [PairedStackWordWriteItem.checked, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at itemChecked
      have itemDisjoint :
          selected.amount + 4 <= item.amount ∨
            item.amount + 4 <= selected.amount := by
        simpa only [decide_eq_true_eq, Bool.or_eq_true] using laterDisjoint.1
      have headAvoids := stackWindowAboveWordsAvoid context world window
        originalState.registers candidateState.registers rangesValid windowHolds
        selected.amount item.amount selectedInside itemChecked.1.2 itemDisjoint
      have tailAvoids := induction laterChecked.2 laterDisjoint.2
      constructor
      · intro write member
        simp only [List.map_cons, List.mem_cons] at member
        rcases member with rfl | member
        · simpa [PairedStackWordWriteItem.originalAddress,
            pairedStackWordAddress_eval] using headAvoids.1
        · exact tailAvoids.1 write member
      · intro write member
        simp only [List.map_cons, List.mem_cons] at member
        rcases member with rfl | member
        · simpa [PairedStackWordWriteItem.candidateAddress,
            pairedStackWordAddress_eval] using headAvoids.2
        · exact tailAvoids.2 write member

theorem Memory.read32_applyConcreteWrites_selected
    (memory : Memory) (before after : List (Word × Word))
    (address value : Word) (fits : address.toNat + 4 <= 2 ^ 32)
    (afterAvoids : WritesAvoidWord address after) :
    Memory.read32
        (applyConcreteWrites memory (before ++ (address, value) :: after)) address =
      value := by
  rw [show applyConcreteWrites memory (before ++ (address, value) :: after) =
      applyConcreteWrites
        ((applyConcreteWrites memory before).write32 address value) after by
    simp [applyConcreteWrites, List.foldl_append]]
  rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ afterAvoids]
  exact Memory.read32_write32_same_of_fits _ _ _ fits

theorem DirectCallStackWritesClaim.selectedExactWriteReadsBack
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : DirectCallStackWritesClaim)
    (before : List PairedStackWordWriteItem)
    (selected : PairedStackWordWriteItem)
    (after : List PairedStackWordWriteItem)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (claimChecked : claim.checked context sourceInvariant originalNormalized
      candidateNormalized = true)
    (writesExact : claim.stackWrites.writes = before ++ selected :: after)
    (selectedExact : selected.value.staticRelationCompatible .exact = true)
    (afterDisjoint : after.all (fun item => decide (
      selected.amount + 4 <= item.amount ||
        item.amount + 4 <= selected.amount)) = true)
    (sourceWindowMember : claim.stackWrites.window ∈ sourceInvariant.stackWindows)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (originalNoX87 : originalBehavior.x87Effect = none)
    (candidateNoX87 : candidateBehavior.x87Effect = none)
    (originalWrites : originalBehavior.writes = claim.originalWrites originalState)
    (candidateWrites : candidateBehavior.writes = claim.candidateWrites candidateState) :
    Memory.read32 (originalBehavior.nextMachineState originalState).memory
        (originalState.registers.get claim.stackWrites.window.originalRegister +
          BitVec.ofNat 32 selected.amount) =
      Memory.read32 (candidateBehavior.nextMachineState candidateState).memory
        (candidateState.registers.get claim.stackWrites.window.candidateRegister +
          BitVec.ofNat 32 selected.amount) := by
  simp only [DirectCallStackWritesClaim.checked, Bool.and_eq_true] at claimChecked
  have preparedChecked := claimChecked.1.1
  have frameChecked := claimChecked.1.2
  simp only [DirectCallStackWritesClaim.preparedWritesChecked,
    Bool.and_eq_true] at preparedChecked
  have allItemsChecked := preparedChecked.2
  simp only [List.all_eq_true] at allItemsChecked
  have selectedMember : selected ∈ claim.stackWrites.writes := by
    rw [writesExact]
    simp
  have selectedChecked := allItemsChecked selected selectedMember
  have afterChecked : after.all
      (PairedStackWordWriteItem.checked context sourceInvariant
        claim.stackWrites.window) = true := by
    simp only [List.all_eq_true]
    intro item member
    exact allItemsChecked item (by rw [writesExact]; simp [member])
  simp only [PairedStackWordWriteItem.checked, Bool.and_eq_true,
    beq_iff_eq, decide_eq_true_eq] at selectedChecked
  have selectedAligned := selectedChecked.1.1
  have selectedInside := selectedChecked.1.2
  have selectedValuesEqual := selected.value.eval_equal_of_checked_exact
    context world sourceInvariant selectedChecked.2 selectedExact originalState
    candidateState related
  simp only [DirectCallStackWritesClaim.frameChecked, Bool.and_eq_true,
    decide_eq_true_eq, beq_iff_eq] at frameChecked
  rcases frameChecked with
    ⟨⟨⟨⟨⟨⟨stackAtLeast, _stackAligned⟩, stackFits⟩, enoughBelow⟩,
      _calleePresent⟩, _continuationPair⟩, _zeroAgreement⟩
  have relatedForWindow := related
  rcases relatedForWindow with
    ⟨_worldValid, rangesValid, _stackMemory, _importsStatic,
      _importsComplete, _importsMemory, _originalImmutable,
      _candidateImmutable, relatedCore, _trailing⟩
  rcases relatedCore with
    ⟨_inputRegisters, _inputBounds, _inputSeparations, inputStackWindows,
      _inputMemory, _inputDynamicMemory, _inputUndefined, _inputX87,
      _inputFlags, _inputFsBase⟩
  simp only [stackWindowsRelated, List.all_eq_true] at inputStackWindows
  have windowHolds := inputStackWindows claim.stackWrites.window sourceWindowMember
  have laterAvoids := stackWindowLaterWritesAvoidSelected context world sourceInvariant
    claim.stackWrites.window selected after originalState candidateState rangesValid
    windowHolds selectedInside afterChecked afterDisjoint
  have pushAvoids := stackWindowAboveWordAvoidsBelowWord context world
    claim.stackWrites.window originalState.registers candidateState.registers
    rangesValid windowHolds selected.amount claim.stackAmount selectedInside
    stackAtLeast enoughBelow
  rcases pairedStackWordLocation_above_window context world claim.stackWrites.window
      originalState.registers candidateState.registers rangesValid windowHolds
      selected.amount selectedAligned selectedInside with
    ⟨location, originalLocation, candidateLocation⟩
  have locationValid : location.range.disjointFromImages context = true := by
    have validRows := rangesValid
    simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
      List.all_eq_true] at validRows
    exact (validRows.1.1.2 location.range location.rangeMember).1.1.1
  have originalFits := DynamicAddressRangePair.wordAddress_fits context false
    location.range locationValid location.offset location.inside
  have candidateFits := DynamicAddressRangePair.wordAddress_fits context true
    location.range locationValid location.offset location.inside
  let originalBeforeWrites : List (Word × Word) := before.map fun item =>
    ((item.originalAddress claim.stackWrites.window).eval originalState,
      item.value.original.eval originalState)
  let candidateBeforeWrites : List (Word × Word) := before.map fun item =>
    ((item.candidateAddress claim.stackWrites.window).eval candidateState,
      item.value.candidate.eval candidateState)
  let originalAfterWrites : List (Word × Word) := after.map fun item =>
    ((item.originalAddress claim.stackWrites.window).eval originalState,
      item.value.original.eval originalState)
  let candidateAfterWrites : List (Word × Word) := after.map fun item =>
    ((item.candidateAddress claim.stackWrites.window).eval candidateState,
      item.value.candidate.eval candidateState)
  let originalPush : Word × Word :=
    (claim.originalPushAddress.eval originalState,
      BitVec.ofNat 32 claim.originalReturnAddress)
  let candidatePush : Word × Word :=
    (claim.candidatePushAddress.eval candidateState,
      BitVec.ofNat 32 claim.candidateReturnAddress)
  have originalTailAvoids : WritesAvoidWord
      (originalState.registers.get claim.stackWrites.window.originalRegister +
        BitVec.ofNat 32 selected.amount) (originalAfterWrites ++ [originalPush]) := by
    intro write member
    simp only [List.mem_append, List.mem_singleton] at member
    rcases member with member | rfl
    · exact laterAvoids.1 write member
    · simpa [originalPush, DirectCallStackWritesClaim.originalPushAddress,
        Expr.eval, word_add_ia32_twos_complement _ claim.stackAmount stackFits]
        using pushAvoids.1
  have candidateTailAvoids : WritesAvoidWord
      (candidateState.registers.get claim.stackWrites.window.candidateRegister +
        BitVec.ofNat 32 selected.amount) (candidateAfterWrites ++ [candidatePush]) := by
    intro write member
    simp only [List.mem_append, List.mem_singleton] at member
    rcases member with member | rfl
    · exact laterAvoids.2 write member
    · simpa [candidatePush, DirectCallStackWritesClaim.candidatePushAddress,
        Expr.eval, word_add_ia32_twos_complement _ claim.stackAmount stackFits]
        using pushAvoids.2
  have originalAddress :
      (selected.originalAddress claim.stackWrites.window).eval originalState =
        location.originalAddress := by
    simpa [PairedStackWordWriteItem.originalAddress,
      pairedStackWordAddress_eval] using originalLocation.symm
  have candidateAddress :
      (selected.candidateAddress claim.stackWrites.window).eval candidateState =
        location.candidateAddress := by
    simpa [PairedStackWordWriteItem.candidateAddress,
      pairedStackWordAddress_eval] using candidateLocation.symm
  have originalAddressFits :
      ((selected.originalAddress claim.stackWrites.window).eval originalState).toNat +
          4 <= 2 ^ 32 := by
    rw [originalAddress, location.originalAddressExact]
    exact originalFits
  have candidateAddressFits :
      ((selected.candidateAddress claim.stackWrites.window).eval candidateState).toNat +
          4 <= 2 ^ 32 := by
    rw [candidateAddress, location.candidateAddressExact]
    exact candidateFits
  have originalTailAvoidsSelected : WritesAvoidWord
      ((selected.originalAddress claim.stackWrites.window).eval originalState)
      (originalAfterWrites ++ [originalPush]) := by
    simpa [PairedStackWordWriteItem.originalAddress,
      pairedStackWordAddress_eval] using originalTailAvoids
  have candidateTailAvoidsSelected : WritesAvoidWord
      ((selected.candidateAddress claim.stackWrites.window).eval candidateState)
      (candidateAfterWrites ++ [candidatePush]) := by
    simpa [PairedStackWordWriteItem.candidateAddress,
      pairedStackWordAddress_eval] using candidateTailAvoids
  have originalWritesShape : claim.originalWrites originalState =
      originalBeforeWrites ++
        ((selected.originalAddress claim.stackWrites.window).eval originalState,
          selected.value.original.eval originalState) ::
        (originalAfterWrites ++ [originalPush]) := by
    simp [DirectCallStackWritesClaim.originalWrites,
      PairedStackWordWritesClaim.originalWrites, writesExact,
      originalBeforeWrites, originalAfterWrites, originalPush]
  have candidateWritesShape : claim.candidateWrites candidateState =
      candidateBeforeWrites ++
        ((selected.candidateAddress claim.stackWrites.window).eval candidateState,
          selected.value.candidate.eval candidateState) ::
        (candidateAfterWrites ++ [candidatePush]) := by
    simp [DirectCallStackWritesClaim.candidateWrites,
      PairedStackWordWritesClaim.candidateWrites, writesExact,
      candidateBeforeWrites, candidateAfterWrites, candidatePush]
  have originalRead :
      Memory.read32 (originalBehavior.nextMachineState originalState).memory
          ((selected.originalAddress claim.stackWrites.window).eval originalState) =
        selected.value.original.eval originalState := by
    rw [show (originalBehavior.nextMachineState originalState).memory =
        applyConcreteWrites originalState.memory originalBehavior.writes by
          simp [RelationalBehavior.nextMachineState, originalNoX87]]
    rw [originalWrites, originalWritesShape]
    exact Memory.read32_applyConcreteWrites_selected originalState.memory
      originalBeforeWrites (originalAfterWrites ++ [originalPush])
      ((selected.originalAddress claim.stackWrites.window).eval originalState)
      (selected.value.original.eval originalState) originalAddressFits
      originalTailAvoidsSelected
  have candidateRead :
      Memory.read32 (candidateBehavior.nextMachineState candidateState).memory
          ((selected.candidateAddress claim.stackWrites.window).eval candidateState) =
        selected.value.candidate.eval candidateState := by
    rw [show (candidateBehavior.nextMachineState candidateState).memory =
        applyConcreteWrites candidateState.memory candidateBehavior.writes by
          simp [RelationalBehavior.nextMachineState, candidateNoX87]]
    rw [candidateWrites, candidateWritesShape]
    exact Memory.read32_applyConcreteWrites_selected candidateState.memory
      candidateBeforeWrites (candidateAfterWrites ++ [candidatePush])
      ((selected.candidateAddress claim.stackWrites.window).eval candidateState)
      (selected.value.candidate.eval candidateState) candidateAddressFits
      candidateTailAvoidsSelected
  rw [← pairedStackWordAddress_eval claim.stackWrites.window.originalRegister
      selected.amount originalState,
    ← pairedStackWordAddress_eval claim.stackWrites.window.candidateRegister
      selected.amount candidateState]
  exact originalRead.trans (selectedValuesEqual.trans candidateRead.symm)

theorem pairedStackWordWriteReadsBack
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant) (sourceWindow : StackWindowPair)
    (originalValue candidateValue : Word)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (originalNoX87 : originalBehavior.x87Effect = none)
    (candidateNoX87 : candidateBehavior.x87Effect = none)
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
    candidateBehavior originalNoX87 candidateNoX87 related sourceWindowMember
    (by decide) (by decide)
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
  have originalNoX87 := evalBehavior_x87Effect_none false localCodeTargets
    originalState originalBehavior originalResult originalEval
  have candidateNoX87 := evalBehavior_x87Effect_none true localCodeTargets
    candidateState candidateBehavior candidateResult candidateEval
  have originalRegistersExact :
      (originalResult.nextMachineState originalState).registers =
        originalResult.registers := by
    simp [RelationalBehavior.nextMachineState, originalNoX87]
  have candidateRegistersExact :
      (candidateResult.nextMachineState candidateState).registers =
        candidateResult.registers := by
    simp [RelationalBehavior.nextMachineState, candidateNoX87]
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
    originalState candidateState originalResult candidateResult originalNoX87
    candidateNoX87 relatedForReadback
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
      originalNoX87, candidateNoX87, applyConcreteWrites] using outputWords
  rw [targetInventory]
  simp only [activeDynamicStackRangeRelationsHold, List.all_cons, List.all_nil,
    Bool.and_true]
  unfold DynamicStackRangeRelation.activeHolds
  simp only [Bool.and_eq_true, List.any_eq_true, beq_iff_eq]
  refine ⟨?_, range, rangeMember, ?_⟩
  · rw [targetWindowExact]
    rw [originalRegistersExact, candidateRegistersExact]
    change writeClaim.window.holds world originalResult.registers
      candidateResult.registers = true
    unfold StackWindowPair.holds
    rw [outputBases.1, outputBases.2]
    simpa only [StackWindowPair.holds] using sourceWindowHolds
  · refine ⟨⟨⟨⟨?_, ?_⟩, ?_⟩, activeWordsSubset⟩, outputWordsExact⟩
    · rw [targetWindowExact, targetStackOffsetExact]
      rw [originalRegistersExact]
      change Memory.read32 (originalResult.nextMachineState originalState).memory
        (originalResult.registers.get writeClaim.window.originalRegister +
          BitVec.ofNat 32 writeClaim.amount) = _
      rw [outputBases.1, readsBack.1,
        sourceOriginalValue, targetOriginalOffsetExact]
    · rw [targetWindowExact, targetStackOffsetExact]
      rw [candidateRegistersExact]
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
  have originalNoX87 := evalBehavior_x87Effect_none false localCodeTargets
    originalState originalBehavior originalResult originalEval
  have candidateNoX87 := evalBehavior_x87Effect_none true localCodeTargets
    candidateState candidateBehavior candidateResult candidateEval
  have originalRegistersExact :
      (originalResult.nextMachineState originalState).registers =
        originalResult.registers := by
    simp [RelationalBehavior.nextMachineState, originalNoX87]
  have candidateRegistersExact :
      (candidateResult.nextMachineState candidateState).registers =
        candidateResult.registers := by
    simp [RelationalBehavior.nextMachineState, candidateNoX87]
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
    originalResult candidateResult originalNoX87 candidateNoX87 contextValid
    relatedForReadback writesChecked spillCheckedForReadback
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
      shapeCandidateWrites, originalNoX87, candidateNoX87] using outputWords
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
    rw [originalRegistersExact, candidateRegistersExact]
    change spillClaim.window.holds world originalResult.registers
      candidateResult.registers = true
    unfold StackWindowPair.holds
    rw [outputBases.1, outputBases.2]
    simpa only [StackWindowPair.holds] using sourceWindowHolds
  · refine ⟨⟨⟨⟨?_, ?_⟩, ?_⟩, activeWordsSubset⟩, outputWordsExact⟩
    · rw [targetWindowExact, targetStackOffsetExact]
      rw [originalRegistersExact]
      change Memory.read32 (originalResult.nextMachineState originalState).memory
        (originalResult.registers.get spillClaim.window.originalRegister +
          BitVec.ofNat 32 spillClaim.amount) = _
      rw [outputBases.1, readsBack.1,
        sourceOriginalValue, targetOriginalOffsetExact]
    · rw [targetWindowExact, targetStackOffsetExact]
      rw [candidateRegistersExact]
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
    (originalNoX87 : originalBehavior.x87Effect = none)
    (candidateNoX87 : candidateBehavior.x87Effect = none)
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
    (originRegisters : registerValueOriginRelationsHold context world
      targetInvariant.registerValueOriginRelations originalBehavior.registers
      candidateBehavior.registers = true)
    (memoryOrigins : memoryValueOriginRelationsHold context world
      targetInvariant.memoryValueOriginRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (dynamicRegisters : activeDynamicRegisterRangeRelationsHold context world
      targetInvariant.dynamicRegisterRangeRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (dynamicStacks : activeDynamicStackRangeRelationsHold context world
      targetInvariant.dynamicStackRangeRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (predicates : pairedStatePredicatesHold targetInvariant.predicates
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
    ⟨_, _, _, _, inputMemory, inputDynamicWords, inputUndefined, inputX87, _,
      inputFsBase⟩
  have outputX87 : MachineX87Related context world
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) := by
    refine ⟨x87, ?_, ?_⟩
    · simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using inputX87.2.1
    · simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using inputX87.2.2
  refine ⟨worldStatic, stackRangesValid, ?_, importsStatic, importsComplete,
    ?_, ?_, ?_, ?_, ?_⟩
  · simpa [RelationalBehavior.nextMachineState, originalWrites,
      candidateWrites, originalNoX87, candidateNoX87] using stackMemory
  · simpa [RelationalBehavior.nextMachineState, originalWrites,
      candidateWrites, originalNoX87, candidateNoX87] using importsMemory
  · simpa [RelationalBehavior.nextMachineState, originalWrites,
      originalNoX87] using originalImmutable
  · simpa [RelationalBehavior.nextMachineState, candidateWrites,
      candidateNoX87] using candidateImmutable
  · refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, outputX87, ?_, ?_⟩
    · simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using registers
    · simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using bounds
    · simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using separations
    · simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using stackWindows
    · simpa [RelationalBehavior.nextMachineState, originalWrites,
        candidateWrites, originalNoX87, candidateNoX87] using
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
            originalWrites, candidateWrites, originalNoX87, candidateNoX87] using
            inputDynamicWords.staticPointerSlots
        staticWordSlots := by
          simpa [originalNext, candidateNext, RelationalBehavior.nextMachineState,
            originalWrites, candidateWrites, originalNoX87, candidateNoX87] using
            inputDynamicWords.staticWordSlots
        active := {
          registerRanges := outputDynamicRegisters
          stackRanges := outputDynamicStacks
        }
      }
    · simpa [RelationalBehavior.nextMachineState] using inputUndefined
    · simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using flags
    · simpa [RelationalBehavior.nextMachineState] using inputFsBase
  · exact ⟨by simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using importRegisters,
      by simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using originRegisters,
      memoryOrigins,
      dynamicRegisterRangeRelationsHold_of_active context world
        targetInvariant.dynamicRegisterRangeRelations _ _ dynamicRegisters,
      dynamicStackRangeRelationsHold_of_active context world
        targetInvariant.dynamicStackRangeRelations _ _ dynamicStacks,
      predicates⟩

theorem StateRel.afterPairedMemoryFamiliesUpdate
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (originalWrites candidateWrites : List (Word × Word))
    (related : StateRel context world sourceInvariant originalState candidateState)
    (originalWritesExact : originalBehavior.writes = originalWrites)
    (candidateWritesExact : candidateBehavior.writes = candidateWrites)
    (originalNoX87 : originalBehavior.x87Effect = none)
    (candidateNoX87 : candidateBehavior.x87Effect = none)
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
    (originRegisters : registerValueOriginRelationsHold context world
      targetInvariant.registerValueOriginRelations originalBehavior.registers
      candidateBehavior.registers = true)
    (memoryOrigins : memoryValueOriginRelationsHold context world
      targetInvariant.memoryValueOriginRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (dynamicRegisters : activeDynamicRegisterRangeRelationsHold context world
      targetInvariant.dynamicRegisterRangeRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (dynamicStacks : activeDynamicStackRangeRelationsHold context world
      targetInvariant.dynamicStackRangeRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (predicates : pairedStatePredicatesHold targetInvariant.predicates
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
    ⟨_, _, _, _, _inputMemory, _inputDynamicWords, inputUndefined, inputX87, _,
      inputFsBase⟩
  have outputX87 : MachineX87Related context world
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) := by
    refine ⟨x87, ?_, ?_⟩
    · simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using inputX87.2.1
    · simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using inputX87.2.2
  refine ⟨worldStatic, stackRangesValid, ?_, importsStatic, importsComplete,
    ?_, ?_, ?_, ?_, ?_⟩
  · simpa [RelationalBehavior.nextMachineState, originalWritesExact,
      candidateWritesExact, originalNoX87, candidateNoX87] using
      memoryFamilies.stackRanges
  · simpa [RelationalBehavior.nextMachineState, originalWritesExact,
      candidateWritesExact, originalNoX87, candidateNoX87] using
      memoryFamilies.importAddresses
  · simpa [RelationalBehavior.nextMachineState, originalWritesExact,
      originalNoX87] using
      memoryFamilies.originalImmutable
  · simpa [RelationalBehavior.nextMachineState, candidateWritesExact,
      candidateNoX87] using
      memoryFamilies.candidateImmutable
  · refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, outputX87, ?_, ?_⟩
    · simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using registers
    · simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using bounds
    · simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using separations
    · simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using stackWindows
    · simpa [RelationalBehavior.nextMachineState, originalWritesExact,
        candidateWritesExact, originalNoX87, candidateNoX87] using
        memoryFamilies.ordinary
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
            originalWritesExact, candidateWritesExact, originalNoX87,
            candidateNoX87] using
            memoryFamilies.staticPointerSlots
        staticWordSlots := by
          simpa [originalNext, candidateNext, RelationalBehavior.nextMachineState,
            originalWritesExact, candidateWritesExact, originalNoX87,
            candidateNoX87] using
            memoryFamilies.staticWordSlots
        active := {
          registerRanges := outputDynamicRegisters
          stackRanges := outputDynamicStacks
        }
      }
    · simpa [RelationalBehavior.nextMachineState] using inputUndefined
    · simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using flags
    · simpa [RelationalBehavior.nextMachineState] using inputFsBase
  · exact ⟨by simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using importRegisters,
      by simpa [RelationalBehavior.nextMachineState, originalNoX87,
        candidateNoX87] using originRegisters,
      memoryOrigins,
      dynamicRegisterRangeRelationsHold_of_active context world
        targetInvariant.dynamicRegisterRangeRelations _ _ dynamicRegisters,
      dynamicStackRangeRelationsHold_of_active context world
        targetInvariant.dynamicStackRangeRelations _ _ dynamicStacks,
      predicates⟩

/-- Rebuild `StateRel` after an already checked list of paired framed updates.
The update constructors carry the value relation and location evidence; exact
decoded write equality prevents this theorem from authorizing an omitted or
invented memory effect. -/
theorem StateRel.afterPairedPreparedWordUpdatesEvaluation
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (updates : List (PairedPreparedWordUpdate context world))
    (contextValid : context.StructurallyValid)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (originalWrites :
      originalBehavior.writes =
        updates.map PairedPreparedWordUpdate.originalWrite)
    (candidateWrites :
      candidateBehavior.writes =
        updates.map PairedPreparedWordUpdate.candidateWrite)
    (originalNoX87 : originalBehavior.x87Effect = none)
    (candidateNoX87 : candidateBehavior.x87Effect = none)
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
    (originRegisters : registerValueOriginRelationsHold context world
      targetInvariant.registerValueOriginRelations originalBehavior.registers
      candidateBehavior.registers = true)
    (memoryOrigins : memoryValueOriginRelationsHold context world
      targetInvariant.memoryValueOriginRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (dynamicRegisters : activeDynamicRegisterRangeRelationsHold context world
      targetInvariant.dynamicRegisterRangeRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (dynamicStacks : activeDynamicStackRangeRelationsHold context world
      targetInvariant.dynamicStackRangeRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (predicates : pairedStatePredicatesHold targetInvariant.predicates
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true) :
    StateRel context world targetInvariant
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) := by
  have relatedForFinal := related
  rcases related with
    ⟨worldValid, stackRangesValid, stackMemory, importsStatic, _importsComplete,
      importsMemory, originalImmutable, candidateImmutable, relatedCore,
      _inputImportRegisters⟩
  rcases relatedCore with
    ⟨_inputRegisters, _inputBounds, _inputSeparations, _inputStackWindows,
      inputMemory, inputDynamicMemory, _inputUndefined, _inputX87,
      _inputFlags, _inputFsBase⟩
  have worldDynamicValid : world.dynamicRangesValid context = true := by
    simp only [RelationalWorld.valid, Bool.and_eq_true] at worldValid
    exact worldValid.1.1.1.1
  have staticSlotsValid : staticDynamicPointerSlotsValid context = true := by
    rcases contextValid with
      ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _, _⟩
    exact slotsValid
  have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
    rcases contextValid with
      ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _⟩
    exact slotsValid
  have memoryFamilies :=
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
  exact StateRel.afterPairedMemoryFamiliesUpdate context world sourceInvariant
    targetInvariant originalState candidateState originalBehavior candidateBehavior
    (updates.map PairedPreparedWordUpdate.originalWrite)
    (updates.map PairedPreparedWordUpdate.candidateWrite)
    relatedForFinal
    originalWrites candidateWrites originalNoX87 candidateNoX87 memoryFamilies
    registers bounds separations stackWindows x87 flags importRegisters
    originRegisters memoryOrigins dynamicRegisters dynamicStacks predicates

/-- Reusable framed-memory transition for a decoded list of paired word writes.
The claim classifies each concrete write, while this theorem preserves every
authoritative flat-memory relation before rebuilding `StateRel`. -/
theorem StateRel.afterPairedPreparedWordWritesEvaluation
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalState candidateState : MachineState)
    (originalBehavior candidateBehavior : RelationalBehavior)
    (claim : PairedPreparedWordWritesClaim)
    (contextValid : context.StructurallyValid)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (claimChecked : claim.checked context sourceInvariant = true)
    (originalWrites :
      originalBehavior.writes = claim.originalWrites originalState)
    (candidateWrites :
      candidateBehavior.writes = claim.candidateWrites candidateState)
    (originalNoX87 : originalBehavior.x87Effect = none)
    (candidateNoX87 : candidateBehavior.x87Effect = none)
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
    (originRegisters : registerValueOriginRelationsHold context world
      targetInvariant.registerValueOriginRelations originalBehavior.registers
      candidateBehavior.registers = true)
    (memoryOrigins : memoryValueOriginRelationsHold context world
      targetInvariant.memoryValueOriginRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (dynamicRegisters : activeDynamicRegisterRangeRelationsHold context world
      targetInvariant.dynamicRegisterRangeRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (dynamicStacks : activeDynamicStackRangeRelationsHold context world
      targetInvariant.dynamicStackRangeRelations
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true)
    (predicates : pairedStatePredicatesHold targetInvariant.predicates
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) = true) :
    StateRel context world targetInvariant
      (originalBehavior.nextMachineState originalState)
      (candidateBehavior.nextMachineState candidateState) := by
  simp only [PairedPreparedWordWritesClaim.checked, Bool.and_eq_true]
    at claimChecked
  have itemsChecked := claimChecked.2
  have relatedForUpdates := related
  rcases related with
    ⟨_worldValid, stackRangesValid, _stackMemory, _importsStatic,
      _importsComplete, _importsMemory, _originalImmutable,
      _candidateImmutable, _relatedCore, _inputImportRegisters⟩
  rcases pairedPreparedWordUpdates_of_checkedItems context world sourceInvariant
      claim.writes originalState candidateState stackRangesValid itemsChecked
      relatedForUpdates with
    ⟨updates, originalUpdateWrites, candidateUpdateWrites, _updateKinds⟩
  exact StateRel.afterPairedPreparedWordUpdatesEvaluation context world
    sourceInvariant targetInvariant originalState candidateState originalBehavior
    candidateBehavior updates contextValid relatedForUpdates
    (originalWrites.trans originalUpdateWrites.symm)
    (candidateWrites.trans candidateUpdateWrites.symm)
    originalNoX87 candidateNoX87 registers bounds separations stackWindows x87
    flags importRegisters originRegisters memoryOrigins dynamicRegisters dynamicStacks
    predicates

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
  have originalNoX87 := evalBehavior_x87Effect_none false localCodeTargets
    originalState originalBehavior originalResult originalEval
  have candidateNoX87 := evalBehavior_x87Effect_none true localCodeTargets
    candidateState candidateBehavior candidateResult candidateEval
  rw [originalEval, candidateEval]
  refine ⟨originalExit, candidateExit, outcomes, ?_⟩
  cases edge.exit with
  | internal target =>
      rcases stateTransfer world originalState candidateState originalResult
          candidateResult related originalEval candidateEval guardTrue with
        ⟨registers, bounds, separations, stackWindows, x87, flags,
          originRegisters, memoryOrigins, predicates⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      have outputDynamicStack := dynamicStackTransfer world originalState candidateState
        originalResult candidateResult related originalEval candidateEval guardTrue
      exact StateRel.afterNoWriteEvaluation context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        relatedForTransfer originalWrites candidateWrites originalNoX87 candidateNoX87
        registers bounds separations stackWindows x87 flags outputImports
        originRegisters memoryOrigins outputDynamic outputDynamicStack predicates
  | external imported => trivial
  | returned => trivial
  | fault => trivial

theorem segmentTransitionBodyClosed_of_no_write_with_transfers
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (localCodeTargets : List CodeTargetPair) (localValues : List ValueTargetPair)
    (localCodeTargetsResolved :
      context.codeMap.resolveIds edge.localCodeTargetIds = some localCodeTargets)
    (localValuesResolved :
      context.dataMap.resolveIds edge.localValueTargetIds = some localValues)
    (shape : NoWriteSegmentShapeBodyClosed context edge sourceInvariant
      originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferBodyClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicTransfer : NoWriteSegmentDynamicTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (dynamicStackTransfer : NoWriteSegmentDynamicStackTransferClosed context edge
      sourceInvariant targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionBodyClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  unfold SegmentTransitionBodyClosed
  rw [localCodeTargetsResolved, localValuesResolved]
  unfold NoWriteSegmentShapeBodyClosed at shape
  rw [localCodeTargetsResolved, localValuesResolved] at shape
  unfold NoWriteSegmentStateTransferBodyClosed at stateTransfer
  rw [localCodeTargetsResolved] at stateTransfer
  unfold NoWriteSegmentImportTransferClosed at importTransfer
  rw [localCodeTargetsResolved] at importTransfer
  unfold NoWriteSegmentDynamicTransferClosed at dynamicTransfer
  rw [localCodeTargetsResolved] at dynamicTransfer
  unfold NoWriteSegmentDynamicStackTransferClosed at dynamicStackTransfer
  rw [localCodeTargetsResolved] at dynamicStackTransfer
  intro world originalState candidateState related guardsAgree guardTrue
  have relatedForShape := related
  have relatedForTransfer := related
  have relatedForImports := related
  have relatedForDynamic := related
  rcases shape world originalState candidateState relatedForShape guardsAgree guardTrue with
    ⟨originalResult, candidateResult, originalEval, candidateEval, originalWrites,
      candidateWrites, originalExit, candidateExit, outcomes⟩
  have originalNoX87 := evalBehavior_x87Effect_none false localCodeTargets
    originalState originalBehavior originalResult originalEval
  have candidateNoX87 := evalBehavior_x87Effect_none true localCodeTargets
    candidateState candidateBehavior candidateResult candidateEval
  rw [originalEval, candidateEval]
  refine ⟨originalExit, candidateExit, outcomes, ?_⟩
  cases edge.exit with
  | internal target =>
      rcases stateTransfer world originalState candidateState originalResult
          candidateResult related originalEval candidateEval guardsAgree guardTrue with
        ⟨registers, bounds, separations, stackWindows, x87, flags,
          originRegisters, memoryOrigins, predicates⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      have outputDynamicStack := dynamicStackTransfer world originalState candidateState
        originalResult candidateResult related originalEval candidateEval guardTrue
      exact StateRel.afterNoWriteEvaluation context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        relatedForTransfer originalWrites candidateWrites originalNoX87 candidateNoX87
        registers bounds separations stackWindows x87 flags outputImports
        originRegisters memoryOrigins outputDynamic outputDynamicStack predicates
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
  have originalNoX87 := evalBehavior_x87Effect_none false localCodeTargets
    originalState originalBehavior originalResult originalEval
  have candidateNoX87 := evalBehavior_x87Effect_none true localCodeTargets
    candidateState candidateBehavior candidateResult candidateEval
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
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _, _⟩
        exact slotsValid
      have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _⟩
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
        ⟨registers, bounds, separations, stackWindows, x87, flags,
          originRegisters, memoryOrigins, predicates⟩
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
        originalNoX87 candidateNoX87
      · simpa [applyConcreteWrites, originalWriteAddress, candidateWriteAddress] using
          outputMemoryFamilies
      · exact registers
      · exact bounds
      · exact separations
      · exact stackWindows
      · exact x87
      · exact flags
      · exact outputImports
      · exact originRegisters
      · exact memoryOrigins
      · exact outputDynamic
      · exact outputDynamicStack
      · exact predicates
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
  have originalNoX87 := evalBehavior_x87Effect_none false localCodeTargets
    originalState originalBehavior originalResult originalEval
  have candidateNoX87 := evalBehavior_x87Effect_none true localCodeTargets
    candidateState candidateBehavior candidateResult candidateEval
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
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _, _⟩
        exact slotsValid
      have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _⟩
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
        ⟨registers, bounds, separations, stackWindows, x87, flags,
          originRegisters, memoryOrigins, predicates⟩
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
        related originalWrites candidateWrites originalNoX87 candidateNoX87
      · simpa [applyConcreteWrites, originalWriteAddress, candidateWriteAddress] using
          outputMemoryFamilies
      · exact registers
      · exact bounds
      · exact separations
      · exact stackWindows
      · exact x87
      · exact flags
      · exact outputImports
      · exact originRegisters
      · exact memoryOrigins
      · exact outputDynamic
      · exact outputDynamicStack
      · exact predicates
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
  have originalNoX87 := evalBehavior_x87Effect_none false localCodeTargets
    originalState originalBehavior originalResult originalEval
  have candidateNoX87 := evalBehavior_x87Effect_none true localCodeTargets
    candidateState candidateBehavior candidateResult candidateEval
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
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _, _⟩
        exact slotsValid
      have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _⟩
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
        ⟨registers, bounds, separations, stackWindows, x87, flags,
          originRegisters, memoryOrigins, predicates⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      apply StateRel.afterPairedMemoryFamiliesUpdate context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        (claim.originalWrites originalState) (claim.candidateWrites candidateState)
        related originalWrites candidateWrites originalNoX87 candidateNoX87
        outputMemoryFamilies registers bounds
        separations stackWindows x87 flags outputImports originRegisters memoryOrigins
        outputDynamic
        (by simp [targetDynamicStackRelationsEmpty, activeDynamicStackRangeRelationsHold])
        predicates
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
  have originalNoX87 := evalBehavior_x87Effect_none false localCodeTargets
    originalState originalBehavior originalResult originalEval
  have candidateNoX87 := evalBehavior_x87Effect_none true localCodeTargets
    candidateState candidateBehavior candidateResult candidateEval
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
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _, _⟩
        exact slotsValid
      have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _⟩
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
        ⟨registers, bounds, separations, stackWindows, x87, flags,
          originRegisters, memoryOrigins, predicates⟩
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
        related originalWrites candidateWrites originalNoX87 candidateNoX87
        outputMemoryFamilies registers bounds
        separations stackWindows x87 flags outputImports originRegisters memoryOrigins
        outputDynamic
        outputDynamicStack
        predicates
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
  have originalNoX87 := evalBehavior_x87Effect_none false localCodeTargets
    originalState originalBehavior originalResult originalEval
  have candidateNoX87 := evalBehavior_x87Effect_none true localCodeTargets
    candidateState candidateBehavior candidateResult candidateEval
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
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _, _⟩
        exact slotsValid
      have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _⟩
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
        ⟨registers, bounds, separations, stackWindows, x87, flags,
          originRegisters, memoryOrigins, predicates⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      apply StateRel.afterPairedMemoryFamiliesUpdate context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        (claim.originalWrites originalState) (claim.candidateWrites candidateState)
        related originalWrites candidateWrites originalNoX87 candidateNoX87
        outputMemoryFamilies registers bounds
        separations stackWindows x87 flags outputImports originRegisters memoryOrigins
        outputDynamic
        (by simp [targetDynamicStackRelationsEmpty, activeDynamicStackRangeRelationsHold])
        predicates
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
  have originalNoX87 := evalBehavior_x87Effect_none false localCodeTargets
    originalState originalBehavior originalResult originalEval
  have candidateNoX87 := evalBehavior_x87Effect_none true localCodeTargets
    candidateState candidateBehavior candidateResult candidateEval
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
          ⟨_, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _, _⟩
        exact slotsValid
      have staticWordSlotsValid : staticWordRelationSlotsValid context = true := by
        rcases contextValid with
          ⟨_, _, _, _, _, _, _, _, _, slotsValid, _, _, _, _, _, _, _⟩
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
        ⟨registers, bounds, separations, stackWindows, x87, flags,
          originRegisters, memoryOrigins, predicates⟩
      have outputImports := importTransfer world originalState candidateState
        originalResult candidateResult relatedForImports originalEval candidateEval
      have outputDynamic := dynamicTransfer world originalState candidateState
        originalResult candidateResult relatedForDynamic originalEval candidateEval
        guardTrue
      apply StateRel.afterPairedMemoryFamiliesUpdate context world sourceInvariant
        targetInvariant originalState candidateState originalResult candidateResult
        (claim.originalWrites originalState) (claim.candidateWrites candidateState)
        related originalWrites candidateWrites originalNoX87 candidateNoX87
        outputMemoryFamilies registers bounds
        separations stackWindows x87 flags outputImports originRegisters memoryOrigins
        outputDynamic
        (by simp [targetDynamicStackRelationsEmpty, activeDynamicStackRangeRelationsHold])
        predicates
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

theorem segmentTransitionClosed_of_direct_call_with_imports
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
    (targetDynamicRelationsEmpty :
      targetInvariant.dynamicRegisterRangeRelations = [])
    (targetDynamicStackRelationsEmpty :
      targetInvariant.dynamicStackRangeRelations = [])
    (shape : DirectCallSegmentShapeClosed context edge sourceInvariant sourceWindow
      stackAmount originalReturnAddress candidateReturnAddress originalBehavior
      candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior)
    (importTransfer : NoWriteSegmentImportTransferClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionClosed_of_direct_call_with_transfers context edge
    sourceInvariant targetInvariant sourceWindow stackAmount originalReturnAddress
    candidateReturnAddress originalBehavior candidateBehavior localCodeTargets localValues
    localCodeTargetsResolved localValuesResolved contextValid sourceWindowMember
    stackAmountAtLeastWord stackAmountAligned sourceWindowEnoughBelow
    returnAddressesRelated shape stateTransfer importTransfer
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

theorem segmentTransitionBodyClosed_of_no_write
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
    (shape : NoWriteSegmentShapeBodyClosed context edge sourceInvariant
      originalBehavior candidateBehavior)
    (stateTransfer : NoWriteSegmentStateTransferBodyClosed context edge sourceInvariant
      targetInvariant originalBehavior candidateBehavior) :
    SegmentTransitionBodyClosed context edge sourceInvariant targetInvariant
      originalBehavior candidateBehavior := by
  apply segmentTransitionBodyClosed_of_no_write_with_transfers context edge
    sourceInvariant targetInvariant originalBehavior candidateBehavior
    localCodeTargets localValues localCodeTargetsResolved localValuesResolved shape
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
  · exact noWriteSegmentDynamicStackTransferClosed_of_empty context edge
      sourceInvariant targetInvariant originalBehavior candidateBehavior
      localCodeTargets localCodeTargetsResolved targetDynamicStackRelationsEmpty

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
  (∃ originalBehavior candidateBehavior,
      regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
        context.machineImportCallContracts edge.originalSpan = some originalBehavior ∧
      regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
        context.machineImportCallContracts edge.candidateSpan = some candidateBehavior ∧
      SegmentTransitionClosed context edge sourceInvariant targetInvariant
        originalBehavior candidateBehavior) ∨
    X87SegmentTransitionClosed context edge sourceInvariant targetInvariant

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
  Or.inl
    ⟨originalBehavior, candidateBehavior, originalDecoded, candidateDecoded, transition⟩

theorem relationalSegmentRefinement_of_x87_singleton
    (context : StaticProofContext) (edge : RelationalSegmentEdge)
    (sourceInvariant targetInvariant : StateInvariant)
    (transition : X87SegmentTransitionClosed context edge sourceInvariant targetInvariant) :
    RelationalSegmentRefinement context edge sourceInvariant targetInvariant :=
  Or.inr transition

end StageA.Relational
