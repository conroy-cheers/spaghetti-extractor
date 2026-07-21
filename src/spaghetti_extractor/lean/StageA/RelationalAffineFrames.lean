import StageA.RelationalCallbacks

namespace StageA.Relational

open StageA.Formal

/-- An exact common-translation family of paired runtime-frame locations.

The two concrete offsets move by the same modular translation.  The stride
restricts that translation to one exact coset; it is not a finite sample or a
widened stack window. -/
structure ReturnSlotAffineFamily where
  originalRegister : Reg
  originalBase : Word
  candidateRegister : Reg
  candidateBase : Word
  translationStride : Nat
deriving Repr, DecidableEq

def ReturnSlotAffineFamily.valid (family : ReturnSlotAffineFamily) : Bool :=
  family.translationStride > 0 &&
    (2 ^ 32) % family.translationStride == 0 &&
    family.originalBase.toNat < family.translationStride

theorem word_affine_rebase (base coefficient shift stride : Word) :
    base + shift * stride + (coefficient - shift) * stride =
      base + coefficient * stride := by
  rw [BitVec.mul_comm (coefficient - shift) stride, BitVec.mul_sub,
    BitVec.mul_comm stride coefficient, BitVec.mul_comm stride shift]
  exact word_add_delta_sub base (shift * stride) (coefficient * stride)

theorem word_affine_unrebase (base coefficient shift stride : Word) :
    base + shift * stride + coefficient * stride =
      base + (shift + coefficient) * stride := by
  rw [BitVec.add_mul]
  ac_rfl

def ReturnSlotAffineFamily.contains (family : ReturnSlotAffineFamily)
    (offsets : ReturnSlotOffsetPair) : Prop :=
  offsets.originalRegister = family.originalRegister ∧
    offsets.candidateRegister = family.candidateRegister ∧
    ∃ coefficient : Word,
      let translation := coefficient * BitVec.ofNat 32 family.translationStride
      offsets.originalOffset = family.originalBase + translation ∧
        offsets.candidateOffset = family.candidateBase + translation

/-- Apply one checked register transfer to every member of an affine family.
The returned bases need not be canonical: canonicalization is represented by a
separate checked common translation, while this primitive preserves the family
pointwise. -/
def ReturnSlotTransferRule.applyAffineFamily (rule : ReturnSlotTransferRule)
    (source : ReturnSlotAffineFamily) : Option ReturnSlotAffineFamily :=
  if source.originalRegister == rule.originalSourceRegister &&
      source.candidateRegister == rule.candidateSourceRegister then
    some {
      originalRegister := rule.originalTargetRegister
      originalBase := source.originalBase - rule.originalDelta
      candidateRegister := rule.candidateTargetRegister
      candidateBase := source.candidateBase - rule.candidateDelta
      translationStride := source.translationStride
    }
  else none

/-- A finite witness that two canonical descriptions denote the same affine
family.  The shift is itself an exact multiple of the common stride. -/
structure ReturnSlotAffineFamilyShiftClaim where
  shiftCoefficient : Word
deriving Repr, DecidableEq

def ReturnSlotAffineFamilyShiftClaim.checked
    (claim : ReturnSlotAffineFamilyShiftClaim)
    (source target : ReturnSlotAffineFamily) : Bool :=
  target.valid &&
    source.originalRegister == target.originalRegister &&
    source.candidateRegister == target.candidateRegister &&
    source.translationStride == target.translationStride &&
    target.originalBase == source.originalBase +
      claim.shiftCoefficient * BitVec.ofNat 32 source.translationStride &&
    target.candidateBase == source.candidateBase +
      claim.shiftCoefficient * BitVec.ofNat 32 source.translationStride

theorem ReturnSlotAffineFamilyShiftClaim.contains_iff_of_checked
    (claim : ReturnSlotAffineFamilyShiftClaim)
    (source target : ReturnSlotAffineFamily)
    (offsets : ReturnSlotOffsetPair)
    (checked : claim.checked source target = true) :
    source.contains offsets ↔ target.contains offsets := by
  simp only [ReturnSlotAffineFamilyShiftClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  have originalRegister : source.originalRegister = target.originalRegister :=
    checked.1.1.1.1.2
  have candidateRegister : source.candidateRegister = target.candidateRegister :=
    checked.1.1.1.2
  have stride : source.translationStride = target.translationStride :=
    checked.1.1.2
  have originalBase : target.originalBase = source.originalBase +
      claim.shiftCoefficient * BitVec.ofNat 32 source.translationStride :=
    checked.1.2
  have candidateBase : target.candidateBase = source.candidateBase +
      claim.shiftCoefficient * BitVec.ofNat 32 source.translationStride :=
    checked.2
  constructor
  · rintro ⟨offsetOriginalRegister, offsetCandidateRegister,
      coefficient, offsetOriginal, offsetCandidate⟩
    refine ⟨offsetOriginalRegister.trans originalRegister,
      offsetCandidateRegister.trans candidateRegister, coefficient -
        claim.shiftCoefficient, ?_, ?_⟩
    · rw [originalBase, ← stride, word_affine_rebase]
      exact offsetOriginal
    · rw [candidateBase, ← stride, word_affine_rebase]
      exact offsetCandidate
  · rintro ⟨offsetOriginalRegister, offsetCandidateRegister,
      coefficient, offsetOriginal, offsetCandidate⟩
    refine ⟨offsetOriginalRegister.trans originalRegister.symm,
      offsetCandidateRegister.trans candidateRegister.symm,
      claim.shiftCoefficient + coefficient, ?_, ?_⟩
    · rw [originalBase, ← stride] at offsetOriginal
      rw [← word_affine_unrebase]
      exact offsetOriginal
    · rw [candidateBase, ← stride] at offsetCandidate
      rw [← word_affine_unrebase]
      exact offsetCandidate

theorem ReturnSlotTransferRule.applyAffineFamily_contains
    (rule : ReturnSlotTransferRule)
    (sourceFamily targetFamily : ReturnSlotAffineFamily)
    (sourceOffsets targetOffsets : ReturnSlotOffsetPair)
    (familyApplied : rule.applyAffineFamily sourceFamily = some targetFamily)
    (offsetsApplied : rule.apply sourceOffsets = some targetOffsets)
    (sourceContains : sourceFamily.contains sourceOffsets) :
    targetFamily.contains targetOffsets := by
  unfold ReturnSlotTransferRule.applyAffineFamily at familyApplied
  unfold ReturnSlotTransferRule.apply at offsetsApplied
  split at familyApplied
  next familyRegistersMatch =>
    split at offsetsApplied
    next offsetRegistersMatch =>
      simp only [Bool.and_eq_true, beq_iff_eq] at familyRegistersMatch
      simp only [Bool.and_eq_true, beq_iff_eq] at offsetRegistersMatch
      cases familyApplied
      cases offsetsApplied
      rcases sourceContains with
        ⟨sourceOriginalRegister, sourceCandidateRegister, coefficient,
          sourceOriginalOffset, sourceCandidateOffset⟩
      refine ⟨?familyOriginalRegister, ?familyCandidateRegister,
        coefficient, ?familyOriginalOffset, ?familyCandidateOffset⟩
      · simpa [sourceOriginalRegister, familyRegistersMatch.1] using
          offsetRegistersMatch.1
      · simpa [sourceCandidateRegister, familyRegistersMatch.2] using
          offsetRegistersMatch.2
      · simp only
        rw [sourceOriginalOffset]
        simp only [BitVec.sub_eq_add_neg]
        ac_rfl
      · simp only
        rw [sourceCandidateOffset]
        simp only [BitVec.sub_eq_add_neg]
        ac_rfl
    next offsetRegistersMismatch => simp at offsetsApplied
  next familyRegistersMismatch => simp at familyApplied

/-- Pointwise affine transfer preserves the concrete runtime-frame equation. -/
theorem returnSlotAffineFamilyTransferHoldsRuntimeFrame_of_checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (rule : ReturnSlotTransferRule)
    (sourceFamily targetFamily : ReturnSlotAffineFamily)
    (sourceOffsets targetOffsets : ReturnSlotOffsetPair)
    (frame : RelationalRuntimeFrame)
    (originalState candidateState : MachineState)
    (checked : rule.checked originalBehavior candidateBehavior = true)
    (familyApplied : rule.applyAffineFamily sourceFamily = some targetFamily)
    (offsetsApplied : rule.apply sourceOffsets = some targetOffsets)
    (sourceContains : sourceFamily.contains sourceOffsets)
    (sourceHolds : sourceOffsets.holdsRuntimeFrame frame
      originalState.registers candidateState.registers) :
    targetFamily.contains targetOffsets ∧
      targetOffsets.holdsRuntimeFrame frame
        (originalBehavior.eval originalState).registers
        (candidateBehavior.eval candidateState).registers := by
  exact ⟨rule.applyAffineFamily_contains sourceFamily targetFamily
      sourceOffsets targetOffsets familyApplied offsetsApplied sourceContains,
    returnSlotTransferRuleHoldsRuntimeFrame_of_checked
      originalBehavior candidateBehavior rule sourceOffsets targetOffsets frame
      originalState candidateState checked offsetsApplied sourceHolds⟩

/-- A generated proof supplies universal write separation for every concrete
member of one exact affine family.  The Python analysis may propose this
property, but only this Lean proposition can authorize frame preservation. -/
structure ReturnSlotAffineMemoryTransferClaim where
  family : ReturnSlotAffineFamily
  originalWrites : List RegisterOffsetWitness
  candidateWrites : List RegisterOffsetWitness
deriving Repr, DecidableEq

def ReturnSlotAffineMemoryTransferClaim.Checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotAffineMemoryTransferClaim) : Prop :=
  claim.family.valid = true ∧
    ∀ offsets, claim.family.contains offsets →
      (ReturnSlotMemoryTransferClaim.mk offsets claim.originalWrites
        claim.candidateWrites).checked originalBehavior candidateBehavior = true

theorem returnSlotAffineMemoryTransferHoldsRuntimeFrame_of_checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotAffineMemoryTransferClaim)
    (offsets : ReturnSlotOffsetPair)
    (frame : RelationalRuntimeFrame)
    (originalState candidateState : MachineState)
    (checked : claim.Checked originalBehavior candidateBehavior)
    (contains : claim.family.contains offsets)
    (offsetsHold : offsets.holdsRuntimeFrame frame originalState.registers
      candidateState.registers)
    (memoryHolds : frame.memoryHolds originalState.memory candidateState.memory) :
    frame.memoryHolds
      (applyConcreteWrites originalState.memory
        (evalNormalizedWrites originalState originalBehavior.writes))
      (applyConcreteWrites candidateState.memory
        (evalNormalizedWrites candidateState candidateBehavior.writes)) := by
  let concreteClaim : ReturnSlotMemoryTransferClaim := {
    offsets
    originalWrites := claim.originalWrites
    candidateWrites := claim.candidateWrites
  }
  have concreteChecked := checked.2 offsets contains
  have closed := returnSlotMemoryTransferClaimClosed_of_checked
    originalBehavior candidateBehavior concreteClaim concreteChecked
  have originalAvoids := registerOffsetWitnessesAvoidWord_of_closed
    offsets.originalRegister offsets.originalOffset claim.originalWrites
    originalBehavior.writes originalState closed.1
  have candidateAvoids := registerOffsetWitnessesAvoidWord_of_closed
    offsets.candidateRegister offsets.candidateOffset claim.candidateWrites
    candidateBehavior.writes candidateState closed.2
  cases frame <;>
    simp only [RelationalRuntimeFrame.memoryHolds,
      RelationalRuntimeCallFrame.memoryHolds,
      RelationalExternalCallbackFrame.memoryHolds,
      RelationalRuntimeFrame.originalStackAddress,
      RelationalRuntimeFrame.candidateStackAddress,
      ReturnSlotOffsetPair.holdsRuntimeFrame] at offsetsHold memoryHolds ⊢
  all_goals
    rcases offsetsHold with ⟨originalOffset, candidateOffset⟩
    rcases memoryHolds with ⟨originalMemory, candidateMemory⟩
    constructor
    · rw [← originalOffset]
      rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ originalAvoids]
      rw [originalOffset]
      exact originalMemory
    · rw [← candidateOffset]
      rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ candidateAvoids]
      rw [candidateOffset]
      exact candidateMemory

structure ReturnSlotAffineFrameState where
  nodeId : Nat
  family : ReturnSlotAffineFamily
deriving Repr, DecidableEq

structure ReturnSlotAffineFrameSeed where
  edgeId : Nat
  nodeId : Nat
  offsets : ReturnSlotOffsetPair
  coefficient : Word
deriving Repr, DecidableEq

structure ReturnSlotAffineFrameTransitionClaim where
  source : ReturnSlotAffineFrameState
  edgeId : Nat
  rule : ReturnSlotTransferRule
  rawTargetFamily : ReturnSlotAffineFamily
  canonicalShift : ReturnSlotAffineFamilyShiftClaim
  target : ReturnSlotAffineFrameState
deriving Repr, DecidableEq

def RelationalProductEdge.requiresRuntimeFrameTransfer
    (edge : RelationalProductEdge) : Bool :=
  !edge.infeasible &&
    (edge.kind == .jump || edge.kind == .call ||
      edge.kind == .branchTaken || edge.kind == .branchFallthrough)

def ReturnSlotAffineFrameTransitionClaim.checked
    (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameTransitionClaim) : Bool :=
  match graph.getEdge? claim.edgeId with
  | none => false
  | some edge =>
      edge.id == claim.edgeId &&
        edge.sourceNodeId == claim.source.nodeId &&
        edge.targetNodeId == claim.target.nodeId &&
        edge.requiresRuntimeFrameTransfer &&
        claim.source.family.valid && claim.target.family.valid &&
        claim.rule.applyAffineFamily claim.source.family ==
          some claim.rawTargetFamily &&
        claim.canonicalShift.checked claim.rawTargetFamily claim.target.family

theorem ReturnSlotAffineFrameTransitionClaim.contains_of_checked
    (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameTransitionClaim)
    (sourceOffsets targetOffsets : ReturnSlotOffsetPair)
    (checked : claim.checked graph = true)
    (sourceContains : claim.source.family.contains sourceOffsets)
    (offsetsApplied : claim.rule.apply sourceOffsets = some targetOffsets) :
    claim.target.family.contains targetOffsets := by
  unfold ReturnSlotAffineFrameTransitionClaim.checked at checked
  cases edgeFound : graph.getEdge? claim.edgeId with
  | none => simp [edgeFound] at checked
  | some edge =>
      simp only [edgeFound, Bool.and_eq_true, beq_iff_eq] at checked
      have rawContains := claim.rule.applyAffineFamily_contains
        claim.source.family claim.rawTargetFamily sourceOffsets targetOffsets
        checked.1.2 offsetsApplied sourceContains
      exact (claim.canonicalShift.contains_iff_of_checked
        claim.rawTargetFamily claim.target.family targetOffsets checked.2).mp
          rawContains

/-- The semantic witness for one affine graph transition.  The symbolic and
normalized behaviors are explicit fields so generated proof shards can reuse
the exact-byte decoder certificates instead of asking one aggregate checker to
decode the entire image again. -/
structure ReturnSlotAffineFrameSemanticTransitionClaim where
  transition : ReturnSlotAffineFrameTransitionClaim
  region : RegionRelation
  originalBehavior : SymbolicBehavior
  candidateBehavior : SymbolicBehavior
  originalNormalized : NormalizedSymbolicBehavior
  candidateNormalized : NormalizedSymbolicBehavior
  physicalStateOnly : Bool := false
deriving Repr, DecidableEq

def ReturnSlotTransferRule.statePreservingChecked
    (rule : ReturnSlotTransferRule) : Bool :=
  rule.originalSourceRegister == rule.originalTargetRegister &&
    rule.candidateSourceRegister == rule.candidateTargetRegister &&
    rule.originalOutput == .input && rule.candidateOutput == .input &&
    rule.originalDelta == BitVec.ofNat 32 0 &&
    rule.candidateDelta == BitVec.ofNat 32 0

def ReturnSlotAffineFrameSemanticTransitionClaim.checked
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticTransitionClaim) : Bool :=
  claim.transition.checked graph &&
    match graph.getNode? claim.transition.source.nodeId with
    | none => false
    | some node =>
        node.targetId == claim.region.id &&
          if claim.physicalStateOnly then
            StageA.Relational.X87.decodeSingletonCommand context.originalPe
                claim.region.original ==
              StageA.Relational.X87.decodeSingletonCommand context.candidatePe
                claim.region.candidate &&
            StageA.Relational.X87.stateOnlySingletonCommandChecked
                context.originalPe claim.region.original &&
            StageA.Relational.X87.stateOnlySingletonCommandChecked
                context.candidatePe claim.region.candidate &&
            claim.transition.rule.statePreservingChecked
          else
            regionBehaviorWithMachineCallContracts context.originalPe
                context.originalImports context.machineImportCallContracts
                claim.region.original == some claim.originalBehavior &&
            regionBehaviorWithMachineCallContracts context.candidatePe
                context.candidateImports context.machineImportCallContracts
                claim.region.candidate == some claim.candidateBehavior &&
            normalizeSymbolicBehavior false claim.region.targets
                claim.originalBehavior == some claim.originalNormalized &&
            normalizeSymbolicBehavior true claim.region.targets
                claim.candidateBehavior == some claim.candidateNormalized &&
            claim.transition.rule.checked claim.originalNormalized
              claim.candidateNormalized

/-- Assemble one semantic transition check from explicit graph and decoder
evidence. Generated shards use this theorem so their proof shape is independent
of the Boolean conjunction nesting inside `checked`. -/
theorem ReturnSlotAffineFrameSemanticTransitionClaim.checked_of_evidence
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticTransitionClaim)
    (node : RelationalProductNode)
    (transitionChecked : claim.transition.checked graph = true)
    (nodeFound : graph.getNode? claim.transition.source.nodeId = some node)
    (targetMatches : node.targetId = claim.region.id)
    (ordinary : claim.physicalStateOnly = false)
    (originalDecoded : regionBehaviorWithMachineCallContracts context.originalPe
      context.originalImports context.machineImportCallContracts
      claim.region.original = some claim.originalBehavior)
    (candidateDecoded : regionBehaviorWithMachineCallContracts context.candidatePe
      context.candidateImports context.machineImportCallContracts
      claim.region.candidate = some claim.candidateBehavior)
    (originalNormalized : normalizeSymbolicBehavior false claim.region.targets
      claim.originalBehavior = some claim.originalNormalized)
    (candidateNormalized : normalizeSymbolicBehavior true claim.region.targets
      claim.candidateBehavior = some claim.candidateNormalized)
    (ruleChecked : claim.transition.rule.checked claim.originalNormalized
      claim.candidateNormalized = true) :
    claim.checked context graph = true := by
  unfold ReturnSlotAffineFrameSemanticTransitionClaim.checked
  simp [transitionChecked, nodeFound, targetMatches, ordinary, originalDecoded,
    candidateDecoded, originalNormalized, candidateNormalized, ruleChecked]

theorem ReturnSlotAffineFrameSemanticTransitionClaim.checked_physical_of_evidence
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticTransitionClaim)
    (node : RelationalProductNode)
    (transitionChecked : claim.transition.checked graph = true)
    (nodeFound : graph.getNode? claim.transition.source.nodeId = some node)
    (targetMatches : node.targetId = claim.region.id)
    (physical : claim.physicalStateOnly = true)
    (decodedPair : StageA.Relational.X87.decodeSingletonCommand context.originalPe
        claim.region.original =
      StageA.Relational.X87.decodeSingletonCommand context.candidatePe
        claim.region.candidate)
    (originalChecked : StageA.Relational.X87.stateOnlySingletonCommandChecked
      context.originalPe claim.region.original = true)
    (candidateChecked : StageA.Relational.X87.stateOnlySingletonCommandChecked
      context.candidatePe claim.region.candidate = true)
    (ruleChecked : claim.transition.rule.statePreservingChecked = true) :
    claim.checked context graph = true := by
  unfold ReturnSlotAffineFrameSemanticTransitionClaim.checked
  simp [transitionChecked, nodeFound, targetMatches, physical, decodedPair,
    originalChecked, candidateChecked, ruleChecked]

theorem ReturnSlotAffineFrameSemanticTransitionClaim.transition_checked_of_checked
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticTransitionClaim)
    (checked : claim.checked context graph = true) :
    claim.transition.checked graph = true := by
  unfold ReturnSlotAffineFrameSemanticTransitionClaim.checked at checked
  simp only [Bool.and_eq_true] at checked
  exact checked.1

theorem ReturnSlotAffineFrameSemanticTransitionClaim.rule_checked_of_checked
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticTransitionClaim)
    (ordinary : claim.physicalStateOnly = false)
    (checked : claim.checked context graph = true) :
    claim.transition.rule.checked claim.originalNormalized
      claim.candidateNormalized = true := by
  unfold ReturnSlotAffineFrameSemanticTransitionClaim.checked at checked
  simp only [Bool.and_eq_true] at checked
  rcases checked with ⟨_, checked⟩
  cases nodeFound : graph.getNode? claim.transition.source.nodeId with
  | none => simp [nodeFound] at checked
  | some node =>
      simp only [nodeFound, Bool.and_eq_true, beq_iff_eq, ordinary,
        Bool.false_eq_true, ↓reduceIte] at checked
      exact checked.2.2

/-- A semantically checked transition moves every concrete member of its
source family to the declared target family while preserving the runtime-frame
register equation. -/
theorem ReturnSlotAffineFrameSemanticTransitionClaim.holdsRuntimeFrame_of_checked
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticTransitionClaim)
    (sourceOffsets targetOffsets : ReturnSlotOffsetPair)
    (frame : RelationalRuntimeFrame)
    (originalState candidateState : MachineState)
    (ordinary : claim.physicalStateOnly = false)
    (checked : claim.checked context graph = true)
    (sourceContains : claim.transition.source.family.contains sourceOffsets)
    (offsetsApplied : claim.transition.rule.apply sourceOffsets = some targetOffsets)
    (sourceHolds : sourceOffsets.holdsRuntimeFrame frame
      originalState.registers candidateState.registers) :
    claim.transition.target.family.contains targetOffsets ∧
      targetOffsets.holdsRuntimeFrame frame
        (claim.originalNormalized.eval originalState).registers
        (claim.candidateNormalized.eval candidateState).registers := by
  have transitionChecked := claim.transition_checked_of_checked context graph checked
  have ruleChecked := claim.rule_checked_of_checked context graph ordinary checked
  unfold ReturnSlotAffineFrameTransitionClaim.checked at transitionChecked
  cases edgeFound : graph.getEdge? claim.transition.edgeId with
  | none => simp [edgeFound] at transitionChecked
  | some edge =>
      simp only [edgeFound, Bool.and_eq_true, beq_iff_eq] at transitionChecked
      have transferred := returnSlotAffineFamilyTransferHoldsRuntimeFrame_of_checked
        claim.originalNormalized claim.candidateNormalized claim.transition.rule
        claim.transition.source.family claim.transition.rawTargetFamily
        sourceOffsets targetOffsets frame originalState candidateState ruleChecked
        transitionChecked.1.2 offsetsApplied sourceContains sourceHolds
      exact ⟨(claim.transition.canonicalShift.contains_iff_of_checked
          claim.transition.rawTargetFamily claim.transition.target.family targetOffsets
          transitionChecked.2).mp transferred.1,
        transferred.2⟩

/-- A call-entry seed is accepted only when it is the zero-offset return slot
created by an exact decoded direct call. -/
structure ReturnSlotAffineFrameSemanticSeedClaim where
  seed : ReturnSlotAffineFrameSeed
  sourceRegion : RegionRelation
  originalBehavior : SymbolicBehavior
  candidateBehavior : SymbolicBehavior
  originalNormalized : NormalizedSymbolicBehavior
  candidateNormalized : NormalizedSymbolicBehavior
  callPush : DirectCallPushClaim
deriving Repr, DecidableEq

def ReturnSlotAffineFrameSemanticSeedClaim.checked
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticSeedClaim) : Bool :=
  match graph.getEdge? claim.seed.edgeId with
  | none => false
  | some edge =>
      match graph.getNode? edge.sourceNodeId with
      | none => false
      | some source =>
          !edge.infeasible && edge.kind == .call &&
            edge.targetNodeId == claim.seed.nodeId &&
            source.targetId == claim.sourceRegion.id &&
            claim.callPush.calleeTargetId == edge.targetTargetId &&
            regionBehaviorWithMachineCallContracts context.originalPe
                context.originalImports context.machineImportCallContracts
                claim.sourceRegion.original == some claim.originalBehavior &&
            regionBehaviorWithMachineCallContracts context.candidatePe
                context.candidateImports context.machineImportCallContracts
                claim.sourceRegion.candidate == some claim.candidateBehavior &&
            normalizeSymbolicBehavior false claim.sourceRegion.targets
                claim.originalBehavior == some claim.originalNormalized &&
            normalizeSymbolicBehavior true claim.sourceRegion.targets
                claim.candidateBehavior == some claim.candidateNormalized &&
            claim.callPush.checked context claim.originalNormalized
              claim.candidateNormalized &&
            claim.seed.offsets == ReturnSlotOffsetPair.zero

/-- Assemble one call-entry seed check from explicit graph, decoder, and call
push evidence. This keeps generated proofs independent of Boolean field order. -/
theorem ReturnSlotAffineFrameSemanticSeedClaim.checked_of_evidence
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticSeedClaim)
    (edge : RelationalProductEdge) (source : RelationalProductNode)
    (edgeFound : graph.getEdge? claim.seed.edgeId = some edge)
    (sourceFound : graph.getNode? edge.sourceNodeId = some source)
    (edgeFeasible : edge.infeasible = false)
    (edgeKind : edge.kind = .call)
    (targetMatches : edge.targetNodeId = claim.seed.nodeId)
    (sourceMatches : source.targetId = claim.sourceRegion.id)
    (calleeMatches : claim.callPush.calleeTargetId = edge.targetTargetId)
    (originalDecoded : regionBehaviorWithMachineCallContracts context.originalPe
      context.originalImports context.machineImportCallContracts
      claim.sourceRegion.original = some claim.originalBehavior)
    (candidateDecoded : regionBehaviorWithMachineCallContracts context.candidatePe
      context.candidateImports context.machineImportCallContracts
      claim.sourceRegion.candidate = some claim.candidateBehavior)
    (originalNormalized : normalizeSymbolicBehavior false claim.sourceRegion.targets
      claim.originalBehavior = some claim.originalNormalized)
    (candidateNormalized : normalizeSymbolicBehavior true claim.sourceRegion.targets
      claim.candidateBehavior = some claim.candidateNormalized)
    (callPushChecked : claim.callPush.checked context claim.originalNormalized
      claim.candidateNormalized = true)
    (seedZero : claim.seed.offsets = ReturnSlotOffsetPair.zero) :
    claim.checked context graph = true := by
  unfold ReturnSlotAffineFrameSemanticSeedClaim.checked
  simp [edgeFound, sourceFound, edgeFeasible, edgeKind, targetMatches,
    sourceMatches, calleeMatches, originalDecoded, candidateDecoded,
    originalNormalized, candidateNormalized, callPushChecked, seedZero]

theorem ReturnSlotAffineFrameSemanticSeedClaim.callPush_checked_of_checked
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticSeedClaim)
    (checked : claim.checked context graph = true) :
    claim.callPush.checked context claim.originalNormalized
      claim.candidateNormalized = true := by
  unfold ReturnSlotAffineFrameSemanticSeedClaim.checked at checked
  cases edgeFound : graph.getEdge? claim.seed.edgeId with
  | none => simp [edgeFound] at checked
  | some edge =>
      cases sourceFound : graph.getNode? edge.sourceNodeId with
      | none => simp [edgeFound, sourceFound] at checked
      | some source =>
          simp only [edgeFound, sourceFound, Bool.and_eq_true, beq_iff_eq] at checked
          exact checked.1.2

theorem ReturnSlotAffineFrameSemanticSeedClaim.holdsRuntimeFrame_of_checked
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticSeedClaim)
    (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : claim.checked context graph = true)
    (frameResult : claim.callPush.runtimeFrame context originalState candidateState =
      some frame) :
    claim.seed.offsets.holdsRuntimeFrame (.internal frame)
      (claim.originalNormalized.eval originalState).registers
      (claim.candidateNormalized.eval candidateState).registers := by
  have pushChecked := claim.callPush_checked_of_checked context graph checked
  have entry := directCallPushEntryReturnSlot_of_checked context
    claim.originalNormalized claim.candidateNormalized claim.callPush frame
    originalState candidateState pushChecked frameResult
  unfold ReturnSlotAffineFrameSemanticSeedClaim.checked at checked
  cases edgeFound : graph.getEdge? claim.seed.edgeId with
  | none => simp [edgeFound] at checked
  | some edge =>
      cases sourceFound : graph.getNode? edge.sourceNodeId with
      | none => simp [edgeFound, sourceFound] at checked
      | some source =>
          simp only [edgeFound, sourceFound, Bool.and_eq_true, beq_iff_eq] at checked
          simpa [checked.2, ReturnSlotOffsetPair.holdsRuntimeFrame_internal] using entry

structure ReturnSlotAffineFrameProfile where
  states : List ReturnSlotAffineFrameState
  transitions : List ReturnSlotAffineFrameTransitionClaim
  seeds : List ReturnSlotAffineFrameSeed
deriving Repr, DecidableEq

/-- Semantic claims must project to the graph-closed profile exactly.  This
prevents a generated proof from checking only the convenient transitions and
silently omitting another feasible affine successor. -/
structure ReturnSlotAffineFrameSemanticProfile where
  frameProfile : ReturnSlotAffineFrameProfile
  transitionClaims : List ReturnSlotAffineFrameSemanticTransitionClaim
  seedClaims : List ReturnSlotAffineFrameSemanticSeedClaim
deriving Repr, DecidableEq

def ReturnSlotAffineFrameProfile.coversSeed
    (profile : ReturnSlotAffineFrameProfile)
    (seed : ReturnSlotAffineFrameSeed) : Bool :=
  profile.states.any fun state =>
    state.nodeId == seed.nodeId &&
      seed.offsets.originalRegister == state.family.originalRegister &&
      seed.offsets.candidateRegister == state.family.candidateRegister &&
      seed.offsets.originalOffset == state.family.originalBase +
        seed.coefficient * BitVec.ofNat 32 state.family.translationStride &&
      seed.offsets.candidateOffset == state.family.candidateBase +
        seed.coefficient * BitVec.ofNat 32 state.family.translationStride

theorem ReturnSlotAffineFrameProfile.coversSeed_contains_of_true
    (profile : ReturnSlotAffineFrameProfile)
    (seed : ReturnSlotAffineFrameSeed)
    (covered : profile.coversSeed seed = true) :
    ∃ state ∈ profile.states,
      state.nodeId = seed.nodeId ∧ state.family.contains seed.offsets := by
  unfold ReturnSlotAffineFrameProfile.coversSeed at covered
  rcases List.any_eq_true.mp covered with ⟨state, member, matched⟩
  simp only [Bool.and_eq_true, beq_iff_eq] at matched
  refine ⟨state, member, matched.1.1.1.1,
    matched.1.1.1.2, matched.1.1.2, seed.coefficient,
    matched.1.2, matched.2⟩

def ReturnSlotAffineFrameProfile.coversOutgoingEdge
    (profile : ReturnSlotAffineFrameProfile)
    (state : ReturnSlotAffineFrameState) (edgeId : Nat) : Bool :=
  profile.transitions.any fun transition =>
    transition.source == state && transition.edgeId == edgeId &&
      profile.states.contains transition.target

def ReturnSlotAffineFrameProfile.stateClosed
    (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (state : ReturnSlotAffineFrameState) : Bool :=
  match graph.getNode? state.nodeId with
  | none => false
  | some node => node.outgoingEdgeIds.all fun edgeId =>
      match graph.getEdge? edgeId with
      | none => false
      | some edge =>
          !edge.requiresRuntimeFrameTransfer ||
            profile.coversOutgoingEdge state edgeId

def ReturnSlotAffineFrameProfile.checked
    (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Bool :=
  decide profile.states.Nodup &&
    (profile.states.all fun state =>
      state.family.valid && profile.stateClosed graph state) &&
    decide profile.transitions.Nodup &&
    (profile.transitions.all fun transition =>
      transition.checked graph && profile.states.contains transition.source &&
        profile.states.contains transition.target) &&
    decide profile.seeds.Nodup &&
    profile.seeds.all profile.coversSeed

def ReturnSlotAffineFrameSemanticProfile.checked
    (profile : ReturnSlotAffineFrameSemanticProfile)
    (context : StaticProofContext) (graph : RelationalProductGraph) : Bool :=
  profile.frameProfile.checked graph &&
    profile.transitionClaims.map (fun claim => claim.transition) ==
      profile.frameProfile.transitions &&
    (profile.transitionClaims.all fun claim => claim.checked context graph) &&
    profile.seedClaims.map (fun claim => claim.seed) == profile.frameProfile.seeds &&
    profile.seedClaims.all fun claim => claim.checked context graph

theorem ReturnSlotAffineFrameSemanticProfile.frame_checked_of_checked
    (profile : ReturnSlotAffineFrameSemanticProfile)
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (checked : profile.checked context graph = true) :
    profile.frameProfile.checked graph = true := by
  simp only [ReturnSlotAffineFrameSemanticProfile.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  exact checked.1.1.1.1

theorem ReturnSlotAffineFrameSemanticProfile.transition_claim_checked_of_checked
    (profile : ReturnSlotAffineFrameSemanticProfile)
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticTransitionClaim)
    (checked : profile.checked context graph = true)
    (member : claim ∈ profile.transitionClaims) :
    claim.checked context graph = true := by
  simp only [ReturnSlotAffineFrameSemanticProfile.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  exact List.all_eq_true.mp checked.1.1.2 claim member

theorem ReturnSlotAffineFrameSemanticProfile.transition_member_of_checked
    (profile : ReturnSlotAffineFrameSemanticProfile)
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticTransitionClaim)
    (checked : profile.checked context graph = true)
    (member : claim ∈ profile.transitionClaims) :
    claim.transition ∈ profile.frameProfile.transitions := by
  simp only [ReturnSlotAffineFrameSemanticProfile.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rw [← checked.1.1.1.2]
  exact List.mem_map.mpr ⟨claim, member, rfl⟩

theorem ReturnSlotAffineFrameSemanticProfile.seed_claim_checked_of_checked
    (profile : ReturnSlotAffineFrameSemanticProfile)
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticSeedClaim)
    (checked : profile.checked context graph = true)
    (member : claim ∈ profile.seedClaims) :
    claim.checked context graph = true := by
  simp only [ReturnSlotAffineFrameSemanticProfile.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  exact List.all_eq_true.mp checked.2 claim member

theorem ReturnSlotAffineFrameSemanticProfile.seed_member_of_checked
    (profile : ReturnSlotAffineFrameSemanticProfile)
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticSeedClaim)
    (checked : profile.checked context graph = true)
    (member : claim ∈ profile.seedClaims) :
    claim.seed ∈ profile.frameProfile.seeds := by
  simp only [ReturnSlotAffineFrameSemanticProfile.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rw [← checked.1.2]
  exact List.mem_map.mpr ⟨claim, member, rfl⟩

theorem ReturnSlotAffineFrameProfile.transition_checked_of_checked
    (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (transition : ReturnSlotAffineFrameTransitionClaim)
    (checked : profile.checked graph = true)
    (member : transition ∈ profile.transitions) :
    transition.checked graph = true := by
  simp only [ReturnSlotAffineFrameProfile.checked, Bool.and_eq_true,
    List.all_eq_true] at checked
  exact (checked.1.1.2 transition member).1.1

theorem ReturnSlotAffineFrameProfile.seed_covered_of_checked
    (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (seed : ReturnSlotAffineFrameSeed)
    (checked : profile.checked graph = true)
    (member : seed ∈ profile.seeds) :
    profile.coversSeed seed = true := by
  simp only [ReturnSlotAffineFrameProfile.checked, Bool.and_eq_true,
    List.all_eq_true] at checked
  exact checked.2 seed member

theorem ReturnSlotAffineFrameProfile.seed_contains_of_checked
    (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (seed : ReturnSlotAffineFrameSeed)
    (checked : profile.checked graph = true)
    (member : seed ∈ profile.seeds) :
    ∃ state ∈ profile.states,
      state.nodeId = seed.nodeId ∧ state.family.contains seed.offsets :=
  profile.coversSeed_contains_of_true seed
    (profile.seed_covered_of_checked graph seed checked member)

end StageA.Relational
