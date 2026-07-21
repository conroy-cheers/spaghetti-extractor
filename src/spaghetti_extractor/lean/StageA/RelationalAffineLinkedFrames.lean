import StageA.RelationalAffineFrames
import StageA.RelationalLinkedFrames

namespace StageA.Relational

open StageA.Formal

/-- A static inventory either names every concrete location exactly or refers
to one checked affine family.  The affine case is realized by one concrete
member at runtime; it is never replaced by a representative offset. -/
inductive ReturnSlotAffineInventoryLocations where
  | exact (locations : List ReturnSlotOffsetPair)
  | affineFamily (stateIndex : Nat)
deriving Repr, DecidableEq

/-- The static part of a runtime-frame inventory.  Location variation is
isolated in `locations`; every other payload field remains exact. -/
structure ReturnSlotAffineInventoryShape where
  locations : ReturnSlotAffineInventoryLocations
  exactWords : List ReturnSlotExactWordPair := []
  preservedImports : List ImportRegisterRelation := []
  preservedRelations : List RegisterRelationPair := []
deriving Repr, DecidableEq

def ReturnSlotAffineInventoryShape.payloadChecked
    (shape : ReturnSlotAffineInventoryShape) : Bool :=
  decide shape.exactWords.Nodup &&
    shape.exactWords.length <= ReturnSlotOffsetInventory.maxExactWords &&
    shape.exactWords.all ReturnSlotExactWordPair.checked &&
    decide shape.preservedImports.Nodup &&
    shape.preservedImports.length <=
      ReturnSlotOffsetInventory.maxPreservedImports &&
    decide shape.preservedRelations.Nodup &&
    shape.preservedRelations.length <=
      ReturnSlotOffsetInventory.maxPreservedRelations

def ReturnSlotAffineInventoryShape.toInventory
    (shape : ReturnSlotAffineInventoryShape)
    (locations : List ReturnSlotOffsetPair) : ReturnSlotOffsetInventory := {
  locations
  exactWords := shape.exactWords
  preservedImports := shape.preservedImports
  preservedRelations := shape.preservedRelations
}

/-- Exact affine-family membership with the modular coefficient kept as
kernel evidence instead of hidden behind an arbitrary representative. -/
def ReturnSlotAffineFamily.ContainsAt (family : ReturnSlotAffineFamily)
    (coefficient : Word) (location : ReturnSlotOffsetPair) : Prop :=
  location.originalRegister = family.originalRegister ∧
    location.candidateRegister = family.candidateRegister ∧
    location.originalOffset = family.originalBase +
      coefficient * BitVec.ofNat 32 family.translationStride ∧
    location.candidateOffset = family.candidateBase +
      coefficient * BitVec.ofNat 32 family.translationStride

theorem ReturnSlotAffineFamily.ContainsAt.contains
    (family : ReturnSlotAffineFamily) (coefficient : Word)
    (location : ReturnSlotOffsetPair)
    (containsAt : family.ContainsAt coefficient location) :
    family.contains location := by
  exact ⟨containsAt.1, containsAt.2.1, coefficient,
    containsAt.2.2.1, containsAt.2.2.2⟩

def ReturnSlotAffineInventoryShape.checked
    (shape : ReturnSlotAffineInventoryShape)
    (profile : ReturnSlotAffineFrameProfile) (nodeId : Nat) : Bool :=
  match shape.locations with
  | .exact locations => (shape.toInventory locations).checked
  | .affineFamily stateIndex =>
      shape.payloadChecked &&
        match profile.states[stateIndex]? with
        | none => false
        | some state => state.nodeId == nodeId && state.family.valid

def ReturnSlotAffineInventoryShape.PayloadMatches
    (shape : ReturnSlotAffineInventoryShape)
    (inventory : ReturnSlotOffsetInventory) : Prop :=
  inventory.exactWords = shape.exactWords ∧
    inventory.preservedImports = shape.preservedImports ∧
    inventory.preservedRelations = shape.preservedRelations

def ReturnSlotAffineInventoryShape.Realizes
    (shape : ReturnSlotAffineInventoryShape)
    (profile : ReturnSlotAffineFrameProfile) (nodeId : Nat)
    (inventory : ReturnSlotOffsetInventory) : Prop :=
  shape.PayloadMatches inventory ∧
    match shape.locations with
    | .exact locations => inventory.locations = locations
    | .affineFamily stateIndex =>
        ∃ state coefficient location,
          profile.states[stateIndex]? = some state ∧
            state.nodeId = nodeId ∧
            state.family.ContainsAt coefficient location ∧
            inventory.locations = [location]

theorem ReturnSlotAffineInventoryShape.payload_eq_of_realizes
    (shape : ReturnSlotAffineInventoryShape)
    (profile : ReturnSlotAffineFrameProfile) (nodeId : Nat)
    (inventory : ReturnSlotOffsetInventory)
    (realizes : shape.Realizes profile nodeId inventory) :
    inventory.exactWords = shape.exactWords ∧
      inventory.preservedImports = shape.preservedImports ∧
      inventory.preservedRelations = shape.preservedRelations :=
  realizes.1

theorem ReturnSlotAffineInventoryShape.realizes_checked
    (shape : ReturnSlotAffineInventoryShape)
    (profile : ReturnSlotAffineFrameProfile) (nodeId : Nat)
    (inventory : ReturnSlotOffsetInventory)
    (shapeChecked : shape.checked profile nodeId = true)
    (realizes : shape.Realizes profile nodeId inventory) :
    inventory.checked = true := by
  cases locationShape : shape.locations with
  | exact locations =>
      simp only [ReturnSlotAffineInventoryShape.Realizes,
        ReturnSlotAffineInventoryShape.PayloadMatches, locationShape] at realizes
      rcases realizes with
        ⟨⟨exactWordsMatch, preservedImportsMatch, preservedRelationsMatch⟩,
          locationsMatch⟩
      simp only [ReturnSlotAffineInventoryShape.checked, locationShape,
        ReturnSlotAffineInventoryShape.toInventory,
        ReturnSlotOffsetInventory.checked] at shapeChecked
      simpa only [ReturnSlotOffsetInventory.checked, locationsMatch,
        exactWordsMatch, preservedImportsMatch, preservedRelationsMatch] using
          shapeChecked
  | affineFamily stateIndex =>
      simp only [ReturnSlotAffineInventoryShape.Realizes,
        ReturnSlotAffineInventoryShape.PayloadMatches, locationShape] at realizes
      rcases realizes with
        ⟨⟨exactWordsMatch, preservedImportsMatch, preservedRelationsMatch⟩,
        ⟨state, coefficient, location, _stateFound, _nodeMatches,
          _containsAt, locationsMatch⟩⟩
      simp only [ReturnSlotAffineInventoryShape.checked, locationShape,
        Bool.and_eq_true] at shapeChecked
      simpa [ReturnSlotAffineInventoryShape.payloadChecked,
        ReturnSlotOffsetInventory.checked, locationsMatch,
        ReturnSlotOffsetInventory.maxLocations, exactWordsMatch,
        preservedImportsMatch, preservedRelationsMatch] using shapeChecked.1

theorem ReturnSlotAffineInventoryShape.realizes_affine_contains
    (shape : ReturnSlotAffineInventoryShape)
    (profile : ReturnSlotAffineFrameProfile) (nodeId : Nat)
    (inventory : ReturnSlotOffsetInventory) (stateIndex : Nat)
    (affine : shape.locations = .affineFamily stateIndex)
    (realizes : shape.Realizes profile nodeId inventory) :
    ∃ state coefficient location,
      profile.states[stateIndex]? = some state ∧
        state.nodeId = nodeId ∧
        location ∈ inventory.locations ∧
        state.family.ContainsAt coefficient location ∧
        state.family.contains location := by
  rw [ReturnSlotAffineInventoryShape.Realizes, affine] at realizes
  rcases realizes.2 with
    ⟨state, coefficient, location, stateFound, nodeMatches,
      containsAt, locationsMatch⟩
  exact ⟨state, coefficient, location, stateFound, nodeMatches, by
    simp [locationsMatch], containsAt, containsAt.contains⟩

theorem ReturnSlotTransferRule.apply_exists_of_applyAffineFamily
    (rule : ReturnSlotTransferRule)
    (sourceFamily targetFamily : ReturnSlotAffineFamily)
    (sourceLocation : ReturnSlotOffsetPair)
    (familyApplied : rule.applyAffineFamily sourceFamily = some targetFamily)
    (sourceContains : sourceFamily.contains sourceLocation) :
    ∃ targetLocation, rule.apply sourceLocation = some targetLocation := by
  unfold ReturnSlotTransferRule.applyAffineFamily at familyApplied
  split at familyApplied
  next registersMatch =>
    simp only [Bool.and_eq_true, beq_iff_eq] at registersMatch
    refine ⟨{
      originalRegister := rule.originalTargetRegister
      originalOffset := sourceLocation.originalOffset - rule.originalDelta
      candidateRegister := rule.candidateTargetRegister
      candidateOffset := sourceLocation.candidateOffset - rule.candidateDelta
    }, ?_⟩
    unfold ReturnSlotTransferRule.apply
    simp [sourceContains.1, sourceContains.2.1, registersMatch.1,
      registersMatch.2]
  next registersMismatch => simp at familyApplied

theorem ReturnSlotAffineFrameSemanticTransitionClaim.apply_exists_of_checked
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (claim : ReturnSlotAffineFrameSemanticTransitionClaim)
    (sourceLocation : ReturnSlotOffsetPair)
    (checked : claim.checked context graph = true)
    (sourceContains : claim.transition.source.family.contains sourceLocation) :
    ∃ targetLocation,
      claim.transition.rule.apply sourceLocation = some targetLocation := by
  have transitionChecked := claim.transition_checked_of_checked context graph checked
  unfold ReturnSlotAffineFrameTransitionClaim.checked at transitionChecked
  cases edgeFound : graph.getEdge? claim.transition.edgeId with
  | none => simp [edgeFound] at transitionChecked
  | some edge =>
      simp only [edgeFound, Bool.and_eq_true, beq_iff_eq] at transitionChecked
      exact claim.transition.rule.apply_exists_of_applyAffineFamily
        claim.transition.source.family claim.transition.rawTargetFamily
        sourceLocation transitionChecked.1.2 sourceContains

/-- One exact semantic transition binds affine source and target inventory
specifications.  This first slice is deliberately ordinary, no-write, and
payload preserving; nested frame links require a separate affine link profile. -/
structure ReturnSlotAffineFrameSemanticTransitionBinding where
  sourceShape : ReturnSlotAffineInventoryShape
  targetShape : ReturnSlotAffineInventoryShape
  claim : ReturnSlotAffineFrameSemanticTransitionClaim
deriving Repr, DecidableEq

/-- Check the register-only payload of an affine frame shape independently of
its concrete return-slot location.  Location transfer is proved by the affine
rule; these clauses preserve import identities and relational register facts. -/
def ReturnSlotAffineInventoryShape.factsPreservedAcross
    (context : StaticProofContext) (shape : ReturnSlotAffineInventoryShape)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) : Bool :=
  shape.preservedImports.all (fun relation =>
      originalBehavior.registers.get relation.original == .inputReg relation.original &&
        candidateBehavior.registers.get relation.candidate == .inputReg relation.candidate) &&
    (shape.toInventory [ReturnSlotOffsetPair.zero]).preservedRelationsUnambiguous &&
    shape.preservedRelations.all (fun relation =>
      relation.relation.staticTargetValid context) &&
    shape.preservedRelations.all (fun relation =>
      originalBehavior.registers.get relation.original == .inputReg relation.original &&
        candidateBehavior.registers.get relation.candidate == .inputReg relation.candidate)

def ReturnSlotAffineFrameSemanticTransitionBinding.checked
    (binding : ReturnSlotAffineFrameSemanticTransitionBinding)
    (context : StaticProofContext) (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Bool :=
  match binding.sourceShape.locations, binding.targetShape.locations with
  | .affineFamily sourceStateIndex, .affineFamily targetStateIndex =>
      profile.checked graph && binding.claim.checked context graph &&
        binding.claim.physicalStateOnly == false &&
        binding.claim.originalNormalized.writes == [] &&
        binding.claim.candidateNormalized.writes == [] &&
        binding.sourceShape.exactWords == binding.targetShape.exactWords &&
        binding.sourceShape.preservedImports ==
          binding.targetShape.preservedImports &&
        binding.sourceShape.preservedRelations ==
          binding.targetShape.preservedRelations &&
        binding.sourceShape.factsPreservedAcross context
          binding.claim.originalNormalized binding.claim.candidateNormalized &&
        binding.sourceShape.checked profile
          binding.claim.transition.source.nodeId &&
        binding.targetShape.checked profile
          binding.claim.transition.target.nodeId &&
        profile.states[sourceStateIndex]? == some binding.claim.transition.source &&
        profile.states[targetStateIndex]? == some binding.claim.transition.target
  | _, _ => false

/-- Transfer the active frame across one ordinary affine transition while
preserving an arbitrary dormant stack tail.  The target location is obtained
by applying the checked rule to the concrete source location and then unpacking
target-family membership; no family representative is selected. -/
theorem ReturnSlotAffineFrameSemanticTransitionBinding.afterNoWriteNested
    (binding : ReturnSlotAffineFrameSemanticTransitionBinding)
    (context : StaticProofContext) (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation : Nat) (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (sourceInventory : ReturnSlotOffsetInventory)
    (checked : binding.checked context profile graph = true)
    (sourceRealizes : binding.sourceShape.Realizes profile
      binding.claim.transition.source.nodeId sourceInventory)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (frame :: frames) (continuation :: continuations)
        (some sourceInventory) links)
    (originalMemory :
      ((binding.claim.originalNormalized.eval originalState).nextMachineState
        originalState).memory = originalState.memory)
    (candidateMemory :
      ((binding.claim.candidateNormalized.eval candidateState).nextMachineState
        candidateState).memory = candidateState.memory) :
    ∃ targetInventory,
      binding.targetShape.Realizes profile
          binding.claim.transition.target.nodeId targetInventory ∧
        RelationalLinkedRuntimeCallStackHolds context
          ((binding.claim.originalNormalized.eval originalState).nextMachineState
            originalState)
          ((binding.claim.candidateNormalized.eval candidateState).nextMachineState
            candidateState)
          (frame :: frames) (continuation :: continuations)
          (some targetInventory) links := by
  cases sourceLocations : binding.sourceShape.locations with
  | exact locations =>
      simp [ReturnSlotAffineFrameSemanticTransitionBinding.checked,
        sourceLocations] at checked
  | affineFamily sourceStateIndex =>
      cases targetLocations : binding.targetShape.locations with
      | exact locations =>
          simp [ReturnSlotAffineFrameSemanticTransitionBinding.checked,
            sourceLocations, targetLocations] at checked
      | affineFamily targetStateIndex =>
          simp only [ReturnSlotAffineFrameSemanticTransitionBinding.checked,
            sourceLocations, targetLocations] at checked
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, targetStateFoundChecked⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, sourceStateFoundChecked⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, targetShapeChecked⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, _sourceShapeChecked⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, _payloadFactsPreserved⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, _payloadRelations⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, _payloadImports⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, payloadWordsChecked⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, _candidateWrites⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, _originalWrites⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, ordinaryChecked⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨_profileChecked, claimChecked⟩
          have ordinary : binding.claim.physicalStateOnly = false := by
            simpa only [beq_iff_eq] using ordinaryChecked
          have payloadWords : binding.sourceShape.exactWords =
              binding.targetShape.exactWords := by
            simpa only [beq_iff_eq] using payloadWordsChecked
          have sourceStateFound : profile.states[sourceStateIndex]? =
              some binding.claim.transition.source := by
            simpa only [beq_iff_eq] using sourceStateFoundChecked
          have targetStateFound : profile.states[targetStateIndex]? =
              some binding.claim.transition.target := by
            simpa only [beq_iff_eq] using targetStateFoundChecked
          simp only [ReturnSlotAffineInventoryShape.Realizes,
            ReturnSlotAffineInventoryShape.PayloadMatches,
            sourceLocations] at sourceRealizes
          rcases sourceRealizes with
            ⟨⟨sourceWords, _sourceImports, _sourceRelations⟩,
              sourceState, sourceCoefficient, sourceLocation,
              profileSourceFound, _sourceNodeMatches, sourceContainsAt,
              sourceLocationsExact⟩
          have sourceStateExact :
              sourceState = binding.claim.transition.source := by
            rw [sourceStateFound] at profileSourceFound
            exact (Option.some.inj profileSourceFound).symm
          have sourceContains :
              binding.claim.transition.source.family.contains sourceLocation := by
            rw [← sourceStateExact]
            exact sourceContainsAt.contains
          simp only [RelationalLinkedRuntimeCallStackHolds] at stackHolds
          have sourceLocationHolds := stackHolds.2.1.2 sourceLocation (by
            rw [sourceLocationsExact]
            simp)
          obtain ⟨targetLocation, offsetsApplied⟩ :=
            binding.claim.apply_exists_of_checked context graph sourceLocation
              claimChecked sourceContains
          have transferred := binding.claim.holdsRuntimeFrame_of_checked
            context graph sourceLocation targetLocation (.internal frame)
            originalState candidateState ordinary claimChecked sourceContains
            offsetsApplied (by
              simpa [ReturnSlotOffsetPair.holdsRuntimeFrame_internal] using
                sourceLocationHolds)
          rcases transferred.1 with
            ⟨targetOriginalRegister, targetCandidateRegister, targetCoefficient,
              targetOriginalOffset, targetCandidateOffset⟩
          have targetContainsAt :
              binding.claim.transition.target.family.ContainsAt
                targetCoefficient targetLocation :=
            ⟨targetOriginalRegister, targetCandidateRegister,
              targetOriginalOffset, targetCandidateOffset⟩
          let targetInventory :=
            binding.targetShape.toInventory [targetLocation]
          have targetRealizes : binding.targetShape.Realizes profile
              binding.claim.transition.target.nodeId targetInventory := by
            simp only [ReturnSlotAffineInventoryShape.Realizes,
              ReturnSlotAffineInventoryShape.PayloadMatches, targetLocations]
            refine ⟨?_, binding.claim.transition.target, targetCoefficient,
              targetLocation, targetStateFound, rfl, targetContainsAt, ?_⟩
            · simp [targetInventory,
                ReturnSlotAffineInventoryShape.toInventory]
            · simp [targetInventory,
                ReturnSlotAffineInventoryShape.toInventory]
          have targetChecked : targetInventory.checked = true :=
            binding.targetShape.realizes_checked profile
              binding.claim.transition.target.nodeId targetInventory
              targetShapeChecked targetRealizes
          have targetLocationHolds : targetLocation.holds frame
              ((binding.claim.originalNormalized.eval originalState).nextMachineState
                originalState).registers
              ((binding.claim.candidateNormalized.eval candidateState).nextMachineState
                candidateState).registers := by
            simpa [ReturnSlotOffsetPair.holdsRuntimeFrame_internal,
              RelationalBehavior.nextMachineState] using transferred.2
          have targetHolds : targetInventory.holds frame
              ((binding.claim.originalNormalized.eval originalState).nextMachineState
                originalState).registers
              ((binding.claim.candidateNormalized.eval candidateState).nextMachineState
                candidateState).registers := by
            refine ⟨by simp [targetInventory,
              ReturnSlotAffineInventoryShape.toInventory], ?_⟩
            intro location member
            have locationExact : location = targetLocation := by
              simpa [targetInventory,
                ReturnSlotAffineInventoryShape.toInventory] using member
            subst location
            exact targetLocationHolds
          have inventoryWords :
              targetInventory.exactWords = sourceInventory.exactWords := by
            calc
              targetInventory.exactWords = binding.targetShape.exactWords := by
                rfl
              _ = binding.sourceShape.exactWords := payloadWords.symm
              _ = sourceInventory.exactWords := sourceWords.symm
          have targetExactWords : targetInventory.boundedExactWordsHold frame
              ((binding.claim.originalNormalized.eval originalState).nextMachineState
                originalState).memory
              ((binding.claim.candidateNormalized.eval candidateState).nextMachineState
                candidateState).memory := by
            constructor
            · unfold ReturnSlotOffsetInventory.exactWordsFit
              rw [inventoryWords]
              exact stackHolds.2.2.1.1
            · unfold ReturnSlotOffsetInventory.exactWordsHold
              rw [inventoryWords]
              simpa [originalMemory, candidateMemory] using stackHolds.2.2.1.2
          have framesAfter := RelationalRuntimeCallFramesHold.of_memory_eq context
            originalState candidateState
            ((binding.claim.originalNormalized.eval originalState).nextMachineState
              originalState)
            ((binding.claim.candidateNormalized.eval candidateState).nextMachineState
              candidateState)
            (frame :: frames) (continuation :: continuations)
            stackHolds.2.2.2.1
            originalMemory candidateMemory
          have linksAfter := RelationalRuntimeCallFrameLinksHold.of_memory_eq
            originalState.memory candidateState.memory
            ((binding.claim.originalNormalized.eval originalState).nextMachineState
              originalState).memory
            ((binding.claim.candidateNormalized.eval candidateState).nextMachineState
              candidateState).memory
            (frame :: frames) links stackHolds.2.2.2.2
            originalMemory candidateMemory
          refine ⟨targetInventory, targetRealizes, ?_⟩
          simp only [RelationalLinkedRuntimeCallStackHolds]
          exact ⟨targetChecked, targetHolds, targetExactWords, framesAfter,
            linksAfter⟩

/-- Extract the machine-checked active-frame payload transfer from a complete
semantic binding check. -/
theorem ReturnSlotAffineFrameSemanticTransitionBinding.facts_checked_of_checked
    (binding : ReturnSlotAffineFrameSemanticTransitionBinding)
    (context : StaticProofContext) (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context profile graph = true) :
    binding.sourceShape.factsPreservedAcross context
      binding.claim.originalNormalized binding.claim.candidateNormalized = true := by
  cases sourceLocations : binding.sourceShape.locations with
  | exact locations =>
      simp [ReturnSlotAffineFrameSemanticTransitionBinding.checked,
        sourceLocations] at checked
  | affineFamily sourceStateIndex =>
      cases targetLocations : binding.targetShape.locations with
      | exact locations =>
          simp [ReturnSlotAffineFrameSemanticTransitionBinding.checked,
            sourceLocations, targetLocations] at checked
      | affineFamily targetStateIndex =>
          simp only [ReturnSlotAffineFrameSemanticTransitionBinding.checked,
            sourceLocations, targetLocations, Bool.and_eq_true, beq_iff_eq]
            at checked
          rcases checked with ⟨checked, _targetStateFound⟩
          rcases checked with ⟨checked, _sourceStateFound⟩
          rcases checked with ⟨checked, _targetShapeChecked⟩
          rcases checked with ⟨checked, _sourceShapeChecked⟩
          exact checked.2

theorem ReturnSlotAffineFrameSemanticTransitionBinding.payload_eq_of_checked
    (binding : ReturnSlotAffineFrameSemanticTransitionBinding)
    (context : StaticProofContext) (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context profile graph = true) :
    binding.sourceShape.exactWords = binding.targetShape.exactWords ∧
      binding.sourceShape.preservedImports =
        binding.targetShape.preservedImports ∧
      binding.sourceShape.preservedRelations =
        binding.targetShape.preservedRelations := by
  cases sourceLocations : binding.sourceShape.locations with
  | exact locations =>
      simp [ReturnSlotAffineFrameSemanticTransitionBinding.checked,
        sourceLocations] at checked
  | affineFamily sourceStateIndex =>
      cases targetLocations : binding.targetShape.locations with
      | exact locations =>
          simp [ReturnSlotAffineFrameSemanticTransitionBinding.checked,
            sourceLocations, targetLocations] at checked
      | affineFamily targetStateIndex =>
          simp only [ReturnSlotAffineFrameSemanticTransitionBinding.checked,
            sourceLocations, targetLocations, Bool.and_eq_true, beq_iff_eq]
            at checked
          rcases checked with ⟨checked, _targetStateFound⟩
          rcases checked with ⟨checked, _sourceStateFound⟩
          rcases checked with ⟨checked, _targetShapeChecked⟩
          rcases checked with ⟨checked, _sourceShapeChecked⟩
          rcases checked with ⟨checked, _factsPreserved⟩
          rcases checked with ⟨checked, relationsExact⟩
          rcases checked with ⟨checked, importsExact⟩
          exact ⟨checked.2, importsExact, relationsExact⟩

/-- Shallow specialization of `afterNoWriteNested`. -/
theorem ReturnSlotAffineFrameSemanticTransitionBinding.afterNoWrite
    (binding : ReturnSlotAffineFrameSemanticTransitionBinding)
    (context : StaticProofContext) (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame) (continuation : Nat)
    (sourceInventory : ReturnSlotOffsetInventory)
    (checked : binding.checked context profile graph = true)
    (sourceRealizes : binding.sourceShape.Realizes profile
      binding.claim.transition.source.nodeId sourceInventory)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState [frame] [continuation] (some sourceInventory) [])
    (originalMemory :
      ((binding.claim.originalNormalized.eval originalState).nextMachineState
        originalState).memory = originalState.memory)
    (candidateMemory :
      ((binding.claim.candidateNormalized.eval candidateState).nextMachineState
        candidateState).memory = candidateState.memory) :
    ∃ targetInventory,
      binding.targetShape.Realizes profile
          binding.claim.transition.target.nodeId targetInventory ∧
        RelationalLinkedRuntimeCallStackHolds context
          ((binding.claim.originalNormalized.eval originalState).nextMachineState
            originalState)
          ((binding.claim.candidateNormalized.eval candidateState).nextMachineState
            candidateState)
          [frame] [continuation] (some targetInventory) [] := by
  exact binding.afterNoWriteNested context profile graph originalState
    candidateState frame [] continuation [] [] sourceInventory checked
    sourceRealizes stackHolds originalMemory candidateMemory

/-- Finite control over affine frame shapes.  `Allows` is a proposition because
family membership carries an explicit modular coefficient witness. -/
structure AffineLinkedProductControlState where
  nodeId : Nat
  continuation : Option Nat
  activeShape : Option ReturnSlotAffineInventoryShape
  minimumDepth : Nat := 0
deriving Repr, DecidableEq

/-- A static affine shape for one nested call-frame link.  Inventory node IDs
are explicit because the suspended caller inventory is expressed in the
callee-entry register state after the call push; it is not a caller-source
inventory.  Concrete runtime frames and their flat memories remain
authoritative in `RelationalRuntimeCallFrameLink`. -/
structure RelationalRuntimeCallFrameAffineLinkShape where
  callEdgeId : Nat
  callSourceNodeId : Nat
  callSourceTargetId : Nat
  innerInventoryNodeId : Nat
  suspendedInventoryNodeId : Nat
  resumeInventoryNodeId : Nat
  resumeTargetId : Nat
  resumeContinuation : Nat
  originalGap : Nat
  candidateGap : Nat
  innerShape : ReturnSlotAffineInventoryShape
  suspendedShape : ReturnSlotAffineInventoryShape
  resumeShape : ReturnSlotAffineInventoryShape
deriving Repr, DecidableEq

/-- Check the graph identity, call/callee relationship, affine-family
membership, and non-wrapping frame gaps of one submitted link shape. -/
def RelationalRuntimeCallFrameAffineLinkShape.checkedAgainstGraph
    (shape : RelationalRuntimeCallFrameAffineLinkShape)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Bool :=
  match graph.getEdge? shape.callEdgeId,
      graph.getNode? shape.callSourceNodeId,
      graph.getNode? shape.innerInventoryNodeId,
      graph.getNode? shape.suspendedInventoryNodeId,
      graph.getNode? shape.resumeInventoryNodeId with
  | some edge, some source, some inner, some suspended, some resume =>
      edge.id == shape.callEdgeId && !edge.infeasible && edge.kind == .call &&
        edge.sourceNodeId == shape.callSourceNodeId &&
        edge.targetNodeId == shape.innerInventoryNodeId &&
        edge.targetNodeId == shape.suspendedInventoryNodeId &&
        edge.sourceTargetId == shape.callSourceTargetId &&
        source.id == shape.callSourceNodeId &&
        source.targetId == shape.callSourceTargetId &&
        inner.id == shape.innerInventoryNodeId &&
        inner.targetId == edge.targetTargetId &&
        suspended.id == shape.suspendedInventoryNodeId &&
        suspended.targetId == edge.targetTargetId &&
        resume.id == shape.resumeInventoryNodeId &&
        resume.targetId == shape.resumeTargetId &&
        4 <= shape.originalGap && shape.originalGap < 2 ^ 32 &&
        4 <= shape.candidateGap && shape.candidateGap < 2 ^ 32 &&
        shape.innerShape.checked affine shape.innerInventoryNodeId &&
        shape.suspendedShape.checked affine shape.suspendedInventoryNodeId &&
        shape.resumeShape.checked affine shape.resumeInventoryNodeId
  | _, _, _, _, _ => false

def RelationalRuntimeCallFrameAffineLinkShape.checked
    (shape : RelationalRuntimeCallFrameAffineLinkShape)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Bool :=
  affine.checked graph && shape.checkedAgainstGraph affine graph

/-- A concrete nested link realizes a static affine shape only when every
exact scalar field agrees and all three concrete inventories realize their
declared shapes.  `link.checked` retains the authoritative flat-memory gap and
inventory checks. -/
structure RelationalRuntimeCallFrameAffineLinkShape.Realizes
    (shape : RelationalRuntimeCallFrameAffineLinkShape)
    (affine : ReturnSlotAffineFrameProfile)
    (link : RelationalRuntimeCallFrameLink) : Prop where
  linkChecked : link.checked = true
  callSourceTargetExact : link.callSourceTargetId = shape.callSourceTargetId
  resumeNodeExact : link.resumeNodeId = shape.resumeInventoryNodeId
  resumeTargetExact : link.resumeTargetId = shape.resumeTargetId
  resumeContinuationExact : link.resumeContinuation = shape.resumeContinuation
  originalGapExact : link.originalGap = shape.originalGap
  candidateGapExact : link.candidateGap = shape.candidateGap
  innerRealizes : shape.innerShape.Realizes affine shape.innerInventoryNodeId
    link.innerInventory
  suspendedRealizes : shape.suspendedShape.Realizes affine
    shape.suspendedInventoryNodeId link.suspendedInventory
  resumeRealizes : shape.resumeShape.Realizes affine shape.resumeInventoryNodeId
    link.resumeInventory

def AffineLinkedProductControlState.checked
    (state : AffineLinkedProductControlState)
    (affine : ReturnSlotAffineFrameProfile) : Bool :=
  match state.continuation, state.activeShape with
  | none, none => state.minimumDepth == 0
  | some _, some shape =>
      0 < state.minimumDepth && shape.checked affine state.nodeId
  | _, _ => false

def AffineLinkedProductControlState.Matches
    (state : AffineLinkedProductControlState)
    (affine : ReturnSlotAffineFrameProfile) (nodeId : Nat)
    (continuation : Option Nat)
    (active : Option ReturnSlotOffsetInventory) : Prop :=
  state.nodeId = nodeId ∧ state.continuation = continuation ∧
    match state.activeShape, active with
    | none, none => True
    | some shape, some inventory => shape.Realizes affine nodeId inventory
    | _, _ => False

structure AffineLinkedProductControlProfile where
  states : List AffineLinkedProductControlState
  linkShapes : List RelationalRuntimeCallFrameAffineLinkShape := []
deriving Repr, DecidableEq

def AffineLinkedProductControlProfile.coversResumeShape
    (profile : AffineLinkedProductControlProfile)
    (shape : RelationalRuntimeCallFrameAffineLinkShape) : Bool :=
  profile.states.any fun state =>
    state.nodeId == shape.resumeInventoryNodeId &&
      state.continuation == some shape.resumeContinuation &&
      state.activeShape == some shape.resumeShape && state.minimumDepth <= 1

def AffineLinkedProductControlProfile.checked
    (profile : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Bool :=
  affine.checked graph &&
    profile.states.all (fun state => state.checked affine) &&
    decide profile.states.Nodup &&
    profile.linkShapes.all (fun shape =>
      shape.checkedAgainstGraph affine graph && profile.coversResumeShape shape) &&
    decide profile.linkShapes.Nodup

/-- A proof-relevant ordinary-control edge.  The semantic frame binding is
checked separately, while these indices tie it to the exact finite control
states submitted for whole-program composition. -/
structure AffineLinkedOrdinaryTransitionBinding where
  sourceControlStateIndex : Nat
  targetControlStateIndex : Nat
  edgeId : Nat
  continuationTargetId : Nat
  frameBinding : ReturnSlotAffineFrameSemanticTransitionBinding
deriving Repr, DecidableEq

def AffineLinkedOrdinaryTransitionBinding.checked
    (binding : AffineLinkedOrdinaryTransitionBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Bool :=
  control.checked affine graph &&
    binding.frameBinding.checked context affine graph &&
    binding.edgeId == binding.frameBinding.claim.transition.edgeId &&
    match control.states[binding.sourceControlStateIndex]?,
        control.states[binding.targetControlStateIndex]? with
    | some source, some target =>
        source.nodeId == binding.frameBinding.claim.transition.source.nodeId &&
          target.nodeId == binding.frameBinding.claim.transition.target.nodeId &&
          source.continuation == some binding.continuationTargetId &&
          target.continuation == some binding.continuationTargetId &&
          source.activeShape == some binding.frameBinding.sourceShape &&
          target.activeShape == some binding.frameBinding.targetShape &&
          source.minimumDepth == 1 && target.minimumDepth == 1
    | _, _ => false

theorem AffineLinkedOrdinaryTransitionBinding.frame_checked_of_checked
    (binding : AffineLinkedOrdinaryTransitionBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context control affine graph = true) :
    binding.frameBinding.checked context affine graph = true := by
  simp only [AffineLinkedOrdinaryTransitionBinding.checked,
    Bool.and_eq_true] at checked
  exact checked.1.1.2

def AffineLinkedProductControlProfile.Allows
    (profile : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) (nodeId : Nat)
    (continuations : List Nat)
    (active : Option ReturnSlotOffsetInventory) : Prop :=
  profile.checked affine graph = true ∧
    ∃ state ∈ profile.states,
      state.Matches affine nodeId continuations.head? active ∧
        state.minimumDepth ≤ continuations.length

/-- Execute a checked ordinary affine transition, preserve every dormant frame
and link, and re-establish finite control at the checked target state. -/
theorem AffineLinkedOrdinaryTransitionBinding.afterNoWriteNested
    (binding : AffineLinkedOrdinaryTransitionBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation : Nat) (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (sourceInventory : ReturnSlotOffsetInventory)
    (checked : binding.checked context control affine graph = true)
    (sourceRealizes : binding.frameBinding.sourceShape.Realizes affine
      binding.frameBinding.claim.transition.source.nodeId sourceInventory)
    (continuationExact : continuation = binding.continuationTargetId)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (frame :: frames) (continuation :: continuations)
      (some sourceInventory) links)
    (originalMemory :
      ((binding.frameBinding.claim.originalNormalized.eval
        originalState).nextMachineState originalState).memory =
        originalState.memory)
    (candidateMemory :
      ((binding.frameBinding.claim.candidateNormalized.eval
        candidateState).nextMachineState candidateState).memory =
        candidateState.memory) :
    ∃ targetInventory,
      binding.frameBinding.targetShape.Realizes affine
          binding.frameBinding.claim.transition.target.nodeId targetInventory ∧
        RelationalLinkedRuntimeCallStackHolds context
          ((binding.frameBinding.claim.originalNormalized.eval
            originalState).nextMachineState originalState)
          ((binding.frameBinding.claim.candidateNormalized.eval
            candidateState).nextMachineState candidateState)
          (frame :: frames) (continuation :: continuations)
          (some targetInventory) links ∧
        control.Allows affine graph
          binding.frameBinding.claim.transition.target.nodeId
          (continuation :: continuations) (some targetInventory) := by
  have transferred := binding.frameBinding.afterNoWriteNested context affine graph
    originalState candidateState frame frames continuation continuations links
    sourceInventory (binding.frame_checked_of_checked context control affine graph
      checked) sourceRealizes stackHolds originalMemory candidateMemory
  rcases transferred with ⟨targetInventory, targetRealizes, targetStack⟩
  have checkedFacts := checked
  unfold AffineLinkedOrdinaryTransitionBinding.checked at checkedFacts
  cases sourceFound : control.states[binding.sourceControlStateIndex]? with
  | none => simp [sourceFound] at checkedFacts
  | some source =>
      cases targetFound : control.states[binding.targetControlStateIndex]? with
      | none => simp [sourceFound, targetFound] at checkedFacts
      | some target =>
          simp only [sourceFound, targetFound, Bool.and_eq_true, beq_iff_eq]
            at checkedFacts
          refine ⟨targetInventory, targetRealizes, targetStack,
            checkedFacts.1.1.1, target,
            List.mem_of_getElem? targetFound, ?_, ?_⟩
          · exact ⟨checkedFacts.2.1.1.1.1.1.1.2,
              by simpa [continuationExact] using checkedFacts.2.1.1.1.1.2,
              by simpa [checkedFacts.2.1.1.2] using targetRealizes⟩
          · simp [checkedFacts.2.2]

def AffineLinkedProductControlProfile.LinkShapeAllowed
    (profile : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (shape : RelationalRuntimeCallFrameAffineLinkShape) : Bool :=
  profile.checked affine graph && shape.checkedAgainstGraph affine graph &&
    profile.coversResumeShape shape && profile.linkShapes.contains shape

/-- Every concrete dormant link may select a different affine coefficient,
but it must realize one checked static shape in the finite profile.  The list
is not depth-bounded: recursive and otherwise nested concrete frame stacks are
handled inductively. -/
def AffineLinkedProductControlProfile.LinksAllowed
    (profile : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (links : List RelationalRuntimeCallFrameLink) : Prop :=
  profile.checked affine graph = true ∧
    ∀ link, link ∈ links →
      ∃ shape ∈ profile.linkShapes, shape.Realizes affine link

@[simp]
theorem AffineLinkedProductControlProfile.LinksAllowed.nil
    (profile : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : profile.checked affine graph = true) :
    profile.LinksAllowed affine graph [] := by
  exact ⟨checked, by simp⟩

theorem AffineLinkedProductControlProfile.LinksAllowed.cons
    (profile : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (shape : RelationalRuntimeCallFrameAffineLinkShape)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (shapeAllowed : profile.LinkShapeAllowed affine graph shape = true)
    (realizes : shape.Realizes affine link)
    (tail : profile.LinksAllowed affine graph links) :
    profile.LinksAllowed affine graph (link :: links) := by
  simp only [AffineLinkedProductControlProfile.LinkShapeAllowed,
    Bool.and_eq_true] at shapeAllowed
  refine ⟨shapeAllowed.1.1.1, ?_⟩
  intro selected member
  rcases List.mem_cons.mp member with same | inTail
  · subst selected
    exact ⟨shape, List.contains_iff_mem.mp shapeAllowed.2, realizes⟩
  · exact tail.2 selected inTail

theorem AffineLinkedProductControlProfile.LinksAllowed.tail
    (profile : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (allowed : profile.LinksAllowed affine graph (link :: links)) :
    profile.LinksAllowed affine graph links := by
  exact ⟨allowed.1, fun selected member =>
    allowed.2 selected (by simp [member])⟩

/-- A return target must select one unique static affine link shape.  Two
different contracts for the same target remain incomplete instead of choosing
one from list order. -/
def AffineLinkedProductControlProfile.selectsUniqueResumeShape
    (profile : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (continuation : Nat)
    (expected : RelationalRuntimeCallFrameAffineLinkShape) : Bool :=
  profile.LinkShapeAllowed affine graph expected &&
    profile.linkShapes.all fun candidate =>
      decide (candidate.resumeTargetId = continuation → candidate = expected)

theorem AffineLinkedProductControlProfile.selectedHeadShape_realizes
    (profile : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (continuation : Nat)
    (expected : RelationalRuntimeCallFrameAffineLinkShape)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (unique : profile.selectsUniqueResumeShape affine graph continuation expected = true)
    (allowed : profile.LinksAllowed affine graph (link :: links))
    (resumeTarget : link.resumeTargetId = continuation) :
    expected.Realizes affine link := by
  simp only [AffineLinkedProductControlProfile.selectsUniqueResumeShape,
    Bool.and_eq_true] at unique
  obtain ⟨selected, selectedMember, selectedRealizes⟩ :=
    allowed.2 link (by simp)
  have selectedRule :=
    List.all_eq_true.mp unique.2 selected selectedMember
  simp only [decide_eq_true_eq] at selectedRule
  have selectedTarget : selected.resumeTargetId = continuation :=
    selectedRealizes.resumeTargetExact.symm.trans resumeTarget
  have selectedExact : selected = expected := selectedRule selectedTarget
  simpa [selectedExact] using selectedRealizes

/-- Resume authorization is derived from the concrete realized head link.
The resume inventory retains its existential affine coefficient; no canonical
or representative location is selected. -/
theorem AffineLinkedProductControlProfile.allowsResumeOfRealizedHead
    (profile : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (expected : RelationalRuntimeCallFrameAffineLinkShape)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (continuations : List Nat)
    (unique : profile.selectsUniqueResumeShape affine graph
      link.resumeTargetId expected = true)
    (allowed : profile.LinksAllowed affine graph (link :: links)) :
    profile.Allows affine graph link.resumeNodeId
      (link.resumeContinuation :: continuations) (some link.resumeInventory) := by
  have expectedRealizes := profile.selectedHeadShape_realizes affine graph
    link.resumeTargetId expected link links unique allowed rfl
  simp only [AffineLinkedProductControlProfile.selectsUniqueResumeShape,
    Bool.and_eq_true] at unique
  simp only [AffineLinkedProductControlProfile.LinkShapeAllowed,
    Bool.and_eq_true] at unique
  have profileChecked := unique.1.1.1.1
  have resumeCovered := unique.1.1.2
  unfold AffineLinkedProductControlProfile.coversResumeShape at resumeCovered
  rcases List.any_eq_true.mp resumeCovered with ⟨state, stateMember, matched⟩
  simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at matched
  refine ⟨profileChecked, state, stateMember, ?_, ?_⟩
  · refine ⟨matched.1.1.1.trans expectedRealizes.resumeNodeExact.symm,
      ?_, ?_⟩
    · simpa [expectedRealizes.resumeContinuationExact] using matched.1.1.2
    · simpa [matched.1.2, expectedRealizes.resumeNodeExact] using
        expectedRealizes.resumeRealizes
  · exact Nat.le_trans matched.2 (Nat.succ_le_succ (Nat.zero_le _))

/-- A sound authority for executions with no dormant frame links.  This is the
base case used by ordinary affine jumps and branches.  Nested calls require an
affine link profile and therefore cannot be admitted through this constructor. -/
def AffineLinkedProductControlProfile.shallowAuthority
    (profile : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : LinkedControlAuthority := {
  allows := profile.Allows affine graph
  linksAllowed := fun links => links = []
}

/-- Full affine authority for arbitrarily deep concrete nested link lists. -/
def AffineLinkedProductControlProfile.authority
    (profile : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : LinkedControlAuthority := {
  allows := profile.Allows affine graph
  linksAllowed := profile.LinksAllowed affine graph
}

theorem AffineLinkedProductControlProfile.active_realizes_of_allows
    (profile : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) (nodeId : Nat)
    (continuations : List Nat) (inventory : ReturnSlotOffsetInventory)
    (allowed : profile.Allows affine graph nodeId continuations (some inventory)) :
    ∃ state ∈ profile.states, ∃ shape,
      state.activeShape = some shape ∧
        shape.Realizes affine nodeId inventory := by
  rcases allowed.2 with ⟨state, member, stateMatches, _depth⟩
  refine ⟨state, member, ?_⟩
  rcases stateMatches with ⟨_nodeMatches, _continuationMatches, activeMatches⟩
  cases shapeResult : state.activeShape with
  | none => simp [shapeResult] at activeMatches
  | some shape =>
      exact ⟨shape, rfl, by simpa [shapeResult] using activeMatches⟩

/-! ## Checked singleton-affine nested direct calls

This section binds the static ingredients needed by later `pushNested` and
`popNested` proofs.  The binding is evidence only: its checker does not create
a control authority, an execution refinement, or an acceptance certificate. -/

/-- A full-word-stride affine family denotes exactly one paired offset. -/
def ReturnSlotAffineFamily.SingletonAt (family : ReturnSlotAffineFamily)
    (offsets : ReturnSlotOffsetPair) : Prop :=
  family.valid = true ∧
    family.translationStride = 2 ^ 32 ∧
    family.originalRegister = offsets.originalRegister ∧
    family.candidateRegister = offsets.candidateRegister ∧
    family.originalBase = offsets.originalOffset ∧
    family.candidateBase = offsets.candidateOffset

def ReturnSlotAffineFamily.singletonAtChecked
    (family : ReturnSlotAffineFamily) (offsets : ReturnSlotOffsetPair) : Bool :=
  family.valid && family.translationStride == 2 ^ 32 &&
    family.originalRegister == offsets.originalRegister &&
    family.candidateRegister == offsets.candidateRegister &&
    family.originalBase == offsets.originalOffset &&
    family.candidateBase == offsets.candidateOffset

theorem ReturnSlotAffineFamily.singletonAtChecked_iff
    (family : ReturnSlotAffineFamily) (offsets : ReturnSlotOffsetPair) :
    family.singletonAtChecked offsets = true ↔ family.SingletonAt offsets := by
  constructor
  · intro checked
    simp only [ReturnSlotAffineFamily.singletonAtChecked, Bool.and_eq_true,
      beq_iff_eq] at checked
    exact ⟨checked.1.1.1.1.1, checked.1.1.1.1.2, checked.1.1.1.2,
      checked.1.1.2, checked.1.2, checked.2⟩
  · rintro ⟨valid, stride, originalRegister, candidateRegister, originalBase,
      candidateBase⟩
    simp [ReturnSlotAffineFamily.singletonAtChecked, valid, stride,
      originalRegister, candidateRegister, originalBase, candidateBase]

/-- Full-word stride is zero as an IA-32 word, so every concrete member is the
submitted singleton rather than an unchecked representative. -/
theorem ReturnSlotAffineFamily.contains_eq_of_singletonAt
    (family : ReturnSlotAffineFamily) (expected actual : ReturnSlotOffsetPair)
    (singleton : family.SingletonAt expected)
    (contains : family.contains actual) : actual = expected := by
  rcases singleton with
    ⟨_valid, stride, originalRegister, candidateRegister, originalBase,
      candidateBase⟩
  rcases contains with
    ⟨actualOriginalRegister, actualCandidateRegister, coefficient,
      actualOriginalOffset, actualCandidateOffset⟩
  cases actual
  cases expected
  simp_all

/-- Select one exact affine state through the inventory-shape index. -/
def ReturnSlotAffineInventoryShape.singletonStateChecked
    (shape : ReturnSlotAffineInventoryShape)
    (profile : ReturnSlotAffineFrameProfile)
    (state : ReturnSlotAffineFrameState)
    (offsets : ReturnSlotOffsetPair) : Bool :=
  shape.checked profile state.nodeId &&
    match shape.locations with
    | .affineFamily stateIndex =>
        profile.states[stateIndex]? == some state &&
          state.family.singletonAtChecked offsets
    | .exact _ => false

theorem ReturnSlotAffineInventoryShape.singletonState_facts_of_checked
    (shape : ReturnSlotAffineInventoryShape)
    (profile : ReturnSlotAffineFrameProfile)
    (state : ReturnSlotAffineFrameState)
    (offsets : ReturnSlotOffsetPair)
    (checked : shape.singletonStateChecked profile state offsets = true) :
    shape.checked profile state.nodeId = true ∧
      ∃ stateIndex,
        shape.locations = .affineFamily stateIndex ∧
          profile.states[stateIndex]? = some state ∧
          state.family.SingletonAt offsets := by
  unfold ReturnSlotAffineInventoryShape.singletonStateChecked at checked
  rw [Bool.and_eq_true] at checked
  refine ⟨checked.1, ?_⟩
  cases locations : shape.locations with
  | exact locations => simp [locations] at checked
  | affineFamily stateIndex =>
      simp only [locations, Bool.and_eq_true, beq_iff_eq] at checked
      exact ⟨stateIndex, rfl, checked.2.1,
        (state.family.singletonAtChecked_iff offsets).mp checked.2.2⟩

/-- A realized inventory of a checked singleton affine shape is the exact
submitted inventory.  This removes the existential affine coefficient only
after Lean has established that the full-word stride makes every member equal
to the submitted offset. -/
theorem ReturnSlotAffineInventoryShape.realizes_eq_toInventory_of_singletonState
    (shape : ReturnSlotAffineInventoryShape)
    (profile : ReturnSlotAffineFrameProfile)
    (state : ReturnSlotAffineFrameState)
    (offsets : ReturnSlotOffsetPair)
    (inventory : ReturnSlotOffsetInventory)
    (checked : shape.singletonStateChecked profile state offsets = true)
    (realizes : shape.Realizes profile state.nodeId inventory) :
    inventory = shape.toInventory [offsets] := by
  obtain ⟨_shapeChecked, stateIndex, locationsShape, stateFound, singleton⟩ :=
    shape.singletonState_facts_of_checked profile state offsets checked
  simp only [ReturnSlotAffineInventoryShape.Realizes,
    ReturnSlotAffineInventoryShape.PayloadMatches, locationsShape] at realizes
  rcases realizes with
    ⟨⟨exactWords, imports, relations⟩,
      ⟨actualState, coefficient, location, actualStateFound, _nodeExact,
        containsAt, inventoryLocations⟩⟩
  have actualStateExact : actualState = state := by
    exact Option.some.inj (actualStateFound.symm.trans stateFound)
  subst actualState
  have locationExact : location = offsets :=
    state.family.contains_eq_of_singletonAt offsets location singleton
      containsAt.contains
  subst location
  cases inventory
  simp_all [ReturnSlotAffineInventoryShape.toInventory]

/-- Select a singleton affine family at one node without trusting a separately
submitted family value. -/
def ReturnSlotAffineInventoryShape.singletonAtNodeChecked
    (shape : ReturnSlotAffineInventoryShape)
    (profile : ReturnSlotAffineFrameProfile) (nodeId : Nat)
    (offsets : ReturnSlotOffsetPair) : Bool :=
  match shape.locations with
  | .affineFamily stateIndex =>
      match profile.states[stateIndex]? with
      | some state =>
          state.nodeId == nodeId &&
            shape.singletonStateChecked profile state offsets
      | none => false
  | .exact _ => false

theorem ReturnSlotAffineInventoryShape.singletonAtNode_facts_of_checked
    (shape : ReturnSlotAffineInventoryShape)
    (profile : ReturnSlotAffineFrameProfile) (nodeId : Nat)
    (offsets : ReturnSlotOffsetPair)
    (checked : shape.singletonAtNodeChecked profile nodeId offsets = true) :
    ∃ stateIndex state,
      shape.locations = .affineFamily stateIndex ∧
        profile.states[stateIndex]? = some state ∧
        state.nodeId = nodeId ∧
        shape.checked profile nodeId = true ∧
        state.family.SingletonAt offsets := by
  unfold ReturnSlotAffineInventoryShape.singletonAtNodeChecked at checked
  cases locations : shape.locations with
  | exact locations => simp [locations] at checked
  | affineFamily stateIndex =>
      cases stateFound : profile.states[stateIndex]? with
      | none => simp [locations, stateFound] at checked
      | some state =>
          simp only [locations, stateFound, Bool.and_eq_true, beq_iff_eq] at checked
          have selected := shape.singletonState_facts_of_checked profile state offsets
            checked.2
          exact ⟨stateIndex, state, rfl, stateFound, checked.1,
            by simpa [checked.1] using selected.1, selected.2.choose_spec.2.2⟩

/-- The original and candidate may reserve different stack amounts, but each
must be an exact aligned ESP subtraction inside the same checked stack window. -/
structure PairedEspSubtractionStackAmount where
  original : Nat
  candidate : Nat
deriving Repr, DecidableEq

def PairedEspSubtractionStackAmount.originalExpression
    (amount : PairedEspSubtractionStackAmount) : Expr :=
  .add (.inputReg .esp) (.constant (2 ^ 32 - amount.original))

def PairedEspSubtractionStackAmount.candidateExpression
    (amount : PairedEspSubtractionStackAmount) : Expr :=
  .add (.inputReg .esp) (.constant (2 ^ 32 - amount.candidate))

def PairedEspSubtractionStackAmount.checked
    (amount : PairedEspSubtractionStackAmount) (window : StackWindowPair)
    (callPush : DirectCallPushClaim) : Bool :=
  window.originalRegister == .esp && window.candidateRegister == .esp &&
    4 <= amount.original && amount.original % 4 == 0 &&
    amount.original < 2 ^ 32 && amount.original <= window.bytesBelow &&
    4 <= amount.candidate && amount.candidate % 4 == 0 &&
    amount.candidate < 2 ^ 32 && amount.candidate <= window.bytesBelow &&
    callPush.originalStackAddress == amount.originalExpression &&
    callPush.candidateStackAddress == amount.candidateExpression

theorem PairedEspSubtractionStackAmount.facts_of_checked
    (amount : PairedEspSubtractionStackAmount) (window : StackWindowPair)
    (callPush : DirectCallPushClaim)
    (checked : amount.checked window callPush = true) :
    window.originalRegister = .esp ∧ window.candidateRegister = .esp ∧
      4 ≤ amount.original ∧ amount.original % 4 = 0 ∧
      amount.original < 2 ^ 32 ∧ amount.original ≤ window.bytesBelow ∧
      4 ≤ amount.candidate ∧ amount.candidate % 4 = 0 ∧
      amount.candidate < 2 ^ 32 ∧ amount.candidate ≤ window.bytesBelow ∧
      callPush.originalStackAddress = amount.originalExpression ∧
      callPush.candidateStackAddress = amount.candidateExpression := by
  simp only [PairedEspSubtractionStackAmount.checked, Bool.and_eq_true,
    beq_iff_eq, decide_eq_true_eq] at checked
  rcases checked with ⟨checked, candidateExpression⟩
  rcases checked with ⟨checked, originalExpression⟩
  rcases checked with ⟨checked, candidateInside⟩
  rcases checked with ⟨checked, candidateSmall⟩
  rcases checked with ⟨checked, candidateAligned⟩
  rcases checked with ⟨checked, candidateAtLeastWord⟩
  rcases checked with ⟨checked, originalInside⟩
  rcases checked with ⟨checked, originalSmall⟩
  rcases checked with ⟨checked, originalAligned⟩
  rcases checked with ⟨checked, originalAtLeastWord⟩
  rcases checked with ⟨originalEsp, candidateEsp⟩
  exact ⟨originalEsp, candidateEsp, originalAtLeastWord, originalAligned,
    originalSmall, originalInside, candidateAtLeastWord, candidateAligned,
    candidateSmall, candidateInside, originalExpression, candidateExpression⟩

theorem PairedEspSubtractionStackAmount.stackAddress_evals_of_checked
    (amount : PairedEspSubtractionStackAmount) (window : StackWindowPair)
    (callPush : DirectCallPushClaim) (original candidate : MachineState)
    (checked : amount.checked window callPush = true) :
    callPush.originalStackAddress.eval original =
        original.registers.esp - BitVec.ofNat 32 amount.original ∧
      callPush.candidateStackAddress.eval candidate =
        candidate.registers.esp - BitVec.ofNat 32 amount.candidate := by
  have facts := amount.facts_of_checked window callPush checked
  rw [facts.2.2.2.2.2.2.2.2.2.2.1, facts.2.2.2.2.2.2.2.2.2.2.2]
  constructor
  · simp [PairedEspSubtractionStackAmount.originalExpression, Expr.eval,
      StageA.Formal.Registers.get,
      word_add_ia32_twos_complement _ amount.original facts.2.2.2.2.1]
  · simp [PairedEspSubtractionStackAmount.candidateExpression, Expr.eval,
      StageA.Formal.Registers.get,
      word_add_ia32_twos_complement _ amount.candidate facts.2.2.2.2.2.2.2.2.1]

/-- One exact decoded return site participating in a nested direct-call
summary.  This is local semantic evidence only: product-graph composition must
still prove that the listed return sites exhaust every reachable callee exit. -/
structure SingletonAffineNestedDirectCallReturnSummary where
  returnNodeId : Nat
  returnRegion : RegionRelation
  originalBehavior : SymbolicBehavior
  candidateBehavior : SymbolicBehavior
  originalNormalized : NormalizedSymbolicBehavior
  candidateNormalized : NormalizedSymbolicBehavior
  summary : ReturnSlotCallSummaryClaim
deriving Repr, DecidableEq

def SingletonAffineNestedDirectCallReturnSummary.checked
    (evidence : SingletonAffineNestedDirectCallReturnSummary)
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (callPush : DirectCallPushClaim)
    (originalCall candidateCall : NormalizedSymbolicBehavior)
    (sourceOffsets resumeOffsets : ReturnSlotOffsetPair) : Bool :=
  match graph.getNode? evidence.returnNodeId with
  | none => false
  | some node =>
      node.targetId == evidence.returnRegion.id &&
        regionBehaviorWithMachineCallContracts context.originalPe
            context.originalImports context.machineImportCallContracts
            evidence.returnRegion.original == some evidence.originalBehavior &&
        regionBehaviorWithMachineCallContracts context.candidatePe
            context.candidateImports context.machineImportCallContracts
            evidence.returnRegion.candidate == some evidence.candidateBehavior &&
        normalizeSymbolicBehavior false evidence.returnRegion.targets
            evidence.originalBehavior == some evidence.originalNormalized &&
        normalizeSymbolicBehavior true evidence.returnRegion.targets
            evidence.candidateBehavior == some evidence.candidateNormalized &&
        evidence.summary.checked originalCall candidateCall
          evidence.originalNormalized evidence.candidateNormalized callPush &&
        evidence.summary.source == sourceOffsets &&
        evidence.summary.target == resumeOffsets

/-- Static, non-authoritative evidence for one nested direct call whose four
active/suspended affine families are exact singleton ESP-relative offsets. -/
structure SingletonAffineNestedDirectCallControlBinding where
  sourceControlStateIndex : Nat
  innerControlStateIndex : Nat
  resumeControlStateIndex : Nat
  sourceToSuspended : ReturnSlotAffineFrameSemanticTransitionClaim
  innerSeed : ReturnSlotAffineFrameSemanticSeedClaim
  linkShape : RelationalRuntimeCallFrameAffineLinkShape
  sourceOffsets : ReturnSlotOffsetPair
  suspendedOffsets : ReturnSlotOffsetPair
  innerOffsets : ReturnSlotOffsetPair
  resumeOffsets : ReturnSlotOffsetPair
  stackAmount : PairedEspSubtractionStackAmount
  sourceWindow : StackWindowPair
  returnSummaries : List SingletonAffineNestedDirectCallReturnSummary
deriving Repr, DecidableEq

def SingletonAffineNestedDirectCallControlBinding.semanticChecked
    (binding : SingletonAffineNestedDirectCallControlBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Bool :=
  binding.sourceToSuspended.checked context graph &&
    binding.innerSeed.checked context graph &&
    affine.transitions.contains binding.sourceToSuspended.transition &&
    affine.seeds.contains binding.innerSeed.seed &&
    control.LinkShapeAllowed affine graph binding.linkShape &&
    binding.sourceToSuspended.physicalStateOnly == false &&
    binding.sourceToSuspended.transition.edgeId == binding.innerSeed.seed.edgeId &&
    binding.linkShape.callEdgeId == binding.innerSeed.seed.edgeId &&
    binding.linkShape.callSourceNodeId ==
      binding.sourceToSuspended.transition.source.nodeId &&
    binding.linkShape.innerInventoryNodeId ==
      binding.sourceToSuspended.transition.target.nodeId &&
    binding.linkShape.suspendedInventoryNodeId ==
      binding.sourceToSuspended.transition.target.nodeId &&
    binding.innerSeed.seed.nodeId == binding.linkShape.innerInventoryNodeId &&
    binding.innerSeed.callPush.continuationTargetId == binding.linkShape.resumeTargetId &&
    binding.linkShape.callSourceTargetId == binding.sourceToSuspended.region.id &&
    binding.sourceToSuspended.region == binding.innerSeed.sourceRegion &&
    binding.sourceToSuspended.originalNormalized == binding.innerSeed.originalNormalized &&
    binding.sourceToSuspended.candidateNormalized == binding.innerSeed.candidateNormalized &&
    decide binding.returnSummaries.Nodup &&
    !binding.returnSummaries.isEmpty &&
    binding.returnSummaries.all fun summary =>
      summary.checked context graph binding.innerSeed.callPush
        binding.sourceToSuspended.originalNormalized
        binding.sourceToSuspended.candidateNormalized
        binding.sourceOffsets binding.resumeOffsets

def SingletonAffineNestedDirectCallControlBinding.controlStatesChecked
    (binding : SingletonAffineNestedDirectCallControlBinding)
    (control : AffineLinkedProductControlProfile) : Bool :=
  match control.states[binding.sourceControlStateIndex]?,
      control.states[binding.innerControlStateIndex]?,
      control.states[binding.resumeControlStateIndex]? with
  | some source, some inner, some resume =>
      source.nodeId == binding.linkShape.callSourceNodeId &&
        source.continuation == some binding.linkShape.resumeContinuation &&
        inner.nodeId == binding.linkShape.innerInventoryNodeId &&
        inner.continuation == some binding.linkShape.resumeTargetId &&
        inner.activeShape == some binding.linkShape.innerShape &&
        resume.nodeId == binding.linkShape.resumeInventoryNodeId &&
        resume.continuation == some binding.linkShape.resumeContinuation &&
        resume.activeShape == some binding.linkShape.resumeShape &&
        0 < source.minimumDepth &&
        inner.minimumDepth <= source.minimumDepth + 1 &&
        resume.minimumDepth <= source.minimumDepth
  | _, _, _ => false

def SingletonAffineNestedDirectCallControlBinding.familiesChecked
    (binding : SingletonAffineNestedDirectCallControlBinding)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile) : Bool :=
  match control.states[binding.sourceControlStateIndex]? with
  | none => false
  | some source =>
      match source.activeShape with
      | none => false
      | some sourceShape =>
          sourceShape.singletonStateChecked affine
              binding.sourceToSuspended.transition.source binding.sourceOffsets &&
            binding.linkShape.suspendedShape.singletonStateChecked affine
              binding.sourceToSuspended.transition.target binding.suspendedOffsets &&
            binding.linkShape.innerShape.singletonAtNodeChecked affine
              binding.linkShape.innerInventoryNodeId binding.innerOffsets &&
            binding.linkShape.resumeShape.singletonAtNodeChecked affine
              binding.linkShape.resumeInventoryNodeId binding.resumeOffsets &&
            binding.innerSeed.seed.offsets == binding.innerOffsets &&
            sourceShape.exactWords == binding.linkShape.suspendedShape.exactWords &&
            sourceShape.preservedImports ==
              binding.linkShape.suspendedShape.preservedImports &&
            sourceShape.preservedRelations ==
              binding.linkShape.suspendedShape.preservedRelations

def SingletonAffineNestedDirectCallControlBinding.stackChecked
    (binding : SingletonAffineNestedDirectCallControlBinding)
    (sourceInvariant : StateInvariant) : Bool :=
  sourceInvariant.stackWindows.contains binding.sourceWindow &&
    binding.stackAmount.checked binding.sourceWindow binding.innerSeed.callPush &&
    binding.sourceOffsets.originalRegister == .esp &&
    binding.sourceOffsets.candidateRegister == .esp &&
    binding.suspendedOffsets.originalRegister == .esp &&
    binding.suspendedOffsets.candidateRegister == .esp &&
    binding.innerOffsets.originalRegister == .esp &&
    binding.innerOffsets.candidateRegister == .esp &&
    binding.resumeOffsets.originalRegister == .esp &&
    binding.resumeOffsets.candidateRegister == .esp &&
    binding.sourceOffsets.originalOffset.toNat + 4 <= binding.sourceWindow.bytesAbove &&
    binding.sourceOffsets.candidateOffset.toNat + 4 <= binding.sourceWindow.bytesAbove &&
    binding.sourceOffsets.originalOffset.toNat + binding.stackAmount.original ==
      binding.suspendedOffsets.originalOffset.toNat &&
    binding.sourceOffsets.candidateOffset.toNat + binding.stackAmount.candidate ==
      binding.suspendedOffsets.candidateOffset.toNat &&
    binding.innerOffsets.originalOffset.toNat + binding.linkShape.originalGap ==
      binding.suspendedOffsets.originalOffset.toNat &&
    binding.innerOffsets.candidateOffset.toNat + binding.linkShape.candidateGap ==
      binding.suspendedOffsets.candidateOffset.toNat

/-- The top-level checker is intentionally just the conjunction of independent
static facts.  Passing it cannot authorize execution or whole-program closure. -/
def SingletonAffineNestedDirectCallControlBinding.checked
    (binding : SingletonAffineNestedDirectCallControlBinding)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Bool :=
  control.checked affine graph &&
    binding.semanticChecked context control affine graph &&
    binding.controlStatesChecked control &&
    binding.familiesChecked control affine &&
    binding.stackChecked sourceInvariant

/-- Exact thunk and machine-contract evidence for a returning imported call.
Unlike an internal return summary, this cites an `externalJump` decoded from
the callee region and a unique contract in the canonical static context. -/
structure SingletonAffineReturningImportDirectCallSummary where
  thunkNodeId : Nat
  thunkRegion : RegionRelation
  originalBehavior : SymbolicBehavior
  candidateBehavior : SymbolicBehavior
  originalNormalized : NormalizedSymbolicBehavior
  candidateNormalized : NormalizedSymbolicBehavior
  machineContractId : Nat
  summary : ExternalReturnSlotCallSummaryClaim
deriving Repr, DecidableEq

def normalizedExternalJumpMatches
    (behavior : NormalizedSymbolicBehavior) (imported : ExternalTarget) : Bool :=
  match behavior.outcome with
  | .externalJump actual _ => actual == imported
  | _ => false

def SingletonAffineReturningImportDirectCallSummary.checked
    (evidence : SingletonAffineReturningImportDirectCallSummary)
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (callPush : DirectCallPushClaim)
    (originalCall candidateCall : NormalizedSymbolicBehavior)
    (sourceOffsets resumeOffsets : ReturnSlotOffsetPair) : Bool :=
  match graph.getNode? evidence.thunkNodeId,
      machineImportCallContractById? context evidence.machineContractId with
  | some node, some contract =>
      node.targetId == evidence.thunkRegion.id &&
        regionBehaviorWithMachineCallContracts context.originalPe
            context.originalImports context.machineImportCallContracts
            evidence.thunkRegion.original == some evidence.originalBehavior &&
        regionBehaviorWithMachineCallContracts context.candidatePe
            context.candidateImports context.machineImportCallContracts
            evidence.thunkRegion.candidate == some evidence.candidateBehavior &&
        normalizeSymbolicBehavior false evidence.thunkRegion.targets
            evidence.originalBehavior == some evidence.originalNormalized &&
        normalizeSymbolicBehavior true evidence.thunkRegion.targets
            evidence.candidateBehavior == some evidence.candidateNormalized &&
        contract.id == evidence.machineContractId &&
        (context.machineImportCallContracts.filter
          (fun candidate => candidate.id == evidence.machineContractId)).length == 1 &&
        contract.shapeValid &&
        contract.disposition == .returns &&
        normalizedExternalJumpMatches evidence.originalNormalized contract.imported &&
        normalizedExternalJumpMatches evidence.candidateNormalized contract.imported &&
        evidence.summary.checked originalCall candidateCall
          evidence.originalNormalized evidence.candidateNormalized
          callPush.stackClaim contract &&
        evidence.summary.source == sourceOffsets &&
        evidence.summary.target == resumeOffsets
  | _, _ => false

/-- The shared affine call-frame shape plus exact returning-import evidence.
The embedded internal-return inventory must be empty, preventing either proof
regime from being substituted for the other. -/
structure SingletonAffineReturningImportDirectCallControlBinding where
  base : SingletonAffineNestedDirectCallControlBinding
  externalSummary : SingletonAffineReturningImportDirectCallSummary
deriving Repr, DecidableEq

/-- Proof-relevant inventory evidence needed to lift a checked returning-import
call binding into execution.  The Python analysis may propose these claims, but
only this checker connects them to the canonical affine shapes, decoded call
behavior, and canonical machine import contract. -/
structure SingletonAffineReturningImportDirectCallExecutionCertificate where
  binding : SingletonAffineReturningImportDirectCallControlBinding
  entryClaim : ReturnSlotFrameInventoryTransferClaim
  resumeClaim : ExternalJumpReturnSlotInventoryTransferClaim
deriving Repr, DecidableEq

def SingletonAffineReturningImportDirectCallControlBinding.semanticChecked
    (binding : SingletonAffineReturningImportDirectCallControlBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Bool :=
  binding.base.returnSummaries.isEmpty &&
    binding.base.sourceToSuspended.checked context graph &&
    binding.base.innerSeed.checked context graph &&
    affine.transitions.contains binding.base.sourceToSuspended.transition &&
    affine.seeds.contains binding.base.innerSeed.seed &&
    control.LinkShapeAllowed affine graph binding.base.linkShape &&
    binding.base.sourceToSuspended.physicalStateOnly == false &&
    binding.base.sourceToSuspended.transition.edgeId ==
      binding.base.innerSeed.seed.edgeId &&
    binding.base.linkShape.callEdgeId == binding.base.innerSeed.seed.edgeId &&
    binding.base.linkShape.callSourceNodeId ==
      binding.base.sourceToSuspended.transition.source.nodeId &&
    binding.base.linkShape.innerInventoryNodeId ==
      binding.base.sourceToSuspended.transition.target.nodeId &&
    binding.base.linkShape.suspendedInventoryNodeId ==
      binding.base.sourceToSuspended.transition.target.nodeId &&
    binding.base.innerSeed.seed.nodeId ==
      binding.base.linkShape.innerInventoryNodeId &&
    binding.base.innerSeed.callPush.continuationTargetId ==
      binding.base.linkShape.resumeTargetId &&
    binding.base.linkShape.callSourceTargetId ==
      binding.base.sourceToSuspended.region.id &&
    binding.base.sourceToSuspended.region == binding.base.innerSeed.sourceRegion &&
    binding.base.sourceToSuspended.originalNormalized ==
      binding.base.innerSeed.originalNormalized &&
    binding.base.sourceToSuspended.candidateNormalized ==
      binding.base.innerSeed.candidateNormalized &&
    binding.externalSummary.thunkNodeId ==
      binding.base.linkShape.innerInventoryNodeId &&
    binding.externalSummary.checked context graph binding.base.innerSeed.callPush
      binding.base.sourceToSuspended.originalNormalized
      binding.base.sourceToSuspended.candidateNormalized
      binding.base.sourceOffsets binding.base.resumeOffsets &&
    binding.base.innerSeed.callPush.singletonWriteChecked context
      binding.base.sourceToSuspended.originalNormalized
      binding.base.sourceToSuspended.candidateNormalized

def SingletonAffineReturningImportDirectCallControlBinding.checked
    (binding : SingletonAffineReturningImportDirectCallControlBinding)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Bool :=
  control.checked affine graph &&
    binding.semanticChecked context control affine graph &&
    binding.base.controlStatesChecked control &&
    binding.base.familiesChecked control affine &&
    binding.base.stackChecked sourceInvariant

structure SingletonAffineReturningImportDirectCallControlBinding.CheckedFacts
    (binding : SingletonAffineReturningImportDirectCallControlBinding)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Prop where
  controlChecked : control.checked affine graph = true
  semanticChecked : binding.semanticChecked context control affine graph = true
  controlStatesChecked : binding.base.controlStatesChecked control = true
  familiesChecked : binding.base.familiesChecked control affine = true
  stackChecked : binding.base.stackChecked sourceInvariant = true

theorem SingletonAffineReturningImportDirectCallControlBinding.checkedFacts
    (binding : SingletonAffineReturningImportDirectCallControlBinding)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context sourceInvariant control affine graph = true) :
    binding.CheckedFacts context sourceInvariant control affine graph := by
  simp only [SingletonAffineReturningImportDirectCallControlBinding.checked,
    Bool.and_eq_true] at checked
  exact {
    controlChecked := checked.1.1.1.1
    semanticChecked := checked.1.1.1.2
    controlStatesChecked := checked.1.1.2
    familiesChecked := checked.1.2
    stackChecked := checked.2
  }

def SingletonAffineReturningImportDirectCallExecutionCertificate.checked
    (certificate : SingletonAffineReturningImportDirectCallExecutionCertificate)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Bool :=
  certificate.binding.checked context sourceInvariant control affine graph &&
    match control.states[certificate.binding.base.sourceControlStateIndex]?,
        machineImportCallContractById? context
          certificate.binding.externalSummary.machineContractId with
    | some sourceControl, some contract =>
        match sourceControl.activeShape with
        | some sourceShape =>
            certificate.entryClaim.source == sourceShape.toInventory
                [certificate.binding.base.sourceOffsets] &&
              certificate.entryClaim.target ==
                certificate.binding.base.linkShape.suspendedShape.toInventory
                  [certificate.binding.base.suspendedOffsets] &&
              certificate.entryClaim.checked context sourceInvariant
                certificate.binding.base.sourceToSuspended.originalNormalized
                certificate.binding.base.sourceToSuspended.candidateNormalized &&
              certificate.resumeClaim.source ==
                certificate.binding.base.linkShape.suspendedShape.toInventory
                  [certificate.binding.base.suspendedOffsets] &&
              certificate.resumeClaim.target ==
                certificate.binding.base.linkShape.resumeShape.toInventory
                  [certificate.binding.base.resumeOffsets] &&
              certificate.resumeClaim.checked context sourceInvariant
                certificate.binding.externalSummary.originalNormalized
                certificate.binding.externalSummary.candidateNormalized contract
        | none => false
    | _, _ => false

structure SingletonAffineReturningImportDirectCallExecutionCertificate.CheckedFacts
    (certificate : SingletonAffineReturningImportDirectCallExecutionCertificate)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Type where
  bindingChecked : certificate.binding.checked context sourceInvariant control
    affine graph = true
  sourceShape : ReturnSlotAffineInventoryShape
  sourceControl : AffineLinkedProductControlState
  contract : MachineImportCallContract
  sourceControlFound :
    control.states[certificate.binding.base.sourceControlStateIndex]? =
      some sourceControl
  sourceShapeFound : sourceControl.activeShape = some sourceShape
  contractFound : machineImportCallContractById? context
    certificate.binding.externalSummary.machineContractId = some contract
  entrySource : certificate.entryClaim.source = sourceShape.toInventory
    [certificate.binding.base.sourceOffsets]
  entryTarget : certificate.entryClaim.target =
    certificate.binding.base.linkShape.suspendedShape.toInventory
      [certificate.binding.base.suspendedOffsets]
  entryChecked : certificate.entryClaim.checked context sourceInvariant
    certificate.binding.base.sourceToSuspended.originalNormalized
    certificate.binding.base.sourceToSuspended.candidateNormalized = true
  resumeSource : certificate.resumeClaim.source =
    certificate.binding.base.linkShape.suspendedShape.toInventory
      [certificate.binding.base.suspendedOffsets]
  resumeTarget : certificate.resumeClaim.target =
    certificate.binding.base.linkShape.resumeShape.toInventory
      [certificate.binding.base.resumeOffsets]
  resumeChecked : certificate.resumeClaim.checked context sourceInvariant
    certificate.binding.externalSummary.originalNormalized
    certificate.binding.externalSummary.candidateNormalized contract = true

def SingletonAffineReturningImportDirectCallExecutionCertificate.checkedFacts
    (certificate : SingletonAffineReturningImportDirectCallExecutionCertificate)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : certificate.checked context sourceInvariant control affine graph = true) :
    certificate.CheckedFacts context sourceInvariant control affine graph := by
  simp only [SingletonAffineReturningImportDirectCallExecutionCertificate.checked,
    Bool.and_eq_true] at checked
  rcases checked with ⟨bindingChecked, evidenceChecked⟩
  cases sourceControlFound :
      control.states[certificate.binding.base.sourceControlStateIndex]? with
  | none => simp [sourceControlFound] at evidenceChecked
  | some sourceControl =>
      cases contractFound : machineImportCallContractById? context
          certificate.binding.externalSummary.machineContractId with
      | none => simp [sourceControlFound, contractFound] at evidenceChecked
      | some contract =>
          cases sourceShapeFound : sourceControl.activeShape with
          | none =>
              simp [sourceControlFound, contractFound, sourceShapeFound] at evidenceChecked
          | some sourceShape =>
              simp only [sourceControlFound, contractFound, sourceShapeFound,
                Bool.and_eq_true, beq_iff_eq] at evidenceChecked
              rcases evidenceChecked with
                ⟨⟨⟨⟨⟨entrySource, entryTarget⟩, entryChecked⟩,
                  resumeSource⟩, resumeTarget⟩, resumeChecked⟩
              exact {
                bindingChecked := bindingChecked
                sourceShape := sourceShape
                sourceControl := sourceControl
                contract := contract
                sourceControlFound := sourceControlFound
                sourceShapeFound := sourceShapeFound
                contractFound := contractFound
                entrySource := entrySource
                entryTarget := entryTarget
                entryChecked := entryChecked
                resumeSource := resumeSource
                resumeTarget := resumeTarget
                resumeChecked := resumeChecked
              }

/-- Stable execution-facing projections for a returning imported call.  The
singleton-write fact is deliberately part of the checked binding: richer call
regions must use the general linked-memory transition instead of inheriting a
false no-clobber assumption. -/
theorem SingletonAffineReturningImportDirectCallControlBinding.semantic_facts_of_checked
    (binding : SingletonAffineReturningImportDirectCallControlBinding)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context sourceInvariant control affine graph = true) :
    binding.base.returnSummaries.isEmpty = true ∧
      binding.base.sourceToSuspended.checked context graph = true ∧
      binding.base.innerSeed.checked context graph = true ∧
      binding.base.sourceToSuspended.transition ∈ affine.transitions ∧
      binding.base.innerSeed.seed ∈ affine.seeds ∧
      control.LinkShapeAllowed affine graph binding.base.linkShape = true ∧
      binding.base.sourceToSuspended.physicalStateOnly = false ∧
      binding.base.sourceToSuspended.transition.edgeId =
        binding.base.innerSeed.seed.edgeId ∧
      binding.base.linkShape.callEdgeId = binding.base.innerSeed.seed.edgeId ∧
      binding.base.linkShape.callSourceNodeId =
        binding.base.sourceToSuspended.transition.source.nodeId ∧
      binding.base.linkShape.innerInventoryNodeId =
        binding.base.sourceToSuspended.transition.target.nodeId ∧
      binding.base.linkShape.suspendedInventoryNodeId =
        binding.base.sourceToSuspended.transition.target.nodeId ∧
      binding.base.innerSeed.seed.nodeId =
        binding.base.linkShape.innerInventoryNodeId ∧
      binding.base.innerSeed.callPush.continuationTargetId =
        binding.base.linkShape.resumeTargetId ∧
      binding.base.linkShape.callSourceTargetId =
        binding.base.sourceToSuspended.region.id ∧
      binding.base.sourceToSuspended.region = binding.base.innerSeed.sourceRegion ∧
      binding.base.sourceToSuspended.originalNormalized =
        binding.base.innerSeed.originalNormalized ∧
      binding.base.sourceToSuspended.candidateNormalized =
        binding.base.innerSeed.candidateNormalized ∧
      binding.externalSummary.thunkNodeId =
        binding.base.linkShape.innerInventoryNodeId ∧
      binding.externalSummary.checked context graph binding.base.innerSeed.callPush
        binding.base.sourceToSuspended.originalNormalized
        binding.base.sourceToSuspended.candidateNormalized
        binding.base.sourceOffsets binding.base.resumeOffsets = true ∧
      binding.base.innerSeed.callPush.singletonWriteChecked context
        binding.base.sourceToSuspended.originalNormalized
        binding.base.sourceToSuspended.candidateNormalized = true := by
  have facts := binding.checkedFacts context sourceInvariant control affine graph checked
  have semantic := facts.semanticChecked
  unfold SingletonAffineReturningImportDirectCallControlBinding.semanticChecked at semantic
  simp only [Bool.and_eq_true, beq_iff_eq] at semantic
  rcases semantic with ⟨semantic, singletonWrite⟩
  rcases semantic with ⟨semantic, externalSummary⟩
  rcases semantic with ⟨semantic, thunkNode⟩
  rcases semantic with ⟨semantic, candidateNormalized⟩
  rcases semantic with ⟨semantic, originalNormalized⟩
  rcases semantic with ⟨semantic, sourceRegion⟩
  rcases semantic with ⟨semantic, sourceTarget⟩
  rcases semantic with ⟨semantic, continuation⟩
  rcases semantic with ⟨semantic, seedNode⟩
  rcases semantic with ⟨semantic, suspendedNode⟩
  rcases semantic with ⟨semantic, innerNode⟩
  rcases semantic with ⟨semantic, sourceNode⟩
  rcases semantic with ⟨semantic, linkEdge⟩
  rcases semantic with ⟨semantic, transitionEdge⟩
  rcases semantic with ⟨semantic, ordinary⟩
  rcases semantic with ⟨semantic, linkShapeAllowed⟩
  rcases semantic with ⟨semantic, seedMember⟩
  rcases semantic with ⟨semantic, transitionMember⟩
  rcases semantic with ⟨semantic, seedChecked⟩
  rcases semantic with ⟨returnSummariesEmpty, transitionChecked⟩
  exact ⟨returnSummariesEmpty, transitionChecked, seedChecked,
    List.contains_iff_mem.mp transitionMember,
    List.contains_iff_mem.mp seedMember, linkShapeAllowed, ordinary,
    transitionEdge, linkEdge, sourceNode, innerNode, suspendedNode, seedNode,
    continuation, sourceTarget, sourceRegion, originalNormalized,
    candidateNormalized, thunkNode, externalSummary, singletonWrite⟩

/-- Stable projections consumed by later execution lemmas.  These remain
checked static facts and deliberately omit any authority or refinement field. -/
structure SingletonAffineNestedDirectCallControlBinding.CheckedFacts
    (binding : SingletonAffineNestedDirectCallControlBinding)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Prop where
  controlChecked : control.checked affine graph = true
  semanticChecked : binding.semanticChecked context control affine graph = true
  controlStatesChecked : binding.controlStatesChecked control = true
  familiesChecked : binding.familiesChecked control affine = true
  stackChecked : binding.stackChecked sourceInvariant = true

theorem SingletonAffineNestedDirectCallControlBinding.checkedFacts
    (binding : SingletonAffineNestedDirectCallControlBinding)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context sourceInvariant control affine graph = true) :
    binding.CheckedFacts context sourceInvariant control affine graph := by
  simp only [SingletonAffineNestedDirectCallControlBinding.checked,
    Bool.and_eq_true] at checked
  exact {
    controlChecked := checked.1.1.1.1
    semanticChecked := checked.1.1.1.2
    controlStatesChecked := checked.1.1.2
    familiesChecked := checked.1.2
    stackChecked := checked.2
  }

theorem SingletonAffineNestedDirectCallControlBinding.semantic_facts_of_checked
    (binding : SingletonAffineNestedDirectCallControlBinding)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context sourceInvariant control affine graph = true) :
    binding.sourceToSuspended.checked context graph = true ∧
      binding.innerSeed.checked context graph = true ∧
      binding.sourceToSuspended.transition ∈ affine.transitions ∧
      binding.innerSeed.seed ∈ affine.seeds ∧
      control.LinkShapeAllowed affine graph binding.linkShape = true ∧
      binding.sourceToSuspended.transition.edgeId = binding.innerSeed.seed.edgeId ∧
      binding.linkShape.callEdgeId = binding.innerSeed.seed.edgeId ∧
      binding.innerSeed.callPush.continuationTargetId =
        binding.linkShape.resumeTargetId := by
  have facts := binding.checkedFacts context sourceInvariant control affine graph checked
  have semantic := facts.semanticChecked
  unfold SingletonAffineNestedDirectCallControlBinding.semanticChecked at semantic
  simp only [Bool.and_eq_true, beq_iff_eq] at semantic
  rcases semantic with ⟨semantic, _returnSummariesChecked⟩
  rcases semantic with ⟨semantic, _returnSummariesNonempty⟩
  rcases semantic with ⟨semantic, _returnSummariesNodup⟩
  rcases semantic with ⟨semantic, _candidateNormalized⟩
  rcases semantic with ⟨semantic, _originalNormalized⟩
  rcases semantic with ⟨semantic, _regionExact⟩
  rcases semantic with ⟨semantic, _sourceTargetExact⟩
  rcases semantic with ⟨semantic, continuationExact⟩
  rcases semantic with ⟨semantic, _seedNodeExact⟩
  rcases semantic with ⟨semantic, _suspendedNodeExact⟩
  rcases semantic with ⟨semantic, _innerNodeExact⟩
  rcases semantic with ⟨semantic, _sourceNodeExact⟩
  rcases semantic with ⟨semantic, linkEdgeExact⟩
  rcases semantic with ⟨semantic, transitionEdgeExact⟩
  rcases semantic with ⟨semantic, _ordinary⟩
  rcases semantic with ⟨semantic, linkShapeAllowed⟩
  rcases semantic with ⟨semantic, seedMember⟩
  rcases semantic with ⟨semantic, transitionMember⟩
  rcases semantic with ⟨transitionChecked, seedChecked⟩
  exact ⟨transitionChecked, seedChecked,
    List.contains_iff_mem.mp transitionMember,
    List.contains_iff_mem.mp seedMember, linkShapeAllowed,
    transitionEdgeExact, linkEdgeExact, continuationExact⟩

theorem SingletonAffineNestedDirectCallControlBinding.return_summary_checked_of_checked
    (binding : SingletonAffineNestedDirectCallControlBinding)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (summary : SingletonAffineNestedDirectCallReturnSummary)
    (checked : binding.checked context sourceInvariant control affine graph = true)
    (member : summary ∈ binding.returnSummaries) :
    summary.checked context graph binding.innerSeed.callPush
      binding.sourceToSuspended.originalNormalized
      binding.sourceToSuspended.candidateNormalized
      binding.sourceOffsets binding.resumeOffsets = true := by
  have facts := binding.checkedFacts context sourceInvariant control affine graph checked
  have semantic := facts.semanticChecked
  unfold SingletonAffineNestedDirectCallControlBinding.semanticChecked at semantic
  simp only [Bool.and_eq_true] at semantic
  exact List.all_eq_true.mp semantic.2 summary member

theorem SingletonAffineNestedDirectCallControlBinding.control_states_of_checked
    (binding : SingletonAffineNestedDirectCallControlBinding)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context sourceInvariant control affine graph = true) :
    ∃ source inner resume,
      control.states[binding.sourceControlStateIndex]? = some source ∧
      control.states[binding.innerControlStateIndex]? = some inner ∧
      control.states[binding.resumeControlStateIndex]? = some resume ∧
      source.nodeId = binding.linkShape.callSourceNodeId ∧
      source.continuation = some binding.linkShape.resumeContinuation ∧
      inner.nodeId = binding.linkShape.innerInventoryNodeId ∧
      inner.continuation = some binding.linkShape.resumeTargetId ∧
      inner.activeShape = some binding.linkShape.innerShape ∧
      resume.nodeId = binding.linkShape.resumeInventoryNodeId ∧
      resume.continuation = some binding.linkShape.resumeContinuation ∧
      resume.activeShape = some binding.linkShape.resumeShape ∧
      inner.minimumDepth ≤ source.minimumDepth + 1 ∧
      resume.minimumDepth ≤ source.minimumDepth := by
  have facts := binding.checkedFacts context sourceInvariant control affine graph checked
  have statesChecked := facts.controlStatesChecked
  unfold SingletonAffineNestedDirectCallControlBinding.controlStatesChecked at statesChecked
  cases sourceFound : control.states[binding.sourceControlStateIndex]? with
  | none => simp [sourceFound] at statesChecked
  | some source =>
      cases innerFound : control.states[binding.innerControlStateIndex]? with
      | none => simp [sourceFound, innerFound] at statesChecked
      | some inner =>
          cases resumeFound : control.states[binding.resumeControlStateIndex]? with
          | none =>
              simp [sourceFound, innerFound, resumeFound] at statesChecked
          | some resume =>
              simp only [sourceFound, innerFound, resumeFound, Bool.and_eq_true,
                beq_iff_eq, decide_eq_true_eq] at statesChecked
              rcases statesChecked with ⟨statesChecked, resumeDepth⟩
              rcases statesChecked with ⟨statesChecked, innerDepth⟩
              rcases statesChecked with ⟨statesChecked, _sourceDepth⟩
              rcases statesChecked with ⟨statesChecked, resumeShape⟩
              rcases statesChecked with ⟨statesChecked, resumeContinuation⟩
              rcases statesChecked with ⟨statesChecked, resumeNode⟩
              rcases statesChecked with ⟨statesChecked, innerShape⟩
              rcases statesChecked with ⟨statesChecked, innerContinuation⟩
              rcases statesChecked with ⟨statesChecked, innerNode⟩
              rcases statesChecked with ⟨sourceNode, sourceContinuation⟩
              exact ⟨source, inner, resume, rfl, rfl, rfl,
                sourceNode, sourceContinuation, innerNode, innerContinuation,
                innerShape, resumeNode, resumeContinuation, resumeShape,
                innerDepth, resumeDepth⟩

theorem SingletonAffineNestedDirectCallControlBinding.family_facts_of_checked
    (binding : SingletonAffineNestedDirectCallControlBinding)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context sourceInvariant control affine graph = true) :
    binding.sourceToSuspended.transition.source.family.SingletonAt
        binding.sourceOffsets ∧
      binding.sourceToSuspended.transition.target.family.SingletonAt
        binding.suspendedOffsets ∧
      (∃ state : ReturnSlotAffineFrameState,
        state.nodeId = binding.linkShape.innerInventoryNodeId ∧
          state.family.SingletonAt binding.innerOffsets) ∧
      (∃ state : ReturnSlotAffineFrameState,
        state.nodeId = binding.linkShape.resumeInventoryNodeId ∧
          state.family.SingletonAt binding.resumeOffsets) ∧
      binding.innerSeed.seed.offsets = binding.innerOffsets := by
  have facts := binding.checkedFacts context sourceInvariant control affine graph checked
  have familiesChecked := facts.familiesChecked
  unfold SingletonAffineNestedDirectCallControlBinding.familiesChecked at familiesChecked
  cases sourceFound : control.states[binding.sourceControlStateIndex]? with
  | none => simp [sourceFound] at familiesChecked
  | some source =>
      cases sourceShapeFound : source.activeShape with
      | none => simp [sourceFound, sourceShapeFound] at familiesChecked
      | some sourceShape =>
          simp only [sourceFound, sourceShapeFound, Bool.and_eq_true, beq_iff_eq]
            at familiesChecked
          rcases familiesChecked with ⟨familiesChecked, _relationsExact⟩
          rcases familiesChecked with ⟨familiesChecked, _importsExact⟩
          rcases familiesChecked with ⟨familiesChecked, _wordsExact⟩
          rcases familiesChecked with ⟨familiesChecked, seedOffsetsExact⟩
          rcases familiesChecked with ⟨familiesChecked, resumeSingletonChecked⟩
          rcases familiesChecked with ⟨familiesChecked, innerSingletonChecked⟩
          rcases familiesChecked with
            ⟨sourceSingletonChecked, suspendedSingletonChecked⟩
          have sourceSingleton := sourceShape.singletonState_facts_of_checked affine
            binding.sourceToSuspended.transition.source binding.sourceOffsets
            sourceSingletonChecked
          have suspendedSingleton :=
            binding.linkShape.suspendedShape.singletonState_facts_of_checked affine
              binding.sourceToSuspended.transition.target binding.suspendedOffsets
              suspendedSingletonChecked
          have innerSingleton :=
            binding.linkShape.innerShape.singletonAtNode_facts_of_checked affine
              binding.linkShape.innerInventoryNodeId binding.innerOffsets
              innerSingletonChecked
          have resumeSingleton :=
            binding.linkShape.resumeShape.singletonAtNode_facts_of_checked affine
              binding.linkShape.resumeInventoryNodeId binding.resumeOffsets
              resumeSingletonChecked
          rcases innerSingleton with
            ⟨_innerIndex, innerState, _innerLocations, _innerFound, innerNode,
              _innerShapeChecked, innerFamily⟩
          rcases resumeSingleton with
            ⟨_resumeIndex, resumeState, _resumeLocations, _resumeFound, resumeNode,
              _resumeShapeChecked, resumeFamily⟩
          exact ⟨sourceSingleton.2.choose_spec.2.2,
            suspendedSingleton.2.choose_spec.2.2,
            ⟨innerState, innerNode, innerFamily⟩,
            ⟨resumeState, resumeNode, resumeFamily⟩, seedOffsetsExact⟩

theorem SingletonAffineNestedDirectCallControlBinding.stack_facts_of_checked
    (binding : SingletonAffineNestedDirectCallControlBinding)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context sourceInvariant control affine graph = true) :
    binding.sourceWindow ∈ sourceInvariant.stackWindows ∧
      binding.stackAmount.checked binding.sourceWindow binding.innerSeed.callPush = true ∧
      binding.sourceOffsets.originalOffset.toNat + binding.stackAmount.original =
        binding.suspendedOffsets.originalOffset.toNat ∧
      binding.sourceOffsets.candidateOffset.toNat + binding.stackAmount.candidate =
        binding.suspendedOffsets.candidateOffset.toNat ∧
      binding.innerOffsets.originalOffset.toNat + binding.linkShape.originalGap =
        binding.suspendedOffsets.originalOffset.toNat ∧
      binding.innerOffsets.candidateOffset.toNat + binding.linkShape.candidateGap =
        binding.suspendedOffsets.candidateOffset.toNat := by
  have facts := binding.checkedFacts context sourceInvariant control affine graph checked
  have stackChecked := facts.stackChecked
  unfold SingletonAffineNestedDirectCallControlBinding.stackChecked at stackChecked
  simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at stackChecked
  rcases stackChecked with ⟨stackChecked, candidateGap⟩
  rcases stackChecked with ⟨stackChecked, originalGap⟩
  rcases stackChecked with ⟨stackChecked, candidateSuspended⟩
  rcases stackChecked with ⟨stackChecked, originalSuspended⟩
  rcases stackChecked with ⟨stackChecked, _candidateSourceFits⟩
  rcases stackChecked with ⟨stackChecked, _originalSourceFits⟩
  rcases stackChecked with ⟨stackChecked, _resumeCandidateEsp⟩
  rcases stackChecked with ⟨stackChecked, _resumeOriginalEsp⟩
  rcases stackChecked with ⟨stackChecked, _innerCandidateEsp⟩
  rcases stackChecked with ⟨stackChecked, _innerOriginalEsp⟩
  rcases stackChecked with ⟨stackChecked, _suspendedCandidateEsp⟩
  rcases stackChecked with ⟨stackChecked, _suspendedOriginalEsp⟩
  rcases stackChecked with ⟨stackChecked, _sourceCandidateEsp⟩
  rcases stackChecked with ⟨stackChecked, _sourceOriginalEsp⟩
  rcases stackChecked with ⟨windowMember, stackAmountChecked⟩
  exact ⟨List.contains_iff_mem.mp windowMember, stackAmountChecked,
    originalSuspended, candidateSuspended, originalGap, candidateGap⟩

theorem SingletonAffineNestedDirectCallControlBinding.offset_registers_esp_of_checked
    (binding : SingletonAffineNestedDirectCallControlBinding)
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context sourceInvariant control affine graph = true) :
    binding.sourceOffsets.originalRegister = .esp ∧
      binding.sourceOffsets.candidateRegister = .esp ∧
      binding.suspendedOffsets.originalRegister = .esp ∧
      binding.suspendedOffsets.candidateRegister = .esp ∧
      binding.innerOffsets.originalRegister = .esp ∧
      binding.innerOffsets.candidateRegister = .esp ∧
      binding.resumeOffsets.originalRegister = .esp ∧
      binding.resumeOffsets.candidateRegister = .esp := by
  have facts := binding.checkedFacts context sourceInvariant control affine graph checked
  have stackChecked := facts.stackChecked
  unfold SingletonAffineNestedDirectCallControlBinding.stackChecked at stackChecked
  simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at stackChecked
  rcases stackChecked with ⟨stackChecked, _candidateGap⟩
  rcases stackChecked with ⟨stackChecked, _originalGap⟩
  rcases stackChecked with ⟨stackChecked, _candidateSuspended⟩
  rcases stackChecked with ⟨stackChecked, _originalSuspended⟩
  rcases stackChecked with ⟨stackChecked, _candidateSourceFits⟩
  rcases stackChecked with ⟨stackChecked, _originalSourceFits⟩
  rcases stackChecked with ⟨stackChecked, resumeCandidateEsp⟩
  rcases stackChecked with ⟨stackChecked, resumeOriginalEsp⟩
  rcases stackChecked with ⟨stackChecked, innerCandidateEsp⟩
  rcases stackChecked with ⟨stackChecked, innerOriginalEsp⟩
  rcases stackChecked with ⟨stackChecked, suspendedCandidateEsp⟩
  rcases stackChecked with ⟨stackChecked, suspendedOriginalEsp⟩
  rcases stackChecked with ⟨stackChecked, sourceCandidateEsp⟩
  rcases stackChecked with ⟨_windowAndAmount, sourceOriginalEsp⟩
  exact ⟨sourceOriginalEsp, sourceCandidateEsp, suspendedOriginalEsp,
    suspendedCandidateEsp, innerOriginalEsp, innerCandidateEsp,
    resumeOriginalEsp, resumeCandidateEsp⟩

end StageA.Relational
