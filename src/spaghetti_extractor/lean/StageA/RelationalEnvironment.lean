import StageA.RelationalComposition

namespace StageA.Relational

open StageA.Formal

structure WorldExternalEvent where
  siteId : Nat
  imported : ExternalTarget
  arguments : List Word
  state : MachineState
  world : RelationalWorld

structure WorldExternalResult where
  state : MachineState
  world : RelationalWorld

structure WorldExternalEnvironment where
  result : Nat -> WorldExternalEvent -> WorldExternalResult

def normalizeImportReturnSlotState (state : MachineState) : MachineState := {
  state with
  registers := state.registers.set .esp
    (state.registers.esp + BitVec.ofNat 32 4)
}

def ReturnSlotOffsetPair.afterImportReturnSlot
    (source : ReturnSlotOffsetPair) : ReturnSlotOffsetPair := {
  originalRegister := source.originalRegister
  originalOffset := source.originalOffset -
    (if source.originalRegister == .esp then BitVec.ofNat 32 4 else BitVec.ofNat 32 0)
  candidateRegister := source.candidateRegister
  candidateOffset := source.candidateOffset -
    (if source.candidateRegister == .esp then BitVec.ofNat 32 4 else BitVec.ofNat 32 0)
}

theorem ReturnSlotOffsetPair.afterImportReturnSlot_holds
    (source : ReturnSlotOffsetPair) (frame : RelationalRuntimeCallFrame)
    (original candidate : MachineState)
    (sourceHolds : source.holds frame original.registers candidate.registers) :
    source.afterImportReturnSlot.holds frame
      (normalizeImportReturnSlotState original).registers
      (normalizeImportReturnSlotState candidate).registers := by
  rcases source with ⟨originalRegister, originalOffset, candidateRegister,
    candidateOffset⟩
  rcases sourceHolds with ⟨originalHolds, candidateHolds⟩
  constructor
  · cases originalRegister <;>
      simp_all [ReturnSlotOffsetPair.afterImportReturnSlot,
        normalizeImportReturnSlotState, ReturnSlotOffsetPair.holds,
        StageA.Formal.Registers.get, StageA.Formal.Registers.set,
        word_add_delta_sub]
  · cases candidateRegister <;>
      simp_all [ReturnSlotOffsetPair.afterImportReturnSlot,
        normalizeImportReturnSlotState, ReturnSlotOffsetPair.holds,
        StageA.Formal.Registers.get, StageA.Formal.Registers.set,
        word_add_delta_sub]

structure ExternalCallSiteContract where
  id : Nat
  sourceTargetId : Nat
  continuationTargetId : Nat
  machineContractId : Nat
  boundaryInvariant : StateInvariant
  targetInvariant : StateInvariant
deriving Repr, DecidableEq

def machineImportCallContractById? (context : StaticProofContext)
    (id : Nat) : Option MachineImportCallContract :=
  context.machineImportCallContracts.find? (fun contract => contract.id == id)

def ExternalCallSiteContract.staticValid (context : StaticProofContext)
    (site : ExternalCallSiteContract) : Bool :=
  (context.codeMap.get? site.sourceTargetId).isSome &&
    (context.codeMap.get? site.continuationTargetId).isSome &&
    (machineImportCallContractById? context site.machineContractId).isSome

def externalCallSiteIdsUnique (sites : List ExternalCallSiteContract) : Bool :=
  sites.all fun site =>
    (sites.filter (fun other => other.id == site.id)).length == 1

def machineCallPreservedRegistersHold (contract : MachineImportCallContract)
    (before after : MachineState) : Bool :=
  contract.preservedRegisters.all fun register =>
    after.registers.get register == before.registers.get register

def machineCallStackResultHolds (contract : MachineImportCallContract)
    (before after : MachineState) : Bool :=
  after.registers.esp ==
    before.registers.esp + BitVec.ofNat 32 contract.stackResultDelta

def machineCallAbiResultHolds (contract : MachineImportCallContract)
    (before after : MachineState) : Bool :=
  machineCallStackResultHolds contract before after &&
    machineCallPreservedRegistersHold contract before after

def machineCallRegisterDelta? (contract : MachineImportCallContract)
    (register : Reg) : Option Nat :=
  if register == .esp then
    some contract.stackResultDelta
  else if contract.preservedRegisters.contains register then
    some 0
  else
    none

theorem machineCallRegisterDeltaHolds_of_abi
    (contract : MachineImportCallContract) (before after : MachineState)
    (register : Reg) (delta : Nat)
    (deltaKnown : machineCallRegisterDelta? contract register = some delta)
    (abi : machineCallAbiResultHolds contract before after = true) :
    after.registers.get register =
      before.registers.get register + BitVec.ofNat 32 delta := by
  simp only [machineCallAbiResultHolds, Bool.and_eq_true] at abi
  unfold machineCallRegisterDelta? at deltaKnown
  split at deltaKnown
  next stackRegister =>
    simp only [beq_iff_eq] at stackRegister
    subst register
    cases deltaKnown
    simpa [machineCallStackResultHolds] using abi.1
  next notStackRegister =>
    split at deltaKnown
    next preservedRegister =>
      cases deltaKnown
      simp only [machineCallPreservedRegistersHold, List.all_eq_true,
        beq_iff_eq] at abi
      have preserved := abi.2 register
        (List.contains_iff_mem.mp preservedRegister)
      simpa using preserved
    next clobberedRegister => simp at deltaKnown

structure ExternalReturnSlotResultRule where
  source : ReturnSlotOffsetPair
  target : ReturnSlotOffsetPair
  originalDelta : Nat
  candidateDelta : Nat
deriving Repr, DecidableEq

def externalReturnSlotResultSideChecked
    (contract : MachineImportCallContract)
    (sourceRegister targetRegister : Reg)
    (sourceOffset targetOffset : Word) (delta : Nat) : Bool :=
  sourceRegister == targetRegister &&
    machineCallRegisterDelta? contract sourceRegister == some delta &&
    targetOffset == sourceOffset - BitVec.ofNat 32 delta

def ExternalReturnSlotResultRule.checked
    (contract : MachineImportCallContract)
    (rule : ExternalReturnSlotResultRule) : Bool :=
  externalReturnSlotResultSideChecked contract
      rule.source.originalRegister rule.target.originalRegister
      rule.source.originalOffset rule.target.originalOffset rule.originalDelta &&
    externalReturnSlotResultSideChecked contract
      rule.source.candidateRegister rule.target.candidateRegister
      rule.source.candidateOffset rule.target.candidateOffset rule.candidateDelta

theorem externalReturnSlotResultSideHolds_of_checked
    (contract : MachineImportCallContract) (before after : MachineState)
    (sourceRegister targetRegister : Reg)
    (sourceOffset targetOffset : Word) (delta : Nat)
    (checked : externalReturnSlotResultSideChecked contract sourceRegister
      targetRegister sourceOffset targetOffset delta = true)
    (abi : machineCallAbiResultHolds contract before after = true)
    (sourceAddress : before.registers.get sourceRegister + sourceOffset = frameAddress) :
    after.registers.get targetRegister + targetOffset = frameAddress := by
  simp only [externalReturnSlotResultSideChecked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with ⟨⟨registersMatch, deltaKnown⟩, offsetMatch⟩
  rw [← registersMatch, machineCallRegisterDeltaHolds_of_abi contract before after
    sourceRegister delta deltaKnown abi, offsetMatch]
  exact (word_add_delta_sub _ _ _).trans sourceAddress

theorem externalReturnSlotResultRuleHolds_of_checked
    (contract : MachineImportCallContract) (beforeOriginal beforeCandidate
      afterOriginal afterCandidate : MachineState)
    (rule : ExternalReturnSlotResultRule) (frame : RelationalRuntimeCallFrame)
    (checked : rule.checked contract = true)
    (originalAbi : machineCallAbiResultHolds contract beforeOriginal
      afterOriginal = true)
    (candidateAbi : machineCallAbiResultHolds contract beforeCandidate
      afterCandidate = true)
    (sourceHolds : rule.source.holds frame beforeOriginal.registers
      beforeCandidate.registers) :
    rule.target.holds frame afterOriginal.registers afterCandidate.registers := by
  simp only [ExternalReturnSlotResultRule.checked, Bool.and_eq_true] at checked
  rcases sourceHolds with ⟨originalSource, candidateSource⟩
  exact ⟨externalReturnSlotResultSideHolds_of_checked contract
      beforeOriginal afterOriginal rule.source.originalRegister
      rule.target.originalRegister rule.source.originalOffset
      rule.target.originalOffset rule.originalDelta checked.1 originalAbi
      originalSource,
    externalReturnSlotResultSideHolds_of_checked contract beforeCandidate
      afterCandidate rule.source.candidateRegister rule.target.candidateRegister
      rule.source.candidateOffset rule.target.candidateOffset rule.candidateDelta
      checked.2 candidateAbi candidateSource⟩

structure ExternalReturnSlotTransferClaim where
  source : ReturnSlotOffsetPair
  internalTarget : ReturnSlotOffsetPair
  internalRule : ReturnSlotTransferRule
  resultRule : ExternalReturnSlotResultRule
  memory : ReturnSlotMemoryTransferClaim
deriving Repr, DecidableEq

def ExternalReturnSlotTransferClaim.checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (contract : MachineImportCallContract)
    (claim : ExternalReturnSlotTransferClaim) : Bool :=
  claim.internalRule.checked originalBehavior candidateBehavior &&
    claim.internalRule.apply claim.source == some claim.internalTarget &&
    claim.memory.offsets == claim.source &&
    claim.memory.checked originalBehavior candidateBehavior &&
    claim.resultRule.source == claim.internalTarget &&
    claim.resultRule.checked contract

theorem externalReturnSlotTransferHolds_of_checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (contract : MachineImportCallContract)
    (claim : ExternalReturnSlotTransferClaim)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (originalResult candidateResult : MachineState)
    (checked : claim.checked originalBehavior candidateBehavior contract = true)
    (sourceOffsets : claim.source.holds frame originalState.registers
      candidateState.registers)
    (sourceMemory : frame.memoryHolds originalState.memory candidateState.memory)
    (originalAbi : machineCallAbiResultHolds contract
      ((originalBehavior.eval originalState).nextMachineState originalState)
      originalResult = true)
    (candidateAbi : machineCallAbiResultHolds contract
      ((candidateBehavior.eval candidateState).nextMachineState candidateState)
      candidateResult = true)
    (framesPreserved : frame.memoryHolds
        ((originalBehavior.eval originalState).nextMachineState originalState).memory
        ((candidateBehavior.eval candidateState).nextMachineState candidateState).memory →
      frame.memoryHolds originalResult.memory candidateResult.memory) :
    claim.resultRule.target.holds frame originalResult.registers
        candidateResult.registers ∧
      frame.memoryHolds originalResult.memory candidateResult.memory := by
  simp only [ExternalReturnSlotTransferClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨internalRuleChecked, internalApplied⟩, memorySource⟩,
      memoryChecked⟩, resultSource⟩, resultChecked⟩
  have internalOffsets := returnSlotTransferRuleHolds_of_checked
    originalBehavior candidateBehavior claim.internalRule claim.source
    claim.internalTarget frame originalState candidateState internalRuleChecked
    internalApplied sourceOffsets
  have internalMemory := returnSlotMemoryTransferHolds_of_checked
    originalBehavior candidateBehavior claim.memory frame originalState candidateState
    memoryChecked (by simpa [memorySource] using sourceOffsets) sourceMemory
  have resultOffsets := externalReturnSlotResultRuleHolds_of_checked contract
    ((originalBehavior.eval originalState).nextMachineState originalState)
    ((candidateBehavior.eval candidateState).nextMachineState candidateState)
    originalResult candidateResult claim.resultRule frame resultChecked originalAbi
    candidateAbi (by
      rw [resultSource]
      simpa [RelationalBehavior.nextMachineState] using internalOffsets)
  refine ⟨resultOffsets, framesPreserved ?_⟩
  simpa [RelationalBehavior.nextMachineState] using internalMemory

structure ExternalJumpReturnSlotTransferClaim where
  source : ReturnSlotOffsetPair
  internalTarget : ReturnSlotOffsetPair
  boundaryTarget : ReturnSlotOffsetPair
  internalRule : ReturnSlotTransferRule
  resultRule : ExternalReturnSlotResultRule
  memory : ReturnSlotMemoryTransferClaim
deriving Repr, DecidableEq

def ExternalJumpReturnSlotTransferClaim.checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (contract : MachineImportCallContract)
    (claim : ExternalJumpReturnSlotTransferClaim) : Bool :=
  claim.internalRule.checked originalBehavior candidateBehavior &&
    claim.internalRule.apply claim.source == some claim.internalTarget &&
    claim.boundaryTarget == claim.internalTarget.afterImportReturnSlot &&
    claim.memory.offsets == claim.source &&
    claim.memory.checked originalBehavior candidateBehavior &&
    claim.resultRule.source == claim.boundaryTarget &&
    claim.resultRule.checked contract

theorem externalJumpReturnSlotTransferHolds_of_checked
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (contract : MachineImportCallContract)
    (claim : ExternalJumpReturnSlotTransferClaim)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (originalResult candidateResult : MachineState)
    (checked : claim.checked originalBehavior candidateBehavior contract = true)
    (sourceOffsets : claim.source.holds frame originalState.registers
      candidateState.registers)
    (sourceMemory : frame.memoryHolds originalState.memory candidateState.memory)
    (originalAbi : machineCallAbiResultHolds contract
      (normalizeImportReturnSlotState
        ((originalBehavior.eval originalState).nextMachineState originalState))
      originalResult = true)
    (candidateAbi : machineCallAbiResultHolds contract
      (normalizeImportReturnSlotState
        ((candidateBehavior.eval candidateState).nextMachineState candidateState))
      candidateResult = true)
    (framesPreserved : frame.memoryHolds
        (normalizeImportReturnSlotState
          ((originalBehavior.eval originalState).nextMachineState originalState)).memory
        (normalizeImportReturnSlotState
          ((candidateBehavior.eval candidateState).nextMachineState candidateState)).memory →
      frame.memoryHolds originalResult.memory candidateResult.memory) :
    claim.resultRule.target.holds frame originalResult.registers
        candidateResult.registers ∧
      frame.memoryHolds originalResult.memory candidateResult.memory := by
  simp only [ExternalJumpReturnSlotTransferClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨internalRuleChecked, internalApplied⟩, boundaryTarget⟩,
      memorySource⟩, memoryChecked⟩, resultSource⟩, resultChecked⟩
  have internalOffsets := returnSlotTransferRuleHolds_of_checked
    originalBehavior candidateBehavior claim.internalRule claim.source
    claim.internalTarget frame originalState candidateState internalRuleChecked
    internalApplied sourceOffsets
  have boundaryOffsets := claim.internalTarget.afterImportReturnSlot_holds frame
    ((originalBehavior.eval originalState).nextMachineState originalState)
    ((candidateBehavior.eval candidateState).nextMachineState candidateState)
    (by simpa [RelationalBehavior.nextMachineState] using internalOffsets)
  have internalMemory := returnSlotMemoryTransferHolds_of_checked
    originalBehavior candidateBehavior claim.memory frame originalState candidateState
    memoryChecked (by simpa [memorySource] using sourceOffsets) sourceMemory
  have resultOffsets := externalReturnSlotResultRuleHolds_of_checked contract
    (normalizeImportReturnSlotState
      ((originalBehavior.eval originalState).nextMachineState originalState))
    (normalizeImportReturnSlotState
      ((candidateBehavior.eval candidateState).nextMachineState candidateState))
    originalResult candidateResult claim.resultRule frame resultChecked originalAbi
    candidateAbi (by
      rw [resultSource, boundaryTarget]
      exact boundaryOffsets)
  refine ⟨resultOffsets, framesPreserved ?_⟩
  simpa [normalizeImportReturnSlotState, RelationalBehavior.nextMachineState]
    using internalMemory

def MachineCallMemorySize.bytes? (arguments : List Word) :
    MachineCallMemorySize -> Option Nat
  | .fixed bytes => some bytes
  | .argument index scale =>
      match arguments[index]? with
      | none => none
      | some value =>
          let bytes := value.toNat * scale
          if bytes < 2^32 then some bytes else none

def MachineCallMemoryFootprint.range? (arguments : List Word)
    (footprint : MachineCallMemoryFootprint) : Option (Nat × Nat) :=
  match arguments[footprint.baseArgument]?,
      footprint.size.bytes? arguments with
  | some base, some size =>
      if base == BitVec.ofNat 32 0 && footprint.nullable then
        some (0, 0)
      else
        let start := base.toNat + footprint.offset
        if (size == 0 || base != BitVec.ofNat 32 0) && start + size <= 2^32 then
          some (start, start + size)
        else none
  | _, _ => none

def MachineCallMemoryFootprint.contains (arguments : List Word)
    (footprint : MachineCallMemoryFootprint) (address : Word) : Bool :=
  match footprint.range? arguments with
  | none => false
  | some range => range.1 <= address.toNat && address.toNat < range.2

def machineCallMemoryFootprintsRuntimeValid (contract : MachineImportCallContract)
    (arguments : List Word) : Bool :=
  contract.memoryFootprints.all fun footprint =>
    (footprint.range? arguments).isSome

def machineCallMemoryEffectHolds (contract : MachineImportCallContract)
    (arguments : List Word) (before after : Memory) : Prop :=
  match contract.memoryEffect with
  | .none | .readOnly => before = after
  | .argumentRanges =>
      machineCallMemoryFootprintsRuntimeValid contract arguments = true ∧
        ∀ address,
          (contract.memoryFootprints.any fun footprint =>
            footprint.access == .write && footprint.contains arguments address) = false →
          after address = before address

def opaqueResourcesExtend (before after : RelationalWorld) : Prop :=
  forall resource, resource ∈ before.opaqueResources ->
    resource ∈ after.opaqueResources

def dynamicRangesExtend (before after : RelationalWorld) : Prop :=
  forall range, range ∈ before.dynamicRanges -> range ∈ after.dynamicRanges

def dynamicRangeReleaseHolds (candidate : Bool) (argumentIndex : Nat)
    (arguments : List Word) (before after : RelationalWorld) : Prop :=
  match arguments[argumentIndex]? with
  | none => False
  | some argument =>
      if argument == BitVec.ofNat 32 0 then
        after = before
      else
        ∃ range, range ∈ before.dynamicRanges ∧
          range.sideBase candidate = argument ∧
          after.dynamicRanges = before.dynamicRanges.erase range ∧
          after.stackRanges = before.stackRanges ∧
          after.opaqueResources = before.opaqueResources ∧
          after.importAddresses = before.importAddresses ∧
          after.registeredCallbacks = before.registeredCallbacks ∧
          after.tlsState = before.tlsState

def callbackRegistrationHolds (candidate : Bool) (context : StaticProofContext)
    (argumentIndex : Nat) (arguments : List Word)
    (before after : RelationalWorld) : Prop :=
  match arguments[argumentIndex]? with
  | none => False
  | some argument =>
      ∃ callback,
        after.registeredCallbacks = callback :: before.registeredCallbacks ∧
          (if candidate then callback.candidateAddress else callback.originalAddress) =
            argument ∧
          callback.valid context = true ∧
          after.dynamicRanges = before.dynamicRanges ∧
          after.stackRanges = before.stackRanges ∧
          after.opaqueResources = before.opaqueResources ∧
          after.importAddresses = before.importAddresses ∧
          after.tlsState = before.tlsState

def machineCallWorldEffectHolds (candidate : Bool)
    (context : StaticProofContext) (effect : MachineCallWorldEffect)
    (arguments : List Word) (before after : RelationalWorld) : Prop :=
  after.valid context = true ∧ match effect with
  | .none => after = before
  | .opaqueResources =>
      after.dynamicRanges = before.dynamicRanges ∧
        after.stackRanges = before.stackRanges ∧
        after.importAddresses = before.importAddresses ∧
        after.registeredCallbacks = before.registeredCallbacks ∧
        after.tlsState = before.tlsState ∧
        opaqueResourcesExtend before after
  | .dynamicRanges =>
      after.stackRanges = before.stackRanges ∧
        after.opaqueResources = before.opaqueResources ∧
        after.importAddresses = before.importAddresses ∧
        after.registeredCallbacks = before.registeredCallbacks ∧
        after.tlsState = before.tlsState ∧
        dynamicRangesExtend before after
  | .dynamicRangeRelease argumentIndex =>
      dynamicRangeReleaseHolds candidate argumentIndex arguments before after
  | .callbackRegistration argumentIndex =>
      callbackRegistrationHolds candidate context argumentIndex arguments before after
  | .tlsState =>
      after.dynamicRanges = before.dynamicRanges ∧
        after.stackRanges = before.stackRanges ∧
        after.opaqueResources = before.opaqueResources ∧
        after.importAddresses = before.importAddresses ∧
        after.registeredCallbacks = before.registeredCallbacks

def machineCallResultConforms (candidate : Bool) (context : StaticProofContext)
    (contract : MachineImportCallContract) (event : WorldExternalEvent)
    (result : WorldExternalResult) : Prop :=
  contract.disposition = .returns ∧
    machineCallAbiResultHolds contract event.state result.state = true ∧
    machineCallMemoryEffectHolds contract event.arguments
      event.state.memory result.state.memory ∧
    machineCallWorldEffectHolds candidate context contract.worldEffect
      event.arguments event.world result.world

def externalCallArgumentsRelated (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : List Word) : Bool :=
  wordsRelated context.originalPe.imageBase context.candidatePe.imageBase
    context.codeMap.entries.toList (context.relationalValueTargets world)
    original candidate

theorem wordsRelated_cons_of_true
    {originalImageBase candidateImageBase : Nat}
    {targets : List CodeTargetPair} {values : List ValueTargetPair}
    {originalHead candidateHead : Word} {originalTail candidateTail : List Word}
    (headRelated : wordRelated originalImageBase candidateImageBase targets values
      originalHead candidateHead = true)
    (tailRelated : wordsRelated originalImageBase candidateImageBase targets values
      originalTail candidateTail = true) :
    wordsRelated originalImageBase candidateImageBase targets values
      (originalHead :: originalTail) (candidateHead :: candidateTail) = true := by
  simp [wordsRelated, headRelated, tailRelated]

def ExternalBoundaryStateRel (context : StaticProofContext)
    (world : RelationalWorld) (invariant : StateInvariant)
    (original candidate : MachineState) : Prop :=
  world.valid context = true ∧
    world.stackRangesValid context = true ∧
    registerRelationsHold context.originalPe.imageBase
      context.candidatePe.imageBase context.codeMap.entries.toList
      (context.relationalValueTargets world) invariant.registerRelations
      original.registers candidate.registers = true ∧
    boundsRelated invariant.bounds original.registers candidate.registers = true ∧
    addressSeparationsRelated invariant.addressSeparations
      original.registers candidate.registers = true ∧
    stackWindowsRelated world invariant.stackWindows
      original.registers candidate.registers = true ∧
    original.undefinedValue = candidate.undefinedValue ∧
    original.x87 = candidate.x87 ∧
    flagsRelated invariant.flagBits original.eflags candidate.eflags = true ∧
    original.fsBase = candidate.fsBase ∧
    importRegisterRelationsHold world invariant.importRegisterRelations
      original.registers candidate.registers = true ∧
    dynamicRegisterRangeRelationsHold world
      invariant.dynamicRegisterRangeRelations original.registers
      candidate.registers = true

def ExternalCallBoundaryRelated (context : StaticProofContext)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (original candidate : WorldExternalEvent) : Prop :=
  original.siteId = site.id ∧ candidate.siteId = site.id ∧
    original.world = candidate.world ∧
    original.imported = contract.imported ∧
    candidate.imported = contract.imported ∧
    ExternalBoundaryStateRel context original.world site.boundaryInvariant
      original.state candidate.state ∧
    externalCallArgumentsRelated context original.world
      original.arguments candidate.arguments = true

def ExternalRuntimeFramesPreserved
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult) : Prop :=
  ∀ frame : RelationalRuntimeCallFrame,
    frame.memoryHolds originalEvent.state.memory candidateEvent.state.memory →
      frame.memoryHolds originalResult.state.memory candidateResult.state.memory

def ExternalEnvironmentRefinesAt (context : StaticProofContext)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (original candidate : WorldExternalEnvironment) : Prop :=
  match contract.disposition with
  | .returns =>
      forall eventIndex originalEvent candidateEvent,
        ExternalCallBoundaryRelated context site contract originalEvent candidateEvent ->
        let originalResult := original.result eventIndex originalEvent
        let candidateResult := candidate.result eventIndex candidateEvent
        originalResult.world = candidateResult.world ∧
          machineCallResultConforms false context contract originalEvent originalResult ∧
          machineCallResultConforms true context contract candidateEvent candidateResult ∧
          StateRel context originalResult.world site.targetInvariant
            originalResult.state candidateResult.state ∧
          ExternalRuntimeFramesPreserved originalEvent candidateEvent
            originalResult candidateResult
  | .terminates => True
  | .protocol => True

def ExternalEnvironmentRefines (context : StaticProofContext)
    (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalEnvironment) : Prop :=
  externalCallSiteIdsUnique sites = true ∧
    sites.all (ExternalCallSiteContract.staticValid context) = true ∧
    forall site, site ∈ sites ->
      exists contract,
        machineImportCallContractById? context site.machineContractId = some contract ∧
        ExternalEnvironmentRefinesAt context site contract original candidate

theorem ExternalEnvironmentRefines.at (context : StaticProofContext)
    (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalEnvironment)
    (refines : ExternalEnvironmentRefines context sites original candidate)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (member : site ∈ sites)
    (resolved : machineImportCallContractById? context site.machineContractId =
      some contract) :
    ExternalEnvironmentRefinesAt context site contract original candidate := by
  rcases refines.2.2 site member with
    ⟨foundContract, foundResolved, foundRefinement⟩
  rw [resolved] at foundResolved
  cases foundResolved
  exact foundRefinement

def ExternalCallTransitionClosed (context : StaticProofContext)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      forall world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState ->
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true ->
            match evalBehavior false localCodeTargets originalState originalBehavior,
                evalBehavior true localCodeTargets candidateState candidateBehavior with
            | some originalResult, some candidateResult =>
                exists originalArguments candidateArguments,
                  originalResult.outcome = .externalCall contract.imported
                    originalArguments site.continuationTargetId ∧
                  candidateResult.outcome = .externalCall contract.imported
                    candidateArguments site.continuationTargetId ∧
                  edge.exit = .external contract.imported ∧
                  outcomesRelated context.originalPe.imageBase
                    context.candidatePe.imageBase context.codeMap.entries.toList
                    (context.relationalValueTargets world)
                    originalResult.outcome candidateResult.outcome = true ∧
                  ExternalCallBoundaryRelated context site contract
                    {
                      siteId := site.id
                      imported := contract.imported
                      arguments := originalArguments
                      state := originalResult.nextMachineState originalState
                      world
                    }
                    {
                      siteId := site.id
                      imported := contract.imported
                      arguments := candidateArguments
                      state := candidateResult.nextMachineState candidateState
                      world
                    }
            | _, _ => False)
  | _, _ => False

def ExternalCallShapeClosed (context : StaticProofContext)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds,
      context.dataMap.resolveIds edge.localValueTargetIds with
  | some localCodeTargets, some localValues =>
      forall world originalState candidateState,
        StateRel context world sourceInvariant originalState candidateState ->
        edge.originalGuard.eval originalState = edge.candidateGuard.eval candidateState ∧
          (edge.originalGuard.eval originalState = true ->
            exists originalResult candidateResult originalArguments candidateArguments,
              evalBehavior false localCodeTargets originalState originalBehavior =
                some originalResult ∧
              evalBehavior true localCodeTargets candidateState candidateBehavior =
                some candidateResult ∧
              originalResult.outcome = .externalCall contract.imported
                originalArguments site.continuationTargetId ∧
              candidateResult.outcome = .externalCall contract.imported
                candidateArguments site.continuationTargetId ∧
              edge.exit = .external contract.imported ∧
              outcomesRelated context.originalPe.imageBase
                context.candidatePe.imageBase context.codeMap.entries.toList
                (context.relationalValueTargets world)
                originalResult.outcome candidateResult.outcome = true ∧
              externalCallArgumentsRelated context world
                originalArguments candidateArguments = true)
  | _, _ => False

def ExternalBoundaryTransferClosed (context : StaticProofContext)
    (site : ExternalCallSiteContract) (edge : RelationalSegmentEdge)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds with
  | some localCodeTargets =>
      forall world originalState candidateState originalResult candidateResult,
        StateRel context world sourceInvariant originalState candidateState ->
        evalBehavior false localCodeTargets originalState originalBehavior =
          some originalResult ->
        evalBehavior true localCodeTargets candidateState candidateBehavior =
          some candidateResult ->
        ExternalBoundaryStateRel context world site.boundaryInvariant
          (originalResult.nextMachineState originalState)
          (candidateResult.nextMachineState candidateState)
  | none => False

theorem externalCallTransitionClosed_of_shape_and_transfer
    (context : StaticProofContext)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (edge : RelationalSegmentEdge) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (shape : ExternalCallShapeClosed context site contract edge sourceInvariant
      originalBehavior candidateBehavior)
    (transfer : ExternalBoundaryTransferClosed context site edge sourceInvariant
      originalBehavior candidateBehavior) :
    ExternalCallTransitionClosed context site contract edge sourceInvariant
      originalBehavior candidateBehavior := by
  unfold ExternalCallShapeClosed at shape
  unfold ExternalBoundaryTransferClosed at transfer
  unfold ExternalCallTransitionClosed
  cases codeResult : context.codeMap.resolveIds edge.localCodeTargetIds with
  | none => simp [codeResult] at shape
  | some localCodeTargets =>
      cases valueResult : context.dataMap.resolveIds edge.localValueTargetIds with
      | none => simp [codeResult, valueResult] at shape
      | some localValues =>
          simp only [codeResult, valueResult] at shape ⊢
          simp only [codeResult] at transfer
          intro world originalState candidateState related
          have shaped := shape world originalState candidateState related
          refine ⟨shaped.1, ?_⟩
          intro guardTrue
          rcases shaped.2 guardTrue with
            ⟨originalResult, candidateResult, originalArguments, candidateArguments,
              originalEval, candidateEval, originalOutcome, candidateOutcome,
              edgeExit, outcomes, argumentsRelated⟩
          rw [originalEval, candidateEval]
          refine ⟨originalArguments, candidateArguments, originalOutcome,
            candidateOutcome, edgeExit, outcomes, ?_⟩
          refine ⟨rfl, rfl, rfl, rfl, rfl, ?_, argumentsRelated⟩
          exact transfer world originalState candidateState originalResult candidateResult
            related originalEval candidateEval


def RelationalExternalCallRefinement (context : StaticProofContext)
    (site : ExternalCallSiteContract) (edge : RelationalSegmentEdge)
    (sourceInvariant : StateInvariant) : Prop :=
  exists contract originalBehavior candidateBehavior,
    machineImportCallContractById? context site.machineContractId = some contract ∧
    site.sourceTargetId = edge.sourceTargetId ∧
    regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
      context.machineImportCallContracts edge.originalSpan = some originalBehavior ∧
    regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
      context.machineImportCallContracts edge.candidateSpan = some candidateBehavior ∧
    ExternalCallTransitionClosed context site contract edge sourceInvariant
      originalBehavior candidateBehavior

def RelationalRegisterExternalCallRefinement (context : StaticProofContext)
    (site : ExternalCallSiteContract) (edge : RelationalSegmentEdge)
    (sourceInvariant : StateInvariant) : Prop :=
  match context.codeMap.resolveIds edge.localCodeTargetIds with
  | none => False
  | some localCodeTargets =>
      exists contract decodedOriginal decodedCandidate originalNormalized
          candidateNormalized originalExternalized candidateExternalized,
        exists claim : ImportRegisterIndirectCallClaim,
        machineImportCallContractById? context site.machineContractId = some contract ∧
        site.sourceTargetId = edge.sourceTargetId ∧
        claim.imported = contract.imported ∧
        claim.continuationTargetId = site.continuationTargetId ∧
        regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
          context.machineImportCallContracts edge.originalSpan = some decodedOriginal ∧
        regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
          context.machineImportCallContracts edge.candidateSpan = some decodedCandidate ∧
        normalizeSymbolicBehavior false localCodeTargets decodedOriginal =
          some originalNormalized ∧
        normalizeSymbolicBehavior true localCodeTargets decodedCandidate =
          some candidateNormalized ∧
        ImportRegisterIndirectCallTargetsClosed sourceInvariant originalNormalized
          candidateNormalized claim ∧
        externalizeRegisterImportCall contract claim.originalRegister decodedOriginal =
          some originalExternalized ∧
        externalizeRegisterImportCall contract claim.candidateRegister decodedCandidate =
          some candidateExternalized ∧
        ExternalCallTransitionClosed context site contract edge sourceInvariant
          originalExternalized candidateExternalized

def ExternalJumpShapeClosed (context : StaticProofContext)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  forall world originalState candidateState,
    StateRel context world region.inputInvariant originalState candidateState ->
    match evalBehavior false region.targets originalState originalBehavior,
        evalBehavior true region.targets candidateState candidateBehavior with
    | some originalResult, some candidateResult =>
        exists originalArguments candidateArguments,
          originalResult.outcome = .externalJump contract.imported originalArguments ∧
          candidateResult.outcome = .externalJump contract.imported candidateArguments ∧
          externalCallArgumentsRelated context world
            originalArguments candidateArguments = true
    | _, _ => False

def ExternalJumpBoundaryTransferClosed (context : StaticProofContext)
    (site : ExternalCallSiteContract) (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  forall world originalState candidateState originalResult candidateResult,
    StateRel context world region.inputInvariant originalState candidateState ->
    evalBehavior false region.targets originalState originalBehavior =
      some originalResult ->
    evalBehavior true region.targets candidateState candidateBehavior =
      some candidateResult ->
    ExternalBoundaryStateRel context world site.boundaryInvariant
      (normalizeImportReturnSlotState
        (originalResult.nextMachineState originalState))
      (normalizeImportReturnSlotState
        (candidateResult.nextMachineState candidateState))

def ExternalJumpTransitionClosed (context : StaticProofContext)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior) : Prop :=
  forall world originalState candidateState,
    StateRel context world region.inputInvariant originalState candidateState ->
    match evalBehavior false region.targets originalState originalBehavior,
        evalBehavior true region.targets candidateState candidateBehavior with
    | some originalResult, some candidateResult =>
        exists originalArguments candidateArguments,
          originalResult.outcome = .externalJump contract.imported originalArguments ∧
          candidateResult.outcome = .externalJump contract.imported candidateArguments ∧
          ExternalCallBoundaryRelated context site contract
            {
              siteId := site.id
              imported := contract.imported
              arguments := originalArguments
              state := normalizeImportReturnSlotState
                (originalResult.nextMachineState originalState)
              world
            }
            {
              siteId := site.id
              imported := contract.imported
              arguments := candidateArguments
              state := normalizeImportReturnSlotState
                (candidateResult.nextMachineState candidateState)
              world
            }
    | _, _ => False

theorem externalJumpTransitionClosed_of_shape_and_transfer
    (context : StaticProofContext)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (shape : ExternalJumpShapeClosed context site contract region
      originalBehavior candidateBehavior)
    (transfer : ExternalJumpBoundaryTransferClosed context site region
      originalBehavior candidateBehavior) :
    ExternalJumpTransitionClosed context site contract region
      originalBehavior candidateBehavior := by
  intro world originalState candidateState related
  have shaped := shape world originalState candidateState related
  cases originalEval : evalBehavior false region.targets originalState
      originalBehavior with
  | none => simp [originalEval] at shaped
  | some originalResult =>
      cases candidateEval : evalBehavior true region.targets candidateState
          candidateBehavior with
      | none => simp [originalEval, candidateEval] at shaped
      | some candidateResult =>
          simp only [originalEval, candidateEval] at shaped ⊢
          rcases shaped with
            ⟨originalArguments, candidateArguments, originalOutcome,
              candidateOutcome, argumentsRelated⟩
          refine ⟨originalArguments, candidateArguments, originalOutcome,
            candidateOutcome, rfl, rfl, rfl, rfl, rfl, ?_, argumentsRelated⟩
          exact transfer world originalState candidateState originalResult
            candidateResult related originalEval candidateEval

def RelationalExternalJumpRefinement (context : StaticProofContext)
    (site : ExternalCallSiteContract) (region : RegionRelation) : Prop :=
  exists contract originalBehavior candidateBehavior,
    machineImportCallContractById? context site.machineContractId = some contract ∧
    site.sourceTargetId = region.id ∧
    regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
      context.machineImportCallContracts region.original = some originalBehavior ∧
    regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
      context.machineImportCallContracts region.candidate = some candidateBehavior ∧
    ExternalJumpTransitionClosed context site contract region
      originalBehavior candidateBehavior

def RelationalExternalProductEdgeRefinement (context : StaticProofContext)
    (graph : RelationalProductGraph) (edgeId : Nat)
    (site : ExternalCallSiteContract) (segment : RelationalSegmentEdge)
    (sourceInvariant : StateInvariant) : Prop :=
  match graph.getEdge? edgeId with
  | none => False
  | some edge =>
      edge.kind = .externalCall ∧
        edge.sourceTargetId = site.sourceTargetId ∧
        edge.targetTargetId = site.continuationTargetId ∧
        (RelationalExternalCallRefinement context site segment sourceInvariant ∨
          RelationalRegisterExternalCallRefinement context site segment sourceInvariant)

def RelationalProductEdgeLocallyRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (edgeId : Nat) : Prop :=
  (∃ segment sourceInvariant targetInvariant,
    RelationalProductEdgeRefinement context graph edgeId segment
      sourceInvariant targetInvariant) ∨
  (∃ site segment sourceInvariant,
    site.staticValid context = true ∧
      RelationalExternalProductEdgeRefinement context graph edgeId site segment
        sourceInvariant)

def ReachableProductNodesDecodedControlComplete (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence) : Prop :=
  ∀ nodeId, nodeId < graph.nodes.size → reachability.contains nodeId = true →
    ∃ region originalBehavior candidateBehavior,
      NodeControlEdgesComplete graph nodeId context region originalBehavior
        candidateBehavior

def ReachableProductEdgesLocallyRefined (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence) : Prop :=
  ∀ edgeId, edgeId < graph.edges.size →
    match graph.getEdge? edgeId with
    | none => False
    | some edge =>
        reachability.contains edge.sourceNodeId = true →
        edge.infeasible = false →
        RelationalProductEdgeLocallyRefined context graph edgeId

structure RelationalProductLocalEvidence where
  decodedNodeIds : List Nat
  refinedEdgeIds : List Nat
deriving Repr, DecidableEq

def RelationalProductReachabilityEvidence.reachableNodeIds
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence) : List Nat :=
  (List.range graph.nodes.size).filter reachability.contains

def RelationalProductReachabilityEvidence.edgeReachableAndFeasible
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence) (edgeId : Nat) : Bool :=
  match graph.getEdge? edgeId with
  | none => false
  | some edge => reachability.contains edge.sourceNodeId && !edge.infeasible

def RelationalProductReachabilityEvidence.reachableFeasibleEdgeIds
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence) : List Nat :=
  (List.range graph.edges.size).filter
    (reachability.edgeReachableAndFeasible graph)

def RelationalProductLocalEvidence.valid (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (evidence : RelationalProductLocalEvidence) : Bool :=
  strictlyIncreasingNats evidence.decodedNodeIds &&
    (evidence.decodedNodeIds.all fun nodeId =>
      nodeId < graph.nodes.size && reachability.contains nodeId) &&
    strictlyIncreasingNats evidence.refinedEdgeIds &&
    evidence.refinedEdgeIds.all
      (reachability.edgeReachableAndFeasible graph)

def RelationalProductLocalEvidence.complete (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (evidence : RelationalProductLocalEvidence) : Bool :=
  evidence.decodedNodeIds == reachability.reachableNodeIds graph &&
    evidence.refinedEdgeIds == reachability.reachableFeasibleEdgeIds graph

def AllListedProductEdgesLocallyRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) : List Nat → Prop
  | [] => True
  | edgeId :: edgeIds =>
      RelationalProductEdgeLocallyRefined context graph edgeId ∧
        AllListedProductEdgesLocallyRefined context graph edgeIds

def AllListedReachableProductNodes (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence) : List Nat → Prop
  | [] => True
  | nodeId :: nodeIds =>
      (nodeId < graph.nodes.size ∧ reachability.contains nodeId = true) ∧
        AllListedReachableProductNodes graph reachability nodeIds

def AllListedReachableFeasibleProductEdges (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence) : List Nat → Prop
  | [] => True
  | edgeId :: edgeIds =>
      reachability.edgeReachableAndFeasible graph edgeId = true ∧
        AllListedReachableFeasibleProductEdges graph reachability edgeIds

theorem allListedDecodedControlNodesComplete_append
    (graph : RelationalProductGraph) (context : StaticProofContext)
    (left right : List Nat)
    (leftComplete : AllListedDecodedControlNodesComplete graph context left)
    (rightComplete : AllListedDecodedControlNodesComplete graph context right) :
    AllListedDecodedControlNodesComplete graph context (left ++ right) := by
  induction left with
  | nil => simpa using rightComplete
  | cons _ tail ih =>
      rcases leftComplete with ⟨headComplete, tailComplete⟩
      exact ⟨headComplete, ih tailComplete⟩

theorem allListedProductEdgesLocallyRefined_append
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (left right : List Nat)
    (leftRefined : AllListedProductEdgesLocallyRefined context graph left)
    (rightRefined : AllListedProductEdgesLocallyRefined context graph right) :
    AllListedProductEdgesLocallyRefined context graph (left ++ right) := by
  induction left with
  | nil => simpa using rightRefined
  | cons _ tail ih =>
      rcases leftRefined with ⟨headRefined, tailRefined⟩
      exact ⟨headRefined, ih tailRefined⟩

theorem allListedReachableProductNodes_append
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (left right : List Nat)
    (leftValid : AllListedReachableProductNodes graph reachability left)
    (rightValid : AllListedReachableProductNodes graph reachability right) :
    AllListedReachableProductNodes graph reachability (left ++ right) := by
  induction left with
  | nil => simpa using rightValid
  | cons _ tail ih =>
      rcases leftValid with ⟨headValid, tailValid⟩
      exact ⟨headValid, ih tailValid⟩

theorem allListedReachableFeasibleProductEdges_append
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (left right : List Nat)
    (leftValid :
      AllListedReachableFeasibleProductEdges graph reachability left)
    (rightValid :
      AllListedReachableFeasibleProductEdges graph reachability right) :
    AllListedReachableFeasibleProductEdges graph reachability
      (left ++ right) := by
  induction left with
  | nil => simpa using rightValid
  | cons _ tail ih =>
      rcases leftValid with ⟨headValid, tailValid⟩
      exact ⟨headValid, ih tailValid⟩

structure PartialReachableProductLocalCertificate (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (evidence : RelationalProductLocalEvidence) : Prop where
  decodedNodeIdsIncreasing : strictlyIncreasingNats evidence.decodedNodeIds = true
  decodedNodeIdsValid :
    AllListedReachableProductNodes graph reachability evidence.decodedNodeIds
  refinedEdgeIdsIncreasing : strictlyIncreasingNats evidence.refinedEdgeIds = true
  refinedEdgeIdsValid :
    AllListedReachableFeasibleProductEdges graph reachability evidence.refinedEdgeIds
  decodedControlComplete :
    AllListedDecodedControlNodesComplete graph context evidence.decodedNodeIds
  edgesLocallyRefined :
    AllListedProductEdgesLocallyRefined context graph evidence.refinedEdgeIds

theorem allListedDecodedControlNodesComplete_of_mem
    (graph : RelationalProductGraph) (context : StaticProofContext)
    (nodeIds : List Nat)
    (listed : AllListedDecodedControlNodesComplete graph context nodeIds) :
    ∀ nodeId, nodeId ∈ nodeIds →
      ∃ region originalBehavior candidateBehavior,
        NodeControlEdgesComplete graph nodeId context region originalBehavior
          candidateBehavior := by
  induction nodeIds with
  | nil => simp
  | cons head tail ih =>
      intro nodeId member
      rcases listed with ⟨headComplete, tailComplete⟩
      simp only [List.mem_cons] at member
      cases member with
      | inl same => simpa [same] using headComplete
      | inr inTail => exact ih tailComplete nodeId inTail

theorem allListedProductEdgesLocallyRefined_of_mem
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (edgeIds : List Nat)
    (listed : AllListedProductEdgesLocallyRefined context graph edgeIds) :
    ∀ edgeId, edgeId ∈ edgeIds →
      RelationalProductEdgeLocallyRefined context graph edgeId := by
  induction edgeIds with
  | nil => simp
  | cons head tail ih =>
      intro edgeId member
      rcases listed with ⟨headRefined, tailRefined⟩
      simp only [List.mem_cons] at member
      cases member with
      | inl same => simpa [same] using headRefined
      | inr inTail => exact ih tailRefined edgeId inTail

theorem reachableProductNodesDecodedControlComplete_of_complete_evidence
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (evidence : RelationalProductLocalEvidence)
    (complete : evidence.complete graph reachability = true)
    (listed : AllListedDecodedControlNodesComplete graph context
      evidence.decodedNodeIds) :
    ReachableProductNodesDecodedControlComplete context graph reachability := by
  simp only [RelationalProductLocalEvidence.complete, Bool.and_eq_true,
    beq_iff_eq] at complete
  intro nodeId before reachable
  apply allListedDecodedControlNodesComplete_of_mem graph context
    evidence.decodedNodeIds listed nodeId
  rw [complete.1]
  simp [RelationalProductReachabilityEvidence.reachableNodeIds, before, reachable]

theorem reachableProductEdgesLocallyRefined_of_complete_evidence
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (evidence : RelationalProductLocalEvidence)
    (complete : evidence.complete graph reachability = true)
    (listed : AllListedProductEdgesLocallyRefined context graph
      evidence.refinedEdgeIds) :
    ReachableProductEdgesLocallyRefined context graph reachability := by
  simp only [RelationalProductLocalEvidence.complete, Bool.and_eq_true,
    beq_iff_eq] at complete
  intro edgeId before
  cases edgeResult : graph.getEdge? edgeId with
  | none =>
      simp [RelationalProductGraph.getEdge?, before] at edgeResult
  | some edge =>
      simp only [edgeResult]
      intro sourceReachable feasible
      apply allListedProductEdgesLocallyRefined_of_mem context graph
        evidence.refinedEdgeIds listed edgeId
      rw [complete.2]
      simp [RelationalProductReachabilityEvidence.reachableFeasibleEdgeIds,
        RelationalProductReachabilityEvidence.edgeReachableAndFeasible,
        before, edgeResult, sourceReachable, feasible]

structure ReachableProductLocalCertificate (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence) where
  staticContextValid : StaticProofContext.StructurallyValid context
  reachabilitySound : reachability.SoundlyClosed context graph
  reachableControlComplete :
    ReachableProductNodesDecodedControlComplete context graph reachability
  reachableEdgesRefined :
    ReachableProductEdgesLocallyRefined context graph reachability

theorem externalCallResultsRelated
    (context : StaticProofContext) (site : ExternalCallSiteContract)
    (contract : MachineImportCallContract)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (environmentRefines : ExternalEnvironmentRefinesAt context site contract
      originalEnvironment candidateEnvironment)
    (returns : contract.disposition = .returns)
    (eventIndex : Nat) (originalEvent candidateEvent : WorldExternalEvent)
    (boundary : ExternalCallBoundaryRelated context site contract
      originalEvent candidateEvent) :
    let originalResult := originalEnvironment.result eventIndex originalEvent
    let candidateResult := candidateEnvironment.result eventIndex candidateEvent
    originalResult.world = candidateResult.world ∧
      machineCallResultConforms false context contract originalEvent originalResult ∧
      machineCallResultConforms true context contract candidateEvent candidateResult ∧
      StateRel context originalResult.world site.targetInvariant
        originalResult.state candidateResult.state ∧
      ExternalRuntimeFramesPreserved originalEvent candidateEvent
        originalResult candidateResult := by
  unfold ExternalEnvironmentRefinesAt at environmentRefines
  rw [returns] at environmentRefines
  exact environmentRefines eventIndex originalEvent candidateEvent boundary

end StageA.Relational
