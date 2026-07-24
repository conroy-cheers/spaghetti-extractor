import StageA.RelationalCallableExternalExecution
import StageA.RelationalInterpreterMixedKernelComposition
import StageA.RelationalReachableStaticPointerSlot

namespace StageA.Relational.CallableExternalMixedBridge

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalCapability
open StageA.Relational.CallableExternalExecution
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.ReachableStaticPointerSlot

/-! # Callable-external mixed execution bridge

This module supplies the integration facts between callable capabilities and
the decoded-original/native-candidate composition layer.  It deliberately
does not construct a mixed acceptance certificate.  Callable observations
must come from exact original and native transition paths before this layer
can relate or compose them.
-/

def canonicalCandidateInternalMatches
    (context : StaticProofContext) (target : Word) : List Nat :=
  nativeCandidateExecutableMatches context.candidatePe target

def canonicalCandidateImportMatches
    (world : RelationalWorld) (target : Word) : List ImportAddressPair :=
  world.importAddresses.filter fun binding => binding.candidateAddress == target

def canonicalCandidateResourceMatches
    (world : RelationalWorld) (target : Word) : List OpaqueResourcePair :=
  world.opaqueResources.filter fun resource => resource.candidate == target

def resolveCandidateCallableIndirect
    (capabilities : List CallableExternalCapability)
    (resolvedABIContracts : List ResolvedExternalABIContract)
    (context : StaticProofContext) (world : RelationalWorld) (target : Word)
    (transfer : ResolvedExternalTransfer) : OriginalIndirectResolution :=
  if callableExternalWorldValid context world != true then
    .invalidWorld
  else
    classifyOriginalIndirectMatches
      (canonicalCandidateInternalMatches context target)
      (canonicalCandidateImportMatches world target)
      (canonicalCandidateResourceMatches world target)
      capabilities resolvedABIContracts transfer

theorem resolveCandidateCallableIndirect_rejectsInvalidWorld
    (capabilities : List CallableExternalCapability)
    (resolvedABIContracts : List ResolvedExternalABIContract)
    (context : StaticProofContext) (world : RelationalWorld) (target : Word)
    (transfer : ResolvedExternalTransfer)
    (invalid : callableExternalWorldValid context world != true) :
    resolveCandidateCallableIndirect capabilities resolvedABIContracts context
      world target transfer = .invalidWorld := by
  simp [resolveCandidateCallableIndirect, invalid]

theorem resolveCandidateCallableIndirect_exact
    (capabilities : List CallableExternalCapability)
    (resolvedABIContracts : List ResolvedExternalABIContract)
    (context : StaticProofContext) (world : RelationalWorld) (target : Word)
    (transfer : ResolvedExternalTransfer)
    (valid : callableExternalWorldValid context world = true) :
    resolveCandidateCallableIndirect capabilities resolvedABIContracts context
        world target transfer =
      classifyOriginalIndirectMatches
        (canonicalCandidateInternalMatches context target)
        (canonicalCandidateImportMatches world target)
        (canonicalCandidateResourceMatches world target)
        capabilities resolvedABIContracts transfer := by
  simp [resolveCandidateCallableIndirect, valid]

private theorem filteredCandidateResource_eq_target
    (world : RelationalWorld) (target : Word)
    (resource : OpaqueResourcePair)
    (singleton : canonicalCandidateResourceMatches world target = [resource]) :
    resource.candidate = target := by
  have member : resource ∈ canonicalCandidateResourceMatches world target := by
    rw [singleton]
    simp
  simpa [canonicalCandidateResourceMatches] using (List.mem_filter.mp member).2

theorem resolveCandidateCallableIndirect_usesCandidateValue
    (capabilities : List CallableExternalCapability)
    (resolvedABIContracts : List ResolvedExternalABIContract)
    (context : StaticProofContext) (world : RelationalWorld) (target : Word)
    (transfer : ResolvedExternalTransfer)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract) (resource : OpaqueResourcePair)
    (resolved : resolveCandidateCallableIndirect capabilities
      resolvedABIContracts context world target transfer =
        .callable capability abi resource) :
    resource.candidate = target := by
  by_cases valid : callableExternalWorldValid context world = true
  · rw [resolveCandidateCallableIndirect, if_neg (by simp [valid])] at resolved
    unfold classifyOriginalIndirectMatches at resolved
    generalize canonicalCandidateInternalMatches context target = internals at resolved
    generalize canonicalCandidateImportMatches world target = imports at resolved
    generalize resourceMatches :
      canonicalCandidateResourceMatches world target = resources at resolved
    cases internals with
    | nil =>
        cases imports with
        | nil =>
            cases resources with
            | nil => simp at resolved
            | cons resourceHead resourceTail =>
                cases resourceTail with
                | nil =>
                    have sameResource : resourceHead = resource := by
                      cases matchingCapabilities : List.filter (fun candidate =>
                          candidate.resourceId == resourceHead.id) capabilities with
                      | nil => simp [matchingCapabilities] at resolved
                      | cons matchingCapability matchingCapabilitiesTail =>
                          cases matchingCapabilitiesTail with
                          | nil =>
                              cases matchingABIs : List.filter (fun candidateABI =>
                                  candidateABI.capabilityId ==
                                      matchingCapability.id &&
                                    candidateABI.transfer == transfer)
                                  resolvedABIContracts with
                              | nil => simp [matchingCapabilities, matchingABIs] at resolved
                              | cons matchingABI matchingABIsTail =>
                                  cases matchingABIsTail with
                                  | nil =>
                                      simp [matchingCapabilities, matchingABIs] at resolved
                                      exact resolved.2.2
                                  | cons =>
                                      simp [matchingCapabilities, matchingABIs] at resolved
                          | cons => simp [matchingCapabilities] at resolved
                    subst resourceHead
                    exact filteredCandidateResource_eq_target world target resource
                      resourceMatches
                | cons => cases resolved
        | cons importHead importTail =>
            cases importTail with
            | nil =>
                cases resources with
                | nil => cases resolved
                | cons => cases resolved
            | cons => cases resolved
    | cons internalHead internalTail =>
        cases internalTail with
        | nil =>
            cases imports with
            | nil =>
                cases resources with
                | nil => cases resolved
                | cons => cases resolved
            | cons => cases resolved
        | cons => cases resolved
  · rw [resolveCandidateCallableIndirect, if_pos (by simpa using valid)] at resolved
    cases resolved

def canonicalCandidateKernelCallableFrontier
    (capabilities : List CallableExternalCapability)
    (resolvedABIContracts : List ResolvedExternalABIContract) :
    CandidateKernelCallableFrontier := {
  capabilities
  resolvedABIContracts
  internalMatches := canonicalCandidateInternalMatches
  importMatches := canonicalCandidateImportMatches
  resourceMatches := canonicalCandidateResourceMatches
  classifyIndirect := resolveCandidateCallableIndirect capabilities
    resolvedABIContracts
  classificationExact := resolveCandidateCallableIndirect_exact capabilities
    resolvedABIContracts
  callableUsesCandidateValue := resolveCandidateCallableIndirect_usesCandidateValue
    capabilities resolvedABIContracts
  rejectsInvalidWorld := resolveCandidateCallableIndirect_rejectsInvalidWorld
    capabilities resolvedABIContracts
}

structure CallableWorldValidity
    (context : StaticProofContext) (world : RelationalWorld) : Prop where
  worldValid : world.valid context = true
  importInventoryValid : world.importAddressesStaticValid context = true

theorem CallableWorldValidity.callableExternalWorldValid
    (valid : CallableWorldValidity context world) :
    callableExternalWorldValid context world = true := by
  change (world.valid context && world.importAddressesStaticValid context) = true
  simp [valid.worldValid, valid.importInventoryValid]

theorem callableExternalWorldValid_toValidity
    (valid : callableExternalWorldValid context world = true) :
    CallableWorldValidity context world := by
  change (world.valid context && world.importAddressesStaticValid context) = true at valid
  simp only [Bool.and_eq_true] at valid
  exact ⟨valid.1, valid.2⟩

theorem exactlyOneFreshCallableResourceIssued_preservesValidity
    (beforeValid : CallableWorldValidity context before)
    (issued : ExactlyOneFreshCallableResourceIssued context before after resource) :
    CallableWorldValidity context after := by
  rcases issued with
    ⟨afterValid, _dynamic, _stack, imports, _callbacks, _tls, _resources⟩
  refine ⟨afterValid, ?_⟩
  unfold RelationalWorld.importAddressesStaticValid
  rw [imports]
  exact beforeValid.importInventoryValid

theorem resolvedExternalSideResultConforms_preservesValidity
    (beforeValid : CallableWorldValidity context event.world)
    (abiValid : abi.shapeValid = true)
    (conforms : ResolvedExternalSideResultConforms candidate context capability
      abi event result) :
    CallableWorldValidity context result.world := by
  have effectNone : abi.worldEffect = .none := by
    simp only [ResolvedExternalABIContract.shapeValid, Bool.and_eq_true] at abiValid
    have effectValid := abiValid.2
    simp only [ResolvedExternalABIContract.effectShapeValid, Bool.and_eq_true] at effectValid
    exact beq_iff_eq.mp effectValid.2
  have world := conforms.worldHolds
  rw [effectNone] at world
  simp only [machineCallWorldEffectHolds] at world
  refine ⟨world.1, ?_⟩
  rw [world.2]
  exact beforeValid.importInventoryValid

/-! ## External writable-slot frames

Internal `RegionTransition` preservation does not cover an external ABI
transition.  These definitions make the missing frame explicit.  A supported
footprint case checks every byte of the four-byte slot; broader memory effects
must provide the finite-set preservation fact directly.
-/

def ExternalWriteFootprintsAvoidWord
    (footprints : List MachineCallMemoryFootprint)
    (memory : Memory) (arguments : List Word) (slot : Word) : Prop :=
  forall offset, offset < 4 ->
    (footprints.any fun footprint =>
      footprint.access == .write &&
        footprint.contains memory arguments
          (slot + BitVec.ofNat 32 offset)) = false

def MachineCallMemoryEffectFootprintBounded
    (effect : MachineCallMemoryEffect) : Prop :=
  effect = .none \/ effect = .readOnly \/ effect = .argumentRanges

private theorem read32_eq_of_four_bytes_eq
    (before after : Memory) (slot : Word)
    (bytes : forall offset, offset < 4 ->
      after (slot + BitVec.ofNat 32 offset) =
        before (slot + BitVec.ofNat 32 offset)) :
    Memory.read32 after slot = Memory.read32 before slot := by
  have byte0 : after slot = before slot := by
    simpa using bytes 0 (by decide)
  unfold Memory.read32
  rw [byte0, bytes 1 (by decide), bytes 2 (by decide),
    bytes 3 (by decide)]

theorem machineCallMemoryEffectHolds_preservesWord
    (contract : MachineImportCallContract) (arguments : List Word)
    (before after : Memory) (slot : Word)
    (supported : MachineCallMemoryEffectFootprintBounded contract.memoryEffect)
    (holds : machineCallMemoryEffectHolds contract arguments before after)
    (avoids : ExternalWriteFootprintsAvoidWord contract.memoryFootprints
      before arguments slot) :
    Memory.read32 after slot = Memory.read32 before slot := by
  unfold machineCallMemoryEffectHolds at holds
  rcases supported with effect | effect | effect
  · rw [effect] at holds
    rw [holds]
  · rw [effect] at holds
    rw [holds.2]
  · rw [effect] at holds
    apply read32_eq_of_four_bytes_eq
    intro offset beforeFour
    exact holds.2 _ (avoids offset beforeFour)

theorem resolvedExternalMemoryEffectHolds_preservesWord
    (contract : ResolvedExternalABIContract) (arguments : List Word)
    (before after : Memory) (slot : Word)
    (supported : MachineCallMemoryEffectFootprintBounded contract.memoryEffect)
    (holds : resolvedExternalMemoryEffectHolds contract arguments before after)
    (avoids : ExternalWriteFootprintsAvoidWord contract.memoryFootprints
      before arguments slot) :
    Memory.read32 after slot = Memory.read32 before slot := by
  unfold resolvedExternalMemoryEffectHolds at holds
  rcases supported with effect | effect | effect
  · rw [effect] at holds
    rw [holds]
  · rw [effect] at holds
    rw [holds.2]
  · rw [effect] at holds
    apply read32_eq_of_four_bytes_eq
    intro offset beforeFour
    exact holds.2 _ (avoids offset beforeFour)

inductive MachineCallStaticWordFrame
    (contract : MachineImportCallContract)
    (event : WorldExternalEvent) (result : WorldExternalResult)
    (slot : Word) (allowed : List Word) : Prop where
  | footprints
      (supported : MachineCallMemoryEffectFootprintBounded contract.memoryEffect)
      (avoids : ExternalWriteFootprintsAvoidWord contract.memoryFootprints
        event.state.memory event.arguments slot) :
      MachineCallStaticWordFrame contract event result slot allowed
  | finiteSet
      (preserved : Memory.read32 result.state.memory slot ∈ allowed) :
      MachineCallStaticWordFrame contract event result slot allowed

theorem machineCallResultConforms_preservesStaticWordInvariant
    (candidate : Bool) (context : StaticProofContext)
    (contract : MachineImportCallContract)
    (event : WorldExternalEvent) (result : WorldExternalResult)
    (slot : Word) (allowed : List Word)
    (conforms : machineCallResultConforms candidate context contract event result)
    (frame : MachineCallStaticWordFrame contract event result slot allowed)
    (prior : Memory.read32 event.state.memory slot ∈ allowed) :
    Memory.read32 result.state.memory slot ∈ allowed := by
  cases frame with
  | finiteSet preserved => exact preserved
  | footprints supported avoids =>
      have direct : machineCallMemoryEffectHolds contract event.arguments
          event.state.memory result.state.memory := by
        have withWorld := conforms.2.2.1
        unfold machineCallMemoryEffectHoldsWithWorld at withWorld
        rcases supported with effect | effect | effect
        · simpa [effect] using withWorld
        · simpa [effect] using withWorld
        · simpa [effect] using withWorld
      rw [machineCallMemoryEffectHolds_preservesWord contract event.arguments
        event.state.memory result.state.memory slot supported direct avoids]
      exact prior

inductive ResolvedExternalStaticWordFrame
    (contract : ResolvedExternalABIContract)
    (event : ResolvedExternalEvent) (result : WorldExternalResult)
    (slot : Word) (allowed : List Word) : Prop where
  | footprints
      (supported : MachineCallMemoryEffectFootprintBounded contract.memoryEffect)
      (avoids : ExternalWriteFootprintsAvoidWord contract.memoryFootprints
        event.state.memory event.arguments slot) :
      ResolvedExternalStaticWordFrame contract event result slot allowed
  | finiteSet
      (preserved : Memory.read32 result.state.memory slot ∈ allowed) :
      ResolvedExternalStaticWordFrame contract event result slot allowed

theorem resolvedExternalSideResultConforms_preservesStaticWordInvariant
    (candidate : Bool) (context : StaticProofContext)
    (capability : CallableExternalCapability)
    (contract : ResolvedExternalABIContract)
    (event : ResolvedExternalEvent) (result : WorldExternalResult)
    (slot : Word) (allowed : List Word)
    (conforms : ResolvedExternalSideResultConforms candidate context capability
      contract event result)
    (frame : ResolvedExternalStaticWordFrame contract event result slot allowed)
    (prior : Memory.read32 event.state.memory slot ∈ allowed) :
    Memory.read32 result.state.memory slot ∈ allowed := by
  cases frame with
  | finiteSet preserved => exact preserved
  | footprints supported avoids =>
      rw [resolvedExternalMemoryEffectHolds_preservesWord contract event.arguments
        event.state.memory result.state.memory slot supported conforms.memoryHolds
        avoids]
      exact prior

theorem machineCallResultConforms_preservesReachableStaticPointerSlot
    (candidate : Bool) (context : StaticProofContext)
    (originalContext : OriginalDecodedStaticContext)
    (certificate : ReachableStaticPointerSlot.Certificate)
    (targetIds : List Nat)
    (contract : MachineImportCallContract)
    (event : WorldExternalEvent) (result : WorldExternalResult)
    (allowedExact : certificate.allowedTargetIds = .exact targetIds)
    (conforms : machineCallResultConforms candidate context contract event result)
    (frame : MachineCallStaticWordFrame contract event result
      (BitVec.ofNat 32 (slotAddress originalContext certificate))
      (allowedWords originalContext targetIds))
    (prior : SlotValueAllowed originalContext certificate event.state.memory) :
    SlotValueAllowed originalContext certificate result.state.memory := by
  unfold SlotValueAllowed at prior ⊢
  rw [allowedExact] at prior ⊢
  exact machineCallResultConforms_preservesStaticWordInvariant candidate context
    contract event result _ _ conforms frame prior

theorem resolvedExternalSideResultConforms_preservesReachableStaticPointerSlot
    (candidate : Bool) (context : StaticProofContext)
    (originalContext : OriginalDecodedStaticContext)
    (certificate : ReachableStaticPointerSlot.Certificate)
    (targetIds : List Nat)
    (capability : CallableExternalCapability)
    (contract : ResolvedExternalABIContract)
    (event : ResolvedExternalEvent) (result : WorldExternalResult)
    (allowedExact : certificate.allowedTargetIds = .exact targetIds)
    (conforms : ResolvedExternalSideResultConforms candidate context capability
      contract event result)
    (frame : ResolvedExternalStaticWordFrame contract event result
      (BitVec.ofNat 32 (slotAddress originalContext certificate))
      (allowedWords originalContext targetIds))
    (prior : SlotValueAllowed originalContext certificate event.state.memory) :
    SlotValueAllowed originalContext certificate result.state.memory := by
  unfold SlotValueAllowed at prior ⊢
  rw [allowedExact] at prior ⊢
  exact resolvedExternalSideResultConforms_preservesStaticWordInvariant candidate
    context capability contract event result _ _ conforms frame prior

structure PairedCallableEnvironmentRefinement
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract)
    (resolvedBoundaryInvariant resolvedTargetInvariant : StateInvariant)
    (originalResolver candidateResolver : WorldExternalEnvironment)
    (originalResolved candidateResolved : ResolvedExternalEnvironment) : Prop where
  resolverRefines : ResolverCapabilityEnvironmentRefinesAt context site machine resolver
    capability originalResolver candidateResolver
  resolvedRefines : ResolvedExternalEnvironmentRefinesAt context resolver capability abi
    resolvedBoundaryInvariant resolvedTargetInvariant originalResolved
    candidateResolved

structure ResolverRefinementSuccessor
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (originalResult candidateResult : WorldExternalResult) : Prop where
  sameWorld : originalResult.world = candidateResult.world
  stateRelated : StateRel context originalResult.world site.targetInvariant
    originalResult.state candidateResult.state
  originalWorldValid : CallableWorldValidity context originalResult.world
  candidateWorldValid : CallableWorldValidity context candidateResult.world

theorem PairedCallableEnvironmentRefinement.resolverSuccessor
    (bridge : PairedCallableEnvironmentRefinement context site machine resolver
      capability abi resolvedBoundaryInvariant resolvedTargetInvariant
      originalResolver candidateResolver originalResolved candidateResolved)
    (eventIndex : Nat) (originalEvent candidateEvent : WorldExternalEvent)
    (boundary : ResolverCapabilityBoundaryRelated context site machine resolver
      capability originalEvent candidateEvent)
    (beforeValid : CallableWorldValidity context originalEvent.world) :
    ResolverRefinementSuccessor context site
      (originalResolver.result eventIndex originalEvent)
      (candidateResolver.result eventIndex candidateEvent) := by
  have related := bridge.resolverRefines eventIndex originalEvent candidateEvent boundary
  have valid : CallableWorldValidity context
      (originalResolver.result eventIndex originalEvent).world := by
    rcases related.originalConforms.resultCase with unavailable | issuedResource
    · rw [unavailable.2.2]
      exact beforeValid
    · rcases issuedResource with
        ⟨resource, issued, _resourceId, _resultValue, _originalNonzero,
          _candidateNonzero⟩
      exact exactlyOneFreshCallableResourceIssued_preservesValidity beforeValid
        issued
  exact ⟨related.resultWorld, related.targetState, valid, by
    rw [← related.resultWorld]
    exact valid⟩

structure ResolvedRefinementSuccessor
    (context : StaticProofContext) (targetInvariant : StateInvariant)
    (originalResult candidateResult : WorldExternalResult) : Prop where
  sameWorld : originalResult.world = candidateResult.world
  stateRelated : StateRel context originalResult.world targetInvariant
    originalResult.state candidateResult.state
  originalWorldValid : CallableWorldValidity context originalResult.world
  candidateWorldValid : CallableWorldValidity context candidateResult.world

theorem PairedCallableEnvironmentRefinement.resolvedSuccessor
    (bridge : PairedCallableEnvironmentRefinement context site machine resolver
      capability abi resolvedBoundaryInvariant resolvedTargetInvariant
      originalResolver candidateResolver originalResolved candidateResolved)
    (eventIndex : Nat) (originalEvent candidateEvent : ResolvedExternalEvent)
    (boundary : ResolvedExternalBoundaryRelated context resolver capability abi
      resolvedBoundaryInvariant originalEvent candidateEvent)
    (beforeValid : CallableWorldValidity context originalEvent.world) :
    ResolvedRefinementSuccessor context resolvedTargetInvariant
      (originalResolved.result eventIndex originalEvent)
      (candidateResolved.result eventIndex candidateEvent) := by
  have related := bridge.resolvedRefines eventIndex originalEvent candidateEvent boundary
  have valid := resolvedExternalSideResultConforms_preservesValidity beforeValid
    boundary.abiValid related.originalConforms
  exact ⟨related.resultWorld, related.targetState, valid, by
    rw [← related.resultWorld]
    exact valid⟩

/-! ## Exact native callable transitions

The native transition system now owns opaque-callable classification and
execution. The bridge accepts only an equality to that exact transition and
its shared callable observation; there is no separate projection premise or
missing-transition constructor.
-/

structure CandidateNativeCallableState where
  rva : Nat
  undefinedSlot : Nat
  state : MachineState
  calls : List NativeCallFrame
  globalExternalIndex : Nat
  nativeEvents : List NativeExternalEvent
  world : RelationalWorld
  externalTrace : List CallableExternalObservation

def CandidateNativeCallableState.toNative
    (state : CandidateNativeCallableState) : NativeWorldExecution :=
  .running state.rva state.undefinedSlot state.state state.calls
    state.globalExternalIndex state.nativeEvents state.world

structure ExactCandidateCallableProgramBinding
    (context : StaticProofContext)
    (candidate : ExactNativeWorldProgram) : Prop where
  candidatePe : context.candidatePe = candidate.pe
  candidateImports : context.candidateImports = candidate.imports
  indirectTargetsValid : candidate.indirectTargets.valid candidate.pe = true
  callableConfig : exists config,
    candidate.callableExternal = some config /\
      config.context = context /\
      config.BoundTo candidate.pe candidate.imports

structure ExactDecodedOriginalCallableProgramBinding
    (decoded : DecodedWorldProgram)
    (program : OriginalCallableProgram)
    (environment : OriginalCallableExternalEnvironment) : Prop where
  originalRole : decoded.candidate = false
  callableProgram : decoded.callableProgram = some program
  callableEnvironment : decoded.callableEnvironment = some environment
  contextExact : program.context = decoded.context
  programValid : program.Valid

def ExactDecodedOriginalCallableProgramBinding.ofWithCallable
    (decoded : DecodedWorldProgram)
    (program : OriginalCallableProgram)
    (environment : OriginalCallableExternalEnvironment)
    (originalRole : decoded.candidate = false)
    (contextExact : program.context = decoded.context)
    (programValid : program.Valid) :
    ExactDecodedOriginalCallableProgramBinding
      (decodedWorldProgramWithCallable decoded program environment)
        program environment := {
  originalRole
  callableProgram := rfl
  callableEnvironment := rfl
  contextExact
  programValid
}

structure ExactCandidateKernelOutcome
    (candidate : ExactNativeWorldProgram)
    (before : CandidateNativeCallableState)
    (outcome : ConcreteOutcome) where
  stoppedState : MachineState
  decoded : stepKernelPE32Instruction candidate.pe candidate.imports
    (.running before.rva before.undefinedSlot before.state) =
      .stopped outcome stoppedState

structure ActualNativeCallableTransitionEvidence
    (candidate : ExactNativeWorldProgram)
    (before after : CandidateNativeCallableState)
    (outcome : ConcreteOutcome) where
  kernel : ExactCandidateKernelOutcome candidate before outcome
  observation : CallableExternalObservation
  nativeStep : candidate.transitionSystem.step before.toNative = {
    next := after.toNative
    observation := some (.callableExternal observation)
  }
  index : observation.globalExternalIndex = before.globalExternalIndex
  nextIndex : after.globalExternalIndex = before.globalExternalIndex + 1
  trace : after.externalTrace = before.externalTrace ++ [observation]
  callContinuation : forall target continuation returnAddress,
    outcome = .indirectCall target continuation returnAddress ->
      after.rva = continuation
  tailFrame : forall target, outcome = .indirectJump target ->
    exists frame tail, before.calls = frame :: tail /\
      after.calls = tail /\ after.rva = frame.continuationRva

inductive CandidateNativeCallableTransitionEvidence
    (candidate : ExactNativeWorldProgram)
    (candidateContext : StaticProofContext)
    (kernelFrontier : CandidateKernelCallableFrontier) :
    CandidateNativeCallableState -> ConcreteOutcome ->
      CandidateNativeCallableState -> Prop where
  | actual {before outcome after}
      (native : ActualNativeCallableTransitionEvidence candidate before after
        outcome) :
      CandidateNativeCallableTransitionEvidence candidate candidateContext
        kernelFrontier before outcome after

theorem CandidateNativeCallableTransitionEvidence.appendsObservation
    (evidence : CandidateNativeCallableTransitionEvidence candidate
      candidateContext kernelFrontier before outcome after) :
    exists observation,
      observation.globalExternalIndex = before.globalExternalIndex /\
      after.globalExternalIndex = before.globalExternalIndex + 1 /\
      after.externalTrace = before.externalTrace ++ [observation] := by
  cases evidence with
  | actual native =>
      exact ⟨native.observation, native.index, native.nextIndex, native.trace⟩

theorem CandidateNativeCallableTransitionEvidence.indirectCallContinuation
    (evidence : CandidateNativeCallableTransitionEvidence candidate
      candidateContext kernelFrontier before
      (.indirectCall target continuation returnAddress) after) :
    after.rva = continuation := by
  cases evidence with
  | actual native =>
      exact native.callContinuation target continuation returnAddress rfl

theorem CandidateNativeCallableTransitionEvidence.indirectTailFrame
    (evidence : CandidateNativeCallableTransitionEvidence candidate
      candidateContext kernelFrontier before (.indirectJump target) after) :
    exists frame tail,
      before.calls = frame :: tail /\ after.calls = tail /\
        after.rva = frame.continuationRva := by
  cases evidence with
  | actual native => exact native.tailFrame target rfl

def candidateNativeCallableFrontier
    (candidate : ExactNativeWorldProgram)
    (candidateContext : StaticProofContext)
    (_candidateBinding : ExactCandidateCallableProgramBinding candidateContext
      candidate)
    (kernelFrontier : CandidateKernelCallableFrontier) :
    CandidateNativeCallableFrontier := {
  State := CandidateNativeCallableState
  rva := CandidateNativeCallableState.rva
  machineState := CandidateNativeCallableState.state
  calls := CandidateNativeCallableState.calls
  world := CandidateNativeCallableState.world
  globalExternalIndex := CandidateNativeCallableState.globalExternalIndex
  externalTrace := CandidateNativeCallableState.externalTrace
  transition := CandidateNativeCallableTransitionEvidence candidate
    candidateContext kernelFrontier
  externalStepSound := fun _ _ _ evidence => evidence.appendsObservation
  indirectCallContinuation := fun _ _ _ _ _ evidence =>
    evidence.indirectCallContinuation
  indirectTailFrame := fun _ _ _ evidence => evidence.indirectTailFrame
}

structure MixedCallableExternalObservationRelated
    (contract : MixedRelationContract)
    (original candidate : CallableExternalObservation) : Prop where
  sameIndex : original.globalExternalIndex = candidate.globalExternalIndex
  sameIdentity : original.identity = candidate.identity
  worldsRelated : contract.worldsRelated original.world candidate.world
  argumentsRelated : mixedValuesRelated
    (contract.valuesRelated original.world candidate.world)
    original.arguments candidate.arguments

structure MixedCallableRuntimeEnvironmentRefinement
    (contract : MixedRelationContract)
    (originalBefore originalAfter : OriginalCallableExecutionState)
    (candidateBefore candidateAfter : CandidateNativeCallableState) : Prop where
  observationsRelated : forall originalObservation candidateObservation,
    originalAfter.externalTrace = originalBefore.externalTrace ++
        [originalObservation] ->
    candidateAfter.externalTrace = candidateBefore.externalTrace ++
        [candidateObservation] ->
    MixedCallableExternalObservationRelated contract originalObservation
      candidateObservation

/-- A local fact for the final mixed chunk composer.  It contains no launch
root, reachability closure, invariant, candidate authority, or chunk path, so
it cannot authorize standalone acceptance. -/
structure CallableMixedChunkEventFact
    (context : StaticProofContext)
    (contract : MixedRelationContract)
    (originalBefore originalAfter : OriginalCallableExecutionState)
    (candidateBefore candidateAfter : CandidateNativeCallableState)
    (staticWordSlot : Word) (staticWordAllowed : List Word)
    (originalObservation candidateObservation : CallableExternalObservation) : Prop where
  originalTrace : originalAfter.externalTrace =
    originalBefore.externalTrace ++ [originalObservation]
  candidateTrace : candidateAfter.externalTrace =
    candidateBefore.externalTrace ++ [candidateObservation]
  observationsRelated : MixedCallableExternalObservationRelated contract
    originalObservation candidateObservation
  originalWorldValid : CallableWorldValidity context originalAfter.world
  candidateWorldValid : CallableWorldValidity context candidateAfter.world
  originalStaticWordBefore :
    Memory.read32 originalBefore.state.memory staticWordSlot ∈ staticWordAllowed
  originalStaticWordAfter :
    Memory.read32 originalAfter.state.memory staticWordSlot ∈ staticWordAllowed

theorem CallableMixedChunkEventFact.sharedObservationRelated
    (fact : CallableMixedChunkEventFact context contract originalBefore
      originalAfter candidateBefore candidateAfter staticWordSlot
      staticWordAllowed originalObservation candidateObservation) :
    contract.eventObservationsRelated
      (some (.callableExternal originalObservation))
      (some (.callableExternal candidateObservation)) := by
  exact ⟨fact.observationsRelated.sameIndex,
    fact.observationsRelated.sameIdentity,
    fact.observationsRelated.worldsRelated,
    fact.observationsRelated.argumentsRelated⟩

/-- Consume the callable fact at the ordinary mixed chunk boundary. The two
paths remain exact operational paths; the fact supplies only their checked
single-event relation and world/frame side conditions. -/
def CallableMixedChunkEventFact.toMixedKernelChunkPaths
    (fact : CallableMixedChunkEventFact context contract callableOriginalBefore
      callableOriginalAfter callableCandidateBefore callableCandidateAfter
      staticWordSlot staticWordAllowed originalObservation candidateObservation)
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (_originalBinding : ExactDecodedOriginalCallableProgramBinding original
      callableProgram callableEnvironment)
    (_candidateBinding : ExactCandidateCallableProgramBinding
      callableProgram.context candidate)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (originalBefore originalAfter : WorldExecution)
    (candidateBefore candidateAfter : NativeWorldExecution)
    (originalPath : NonemptyRelatedPath original.pe32TransitionSystem
      originalBefore [(.callableExternal originalObservation)] originalAfter)
    (candidatePath : NonemptyRelatedPath candidate.transitionSystem
      candidateBefore [(.callableExternal candidateObservation)] candidateAfter)
    (afterRelated : invariant.holds originalAfter candidateAfter) :
    MixedKernelChunkPaths original candidate contract invariant originalBefore
      candidateBefore := {
  originalObservations := [(.callableExternal originalObservation)]
  candidateObservations := [(.callableExternal candidateObservation)]
  originalAfter
  candidateAfter
  originalPath
  candidatePath
  observationsChecked := {
    pointwise := ⟨fact.sharedObservationRelated, trivial⟩
  }
  afterRelated
}

theorem callableMixedChunkEventFact_of_runtimeSteps
    (program : OriginalCallableProgram)
    (environment : OriginalCallableExternalEnvironment)
    (candidate : ExactNativeWorldProgram)
    (candidateBinding : ExactCandidateCallableProgramBinding program.context
      candidate)
    (kernelFrontier : CandidateKernelCallableFrontier)
    (contract : MixedRelationContract)
    (originalBefore originalAfter : OriginalCallableExecutionState)
    (candidateBefore candidateAfter : CandidateNativeCallableState)
    (originalOutcome candidateOutcome : ConcreteOutcome)
    (originalStep : OriginalCallableExternalStep program environment
      originalBefore originalOutcome originalAfter)
    (candidateStep : CandidateNativeCallableTransitionEvidence candidate
      program.context kernelFrontier candidateBefore candidateOutcome candidateAfter)
    (environmentRefines : MixedCallableRuntimeEnvironmentRefinement contract
      originalBefore originalAfter candidateBefore candidateAfter)
    (originalAfterValid : CallableWorldValidity program.context originalAfter.world)
    (candidateAfterValid : CallableWorldValidity program.context candidateAfter.world)
    (staticWordSlot : Word) (staticWordAllowed : List Word)
    (originalStaticWordBefore :
      Memory.read32 originalBefore.state.memory staticWordSlot ∈ staticWordAllowed)
    (originalStaticWordAfter :
      Memory.read32 originalAfter.state.memory staticWordSlot ∈ staticWordAllowed) :
    exists originalObservation candidateObservation,
      CallableMixedChunkEventFact program.context contract originalBefore originalAfter
        candidateBefore candidateAfter staticWordSlot staticWordAllowed
        originalObservation candidateObservation := by
  rcases originalStep.appendsRuntimeObservation program environment
      originalBefore originalAfter originalOutcome with
    ⟨originalObservation, _originalIndex, _originalNext, originalAppend⟩
  rcases candidateStep.appendsObservation with
    ⟨candidateObservation, _candidateIndex, _candidateNext, candidateAppend⟩
  exact ⟨originalObservation, candidateObservation, originalAppend,
    candidateAppend, environmentRefines.observationsRelated
      originalObservation candidateObservation originalAppend candidateAppend,
    originalAfterValid, candidateAfterValid, originalStaticWordBefore,
    originalStaticWordAfter⟩

#print axioms resolveCandidateCallableIndirect_usesCandidateValue
#print axioms exactlyOneFreshCallableResourceIssued_preservesValidity
#print axioms resolvedExternalSideResultConforms_preservesValidity
#print axioms candidateNativeCallableFrontier
#print axioms CallableMixedChunkEventFact.toMixedKernelChunkPaths
#print axioms callableMixedChunkEventFact_of_runtimeSteps

end StageA.Relational.CallableExternalMixedBridge
