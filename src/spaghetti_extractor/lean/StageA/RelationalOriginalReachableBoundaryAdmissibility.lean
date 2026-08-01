import StageA.RelationalNativeSourceReachableBoundaryDomain
import StageA.RelationalOriginalRuntimeMemoryAccessChecker

namespace StageA.Relational.OriginalReachableBoundaryAdmissibility

open StageA.Formal StageA.Relational
open StageA.Relational.ControlValueProvenance
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.NativeSource
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalCombinedAwaitingExternalPreservation
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalRuntimeMemoryPartition
open StageA.Relational.OriginalValueFlowExecutionInvariant
open StageA.Relational.ValueProvenance

/-! # Reachable external-boundary input admissibility

External response laws cannot manufacture their own preconditions.  This module
packages the three state-indexed input families required by the first PE32
profile: mapped memory footprints, owned dynamic-range releases, and checked
callback registrations.  The witnesses are over concrete words, memories, and
relational worlds.  They contain no import names or status fields.

The final two adapters deliberately quantify over exact reachable transitions
or invariant-held protocol suspensions.  Generated code supplies compact
witnesses; the generic theorems derive the `MachineResponseInputAdmissible`
facts and construct the authoritative ordinary and nested boundary domains.
-/

def machineCallMemoryAccessMode : MachineCallMemoryAccess -> ModeledAccessMode
  | .read => .read
  | .write => .write

/-- One footprint has resolved in the exact event memory.  A nonempty span is
also proved to be mapped by the static PE or relational runtime world.  Empty
nullable spans carry no access witness. -/
structure CheckedBoundaryFootprintAccess (side : RelationalSide)
    (context : StaticProofContext) (event : WorldExternalEvent)
    (footprint : MachineCallMemoryFootprint) : Prop where
  resolved : exists start stop,
    footprint.range? event.state.memory event.arguments = some (start, stop) /\
      (start = stop \/
        RelationalAccessSpanWitness side context event.world
          (machineCallMemoryAccessMode footprint.access) start (stop - start))

theorem CheckedBoundaryFootprintAccess.runtimeValid
    {side : RelationalSide} {context : StaticProofContext}
    {event : WorldExternalEvent} {footprint : MachineCallMemoryFootprint}
    (checked : CheckedBoundaryFootprintAccess side context event footprint) :
    (footprint.range? event.state.memory event.arguments).isSome = true := by
  rcases checked.resolved with ⟨start, stop, rangeExact, _⟩
  rw [rangeExact]
  rfl

def CheckedBoundaryFootprintAccess.ofCheckedMappedSpan
    (side : RelationalSide) (context : StaticProofContext)
    (event : WorldExternalEvent) (footprint : MachineCallMemoryFootprint)
    (start stop : Nat)
    (rangeExact : footprint.range? event.state.memory event.arguments =
      some (start, stop))
    (checked : relationalAccessSpanChecked side context event.world
      (machineCallMemoryAccessMode footprint.access) start (stop - start) = true) :
    CheckedBoundaryFootprintAccess side context event footprint := ⟨
  start, stop, rangeExact,
  Or.inr <| relationalAccessSpanChecked_sound side context event.world
    (machineCallMemoryAccessMode footprint.access) start (stop - start) checked⟩

def CheckedBoundaryFootprintAccess.empty
    (side : RelationalSide) (context : StaticProofContext)
    (event : WorldExternalEvent) (footprint : MachineCallMemoryFootprint)
    (start : Nat)
    (rangeExact : footprint.range? event.state.memory event.arguments =
      some (start, start)) :
    CheckedBoundaryFootprintAccess side context event footprint :=
  ⟨start, start, rangeExact, Or.inl rfl⟩

/-- Convert the checked original runtime-range witness into the general mapped
span used at an external boundary.  The runtime partition contributes both
range no-wrap and disjointness from the PE image. -/
theorem OriginalRuntimeAccessWitness.toRelationalReadAccessSpan
    {context : StaticProofContext} {world : RelationalWorld}
    {address : Word} {bytes : Nat}
    (witness : OriginalRuntimeAccessWitness world address bytes)
    (partition : HoldsIn context world) :
    RelationalAccessSpanWitness .original context world .read address.toNat
      bytes := by
  right
  refine ⟨witness.range, ?_, ?_⟩
  · cases kindExact : witness.kind with
    | stack =>
        exact List.mem_append_left _ (by simpa [kindExact] using witness.rangeMember)
    | dynamic =>
        exact List.mem_append_right _ (by simpa [kindExact] using witness.rangeMember)
  · refine ⟨witness.bytesPositive, ?_, ?_, witness.startsInside,
      witness.endsInside⟩
    · have noWrap := originalRangeNoWrap context witness.range
        (witness.rangeDisjointFromImages partition)
      simpa [DynamicAddressRangePair.baseOn, addressSpaceSize,
        pe32AddressSpaceSize] using Nat.le_of_lt noWrap
    · exact (witness.spanValid partition).2

/-- Exact all-footprint evidence on both sides of one paired boundary. -/
structure CheckedPairedBoundaryMemoryFootprints
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (original candidate : WorldExternalEvent) : Prop where
  originalAccess : forall footprint, footprint ∈ contract.memoryFootprints ->
    CheckedBoundaryFootprintAccess .original context original footprint
  candidateAccess : forall footprint, footprint ∈ contract.memoryFootprints ->
    CheckedBoundaryFootprintAccess .candidate context candidate footprint

theorem CheckedPairedBoundaryMemoryFootprints.runtimeValid
    {context : StaticProofContext} {contract : MachineImportCallContract}
    {original candidate : WorldExternalEvent}
    (checked : CheckedPairedBoundaryMemoryFootprints context contract original
      candidate) :
    machineCallMemoryFootprintsRuntimeValid contract original.state.memory
        original.arguments = true /\
      machineCallMemoryFootprintsRuntimeValid contract candidate.state.memory
        candidate.arguments = true := by
  constructor <;>
    simp only [machineCallMemoryFootprintsRuntimeValid, List.all_eq_true]
  · intro footprint member
    exact (checked.originalAccess footprint member).runtimeValid
  · intro footprint member
    exact (checked.candidateAccess footprint member).runtimeValid

/-- Exact paired ownership of a release argument.  One relational range pair
must occur in both current worlds; matching scalar bits alone are insufficient.
-/
inductive CheckedPairedDynamicRangeReleaseInput (argumentIndex : Nat)
    (originalArguments candidateArguments : List Word)
    (originalWorld candidateWorld : RelationalWorld) : Prop where
  | null
      (originalFound : originalArguments[argumentIndex]? =
        some (BitVec.ofNat 32 0))
      (candidateFound : candidateArguments[argumentIndex]? =
        some (BitVec.ofNat 32 0))
  | owned
      (range : DynamicAddressRangePair)
      (originalMember : range ∈ originalWorld.dynamicRanges)
      (candidateMember : range ∈ candidateWorld.dynamicRanges)
      (originalFound : originalArguments[argumentIndex]? =
        some range.originalBase)
      (candidateFound : candidateArguments[argumentIndex]? =
        some range.candidateBase)

theorem CheckedPairedDynamicRangeReleaseInput.admissible
    {argumentIndex : Nat} {originalArguments candidateArguments : List Word}
    {originalWorld candidateWorld : RelationalWorld}
    (checked : CheckedPairedDynamicRangeReleaseInput argumentIndex
      originalArguments candidateArguments originalWorld candidateWorld) :
    DynamicRangeReleaseInputAdmissible false argumentIndex originalArguments
        originalWorld /\
      DynamicRangeReleaseInputAdmissible true argumentIndex candidateArguments
        candidateWorld := by
  cases checked with
  | null originalFound candidateFound =>
      constructor
      · simp [DynamicRangeReleaseInputAdmissible, originalFound]
      · simp [DynamicRangeReleaseInputAdmissible, candidateFound]
  | owned range originalMember candidateMember originalFound candidateFound =>
      constructor
      · simp only [DynamicRangeReleaseInputAdmissible, originalFound]
        exact Or.inr ⟨range, originalMember, rfl⟩
      · simp only [DynamicRangeReleaseInputAdmissible, candidateFound]
        exact Or.inr ⟨range, candidateMember, rfl⟩

theorem CheckedPairedDynamicRangeReleaseInput.ofDynamicRangeOrigin
    (context : StaticProofContext) (world : RelationalWorld)
    (argumentIndex rangeId : Nat) (originalArguments candidateArguments : List Word)
    (original candidate : Word)
    (originalFound : originalArguments[argumentIndex]? = some original)
    (candidateFound : candidateArguments[argumentIndex]? = some candidate)
    (origin : (ValueOriginAtom.dynamicRangeLocation rangeId 0).Holds context world
      original candidate) :
    CheckedPairedDynamicRangeReleaseInput argumentIndex originalArguments
      candidateArguments world world := by
  rcases origin with
    ⟨range, member, _id, _positive, originalExact, candidateExact⟩
  apply CheckedPairedDynamicRangeReleaseInput.owned range member member
  · simpa [originalExact] using originalFound
  · simpa [candidateExact] using candidateFound

/-- Exact paired code provenance for a callback-registration input. -/
structure CheckedPairedCallbackRegistrationInput (context : StaticProofContext)
    (argumentIndex : Nat) (originalArguments candidateArguments : List Word) : Prop where
  witness : exists callback : RegisteredCallbackPair,
    originalArguments[argumentIndex]? = some callback.originalAddress /\
      candidateArguments[argumentIndex]? = some callback.candidateAddress /\
      callback.valid context = true

theorem CheckedPairedCallbackRegistrationInput.admissible
    {context : StaticProofContext} {argumentIndex : Nat}
    {originalArguments candidateArguments : List Word}
    (checked : CheckedPairedCallbackRegistrationInput context argumentIndex
      originalArguments candidateArguments) :
    CallbackRegistrationInputAdmissible false context argumentIndex
        originalArguments /\
      CallbackRegistrationInputAdmissible true context argumentIndex
        candidateArguments := by
  rcases checked.witness with ⟨callback, originalFound, candidateFound, valid⟩
  constructor
  · simp only [CallbackRegistrationInputAdmissible, originalFound]
    exact ⟨callback, rfl, valid⟩
  · simp only [CallbackRegistrationInputAdmissible, candidateFound]
    exact ⟨callback, rfl, valid⟩

theorem CheckedPairedCallbackRegistrationInput.ofStaticCodeOrigin
    (context : StaticProofContext) (world : RelationalWorld)
    (argumentIndex targetId : Nat)
    (originalArguments candidateArguments : List Word)
    (original candidate : Word)
    (originalFound : originalArguments[argumentIndex]? = some original)
    (candidateFound : candidateArguments[argumentIndex]? = some candidate)
    (origin : (ValueOriginAtom.staticCodeTarget targetId 0).Holds context world
      original candidate) :
    CheckedPairedCallbackRegistrationInput context argumentIndex
      originalArguments candidateArguments := by
  rcases origin with ⟨target, targetFound, addressEvidence⟩
  rcases addressEvidence with exact | impossible
  · let callback : RegisteredCallbackPair := {
      targetId
      originalAddress := original
      candidateAddress := candidate
    }
    refine {
      witness := ⟨callback, ?_, ?_, ?_⟩
    }
    · simpa [callback] using originalFound
    · simpa [callback] using candidateFound
    · simpa [callback, RegisteredCallbackPair.valid, targetFound,
        codeAddressMatches] using And.intro exact.2.1 exact.2.2
  · omega

/-- The machine-memory effect selects whether footprint evidence is required. -/
def CheckedPairedMachineMemoryInput
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (original candidate : WorldExternalEvent) : Prop :=
  match contract.memoryEffect with
  | .readOnly | .argumentRanges =>
      CheckedPairedBoundaryMemoryFootprints context contract original candidate
  | .none | .newDynamicRanges | .relationalState => True

/-- The machine-world effect selects one of the checked provenance witnesses. -/
def CheckedPairedMachineWorldInput
    (context : StaticProofContext) (effect : MachineCallWorldEffect)
    (original candidate : WorldExternalEvent) : Prop :=
  match effect with
  | .dynamicRangeRelease argumentIndex =>
      CheckedPairedDynamicRangeReleaseInput argumentIndex original.arguments
        candidate.arguments original.world candidate.world
  | .callbackRegistration argumentIndex =>
      CheckedPairedCallbackRegistrationInput context argumentIndex
        original.arguments candidate.arguments
  | .none | .opaqueResources | .dynamicRanges | .tlsState => True

theorem checkedPairedMachineMemoryInput_admissible
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (original candidate : WorldExternalEvent)
    (checked : CheckedPairedMachineMemoryInput context contract original candidate) :
    MachineMemoryEffectInputAdmissible contract original /\
      MachineMemoryEffectInputAdmissible contract candidate := by
  cases effect : contract.memoryEffect with
  | none | newDynamicRanges | relationalState =>
      simp [MachineMemoryEffectInputAdmissible, effect]
  | readOnly | argumentRanges =>
      simp only [CheckedPairedMachineMemoryInput, effect] at checked
      have valid := checked.runtimeValid
      simpa [MachineMemoryEffectInputAdmissible, effect] using valid

theorem checkedPairedMachineWorldInput_admissible
    (context : StaticProofContext) (effect : MachineCallWorldEffect)
    (original candidate : WorldExternalEvent)
    (checked : CheckedPairedMachineWorldInput context effect original candidate) :
    MachineWorldEffectInputAdmissible false context effect original.arguments
        original.world /\
      MachineWorldEffectInputAdmissible true context effect candidate.arguments
        candidate.world := by
  cases effect with
  | none | opaqueResources | dynamicRanges | tlsState =>
      simp [CheckedPairedMachineWorldInput, MachineWorldEffectInputAdmissible]
  | dynamicRangeRelease argumentIndex =>
      exact checked.admissible
  | callbackRegistration argumentIndex =>
      exact checked.admissible

structure CheckedPairedMachineResponseInput (context : StaticProofContext)
    (contract : MachineImportCallContract)
    (original candidate : WorldExternalEvent) : Prop where
  memory : CheckedPairedMachineMemoryInput context contract original candidate
  world : CheckedPairedMachineWorldInput context contract.worldEffect original
    candidate

theorem CheckedPairedMachineResponseInput.admissible
    {context : StaticProofContext} {contract : MachineImportCallContract}
    {original candidate : WorldExternalEvent}
    (checked : CheckedPairedMachineResponseInput context contract original candidate) :
    MachineResponseInputAdmissible false context contract original /\
      MachineResponseInputAdmissible true context contract candidate := by
  have memory := checkedPairedMachineMemoryInput_admissible context contract
    original candidate checked.memory
  have world := checkedPairedMachineWorldInput_admissible context
    contract.worldEffect original candidate checked.world
  exact ⟨⟨memory.1, world.1⟩, ⟨memory.2, world.2⟩⟩

/-! ## Projections from the combined original invariant -/

/-- A candidate companion proof turns an original value-flow fact into a paired
origin at an awaiting boundary.  The transfer obligation is explicit because a
coarse `relatedWord` fact cannot determine which finite origin was selected. -/
theorem pairedValueOriginAtAwaiting
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    (holds : inventory.Holds (.awaitingExternal suspension callbacks))
    (fact : OriginalFiniteValueFlowFact program.context)
    (factMember : fact ∈ inventory.valueFlows.facts)
    (endpointMember : suspension.sourceTargetId ∈ fact.targetIds \/
      suspension.continuationTargetId ∈ fact.targetIds)
    (original candidate : Word) (candidateWorld : RelationalWorld)
    (originalExact : originalLocationValue fact.location suspension.state = original)
    (companion : forall origin, origin ∈ fact.alternatives ->
      OriginalValueOriginAtomHolds program.context suspension.world original origin ->
        origin.Holds program.context candidateWorld original candidate) :
    exists origin, origin ∈ fact.alternatives /\
      origin.Holds program.context candidateWorld original candidate := by
  have factAt := (inventory.valueFlowHolds holds fact factMember endpointMember)
  rcases factAt with ⟨origin, originMember, source⟩
  rw [originalExact] at source
  exact ⟨origin, originMember, companion origin originMember source⟩

/-- Dormant frame values use the same companion interface.  This is the nested
call/callback form needed when an argument survives below the active frame. -/
theorem pairedValueOriginInDormantFrame
    {context : StaticProofContext} {beforeWorld candidateWorld : RelationalWorld}
    {state : MachineState} {frame : DormantOriginalCallFrame}
    (frameHolds : frame.Holds context beforeWorld state)
    (fact : DormantOriginalValueFact) (factMember : fact ∈ frame.values)
    (original candidate : Word)
    (originalExact : Memory.read32 state.memory
      (fact.frameAddress frame.runtime) = original)
    (companion : OriginalValueOriginAtomHolds context beforeWorld original
        fact.origin -> fact.origin.Holds context candidateWorld original candidate) :
    fact.origin.Holds context candidateWorld original candidate := by
  have source := frameHolds.2.2.2 fact factMember
  unfold DormantOriginalValueFact.HoldsInFrame at source
  rw [originalExact] at source
  exact companion source

/-! ## Exact ordinary and nested domain construction -/

structure CheckedOpaqueSiteMachineContract (context : StaticProofContext)
    (program : DecodedWorldProgram) (site : OpaqueLockstepCallSite) where
  callSite : ExternalCallSiteContract
  contract : MachineImportCallContract
  callSiteMember : callSite ∈ program.externalCallSites
  siteMatches : site.matchesExternalCallSite context callSite = true
  contractResolved : machineImportCallContractById? context
    callSite.machineContractId = some contract

/-- Program adapter for ordinary synchronous boundaries.  Its premise includes
the exact emitted transition and complete combined invariant, preventing an
analysis-only site inventory from admitting a request. -/
structure CheckedOriginalCombinedReachableBoundaryInputs
    (context : StaticProofContext) (program : DecodedWorldProgram)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    (sites : List OpaqueLockstepCallSite) where
  inputs : forall site (member : site ∈ sites)
      (request : WorldNativeBoundaryRequest),
    OriginalBoundaryRequestReachable inventory site request.eventIndex
        request.originalEvent ->
      request.BoundaryRelated context site ->
      site.disposition = .returns ->
      exists binding : CheckedOpaqueSiteMachineContract context program site,
        CheckedPairedMachineResponseInput context binding.contract
          request.originalEvent (request.candidateWorldEvent site)

def CheckedOriginalCombinedReachableBoundaryInputs.toDomain
    {context : StaticProofContext} {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {sites : List OpaqueLockstepCallSite}
    (checked : CheckedOriginalCombinedReachableBoundaryInputs context program
      originalContext inventory sites) :
    CheckedOriginalCombinedReachableBoundaryDomain context program originalContext
      inventory sites := by
  let domain : forall site, site ∈ sites ->
      CheckedReachableWorldNativeBoundaryDomain context program site :=
    fun site member => {
      Admits := fun request =>
        request.BoundaryRelated context site /\
          (site.disposition = .returns ->
            exists binding : CheckedOpaqueSiteMachineContract context program site,
              CheckedPairedMachineResponseInput context binding.contract
                request.originalEvent (request.candidateWorldEvent site))
      boundaryRelated := fun _ admitted => admitted.1
      returningInputs := fun returns request admitted => by
        rcases admitted.2 returns with ⟨binding, inputs⟩
        have admissible := inputs.admissible
        exact ⟨binding.callSite, binding.contract, binding.callSiteMember,
          binding.siteMatches, binding.contractResolved, admissible.1,
          admissible.2⟩
    }
  exact {
    domain
    reachedAdmitted := fun site member request reached related =>
      ⟨related, checked.inputs site member request reached related⟩
  }

/-- Program adapter for retained protocol suspensions and nested callback
frames.  Evidence is re-established in each current suspension world, so a
callback cannot invalidate an owned range or terminated footprint unnoticed. -/
structure CheckedOriginalCombinedReachableProtocolInputs
    (context : StaticProofContext) (program : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (mixed : MixedRelationContract) (frames : MixedNestedExternalFrameContract)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program originalContext) where
  inputs : forall request : WorldNativeProtocolBoundaryRequest candidate,
    inventory.Holds (.awaitingExternal request.suspension request.callbacks) ->
      request.Related mixed frames -> forall contract,
        CheckedOriginalMachineProtocolBoundary program request.suspension contract ->
          CheckedPairedMachineResponseInput context (protocolReturnContract contract)
            request.suspension.currentEvent
            (request.boundary.suspension.currentWorldEvent
              request.suspension.siteId)

def CheckedOriginalCombinedReachableProtocolInputs.toDomain
    {context : StaticProofContext} {program : DecodedWorldProgram}
    {candidate : ExactNestedNativeWorldProgram}
    {mixed : MixedRelationContract} {frames : MixedNestedExternalFrameContract}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    (checked : CheckedOriginalCombinedReachableProtocolInputs context program
      candidate mixed frames originalContext inventory) :
    CheckedReachableWorldNativeProtocolBoundaryDomain context program candidate
      mixed frames originalContext inventory where
  Admits request :=
    inventory.Holds (.awaitingExternal request.suspension request.callbacks) /\
      request.Related mixed frames
  related _ admitted := admitted.2
  reachedAdmitted _ holds related := ⟨holds, related⟩
  returningInputs request admitted contract boundary :=
    (checked.inputs request admitted.1 admitted.2 contract boundary).admissible

#print axioms CheckedBoundaryFootprintAccess.runtimeValid
#print axioms OriginalRuntimeAccessWitness.toRelationalReadAccessSpan
#print axioms CheckedPairedBoundaryMemoryFootprints.runtimeValid
#print axioms CheckedPairedDynamicRangeReleaseInput.admissible
#print axioms CheckedPairedCallbackRegistrationInput.admissible
#print axioms CheckedPairedMachineResponseInput.admissible
#print axioms pairedValueOriginAtAwaiting
#print axioms pairedValueOriginInDormantFrame
#print axioms CheckedOriginalCombinedReachableBoundaryInputs.toDomain
#print axioms CheckedOriginalCombinedReachableProtocolInputs.toDomain

end StageA.Relational.OriginalReachableBoundaryAdmissibility
