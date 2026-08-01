import StageA.RelationalNativeSourceAdmittedProtocolResponseFamily

namespace StageA.Relational.NativeSource

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWorldBridge

/-! # External response-family completion obligations

Static machine-call contracts describe permitted effects, but effects such as
releasing a dynamic range and registering a callback have state-indexed input
preconditions.  This module states those preconditions without naming an API
and proves that every conforming result necessarily satisfies them.

The predicates are intentionally proof obligations, not response semantics.
In particular, exact lockstep scalar argument equality does not establish that
a nonzero word owns a dynamic range or denotes checked executable code.
-/

theorem dynamicRangeReleaseHolds_inputAdmissible
    (candidate : Bool) (argumentIndex : Nat) (arguments : List Word)
    (before after : RelationalWorld)
    (holds : dynamicRangeReleaseHolds candidate argumentIndex arguments before after) :
    DynamicRangeReleaseInputAdmissible candidate argumentIndex arguments before := by
  cases found : arguments[argumentIndex]? with
  | none =>
      simp only [DynamicRangeReleaseInputAdmissible, found]
      simp only [dynamicRangeReleaseHolds, found] at holds
  | some argument =>
      simp only [DynamicRangeReleaseInputAdmissible, found]
      by_cases zero : argument = BitVec.ofNat 32 0
      · exact Or.inl zero
      · right
        simp only [dynamicRangeReleaseHolds, found, zero,
          beq_iff_eq] at holds
        rcases holds with ⟨range, member, address, _⟩
        exact ⟨range, member, address⟩

theorem callbackRegistrationHolds_inputAdmissible
    (candidate : Bool) (context : StaticProofContext)
    (argumentIndex : Nat) (arguments : List Word)
    (before after : RelationalWorld)
    (holds : callbackRegistrationHolds candidate context argumentIndex arguments
      before after) :
    CallbackRegistrationInputAdmissible candidate context argumentIndex arguments := by
  cases found : arguments[argumentIndex]? with
  | none =>
      simp only [CallbackRegistrationInputAdmissible, found]
      simp only [callbackRegistrationHolds, found] at holds
  | some argument =>
      simp only [CallbackRegistrationInputAdmissible, found]
      simp only [callbackRegistrationHolds, found] at holds
      rcases holds with ⟨callback, _, address, valid, _⟩
      exact ⟨callback, address, valid⟩

theorem machineCallWorldEffectHolds_inputAdmissible
    (candidate : Bool) (context : StaticProofContext)
    (effect : MachineCallWorldEffect) (arguments : List Word)
    (before after : RelationalWorld)
    (holds : machineCallWorldEffectHolds candidate context effect arguments
      before after) :
    MachineWorldEffectInputAdmissible candidate context effect arguments before := by
  cases effect with
  | none | opaqueResources | dynamicRanges | tlsState => trivial
  | dynamicRangeRelease argumentIndex =>
      exact dynamicRangeReleaseHolds_inputAdmissible candidate argumentIndex
        arguments before after holds.2
  | callbackRegistration argumentIndex =>
      exact callbackRegistrationHolds_inputAdmissible candidate context
        argumentIndex arguments before after holds.2

theorem machineCallResultConforms_inputAdmissible
    (candidate : Bool) (context : StaticProofContext)
    (contract : MachineImportCallContract) (event : WorldExternalEvent)
    (result : WorldExternalResult)
    (conforms : machineCallResultConforms candidate context contract event result) :
    MachineWorldEffectInputAdmissible candidate context contract.worldEffect
      event.arguments event.world := by
  exact machineCallWorldEffectHolds_inputAdmissible candidate context
    contract.worldEffect event.arguments event.world result.world conforms.2.2.2

theorem machineCallMemoryEffectHolds_inputAdmissible
    (candidate : Bool) (contract : MachineImportCallContract)
    (event : WorldExternalEvent) (result : WorldExternalResult)
    (holds : machineCallMemoryEffectHoldsWithWorld candidate contract
      event.arguments event.world result.world event.state.memory
      result.state.memory) :
    MachineMemoryEffectInputAdmissible contract event := by
  cases effect : contract.memoryEffect with
  | none | newDynamicRanges | relationalState =>
      simp [MachineMemoryEffectInputAdmissible, effect]
  | readOnly | argumentRanges =>
      simp only [MachineMemoryEffectInputAdmissible, effect]
      simp only [machineCallMemoryEffectHoldsWithWorld, effect,
        machineCallMemoryEffectHolds] at holds
      exact holds.1

theorem machineCallResultConforms_responseInputAdmissible
    (candidate : Bool) (context : StaticProofContext)
    (contract : MachineImportCallContract) (event : WorldExternalEvent)
    (result : WorldExternalResult)
    (conforms : machineCallResultConforms candidate context contract event result) :
    MachineResponseInputAdmissible candidate context contract event := by
  exact ⟨machineCallMemoryEffectHolds_inputAdmissible candidate contract event
      result conforms.2.2.1,
    machineCallResultConforms_inputAdmissible candidate context contract event
      result conforms⟩

theorem noMachineCallResultConformsOfInadmissible
    (candidate : Bool) (context : StaticProofContext)
    (contract : MachineImportCallContract) (event : WorldExternalEvent)
    (inadmissible : Not (MachineWorldEffectInputAdmissible candidate context
      contract.worldEffect event.arguments event.world)) :
    forall result, Not (machineCallResultConforms candidate context contract event
      result) := by
  intro result conforms
  exact inadmissible (machineCallResultConforms_inputAdmissible candidate context
    contract event result conforms)

theorem noDynamicRangeReleaseWithoutOwnedArgument
    (candidate : Bool) (argumentIndex : Nat) (arguments : List Word)
    (before : RelationalWorld) (argument : Word)
    (argumentFound : arguments[argumentIndex]? = some argument)
    (nonzero : argument ≠ BitVec.ofNat 32 0)
    (unowned : forall range, range ∈ before.dynamicRanges ->
      range.sideBase candidate ≠ argument) :
    forall after, ¬ dynamicRangeReleaseHolds candidate argumentIndex arguments
      before after := by
  intro after holds
  have admissible := dynamicRangeReleaseHolds_inputAdmissible candidate
    argumentIndex arguments before after holds
  unfold DynamicRangeReleaseInputAdmissible at admissible
  rw [argumentFound] at admissible
  rcases admissible with zero | ⟨range, member, address⟩
  · exact nonzero zero
  · exact unowned range member address

theorem noCallbackRegistrationWithoutCheckedTarget
    (candidate : Bool) (context : StaticProofContext)
    (argumentIndex : Nat) (arguments : List Word) (before : RelationalWorld)
    (argument : Word) (argumentFound : arguments[argumentIndex]? = some argument)
    (unchecked : forall callback : RegisteredCallbackPair,
      (if candidate then callback.candidateAddress
        else callback.originalAddress) = argument ->
      callback.valid context ≠ true) :
    forall after, ¬ callbackRegistrationHolds candidate context argumentIndex
      arguments before after := by
  intro after holds
  have admissible := callbackRegistrationHolds_inputAdmissible candidate context
    argumentIndex arguments before after holds
  unfold CallbackRegistrationInputAdmissible at admissible
  rw [argumentFound] at admissible
  rcases admissible with ⟨callback, address, valid⟩
  exact unchecked callback address valid

theorem exactArgumentsDoNotProveDynamicRangeOwnership
    (context : StaticProofContext) (argument : Word) :
    externalCallArgumentsRelated context RelationalWorld.empty [argument]
      [argument] = true := by
  exact wordsRelated_self context.originalPe.imageBase
    context.candidatePe.imageBase context.codeMap.entries.toList
    (context.relationalValueTargets RelationalWorld.empty) [argument]

/-- Every checked returning response carries the effect-input fact omitted by
mere static classification.  Completion generators can use this theorem as a
precise required-proof interface. -/
theorem CheckedWorldNativeResponseAt.machineEffectInputAdmissible
    {context : StaticProofContext} {program : DecodedWorldProgram}
    {site : OpaqueLockstepCallSite}
    {sourceEnvironment : WorldExternalEnvironment}
    {nativeEnvironment : NativeWorldEnvironment}
    (checked : CheckedWorldNativeResponseAt context program site
      sourceEnvironment nativeEnvironment)
    (returns : site.disposition = .returns)
    (request : WorldNativeBoundaryRequest)
    (admitted : checked.boundaryDomain.Admits request) :
    exists callSite contract,
      callSite ∈ program.externalCallSites /\
      site.matchesExternalCallSite context callSite = true /\
      machineImportCallContractById? context callSite.machineContractId =
        some contract /\
      MachineWorldEffectInputAdmissible false context contract.worldEffect
        request.originalEvent.arguments request.originalEvent.world := by
  rcases checked.boundaryDomain.returningInputs returns request admitted with
    ⟨callSite, contract, callSiteMember, siteMatches, contractResolved,
      responseInputs, _⟩
  exact ⟨callSite, contract, callSiteMember, siteMatches, contractResolved,
    responseInputs.2⟩

theorem CheckedWorldNativeResponseAt.responseInputsAdmissible
    {context : StaticProofContext} {program : DecodedWorldProgram}
    {site : OpaqueLockstepCallSite}
    {sourceEnvironment : WorldExternalEnvironment}
    {nativeEnvironment : NativeWorldEnvironment}
    (checked : CheckedWorldNativeResponseAt context program site
      sourceEnvironment nativeEnvironment)
    (returns : site.disposition = .returns)
    (request : WorldNativeBoundaryRequest)
    (admitted : checked.boundaryDomain.Admits request) :
    exists callSite contract,
      callSite ∈ program.externalCallSites /\
      site.matchesExternalCallSite context callSite = true /\
      machineImportCallContractById? context callSite.machineContractId =
        some contract /\
      MachineResponseInputAdmissible false context contract
        request.originalEvent /\
      MachineResponseInputAdmissible true context contract
        (request.candidateWorldEvent site) :=
  checked.boundaryDomain.returningInputs returns request admitted

/-- A single boundary in the universal response domain whose checked machine
contract cannot accept the concrete input.  Such a witness rules out a total
response schedule; a response function cannot repair a precondition after the
call has occurred. -/
structure InadmissibleReturningResponseBoundary
    (context : StaticProofContext) (program : DecodedWorldProgram)
    (site : OpaqueLockstepCallSite) where
  returns : site.disposition = .returns
  eventIndex : Nat
  originalEvent : WorldExternalEvent
  candidateEvent : NativeExternalEvent
  boundary : OpaqueLockstepBoundaryRelated context site originalEvent
    (nativeExternalEventToWorldExternalEvent candidateEvent site.id
      originalEvent.world)
  inadmissible : forall callSite contract,
    callSite ∈ program.externalCallSites ->
    site.matchesExternalCallSite context callSite = true ->
    machineImportCallContractById? context callSite.machineContractId =
      some contract ->
    Not (MachineResponseInputAdmissible false context contract originalEvent)

theorem noCheckedWorldNativeResponseAtOfInadmissibleBoundary
    {context : StaticProofContext} {program : DecodedWorldProgram}
    {site : OpaqueLockstepCallSite}
    {sourceEnvironment : WorldExternalEnvironment}
    {nativeEnvironment : NativeWorldEnvironment}
    (checked : CheckedWorldNativeResponseAt context program site
      sourceEnvironment nativeEnvironment)
    (blocked : InadmissibleReturningResponseBoundary context program site) :
    Not (checked.boundaryDomain.Admits {
      eventIndex := blocked.eventIndex
      originalEvent := blocked.originalEvent
      candidateEvent := blocked.candidateEvent
    }) := by
  intro admitted
  rcases checked.responseInputsAdmissible blocked.returns
      { eventIndex := blocked.eventIndex
        originalEvent := blocked.originalEvent
        candidateEvent := blocked.candidateEvent }
      admitted with
    ⟨callSite, contract, member, matched, resolved,
      admissible, _⟩
  exact blocked.inadmissible callSite contract member matched resolved admissible

/-! ## Checked total response definitions

The completion boundary is a typed Lean value, not a declaration name loaded
from JSON.  Its environments are the response definitions themselves, and its
remaining fields are the exact machine-level checks required by the admitted
family.  This is the narrowest honest production input while effect-input and
continuation certificates are still state indexed.
-/

structure CheckedTotalProtocolResponseDefinitions
    {context : StaticProofContext}
    {classified : List CheckedMachineExternalSite}
    {ordinarySites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {mixed : MixedRelationContract}
    {frames : MixedNestedExternalFrameContract}
    (family : CheckedWorldNativeAdmittedProtocolResponseFamily context classified
      ordinarySites compilation mixed frames) where
  sourceEnvironment : SourceWorldResponseEnvironment
  nativeEnvironment : NativeWorldResponseEnvironment
  responseSchedule : CheckedWorldNativeProtocolResponseSchedule context
    (exactNativeCompilationAtResponseEnvironments compilation sourceEnvironment
      nativeEnvironment.ordinary).project.worldProgram
    (nativeEnvironment.nestedProgram
      (exactNativeCompilationAtResponseEnvironments compilation sourceEnvironment
        nativeEnvironment.ordinary).machineAuthority.program)
    classified ordinarySites sourceEnvironment.ordinary mixed frames
  sourceFamily : CheckedNativeSourceLaunchFamily
    (exactNativeCompilationAtResponseEnvironments compilation sourceEnvironment
      nativeEnvironment.ordinary).project
  launchRealizable : NativeCompilationLaunchRealizable
    (exactNativeCompilationAtResponseEnvironments compilation sourceEnvironment
      nativeEnvironment.ordinary).machineAuthority

def CheckedTotalProtocolResponseDefinitions.admitted
    {context : StaticProofContext}
    {classified : List CheckedMachineExternalSite}
    {ordinarySites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {mixed : MixedRelationContract}
    {frames : MixedNestedExternalFrameContract}
    {family : CheckedWorldNativeAdmittedProtocolResponseFamily context classified
      ordinarySites compilation mixed frames}
    (definitions : CheckedTotalProtocolResponseDefinitions family) :
    family.Related definitions.sourceEnvironment definitions.nativeEnvironment :=
  ⟨{
    responseSchedule := definitions.responseSchedule
    sourceFamily := definitions.sourceFamily
    launchRealizable := definitions.launchRealizable
  }⟩

/-- Construct the concrete non-vacuity witness consumed by final acceptance.
All behavioral proof data is checked through the fields above; no generated
string or JSON status can authorize this constructor. -/
def CheckedTotalProtocolResponseDefinitions.toCompletion
    {context : StaticProofContext}
    {classified : List CheckedMachineExternalSite}
    {ordinarySites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {mixed : MixedRelationContract}
    {frames : MixedNestedExternalFrameContract}
    {family : CheckedWorldNativeAdmittedProtocolResponseFamily context classified
      ordinarySites compilation mixed frames}
    (definitions : CheckedTotalProtocolResponseDefinitions family) :
    family.Completion := {
  canonicalSourceEnvironment := definitions.sourceEnvironment
  canonicalNativeEnvironment := definitions.nativeEnvironment
  canonical := definitions.admitted
}

end StageA.Relational.NativeSource
