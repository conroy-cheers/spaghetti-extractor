import StageA.RelationalNativeSourceConcreteEnvironmentPair
import StageA.RelationalInterpreterMixedEnvironment
import StageA.RelationalOriginalCombinedAwaitingExternalPreservation
import StageA.RelationalOriginalCombinedExecutionInvariant

namespace StageA.Relational.NativeSource

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterAcceptance
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWorldBridge
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalCombinedAwaitingExternalPreservation
open StageA.Relational.SourceWorld

/-! # Checked reachable external-boundary domains

External response laws are meaningful only for requests produced by a checked
program execution.  This module makes that domain explicit.  A domain is not
an API model: membership is a proof over the exact machine event, its paired
native event, the resolved machine contract, and the contract's state-indexed
input preconditions.

The producer remains fail closed.  Exact source transitions and retained
protocol suspensions must be shown to enter the domain.  Merely presenting two
events with matching import names is not an admission witness.
-/

def DynamicRangeReleaseInputAdmissible (candidate : Bool)
    (argumentIndex : Nat) (arguments : List Word)
    (world : RelationalWorld) : Prop :=
  match arguments[argumentIndex]? with
  | none => False
  | some argument =>
      argument = BitVec.ofNat 32 0 \/
        exists range, range ∈ world.dynamicRanges /\
          range.sideBase candidate = argument

def CallbackRegistrationInputAdmissible (candidate : Bool)
    (context : StaticProofContext) (argumentIndex : Nat)
    (arguments : List Word) : Prop :=
  match arguments[argumentIndex]? with
  | none => False
  | some argument =>
      exists callback : RegisteredCallbackPair,
        (if candidate then callback.candidateAddress
          else callback.originalAddress) = argument /\
        callback.valid context = true

def MachineWorldEffectInputAdmissible (candidate : Bool)
    (context : StaticProofContext) (effect : MachineCallWorldEffect)
    (arguments : List Word) (world : RelationalWorld) : Prop :=
  match effect with
  | .dynamicRangeRelease argumentIndex =>
      DynamicRangeReleaseInputAdmissible candidate argumentIndex arguments world
  | .callbackRegistration argumentIndex =>
      CallbackRegistrationInputAdmissible candidate context argumentIndex arguments
  | .none | .opaqueResources | .dynamicRanges | .tlsState => True

def MachineMemoryEffectInputAdmissible
    (contract : MachineImportCallContract) (event : WorldExternalEvent) : Prop :=
  match contract.memoryEffect with
  | .readOnly | .argumentRanges =>
      machineCallMemoryFootprintsRuntimeValid contract event.state.memory
        event.arguments = true
  | .none | .newDynamicRanges | .relationalState => True

def MachineResponseInputAdmissible (candidate : Bool)
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (event : WorldExternalEvent) : Prop :=
  MachineMemoryEffectInputAdmissible contract event /\
    MachineWorldEffectInputAdmissible candidate context contract.worldEffect
      event.arguments event.world

/-- One paired request at a concrete logical event index. -/
structure WorldNativeBoundaryRequest where
  eventIndex : Nat
  originalEvent : WorldExternalEvent
  candidateEvent : NativeExternalEvent

def WorldNativeBoundaryRequest.candidateWorldEvent
    (site : OpaqueLockstepCallSite)
    (request : WorldNativeBoundaryRequest) : WorldExternalEvent :=
  nativeExternalEventToWorldExternalEvent request.candidateEvent site.id
    request.originalEvent.world

def WorldNativeBoundaryRequest.BoundaryRelated
    (context : StaticProofContext) (site : OpaqueLockstepCallSite)
    (request : WorldNativeBoundaryRequest) : Prop :=
  OpaqueLockstepBoundaryRelated context site request.originalEvent
    (request.candidateWorldEvent site)

/-- A checked domain for one static site.  Membership proves the exact
lockstep boundary and, for returning calls, both state-indexed machine-contract
input predicates. -/
structure CheckedReachableWorldNativeBoundaryDomain
    (context : StaticProofContext) (program : DecodedWorldProgram)
    (site : OpaqueLockstepCallSite) where
  Admits : WorldNativeBoundaryRequest -> Prop
  boundaryRelated : forall request, Admits request ->
    request.BoundaryRelated context site
  returningInputs : site.disposition = .returns -> forall request,
    Admits request ->
      exists callSite contract,
        callSite ∈ program.externalCallSites /\
          site.matchesExternalCallSite context callSite = true /\
          machineImportCallContractById? context callSite.machineContractId =
            some contract /\
          MachineResponseInputAdmissible false context contract
            request.originalEvent /\
          MachineResponseInputAdmissible true context contract
            (request.candidateWorldEvent site)

/-- The legacy universal boundary is available only as an explicit adapter.
It still requires the caller to prove every related request's input
preconditions, so it cannot recreate the former unchecked widening. -/
def checkedUniversalWorldNativeBoundaryDomain
    (context : StaticProofContext) (program : DecodedWorldProgram)
    (site : OpaqueLockstepCallSite)
    (inputs : site.disposition = .returns ->
      forall request : WorldNativeBoundaryRequest,
      request.BoundaryRelated context site ->
        exists callSite contract,
          callSite ∈ program.externalCallSites /\
            site.matchesExternalCallSite context callSite = true /\
            machineImportCallContractById? context callSite.machineContractId =
              some contract /\
            MachineResponseInputAdmissible false context contract
              request.originalEvent /\
            MachineResponseInputAdmissible true context contract
              (request.candidateWorldEvent site)) :
    CheckedReachableWorldNativeBoundaryDomain context program site := {
  Admits := fun request => request.BoundaryRelated context site
  boundaryRelated := fun _ admitted => admitted
  returningInputs := fun returns request admitted =>
    inputs returns request admitted
}

def worldExecutionEventIndex? : WorldExecution -> Option Nat
  | .running _ _ _ eventIndex _ | .callbackRunning _ _ _ eventIndex _ _ =>
      some eventIndex
  | .awaitingExternal suspension _ => some suspension.eventIndex
  | .returned .. | .terminated .. | .fault .. | .blocked .. => none

/-- Checked evidence that the source semantics produced one external request.
The synchronous constructor binds the exact one-step observation, source
target, event index, world, import, and arguments.  The protocol constructor
uses the immutable event retained in the actual suspension. -/
inductive OriginalBoundaryRequestReachable
    {program : DecodedWorldProgram}
    {originalContext : InterpreterMixedContext.OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    (site : OpaqueLockstepCallSite) :
    Nat -> WorldExternalEvent -> Prop where
  | emitted
      (before : WorldExecution)
      (eventIndex : Nat)
      (event : WorldExternalEvent)
      (holds : inventory.Holds before)
      (atSite : WorldExecution.AtTargetId site.sourceTargetId before)
      (indexExact : worldExecutionEventIndex? before = some eventIndex)
      (stateExact : originalExecutionMachine? before = some event.state)
      (worldExact : originalExecutionWorld? before = some event.world)
      (siteExact : event.siteId = site.id)
      (transitionExact :
        (program.pe32TransitionSystem.step before).observation =
          some (.external event.world event.imported event.arguments)) :
      OriginalBoundaryRequestReachable inventory site eventIndex event

/-- Program-wide domain authority.  `reachedAdmitted` is the only bridge from
the one-sided combined invariant to a response law. -/
structure CheckedOriginalCombinedReachableBoundaryDomain
    (context : StaticProofContext) (program : DecodedWorldProgram)
    (originalContext : InterpreterMixedContext.OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    (sites : List OpaqueLockstepCallSite) where
  domain : forall site, site ∈ sites ->
    CheckedReachableWorldNativeBoundaryDomain context program site
  reachedAdmitted : forall site (member : site ∈ sites)
      (request : WorldNativeBoundaryRequest),
    OriginalBoundaryRequestReachable inventory site request.eventIndex
        request.originalEvent ->
      request.BoundaryRelated context site ->
      (domain site member).Admits request

/-- One nested protocol request retains the exact source suspension, callback
stack, and native boundary that will consume the next protocol action. -/
structure WorldNativeProtocolBoundaryRequest
    (candidate : ExactNestedNativeWorldProgram) where
  suspension : WorldExternalSuspension
  callbacks : List WorldExternalCallbackRuntime
  boundary : ExactNestedNativeExternalProtocolBoundary candidate

def WorldNativeProtocolBoundaryRequest.Related
    {candidate : ExactNestedNativeWorldProgram}
    (mixed : MixedRelationContract) (frames : MixedNestedExternalFrameContract)
    (request : WorldNativeProtocolBoundaryRequest candidate) : Prop :=
  MixedNestedExternalSuspensionsRelated mixed frames request.suspension
    request.callbacks request.boundary.suspension request.boundary.externalFrames

/-- Protocol-domain authority tied directly to one combined source invariant.
`reachedAdmitted` establishes that every retained suspension satisfying that
invariant is admitted; `returningInputs` prevents the response implementation
from using domain membership as an unchecked substitute for machine effects. -/
structure CheckedReachableWorldNativeProtocolBoundaryDomain
    (context : StaticProofContext) (program : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (mixed : MixedRelationContract) (frames : MixedNestedExternalFrameContract)
    (originalContext : InterpreterMixedContext.OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program originalContext) where
  Admits : WorldNativeProtocolBoundaryRequest candidate -> Prop
  related : forall request, Admits request -> request.Related mixed frames
  reachedAdmitted : forall request,
    inventory.Holds
        (.awaitingExternal request.suspension request.callbacks) ->
      request.Related mixed frames -> Admits request
  returningInputs : forall request, Admits request -> forall contract,
    CheckedOriginalMachineProtocolBoundary program request.suspension contract ->
      MachineResponseInputAdmissible false context
          (protocolReturnContract contract) request.suspension.currentEvent /\
        MachineResponseInputAdmissible true context
          (protocolReturnContract contract)
          (request.boundary.suspension.currentWorldEvent
            request.suspension.siteId)

theorem CheckedReachableWorldNativeProtocolBoundaryDomain.everySuspensionAdmitted
    {context : StaticProofContext} {program : DecodedWorldProgram}
    {candidate : ExactNestedNativeWorldProgram}
    {mixed : MixedRelationContract} {frames : MixedNestedExternalFrameContract}
    {originalContext : InterpreterMixedContext.OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    (domain : CheckedReachableWorldNativeProtocolBoundaryDomain context program
      candidate mixed frames originalContext inventory)
    (request : WorldNativeProtocolBoundaryRequest candidate)
    (holds : inventory.Holds
      (.awaitingExternal request.suspension request.callbacks))
    (related : request.Related mixed frames) :
    domain.Admits request :=
  domain.reachedAdmitted request holds related

/-- Launch-rooted form used by acceptance.  The checked execution domain proves
that the actual path endpoint remains in its invariant; the supplied projection
then exposes the complete combined inventory needed by response admission. -/
theorem CheckedReachableWorldNativeProtocolBoundaryDomain.pathSuspensionAdmitted
    {context : StaticProofContext} {program : DecodedWorldProgram}
    {candidate : ExactNestedNativeWorldProgram}
    {mixed : MixedRelationContract} {frames : MixedNestedExternalFrameContract}
    {originalContext : InterpreterMixedContext.OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {root : WorldExecution}
    (domain : CheckedReachableWorldNativeProtocolBoundaryDomain context program
      candidate mixed frames originalContext inventory)
    (executionDomain : CheckedExecutionDomain program root)
    (projects : forall execution, executionDomain.holds execution ->
      inventory.Holds execution)
    (request : WorldNativeProtocolBoundaryRequest candidate)
    {observations : List WorldRelationalObservable}
    (path : NonemptyRelatedPath program.pe32TransitionSystem root observations
      (.awaitingExternal request.suspension request.callbacks))
    (related : request.Related mixed frames) :
    domain.Admits request := by
  apply domain.everySuspensionAdmitted request
  · exact projects _ (executionDomain.pathClosed executionDomain.rootHolds path)
  · exact related

#print axioms CheckedReachableWorldNativeProtocolBoundaryDomain.everySuspensionAdmitted
#print axioms CheckedReachableWorldNativeProtocolBoundaryDomain.pathSuspensionAdmitted

end StageA.Relational.NativeSource
