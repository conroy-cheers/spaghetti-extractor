import StageA.RelationalInterpreterMixedWorldBridge

namespace StageA.Relational.InterpreterMixedEnvironment

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

/-! # Exact one-to-one mixed external environments

This module connects decoded-original protocol suspensions to exact native
candidate external actions.  It deliberately supplies no API semantics.
Instead, a caller proves pointwise refinement of the two concrete environment
functions at an exact event index, protocol phase, and normalized import
identity.

The original transition system emits the external observation while entering
`WorldExecution.awaitingExternal`, then consumes its protocol action in a
second transition.  The native candidate consumes its action synchronously in
the external-call instruction.  The chunk theorem below derives the resulting
two-step/one-step paths from those local transition facts; it does not accept a
submitted final path.

The compatibility theorem first retained below covers synchronous return and
termination actions.  The callback-capable theorem uses
`ExactNestedNativeWorldProgram`: its external suspension and callback-frame
stack are operational state, callback targets must belong to a checked
executable inventory, and a callback return re-enters the suspended protocol
action.  Candidate `blocked` actions have no related case and fail closed. -/

-- This supersedes the former diagnostic-only `MixedExternalCallbackFrontier`.

/-- Relations for control and nested runtime frames at an external boundary.
The relations remain profile inputs because the decoded original uses target
IDs while the native candidate uses concrete RVAs and return-address frames. -/
structure MixedExternalFrameContract where
  continuationTargetsRelated : Nat -> Nat -> Prop
  callFramesRelated :
    List Nat -> List WorldExternalCallbackRuntime -> List NativeCallFrame -> Prop

/-- Explicit frame facts at one paired external call.  Existing callback
frames are included rather than silently discarded. -/
def MixedExternalFrameBoundaryRelated
    (frames : MixedExternalFrameContract)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (candidateContinuationRva : Nat)
    (candidateCalls : List NativeCallFrame) : Prop :=
  frames.continuationTargetsRelated suspension.continuationTargetId
      candidateContinuationRva /\
    frames.callFramesRelated suspension.calls callbacks candidateCalls

/-- One local decoded-original transition that emits the external event and
enters the protocol suspension.  This is a transition-function equality, not
an arbitrary path supplied by generated metadata. -/
structure ExactOriginalExternalDispatch
    (original : DecodedWorldProgram)
    (before : WorldExecution)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime) : Prop where
  transitionExact :
    original.pe32TransitionSystem.step before = {
      next := .awaitingExternal suspension callbacks
      observation := some
        (.external suspension.world suspension.imported suspension.arguments)
    }

/-- Exact candidate instruction boundary for one synchronous external call. -/
structure ExactNativeExternalDispatch
    (candidate : ExactNativeWorldProgram) where
  sourceRva : Nat
  undefinedSlot : Nat
  beforeState : MachineState
  decodedState : MachineState
  calls : List NativeCallFrame
  eventIndex : Nat
  priorEvents : List NativeExternalEvent
  world : RelationalWorld
  imported : PEImport
  arguments : List Word
  continuationRva : Nat
  decodedExact :
    stepKernelPE32Instruction candidate.pe candidate.imports
        (.running sourceRva undefinedSlot beforeState) =
      .stopped (.externalCall imported arguments continuationRva) decodedState

def ExactNativeExternalDispatch.event
    (dispatch : ExactNativeExternalDispatch candidate) : NativeExternalEvent := {
  imported := dispatch.imported
  arguments := dispatch.arguments
  state := dispatch.decodedState
}

def ExactNativeExternalDispatch.boundary
    (dispatch : ExactNativeExternalDispatch candidate) : NativeExternalBoundary := {
  eventIndex := dispatch.eventIndex
  event := dispatch.event
  world := dispatch.world
}

def ExactNativeExternalDispatch.before
    (dispatch : ExactNativeExternalDispatch candidate) : NativeWorldExecution :=
  .running dispatch.sourceRva dispatch.undefinedSlot dispatch.beforeState
    dispatch.calls dispatch.eventIndex dispatch.priorEvents dispatch.world

def ExactNativeExternalDispatch.action
    (dispatch : ExactNativeExternalDispatch candidate) : NativeWorldExternalAction :=
  candidate.environment.action dispatch.eventIndex dispatch.event dispatch.world

def ExactNativeExternalDispatch.after
    (dispatch : ExactNativeExternalDispatch candidate) : NativeWorldExecution :=
  (applyNativeWorldExternalAction dispatch.continuationRva dispatch.calls
    dispatch.eventIndex dispatch.priorEvents dispatch.event dispatch.world
    dispatch.action).next

def ExactNativeExternalDispatch.observation
    (dispatch : ExactNativeExternalDispatch candidate) :
    WorldRelationalObservable :=
  .external dispatch.world (normalizeImport dispatch.imported) dispatch.arguments

def originalExternalObservation
    (suspension : WorldExternalSuspension) : WorldRelationalObservable :=
  .external suspension.world suspension.imported suspension.arguments

def originalExternalAfter (original : DecodedWorldProgram)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime) : WorldExecution :=
  (stepWorldExternalSuspension original suspension callbacks).next

/-- Compatibility relation for the original synchronous native execution
carrier.  Callback actions use the nested carrier defined below. -/
def MixedExternalEnvironmentActionsRelated
    (contract : MixedRelationContract) :
    WorldExternalProtocolAction -> NativeWorldExternalAction -> Prop
  | .returned originalResult, .returned candidateResult =>
      contract.worldsRelated originalResult.world candidateResult.world /\
        contract.runtimeStatesRelated originalResult.world candidateResult.world
          originalResult.state candidateResult.state
  | .terminated originalWorld, .terminated candidateWorld =>
      contract.worldsRelated originalWorld candidateWorld
  | _, _ => False

/-- A profile-level exact 1:1 environment premise.  The antecedents require
the event index, normalized import, arguments, call state, worlds, continuation,
and nested frames to be related before the concrete environment actions may be
used. -/
def ExactOneToOneMixedExternalEnvironmentsRefine
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedExternalFrameContract) : Prop :=
  forall (suspension : WorldExternalSuspension)
      (callbacks : List WorldExternalCallbackRuntime)
      (dispatch : ExactNativeExternalDispatch candidate),
    contract.externalBoundariesRelated suspension dispatch.boundary ->
      MixedExternalFrameBoundaryRelated frames suspension callbacks
        dispatch.continuationRva dispatch.calls ->
      MixedExternalEnvironmentActionsRelated contract
        (original.protocolEnvironment.action suspension.request) dispatch.action

/-- Exact successor forms for external chunks.  Return successors retain the
decoded call stack, callback stack, native call frames, event index, and event
history by construction.  Faults are related only when their modeled causes
are equal.  There is intentionally no blocked constructor. -/
inductive MixedExternalSuccessorsRelated
    (contract : MixedRelationContract)
    (frames : MixedExternalFrameContract)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (dispatch : ExactNativeExternalDispatch candidate) :
    WorldExecution -> NativeWorldExecution -> Prop where
  | returned (originalResult candidateResult : WorldExternalResult)
      (worldsRelated :
        contract.worldsRelated originalResult.world candidateResult.world)
      (statesRelated :
        contract.runtimeStatesRelated originalResult.world candidateResult.world
          originalResult.state candidateResult.state)
      (continuationsRelated :
        frames.continuationTargetsRelated suspension.continuationTargetId
          dispatch.continuationRva)
      (callFramesRelated :
        frames.callFramesRelated suspension.calls callbacks dispatch.calls) :
      MixedExternalSuccessorsRelated contract frames suspension callbacks dispatch
        (resumeWorldExecution callbacks suspension.continuationTargetId
          originalResult.state suspension.calls (suspension.eventIndex + 1)
          originalResult.world)
        (.running dispatch.continuationRva 0 candidateResult.state dispatch.calls
          (dispatch.eventIndex + 1) (dispatch.priorEvents ++ [dispatch.event])
          candidateResult.world)
  | terminated (originalWorld candidateWorld : RelationalWorld)
      (worldsRelated : contract.worldsRelated originalWorld candidateWorld) :
      MixedExternalSuccessorsRelated contract frames suspension callbacks dispatch
        (.terminated originalWorld)
        (.terminated (dispatch.priorEvents ++ [dispatch.event]) candidateWorld)
  | fault (originalCause candidateCause : ModeledFault)
      (causesRelated : originalCause = candidateCause) :
      MixedExternalSuccessorsRelated contract frames suspension callbacks dispatch
        (.fault originalCause) (.fault candidateCause)

theorem MixedExternalSuccessorsRelated.fault_causes_equal
    (related : MixedExternalSuccessorsRelated contract frames suspension callbacks
      dispatch (.fault originalCause) (.fault candidateCause)) :
    originalCause = candidateCause := by
  cases callbacks <;> cases related with
  | fault _ _ causesRelated => exact causesRelated

theorem externalBoundaryObservationsRelated
    (contract : MixedRelationContract)
    (suspension : WorldExternalSuspension)
    (boundary : NativeExternalBoundary)
    (related : contract.externalBoundariesRelated suspension boundary) :
    contract.eventObservationsRelated
      (some (originalExternalObservation suspension))
      (some (.external boundary.world (normalizeImport boundary.event.imported)
        boundary.event.arguments)) := by
  rcases related with
    ⟨_, _, _, _, _, _, imported, worlds, _, arguments⟩
  exact ⟨worlds, imported, arguments⟩

theorem MixedExternalEnvironmentActionsRelated.candidate_blocked_is_unrelated
    (contract : MixedRelationContract)
    (originalAction : WorldExternalProtocolAction)
    (reason : ExecutionBlock) :
    ¬ MixedExternalEnvironmentActionsRelated contract originalAction
      (.blocked reason) := by
  cases originalAction <;>
    simp [MixedExternalEnvironmentActionsRelated]

theorem MixedExternalEnvironmentActionsRelated.callback_is_unrelated
    (contract : MixedRelationContract)
    (entry : WorldExternalCallbackAction)
    (candidateAction : NativeWorldExternalAction) :
    ¬ MixedExternalEnvironmentActionsRelated contract (.callback entry)
      candidateAction := by
  cases candidateAction <;>
    simp [MixedExternalEnvironmentActionsRelated]

theorem MixedExternalEnvironmentActionsRelated.candidate_callback_is_unrelated
    (contract : MixedRelationContract)
    (originalAction : WorldExternalProtocolAction)
    (entry : NativeWorldExternalCallbackAction) :
    ¬ MixedExternalEnvironmentActionsRelated contract originalAction
      (.callback entry) := by
  cases originalAction <;>
    simp [MixedExternalEnvironmentActionsRelated]

theorem ExactNativeExternalDispatch.path
    (dispatch : ExactNativeExternalDispatch candidate)
    (notCallback : forall entry, dispatch.action ≠ .callback entry)
    (notBlocked : forall reason, dispatch.action ≠ .blocked reason) :
    NonemptyRelatedPath candidate.transitionSystem dispatch.before
      [dispatch.observation] dispatch.after := by
  have one := exactNativeWorldStepIsNonempty candidate dispatch.before
  unfold ExactNativeExternalDispatch.before at one
  simp only [ExactNativeWorldProgram.transitionSystem,
    stepPE32NativeWorldExecution, dispatch.decodedExact,
    transitionFromNativeWorldOutcome] at one
  unfold ExactNativeExternalDispatch.after
    ExactNativeExternalDispatch.action
    ExactNativeExternalDispatch.event
    ExactNativeExternalDispatch.observation
  cases actionExact : candidate.environment.action dispatch.eventIndex
      { imported := dispatch.imported, arguments := dispatch.arguments,
        state := dispatch.decodedState } dispatch.world with
  | returned result =>
      simpa [applyNativeWorldExternalAction, actionExact] using one
  | terminated world =>
      simpa [applyNativeWorldExternalAction, actionExact] using one
  | callback entry =>
      exact False.elim (notCallback entry actionExact)
  | blocked reason =>
      exact False.elim (notBlocked reason actionExact)

/-- The action relation determines the exact operational successors and rules
out callback/blocked mismatches. -/
theorem mixedExternalActions_successorsRelated
    (original : DecodedWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedExternalFrameContract)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (dispatch : ExactNativeExternalDispatch candidate)
    (frameBoundary : MixedExternalFrameBoundaryRelated frames suspension callbacks
      dispatch.continuationRva dispatch.calls)
    (actionsRelated : MixedExternalEnvironmentActionsRelated contract
      (original.protocolEnvironment.action suspension.request) dispatch.action) :
    MixedExternalSuccessorsRelated contract frames suspension callbacks dispatch
      (originalExternalAfter original suspension callbacks) dispatch.after := by
  unfold ExactNativeExternalDispatch.action at actionsRelated
  unfold originalExternalAfter ExactNativeExternalDispatch.after
  cases originalAction : original.protocolEnvironment.action suspension.request <;>
    cases candidateAction : candidate.environment.action dispatch.eventIndex
      dispatch.event dispatch.world <;>
    simp [originalAction, candidateAction, MixedExternalEnvironmentActionsRelated]
      at actionsRelated
  case returned.returned originalResult candidateResult =>
    simpa [originalExternalAfter, stepWorldExternalSuspension, originalAction,
      ExactNativeExternalDispatch.after, ExactNativeExternalDispatch.action,
      candidateAction, applyNativeWorldExternalAction] using
      (MixedExternalSuccessorsRelated.returned originalResult candidateResult
        actionsRelated.1 actionsRelated.2 frameBoundary.1 frameBoundary.2)
  case terminated.terminated originalWorld candidateWorld =>
    simpa [originalExternalAfter, stepWorldExternalSuspension, originalAction,
      ExactNativeExternalDispatch.after, ExactNativeExternalDispatch.action,
      candidateAction, applyNativeWorldExternalAction] using
      (MixedExternalSuccessorsRelated.terminated originalWorld candidateWorld
        actionsRelated)

/-- Operational external chunk derived from one original dispatch transition,
one original protocol transition, and one candidate decoded instruction. -/
structure ExactMixedExternalInteractionChunk
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedExternalFrameContract)
    (originalBefore : WorldExecution)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (dispatch : ExactNativeExternalDispatch candidate) : Prop where
  originalPath : NonemptyRelatedPath original.pe32TransitionSystem originalBefore
    [originalExternalObservation suspension]
    (originalExternalAfter original suspension callbacks)
  candidatePath : NonemptyRelatedPath candidate.transitionSystem dispatch.before
    [dispatch.observation] dispatch.after
  observationsRelated : RelatedObservationLists contract.eventObservationsRelated
    [originalExternalObservation suspension] [dispatch.observation]
  successorsRelated : MixedExternalSuccessorsRelated contract frames suspension
    callbacks dispatch (originalExternalAfter original suspension callbacks)
    dispatch.after

theorem exactMixedExternalInteractionChunk
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedExternalFrameContract)
    (originalBefore : WorldExecution)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (dispatch : ExactNativeExternalDispatch candidate)
    (originalDispatch : ExactOriginalExternalDispatch original originalBefore
      suspension callbacks)
    (boundaryRelated :
      contract.externalBoundariesRelated suspension dispatch.boundary)
    (frameBoundary : MixedExternalFrameBoundaryRelated frames suspension callbacks
      dispatch.continuationRva dispatch.calls)
    (environmentsRefine : ExactOneToOneMixedExternalEnvironmentsRefine original
      candidate contract frames) :
    ExactMixedExternalInteractionChunk original candidate contract frames
      originalBefore suspension callbacks dispatch := by
  have actionsRelated := environmentsRefine suspension callbacks dispatch
    boundaryRelated frameBoundary
  have candidateNotBlocked : forall reason, dispatch.action ≠ .blocked reason := by
    intro reason blocked
    exact (MixedExternalEnvironmentActionsRelated.candidate_blocked_is_unrelated
      contract (original.protocolEnvironment.action suspension.request) reason)
      (blocked ▸ actionsRelated)
  have candidateNotCallback : forall entry, dispatch.action ≠ .callback entry := by
    intro entry callback
    exact (MixedExternalEnvironmentActionsRelated.candidate_callback_is_unrelated
      contract (original.protocolEnvironment.action suspension.request) entry) (by
      rw [← callback]
      exact actionsRelated)
  have originalFirst := nonemptyRelatedPath_one original.pe32TransitionSystem
    originalBefore
  rw [originalDispatch.transitionExact] at originalFirst
  have originalSecond := nonemptyRelatedPath_one original.pe32TransitionSystem
    (.awaitingExternal suspension callbacks)
  change NonemptyRelatedPath original.pe32TransitionSystem
    (.awaitingExternal suspension callbacks)
    (stepWorldExternalSuspension original suspension callbacks).observation.toList
    (originalExternalAfter original suspension callbacks) at originalSecond
  have candidatePath := dispatch.path candidateNotCallback candidateNotBlocked
  have successors := mixedExternalActions_successorsRelated original contract frames
    suspension callbacks dispatch frameBoundary actionsRelated
  have observations := externalBoundaryObservationsRelated contract suspension
    dispatch.boundary boundaryRelated
  unfold ExactNativeExternalDispatch.action at actionsRelated
  cases originalAction : original.protocolEnvironment.action suspension.request <;>
    cases candidateAction : candidate.environment.action dispatch.eventIndex
      dispatch.event dispatch.world <;>
    simp [originalAction, candidateAction, MixedExternalEnvironmentActionsRelated]
      at actionsRelated
  case returned.returned originalResult candidateResult =>
    have originalPath : NonemptyRelatedPath original.pe32TransitionSystem
        originalBefore [originalExternalObservation suspension]
        (originalExternalAfter original suspension callbacks) := by
      simpa [originalExternalAfter, stepWorldExternalSuspension, originalAction]
        using originalFirst.trans originalSecond
    exact ⟨originalPath, candidatePath, ⟨observations, True.intro⟩, successors⟩
  case terminated.terminated originalWorld candidateWorld =>
    have originalPath : NonemptyRelatedPath original.pe32TransitionSystem
        originalBefore [originalExternalObservation suspension]
        (originalExternalAfter original suspension callbacks) := by
      simpa [originalExternalAfter, stepWorldExternalSuspension, originalAction]
        using originalFirst.trans originalSecond
    exact ⟨originalPath, candidatePath, ⟨observations, True.intro⟩, successors⟩

/-- Convert the specialized external chunk into the generic mixed-composition
chunk once the caller establishes the shared inductive invariant at both ends. -/
def ExactMixedExternalInteractionChunk.toComponent
    {reachabilityTargetIds : List Nat}
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (chunk : ExactMixedExternalInteractionChunk original candidate contract frames
      originalBefore suspension callbacks dispatch)
    (beforeRelated : invariant.holds originalBefore dispatch.before)
    (afterRelated : invariant.holds
      (originalExternalAfter original suspension callbacks) dispatch.after) :
    MixedWorldComponentChunkRefinement original candidate contract invariant
      originalBefore dispatch.before := {
  beforeRelated
  originalObservations := [originalExternalObservation suspension]
  candidateObservations := [dispatch.observation]
  originalAfter := originalExternalAfter original suspension callbacks
  candidateAfter := dispatch.after
  originalPath := chunk.originalPath
  candidatePath := chunk.candidatePath
  observationsRelated := chunk.observationsRelated
  afterRelated
}

/-! ## Callback-capable exact external protocol

The mixed callback profile relates the decoded suspension stack to the native
candidate's explicit external-frame stack.  The recursive relation makes
well-bracketed nesting structural: entering a callback pushes related heads,
and an exact callback return exposes related tails. -/

structure MixedNestedExternalFrameContract extends MixedExternalFrameContract where
  callbackReturnAddressesRelated : Word -> Word -> Prop

def MixedNestedExternalSuspensionCoreRelated
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (original : WorldExternalSuspension)
    (originalCallbacks : List WorldExternalCallbackRuntime)
    (candidate : NativeWorldExternalSuspension) : Prop :=
  original.event.siteId = original.siteId /\
    original.event.imported = original.imported /\
    original.event.arguments = original.arguments /\
    original.eventIndex = candidate.eventIndex /\
    original.phaseIndex = candidate.phaseIndex /\
    original.imported = normalizeImport candidate.event.imported /\
    contract.worldsRelated original.world candidate.world /\
    contract.runtimeStatesRelated original.world candidate.world
      original.state candidate.state /\
    mixedValuesRelated (contract.valuesRelated original.world candidate.world)
      original.arguments candidate.event.arguments /\
    frames.continuationTargetsRelated original.continuationTargetId
      candidate.continuationRva /\
    frames.callFramesRelated original.calls originalCallbacks candidate.calls

def MixedNestedExternalCallbackEntriesRelated
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (original : WorldExternalCallbackAction)
    (candidate : NativeWorldExternalCallbackAction) : Prop :=
  contract.callbackTargetsRelated original.targetId candidate.targetRva /\
    contract.worldsRelated original.world candidate.world /\
    contract.runtimeStatesRelated original.world candidate.world
      original.state candidate.state /\
    frames.callbackReturnAddressesRelated original.returnAddress
      candidate.returnAddress

inductive MixedNestedExternalCallbackFramesRelated
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract) :
    List WorldExternalCallbackRuntime ->
      List NativeWorldExternalCallbackRuntime -> Prop where
  | nil : MixedNestedExternalCallbackFramesRelated contract frames [] []
  | cons
      (originalFrame : WorldExternalCallbackRuntime)
      (candidateFrame : NativeWorldExternalCallbackRuntime)
      (originalTail : List WorldExternalCallbackRuntime)
      (candidateTail : List NativeWorldExternalCallbackRuntime)
      (suspensionsRelated : MixedNestedExternalSuspensionCoreRelated contract frames
        originalFrame.suspension originalTail candidateFrame.suspension)
      (entriesRelated : MixedNestedExternalCallbackEntriesRelated contract frames
        originalFrame.entry candidateFrame.entry)
      (tailsRelated : MixedNestedExternalCallbackFramesRelated contract frames
        originalTail candidateTail) :
      MixedNestedExternalCallbackFramesRelated contract frames
        (originalFrame :: originalTail) (candidateFrame :: candidateTail)

def MixedNestedExternalSuspensionsRelated
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (original : WorldExternalSuspension)
    (originalCallbacks : List WorldExternalCallbackRuntime)
    (candidate : NativeWorldExternalSuspension)
    (candidateFrames : List NativeWorldExternalCallbackRuntime) : Prop :=
  MixedNestedExternalSuspensionCoreRelated contract frames original
      originalCallbacks candidate /\
    MixedNestedExternalCallbackFramesRelated contract frames originalCallbacks
      candidateFrames

theorem MixedNestedExternalCallbackFramesRelated.tail
    (related : MixedNestedExternalCallbackFramesRelated contract frames
      (originalFrame :: originalTail) (candidateFrame :: candidateTail)) :
    MixedNestedExternalCallbackFramesRelated contract frames originalTail
      candidateTail := by
  cases related with
  | cons _ _ _ _ _ _ tailsRelated => exact tailsRelated

structure ExactNestedNativeExternalDispatch
    (candidate : ExactNestedNativeWorldProgram) where
  sourceRva : Nat
  undefinedSlot : Nat
  beforeState : MachineState
  decodedState : MachineState
  calls : List NativeCallFrame
  eventIndex : Nat
  priorEvents : List NativeExternalEvent
  world : RelationalWorld
  externalFrames : List NativeWorldExternalCallbackRuntime
  imported : PEImport
  arguments : List Word
  continuationRva : Nat
  decodedExact :
    stepKernelPE32Instruction candidate.pe candidate.imports
        (.running sourceRva undefinedSlot beforeState) =
      .stopped (.externalCall imported arguments continuationRva) decodedState

def ExactNestedNativeExternalDispatch.event
    (dispatch : ExactNestedNativeExternalDispatch candidate) :
    NativeExternalEvent := {
  imported := dispatch.imported
  arguments := dispatch.arguments
  state := dispatch.decodedState
}

def ExactNestedNativeExternalDispatch.suspension
    (dispatch : ExactNestedNativeExternalDispatch candidate) :
    NativeWorldExternalSuspension := {
  continuationRva := dispatch.continuationRva
  calls := dispatch.calls
  eventIndex := dispatch.eventIndex
  phaseIndex := 0
  event := dispatch.event
  state := dispatch.decodedState
  events := dispatch.priorEvents ++ [dispatch.event]
  world := dispatch.world
}

def ExactNestedNativeExternalDispatch.boundary
    (dispatch : ExactNestedNativeExternalDispatch candidate) :
    NativeExternalBoundary := {
  eventIndex := dispatch.eventIndex
  event := dispatch.event
  world := dispatch.world
}

def ExactNestedNativeExternalDispatch.before
    (dispatch : ExactNestedNativeExternalDispatch candidate) :
    NestedNativeWorldExecution :=
  .running dispatch.sourceRva dispatch.undefinedSlot dispatch.beforeState
    dispatch.calls dispatch.eventIndex dispatch.priorEvents dispatch.world
    dispatch.externalFrames

def ExactNestedNativeExternalDispatch.afterDispatch
    (dispatch : ExactNestedNativeExternalDispatch candidate) :
    NestedNativeWorldExecution :=
  .awaitingExternal dispatch.suspension dispatch.externalFrames

def ExactNestedNativeExternalDispatch.action
    (dispatch : ExactNestedNativeExternalDispatch candidate) :
    NativeWorldExternalAction :=
  candidate.protocolAction dispatch.suspension.request

def ExactNestedNativeExternalDispatch.afterAction
    (dispatch : ExactNestedNativeExternalDispatch candidate) :
    NestedNativeWorldExecution :=
  (applyNestedNativeWorldExternalAction candidate dispatch.suspension
    dispatch.externalFrames dispatch.action).next

def ExactNestedNativeExternalDispatch.dispatchObservation
    (dispatch : ExactNestedNativeExternalDispatch candidate) :
    WorldRelationalObservable :=
  .external dispatch.world (normalizeImport dispatch.imported) dispatch.arguments

def ExactNestedNativeExternalDispatch.actionObservation
    (dispatch : ExactNestedNativeExternalDispatch candidate) :
    Option WorldRelationalObservable :=
  (applyNestedNativeWorldExternalAction candidate dispatch.suspension
    dispatch.externalFrames dispatch.action).observation

theorem ExactNestedNativeExternalDispatch.pathToSuspension
    (dispatch : ExactNestedNativeExternalDispatch candidate) :
    NonemptyRelatedPath candidate.transitionSystem dispatch.before
      [dispatch.dispatchObservation] dispatch.afterDispatch := by
  have one := exactNestedNativeWorldStepIsNonempty candidate dispatch.before
  unfold ExactNestedNativeExternalDispatch.before at one
  simp only [ExactNestedNativeWorldProgram.transitionSystem,
    stepPE32NestedNativeWorldExecution, dispatch.decodedExact,
    transitionFromNestedNativeWorldOutcome] at one
  simpa [ExactNestedNativeExternalDispatch.afterDispatch,
    ExactNestedNativeExternalDispatch.suspension,
    ExactNestedNativeExternalDispatch.event,
    ExactNestedNativeExternalDispatch.dispatchObservation,
    suspendNestedNativeWorldExternalCall] using one

theorem ExactNestedNativeExternalDispatch.protocolPath
    (dispatch : ExactNestedNativeExternalDispatch candidate) :
    NonemptyRelatedPath candidate.transitionSystem dispatch.afterDispatch
      dispatch.actionObservation.toList dispatch.afterAction := by
  have one := exactNestedNativeWorldStepIsNonempty candidate dispatch.afterDispatch
  simpa [ExactNestedNativeExternalDispatch.afterDispatch,
    ExactNestedNativeExternalDispatch.actionObservation,
    ExactNestedNativeExternalDispatch.afterAction,
    ExactNestedNativeExternalDispatch.action,
    ExactNestedNativeWorldProgram.transitionSystem,
    stepPE32NestedNativeWorldExecution] using one

def MixedNestedExternalEnvironmentActionsRelated
    (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract) :
    WorldExternalProtocolAction -> NativeWorldExternalAction -> Prop
  | .returned originalResult, .returned candidateResult =>
      contract.worldsRelated originalResult.world candidateResult.world /\
        contract.runtimeStatesRelated originalResult.world candidateResult.world
          originalResult.state candidateResult.state
  | .callback originalEntry, .callback candidateEntry =>
      MixedNestedExternalCallbackEntriesRelated contract frames originalEntry
          candidateEntry /\
        nestedNativeCallbackTargetAllowed candidate candidateEntry.targetRva = true
  | .terminated originalWorld, .terminated candidateWorld =>
      contract.worldsRelated originalWorld candidateWorld
  | _, _ => False

structure ExactNestedNativeExternalProtocolBoundary
    (candidate : ExactNestedNativeWorldProgram) where
  suspension : NativeWorldExternalSuspension
  externalFrames : List NativeWorldExternalCallbackRuntime

def ExactNestedNativeExternalProtocolBoundary.before
    (boundary : ExactNestedNativeExternalProtocolBoundary candidate) :
    NestedNativeWorldExecution :=
  .awaitingExternal boundary.suspension boundary.externalFrames

def ExactNestedNativeExternalProtocolBoundary.action
    (boundary : ExactNestedNativeExternalProtocolBoundary candidate) :
    NativeWorldExternalAction :=
  candidate.protocolAction boundary.suspension.request

def ExactNestedNativeExternalProtocolBoundary.after
    (boundary : ExactNestedNativeExternalProtocolBoundary candidate) :
    NestedNativeWorldExecution :=
  (applyNestedNativeWorldExternalAction candidate boundary.suspension
    boundary.externalFrames boundary.action).next

def ExactNestedNativeExternalProtocolBoundary.observation
    (boundary : ExactNestedNativeExternalProtocolBoundary candidate) :
    Option WorldRelationalObservable :=
  (applyNestedNativeWorldExternalAction candidate boundary.suspension
    boundary.externalFrames boundary.action).observation

theorem ExactNestedNativeExternalProtocolBoundary.path
    (boundary : ExactNestedNativeExternalProtocolBoundary candidate) :
    NonemptyRelatedPath candidate.transitionSystem boundary.before
      boundary.observation.toList boundary.after := by
  have one := exactNestedNativeWorldStepIsNonempty candidate boundary.before
  simpa [ExactNestedNativeExternalProtocolBoundary.before,
    ExactNestedNativeExternalProtocolBoundary.observation,
    ExactNestedNativeExternalProtocolBoundary.after,
    ExactNestedNativeExternalProtocolBoundary.action,
    ExactNestedNativeWorldProgram.transitionSystem,
    stepPE32NestedNativeWorldExecution] using one

def ExactNestedNativeExternalDispatch.protocolBoundary
    (dispatch : ExactNestedNativeExternalDispatch candidate) :
    ExactNestedNativeExternalProtocolBoundary candidate := {
  suspension := dispatch.suspension
  externalFrames := dispatch.externalFrames
}

def ExactOneToOneMixedNestedExternalEnvironmentsRefine
    (original : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract) : Prop :=
  forall (suspension : WorldExternalSuspension)
      (callbacks : List WorldExternalCallbackRuntime)
      (boundary : ExactNestedNativeExternalProtocolBoundary candidate),
    MixedNestedExternalSuspensionsRelated contract frames suspension callbacks
      boundary.suspension boundary.externalFrames ->
    MixedNestedExternalEnvironmentActionsRelated candidate contract frames
      (original.protocolEnvironment.action suspension.request) boundary.action

inductive MixedNestedExternalSuccessorsRelated
    (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (dispatch : ExactNestedNativeExternalDispatch candidate) :
    WorldExecution -> NestedNativeWorldExecution -> Prop where
  | returned (originalResult candidateResult : WorldExternalResult)
      (worldsRelated :
        contract.worldsRelated originalResult.world candidateResult.world)
      (statesRelated :
        contract.runtimeStatesRelated originalResult.world candidateResult.world
          originalResult.state candidateResult.state)
      (suspensionsRelated : MixedNestedExternalSuspensionsRelated contract frames
        suspension callbacks dispatch.suspension dispatch.externalFrames) :
      MixedNestedExternalSuccessorsRelated candidate contract frames suspension
        callbacks dispatch
        (resumeWorldExecution callbacks suspension.continuationTargetId
          originalResult.state suspension.calls (suspension.eventIndex + 1)
          originalResult.world)
        (resumeNestedNativeWorldExecution dispatch.suspension
          dispatch.externalFrames candidateResult)
  | callback (originalEntry : WorldExternalCallbackAction)
      (candidateEntry : NativeWorldExternalCallbackAction)
      (suspensionsRelated : MixedNestedExternalSuspensionsRelated contract frames
        suspension callbacks dispatch.suspension dispatch.externalFrames)
      (entriesRelated : MixedNestedExternalCallbackEntriesRelated contract frames
        originalEntry candidateEntry)
      (targetAllowed :
        nestedNativeCallbackTargetAllowed candidate candidateEntry.targetRva = true) :
      MixedNestedExternalSuccessorsRelated candidate contract frames suspension
        callbacks dispatch
        (.callbackRunning originalEntry.targetId originalEntry.state []
          suspension.eventIndex originalEntry.world
          ({ suspension, entry := originalEntry } :: callbacks))
        (.running candidateEntry.targetRva 0 candidateEntry.state []
          dispatch.suspension.eventIndex dispatch.suspension.events
          candidateEntry.world
          ({ suspension := dispatch.suspension, entry := candidateEntry } ::
            dispatch.externalFrames))
  | terminated (originalWorld candidateWorld : RelationalWorld)
      (worldsRelated : contract.worldsRelated originalWorld candidateWorld) :
      MixedNestedExternalSuccessorsRelated candidate contract frames suspension
        callbacks dispatch (.terminated originalWorld)
        (.terminated dispatch.suspension.events candidateWorld)

theorem mixedNestedExternalActions_successorsRelated
    (original : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (dispatch : ExactNestedNativeExternalDispatch candidate)
    (suspensionsRelated : MixedNestedExternalSuspensionsRelated contract frames
      suspension callbacks dispatch.suspension dispatch.externalFrames)
    (actionsRelated : MixedNestedExternalEnvironmentActionsRelated candidate
      contract frames (original.protocolEnvironment.action suspension.request)
      dispatch.action) :
    MixedNestedExternalSuccessorsRelated candidate contract frames suspension
      callbacks dispatch (originalExternalAfter original suspension callbacks)
      dispatch.afterAction := by
  unfold ExactNestedNativeExternalDispatch.action at actionsRelated
  unfold originalExternalAfter ExactNestedNativeExternalDispatch.afterAction
  cases originalAction : original.protocolEnvironment.action suspension.request <;>
    cases candidateAction : candidate.protocolAction dispatch.suspension.request <;>
    simp [originalAction, candidateAction,
      MixedNestedExternalEnvironmentActionsRelated] at actionsRelated
  case returned.returned originalResult candidateResult =>
    simpa [stepWorldExternalSuspension, originalAction,
      applyNestedNativeWorldExternalAction, candidateAction,
      ExactNestedNativeExternalDispatch.action] using
      (MixedNestedExternalSuccessorsRelated.returned
        (candidate := candidate) (contract := contract) (frames := frames)
        (suspension := suspension) (callbacks := callbacks) (dispatch := dispatch)
        originalResult candidateResult
        actionsRelated.1 actionsRelated.2 suspensionsRelated)
  case callback.callback originalEntry candidateEntry =>
    simpa [stepWorldExternalSuspension, originalAction,
      applyNestedNativeWorldExternalAction, candidateAction, actionsRelated.2,
      ExactNestedNativeExternalDispatch.action] using
      (MixedNestedExternalSuccessorsRelated.callback
        (candidate := candidate) (contract := contract) (frames := frames)
        (suspension := suspension) (callbacks := callbacks) (dispatch := dispatch)
        originalEntry candidateEntry
        suspensionsRelated actionsRelated.1 actionsRelated.2)
  case terminated.terminated originalWorld candidateWorld =>
    simpa [stepWorldExternalSuspension, originalAction,
      applyNestedNativeWorldExternalAction, candidateAction,
      ExactNestedNativeExternalDispatch.action] using
      (MixedNestedExternalSuccessorsRelated.terminated
        (candidate := candidate) (contract := contract) (frames := frames)
        (suspension := suspension) (callbacks := callbacks) (dispatch := dispatch)
        originalWorld candidateWorld
        actionsRelated)

theorem mixedNestedExternalActionObservationsRelated
    (original : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (dispatch : ExactNestedNativeExternalDispatch candidate)
    (actionsRelated : MixedNestedExternalEnvironmentActionsRelated candidate
      contract frames (original.protocolEnvironment.action suspension.request)
      dispatch.action) :
    contract.eventObservationsRelated
      (stepWorldExternalSuspension original suspension callbacks).observation
      dispatch.actionObservation := by
  unfold ExactNestedNativeExternalDispatch.action at actionsRelated
  unfold ExactNestedNativeExternalDispatch.actionObservation
    ExactNestedNativeExternalDispatch.action
  cases originalAction : original.protocolEnvironment.action suspension.request <;>
    cases candidateAction : candidate.protocolAction dispatch.suspension.request <;>
    simp [stepWorldExternalSuspension, originalAction, candidateAction,
      applyNestedNativeWorldExternalAction,
      MixedNestedExternalEnvironmentActionsRelated] at actionsRelated ⊢
  case callback.callback originalEntry candidateEntry =>
    rw [if_pos actionsRelated.2]
    exact ⟨actionsRelated.1.2.1, actionsRelated.1.1⟩
  case returned.returned =>
    trivial
  case terminated.terminated =>
    trivial

theorem mixedRelatedObservationOptions_toLists
    (contract : MixedRelationContract)
    {original candidate : Option WorldRelationalObservable}
    (related : contract.eventObservationsRelated original candidate) :
    RelatedObservationLists contract.eventObservationsRelated original.toList
      candidate.toList := by
  cases original <;> cases candidate <;>
    simp_all [MixedRelationContract.eventObservationsRelated,
      RelatedObservationLists]

theorem prependRelatedObservationLists
    {relation : Option originalObservation -> Option candidateObservation -> Prop}
    {originalHead : originalObservation} {candidateHead : candidateObservation}
    {originalTail : List originalObservation}
    {candidateTail : List candidateObservation}
    (headRelated : relation (some originalHead) (some candidateHead))
    (tailRelated : RelatedObservationLists relation originalTail candidateTail) :
    RelatedObservationLists relation (originalHead :: originalTail)
      (candidateHead :: candidateTail) :=
  ⟨headRelated, tailRelated⟩

structure ExactMixedNestedExternalInteractionChunk
    (original : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (originalBefore : WorldExecution)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (dispatch : ExactNestedNativeExternalDispatch candidate) : Prop where
  originalPath : NonemptyRelatedPath original.pe32TransitionSystem originalBefore
    ([originalExternalObservation suspension] ++
      (stepWorldExternalSuspension original suspension callbacks).observation.toList)
    (originalExternalAfter original suspension callbacks)
  candidatePath : NonemptyRelatedPath candidate.transitionSystem dispatch.before
    ([dispatch.dispatchObservation] ++ dispatch.actionObservation.toList)
    dispatch.afterAction
  observationsRelated : RelatedObservationLists contract.eventObservationsRelated
    ([originalExternalObservation suspension] ++
      (stepWorldExternalSuspension original suspension callbacks).observation.toList)
    ([dispatch.dispatchObservation] ++ dispatch.actionObservation.toList)
  successorsRelated : MixedNestedExternalSuccessorsRelated candidate contract frames
    suspension callbacks dispatch (originalExternalAfter original suspension callbacks)
    dispatch.afterAction

theorem exactMixedNestedExternalInteractionChunk
    (original : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (originalBefore : WorldExecution)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (dispatch : ExactNestedNativeExternalDispatch candidate)
    (originalDispatch : ExactOriginalExternalDispatch original originalBefore
      suspension callbacks)
    (boundaryRelated :
      contract.externalBoundariesRelated suspension dispatch.boundary)
    (suspensionsRelated : MixedNestedExternalSuspensionsRelated contract frames
      suspension callbacks dispatch.suspension dispatch.externalFrames)
    (environmentsRefine : ExactOneToOneMixedNestedExternalEnvironmentsRefine
      original candidate contract frames) :
    ExactMixedNestedExternalInteractionChunk original candidate contract frames
      originalBefore suspension callbacks dispatch := by
  have actionsRelated := environmentsRefine suspension callbacks
    dispatch.protocolBoundary
    suspensionsRelated
  have originalFirst := nonemptyRelatedPath_one original.pe32TransitionSystem
    originalBefore
  rw [originalDispatch.transitionExact] at originalFirst
  have originalSecond := nonemptyRelatedPath_one original.pe32TransitionSystem
    (.awaitingExternal suspension callbacks)
  change NonemptyRelatedPath original.pe32TransitionSystem
    (.awaitingExternal suspension callbacks)
    (stepWorldExternalSuspension original suspension callbacks).observation.toList
    (originalExternalAfter original suspension callbacks) at originalSecond
  have candidateFirst := dispatch.pathToSuspension
  have candidateSecond := dispatch.protocolPath
  have initialObservations := externalBoundaryObservationsRelated contract suspension
    dispatch.boundary boundaryRelated
  have actionObservations := mixedNestedExternalActionObservationsRelated original
    candidate contract frames suspension callbacks dispatch actionsRelated
  have tailObservations := mixedRelatedObservationOptions_toLists contract
    actionObservations
  have observations := prependRelatedObservationLists initialObservations
    tailObservations
  exact {
    originalPath := originalFirst.trans originalSecond
    candidatePath := candidateFirst.trans candidateSecond
    observationsRelated := observations
    successorsRelated := mixedNestedExternalActions_successorsRelated original
      candidate contract frames suspension callbacks dispatch suspensionsRelated
      actionsRelated
  }

inductive MixedNestedExternalProtocolSuccessorsRelated
    (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (boundary : ExactNestedNativeExternalProtocolBoundary candidate) :
    WorldExecution -> NestedNativeWorldExecution -> Prop where
  | returned (originalResult candidateResult : WorldExternalResult)
      (worldsRelated :
        contract.worldsRelated originalResult.world candidateResult.world)
      (statesRelated :
        contract.runtimeStatesRelated originalResult.world candidateResult.world
          originalResult.state candidateResult.state)
      (suspensionsRelated : MixedNestedExternalSuspensionsRelated contract frames
        suspension callbacks boundary.suspension boundary.externalFrames) :
      MixedNestedExternalProtocolSuccessorsRelated candidate contract frames
        suspension callbacks boundary
        (resumeWorldExecution callbacks suspension.continuationTargetId
          originalResult.state suspension.calls (suspension.eventIndex + 1)
          originalResult.world)
        (resumeNestedNativeWorldExecution boundary.suspension
          boundary.externalFrames candidateResult)
  | callback (originalEntry : WorldExternalCallbackAction)
      (candidateEntry : NativeWorldExternalCallbackAction)
      (suspensionsRelated : MixedNestedExternalSuspensionsRelated contract frames
        suspension callbacks boundary.suspension boundary.externalFrames)
      (entriesRelated : MixedNestedExternalCallbackEntriesRelated contract frames
        originalEntry candidateEntry)
      (targetAllowed :
        nestedNativeCallbackTargetAllowed candidate candidateEntry.targetRva = true) :
      MixedNestedExternalProtocolSuccessorsRelated candidate contract frames
        suspension callbacks boundary
        (.callbackRunning originalEntry.targetId originalEntry.state []
          suspension.eventIndex originalEntry.world
          ({ suspension, entry := originalEntry } :: callbacks))
        (.running candidateEntry.targetRva 0 candidateEntry.state []
          boundary.suspension.eventIndex boundary.suspension.events
          candidateEntry.world
          ({ suspension := boundary.suspension, entry := candidateEntry } ::
            boundary.externalFrames))
  | terminated (originalWorld candidateWorld : RelationalWorld)
      (worldsRelated : contract.worldsRelated originalWorld candidateWorld) :
      MixedNestedExternalProtocolSuccessorsRelated candidate contract frames
        suspension callbacks boundary (.terminated originalWorld)
        (.terminated boundary.suspension.events candidateWorld)

theorem mixedNestedExternalProtocolActions_successorsRelated
    (original : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (boundary : ExactNestedNativeExternalProtocolBoundary candidate)
    (suspensionsRelated : MixedNestedExternalSuspensionsRelated contract frames
      suspension callbacks boundary.suspension boundary.externalFrames)
    (actionsRelated : MixedNestedExternalEnvironmentActionsRelated candidate
      contract frames (original.protocolEnvironment.action suspension.request)
      boundary.action) :
    MixedNestedExternalProtocolSuccessorsRelated candidate contract frames
      suspension callbacks boundary (originalExternalAfter original suspension callbacks)
      boundary.after := by
  unfold ExactNestedNativeExternalProtocolBoundary.action at actionsRelated
  unfold originalExternalAfter ExactNestedNativeExternalProtocolBoundary.after
  cases originalAction : original.protocolEnvironment.action suspension.request <;>
    cases candidateAction : candidate.protocolAction boundary.suspension.request <;>
    simp [originalAction, candidateAction,
      MixedNestedExternalEnvironmentActionsRelated] at actionsRelated
  case returned.returned originalResult candidateResult =>
    simpa [stepWorldExternalSuspension, originalAction,
      applyNestedNativeWorldExternalAction, candidateAction,
      ExactNestedNativeExternalProtocolBoundary.action] using
      (MixedNestedExternalProtocolSuccessorsRelated.returned
        (candidate := candidate) (contract := contract) (frames := frames)
        (suspension := suspension) (callbacks := callbacks) (boundary := boundary)
        originalResult candidateResult actionsRelated.1 actionsRelated.2
        suspensionsRelated)
  case callback.callback originalEntry candidateEntry =>
    simpa [stepWorldExternalSuspension, originalAction,
      applyNestedNativeWorldExternalAction, candidateAction, actionsRelated.2,
      ExactNestedNativeExternalProtocolBoundary.action] using
      (MixedNestedExternalProtocolSuccessorsRelated.callback
        (candidate := candidate) (contract := contract) (frames := frames)
        (suspension := suspension) (callbacks := callbacks) (boundary := boundary)
        originalEntry candidateEntry suspensionsRelated actionsRelated.1
        actionsRelated.2)
  case terminated.terminated originalWorld candidateWorld =>
    simpa [stepWorldExternalSuspension, originalAction,
      applyNestedNativeWorldExternalAction, candidateAction,
      ExactNestedNativeExternalProtocolBoundary.action] using
      (MixedNestedExternalProtocolSuccessorsRelated.terminated
        (candidate := candidate) (contract := contract) (frames := frames)
        (suspension := suspension) (callbacks := callbacks) (boundary := boundary)
        originalWorld candidateWorld actionsRelated)

theorem mixedNestedExternalProtocolObservationsRelated
    (original : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (boundary : ExactNestedNativeExternalProtocolBoundary candidate)
    (actionsRelated : MixedNestedExternalEnvironmentActionsRelated candidate
      contract frames (original.protocolEnvironment.action suspension.request)
      boundary.action) :
    contract.eventObservationsRelated
      (stepWorldExternalSuspension original suspension callbacks).observation
      boundary.observation := by
  unfold ExactNestedNativeExternalProtocolBoundary.action at actionsRelated
  unfold ExactNestedNativeExternalProtocolBoundary.observation
    ExactNestedNativeExternalProtocolBoundary.action
  cases originalAction : original.protocolEnvironment.action suspension.request <;>
    cases candidateAction : candidate.protocolAction boundary.suspension.request <;>
    simp [stepWorldExternalSuspension, originalAction, candidateAction,
      applyNestedNativeWorldExternalAction,
      MixedNestedExternalEnvironmentActionsRelated] at actionsRelated ⊢
  case callback.callback originalEntry candidateEntry =>
    rw [if_pos actionsRelated.2]
    exact ⟨actionsRelated.1.2.1, actionsRelated.1.1⟩
  case returned.returned => trivial
  case terminated.terminated => trivial

structure ExactMixedNestedExternalProtocolChunk
    (original : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (boundary : ExactNestedNativeExternalProtocolBoundary candidate) : Prop where
  originalPath : NonemptyRelatedPath original.pe32TransitionSystem
    (.awaitingExternal suspension callbacks)
    (stepWorldExternalSuspension original suspension callbacks).observation.toList
    (originalExternalAfter original suspension callbacks)
  candidatePath : NonemptyRelatedPath candidate.transitionSystem boundary.before
    boundary.observation.toList boundary.after
  observationsRelated : RelatedObservationLists contract.eventObservationsRelated
    (stepWorldExternalSuspension original suspension callbacks).observation.toList
    boundary.observation.toList
  successorsRelated : MixedNestedExternalProtocolSuccessorsRelated candidate
    contract frames suspension callbacks boundary
    (originalExternalAfter original suspension callbacks) boundary.after

theorem exactMixedNestedExternalProtocolChunk
    (original : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (boundary : ExactNestedNativeExternalProtocolBoundary candidate)
    (suspensionsRelated : MixedNestedExternalSuspensionsRelated contract frames
      suspension callbacks boundary.suspension boundary.externalFrames)
    (environmentsRefine : ExactOneToOneMixedNestedExternalEnvironmentsRefine
      original candidate contract frames) :
    ExactMixedNestedExternalProtocolChunk original candidate contract frames
      suspension callbacks boundary := by
  have actionsRelated := environmentsRefine suspension callbacks boundary
    suspensionsRelated
  have originalPath := nonemptyRelatedPath_one original.pe32TransitionSystem
    (.awaitingExternal suspension callbacks)
  change NonemptyRelatedPath original.pe32TransitionSystem
    (.awaitingExternal suspension callbacks)
    (stepWorldExternalSuspension original suspension callbacks).observation.toList
    (originalExternalAfter original suspension callbacks) at originalPath
  have actionObservations := mixedNestedExternalProtocolObservationsRelated original
    candidate contract frames suspension callbacks boundary actionsRelated
  exact {
    originalPath
    candidatePath := boundary.path
    observationsRelated := mixedRelatedObservationOptions_toLists contract
      actionObservations
    successorsRelated := mixedNestedExternalProtocolActions_successorsRelated original
      candidate contract frames suspension callbacks boundary suspensionsRelated
      actionsRelated
  }

structure ExactOriginalExternalCallbackReturnDispatch
    (original : DecodedWorldProgram) where
  targetId : Nat
  beforeState : MachineState
  afterState : MachineState
  eventIndex : Nat
  world : RelationalWorld
  frame : WorldExternalCallbackRuntime
  outerFrames : List WorldExternalCallbackRuntime
  transitionExact :
    original.pe32TransitionSystem.step
        (.callbackRunning targetId beforeState [] eventIndex world
          (frame :: outerFrames)) = {
      next := .awaitingExternal {
        frame.suspension with
        phaseIndex := frame.suspension.phaseIndex + 1
        resumeInvariant := frame.entry.returnInvariant
        state := afterState
        world
      } outerFrames
      observation := none
    }

def ExactOriginalExternalCallbackReturnDispatch.before
    (dispatch : ExactOriginalExternalCallbackReturnDispatch original) :
    WorldExecution :=
  .callbackRunning dispatch.targetId dispatch.beforeState [] dispatch.eventIndex
    dispatch.world (dispatch.frame :: dispatch.outerFrames)

def ExactOriginalExternalCallbackReturnDispatch.afterSuspension
    (dispatch : ExactOriginalExternalCallbackReturnDispatch original) :
    WorldExternalSuspension := {
  dispatch.frame.suspension with
  phaseIndex := dispatch.frame.suspension.phaseIndex + 1
  resumeInvariant := dispatch.frame.entry.returnInvariant
  state := dispatch.afterState
  world := dispatch.world
}

def ExactOriginalExternalCallbackReturnDispatch.after
    (dispatch : ExactOriginalExternalCallbackReturnDispatch original) :
    WorldExecution :=
  .awaitingExternal dispatch.afterSuspension dispatch.outerFrames

theorem ExactOriginalExternalCallbackReturnDispatch.path
    (dispatch : ExactOriginalExternalCallbackReturnDispatch original) :
    NonemptyRelatedPath original.pe32TransitionSystem dispatch.before []
      dispatch.after := by
  have one := nonemptyRelatedPath_one original.pe32TransitionSystem dispatch.before
  unfold ExactOriginalExternalCallbackReturnDispatch.before at one
  rw [dispatch.transitionExact] at one
  simpa [ExactOriginalExternalCallbackReturnDispatch.before,
    ExactOriginalExternalCallbackReturnDispatch.after,
    ExactOriginalExternalCallbackReturnDispatch.afterSuspension] using one

structure ExactNestedNativeExternalCallbackReturnDispatch
    (candidate : ExactNestedNativeWorldProgram) where
  sourceRva : Nat
  undefinedSlot : Nat
  beforeState : MachineState
  afterState : MachineState
  eventIndex : Nat
  events : List NativeExternalEvent
  world : RelationalWorld
  frame : NativeWorldExternalCallbackRuntime
  outerFrames : List NativeWorldExternalCallbackRuntime
  decodedExact :
    stepKernelPE32Instruction candidate.pe candidate.imports
        (.running sourceRva undefinedSlot beforeState) =
      .stopped (.returned frame.entry.returnAddress) afterState

def ExactNestedNativeExternalCallbackReturnDispatch.before
    (dispatch : ExactNestedNativeExternalCallbackReturnDispatch candidate) :
    NestedNativeWorldExecution :=
  .running dispatch.sourceRva dispatch.undefinedSlot dispatch.beforeState []
    dispatch.eventIndex dispatch.events dispatch.world
    (dispatch.frame :: dispatch.outerFrames)

def ExactNestedNativeExternalCallbackReturnDispatch.afterSuspension
    (dispatch : ExactNestedNativeExternalCallbackReturnDispatch candidate) :
    NativeWorldExternalSuspension := {
  dispatch.frame.suspension with
  phaseIndex := dispatch.frame.suspension.phaseIndex + 1
  state := dispatch.afterState
  events := dispatch.events
  world := dispatch.world
}

def ExactNestedNativeExternalCallbackReturnDispatch.after
    (dispatch : ExactNestedNativeExternalCallbackReturnDispatch candidate) :
    NestedNativeWorldExecution :=
  .awaitingExternal dispatch.afterSuspension dispatch.outerFrames

theorem ExactNestedNativeExternalCallbackReturnDispatch.path
    (dispatch : ExactNestedNativeExternalCallbackReturnDispatch candidate) :
    NonemptyRelatedPath candidate.transitionSystem dispatch.before []
      dispatch.after := by
  have one := exactNestedNativeWorldStepIsNonempty candidate dispatch.before
  unfold ExactNestedNativeExternalCallbackReturnDispatch.before at one
  rw [nestedNativeCallbackReturnUnwinds candidate dispatch.sourceRva
    dispatch.undefinedSlot dispatch.beforeState dispatch.afterState
    dispatch.eventIndex dispatch.events dispatch.world dispatch.frame
    dispatch.outerFrames dispatch.decodedExact] at one
  simpa [ExactNestedNativeExternalCallbackReturnDispatch.after,
    ExactNestedNativeExternalCallbackReturnDispatch.afterSuspension] using one

theorem mixedNestedExternalCallbackReturn_suspensionsRelated
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (original : ExactOriginalExternalCallbackReturnDispatch originalProgram)
    (candidate : ExactNestedNativeExternalCallbackReturnDispatch candidateProgram)
    (frameStacksRelated : MixedNestedExternalCallbackFramesRelated contract frames
      (original.frame :: original.outerFrames)
      (candidate.frame :: candidate.outerFrames))
    (worldsRelated :
      contract.worldsRelated original.world candidate.world)
    (statesRelated : contract.runtimeStatesRelated original.world
      candidate.world original.afterState candidate.afterState)
    (argumentsRelated : mixedValuesRelated
      (contract.valuesRelated original.world candidate.world)
      original.frame.suspension.arguments
      candidate.frame.suspension.event.arguments) :
    MixedNestedExternalSuspensionsRelated contract frames original.afterSuspension
      original.outerFrames candidate.afterSuspension candidate.outerFrames := by
  cases frameStacksRelated with
  | cons _ _ _ _ suspensionCore _ tailsRelated =>
      rcases suspensionCore with
        ⟨eventSite, eventImport, eventArguments, eventIndex, phaseIndex,
          imported, _, _, _, continuations, calls⟩
      constructor
      · simp only [ExactOriginalExternalCallbackReturnDispatch.afterSuspension,
          ExactNestedNativeExternalCallbackReturnDispatch.afterSuspension]
        exact ⟨eventSite, eventImport, eventArguments, eventIndex,
          congrArg (fun phase => phase + 1) phaseIndex, imported, worldsRelated,
          statesRelated, argumentsRelated, continuations, calls⟩
      · exact tailsRelated

structure ExactMixedNestedExternalCallbackReturnChunk
    (originalProgram : DecodedWorldProgram)
    (candidateProgram : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (original : ExactOriginalExternalCallbackReturnDispatch originalProgram)
    (candidate : ExactNestedNativeExternalCallbackReturnDispatch candidateProgram) :
    Prop where
  originalPath : NonemptyRelatedPath originalProgram.pe32TransitionSystem
    original.before [] original.after
  candidatePath : NonemptyRelatedPath candidateProgram.transitionSystem
    candidate.before [] candidate.after
  observationsRelated : RelatedObservationLists contract.eventObservationsRelated
    [] []
  suspensionsRelated : MixedNestedExternalSuspensionsRelated contract frames
    original.afterSuspension original.outerFrames candidate.afterSuspension
    candidate.outerFrames

theorem exactMixedNestedExternalCallbackReturnChunk
    (original : ExactOriginalExternalCallbackReturnDispatch originalProgram)
    (candidate : ExactNestedNativeExternalCallbackReturnDispatch candidateProgram)
    (frameStacksRelated : MixedNestedExternalCallbackFramesRelated contract frames
      (original.frame :: original.outerFrames)
      (candidate.frame :: candidate.outerFrames))
    (worldsRelated :
      contract.worldsRelated original.world candidate.world)
    (statesRelated : contract.runtimeStatesRelated original.world
      candidate.world original.afterState candidate.afterState)
    (argumentsRelated : mixedValuesRelated
      (contract.valuesRelated original.world candidate.world)
      original.frame.suspension.arguments
      candidate.frame.suspension.event.arguments) :
    ExactMixedNestedExternalCallbackReturnChunk originalProgram candidateProgram
      contract frames original candidate := {
  originalPath := original.path
  candidatePath := candidate.path
  observationsRelated := True.intro
  suspensionsRelated := mixedNestedExternalCallbackReturn_suspensionsRelated
    contract frames original candidate frameStacksRelated worldsRelated
    statesRelated argumentsRelated
}

#print axioms MixedExternalSuccessorsRelated.fault_causes_equal
#print axioms externalBoundaryObservationsRelated
#print axioms MixedExternalEnvironmentActionsRelated.candidate_blocked_is_unrelated
#print axioms MixedExternalEnvironmentActionsRelated.callback_is_unrelated
#print axioms ExactNativeExternalDispatch.path
#print axioms mixedExternalActions_successorsRelated
#print axioms exactMixedExternalInteractionChunk
#print axioms ExactMixedExternalInteractionChunk.toComponent

end StageA.Relational.InterpreterMixedEnvironment
