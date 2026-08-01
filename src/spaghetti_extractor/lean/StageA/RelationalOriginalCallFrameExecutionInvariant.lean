import StageA.RelationalOriginalExecutionInvariant
import StageA.RelationalInternalDirectCallMixedOriginalIntegration

namespace StageA.Relational.OriginalCallFrameExecutionInvariant

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallComposition
open StageA.Relational.InternalDirectCallMixedOriginalIntegration
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.ValueProvenance

/-!
# One-sided original call-frame execution invariant

`WorldExecution` deliberately stores only concrete continuation identifiers.
This module adds a proof-only inventory of `RelationalRuntimeCallFrame` values
whose shape is forced by that concrete `calls` list.  Caller values are read
from concrete memory and use the shared `ValueOriginAtom` language; no source
prototype or program-specific convention is introduced.

External callbacks have a separate machine stack.  Their outer call stacks
therefore remain attached to the immutable `WorldExternalSuspension` values in
the callback list.  Moving between active execution, suspension, and callback
execution moves only the proof inventory.  Returning external actions and
decoded memory effects must separately prove preservation of every dormant
frame fact.
-/

/-- One-sided use of the shared paired origin language.  The candidate word is
an existential provenance witness, not a candidate execution state. -/
def OriginalValueOriginAtomHolds
    (context : StaticProofContext) (world : RelationalWorld)
    (value : Word) (origin : ValueOriginAtom) : Prop :=
  exists companion, origin.Holds context world value companion

def OriginalValueOriginAtomPreserved
    (context : StaticProofContext) (before after : RelationalWorld)
    (origin : ValueOriginAtom) : Prop :=
  forall value,
    OriginalValueOriginAtomHolds context before value origin ->
      OriginalValueOriginAtomHolds context after value origin

theorem OriginalValueOriginAtomPreserved.ofValueOriginsPreserved
    (context : StaticProofContext) (before after : RelationalWorld)
    (origins : List ValueOriginAtom) (origin : ValueOriginAtom)
    (member : origin ∈ origins)
    (preserved : ValueOriginsPreserved context before after origins) :
    OriginalValueOriginAtomPreserved context before after origin := by
  intro value holds
  rcases holds with ⟨companion, originHolds⟩
  exact ⟨companion, preserved origin member value companion originHolds⟩

/-- One caller-owned word, addressed relative to the caller's pre-call ESP.
While the call is active, that address is four bytes above the runtime return
slot plus `word.originalOffset`. -/
structure DormantOriginalValueFact where
  word : ReturnSlotExactWordPair
  origin : ValueOriginAtom

def DormantOriginalValueFact.frameAddress
    (fact : DormantOriginalValueFact)
    (frame : RelationalRuntimeCallFrame) : Word :=
  frame.originalStackAddress +
    BitVec.ofNat 32 (4 + fact.word.originalOffset)

def DormantOriginalValueFact.callerAddress
    (fact : DormantOriginalValueFact) (state : MachineState) : Word :=
  state.registers.esp + BitVec.ofNat 32 fact.word.originalOffset

def DormantOriginalValueFact.HoldsInFrame
    (context : StaticProofContext) (world : RelationalWorld)
    (memory : Memory) (frame : RelationalRuntimeCallFrame)
    (fact : DormantOriginalValueFact) : Prop :=
  OriginalValueOriginAtomHolds context world
    (Memory.read32 memory (fact.frameAddress frame)) fact.origin

def DormantOriginalValueFact.HoldsAtCaller
    (context : StaticProofContext) (world : RelationalWorld)
    (state : MachineState) (fact : DormantOriginalValueFact) : Prop :=
  OriginalValueOriginAtomHolds context world
    (Memory.read32 state.memory (fact.callerAddress state)) fact.origin

theorem DormantOriginalValueFact.holdsInFrame_of_caller
    (fact : DormantOriginalValueFact)
    (context : StaticProofContext)
    (sourceWorld entryWorld : RelationalWorld)
    (sourceState entryState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (source : fact.HoldsAtCaller context sourceWorld sourceState)
    (worldExact : entryWorld = sourceWorld)
    (readExact :
      Memory.read32 entryState.memory (fact.frameAddress frame) =
        Memory.read32 sourceState.memory (fact.callerAddress sourceState)) :
    fact.HoldsInFrame context entryWorld entryState.memory frame := by
  subst entryWorld
  simpa [DormantOriginalValueFact.HoldsInFrame,
    DormantOriginalValueFact.HoldsAtCaller, readExact] using source

theorem DormantOriginalValueFact.holdsInFrame_after
    (fact : DormantOriginalValueFact)
    (context : StaticProofContext)
    (beforeWorld afterWorld : RelationalWorld)
    (beforeMemory afterMemory : Memory)
    (frame : RelationalRuntimeCallFrame)
    (before : fact.HoldsInFrame context beforeWorld beforeMemory frame)
    (readExact :
      Memory.read32 afterMemory (fact.frameAddress frame) =
        Memory.read32 beforeMemory (fact.frameAddress frame))
    (originPreserved : OriginalValueOriginAtomPreserved context
      beforeWorld afterWorld fact.origin) :
    fact.HoldsInFrame context afterWorld afterMemory frame := by
  apply originPreserved
  simpa [DormantOriginalValueFact.HoldsInFrame, readExact] using before

/-- A dormant original frame retains the shared runtime-frame authority and a
finite inventory of one-sided caller values. -/
structure DormantOriginalCallFrame where
  runtime : RelationalRuntimeCallFrame
  values : List DormantOriginalValueFact := []

def DormantOriginalCallFrame.Holds
    (context : StaticProofContext) (world : RelationalWorld)
    (state : MachineState) (frame : DormantOriginalCallFrame) : Prop :=
  frame.runtime.valid context = true /\
    frame.runtime.toRelationalCallFrame.resolves context = true /\
    Memory.read32 state.memory frame.runtime.originalStackAddress =
      frame.runtime.originalReturnAddress /\
    forall fact, fact ∈ frame.values ->
      fact.HoldsInFrame context world state.memory frame.runtime

def DormantOriginalCallFrame.CallerValuesHold
    (context : StaticProofContext) (world : RelationalWorld)
    (state : MachineState) (frame : DormantOriginalCallFrame) : Prop :=
  forall fact, fact ∈ frame.values ->
    fact.HoldsAtCaller context world state

theorem DormantOriginalCallFrame.callerValuesHold_of_frame
    (context : StaticProofContext) (world : RelationalWorld)
    (state : MachineState) (frame : DormantOriginalCallFrame)
    (holds : frame.Holds context world state)
    (stackRestored :
      state.registers.esp =
        frame.runtime.originalStackAddress + BitVec.ofNat 32 4) :
    frame.CallerValuesHold context world state := by
  intro fact member
  have inFrame := holds.2.2.2 fact member
  unfold DormantOriginalValueFact.HoldsInFrame at inFrame
  unfold DormantOriginalValueFact.HoldsAtCaller
    DormantOriginalValueFact.callerAddress
  rw [stackRestored]
  simpa only [DormantOriginalValueFact.frameAddress, BitVec.ofNat_add,
    BitVec.add_assoc] using inFrame

theorem DormantOriginalCallFrame.after
    (context : StaticProofContext)
    (beforeWorld afterWorld : RelationalWorld)
    (beforeState afterState : MachineState)
    (frame : DormantOriginalCallFrame)
    (before : frame.Holds context beforeWorld beforeState)
    (returnSlotExact :
      Memory.read32 afterState.memory frame.runtime.originalStackAddress =
        Memory.read32 beforeState.memory frame.runtime.originalStackAddress)
    (factsPreserved : forall fact, fact ∈ frame.values ->
      fact.HoldsInFrame context beforeWorld beforeState.memory frame.runtime ->
        fact.HoldsInFrame context afterWorld afterState.memory frame.runtime) :
    frame.Holds context afterWorld afterState := by
  refine ⟨before.1, before.2.1, ?_, ?_⟩
  · rw [returnSlotExact]
    exact before.2.2.1
  · intro fact member
    exact factsPreserved fact member (before.2.2.2 fact member)

/-- Runtime frames and concrete continuations have exactly the same shape.
Every frame is checked against the current original memory. -/
def OriginalCallFramesHold
    (context : StaticProofContext) (world : RelationalWorld)
    (state : MachineState) :
    List DormantOriginalCallFrame -> List Nat -> Prop
  | [], [] => True
  | frame :: frames, continuation :: continuations =>
      frame.runtime.continuationTargetId = continuation /\
        frame.Holds context world state /\
        OriginalCallFramesHold context world state frames continuations
  | _, _ => False

theorem OriginalCallFramesHold.length_eq
    (context : StaticProofContext) (world : RelationalWorld)
    (state : MachineState) (frames : List DormantOriginalCallFrame)
    (calls : List Nat)
    (holds : OriginalCallFramesHold context world state frames calls) :
    frames.length = calls.length := by
  induction frames generalizing calls with
  | nil =>
      cases calls <;> simp_all [OriginalCallFramesHold]
  | cons frame frames induction =>
      cases calls with
      | nil => simp [OriginalCallFramesHold] at holds
      | cons continuation calls =>
          simp only [OriginalCallFramesHold] at holds
          simp only [List.length_cons, Nat.succ.injEq]
          exact induction calls holds.2.2

theorem OriginalCallFramesHold.push
    (context : StaticProofContext) (world : RelationalWorld)
    (state : MachineState) (frame : DormantOriginalCallFrame)
    (frames : List DormantOriginalCallFrame) (continuation : Nat)
    (calls : List Nat)
    (continuationExact : frame.runtime.continuationTargetId = continuation)
    (frameHolds : frame.Holds context world state)
    (tailHolds : OriginalCallFramesHold context world state frames calls) :
    OriginalCallFramesHold context world state (frame :: frames)
      (continuation :: calls) :=
  ⟨continuationExact, frameHolds, tailHolds⟩

theorem OriginalCallFramesHold.after
    (context : StaticProofContext)
    (beforeWorld afterWorld : RelationalWorld)
    (beforeState afterState : MachineState)
    (frames : List DormantOriginalCallFrame) (calls : List Nat)
    (before : OriginalCallFramesHold context beforeWorld beforeState frames calls)
    (preserved : forall (frame : DormantOriginalCallFrame),
      DormantOriginalCallFrame.Holds context beforeWorld beforeState frame ->
        DormantOriginalCallFrame.Holds context afterWorld afterState frame) :
    OriginalCallFramesHold context afterWorld afterState frames calls := by
  induction frames generalizing calls with
  | nil =>
      cases calls <;> simp_all [OriginalCallFramesHold]
  | cons frame frames induction =>
      cases calls with
      | nil => simp [OriginalCallFramesHold] at before
      | cons continuation calls =>
          simp only [OriginalCallFramesHold] at before ⊢
          exact ⟨before.1, preserved frame before.2.1,
            induction calls before.2.2⟩

/-- Callback execution is admitted only for a registered and statically valid
callback target.  An arbitrary protocol-environment callback action is not
proof authority. -/
def KnownCallbackRuntime
    (context : StaticProofContext) (callback : WorldExternalCallbackRuntime) :
    Prop :=
  exists registered,
    registered ∈ callback.suspension.world.registeredCallbacks /\
      registered.targetId = callback.entry.targetId /\
      registered.valid context = true

/-- One frame inventory for each suspended callback layer. -/
def SuspendedOriginalCallFramesHold
    (context : StaticProofContext) :
    List WorldExternalCallbackRuntime ->
      List (List DormantOriginalCallFrame) -> Prop
  | [], [] => True
  | callback :: callbacks, frames :: suspended =>
      KnownCallbackRuntime context callback /\
        OriginalCallFramesHold context callback.suspension.world
          callback.suspension.state frames callback.suspension.calls /\
        SuspendedOriginalCallFramesHold context callbacks suspended
  | _, _ => False

theorem SuspendedOriginalCallFramesHold.known
    (context : StaticProofContext)
    (callbacks : List WorldExternalCallbackRuntime)
    (suspended : List (List DormantOriginalCallFrame))
    (holds : SuspendedOriginalCallFramesHold context callbacks suspended)
    (callback : WorldExternalCallbackRuntime) (member : callback ∈ callbacks) :
    KnownCallbackRuntime context callback := by
  induction callbacks generalizing suspended with
  | nil => simp at member
  | cons head callbacks induction =>
      cases suspended with
      | nil => simp [SuspendedOriginalCallFramesHold] at holds
      | cons frames suspended =>
          simp only [SuspendedOriginalCallFramesHold] at holds
          simp only [List.mem_cons] at member
          rcases member with rfl | member
          · exact holds.1
          · exact induction suspended holds.2.2 member

structure OriginalCallFrameExecutionInventory where
  active : List DormantOriginalCallFrame := []
  suspended : List (List DormantOriginalCallFrame) := []

/-- Concrete execution predicate used by the combined original invariant.
Blocked states are intentionally uninhabited. -/
def OriginalCallFrameExecutionInventory.Holds
    (context : StaticProofContext)
    (inventory : OriginalCallFrameExecutionInventory) :
    WorldExecution -> Prop
  | .running _ state calls _ world =>
      inventory.suspended = [] /\
        OriginalCallFramesHold context world state inventory.active calls
  | .returned _ _ | .terminated _ | .fault _ =>
      inventory.active = [] /\ inventory.suspended = []
  | .awaitingExternal suspension callbacks =>
      OriginalCallFramesHold context suspension.world suspension.state
          inventory.active suspension.calls /\
        SuspendedOriginalCallFramesHold context callbacks inventory.suspended
  | .callbackRunning _ state calls _ world callbacks =>
      OriginalCallFramesHold context world state inventory.active calls /\
        SuspendedOriginalCallFramesHold context callbacks inventory.suspended
  | .blocked _ => False

def OriginalCallFrameExecutionHolds
    (context : StaticProofContext) (execution : WorldExecution) : Prop :=
  exists inventory : OriginalCallFrameExecutionInventory,
    OriginalCallFrameExecutionInventory.Holds context inventory execution

theorem OriginalCallFrameExecutionHolds.blocked_false
    (context : StaticProofContext) (reason : ExecutionBlock) :
    Not (OriginalCallFrameExecutionHolds context (.blocked reason)) := by
  rintro ⟨inventory, holds⟩
  exact holds

theorem OriginalCallFrameExecutionHolds.callback_known
    (context : StaticProofContext)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime)
    (holds : OriginalCallFrameExecutionHolds context
      (.callbackRunning targetId state calls eventIndex world callbacks))
    (callback : WorldExternalCallbackRuntime) (member : callback ∈ callbacks) :
    KnownCallbackRuntime context callback := by
  rcases holds with ⟨inventory, _active, suspended⟩
  exact suspended.known context callbacks inventory.suspended callback member

theorem OriginalCallFrameExecutionHolds.unknown_callback_false
    (context : StaticProofContext)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (callback : WorldExternalCallbackRuntime)
    (callbacks : List WorldExternalCallbackRuntime)
    (unknown : Not (KnownCallbackRuntime context callback)) :
    Not (OriginalCallFrameExecutionHolds context
      (.callbackRunning targetId state calls eventIndex world
        (callback :: callbacks))) := by
  intro holds
  exact unknown (holds.callback_known context targetId state calls eventIndex
    world (callback :: callbacks) callback (by simp))

/-! ## Exact transition constructors -/

/-- Enter an internal call using the exact PE32 step.  The new runtime frame is
pushed against the concrete successor `continuation :: calls`; the old dormant
tail must already hold in the computed entry state. -/
theorem OriginalCallFrameExecutionInventory.callEntry
    (program : DecodedWorldProgram) (before : WorldExecution)
    (callbacks : List WorldExternalCallbackRuntime)
    (calleeTargetId continuationTargetId : Nat)
    (entryState : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld)
    (frame : DormantOriginalCallFrame)
    (frames : List DormantOriginalCallFrame)
    (suspended : List (List DormantOriginalCallFrame))
    (stepExact :
      program.pe32TransitionSystem.step before = {
        next := resumeWorldExecution callbacks calleeTargetId entryState
          (continuationTargetId :: calls) eventIndex world
        observation := none
      })
    (continuationExact :
      frame.runtime.continuationTargetId = continuationTargetId)
    (frameHolds : frame.Holds program.context world entryState)
    (tailHolds : OriginalCallFramesHold program.context world entryState
      frames calls)
    (suspendedHolds :
      SuspendedOriginalCallFramesHold program.context callbacks suspended) :
    ({ active := frame :: frames, suspended := suspended } :
      OriginalCallFrameExecutionInventory).Holds program.context
        (program.pe32TransitionSystem.step before).next := by
  rw [stepExact]
  cases callbacks with
  | nil =>
      cases suspended with
      | nil =>
          exact ⟨rfl, OriginalCallFramesHold.push program.context world entryState
            frame frames continuationTargetId calls continuationExact frameHolds
            tailHolds⟩
      | cons suspendedHead suspendedTail =>
          exact False.elim suspendedHolds
  | cons callback callbacks =>
      exact ⟨OriginalCallFramesHold.push program.context world entryState
          frame frames continuationTargetId calls continuationExact frameHolds
          tailHolds,
        suspendedHolds⟩

/-- Preserve an unchanged concrete call stack across one exact internal PE32
step.  This theorem covers ordinary local control and nested callee steps; the
caller supplies only the per-frame preservation fact for the computed state. -/
theorem OriginalCallFrameExecutionInventory.internalPreserved
    (program : DecodedWorldProgram) (before : WorldExecution)
    (callbacks : List WorldExternalCallbackRuntime)
    (nextTargetId : Nat) (beforeState afterState : MachineState)
    (calls : List Nat) (eventIndex : Nat)
    (beforeWorld afterWorld : RelationalWorld)
    (frames : List DormantOriginalCallFrame)
    (suspended : List (List DormantOriginalCallFrame))
    (stepExact :
      program.pe32TransitionSystem.step before = {
        next := resumeWorldExecution callbacks nextTargetId afterState calls
          eventIndex afterWorld
        observation := none
      })
    (beforeFrames : OriginalCallFramesHold program.context beforeWorld
      beforeState frames calls)
    (framesPreserved : forall (frame : DormantOriginalCallFrame),
      DormantOriginalCallFrame.Holds program.context beforeWorld beforeState frame ->
        DormantOriginalCallFrame.Holds program.context afterWorld afterState frame)
    (suspendedHolds :
      SuspendedOriginalCallFramesHold program.context callbacks suspended) :
    ({ active := frames, suspended := suspended } :
      OriginalCallFrameExecutionInventory).Holds program.context
        (program.pe32TransitionSystem.step before).next := by
  have afterFrames := beforeFrames.after program.context beforeWorld afterWorld
    beforeState afterState frames calls framesPreserved
  rw [stepExact]
  cases callbacks with
  | nil =>
      cases suspended with
      | nil => exact ⟨rfl, afterFrames⟩
      | cons suspendedHead suspendedTail => exact False.elim suspendedHolds
  | cons callback callbacks => exact ⟨afterFrames, suspendedHolds⟩

/-- Enter an external suspension through the exact PE32 successor.  The
suspension itself owns the concrete state, world, and `calls` list against
which the active dormant frames are checked. -/
theorem OriginalCallFrameExecutionInventory.externalSuspended
    (program : DecodedWorldProgram) (before : WorldExecution)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (frames : List DormantOriginalCallFrame)
    (suspended : List (List DormantOriginalCallFrame))
    (nextExact :
      (program.pe32TransitionSystem.step before).next =
        .awaitingExternal suspension callbacks)
    (framesHold : OriginalCallFramesHold program.context suspension.world
      suspension.state frames suspension.calls)
    (suspendedHolds :
      SuspendedOriginalCallFramesHold program.context callbacks suspended) :
    ({ active := frames, suspended := suspended } :
      OriginalCallFrameExecutionInventory).Holds program.context
        (program.pe32TransitionSystem.step before).next := by
  rw [nextExact]
  exact ⟨framesHold, suspendedHolds⟩

/-- A returned external action resumes the suspension's exact concrete call
stack.  External state/world mutation is accepted only through an explicit
dormant-frame preservation theorem. -/
theorem OriginalCallFrameExecutionInventory.externalReturned
    (program : DecodedWorldProgram)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (result : WorldExternalResult)
    (frames : List DormantOriginalCallFrame)
    (suspended : List (List DormantOriginalCallFrame))
    (actionExact :
      program.protocolEnvironment.action suspension.request = .returned result)
    (beforeFrames : OriginalCallFramesHold program.context suspension.world
      suspension.state frames suspension.calls)
    (framesPreserved : forall (frame : DormantOriginalCallFrame),
      DormantOriginalCallFrame.Holds program.context suspension.world
          suspension.state frame ->
        DormantOriginalCallFrame.Holds program.context result.world
          result.state frame)
    (suspendedHolds :
      SuspendedOriginalCallFramesHold program.context callbacks suspended) :
    ({ active := frames, suspended := suspended } :
      OriginalCallFrameExecutionInventory).Holds program.context
        (program.pe32TransitionSystem.step
          (.awaitingExternal suspension callbacks)).next := by
  have afterFrames := beforeFrames.after program.context suspension.world
    result.world suspension.state result.state frames suspension.calls
    framesPreserved
  unfold DecodedWorldProgram.pe32TransitionSystem
  simp only [stepPE32WorldExecution, stepWorldExternalSuspension, actionExact]
  cases callbacks with
  | nil =>
      cases suspended with
      | nil => exact ⟨rfl, afterFrames⟩
      | cons suspendedHead suspendedTail => exact False.elim suspendedHolds
  | cons callback callbacks => exact ⟨afterFrames, suspendedHolds⟩

/-- Callback entry starts with an empty concrete internal-call stack and moves
the suspended stack under a checked registered callback frame. -/
theorem OriginalCallFrameExecutionInventory.externalCallbackEntry
    (program : DecodedWorldProgram)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (entry : WorldExternalCallbackAction)
    (frames : List DormantOriginalCallFrame)
    (suspended : List (List DormantOriginalCallFrame))
    (actionExact :
      program.protocolEnvironment.action suspension.request = .callback entry)
    (known : KnownCallbackRuntime program.context
      { suspension := suspension, entry := entry })
    (beforeFrames : OriginalCallFramesHold program.context suspension.world
      suspension.state frames suspension.calls)
    (suspendedHolds :
      SuspendedOriginalCallFramesHold program.context callbacks suspended) :
    ({ active := [], suspended := frames :: suspended } :
      OriginalCallFrameExecutionInventory).Holds program.context
        (program.pe32TransitionSystem.step
          (.awaitingExternal suspension callbacks)).next := by
  unfold DecodedWorldProgram.pe32TransitionSystem
  simp only [stepPE32WorldExecution, stepWorldExternalSuspension, actionExact,
    OriginalCallFrameExecutionInventory.Holds, OriginalCallFramesHold,
    SuspendedOriginalCallFramesHold]
  exact ⟨trivial, known, beforeFrames, suspendedHolds⟩

/-- A well-bracketed callback return moves the top suspended call inventory
back into the active external suspension.  The authoritative outcome checks
the concrete return token before selecting this successor. -/
theorem OriginalCallFrameExecutionInventory.callbackReturnRestored
    (program : DecodedWorldProgram) (sourceTargetId : Nat)
    (state : MachineState) (eventIndex : Nat) (world : RelationalWorld)
    (callback : WorldExternalCallbackRuntime)
    (callbacks : List WorldExternalCallbackRuntime)
    (target : Word)
    (frames : List DormantOriginalCallFrame)
    (suspended : List (List DormantOriginalCallFrame))
    (targetExact : target = callback.entry.returnAddress)
    (framesHold : OriginalCallFramesHold program.context world state frames
      callback.suspension.calls)
    (suspendedHolds :
      SuspendedOriginalCallFramesHold program.context callbacks suspended) :
    ({ active := frames, suspended := suspended } :
      OriginalCallFrameExecutionInventory).Holds program.context
        (transitionFromWorldOutcome program sourceTargetId state [] eventIndex
          world (callback :: callbacks) (.returned target)).next := by
  subst target
  simp only [transitionFromWorldOutcome, beq_self_eq_true, if_true,
    OriginalCallFrameExecutionInventory.Holds]
  exact ⟨framesHold, suspendedHolds⟩

/-- The protocol environment may request a callback, but an unregistered or
statically invalid target cannot enter this original invariant. -/
theorem externalUnknownCallback_not_admitted
    (program : DecodedWorldProgram)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (entry : WorldExternalCallbackAction)
    (actionExact :
      program.protocolEnvironment.action suspension.request = .callback entry)
    (unknown : Not (KnownCallbackRuntime program.context
      { suspension := suspension, entry := entry })) :
    Not (OriginalCallFrameExecutionHolds program.context
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next) := by
  unfold DecodedWorldProgram.pe32TransitionSystem
  simp only [stepPE32WorldExecution, stepWorldExternalSuspension, actionExact]
  exact OriginalCallFrameExecutionHolds.unknown_callback_false program.context
    entry.targetId entry.state [] suspension.eventIndex entry.world
    { suspension := suspension, entry := entry } callbacks unknown

/-- Pop one exact internal return.  Mismatched or unmapped returns cannot
inhabit `stepExact`, because the authoritative transition produces `blocked`.
The popped frame additionally restores its caller-value facts. -/
theorem OriginalCallFrameExecutionInventory.returnRestored
    (program : DecodedWorldProgram) (before : WorldExecution)
    (callbacks : List WorldExternalCallbackRuntime)
    (continuationTargetId : Nat)
    (afterState : MachineState) (tailCalls : List Nat) (eventIndex : Nat)
    (afterWorld : RelationalWorld)
    (frame : DormantOriginalCallFrame)
    (frames : List DormantOriginalCallFrame)
    (suspended : List (List DormantOriginalCallFrame))
    (stepExact :
      program.pe32TransitionSystem.step before = {
        next := resumeWorldExecution callbacks continuationTargetId afterState
          tailCalls eventIndex afterWorld
        observation := none
      })
    (tailHolds : OriginalCallFramesHold program.context afterWorld afterState
      frames tailCalls)
    (returnedFrame : frame.Holds program.context afterWorld afterState)
    (stackRestored :
      afterState.registers.esp =
        frame.runtime.originalStackAddress + BitVec.ofNat 32 4)
    (suspendedHolds :
      SuspendedOriginalCallFramesHold program.context callbacks suspended) :
    ({ active := frames, suspended := suspended } :
        OriginalCallFrameExecutionInventory).Holds program.context
          (program.pe32TransitionSystem.step before).next /\
      frame.CallerValuesHold program.context afterWorld afterState := by
  constructor
  · rw [stepExact]
    cases callbacks with
    | nil =>
        cases suspended with
        | nil => exact ⟨rfl, tailHolds⟩
        | cons suspendedHead suspendedTail => exact False.elim suspendedHolds
    | cons callback callbacks => exact ⟨tailHolds, suspendedHolds⟩
  · exact frame.callerValuesHold_of_frame program.context afterWorld afterState
      returnedFrame stackRestored

/-! ## Checked call/frame adapters -/

theorem DormantOriginalValueFact.restoredByCheckedDirectCall
    (fact : DormantOriginalValueFact)
    (binding : CheckedDirectCallCallerFrameWordControlContract context)
    {entryBinding : ExactDirectCallEntryBinding context binding.tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution context binding.tree entryBinding
      originalProgram candidateProgram)
    (member : fact.word ∈ binding.requestedWords)
    (source : fact.HoldsAtCaller context actual.source.original.world
      actual.source.original.state) :
    fact.HoldsAtCaller context actual.originalExit.world
      actual.originalExit.state := by
  have preserved := binding.preserves actual fact.word member
  unfold DormantOriginalValueFact.HoldsAtCaller at source ⊢
  unfold DormantOriginalValueFact.callerAddress at source ⊢
  rw [actual.exitWorld.1, preserved.1]
  exact source

theorem DormantOriginalValueFact.restoredByCheckedFiniteOriginCall
    (fact : DormantOriginalValueFact)
    (binding : CheckedFiniteOriginCallCallerFrameWordControlContract context)
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualFiniteOriginCallReturnExecution binding.entry
      originalProgram candidateProgram)
    (member : fact.word ∈ binding.requestedWords)
    (source : fact.HoldsAtCaller context actual.sourceOriginal.world
      actual.sourceOriginal.state) :
    fact.HoldsAtCaller context actual.originalExit.world
      actual.originalExit.state := by
  have preserved := binding.preserves actual fact.word member
  unfold DormantOriginalValueFact.HoldsAtCaller at source ⊢
  unfold DormantOriginalValueFact.callerAddress at source ⊢
  rw [actual.exitWorld.1, preserved.1]
  exact source

/-- The exact return resolver fails closed when the concrete return target does
not match the head of `calls`. -/
theorem mismatchedReturn_not_admitted
    (program : DecodedWorldProgram)
    (sourceTargetId : Nat) (state : MachineState)
    (continuation : Nat) (tail : List Nat) (eventIndex : Nat)
    (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime)
    (target : Word) (resolved : Nat)
    (resolvedExact :
      resolveMappedCodeTarget program.candidate
        (if program.candidate then program.context.candidatePe.imageBase
          else program.context.originalPe.imageBase)
        program.context.codeMap.entries.toList target = some resolved)
    (mismatch : resolved ≠ continuation) :
    Not (OriginalCallFrameExecutionHolds program.context
      (transitionFromWorldOutcome program sourceTargetId state
        (continuation :: tail) eventIndex world callbacks
        (.returned target)).next) := by
  have mismatchBool : (resolved == continuation) = false :=
    beq_eq_false_iff_ne.mpr mismatch
  have nextExact :
      (transitionFromWorldOutcome program sourceTargetId state
        (continuation :: tail) eventIndex world callbacks
        (.returned target)).next =
          .blocked (.mismatchedReturnTarget resolved continuation) := by
    simp [transitionFromWorldOutcome, resolvedExact, mismatchBool,
      blockedWorldTransition]
  rw [nextExact]
  exact OriginalCallFrameExecutionHolds.blocked_false program.context _

/-- Callback returns are equally fail closed: the external return token must
match the top callback frame exactly. -/
theorem mismatchedCallbackReturn_not_admitted
    (program : DecodedWorldProgram)
    (sourceTargetId : Nat) (state : MachineState) (eventIndex : Nat)
    (world : RelationalWorld)
    (callback : WorldExternalCallbackRuntime)
    (callbacks : List WorldExternalCallbackRuntime)
    (target : Word)
    (mismatch : target ≠ callback.entry.returnAddress) :
    Not (OriginalCallFrameExecutionHolds program.context
      (transitionFromWorldOutcome program sourceTargetId state [] eventIndex
        world (callback :: callbacks) (.returned target)).next) := by
  have mismatchBool : (target == callback.entry.returnAddress) = false :=
    beq_eq_false_iff_ne.mpr mismatch
  have nextExact :
      (transitionFromWorldOutcome program sourceTargetId state [] eventIndex
        world (callback :: callbacks) (.returned target)).next =
          .blocked (.invalidCallbackReturn target callback.entry.returnAddress) := by
    simp [transitionFromWorldOutcome, mismatchBool, blockedWorldTransition]
  rw [nextExact]
  exact OriginalCallFrameExecutionHolds.blocked_false program.context _

/-! ## Combined original-invariant component -/

/-- Exact one-step closure is deliberately an explicit checked input.  The
lemmas above are its generic constructors; a program adapter must classify
every reachable PE32 step and cannot replace this field with a report flag. -/
structure CheckedOriginalCallFrameExecutionInvariant
    (program : DecodedWorldProgram) : Prop where
  stepClosed : forall before,
    OriginalCallFrameExecutionHolds program.context before ->
      OriginalCallFrameExecutionHolds program.context
        (program.pe32TransitionSystem.step before).next

def CheckedOriginalCallFrameExecutionInvariant.toOriginalInvariant
    (checked : CheckedOriginalCallFrameExecutionInvariant program) :
    OriginalWorldExecutionInvariant program where
  holds := OriginalCallFrameExecutionHolds program.context
  stepClosed := checked.stepClosed

@[simp]
theorem CheckedOriginalCallFrameExecutionInvariant.toOriginalInvariant_holds
    (checked : CheckedOriginalCallFrameExecutionInvariant program)
    (execution : WorldExecution) :
    checked.toOriginalInvariant.holds execution <->
      OriginalCallFrameExecutionHolds program.context execution :=
  Iff.rfl

#print axioms OriginalValueOriginAtomPreserved.ofValueOriginsPreserved
#print axioms OriginalCallFramesHold.after
#print axioms OriginalCallFrameExecutionInventory.callEntry
#print axioms OriginalCallFrameExecutionInventory.internalPreserved
#print axioms OriginalCallFrameExecutionInventory.externalSuspended
#print axioms OriginalCallFrameExecutionInventory.externalReturned
#print axioms OriginalCallFrameExecutionInventory.externalCallbackEntry
#print axioms OriginalCallFrameExecutionInventory.callbackReturnRestored
#print axioms OriginalCallFrameExecutionInventory.returnRestored
#print axioms DormantOriginalValueFact.restoredByCheckedDirectCall
#print axioms DormantOriginalValueFact.restoredByCheckedFiniteOriginCall
#print axioms mismatchedReturn_not_admitted
#print axioms externalUnknownCallback_not_admitted
#print axioms mismatchedCallbackReturn_not_admitted

end StageA.Relational.OriginalCallFrameExecutionInvariant
