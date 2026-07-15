import StageA.RelationalEnvironment

namespace StageA.Relational

open StageA.Formal

/-- A paired return frame owned by a suspended external interaction.

The return token is deliberately not required to be PE code. It must instead be
one checked opaque-resource pair supplied by the relational world. The stack
slot must resolve to the same byte offset in one paired stack range. -/
structure RelationalExternalCallbackFrame where
  siteId : Nat
  eventIndex : Nat
  phaseIndex : Nat
  continuationTargetId : Nat
  callback : RegisteredCallbackPair
  returnResourceId : Nat
  stackRangeId : Nat
  stackOffset : Nat
  originalReturnAddress : Word
  candidateReturnAddress : Word
  originalStackAddress : Word
  candidateStackAddress : Word
deriving Repr, DecidableEq

def RelationalExternalCallbackFrame.valid (context : StaticProofContext)
    (world : RelationalWorld) (frame : RelationalExternalCallbackFrame) : Bool :=
  frame.callback.valid context &&
    (context.codeMap.get? frame.continuationTargetId).isSome &&
    match world.opaqueResources.find? fun resource =>
        resource.id == frame.returnResourceId,
      world.stackRanges.find? fun range => range.id == frame.stackRangeId with
    | some resource, some range =>
        frame.originalReturnAddress == resource.original &&
          frame.candidateReturnAddress == resource.candidate &&
          frame.originalReturnAddress != BitVec.ofNat 32 0 &&
          frame.candidateReturnAddress != BitVec.ofNat 32 0 &&
          frame.stackOffset + 4 <= range.size &&
          frame.originalStackAddress ==
            range.originalBase + BitVec.ofNat 32 frame.stackOffset &&
          frame.candidateStackAddress ==
            range.candidateBase + BitVec.ofNat 32 frame.stackOffset
    | _, _ => false

def RelationalExternalCallbackFrame.memoryHolds
    (frame : RelationalExternalCallbackFrame)
    (original candidate : Memory) : Prop :=
  Memory.read32 original frame.originalStackAddress = frame.originalReturnAddress ∧
    Memory.read32 candidate frame.candidateStackAddress = frame.candidateReturnAddress

def RelationalExternalCallbackFrame.entryRegistersHold
    (frame : RelationalExternalCallbackFrame)
    (original candidate : Registers Word) : Prop :=
  original.esp = frame.originalStackAddress ∧
    candidate.esp = frame.candidateStackAddress

def RelationalExternalCallbackFrame.returnTargetsHold
    (frame : RelationalExternalCallbackFrame)
    (original candidate : Word) : Prop :=
  original = frame.originalReturnAddress ∧ candidate = frame.candidateReturnAddress

/-- The first mixed-frame layer. Existing internal call proofs can be wrapped
without changing their semantics while callback-aware composition migrates to
one authoritative stack. -/
inductive RelationalRuntimeFrame where
  | internal (frame : RelationalRuntimeCallFrame)
  | externalCallback (frame : RelationalExternalCallbackFrame)
deriving Repr, DecidableEq

def RelationalRuntimeFrame.memoryHolds (frame : RelationalRuntimeFrame)
    (original candidate : Memory) : Prop :=
  match frame with
  | .internal internalFrame => internalFrame.memoryHolds original candidate
  | .externalCallback externalFrame => externalFrame.memoryHolds original candidate

def RelationalRuntimeFrame.valid (context : StaticProofContext)
    (world : RelationalWorld) (frame : RelationalRuntimeFrame) : Bool :=
  match frame with
  | .internal internalFrame =>
      internalFrame.toRelationalCallFrame.valid context &&
        internalFrame.toRelationalCallFrame.resolves context
  | .externalCallback externalFrame => externalFrame.valid context world

inductive RelationalRuntimeContinuation where
  | internal (targetId : Nat)
  | external (siteId eventIndex phaseIndex continuationTargetId : Nat)
deriving Repr, DecidableEq

def RelationalRuntimeFrame.originalStackAddress : RelationalRuntimeFrame -> Word
  | .internal frame => frame.originalStackAddress
  | .externalCallback frame => frame.originalStackAddress

def RelationalRuntimeFrame.candidateStackAddress : RelationalRuntimeFrame -> Word
  | .internal frame => frame.candidateStackAddress
  | .externalCallback frame => frame.candidateStackAddress

def RelationalRuntimeFrame.continuationMatches
    (frame : RelationalRuntimeFrame)
    (continuation : RelationalRuntimeContinuation) : Bool :=
  match frame, continuation with
  | .internal internalFrame, .internal targetId =>
      internalFrame.continuationTargetId == targetId
  | .externalCallback externalFrame,
      .external siteId eventIndex phaseIndex continuationTargetId =>
      externalFrame.siteId == siteId &&
        externalFrame.eventIndex == eventIndex &&
        externalFrame.phaseIndex == phaseIndex &&
        externalFrame.continuationTargetId == continuationTargetId
  | _, _ => false

def ReturnSlotOffsetPair.holdsRuntimeFrame (offsets : ReturnSlotOffsetPair)
    (frame : RelationalRuntimeFrame)
    (original candidate : Registers Word) : Prop :=
  original.get offsets.originalRegister + offsets.originalOffset =
      frame.originalStackAddress ∧
    candidate.get offsets.candidateRegister + offsets.candidateOffset =
      frame.candidateStackAddress

def RelationalMixedRuntimeStackHolds (context : StaticProofContext)
    (world : RelationalWorld) (original candidate : MachineState) :
    List RelationalRuntimeFrame -> List RelationalRuntimeContinuation ->
      List ReturnSlotOffsetPair -> Prop
  | [], [], [] => True
  | frame :: frames, continuation :: continuations, offset :: offsets =>
      frame.continuationMatches continuation = true ∧
        frame.valid context world = true ∧
        frame.memoryHolds original.memory candidate.memory ∧
        offset.holdsRuntimeFrame frame original.registers candidate.registers ∧
        RelationalMixedRuntimeStackHolds context world original candidate
          frames continuations offsets
  | _, _, _ => False

theorem ReturnSlotOffsetPair.holdsRuntimeFrame_internal
    (offsets : ReturnSlotOffsetPair) (frame : RelationalRuntimeCallFrame)
    (original candidate : Registers Word) :
    offsets.holdsRuntimeFrame (.internal frame) original candidate ↔
      offsets.holds frame original candidate := by
  rfl

theorem RelationalMixedRuntimeStackHolds.lengths
    (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : MachineState)
    (frames : List RelationalRuntimeFrame)
    (continuations : List RelationalRuntimeContinuation)
    (offsets : List ReturnSlotOffsetPair)
    (holds : RelationalMixedRuntimeStackHolds context world original candidate
      frames continuations offsets) :
    frames.length = continuations.length ∧ frames.length = offsets.length := by
  induction frames generalizing continuations offsets with
  | nil =>
      cases continuations <;> cases offsets <;>
        simp_all [RelationalMixedRuntimeStackHolds]
  | cons frame frames ih =>
      cases continuations with
      | nil => simp [RelationalMixedRuntimeStackHolds] at holds
      | cons continuation continuations =>
          cases offsets with
          | nil => simp [RelationalMixedRuntimeStackHolds] at holds
          | cons offset offsets =>
              simp only [RelationalMixedRuntimeStackHolds] at holds
              have lengths := ih continuations offsets holds.2.2.2.2
              exact ⟨by simpa using congrArg Nat.succ lengths.1,
                by simpa using congrArg Nat.succ lengths.2⟩

structure WorldExternalProtocolRequest where
  eventIndex : Nat
  phaseIndex : Nat
  event : WorldExternalEvent
  state : MachineState
  world : RelationalWorld

structure WorldExternalCallbackAction where
  targetId : Nat
  returnResourceId : Nat
  stackRangeId : Nat
  stackOffset : Nat
  returnAddress : Word
  state : MachineState
  world : RelationalWorld

inductive WorldExternalProtocolAction where
  | returned (result : WorldExternalResult)
  | callback (entry : WorldExternalCallbackAction)
  | terminated (world : RelationalWorld)

structure WorldExternalProtocolEnvironment where
  action : WorldExternalProtocolRequest -> WorldExternalProtocolAction

def RelationalExternalCallbackFrame.ofActions
    (siteId eventIndex phaseIndex continuationTargetId : Nat)
    (callback : RegisteredCallbackPair)
    (original candidate : WorldExternalCallbackAction) :
    RelationalExternalCallbackFrame := {
  siteId
  eventIndex
  phaseIndex
  continuationTargetId
  callback
  returnResourceId := original.returnResourceId
  stackRangeId := original.stackRangeId
  stackOffset := original.stackOffset
  originalReturnAddress := original.returnAddress
  candidateReturnAddress := candidate.returnAddress
  originalStackAddress := original.state.registers.esp
  candidateStackAddress := candidate.state.registers.esp
}

/-- Checked callback entry for the initial well-bracketed profile.

The callback inventory is consumed in LIFO order. The external transition may
add the opaque return token but cannot silently alter any other relational-world
component. The supplied machine states must already satisfy the callback entry
invariant and contain the checked return slot. -/
def RelationalExternalCallbackEntry
    (context : StaticProofContext) (invariant : StateInvariant)
    (before after : RelationalWorld) (frame : RelationalExternalCallbackFrame)
    (original candidate : MachineState) : Prop :=
  before.registeredCallbacks = frame.callback :: after.registeredCallbacks ∧
    after.dynamicRanges = before.dynamicRanges ∧
    after.stackRanges = before.stackRanges ∧
    after.importAddresses = before.importAddresses ∧
    after.tlsState = before.tlsState ∧
    opaqueResourcesExtend before after ∧
    frame.valid context after = true ∧
    frame.memoryHolds original.memory candidate.memory ∧
    frame.entryRegistersHold original.registers candidate.registers ∧
    StateRel context after invariant original candidate

def RelationalExternalCallbackReturn
    (context : StaticProofContext) (invariant : StateInvariant)
    (world : RelationalWorld) (frame : RelationalExternalCallbackFrame)
    (original candidate : MachineState)
    (originalTarget candidateTarget : Word) : Prop :=
  frame.valid context world = true ∧
    frame.memoryHolds original.memory candidate.memory ∧
    frame.returnTargetsHold originalTarget candidateTarget ∧
    StateRel context world invariant original candidate

theorem RelationalExternalCallbackEntry.callback_valid
    (context : StaticProofContext) (invariant : StateInvariant)
    (before after : RelationalWorld) (frame : RelationalExternalCallbackFrame)
    (original candidate : MachineState)
    (entry : RelationalExternalCallbackEntry context invariant before after frame
      original candidate) :
    frame.callback.valid context = true := by
  rcases entry with ⟨_, _, _, _, _, _, frameValid, _, _, _⟩
  simp only [RelationalExternalCallbackFrame.valid, Bool.and_eq_true] at frameValid
  exact frameValid.1.1

theorem RelationalExternalCallbackEntry.world_valid
    (context : StaticProofContext) (invariant : StateInvariant)
    (before after : RelationalWorld) (frame : RelationalExternalCallbackFrame)
    (original candidate : MachineState)
    (entry : RelationalExternalCallbackEntry context invariant before after frame
      original candidate) :
    after.valid context = true := by
  rcases entry with ⟨_, _, _, _, _, _, _, _, _, statesRelated⟩
  exact statesRelated.1

def ExternalCallbackActionsRelated
    (context : StaticProofContext) (invariant : StateInvariant)
    (before : RelationalWorld) (siteId eventIndex phaseIndex continuationTargetId : Nat)
    (original candidate : WorldExternalCallbackAction) : Prop :=
  original.targetId = candidate.targetId ∧
    original.returnResourceId = candidate.returnResourceId ∧
    original.stackRangeId = candidate.stackRangeId ∧
    original.stackOffset = candidate.stackOffset ∧
    original.world = candidate.world ∧
    ∃ callback : RegisteredCallbackPair,
      original.targetId = callback.targetId ∧
        RelationalExternalCallbackEntry context invariant before original.world
          (RelationalExternalCallbackFrame.ofActions siteId eventIndex phaseIndex
            continuationTargetId callback original candidate)
          original.state candidate.state

theorem ExternalCallbackActionsRelated.target
    (context : StaticProofContext) (invariant : StateInvariant)
    (before : RelationalWorld) (siteId eventIndex phaseIndex continuationTargetId : Nat)
    (original candidate : WorldExternalCallbackAction)
    (related : ExternalCallbackActionsRelated context invariant before siteId
      eventIndex phaseIndex continuationTargetId original candidate) :
    ∃ callback : RegisteredCallbackPair,
      original.targetId = callback.targetId ∧
        candidate.targetId = callback.targetId ∧ callback.valid context = true := by
  rcases related with ⟨targetEqual, _, _, _, _, callback, originalTarget, entry⟩
  refine ⟨callback, originalTarget, ?_, ?_⟩
  · rw [← targetEqual]
    exact originalTarget
  · exact entry.callback_valid

theorem RelationalExternalCallbackReturn.targets
    (context : StaticProofContext) (invariant : StateInvariant)
    (world : RelationalWorld) (frame : RelationalExternalCallbackFrame)
    (original candidate : MachineState)
    (originalTarget candidateTarget : Word)
    (returned : RelationalExternalCallbackReturn context invariant world frame
      original candidate originalTarget candidateTarget) :
    originalTarget = frame.originalReturnAddress ∧
      candidateTarget = frame.candidateReturnAddress :=
  returned.2.2.1

end StageA.Relational
