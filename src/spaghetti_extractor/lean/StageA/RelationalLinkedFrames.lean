import StageA.RelationalComposition

namespace StageA.Relational

open StageA.Formal

/-- A checked link from an active inner return slot to its suspended parent.
The gaps are natural-number distances, so the relation also records stack
ordering and excludes modular wraparound. -/
structure RelationalRuntimeCallFrameLink where
  callSourceTargetId : Nat
  resumeNodeId : Nat := 0
  resumeContinuation : Nat := 0
  resumeInventory : ReturnSlotOffsetInventory := ReturnSlotOffsetInventory.zero
  originalGap : Nat
  candidateGap : Nat
deriving Repr, DecidableEq

def RelationalRuntimeCallFrameLink.checked
    (link : RelationalRuntimeCallFrameLink) : Bool :=
  link.resumeInventory.checked &&
    4 <= link.originalGap && link.originalGap < 2 ^ 32 &&
    4 <= link.candidateGap && link.candidateGap < 2 ^ 32

def RelationalRuntimeCallFrameLink.holds
    (link : RelationalRuntimeCallFrameLink)
    (inner outer : RelationalRuntimeCallFrame) : Prop :=
  link.checked = true ∧
    inner.originalStackAddress.toNat + link.originalGap =
      outer.originalStackAddress.toNat ∧
    inner.candidateStackAddress.toNat + link.candidateGap =
      outer.candidateStackAddress.toNat ∧
    outer.continuationTargetId = link.resumeContinuation

/-- Frame validity and return-slot memory are inductive and independent of
the current register names for dormant frames. -/
def RelationalRuntimeCallFramesHold (context : StaticProofContext)
    (original candidate : MachineState) :
    List RelationalRuntimeCallFrame -> List Nat -> Prop
  | [], [] => True
  | frame :: frames, continuation :: continuations =>
      frame.continuationTargetId = continuation ∧
        frame.toRelationalCallFrame.valid context = true ∧
        frame.toRelationalCallFrame.resolves context = true ∧
        frame.memoryHolds original.memory candidate.memory ∧
        RelationalRuntimeCallFramesHold context original candidate frames
          continuations
  | _, _ => False

/-- There is one link between each adjacent pair of runtime frames. -/
def RelationalRuntimeCallFrameLinksHold :
    List RelationalRuntimeCallFrame ->
      List RelationalRuntimeCallFrameLink -> Prop
  | [], [] => True
  | [_], [] => True
  | inner :: outer :: frames, link :: links =>
      link.holds inner outer ∧
        RelationalRuntimeCallFrameLinksHold (outer :: frames) links
  | _, _ => False

/-- The linked profile names only the active frame. Dormant frames retain
their concrete return-slot facts and checked ordering without accumulating
unbounded ESP-relative offsets during recursion. -/
def RelationalLinkedRuntimeCallStackHolds (context : StaticProofContext)
    (original candidate : MachineState) :
    List RelationalRuntimeCallFrame -> List Nat ->
      Option ReturnSlotOffsetInventory ->
      List RelationalRuntimeCallFrameLink -> Prop
  | [], [], none, [] => True
  | frame :: frames, continuation :: continuations, some active, links =>
      active.checked = true ∧
        active.holds frame original.registers candidate.registers ∧
        RelationalRuntimeCallFramesHold context original candidate
          (frame :: frames) (continuation :: continuations) ∧
        RelationalRuntimeCallFrameLinksHold (frame :: frames) links
  | _, _, _, _ => False

/-- A finite control abstraction records only the current node and active
frame shape. The remaining continuation stack is checked inductively by
`RelationalLinkedRuntimeCallStackHolds`, so recursive depth does not create
new profile rows. -/
structure LinkedProductControlState where
  nodeId : Nat
  continuation : Option Nat
  active : Option ReturnSlotOffsetInventory
deriving Repr, DecidableEq

def LinkedProductControlState.checked
    (state : LinkedProductControlState) : Bool :=
  match state.continuation, state.active with
  | none, none => true
  | some _, some inventory => inventory.checked
  | _, _ => false

structure LinkedProductControlProfile where
  states : List LinkedProductControlState
deriving Repr, DecidableEq

def LinkedProductControlProfile.checked
    (profile : LinkedProductControlProfile) : Bool :=
  profile.states.all LinkedProductControlState.checked

def LinkedProductControlProfile.Allows
    (profile : LinkedProductControlProfile) (nodeId : Nat)
    (continuations : List Nat)
    (active : Option ReturnSlotOffsetInventory) : Bool :=
  let state : LinkedProductControlState := {
    nodeId
    continuation := continuations.head?
    active
  }
  profile.checked && profile.states.contains state

def RelationalRuntimeCallFrameLink.profileChecked
    (link : RelationalRuntimeCallFrameLink)
    (profile : LinkedProductControlProfile) : Bool :=
  link.checked && profile.checked && profile.states.contains {
    nodeId := link.resumeNodeId
    continuation := some link.resumeContinuation
    active := some link.resumeInventory
  }

theorem LinkedProductControlProfile.allowsResumeOfLink
    (profile : LinkedProductControlProfile)
    (link : RelationalRuntimeCallFrameLink)
    (inner outer : RelationalRuntimeCallFrame)
    (continuations : List Nat)
    (profileChecked : link.profileChecked profile = true)
    (linkHolds : link.holds inner outer) :
    profile.Allows link.resumeNodeId
      (outer.continuationTargetId :: continuations)
      (some link.resumeInventory) = true := by
  simp only [RelationalRuntimeCallFrameLink.profileChecked,
    Bool.and_eq_true] at profileChecked
  rcases profileChecked with ⟨⟨_linkChecked, profileValid⟩, listed⟩
  rcases linkHolds with ⟨_, _, _, continuationExact⟩
  simpa [LinkedProductControlProfile.Allows, continuationExact,
    profileValid] using listed

theorem RelationalRuntimeCallFramesHold.of_memory_eq
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (holds : RelationalRuntimeCallFramesHold context beforeOriginal
      beforeCandidate frames continuations)
    (originalMemory : afterOriginal.memory = beforeOriginal.memory)
    (candidateMemory : afterCandidate.memory = beforeCandidate.memory) :
    RelationalRuntimeCallFramesHold context afterOriginal afterCandidate
      frames continuations := by
  induction frames generalizing continuations with
  | nil =>
      cases continuations <;>
        simp_all [RelationalRuntimeCallFramesHold]
  | cons frame frames ih =>
      cases continuations with
      | nil => simp [RelationalRuntimeCallFramesHold] at holds
      | cons continuation continuations =>
          simp only [RelationalRuntimeCallFramesHold] at holds ⊢
          exact ⟨holds.1, holds.2.1, holds.2.2.1,
            by simpa [RelationalRuntimeCallFrame.memoryHolds, originalMemory,
              candidateMemory] using holds.2.2.2.1,
            ih continuations holds.2.2.2.2⟩

theorem RelationalRuntimeCallFramesHold.afterMemory
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (holds : RelationalRuntimeCallFramesHold context beforeOriginal
      beforeCandidate frames continuations)
    (framesPreserved : ∀ frame : RelationalRuntimeCallFrame,
      frame.memoryHolds beforeOriginal.memory beforeCandidate.memory →
        frame.memoryHolds afterOriginal.memory afterCandidate.memory) :
    RelationalRuntimeCallFramesHold context afterOriginal afterCandidate
      frames continuations := by
  induction frames generalizing continuations with
  | nil =>
      cases continuations <;>
        simp_all [RelationalRuntimeCallFramesHold]
  | cons frame frames ih =>
      cases continuations with
      | nil => simp [RelationalRuntimeCallFramesHold] at holds
      | cons continuation continuations =>
          simp only [RelationalRuntimeCallFramesHold] at holds ⊢
          exact ⟨holds.1, holds.2.1, holds.2.2.1,
            framesPreserved frame holds.2.2.2.1,
            ih continuations holds.2.2.2.2⟩

def RelationalRuntimeCallFrame.writesAvoid
    (frame : RelationalRuntimeCallFrame)
    (originalWrites candidateWrites : List (Word × Word)) : Prop :=
  WritesAvoidWord frame.originalStackAddress originalWrites ∧
    WritesAvoidWord frame.candidateStackAddress candidateWrites

theorem RelationalRuntimeCallFrame.memoryHolds_afterWrites
    (frame : RelationalRuntimeCallFrame)
    (original candidate : Memory)
    (originalWrites candidateWrites : List (Word × Word))
    (holds : frame.memoryHolds original candidate)
    (avoids : frame.writesAvoid originalWrites candidateWrites) :
    frame.memoryHolds
      (applyConcreteWrites original originalWrites)
      (applyConcreteWrites candidate candidateWrites) := by
  rcases holds with ⟨originalHolds, candidateHolds⟩
  constructor
  · rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ avoids.1]
    exact originalHolds
  · rw [Memory.read32_applyConcreteWrites_of_avoids _ _ _ avoids.2]
    exact candidateHolds

theorem RelationalRuntimeCallFramesHold.afterWrites
    (context : StaticProofContext)
    (original candidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (originalWrites candidateWrites : List (Word × Word))
    (holds : RelationalRuntimeCallFramesHold context original candidate
      frames continuations)
    (avoids : ∀ frame, frame ∈ frames →
      frame.writesAvoid originalWrites candidateWrites) :
    RelationalRuntimeCallFramesHold context
      { original with memory := applyConcreteWrites original.memory originalWrites }
      { candidate with memory := applyConcreteWrites candidate.memory candidateWrites }
      frames continuations := by
  induction frames generalizing continuations with
  | nil =>
      cases continuations <;>
        simp_all [RelationalRuntimeCallFramesHold]
  | cons frame frames ih =>
      cases continuations with
      | nil => simp [RelationalRuntimeCallFramesHold] at holds
      | cons continuation continuations =>
          simp only [RelationalRuntimeCallFramesHold] at holds ⊢
          refine ⟨holds.1, holds.2.1, holds.2.2.1, ?_, ?_⟩
          · exact frame.memoryHolds_afterWrites original.memory candidate.memory
              originalWrites candidateWrites holds.2.2.2.1
              (avoids frame (by simp))
          · exact ih continuations holds.2.2.2.2
              (fun tailFrame member => avoids tailFrame (by simp [member]))

theorem RelationalLinkedRuntimeCallStackHolds.afterNoWrite
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (continuations : List Nat)
    (active : Option ReturnSlotOffsetInventory)
    (links : List RelationalRuntimeCallFrameLink)
    (holds : RelationalLinkedRuntimeCallStackHolds context beforeOriginal
      beforeCandidate frames continuations active links)
    (originalMemory : afterOriginal.memory = beforeOriginal.memory)
    (candidateMemory : afterCandidate.memory = beforeCandidate.memory)
    (originalRegisters : afterOriginal.registers = beforeOriginal.registers)
    (candidateRegisters : afterCandidate.registers = beforeCandidate.registers) :
    RelationalLinkedRuntimeCallStackHolds context afterOriginal afterCandidate
      frames continuations active links := by
  cases frames with
  | nil =>
      cases continuations <;> cases active <;> cases links <;>
        simp_all [RelationalLinkedRuntimeCallStackHolds]
  | cons frame frames =>
      cases continuations with
      | nil => simp [RelationalLinkedRuntimeCallStackHolds] at holds
      | cons continuation continuations =>
          cases active with
          | none => simp [RelationalLinkedRuntimeCallStackHolds] at holds
          | some inventory =>
              simp only [RelationalLinkedRuntimeCallStackHolds] at holds ⊢
              exact ⟨holds.1,
                by simpa [originalRegisters, candidateRegisters] using holds.2.1,
                RelationalRuntimeCallFramesHold.of_memory_eq context
                  beforeOriginal beforeCandidate afterOriginal afterCandidate
                  (frame :: frames) (continuation :: continuations) holds.2.2.1
                  originalMemory candidateMemory,
                holds.2.2.2⟩

theorem RelationalLinkedRuntimeCallStackHolds.afterActiveTransfer
    (context : StaticProofContext) (world : RelationalWorld)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : ReturnSlotFrameInventoryTransferClaim)
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation : Nat) (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (checked : claim.checked context sourceInvariant originalBehavior
      candidateBehavior = true)
    (holds : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (frame :: frames) (continuation :: continuations)
      (some claim.source) links)
    (related : StateRel context world sourceInvariant originalState candidateState)
    (originalMemory :
      ((originalBehavior.eval originalState).nextMachineState
        originalState).memory = originalState.memory)
    (candidateMemory :
      ((candidateBehavior.eval candidateState).nextMachineState
        candidateState).memory = candidateState.memory) :
    RelationalLinkedRuntimeCallStackHolds context
      ((originalBehavior.eval originalState).nextMachineState originalState)
      ((candidateBehavior.eval candidateState).nextMachineState candidateState)
      (frame :: frames) (continuation :: continuations)
      (some claim.target) links := by
  simp only [RelationalLinkedRuntimeCallStackHolds] at holds ⊢
  have transferred := returnSlotFrameInventoryTransferHolds_of_checked
    context world sourceInvariant originalBehavior candidateBehavior claim frame
    originalState candidateState checked holds.2.1
    holds.2.2.1.2.2.2.1 related
  have framesAfter := RelationalRuntimeCallFramesHold.of_memory_eq context
    originalState candidateState
    ((originalBehavior.eval originalState).nextMachineState originalState)
    ((candidateBehavior.eval candidateState).nextMachineState candidateState)
    (frame :: frames) (continuation :: continuations) holds.2.2.1
    originalMemory candidateMemory
  simp only [ReturnSlotFrameInventoryTransferClaim.checked,
    Bool.and_eq_true, beq_iff_eq] at checked
  exact ⟨checked.1.1.1.2, transferred.1, framesAfter, holds.2.2.2⟩

theorem RelationalLinkedRuntimeCallStackHolds.pushFirst
    (context : StaticProofContext) (original candidate : MachineState)
    (frame : RelationalRuntimeCallFrame) (continuation : Nat)
    (active : ReturnSlotOffsetInventory)
    (activeChecked : active.checked = true)
    (activeHolds : active.holds frame original.registers candidate.registers)
    (continuationMatches : frame.continuationTargetId = continuation)
    (frameValid : frame.toRelationalCallFrame.valid context = true)
    (frameResolves : frame.toRelationalCallFrame.resolves context = true)
    (frameMemory : frame.memoryHolds original.memory candidate.memory) :
    RelationalLinkedRuntimeCallStackHolds context original candidate
      [frame] [continuation] (some active) [] := by
  simp [RelationalLinkedRuntimeCallStackHolds,
    RelationalRuntimeCallFramesHold, RelationalRuntimeCallFrameLinksHold,
    activeChecked, activeHolds, continuationMatches, frameValid, frameResolves,
    frameMemory]

theorem RelationalLinkedRuntimeCallStackHolds.pushNested
    (context : StaticProofContext) (original candidate : MachineState)
    (frame outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation outerContinuation : Nat) (continuations : List Nat)
    (active outerActive : ReturnSlotOffsetInventory)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (outerHolds : RelationalLinkedRuntimeCallStackHolds context original candidate
      (outer :: frames) (outerContinuation :: continuations)
      (some outerActive) links)
    (activeChecked : active.checked = true)
    (activeHolds : active.holds frame original.registers candidate.registers)
    (continuationMatches : frame.continuationTargetId = continuation)
    (frameValid : frame.toRelationalCallFrame.valid context = true)
    (frameResolves : frame.toRelationalCallFrame.resolves context = true)
    (frameMemory : frame.memoryHolds original.memory candidate.memory)
    (linkHolds : link.holds frame outer) :
    RelationalLinkedRuntimeCallStackHolds context original candidate
      (frame :: outer :: frames)
      (continuation :: outerContinuation :: continuations)
      (some active) (link :: links) := by
  simp only [RelationalLinkedRuntimeCallStackHolds] at outerHolds ⊢
  simp only [RelationalRuntimeCallFramesHold,
    RelationalRuntimeCallFrameLinksHold] at outerHolds ⊢
  exact ⟨activeChecked, activeHolds,
    ⟨continuationMatches, frameValid, frameResolves, frameMemory,
      outerHolds.2.2.1⟩,
    ⟨linkHolds, outerHolds.2.2.2⟩⟩

theorem RelationalLinkedRuntimeCallStackHolds.pushNestedAfter
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (frame outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation outerContinuation : Nat) (continuations : List Nat)
    (active outerActive : ReturnSlotOffsetInventory)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (outerBefore : RelationalLinkedRuntimeCallStackHolds context beforeOriginal
      beforeCandidate (outer :: frames) (outerContinuation :: continuations)
      (some outerActive) links)
    (outerFramesAfter : RelationalRuntimeCallFramesHold context afterOriginal
      afterCandidate (outer :: frames) (outerContinuation :: continuations))
    (activeChecked : active.checked = true)
    (activeHolds : active.holds frame afterOriginal.registers
      afterCandidate.registers)
    (continuationMatches : frame.continuationTargetId = continuation)
    (frameValid : frame.toRelationalCallFrame.valid context = true)
    (frameResolves : frame.toRelationalCallFrame.resolves context = true)
    (frameMemory : frame.memoryHolds afterOriginal.memory afterCandidate.memory)
    (linkHolds : link.holds frame outer) :
    RelationalLinkedRuntimeCallStackHolds context afterOriginal afterCandidate
      (frame :: outer :: frames)
      (continuation :: outerContinuation :: continuations)
      (some active) (link :: links) := by
  simp only [RelationalLinkedRuntimeCallStackHolds] at outerBefore ⊢
  simp only [RelationalRuntimeCallFramesHold,
    RelationalRuntimeCallFrameLinksHold] at outerBefore ⊢
  exact ⟨activeChecked, activeHolds,
    ⟨continuationMatches, frameValid, frameResolves, frameMemory,
      outerFramesAfter⟩,
    ⟨linkHolds, outerBefore.2.2.2⟩⟩

theorem RelationalLinkedRuntimeCallStackHolds.popNested
    (context : StaticProofContext) (original candidate : MachineState)
    (frame outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation outerContinuation : Nat) (continuations : List Nat)
    (active : ReturnSlotOffsetInventory)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (holds : RelationalLinkedRuntimeCallStackHolds context original candidate
      (frame :: outer :: frames)
      (continuation :: outerContinuation :: continuations)
      (some active) (link :: links))
    (resumeHolds : link.resumeInventory.holds outer original.registers
      candidate.registers) :
    RelationalLinkedRuntimeCallStackHolds context original candidate
      (outer :: frames) (outerContinuation :: continuations)
      (some link.resumeInventory) links := by
  simp only [RelationalLinkedRuntimeCallStackHolds,
    RelationalRuntimeCallFramesHold,
    RelationalRuntimeCallFrameLinksHold] at holds ⊢
  have resumeChecked : link.resumeInventory.checked = true := by
    have linkChecked := holds.2.2.2.1.1
    simp only [RelationalRuntimeCallFrameLink.checked,
      Bool.and_eq_true] at linkChecked
    exact linkChecked.1.1.1.1
  exact ⟨resumeChecked, resumeHolds, holds.2.2.1.2.2.2.2,
    holds.2.2.2.2⟩

theorem RelationalLinkedRuntimeCallStackHolds.popNestedAfter
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (frame outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation outerContinuation : Nat) (continuations : List Nat)
    (active : ReturnSlotOffsetInventory)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (before : RelationalLinkedRuntimeCallStackHolds context beforeOriginal
      beforeCandidate (frame :: outer :: frames)
      (continuation :: outerContinuation :: continuations)
      (some active) (link :: links))
    (outerFramesAfter : RelationalRuntimeCallFramesHold context afterOriginal
      afterCandidate (outer :: frames) (outerContinuation :: continuations))
    (resumeHolds : link.resumeInventory.holds outer afterOriginal.registers
      afterCandidate.registers) :
    RelationalLinkedRuntimeCallStackHolds context afterOriginal afterCandidate
      (outer :: frames) (outerContinuation :: continuations)
      (some link.resumeInventory) links := by
  simp only [RelationalLinkedRuntimeCallStackHolds,
    RelationalRuntimeCallFrameLinksHold] at before ⊢
  have resumeChecked : link.resumeInventory.checked = true := by
    have linkChecked := before.2.2.2.1.1
    simp only [RelationalRuntimeCallFrameLink.checked,
      Bool.and_eq_true] at linkChecked
    exact linkChecked.1.1.1.1
  exact ⟨resumeChecked, resumeHolds, outerFramesAfter,
    before.2.2.2.2⟩

theorem RelationalLinkedRuntimeCallStackHolds.popLast
    (context : StaticProofContext) (original candidate : MachineState)
    (frame : RelationalRuntimeCallFrame) (continuation : Nat)
    (active : ReturnSlotOffsetInventory)
    (_holds : RelationalLinkedRuntimeCallStackHolds context original candidate
      [frame] [continuation] (some active) []) :
    RelationalLinkedRuntimeCallStackHolds context original candidate
      [] [] none [] := by
  simp [RelationalLinkedRuntimeCallStackHolds]

end StageA.Relational
