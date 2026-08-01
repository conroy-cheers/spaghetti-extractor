import StageA.RelationalOriginalMemoryPostPreservation
import StageA.RelationalOriginalProvenancePreservation
import StageA.RelationalOriginalTargetControlPreservation

namespace StageA.Relational.OriginalNoWriteTargetPreservation

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalMemoryEffectPreservation
open StageA.Relational.OriginalProvenancePreservation
open StageA.Relational.OriginalRuntimeMemoryPartition
open StageA.Relational.OriginalStaticWordExecutionInvariant
open StageA.Relational.OriginalTargetControlPreservation
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.OriginalValueFlowExecutionInvariant
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.ProgramCertificate
open StageA.Relational.ValueProvenance

/-!
# Generic no-write target preservation

This module composes the exact target effect, checked control routing, call
frames, normalized provenance effects, and the runtime-memory partition for a
target whose original-side effect performs no memory writes.  It does not
classify control flow or infer effects.  Generated evidence must retain the
existing exact control transition and prove both an empty original write list
and preservation of the active relational world.

The result is the ordinary `CheckedOriginalTargetPreservationCase` and
`CheckedOriginalTargetPreservationProvider`; there is no second acceptance
interface.  Register changes still require the finite provenance obligations
from `CheckedOriginalTargetProvenancePost`.
-/

/-- A no-write local target may change registers and control, but it cannot
change the active relational world.  Terminal faults do not carry a world. -/
def OriginalCallbacksPreservedOrPopped
    (before after : List WorldExternalCallbackRuntime) : Prop :=
  after = before ∨ exists callback, before = callback :: after

def OriginalNoWriteWorldFrame (before : RelationalWorld)
    (beforeCallbacks : List WorldExternalCallbackRuntime) :
    OriginalNormalizedSuccessor -> Prop
  | .running _ _ _ _ after => after = before
  | .callbackRunning _ _ _ _ after callbacks =>
      after = before /\ callbacks = beforeCallbacks
  | .awaitingExternal suspension callbacks =>
      suspension.world = before /\
        OriginalCallbacksPreservedOrPopped beforeCallbacks callbacks
  | .returned _ after => after = before
  | .terminated after => after = before
  | .fault _ => True

/-! ## Generic no-write construction helpers -/

/-- A dormant call frame observes only the relational world and concrete
memory.  Exact memory equality therefore preserves it when the world is
unchanged, independently of register and flag updates. -/
theorem DormantOriginalCallFrame.Holds.sameWorldOfMemoryEq
    (frame : DormantOriginalCallFrame) (context : StaticProofContext)
    (world : RelationalWorld) (before after : MachineState)
    (memoryExact : after.memory = before.memory)
    (holds : frame.Holds context world before) :
    frame.Holds context world after := by
  simpa [DormantOriginalCallFrame.Holds, memoryExact] using holds

/-- Lift one checked normalized effect summary across the callback-sensitive
resume constructor.  The concrete after-state remains explicit; this helper
does not infer an effect summary or a successor. -/
def CheckedOriginalNormalizedTransitionEffects.ofResume
    (before after : MachineState) (effects : TransitionEffects)
    (effectsChecked : effects.checked = true)
    (implements : effects.OriginalRuntimeImplements before after)
    (callbacks : List WorldExternalCallbackRuntime)
    (nextTargetId : Nat) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld) :
    CheckedOriginalNormalizedTransitionEffects before
      (originalNormalizedResume callbacks nextTargetId after calls eventIndex
        world) := by
  refine { effects, effectsChecked, implements := ?_ }
  cases callbacks <;> exact implements

/-- Checking an empty proposal inventory is strong enough to prove that the
authoritative normalized write inventory itself is empty. -/
theorem normalizedWriteProposalsChecked_empty
    (writes : List (Expr × Expr))
    (checked : normalizedWriteProposalsChecked writes [] = true) :
    writes = [] := by
  have addresses := normalizedWriteProposalsChecked_addresses writes [] checked
  cases writes with
  | nil => rfl
  | cons write writes => simp at addresses

/-- Construct direct-jump control evidence for a checked target whose concrete
decoded state update leaves memory unchanged.  Outcome shape and destination
membership remain explicit proof premises. -/
def CheckedOriginalTargetControlEvidence.ofNoWriteJump
    {program : Program} {targetId nextTargetId : Nat}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {checked : CheckedOriginalTargetEffect program targetId}
    (outcomeExact : forall state calls,
      (checked.components.decodedBehavior state calls).outcome =
        .jump nextTargetId)
    (memoryExact : forall state calls,
      ((checked.components.decodedBehavior state calls).nextMachineState
        state).memory = state.memory)
    (nextReachable : nextTargetId ∈ inventory.reachableTargets.targetIds) :
    CheckedOriginalTargetControlEvidence originalContext inventory checked where
  outcome invocation holds _faultFree := by
    let behavior := checked.components.decodedBehavior invocation.state
      invocation.calls
    let afterState := behavior.nextMachineState invocation.state
    have concreteOutcome : behavior.outcome = .jump nextTargetId := by
      exact outcomeExact invocation.state invocation.calls
    have concreteMemory : afterState.memory = invocation.state.memory := by
      exact memoryExact invocation.state invocation.calls
    refine {
      control := ?_
      successor := originalNormalizedResume invocation.routingCallbacks
        nextTargetId afterState invocation.calls invocation.eventIndex
        invocation.world
      successorExact := ?_
      post := ?_
    }
    · rw [concreteOutcome]
      exact (CheckedOriginalStaticTargetEvidence.mk nextReachable).jumpControl
    · change
        (transitionFromWorldOutcome program.worldProgram targetId afterState
          invocation.calls invocation.eventIndex invocation.world
          invocation.routingCallbacks behavior.outcome).next = _
      rw [concreteOutcome]
      exact originalNormalizedResume_execution _ _ _ _ _ _ |>.symm
    · exact controlPostOfPreservedFrames invocation holds nextTargetId afterState
        invocation.eventIndex invocation.world nextReachable
        (fun frame frameHolds =>
          DormantOriginalCallFrame.Holds.sameWorldOfMemoryEq frame
            program.worldProgram.context
            invocation.world invocation.state afterState concreteMemory
            frameHolds)

/-- Conditional counterpart of `ofNoWriteJump`.  Both decoded branch
destinations are checked once; Lean selects and proves reachability of the
actual successor for each invocation. -/
def CheckedOriginalTargetControlEvidence.ofNoWriteBranch
    {program : Program} {targetId taken fallthrough : Nat}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {checked : CheckedOriginalTargetEffect program targetId}
    (condition : MachineState -> List Nat -> Bool)
    (outcomeExact : forall state calls,
      (checked.components.decodedBehavior state calls).outcome =
        .branch (condition state calls) taken fallthrough)
    (memoryExact : forall state calls,
      ((checked.components.decodedBehavior state calls).nextMachineState
        state).memory = state.memory)
    (takenReachable : taken ∈ inventory.reachableTargets.targetIds)
    (fallthroughReachable : fallthrough ∈
      inventory.reachableTargets.targetIds) :
    CheckedOriginalTargetControlEvidence originalContext inventory checked where
  outcome invocation holds _faultFree := by
    let behavior := checked.components.decodedBehavior invocation.state
      invocation.calls
    let afterState := behavior.nextMachineState invocation.state
    let branchCondition := condition invocation.state invocation.calls
    let nextTargetId := if branchCondition then taken else fallthrough
    have concreteOutcome :
        behavior.outcome = .branch branchCondition taken fallthrough := by
      exact outcomeExact invocation.state invocation.calls
    have concreteMemory : afterState.memory = invocation.state.memory := by
      exact memoryExact invocation.state invocation.calls
    have nextReachable :
        nextTargetId ∈ inventory.reachableTargets.targetIds := by
      simp only [nextTargetId]
      split <;> assumption
    refine {
      control := ?_
      successor := originalNormalizedResume invocation.routingCallbacks
        nextTargetId afterState invocation.calls invocation.eventIndex
        invocation.world
      successorExact := ?_
      post := ?_
    }
    · rw [concreteOutcome]
      exact (CheckedOriginalBranchTargetEvidence.mk takenReachable
        fallthroughReachable).branchControl
    · change
        (transitionFromWorldOutcome program.worldProgram targetId afterState
          invocation.calls invocation.eventIndex invocation.world
          invocation.routingCallbacks behavior.outcome).next = _
      rw [concreteOutcome]
      simp only [transitionFromWorldOutcome]
      exact originalNormalizedResume_execution _ _ _ _ _ _ |>.symm
    · exact controlPostOfPreservedFrames invocation holds nextTargetId afterState
        invocation.eventIndex invocation.world nextReachable
        (fun frame frameHolds =>
          DormantOriginalCallFrame.Holds.sameWorldOfMemoryEq frame
            program.worldProgram.context
            invocation.world invocation.state afterState concreteMemory
            frameHolds)

/-- Build all provenance postconditions for an unchanged-world local resume.
A value-flow fact may become active only when it was already active and its
concrete location value is unchanged.  Register and stack/dynamic indirect
sources must not become active; those cases require their explicit transfer
certificates instead. -/
def OriginalValueFlowEndpointObligation.ofResume
    {program : DecodedWorldProgram} {targetId nextTargetId : Nat}
    (invocation : OriginalTargetInvocation targetId)
    (effects : TransitionEffects) (callbacks : List WorldExternalCallbackRuntime)
    (afterState : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld)
    (fact : OriginalFiniteValueFlowFact program.context)
    (transfer : nextTargetId ∈ fact.targetIds ->
      OriginalValueFlowEndpointTransfer fact invocation effects afterState
        world) :
    OriginalValueFlowEndpointObligation invocation effects
      (originalNormalizedResume callbacks nextTargetId afterState calls
        eventIndex world) fact := by
  cases callbacks <;> exact transfer

def OriginalRegisterTargetEndpointObligation.ofInactiveResume
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    {targetId nextTargetId : Nat}
    (invocation : OriginalTargetInvocation targetId)
    (effects : TransitionEffects) (callbacks : List WorldExternalCallbackRuntime)
    (afterState : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld)
    (requirement : OriginalRegisterTargetRequirement originalContext)
    (inactive : nextTargetId ≠
      requirement.certificate.certificate.site.sourceTargetId) :
    OriginalRegisterTargetEndpointObligation inventory invocation effects
      (originalNormalizedResume callbacks nextTargetId afterState calls
        eventIndex world) requirement := by
  cases callbacks <;> intro endpoint <;> exact False.elim (inactive endpoint)

def OriginalStackDynamicTargetEndpointObligation.ofInactiveResume
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    {targetId nextTargetId : Nat}
    (invocation : OriginalTargetInvocation targetId)
    (callbacks : List WorldExternalCallbackRuntime)
    (afterState : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld)
    (requirement : OriginalStackDynamicTargetRequirement originalContext)
    (inactive : nextTargetId ≠ requirement.site.sourceTargetId) :
    OriginalStackDynamicTargetEndpointObligation inventory invocation
      (originalNormalizedResume callbacks nextTargetId afterState calls
        eventIndex world) requirement := by
  cases callbacks <;> intro endpoint <;> exact False.elim (inactive endpoint)

def CheckedOriginalProvenancePostWitness.ofInertLocalResume
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {targetId nextTargetId : Nat}
    {invocation : OriginalTargetInvocation targetId}
    {afterState : MachineState} {calls : List Nat} {eventIndex : Nat}
    {normalized : CheckedOriginalNormalizedTransitionEffects invocation.state
      (originalNormalizedResume invocation.routingCallbacks nextTargetId
        afterState calls eventIndex invocation.world)}
    (valueFlowsInert : forall fact,
      fact ∈ inventory.valueFlows.facts ->
      nextTargetId ∈ fact.targetIds ->
        targetId ∈ fact.targetIds /\
          originalLocationValue fact.location afterState =
            originalLocationValue fact.location invocation.state)
    (registerTargetsInactive : forall requirement,
      requirement ∈ inventory.registerTargets ->
        nextTargetId ≠
          requirement.certificate.certificate.site.sourceTargetId)
    (stackDynamicTargetsInactive : forall requirement,
      requirement ∈ inventory.stackDynamicTargets ->
        nextTargetId ≠ requirement.site.sourceTargetId) :
    CheckedOriginalProvenancePostWitness inventory invocation
      (originalNormalizedResume invocation.routingCallbacks nextTargetId
        afterState calls eventIndex invocation.world) normalized := by
  refine {
    valueFlows := ?_
    registerTargets := ?_
    stackDynamicTargets := ?_
  }
  · intro fact factMember
    apply OriginalValueFlowEndpointObligation.ofResume
    intro endpoint
    have inert := valueFlowsInert fact factMember endpoint
    exact .valueFrame inert.1 inert.2 {
          preserves := fun _origin _member _value holds => holds
    }
  · intro requirement requirementMember
    exact OriginalRegisterTargetEndpointObligation.ofInactiveResume inventory
      invocation normalized.effects invocation.routingCallbacks afterState calls
      eventIndex invocation.world requirement
      (registerTargetsInactive requirement requirementMember)
  · intro requirement requirementMember
    exact OriginalStackDynamicTargetEndpointObligation.ofInactiveResume inventory
      invocation invocation.routingCallbacks afterState calls eventIndex
      invocation.world requirement
      (stackDynamicTargetsInactive requirement requirementMember)

/-- The complete non-control evidence for one exact routed target transition.
The normalized effect is bound to that transition by the existing provenance
adapter.  `originalWrites = []` therefore describes the concrete successor
memory rather than a detached analysis claim. -/
structure CheckedOriginalNoWritePost
    {program : Program} {targetId : Nat}
    {checked : CheckedOriginalTargetEffect program targetId}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {invocation : OriginalTargetInvocation targetId}
    (transition : CheckedOriginalTargetTransition checked originalContext
      inventory.reachableTargets.targetIds invocation) where
  provenance : CheckedOriginalTargetProvenancePost transition
  originalWritesEmpty :
    provenance.effects.normalized.effects.originalWrites = []
  worldFrame : OriginalNoWriteWorldFrame invocation.world
    invocation.routingCallbacks transition.successor

theorem CheckedOriginalNoWritePost.memoryUnchanged
    {program : Program} {targetId : Nat}
    {checked : CheckedOriginalTargetEffect program targetId}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {invocation : OriginalTargetInvocation targetId}
    {transition : CheckedOriginalTargetTransition checked originalContext
      inventory.reachableTargets.targetIds invocation}
    (post : CheckedOriginalNoWritePost transition) :
    match transition.successor with
    | .running _ state _ _ _ => state.memory = invocation.state.memory
    | .callbackRunning _ state _ _ _ _ =>
        state.memory = invocation.state.memory
    | .awaitingExternal suspension _ =>
        suspension.state.memory = invocation.state.memory
    | .returned state _ => state.memory = invocation.state.memory
    | .terminated _ | .fault _ => True := by
  have implements := post.provenance.effects.normalized.implements
  cases successorExact : transition.successor with
  | running nextTarget state calls eventIndex world =>
      simp only [successorExact] at implements
      simpa [successorExact, TransitionEffects.OriginalRuntimeImplements,
        TransitionEffects.OriginalMemoryImplements,
        TransitionEffects.originalConcreteWrites,
        post.originalWritesEmpty, applyConcreteWrites] using implements.1
  | callbackRunning nextTarget state calls eventIndex world callbacks =>
      simp only [successorExact] at implements
      simpa [successorExact, TransitionEffects.OriginalRuntimeImplements,
        TransitionEffects.OriginalMemoryImplements,
        TransitionEffects.originalConcreteWrites,
        post.originalWritesEmpty, applyConcreteWrites] using implements.1
  | awaitingExternal suspension callbacks =>
      simp only [successorExact] at implements
      simpa [successorExact, TransitionEffects.OriginalRuntimeImplements,
        TransitionEffects.OriginalMemoryImplements,
        TransitionEffects.originalConcreteWrites,
        post.originalWritesEmpty, applyConcreteWrites] using implements.1
  | returned state world =>
      simp only [successorExact] at implements
      simpa [successorExact, TransitionEffects.OriginalRuntimeImplements,
        TransitionEffects.OriginalMemoryImplements,
        TransitionEffects.originalConcreteWrites,
        post.originalWritesEmpty, applyConcreteWrites] using implements.1
  | terminated world => trivial
  | fault cause => trivial

theorem activeStaticWordsAndSuspendedHold
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId)
    (holds : inventory.Holds invocation.execution) :
    inventory.staticWords.HoldsIn program.context invocation.world
        invocation.state.memory /\
      SuspendedOriginalStaticWordsHold program.context inventory.staticWords
        invocation.routingCallbacks := by
  have staticWords := inventory.staticWordsHold holds
  cases callbackCase : invocation.callbacks with
  | none =>
      simpa [OriginalTargetInvocation.execution,
        OriginalTargetInvocation.routingCallbacks, callbackCase,
        OriginalStaticWordInventory.Holds,
        SuspendedOriginalStaticWordsHold] using And.intro staticWords trivial
  | some callbacks =>
      simpa [OriginalTargetInvocation.execution,
        OriginalTargetInvocation.routingCallbacks, callbackCase,
        OriginalStaticWordInventory.Holds] using staticWords

def unchangedOrigins
    (context : StaticProofContext) (world : RelationalWorld)
    (requirement : OriginalStaticWordRequirement) :
    requirement.OriginsPreserved context world world := by
  intro origin _member value holds
  exact holds

def unchangedProtectedMemory
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (world : RelationalWorld) (beforeMemory afterMemory : Memory)
    (memoryExact : afterMemory = beforeMemory) :
    OriginalProtectedMemoryUpdate context inventory world world beforeMemory
      afterMemory where
  words requirement _member := .unchangedRead
    (by rw [memoryExact])
    (unchangedOrigins context world requirement)

theorem SuspendedOriginalStaticWordsHold.ofPreservedOrPopped
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (before after : List WorldExternalCallbackRuntime)
    (holds : SuspendedOriginalStaticWordsHold context inventory before)
    (frame : OriginalCallbacksPreservedOrPopped before after) :
    SuspendedOriginalStaticWordsHold context inventory after := by
  rcases frame with same | ⟨callback, popped⟩
  · simpa [same] using holds
  · subst before
    exact holds.2.2

theorem OriginalRuntimeMemoryPartition.SuspendedHold.ofPreservedOrPopped
    (context : StaticProofContext)
    (before after : List WorldExternalCallbackRuntime)
    (holds : OriginalRuntimeMemoryPartition.SuspendedHold context before)
    (frame : OriginalCallbacksPreservedOrPopped before after) :
    OriginalRuntimeMemoryPartition.SuspendedHold context after := by
  rcases frame with same | ⟨callback, popped⟩
  · simpa [same] using holds
  · subst before
    exact suspendedHold_tail context callback after holds

theorem CheckedOriginalNoWritePost.staticWords
    {program : Program} {targetId : Nat}
    {checked : CheckedOriginalTargetEffect program targetId}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {invocation : OriginalTargetInvocation targetId}
    {transition : CheckedOriginalTargetTransition checked originalContext
      inventory.reachableTargets.targetIds invocation}
    (post : CheckedOriginalNoWritePost transition)
    (holds : inventory.Holds invocation.execution) :
    OriginalStaticWordPostEvidence program.worldProgram.context
      inventory.staticWords invocation.world invocation.state.memory
      transition.successor := by
  have suspended := (activeStaticWordsAndSuspendedHold invocation holds).2
  have memoryExact := post.memoryUnchanged
  cases successorExact : transition.successor with
  | running nextTarget state calls eventIndex world =>
      have worldExact : world = invocation.world := by
        simpa [OriginalNoWriteWorldFrame, successorExact] using post.worldFrame
      subst world
      exact .running nextTarget state calls eventIndex invocation.world
        (unchangedProtectedMemory program.worldProgram.context
          inventory.staticWords invocation.world invocation.state.memory
          state.memory (by simpa [successorExact] using memoryExact))
  | callbackRunning nextTarget state calls eventIndex world callbacks =>
      have frame := post.worldFrame
      simp only [successorExact, OriginalNoWriteWorldFrame] at frame
      have worldExact : world = invocation.world := by
        exact frame.1
      have callbacksExact : callbacks = invocation.routingCallbacks := by
        exact frame.2
      subst world
      exact .callbackRunning nextTarget state calls eventIndex invocation.world
        callbacks
        (unchangedProtectedMemory program.worldProgram.context
          inventory.staticWords invocation.world invocation.state.memory
          state.memory (by simpa [successorExact] using memoryExact))
        (by simpa [callbacksExact] using suspended)
  | awaitingExternal suspension callbacks =>
      have frame := post.worldFrame
      simp only [successorExact, OriginalNoWriteWorldFrame] at frame
      have worldExact : suspension.world = invocation.world := by
        exact frame.1
      have callbacksFrame : OriginalCallbacksPreservedOrPopped
          invocation.routingCallbacks callbacks := by
        exact frame.2
      exact .awaitingExternal suspension callbacks
        (by
          rw [worldExact]
          exact unchangedProtectedMemory program.worldProgram.context
            inventory.staticWords invocation.world invocation.state.memory
            suspension.state.memory
            (by simpa [successorExact] using memoryExact))
        (SuspendedOriginalStaticWordsHold.ofPreservedOrPopped
          program.worldProgram.context inventory.staticWords
          invocation.routingCallbacks callbacks suspended callbacksFrame)
  | returned state world =>
      have worldExact : world = invocation.world := by
        simpa [OriginalNoWriteWorldFrame, successorExact] using post.worldFrame
      subst world
      exact .returned state invocation.world
        (unchangedProtectedMemory program.worldProgram.context
          inventory.staticWords invocation.world invocation.state.memory
          state.memory (by simpa [successorExact] using memoryExact))
  | terminated world =>
      exact .terminated world
  | fault cause =>
      exact .fault cause

theorem CheckedOriginalNoWritePost.runtimeMemory
    {program : Program} {targetId : Nat}
    {checked : CheckedOriginalTargetEffect program targetId}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {invocation : OriginalTargetInvocation targetId}
    {transition : CheckedOriginalTargetTransition checked originalContext
      inventory.reachableTargets.targetIds invocation}
    (post : CheckedOriginalNoWritePost transition)
    (holds : inventory.Holds invocation.execution) :
    OriginalRuntimeMemoryPartition.ExecutionHolds program.worldProgram.context
      transition.successor.execution := by
  have active := (activeRuntimeMemoryHolds invocation holds).1
  have suspended := (activeRuntimeMemoryHolds invocation holds).2
  cases successorExact : transition.successor with
  | running nextTarget state calls eventIndex world =>
      have worldExact : world = invocation.world := by
        simpa [OriginalNoWriteWorldFrame, successorExact] using post.worldFrame
      subst world
      simpa [OriginalNormalizedSuccessor.execution,
        OriginalRuntimeMemoryPartition.ExecutionHolds] using active
  | callbackRunning nextTarget state calls eventIndex world callbacks =>
      have frame := post.worldFrame
      simp only [successorExact, OriginalNoWriteWorldFrame] at frame
      have worldExact : world = invocation.world := by
        exact frame.1
      have callbacksExact : callbacks = invocation.routingCallbacks := by
        exact frame.2
      subst world
      simpa [OriginalNormalizedSuccessor.execution,
        OriginalRuntimeMemoryPartition.ExecutionHolds, callbacksExact] using
        And.intro active suspended
  | awaitingExternal suspension callbacks =>
      have frame := post.worldFrame
      simp only [successorExact, OriginalNoWriteWorldFrame] at frame
      have worldExact : suspension.world = invocation.world := by
        exact frame.1
      have callbacksFrame : OriginalCallbacksPreservedOrPopped
          invocation.routingCallbacks callbacks := by
        exact frame.2
      have callbacksHold :=
        OriginalRuntimeMemoryPartition.SuspendedHold.ofPreservedOrPopped
          program.worldProgram.context invocation.routingCallbacks callbacks
          suspended callbacksFrame
      simpa [OriginalNormalizedSuccessor.execution,
        OriginalRuntimeMemoryPartition.ExecutionHolds, worldExact] using
        And.intro active callbacksHold
  | returned state world =>
      have worldExact : world = invocation.world := by
        simpa [OriginalNoWriteWorldFrame, successorExact] using post.worldFrame
      subst world
      simpa [OriginalNormalizedSuccessor.execution,
        OriginalRuntimeMemoryPartition.ExecutionHolds] using active
  | terminated world =>
      have worldExact : world = invocation.world := by
        simpa [OriginalNoWriteWorldFrame, successorExact] using post.worldFrame
      subst world
      simpa [OriginalNormalizedSuccessor.execution,
        OriginalRuntimeMemoryPartition.ExecutionHolds] using active
  | fault cause =>
      simp [OriginalNormalizedSuccessor.execution,
        OriginalRuntimeMemoryPartition.ExecutionHolds]

/-- Compose one control case with its exact no-write and provenance evidence.
This is the per-invocation adapter consumed by a universal provider. -/
def CheckedOriginalNoWritePost.toPreservationCase
    {program : Program} {targetId : Nat}
    {checked : CheckedOriginalTargetEffect program targetId}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {invocation : OriginalTargetInvocation targetId}
    (control : CheckedOriginalTargetControlPreservationCase originalContext
      inventory checked invocation)
    (post : CheckedOriginalNoWritePost control.transition)
    (holds : inventory.Holds invocation.execution) :
    CheckedOriginalTargetPreservationCase originalContext inventory checked
      invocation := by
  have provenance := post.provenance.toPostFamilies holds
  exact {
    transition := control.transition
    post := {
      reachability := control.reachability
      staticWords := post.staticWords holds
      callFrames := control.callFrames
      valueFlows := provenance.valueFlows
      registerTargets := provenance.registerTargets
      stackDynamicTargets := provenance.stackDynamicTargets
      runtimeMemory := post.runtimeMemory holds
    }
  }

/-- Universal evidence for one target.  Static routing is supplied once by the
existing control provider; each concrete invocation must then supply only the
checked no-write/provenance evidence bound to the control transition chosen by
that provider. -/
structure CheckedOriginalNoWriteTargetEvidence
    {pe : PE32} {program : Program} {binding : ExactBinding pe program}
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext)
    (certificate : ActiveTargetTransitionCertificate binding) where
  checked : CheckedOriginalTargetEffect program certificate.targetId
  control : CheckedOriginalTargetControlEvidence originalContext inventory
    checked
  noWrite : forall
      (invocation : OriginalTargetInvocation certificate.targetId)
      (holds : inventory.Holds invocation.execution),
    CheckedOriginalNoWritePost
      (control.toPreservationCase invocation holds).transition

def CheckedOriginalNoWriteTargetEvidence.toProvider
    {pe : PE32} {program : Program} {binding : ExactBinding pe program}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {certificate : ActiveTargetTransitionCertificate binding}
    (evidence : CheckedOriginalNoWriteTargetEvidence originalContext inventory
      certificate) :
    CheckedOriginalTargetPreservationProvider originalContext inventory
      certificate where
  checked := evidence.checked
  cases invocation holds :=
    let control := evidence.control.toPreservationCase invocation holds
    (evidence.noWrite invocation holds).toPreservationCase control holds

end StageA.Relational.OriginalNoWriteTargetPreservation
