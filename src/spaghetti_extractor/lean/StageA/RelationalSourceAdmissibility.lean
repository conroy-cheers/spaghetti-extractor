import StageA.RelationalSourceInterpreterKernel

namespace StageA.Relational.SourceWorld

open StageA.Relational
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Formal

private def ProofBlockedTransitionSound
    (transition : RelatedTransition WorldExecution WorldRelationalObservable) : Prop :=
  forall reason, transition.observation = some (.proofBlocked reason) ->
    transition.next = .blocked reason

private theorem blockedWorldTransition_proofBlocked_sound
    (reason : ExecutionBlock) :
    ProofBlockedTransitionSound (blockedWorldTransition reason) := by
  intro observedReason observed
  simp [blockedWorldTransition] at observed ⊢
  exact observed

private theorem transitionFromWorldIndirectImportCall_proofBlocked_sound
    (program : DecodedWorldProgram) (sourceTargetId : Nat)
    (state : Formal.MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld) (callbacks : List WorldExternalCallbackRuntime)
    (imported : ExternalTarget) (arguments : List Formal.Word) (continuation : Nat) :
    ProofBlockedTransitionSound
      (transitionFromWorldIndirectImportCall program sourceTargetId state calls
        eventIndex world callbacks imported arguments continuation) := by
  unfold transitionFromWorldIndirectImportCall
  repeat' first
    | split
    | apply blockedWorldTransition_proofBlocked_sound
    | simp [ProofBlockedTransitionSound]

private theorem transitionFromWorldIndirectImportTail_proofBlocked_sound
    (program : DecodedWorldProgram) (sourceTargetId : Nat)
    (state : Formal.MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld) (callbacks : List WorldExternalCallbackRuntime)
    (imported : ExternalTarget) (arguments : List Formal.Word) :
    ProofBlockedTransitionSound
      (transitionFromWorldIndirectImportTail program sourceTargetId state calls
        eventIndex world callbacks imported arguments) := by
  unfold transitionFromWorldIndirectImportTail
  repeat' first
    | split
    | apply blockedWorldTransition_proofBlocked_sound
    | simp [ProofBlockedTransitionSound]

private theorem transitionFromWorldOutcome_proofBlocked_sound
    (program : DecodedWorldProgram) (sourceTargetId : Nat)
    (state : Formal.MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld) (callbacks : List WorldExternalCallbackRuntime)
    (outcome : PureOutcome) :
    ProofBlockedTransitionSound
      (transitionFromWorldOutcome program sourceTargetId state calls eventIndex
        world callbacks outcome) := by
  cases outcome <;> simp only [transitionFromWorldOutcome]
  all_goals
    repeat' first
      | split
      | apply blockedWorldTransition_proofBlocked_sound
      | apply transitionFromWorldIndirectImportCall_proofBlocked_sound
      | apply transitionFromWorldIndirectImportTail_proofBlocked_sound
      | simp [ProofBlockedTransitionSound, applyWorldResolvedCallableCall,
          applyWorldResolvedCallableTail, blockedWorldTransition]

private theorem transitionFromWorldBehavior_proofBlocked_sound
    (program : DecodedWorldProgram) (sourceTargetId : Nat)
    (inputState : Formal.MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld) (callbacks : List WorldExternalCallbackRuntime)
    (behavior : RelationalBehavior) :
    ProofBlockedTransitionSound
      (transitionFromWorldBehavior program sourceTargetId inputState calls
        eventIndex world callbacks behavior) := by
  unfold transitionFromWorldBehavior
  split
  · simp [ProofBlockedTransitionSound]
  · apply transitionFromWorldOutcome_proofBlocked_sound

private theorem stepWorldExternalSuspension_proofBlocked_sound
    (program : DecodedWorldProgram) (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime) :
    ProofBlockedTransitionSound
      (stepWorldExternalSuspension program suspension callbacks) := by
  unfold stepWorldExternalSuspension
  split <;> simp [ProofBlockedTransitionSound]

/-- A proof-block observation is diagnostic evidence for the blocked successor
state; it is never an observable behavior of the decoded program. -/
theorem stepWorldExecution_proofBlocked_implies_blocked
    (program : DecodedWorldProgram) (execution : WorldExecution)
    (reason : ExecutionBlock)
    (observed : (stepWorldExecution program execution).observation =
      some (.proofBlocked reason)) :
    (stepWorldExecution program execution).next = .blocked reason := by
  cases execution with
  | running targetId state calls eventIndex world =>
      cases behaviorResult : decodedWorldRegionBehaviorWithCalls program targetId
          state calls with
      | none =>
          simpa [stepWorldExecution, behaviorResult, blockedWorldTransition] using observed
      | some behavior =>
          have sound := transitionFromWorldBehavior_proofBlocked_sound program targetId
            state calls eventIndex world [] behavior
          have observed' :
              (transitionFromWorldBehavior program targetId state calls eventIndex
                world [] behavior).observation = some (.proofBlocked reason) := by
            simpa [stepWorldExecution, behaviorResult] using observed
          simpa [stepWorldExecution, behaviorResult] using sound reason observed'
  | returned state world => simp [stepWorldExecution] at observed
  | terminated world => simp [stepWorldExecution] at observed
  | awaitingExternal suspension callbacks =>
      exact stepWorldExternalSuspension_proofBlocked_sound _ _ _ reason observed
  | callbackRunning targetId state calls eventIndex world callbacks =>
      cases behaviorResult : decodedWorldRegionBehaviorWithCalls program targetId
          state calls with
      | none =>
          simpa [stepWorldExecution, behaviorResult, blockedWorldTransition] using observed
      | some behavior =>
          have sound := transitionFromWorldBehavior_proofBlocked_sound program targetId
            state calls eventIndex world callbacks behavior
          have observed' :
              (transitionFromWorldBehavior program targetId state calls eventIndex
                world callbacks behavior).observation = some (.proofBlocked reason) := by
            simpa [stepWorldExecution, behaviorResult] using observed
          simpa [stepWorldExecution, behaviorResult] using sound reason observed'
  | fault cause => simp [stepWorldExecution] at observed
  | blocked blockedReason => simp [stepWorldExecution] at observed

/-- A step-closed checked domain that excludes proof-blocked states supplies
the admissibility premise needed by source-kernel composition. -/
theorem CheckedExecutionDomain.decodedSemanticStepsAdmissible_of_blocksExcluded
    {program : DecodedWorldProgram} {root : WorldExecution}
    (domain : CheckedExecutionDomain program root)
    (adequate : program.InstructionSemanticsAdequate)
    (blocksExcluded : forall reason, ¬ domain.holds (.blocked reason)) :
    DecodedSemanticStepsAdmissible program domain := by
  intro execution executionHolds
  let transition := stepWorldExecution program execution
  have successorHolds : domain.holds transition.next := by
    have closed := domain.stepClosed execution executionHolds
    rw [program.pe32TransitionSystem_eq_transitionSystem adequate] at closed
    exact closed
  have proofOpen : forall reason,
      transition.observation ≠ some (.proofBlocked reason) := by
    intro reason observed
    have blocked : transition.next = .blocked reason := by
      exact stepWorldExecution_proofBlocked_implies_blocked program execution reason observed
    exact blocksExcluded reason (blocked ▸ successorHolds)
  cases observed : transition.observation with
  | none => trivial
  | some observation =>
      rw [observed] at proofOpen
      exact ⟨sourceObservationsRelated_refl (some observation) proofOpen, trivial⟩

end StageA.Relational.SourceWorld
