import StageA.RelationalInterpreterKernelOperationPredicateRoute

namespace StageA.Relational.InterpreterKernelOperationEffectChecker

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationControlChecker
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationFrameChecker
open StageA.Relational.InterpreterKernelOperationGraphChecker
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationPredicateRoute
open StageA.Relational.InterpreterKernelOperationReplay
open StageA.Relational.InterpreterKernelOperationStateRouteChecker
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

/-!
# Checked effectful native-operation successors

Local control transitions normally preserve the state produced by the terminal
instruction. Restartable string operations and atomic compare-exchange instead
apply checked machine effects while transferring control. This module computes
those effects from the exact symbolic outcome and exposes the resulting state
to operation-specific invariant proofs.

The target state is a definition, not certificate data. Generated proofs may
establish a relation over it, but cannot submit an endpoint.
-/

def nativeOperationLocalSuccessorState
    (input transitionState : MachineState) : OutcomeExpr -> MachineState
  | .bulkCopy copy _ =>
      { transitionState with
        memory := Memory.bulkCopyDwords transitionState.memory
          (copy.destination.eval input) (copy.source.eval input)
          (copy.direction.eval input) (copy.count.eval input).toNat }
  | .bulkFill fill _ =>
      { transitionState with
        memory := Memory.bulkFillDwords transitionState.memory
          (fill.destination.eval input) (fill.value.eval input)
          (fill.direction.eval input) (fill.count.eval input).toNat }
  | .bulkScan scan _ =>
      let result := repneScasByte transitionState.memory
        (scan.accumulator.eval input) (scan.destination.eval input)
        (scan.count.eval input) transitionState.eflags
        (scan.direction.eval input) (scan.count.eval input).toNat
      { transitionState with
        registers :=
          (transitionState.registers.set .edi result.destination).set .ecx
            result.count
        eflags := result.eflags }
  | .atomicCompareExchange address expected replacement _ =>
      { transitionState with
        memory := Memory.atomicCompareExchange transitionState.memory
          (address.eval input) (expected.eval input)
          (replacement.eval input) }
  | _ => transitionState

theorem nativeOperationLocalSuccessorCallFrames
    (candidate : ExactNativeWorldProgram)
    (source : NativeOperationInvariant)
    (outcome : OutcomeExpr)
    (successor : NativeOperationLocalSuccessor)
    (sourceRva : Nat) (state transitionState : MachineState)
    (frames nextFrames callerTail : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (controlChecked :
      checkedNativeOperationLocalSuccessor source (some outcome) successor =
        true)
    (sourceHolds : source.Holds state)
    (framesChecked :
      nativeOperationSuccessorCallFrames? successor frames =
        some nextFrames) :
    (transitionFromNativeWorldOutcome candidate.pe candidate.environment
      candidate.callableExternal candidate.indirectTargets sourceRva
      transitionState (frames ++ callerTail) eventIndex events world
      (evalNativeOperationOutcomeExpr state outcome)).next =
    .running successor.targetRva 0
      (nativeOperationLocalSuccessorState state transitionState outcome)
      (nextFrames ++ callerTail) eventIndex events world := by
  cases outcome <;> cases successor <;>
    simp only [checkedNativeOperationLocalSuccessor, Bool.false_eq_true]
      at controlChecked
  all_goals try contradiction
  case jump.jump =>
    simp only [beq_iff_eq] at controlChecked
    subst_vars
    simp [nativeOperationSuccessorCallFrames?,
      nativeOperationLocalSuccessorState, evalNativeOperationOutcomeExpr,
      transitionFromNativeWorldOutcome,
      NativeOperationLocalSuccessor.targetRva] at framesChecked ⊢
    exact framesChecked.symm ▸ rfl
  case branch.branchTrue condition taken fallthrough target =>
    simp only [Bool.and_eq_true, beq_iff_eq] at controlChecked
    have selected :=
      nativeOperationInvariant_member_eval source state sourceHolds condition
        (List.contains_iff_mem.mp controlChecked.2)
    rw [controlChecked.1]
    simp [nativeOperationSuccessorCallFrames?] at framesChecked
    subst nextFrames
    simp [nativeOperationLocalSuccessorState,
      evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
      NativeOperationLocalSuccessor.targetRva, selected]
  case branch.branchFalse condition taken fallthrough target =>
    simp only [Bool.and_eq_true, beq_iff_eq] at controlChecked
    have selected :=
      nativeOperationInvariant_not_member_eval source state sourceHolds condition
        (List.contains_iff_mem.mp controlChecked.2)
    rw [controlChecked.1]
    simp [nativeOperationSuccessorCallFrames?] at framesChecked
    subst nextFrames
    simp [nativeOperationLocalSuccessorState,
      evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
      NativeOperationLocalSuccessor.targetRva, selected]
  case call.call =>
    simp only [Bool.and_eq_true, beq_iff_eq] at controlChecked
    rcases controlChecked with
      ⟨⟨targetExact, continuationExact⟩, returnExact⟩
    subst_vars
    simp [nativeOperationSuccessorCallFrames?,
      expectedNativeOperationCallFrame] at framesChecked
    subst nextFrames
    rfl
  case returned.returned target continuationRva returnAddress =>
    have targetExact :=
      nativeOperationInvariant_member_eval source state sourceHolds
        (.equal target (.constant returnAddress))
        (List.contains_iff_mem.mp controlChecked)
    simp [BoolExpr.eval, Expr.eval] at targetExact
    cases frames with
    | nil =>
        simp [nativeOperationSuccessorCallFrames?] at framesChecked
    | cons frame tail =>
        simp only [nativeOperationSuccessorCallFrames?] at framesChecked
        split at framesChecked
        next frameExact =>
          simp only [beq_iff_eq] at frameExact
          subst frame
          simp at framesChecked
          subst nextFrames
          simp [nativeOperationLocalSuccessorState,
            evalNativeOperationOutcomeExpr,
            transitionFromNativeWorldOutcome,
            NativeOperationLocalSuccessor.targetRva,
            expectedNativeOperationCallFrame, Expr.eval, targetExact]
        next _ =>
          contradiction
  case bulkCopy.bulkCopy copy continuation target =>
    simp only [beq_iff_eq] at controlChecked
    subst target
    simp [nativeOperationSuccessorCallFrames?] at framesChecked
    subst nextFrames
    rfl
  case bulkFill.bulkFill fill continuation target =>
    simp only [beq_iff_eq] at controlChecked
    subst target
    simp [nativeOperationSuccessorCallFrames?] at framesChecked
    subst nextFrames
    rfl
  case bulkScan.bulkScan scan continuation target =>
    simp only [beq_iff_eq] at controlChecked
    subst target
    simp [nativeOperationSuccessorCallFrames?] at framesChecked
    subst nextFrames
    rfl
  case checkedContinue.checkedContinue valid continuation target =>
    simp only [Bool.and_eq_true, beq_iff_eq] at controlChecked
    have selected :=
      nativeOperationInvariant_member_eval source state sourceHolds valid
        (List.contains_iff_mem.mp controlChecked.2)
    rw [controlChecked.1]
    simp [nativeOperationSuccessorCallFrames?] at framesChecked
    subst nextFrames
    simp [nativeOperationLocalSuccessorState,
      evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
      NativeOperationLocalSuccessor.targetRva, selected]
  case atomicCompareExchange.atomicCompareExchange address expected replacement
      continuation target =>
    simp only [beq_iff_eq] at controlChecked
    subst target
    simp [nativeOperationSuccessorCallFrames?] at framesChecked
    subst nextFrames
    rfl

/-- A local block whose exact outcome may change memory. The high-level target
relation is proved over the state computed by `nativeOperationLocalSuccessorState`.
It does not participate in computing the endpoint. -/
structure CheckedNativeOperationEffectfulBlockStep
    {candidate : ExactNativeWorldProgram}
    (blocks : List (CheckedNativeOperationBlock candidate))
    (sourceBlock : CheckedNativeOperationBlock candidate)
    (sourceInvariant : NativeOperationInvariant)
    (sourceRelation : MachineState -> Prop)
    (targetBlock : CheckedNativeOperationBlock candidate)
    (targetRelation : MachineState -> Prop) where
  sourceMember : sourceBlock ∈ blocks
  targetMember : targetBlock ∈ blocks
  terminalInvariant : NativeOperationInvariant
  prelude :
    CheckedNativeOperationBlockPredicatePrelude sourceBlock sourceInvariant
      terminalInvariant
  outcome : OutcomeExpr
  outcomeExact :
    sourceBlock.terminal.cutpoint.postcondition.outcome.expected = some outcome
  successor : NativeOperationLocalSuccessor
  successorChecked :
    checkedNativeOperationLocalSuccessor terminalInvariant (some outcome)
      successor = true
  framesPreserved : ∀ frames,
    nativeOperationSuccessorCallFrames? successor frames = some frames
  alwaysRunningLocal :
    nativeOperationOutcomeAlwaysRunningLocal
      sourceBlock.terminal.cutpoint.postcondition.outcome = true
  graphInvariantChecked :
    checkedNativeOperationInvariantLink sourceBlock targetBlock = true
  targetRvaExact : successor.targetRva = targetBlock.entryRva
  targetSlotExact : targetBlock.entrySlot = 0
  targetRelationHolds : ∀ state,
    sourceInvariant.Holds state ->
      sourceRelation state ->
      targetRelation
        (nativeOperationLocalSuccessorState
          (sourceBlock.terminalState state)
          (sourceBlock.terminal.after (sourceBlock.terminalState state))
          outcome)

def CheckedNativeOperationEffectfulBlockStep.targetState
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {sourceRelation : MachineState -> Prop}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetRelation : MachineState -> Prop}
    (step : CheckedNativeOperationEffectfulBlockStep blocks sourceBlock
      sourceInvariant sourceRelation targetBlock targetRelation)
    (state : MachineState) : MachineState :=
  nativeOperationLocalSuccessorState
    (sourceBlock.terminalState state)
    (sourceBlock.terminal.after (sourceBlock.terminalState state))
    step.outcome

theorem CheckedNativeOperationEffectfulBlockStep.afterExactOfTerminalHolds
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {sourceRelation : MachineState -> Prop}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetRelation : MachineState -> Prop}
    (step : CheckedNativeOperationEffectfulBlockStep blocks sourceBlock
      sourceInvariant sourceRelation targetBlock targetRelation)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (terminalHolds :
      step.terminalInvariant.Holds (sourceBlock.terminalState state)) :
    sourceBlock.after state calls eventIndex events world =
      .running targetBlock.entryRva targetBlock.entrySlot
        (step.targetState state) calls eventIndex events world := by
  rw [sourceBlock.afterExpected]
  unfold CheckedNativeOperationBlock.expectedTerminalTransition
  rw [step.outcomeExact]
  simp only [Option.map_some, Option.getD_some]
  have selected :=
    nativeOperationLocalSuccessorCallFrames candidate
      step.terminalInvariant step.outcome step.successor
      sourceBlock.terminal.instruction.rva
      (sourceBlock.terminalState state)
      (sourceBlock.terminal.after (sourceBlock.terminalState state))
      calls calls [] eventIndex events world step.successorChecked
      terminalHolds (step.framesPreserved calls)
  rw [step.targetRvaExact, ← step.targetSlotExact] at selected
  simpa [CheckedNativeOperationEffectfulBlockStep.targetState,
    CheckedNativeOperationStoppedEdge.after] using selected

theorem CheckedNativeOperationEffectfulBlockStep.afterExact
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {sourceRelation : MachineState -> Prop}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetRelation : MachineState -> Prop}
    (step : CheckedNativeOperationEffectfulBlockStep blocks sourceBlock
      sourceInvariant sourceRelation targetBlock targetRelation)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds : sourceInvariant.Holds state) :
    sourceBlock.after state calls eventIndex events world =
      .running targetBlock.entryRva targetBlock.entrySlot
        (step.targetState state) calls eventIndex events world := by
  have terminalHolds := step.prelude.sound state sourceHolds
  rw [sourceBlock.afterExpected]
  unfold CheckedNativeOperationBlock.expectedTerminalTransition
  rw [step.outcomeExact]
  simp only [Option.map_some, Option.getD_some]
  have selected :=
    nativeOperationLocalSuccessorCallFrames candidate
      step.terminalInvariant step.outcome step.successor
      sourceBlock.terminal.instruction.rva
      (sourceBlock.terminalState state)
      (sourceBlock.terminal.after (sourceBlock.terminalState state))
      calls calls [] eventIndex events world step.successorChecked
      terminalHolds (step.framesPreserved calls)
  rw [step.targetRvaExact, ← step.targetSlotExact] at selected
  simpa [CheckedNativeOperationEffectfulBlockStep.targetState,
    CheckedNativeOperationStoppedEdge.after] using selected

def CheckedNativeOperationEffectfulBlockStep.graphSuccessor
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {sourceRelation : MachineState -> Prop}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetRelation : MachineState -> Prop}
    (step : CheckedNativeOperationEffectfulBlockStep blocks sourceBlock
      sourceInvariant sourceRelation targetBlock targetRelation)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds : sourceInvariant.Holds state) :
    CheckedNativeOperationGraphSuccessor blocks sourceBlock state calls
      eventIndex events world := {
  target := targetBlock
  targetMember := step.targetMember
  targetState := step.targetState state
  targetCalls := calls
  targetEventIndex := eventIndex
  targetEvents := events
  targetWorld := world
  afterExact := step.afterExact state calls eventIndex events world sourceHolds
  invariantChecked := step.graphInvariantChecked
}

theorem CheckedNativeOperationEffectfulBlockStep.observationsEmpty
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {sourceRelation : MachineState -> Prop}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetRelation : MachineState -> Prop}
    (step : CheckedNativeOperationEffectfulBlockStep blocks sourceBlock
      sourceInvariant sourceRelation targetBlock targetRelation)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds : sourceInvariant.Holds state) :
    sourceBlock.observations state calls eventIndex events world = [] := by
  have preserved :=
    checkedNativeOperationGraphSuccessor_contextPreserved
      (step.graphSuccessor state calls eventIndex events world sourceHolds)
      step.alwaysRunningLocal
  exact preserved.2.2.2.2

theorem CheckedNativeOperationEffectfulBlockStep.observationsEmptyOfTerminalHolds
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {sourceRelation : MachineState -> Prop}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetRelation : MachineState -> Prop}
    (step : CheckedNativeOperationEffectfulBlockStep blocks sourceBlock
      sourceInvariant sourceRelation targetBlock targetRelation)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (terminalHolds :
      step.terminalInvariant.Holds (sourceBlock.terminalState state)) :
    sourceBlock.observations state calls eventIndex events world = [] := by
  let successor : CheckedNativeOperationGraphSuccessor blocks sourceBlock
      state calls eventIndex events world := {
    target := targetBlock
    targetMember := step.targetMember
    targetState := step.targetState state
    targetCalls := calls
    targetEventIndex := eventIndex
    targetEvents := events
    targetWorld := world
    afterExact := step.afterExactOfTerminalHolds state calls eventIndex events
      world terminalHolds
    invariantChecked := step.graphInvariantChecked
  }
  have preserved :=
    checkedNativeOperationGraphSuccessor_contextPreserved successor
      step.alwaysRunningLocal
  exact preserved.2.2.2.2

/-- Execute an effectful block from independently checked terminal and target
facts. This avoids replaying a synthesized source invariant when compact
semantic projections already establish the exact selected transition and its
postcondition. -/
theorem CheckedNativeOperationEffectfulBlockStep.executeOfTerminalHolds
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {sourceRelation : MachineState -> Prop}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetRelation : MachineState -> Prop}
    (step : CheckedNativeOperationEffectfulBlockStep blocks sourceBlock
      sourceInvariant sourceRelation targetBlock targetRelation)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (terminalHolds :
      step.terminalInvariant.Holds (sourceBlock.terminalState state))
    (targetHolds : targetRelation (step.targetState state)) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running sourceBlock.entryRva sourceBlock.entrySlot state calls
        eventIndex events world)
      []
      (.running targetBlock.entryRva targetBlock.entrySlot
        (step.targetState state) calls eventIndex events world) /\
    targetRelation (step.targetState state) := by
  constructor
  · have path := sourceBlock.path state calls eventIndex events world
    rw [step.afterExactOfTerminalHolds state calls eventIndex events world
      terminalHolds] at path
    simpa [step.observationsEmptyOfTerminalHolds state calls eventIndex events
      world terminalHolds] using path
  · exact targetHolds

theorem CheckedNativeOperationEffectfulBlockStep.execute
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {sourceRelation : MachineState -> Prop}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetRelation : MachineState -> Prop}
    (step : CheckedNativeOperationEffectfulBlockStep blocks sourceBlock
      sourceInvariant sourceRelation targetBlock targetRelation)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds : sourceInvariant.Holds state)
    (sourceRelationHolds : sourceRelation state) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running sourceBlock.entryRva sourceBlock.entrySlot state calls
        eventIndex events world)
      []
      (.running targetBlock.entryRva targetBlock.entrySlot
        (step.targetState state) calls eventIndex events world) /\
    targetRelation (step.targetState state) := by
  constructor
  · have path := sourceBlock.path state calls eventIndex events world
    rw [step.afterExact state calls eventIndex events world sourceHolds] at path
    simpa [step.observationsEmpty state calls eventIndex events world
      sourceHolds] using path
  · exact step.targetRelationHolds state sourceHolds sourceRelationHolds

#print axioms nativeOperationLocalSuccessorCallFrames
#print axioms CheckedNativeOperationEffectfulBlockStep.afterExact
#print axioms CheckedNativeOperationEffectfulBlockStep.observationsEmpty
#print axioms CheckedNativeOperationEffectfulBlockStep.execute

end StageA.Relational.InterpreterKernelOperationEffectChecker
