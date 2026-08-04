import StageA.RelationalInterpreterKernelOperationControlChecker

namespace StageA.Relational.InterpreterKernelOperationFrameChecker

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationControlChecker
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationReplay
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

/-!
# Checked operation call-frame evolution

Local operation routes carry a finite checked call-frame prefix. Calls push the
frame encoded by their exact symbolic outcome, returns pop only the matching
frame, and ordinary local control preserves the prefix. The caller-owned tail
remains abstract and is never inspected.
-/

def expectedNativeOperationCallFrame
    (continuationRva returnAddress : Nat) : NativeCallFrame := {
  continuationRva
  returnAddress := BitVec.ofNat 32 returnAddress
}

def nativeOperationSuccessorCallFrames?
    (successor : NativeOperationLocalSuccessor)
    (frames : List NativeCallFrame) : Option (List NativeCallFrame) :=
  match successor with
  | .call _ continuationRva returnAddress =>
      some (expectedNativeOperationCallFrame continuationRva returnAddress ::
        frames)
  | .returned continuationRva returnAddress =>
      match frames with
      | [] => none
      | frame :: tail =>
          if frame ==
              expectedNativeOperationCallFrame continuationRva returnAddress
          then some tail
          else none
  | _ => some frames

def nativeOperationLocalSuccessorFramePreserving :
    NativeOperationLocalSuccessor -> Bool
  | .call ..
  | .returned .. => false
  | _ => true

theorem nativeOperationFramePreservingSuccessorCallFrames
    (successor : NativeOperationLocalSuccessor)
    (preserving :
      nativeOperationLocalSuccessorFramePreserving successor = true)
    (frames : List NativeCallFrame) :
    nativeOperationSuccessorCallFrames? successor frames = some frames := by
  cases successor <;>
    simp [nativeOperationLocalSuccessorFramePreserving,
      nativeOperationSuccessorCallFrames?] at preserving |-

theorem nativeOperationSuccessorCallFrames?_returned_exact
    (continuationRva returnAddress : Nat)
    (frames nextFrames : List NativeCallFrame)
    (checked :
      nativeOperationSuccessorCallFrames?
          (.returned continuationRva returnAddress) frames =
        some nextFrames) :
    frames =
      expectedNativeOperationCallFrame continuationRva returnAddress ::
        nextFrames := by
  cases frames with
  | nil =>
      simp [nativeOperationSuccessorCallFrames?] at checked
  | cons frame tail =>
      simp only [nativeOperationSuccessorCallFrames?] at checked
      split at checked
      next frameExact =>
        simp only [beq_iff_eq] at frameExact
        subst frame
        have tailExact : tail = nextFrames := Option.some.inj checked
        subst nextFrames
        rfl
      next _ =>
        contradiction

theorem nativeOperationSuccessorCallFrames?_context
    (successor : NativeOperationLocalSuccessor)
    (frames nextFrames callerTail : List NativeCallFrame)
    (checked :
      nativeOperationSuccessorCallFrames? successor frames =
        some nextFrames) :
    successor.callContextHolds (frames ++ callerTail) := by
  cases successor with
  | returned continuationRva returnAddress =>
      cases frames with
      | nil =>
          simp [nativeOperationSuccessorCallFrames?] at checked
      | cons frame tail =>
          simp only [nativeOperationSuccessorCallFrames?,
            expectedNativeOperationCallFrame] at checked
          split at checked
          next frameExact =>
            simp only [beq_iff_eq] at frameExact
            subst frame
            exact ⟨tail ++ callerTail, by simp
              [NativeOperationLocalSuccessor.callContextHolds,
                expectedNativeOperationCallFrame]⟩
          next _ =>
            contradiction
  | jump | branchTrue | branchFalse | call | bulkCopy | bulkFill | bulkScan
  | checkedContinue | atomicCompareExchange =>
      simp [NativeOperationLocalSuccessor.callContextHolds]

theorem nativeOperationStatePreservingSuccessorCallFrames
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
    (preserving : successor.statePreserving = true)
    (sourceHolds : source.Holds state)
    (framesChecked :
      nativeOperationSuccessorCallFrames? successor frames =
        some nextFrames) :
    (transitionFromNativeWorldOutcome candidate.pe candidate.environment
      candidate.callableExternal candidate.indirectTargets sourceRva
      transitionState (frames ++ callerTail) eventIndex events world
      (evalNativeOperationOutcomeExpr state outcome)).next =
    .running successor.targetRva 0 transitionState
      (nextFrames ++ callerTail) eventIndex events world := by
  cases outcome <;> cases successor <;>
    simp only [checkedNativeOperationLocalSuccessor, Bool.false_eq_true]
      at controlChecked
  all_goals try contradiction
  all_goals
    try simp [NativeOperationLocalSuccessor.statePreserving] at preserving
  case jump.jump =>
    simp only [beq_iff_eq] at controlChecked
    subst_vars
    simp [nativeOperationSuccessorCallFrames?,
      evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
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
    simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
      NativeOperationLocalSuccessor.targetRva, selected]
  case branch.branchFalse condition taken fallthrough target =>
    simp only [Bool.and_eq_true, beq_iff_eq] at controlChecked
    have selected :=
      nativeOperationInvariant_not_member_eval source state sourceHolds condition
        (List.contains_iff_mem.mp controlChecked.2)
    rw [controlChecked.1]
    simp [nativeOperationSuccessorCallFrames?] at framesChecked
    subst nextFrames
    simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
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
          simp [evalNativeOperationOutcomeExpr,
            transitionFromNativeWorldOutcome,
            NativeOperationLocalSuccessor.targetRva,
            expectedNativeOperationCallFrame, Expr.eval, targetExact]
        next _ =>
          contradiction
  case checkedContinue.checkedContinue valid continuation target =>
    simp only [Bool.and_eq_true, beq_iff_eq] at controlChecked
    have selected :=
      nativeOperationInvariant_member_eval source state sourceHolds valid
        (List.contains_iff_mem.mp controlChecked.2)
    rw [controlChecked.1]
    simp [nativeOperationSuccessorCallFrames?] at framesChecked
    subst nextFrames
    simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
      NativeOperationLocalSuccessor.targetRva, selected]

theorem CheckedNativeOperationStatePreservingLocalEdge.afterCallFrames
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationStatePreservingLocalEdge candidate)
    (state : MachineState) (frames nextFrames callerTail : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds :
      match edge.edge.block.running with
      | none => edge.edge.block.terminal.cutpoint.source.Holds state
      | some running => running.first.cutpoint.source.Holds state)
    (framesChecked :
      nativeOperationSuccessorCallFrames? edge.edge.control.successor frames =
        some nextFrames) :
    edge.edge.block.after state (frames ++ callerTail) eventIndex events world =
      .running edge.edge.control.successor.targetRva 0
        (edge.edge.block.terminal.after
          (edge.edge.block.terminalState state))
        (nextFrames ++ callerTail) eventIndex events world := by
  have terminalHolds :=
    edge.edge.block.terminalSourceHolds state sourceHolds
  have checked := edge.edge.control.checked
  rw [edge.edge.block.afterExpected state (frames ++ callerTail) eventIndex
    events world]
  unfold CheckedNativeOperationBlock.expectedTerminalTransition
  cases expectedExact :
      edge.edge.block.terminal.cutpoint.postcondition.outcome.expected with
  | none =>
      simp [checkedNativeOperationLocalSuccessor, expectedExact] at checked
  | some outcome =>
      simpa [expectedExact, CheckedNativeOperationStoppedEdge.after] using
        nativeOperationStatePreservingSuccessorCallFrames candidate
          edge.edge.block.terminal.cutpoint.source outcome
          edge.edge.control.successor edge.edge.block.terminal.instruction.rva
          (edge.edge.block.terminalState state)
          (concreteBehaviorNextMachineState
            (edge.edge.block.terminal.replay.behavior.eval
              (edge.edge.block.terminalState state))
            (edge.edge.block.terminalState state))
          frames nextFrames callerTail eventIndex events world
          (by simpa [expectedExact] using checked) edge.statePreserving
          terminalHolds framesChecked

theorem CheckedNativeOperationLocalConnection.followFrames
    {candidate : ExactNativeWorldProgram}
    (connection : CheckedNativeOperationLocalConnection candidate)
    (state : MachineState) (frames nextFrames callerTail : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds :
      (checkedNativeOperationBlockSourceInvariant
        connection.source.edge.block).Holds state)
    (framesChecked :
      nativeOperationSuccessorCallFrames?
          connection.source.edge.control.successor frames =
        some nextFrames) :
    connection.source.edge.block.after state (frames ++ callerTail) eventIndex
        events world =
      .running connection.target.entryRva connection.target.entrySlot
        (connection.source.edge.block.terminal.after
          (connection.source.edge.block.terminalState state))
        (nextFrames ++ callerTail) eventIndex events world ∧
    (checkedNativeOperationBlockSourceInvariant connection.target).Holds
      (connection.source.edge.block.terminal.after
        (connection.source.edge.block.terminalState state)) := by
  have sourceShape :
      match connection.source.edge.block.running with
      | none =>
          connection.source.edge.block.terminal.cutpoint.source.Holds state
      | some running => running.first.cutpoint.source.Holds state :=
    checkedNativeOperationBlockSourceInvariantHolds
      connection.source.edge.block state sourceHolds
  constructor
  · rw [← connection.targetRvaExact, connection.targetSlotExact]
    exact
      CheckedNativeOperationStatePreservingLocalEdge.afterCallFrames
        connection.source state frames nextFrames callerTail eventIndex events
        world sourceShape framesChecked
  · rw [← connection.invariantExact]
    exact connection.source.edge.block.terminalInvariantHolds state sourceShape

#print axioms nativeOperationSuccessorCallFrames?_context
#print axioms nativeOperationSuccessorCallFrames?_returned_exact
#print axioms nativeOperationStatePreservingSuccessorCallFrames
#print axioms
  CheckedNativeOperationStatePreservingLocalEdge.afterCallFrames
#print axioms CheckedNativeOperationLocalConnection.followFrames

end StageA.Relational.InterpreterKernelOperationFrameChecker
