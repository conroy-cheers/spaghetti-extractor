import StageA.RelationalInterpreterKernelOperationTraceChecker

namespace StageA.Relational.InterpreterKernelOperationControlChecker

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationReplay
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

/-!
# Checked native-operation control successors

This layer classifies the exact outcome computed by a checked block.  Branch
selection is justified by a predicate in the block's terminal source
invariant.  Return selection is justified by the actual native call frame.
No successor execution or endpoint equality is submitted as certificate data.
-/

inductive NativeOperationLocalSuccessor where
  | jump (targetRva : Nat)
  | branchTrue (targetRva : Nat)
  | branchFalse (targetRva : Nat)
  | call (targetRva continuationRva returnAddress : Nat)
  | returned (continuationRva returnAddress : Nat)
  | bulkCopy (continuationRva : Nat)
  | bulkFill (continuationRva : Nat)
  | bulkScan (continuationRva : Nat)
  | checkedContinue (continuationRva : Nat)
  | atomicCompareExchange (continuationRva : Nat)
deriving Repr, DecidableEq

def NativeOperationLocalSuccessor.targetRva :
    NativeOperationLocalSuccessor -> Nat
  | .jump targetRva
  | .branchTrue targetRva
  | .branchFalse targetRva
  | .call targetRva ..
  | .returned targetRva _
  | .bulkCopy targetRva
  | .bulkFill targetRva
  | .bulkScan targetRva
  | .checkedContinue targetRva
  | .atomicCompareExchange targetRva => targetRva

def NativeOperationLocalSuccessor.statePreserving :
    NativeOperationLocalSuccessor -> Bool
  | .jump _
  | .branchTrue _
  | .branchFalse _
  | .call ..
  | .returned ..
  | .checkedContinue _ => true
  | .bulkCopy _
  | .bulkFill _
  | .bulkScan _
  | .atomicCompareExchange _ => false

def NativeOperationLocalSuccessor.callContextHolds
    (successor : NativeOperationLocalSuccessor)
    (calls : List NativeCallFrame) : Prop :=
  match successor with
  | .returned continuationRva returnAddress =>
      exists tail,
        calls =
          { continuationRva := continuationRva
            returnAddress := BitVec.ofNat 32 returnAddress } :: tail
  | _ => True

def checkedNativeOperationLocalSuccessor
    (source : NativeOperationInvariant)
    (outcome : Option OutcomeExpr)
    (successor : NativeOperationLocalSuccessor) : Bool :=
  match outcome, successor with
  | some (.jump target), .jump expected =>
      target == expected
  | some (.branch condition taken _), .branchTrue expected =>
      taken == expected && source.predicates.contains condition
  | some (.branch condition _ fallthrough), .branchFalse expected =>
      fallthrough == expected &&
        source.predicates.contains (.not condition)
  | some (.call target continuation returnAddress),
      .call expectedTarget expectedContinuation expectedReturn =>
      target == expectedTarget &&
        continuation == expectedContinuation &&
        returnAddress == expectedReturn
  | some (.returned target),
      .returned _ expectedReturn =>
      source.predicates.contains
        (.equal target (.constant expectedReturn))
  | some (.bulkCopy _ continuation), .bulkCopy expected =>
      continuation == expected
  | some (.bulkFill _ continuation), .bulkFill expected =>
      continuation == expected
  | some (.bulkScan _ continuation), .bulkScan expected =>
      continuation == expected
  | some (.checkedContinue valid continuation),
      .checkedContinue expected =>
      continuation == expected && source.predicates.contains valid
  | some (.atomicCompareExchange _ _ _ continuation),
      .atomicCompareExchange expected =>
      continuation == expected
  | _, _ => false

structure CheckedNativeOperationLocalSuccessor
    (block : CheckedNativeOperationBlock candidate) where
  successor : NativeOperationLocalSuccessor
  checked :
    checkedNativeOperationLocalSuccessor block.terminal.cutpoint.source
      block.terminal.cutpoint.postcondition.outcome.expected successor = true

theorem nativeOperationInvariant_member_eval
    (invariant : NativeOperationInvariant) (state : MachineState)
    (holds : invariant.Holds state) (predicate : BoolExpr)
    (member : predicate ∈ invariant.predicates) :
    predicate.eval state = true := by
  simp only [NativeOperationInvariant.Holds, List.all_eq_true] at holds
  exact holds predicate member

theorem nativeOperationInvariant_not_member_eval
    (invariant : NativeOperationInvariant) (state : MachineState)
    (holds : invariant.Holds state) (predicate : BoolExpr)
    (member : .not predicate ∈ invariant.predicates) :
    predicate.eval state = false := by
  have negated := nativeOperationInvariant_member_eval invariant state holds
    (.not predicate) member
  simpa [BoolExpr.eval] using negated

private theorem localSuccessorAfterRva
    (candidate : ExactNativeWorldProgram)
    (source : NativeOperationInvariant)
    (outcome : OutcomeExpr)
    (successor : NativeOperationLocalSuccessor)
    (sourceRva : Nat) (state transitionState : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld)
    (checked :
      checkedNativeOperationLocalSuccessor source (some outcome) successor =
        true)
    (sourceHolds : source.Holds state)
    (callContext : successor.callContextHolds calls) :
    (transitionFromNativeWorldOutcome candidate.pe candidate.environment
      candidate.callableExternal candidate.indirectTargets sourceRva
      transitionState
      calls eventIndex events world
      (evalNativeOperationOutcomeExpr state outcome)).next.rva? =
        some successor.targetRva := by
  cases outcome <;> cases successor <;>
    simp only [checkedNativeOperationLocalSuccessor, Bool.false_eq_true] at checked
  all_goals try contradiction
  case jump.jump =>
    simp only [beq_iff_eq] at checked
    subst_vars
    rfl
  case branch.branchTrue condition taken fallthrough target =>
    simp only [Bool.and_eq_true, beq_iff_eq] at checked
    have selected := nativeOperationInvariant_member_eval source state
      sourceHolds condition (List.contains_iff_mem.mp checked.2)
    rw [checked.1]
    simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
      NativeOperationLocalSuccessor.targetRva, NativeWorldExecution.rva?,
      selected]
  case branch.branchFalse condition taken fallthrough target =>
    simp only [Bool.and_eq_true, beq_iff_eq] at checked
    have selected := nativeOperationInvariant_not_member_eval source state
      sourceHolds condition (List.contains_iff_mem.mp checked.2)
    rw [checked.1]
    simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
      NativeOperationLocalSuccessor.targetRva, NativeWorldExecution.rva?,
      selected]
  case call.call =>
    simp only [Bool.and_eq_true, beq_iff_eq] at checked
    rcases checked with ⟨⟨targetExact, continuationExact⟩, returnExact⟩
    subst_vars
    rfl
  case returned.returned target continuationRva returnAddress =>
    have targetExact := nativeOperationInvariant_member_eval source state
      sourceHolds (.equal target (.constant returnAddress))
      (List.contains_iff_mem.mp checked)
    simp [BoolExpr.eval, Expr.eval] at targetExact
    rcases callContext with ⟨tail, callsExact⟩
    subst calls
    simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
      NativeOperationLocalSuccessor.targetRva, NativeWorldExecution.rva?,
      Expr.eval, targetExact]
  case bulkCopy.bulkCopy =>
    simp only [beq_iff_eq] at checked
    subst_vars
    rfl
  case bulkFill.bulkFill =>
    simp only [beq_iff_eq] at checked
    subst_vars
    rfl
  case bulkScan.bulkScan =>
    simp only [beq_iff_eq] at checked
    subst_vars
    rfl
  case checkedContinue.checkedContinue valid continuation target =>
    simp only [Bool.and_eq_true, beq_iff_eq] at checked
    have selected := nativeOperationInvariant_member_eval source state
      sourceHolds valid (List.contains_iff_mem.mp checked.2)
    rw [checked.1]
    simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
      NativeOperationLocalSuccessor.targetRva, NativeWorldExecution.rva?,
      selected]
  case atomicCompareExchange.atomicCompareExchange =>
    simp only [beq_iff_eq] at checked
    subst_vars
    rfl

theorem CheckedNativeOperationLocalSuccessor.afterRva
    {candidate : ExactNativeWorldProgram}
    {block : CheckedNativeOperationBlock candidate}
    (edge : CheckedNativeOperationLocalSuccessor block)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds :
      match block.running with
      | none => block.terminal.cutpoint.source.Holds state
      | some running => running.first.cutpoint.source.Holds state)
    (callContext : edge.successor.callContextHolds calls) :
    (block.after state calls eventIndex events world).rva? =
      some edge.successor.targetRva := by
  have terminalHolds := block.terminalSourceHolds state sourceHolds
  have checked := edge.checked
  rw [block.afterExpected state calls eventIndex events world]
  unfold CheckedNativeOperationBlock.expectedTerminalTransition
  cases expectedExact :
      block.terminal.cutpoint.postcondition.outcome.expected with
  | none =>
      simp [checkedNativeOperationLocalSuccessor, expectedExact] at checked
  | some outcome =>
      simpa [expectedExact] using
        localSuccessorAfterRva candidate block.terminal.cutpoint.source outcome
          edge.successor block.terminal.instruction.rva
          (block.terminalState state)
          (concreteBehaviorNextMachineState
            (block.terminal.replay.behavior.eval (block.terminalState state))
            (block.terminalState state))
          calls eventIndex events world
          (by simpa [expectedExact] using checked) terminalHolds callContext

/-- One local edge with a computed endpoint.  The path and endpoint below are
derived from the checked block; generated data supplies only the selected
control class and its Boolean check. -/
structure CheckedNativeOperationLocalEdge
    (candidate : ExactNativeWorldProgram) where
  block : CheckedNativeOperationBlock candidate
  control : CheckedNativeOperationLocalSuccessor block

structure CheckedNativeOperationStatePreservingLocalEdge
    (candidate : ExactNativeWorldProgram) where
  edge : CheckedNativeOperationLocalEdge candidate
  statePreserving :
    edge.control.successor.statePreserving = true

def nativeWorldExecutionMachineState? :
    NativeWorldExecution -> Option MachineState
  | .running _ _ state .. => some state
  | .returned state .. => some state
  | .terminated .. | .fault _ | .blocked _ => none

private theorem statePreservingSuccessorMachineState
    (candidate : ExactNativeWorldProgram)
    (source : NativeOperationInvariant)
    (outcome : OutcomeExpr)
    (successor : NativeOperationLocalSuccessor)
    (sourceRva : Nat) (state transitionState : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld)
    (checked :
      checkedNativeOperationLocalSuccessor source (some outcome) successor =
        true)
    (preserving : successor.statePreserving = true)
    (sourceHolds : source.Holds state)
    (callContext : successor.callContextHolds calls) :
    nativeWorldExecutionMachineState?
      (transitionFromNativeWorldOutcome candidate.pe candidate.environment
        candidate.callableExternal candidate.indirectTargets sourceRva
        transitionState calls eventIndex events world
        (evalNativeOperationOutcomeExpr state outcome)).next =
        some transitionState := by
  cases outcome <;> cases successor <;>
    simp only [checkedNativeOperationLocalSuccessor, Bool.false_eq_true] at checked
  all_goals try contradiction
  all_goals
    try simp [NativeOperationLocalSuccessor.statePreserving] at preserving
  case jump.jump =>
    rfl
  case branch.branchTrue condition taken fallthrough target =>
    simp only [Bool.and_eq_true, beq_iff_eq] at checked
    have selected := nativeOperationInvariant_member_eval source state
      sourceHolds condition (List.contains_iff_mem.mp checked.2)
    simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
      nativeWorldExecutionMachineState?, selected]
  case branch.branchFalse condition taken fallthrough target =>
    simp only [Bool.and_eq_true, beq_iff_eq] at checked
    have selected := nativeOperationInvariant_not_member_eval source state
      sourceHolds condition (List.contains_iff_mem.mp checked.2)
    simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
      nativeWorldExecutionMachineState?, selected]
  case call.call =>
    rfl
  case returned.returned target continuationRva returnAddress =>
    have targetExact := nativeOperationInvariant_member_eval source state
      sourceHolds (.equal target (.constant returnAddress))
      (List.contains_iff_mem.mp checked)
    simp [BoolExpr.eval, Expr.eval] at targetExact
    rcases callContext with ⟨tail, callsExact⟩
    subst calls
    simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
      nativeWorldExecutionMachineState?, Expr.eval, targetExact]
  case checkedContinue.checkedContinue valid continuation target =>
    simp only [Bool.and_eq_true, beq_iff_eq] at checked
    have selected := nativeOperationInvariant_member_eval source state
      sourceHolds valid (List.contains_iff_mem.mp checked.2)
    simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
      nativeWorldExecutionMachineState?, selected]

private theorem statePreservingSuccessorRunning
    (candidate : ExactNativeWorldProgram)
    (source : NativeOperationInvariant)
    (outcome : OutcomeExpr)
    (successor : NativeOperationLocalSuccessor)
    (sourceRva : Nat) (state transitionState : MachineState)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld)
    (checked :
      checkedNativeOperationLocalSuccessor source (some outcome) successor =
        true)
    (preserving : successor.statePreserving = true)
    (sourceHolds : source.Holds state)
    (callContext : successor.callContextHolds calls) :
    ∃ nextCalls,
      (transitionFromNativeWorldOutcome candidate.pe candidate.environment
        candidate.callableExternal candidate.indirectTargets sourceRva
        transitionState calls eventIndex events world
        (evalNativeOperationOutcomeExpr state outcome)).next =
      .running successor.targetRva 0 transitionState nextCalls eventIndex
        events world := by
  cases outcome <;> cases successor <;>
    simp only [checkedNativeOperationLocalSuccessor, Bool.false_eq_true] at checked
  all_goals try contradiction
  all_goals
    try simp [NativeOperationLocalSuccessor.statePreserving] at preserving
  case jump.jump =>
    simp only [beq_iff_eq] at checked
    subst_vars
    exact ⟨calls, rfl⟩
  case branch.branchTrue condition taken fallthrough target =>
    simp only [Bool.and_eq_true, beq_iff_eq] at checked
    have selected := nativeOperationInvariant_member_eval source state
      sourceHolds condition (List.contains_iff_mem.mp checked.2)
    rw [checked.1]
    exact ⟨calls, by
      simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
        NativeOperationLocalSuccessor.targetRva, selected]⟩
  case branch.branchFalse condition taken fallthrough target =>
    simp only [Bool.and_eq_true, beq_iff_eq] at checked
    have selected := nativeOperationInvariant_not_member_eval source state
      sourceHolds condition (List.contains_iff_mem.mp checked.2)
    rw [checked.1]
    exact ⟨calls, by
      simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
        NativeOperationLocalSuccessor.targetRva, selected]⟩
  case call.call =>
    simp only [Bool.and_eq_true, beq_iff_eq] at checked
    rcases checked with
      ⟨⟨targetExact, continuationExact⟩, returnExact⟩
    subst_vars
    exact ⟨_, rfl⟩
  case returned.returned target continuationRva returnAddress =>
    have targetExact := nativeOperationInvariant_member_eval source state
      sourceHolds (.equal target (.constant returnAddress))
      (List.contains_iff_mem.mp checked)
    simp [BoolExpr.eval, Expr.eval] at targetExact
    rcases callContext with ⟨tail, callsExact⟩
    subst calls
    exact ⟨tail, by
      simp [evalNativeOperationOutcomeExpr,
        transitionFromNativeWorldOutcome,
        NativeOperationLocalSuccessor.targetRva, Expr.eval, targetExact]⟩
  case checkedContinue.checkedContinue valid continuation target =>
    simp only [Bool.and_eq_true, beq_iff_eq] at checked
    have selected := nativeOperationInvariant_member_eval source state
      sourceHolds valid (List.contains_iff_mem.mp checked.2)
    rw [checked.1]
    exact ⟨calls, by
      simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
        NativeOperationLocalSuccessor.targetRva, selected]⟩

structure CheckedNativeOperationLocalEdgeResult
    (edge : CheckedNativeOperationLocalEdge candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) where
  path : CheckedNativeOperationPath candidate
    (.running edge.block.entryRva edge.block.entrySlot state calls eventIndex
      events world)
  pathExact :
    path = edge.block.toCheckedPath state calls eventIndex events world
  successorRva :
    path.after.rva? = some edge.control.successor.targetRva

def CheckedNativeOperationLocalEdge.execute
    (edge : CheckedNativeOperationLocalEdge candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds :
      match edge.block.running with
      | none => edge.block.terminal.cutpoint.source.Holds state
      | some running => running.first.cutpoint.source.Holds state)
    (callContext : edge.control.successor.callContextHolds calls) :
    CheckedNativeOperationLocalEdgeResult edge state calls eventIndex events
      world := {
  path := edge.block.toCheckedPath state calls eventIndex events world
  pathExact := rfl
  successorRva := by
    rw [edge.block.toCheckedPath_after state calls eventIndex events world]
    exact edge.control.afterRva state calls eventIndex events world sourceHolds
      callContext
}

theorem CheckedNativeOperationStatePreservingLocalEdge.afterMachineState
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationStatePreservingLocalEdge candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds :
      match edge.edge.block.running with
      | none => edge.edge.block.terminal.cutpoint.source.Holds state
      | some running => running.first.cutpoint.source.Holds state)
    (callContext : edge.edge.control.successor.callContextHolds calls) :
    nativeWorldExecutionMachineState?
        (edge.edge.block.after state calls eventIndex events world) =
      some (edge.edge.block.terminal.after
        (edge.edge.block.terminalState state)) := by
  have terminalHolds :=
    edge.edge.block.terminalSourceHolds state sourceHolds
  have checked := edge.edge.control.checked
  rw [edge.edge.block.afterExpected state calls eventIndex events world]
  unfold CheckedNativeOperationBlock.expectedTerminalTransition
  cases expectedExact :
      edge.edge.block.terminal.cutpoint.postcondition.outcome.expected with
  | none =>
      simp [checkedNativeOperationLocalSuccessor, expectedExact] at checked
  | some outcome =>
      simpa [expectedExact, CheckedNativeOperationStoppedEdge.after] using
        statePreservingSuccessorMachineState candidate
          edge.edge.block.terminal.cutpoint.source outcome
          edge.edge.control.successor edge.edge.block.terminal.instruction.rva
          (edge.edge.block.terminalState state)
          (concreteBehaviorNextMachineState
            (edge.edge.block.terminal.replay.behavior.eval
              (edge.edge.block.terminalState state))
            (edge.edge.block.terminalState state))
          calls eventIndex events world
          (by simpa [expectedExact] using checked) edge.statePreserving
          terminalHolds callContext

theorem CheckedNativeOperationStatePreservingLocalEdge.afterInvariant
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationStatePreservingLocalEdge candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds :
      match edge.edge.block.running with
      | none => edge.edge.block.terminal.cutpoint.source.Holds state
      | some running => running.first.cutpoint.source.Holds state)
    (callContext : edge.edge.control.successor.callContextHolds calls) :
    ∃ afterState,
      nativeWorldExecutionMachineState?
          (edge.edge.block.after state calls eventIndex events world) =
        some afterState ∧
      edge.edge.block.terminal.cutpoint.target.Holds afterState := by
  refine ⟨edge.edge.block.terminal.after
    (edge.edge.block.terminalState state), ?_, ?_⟩
  · exact edge.afterMachineState state calls eventIndex events world
      sourceHolds callContext
  · exact edge.edge.block.terminalInvariantHolds state sourceHolds

def checkedNativeOperationBlockSourceInvariant
    (block : CheckedNativeOperationBlock candidate) :
    NativeOperationInvariant :=
  match block.running with
  | none => block.terminal.cutpoint.source
  | some running => running.first.cutpoint.source

theorem checkedNativeOperationBlockSourceInvariantHolds
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState)
    (holds : (checkedNativeOperationBlockSourceInvariant block).Holds state) :
    match block.running with
    | none => block.terminal.cutpoint.source.Holds state
    | some running => running.first.cutpoint.source.Holds state := by
  cases runningExact : block.running <;>
    simpa [checkedNativeOperationBlockSourceInvariant, runningExact] using holds

structure CheckedNativeOperationLocalConnection
    (candidate : ExactNativeWorldProgram) where
  source : CheckedNativeOperationStatePreservingLocalEdge candidate
  target : CheckedNativeOperationBlock candidate
  targetRvaExact :
    source.edge.control.successor.targetRva = target.entryRva
  targetSlotExact : target.entrySlot = 0
  invariantExact :
    source.edge.block.terminal.cutpoint.target =
      checkedNativeOperationBlockSourceInvariant target

theorem CheckedNativeOperationLocalConnection.follow
    {candidate : ExactNativeWorldProgram}
    (connection : CheckedNativeOperationLocalConnection candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds :
      (checkedNativeOperationBlockSourceInvariant
        connection.source.edge.block).Holds state)
    (callContext :
      connection.source.edge.control.successor.callContextHolds calls) :
    ∃ afterState nextCalls,
      connection.source.edge.block.after state calls eventIndex events world =
        .running connection.target.entryRva connection.target.entrySlot
          afterState nextCalls eventIndex events world ∧
      (checkedNativeOperationBlockSourceInvariant connection.target).Holds
        afterState := by
  have terminalHolds :=
    connection.source.edge.block.terminalSourceHolds state
      (checkedNativeOperationBlockSourceInvariantHolds
        connection.source.edge.block state sourceHolds)
  have checked := connection.source.edge.control.checked
  rw [connection.source.edge.block.afterExpected state calls eventIndex events
    world]
  unfold CheckedNativeOperationBlock.expectedTerminalTransition
  cases expectedExact :
      connection.source.edge.block.terminal.cutpoint.postcondition.outcome.expected with
  | none =>
      simp [checkedNativeOperationLocalSuccessor, expectedExact] at checked
  | some outcome =>
      obtain ⟨nextCalls, endpoint⟩ :=
        statePreservingSuccessorRunning candidate
          connection.source.edge.block.terminal.cutpoint.source outcome
          connection.source.edge.control.successor
          connection.source.edge.block.terminal.instruction.rva
          (connection.source.edge.block.terminalState state)
          (concreteBehaviorNextMachineState
            (connection.source.edge.block.terminal.replay.behavior.eval
              (connection.source.edge.block.terminalState state))
            (connection.source.edge.block.terminalState state))
          calls eventIndex events world
          (by simpa [expectedExact] using checked)
          connection.source.statePreserving terminalHolds callContext
      refine ⟨connection.source.edge.block.terminal.after
        (connection.source.edge.block.terminalState state), nextCalls, ?_, ?_⟩
      · rw [← connection.targetRvaExact, connection.targetSlotExact]
        simpa [expectedExact, CheckedNativeOperationStoppedEdge.after] using
          endpoint
      · rw [← connection.invariantExact]
        exact connection.source.edge.block.terminalInvariantHolds state (by
          exact checkedNativeOperationBlockSourceInvariantHolds
            connection.source.edge.block state sourceHolds)

theorem CheckedNativeOperationLocalConnection.pathThroughTarget
    {candidate : ExactNativeWorldProgram}
    (connection : CheckedNativeOperationLocalConnection candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds :
      (checkedNativeOperationBlockSourceInvariant
        connection.source.edge.block).Holds state)
    (callContext :
      connection.source.edge.control.successor.callContextHolds calls) :
    ∃ afterState nextCalls,
      NonemptyRelatedPath candidate.transitionSystem
        (.running connection.source.edge.block.entryRva
          connection.source.edge.block.entrySlot state calls eventIndex events
          world)
        (connection.source.edge.block.observations state calls eventIndex events
          world ++
          connection.target.observations afterState nextCalls eventIndex events
            world)
        (connection.target.after afterState nextCalls eventIndex events world) ∧
      (checkedNativeOperationBlockSourceInvariant connection.target).Holds
        afterState := by
  obtain ⟨afterState, nextCalls, endpoint, targetHolds⟩ :=
    connection.follow state calls eventIndex events world sourceHolds callContext
  refine ⟨afterState, nextCalls, ?_, targetHolds⟩
  have firstPath :=
    connection.source.edge.block.path state calls eventIndex events world
  have secondPath :=
    connection.target.path afterState nextCalls eventIndex events world
  rw [endpoint] at firstPath
  exact firstPath.trans secondPath

#print axioms CheckedNativeOperationLocalSuccessor.afterRva
#print axioms CheckedNativeOperationLocalEdge.execute
#print axioms
  CheckedNativeOperationStatePreservingLocalEdge.afterMachineState
#print axioms
  CheckedNativeOperationStatePreservingLocalEdge.afterInvariant
#print axioms CheckedNativeOperationLocalConnection.follow
#print axioms CheckedNativeOperationLocalConnection.pathThroughTarget

end StageA.Relational.InterpreterKernelOperationControlChecker
