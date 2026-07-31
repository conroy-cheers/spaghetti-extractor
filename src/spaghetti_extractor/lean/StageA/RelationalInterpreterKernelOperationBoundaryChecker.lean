import StageA.RelationalInterpreterKernelOperationEnvironment
import StageA.RelationalInterpreterKernelOperationRouteChecker

namespace StageA.Relational.InterpreterKernelOperationBoundaryChecker

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterKernelOperationControlChecker
open StageA.Relational.InterpreterKernelOperationFrameChecker
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationReplay
open StageA.Relational.InterpreterKernelOperationRouteChecker
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

noncomputable section

/-!
# Boundary-aware finite operation routes

The local route checker computes execution through a final decoded block.  This
module classifies that exact terminal transition.  A boundary handler contains
no replacement endpoint, path, or post-state:

* direct internal calls are checked against the decoded call outcome;
* finite indirect calls are resolved by the candidate's checked finite target
  inventory at the concrete terminal state;
* external calls carry the existing checked one-to-one environment response;
* top-level and caller returns are checked against the concrete call-frame
  stack.

Boundary steps can then be chained.  Internal and indirect callees are ordinary
subsequent steps in the chain, so nested frames are checked by the same machine
semantics as local control.
-/

theorem checkedNativeOperationTerminalOutcome
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) (outcome : OutcomeExpr)
    (outcomeExact :
      block.terminal.cutpoint.postcondition.outcome.expected = some outcome) :
    block.after state calls eventIndex events world =
      (transitionFromNativeWorldOutcome candidate.pe candidate.environment
        candidate.callableExternal candidate.indirectTargets
        block.terminal.instruction.rva
        (block.terminal.after (block.terminalState state))
        calls eventIndex events world
        (evalNativeOperationOutcomeExpr (block.terminalState state)
          outcome)).next := by
  rw [block.afterExpected state calls eventIndex events world]
  simp [CheckedNativeOperationBlock.expectedTerminalTransition, outcomeExact,
    CheckedNativeOperationStoppedEdge.after]

def checkedNativeOperationNestedInternalCall
    (candidate : ExactNativeWorldProgram)
    (block : CheckedNativeOperationBlock candidate)
    (targetRva continuationRva returnAddress : Nat) : Bool :=
  block.terminal.cutpoint.postcondition.outcome.expected ==
      some (.call targetRva continuationRva returnAddress) &&
    executableRva candidate.pe targetRva

structure CheckedNativeOperationNestedInternalCall
    {candidate : ExactNativeWorldProgram}
    {startBlock : CheckedNativeOperationBlock candidate}
    {startFrames : List NativeCallFrame}
    {finalBlock : CheckedNativeOperationBlock candidate}
    {finalFrames : List NativeCallFrame}
    {route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
      finalBlock finalFrames}
    {state : MachineState} {callerTail : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    (result : CheckedNativeOperationLocalRouteFinalResult route state callerTail
      eventIndex events world) where
  targetRva : Nat
  continuationRva : Nat
  returnAddress : Nat
  checked :
    checkedNativeOperationNestedInternalCall candidate finalBlock targetRva
      continuationRva returnAddress = true

theorem CheckedNativeOperationNestedInternalCall.afterExact
    {candidate : ExactNativeWorldProgram}
    {startBlock : CheckedNativeOperationBlock candidate}
    {startFrames : List NativeCallFrame}
    {finalBlock : CheckedNativeOperationBlock candidate}
    {finalFrames : List NativeCallFrame}
    {route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
      finalBlock finalFrames}
    {state : MachineState} {callerTail : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    {result : CheckedNativeOperationLocalRouteFinalResult route state callerTail
      eventIndex events world}
    (handler : CheckedNativeOperationNestedInternalCall result) :
    result.after =
      .running handler.targetRva 0
        (finalBlock.terminal.after result.terminalState)
        (expectedNativeOperationCallFrame handler.continuationRva
            handler.returnAddress ::
          (finalFrames ++ callerTail))
        eventIndex events world := by
  have checked := handler.checked
  simp only [checkedNativeOperationNestedInternalCall, Bool.and_eq_true,
    beq_iff_eq] at checked
  have exact := checkedNativeOperationTerminalOutcome finalBlock
    result.finalState (finalFrames ++ callerTail) eventIndex events world
    (.call handler.targetRva handler.continuationRva handler.returnAddress)
    checked.1
  simpa [CheckedNativeOperationLocalRouteFinalResult.after,
    evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
    expectedNativeOperationCallFrame] using exact

def checkedNativeOperationFiniteIndirectCall
    (candidate : ExactNativeWorldProgram)
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (world : RelationalWorld)
    (target : Expr) (targetRva continuationRva returnAddress : Nat) : Bool :=
  block.terminal.cutpoint.postcondition.outcome.expected ==
      some (.indirectCall target continuationRva returnAddress) &&
    candidate.indirectTargets.valid candidate.pe &&
    candidate.indirectTargets.resolve? candidate.pe world
        block.terminal.instruction.rva .call
        (target.eval (block.terminalState state)) ==
      some (.internalRva targetRva)

structure CheckedNativeOperationFiniteIndirectCall
    {candidate : ExactNativeWorldProgram}
    {startBlock : CheckedNativeOperationBlock candidate}
    {startFrames : List NativeCallFrame}
    {finalBlock : CheckedNativeOperationBlock candidate}
    {finalFrames : List NativeCallFrame}
    {route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
      finalBlock finalFrames}
    {state : MachineState} {callerTail : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    (result : CheckedNativeOperationLocalRouteFinalResult route state callerTail
      eventIndex events world) where
  target : Expr
  targetRva : Nat
  continuationRva : Nat
  returnAddress : Nat
  checked :
    checkedNativeOperationFiniteIndirectCall candidate finalBlock
      result.finalState world target targetRva continuationRva returnAddress =
        true

theorem CheckedNativeOperationFiniteIndirectCall.afterExact
    {candidate : ExactNativeWorldProgram}
    {startBlock : CheckedNativeOperationBlock candidate}
    {startFrames : List NativeCallFrame}
    {finalBlock : CheckedNativeOperationBlock candidate}
    {finalFrames : List NativeCallFrame}
    {route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
      finalBlock finalFrames}
    {state : MachineState} {callerTail : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    {result : CheckedNativeOperationLocalRouteFinalResult route state callerTail
      eventIndex events world}
    (handler : CheckedNativeOperationFiniteIndirectCall result) :
    result.after =
      .running handler.targetRva 0
        (finalBlock.terminal.after result.terminalState)
        (expectedNativeOperationCallFrame handler.continuationRva
            handler.returnAddress ::
          (finalFrames ++ callerTail))
        eventIndex events world := by
  have checked := handler.checked
  simp only [checkedNativeOperationFiniteIndirectCall, Bool.and_eq_true,
    beq_iff_eq] at checked
  have outcomeExact := checked.1.1
  have resolveExact := checked.2
  have exact := checkedNativeOperationTerminalOutcome finalBlock
    result.finalState (finalFrames ++ callerTail) eventIndex events world
    (.indirectCall handler.target handler.continuationRva
      handler.returnAddress) outcomeExact
  simpa [CheckedNativeOperationLocalRouteFinalResult.after,
    evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
    resolveExact, expectedNativeOperationCallFrame] using exact

def nativeOperationExternalEvent
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (imported : PEImport)
    (arguments : List Expr) : NativeExternalEvent := {
  imported
  arguments := arguments.map (Expr.eval (block.terminalState state))
  state := block.terminal.after (block.terminalState state)
}

def checkedNativeOperationExternalHandoff
    (block : CheckedNativeOperationBlock candidate)
    (imported : PEImport) (arguments : List Expr)
    (continuationRva : Nat) : Bool :=
  block.terminal.cutpoint.postcondition.outcome.expected ==
    some (.externalCall imported arguments continuationRva)

structure CheckedNativeOperationExternalHandoff
    {candidate : ExactNativeWorldProgram}
    {startBlock : CheckedNativeOperationBlock candidate}
    {startFrames : List NativeCallFrame}
    {finalBlock : CheckedNativeOperationBlock candidate}
    {finalFrames : List NativeCallFrame}
    {route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
      finalBlock finalFrames}
    {state : MachineState} {callerTail : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    (result : CheckedNativeOperationLocalRouteFinalResult route state callerTail
      eventIndex events world) where
  semanticEvent : CallEvent
  imported : PEImport
  arguments : List Expr
  continuationRva : Nat
  checked :
    checkedNativeOperationExternalHandoff finalBlock imported arguments
      continuationRva = true
  response : CheckedOneToOneKernelExternalResponse semanticEvent
    (nativeOperationExternalEvent finalBlock result.finalState imported
      arguments)
  nativeEnvironmentExact : response.nativeEnvironment = candidate.environment
  worldExact : response.world = world
  eventIndexExact : response.eventIndex = eventIndex

theorem CheckedNativeOperationExternalHandoff.afterExact
    {candidate : ExactNativeWorldProgram}
    {startBlock : CheckedNativeOperationBlock candidate}
    {startFrames : List NativeCallFrame}
    {finalBlock : CheckedNativeOperationBlock candidate}
    {finalFrames : List NativeCallFrame}
    {route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
      finalBlock finalFrames}
    {state : MachineState} {callerTail : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    {result : CheckedNativeOperationLocalRouteFinalResult route state callerTail
      eventIndex events world}
    (handler : CheckedNativeOperationExternalHandoff result) :
    result.after =
      .running handler.continuationRva 0 handler.response.candidateResult.state
        (finalFrames ++ callerTail) (eventIndex + 1)
        (events ++ [nativeOperationExternalEvent finalBlock result.finalState
          handler.imported handler.arguments])
        handler.response.candidateResult.world := by
  have checked := handler.checked
  simp only [checkedNativeOperationExternalHandoff, beq_iff_eq] at checked
  have exact := checkedNativeOperationTerminalOutcome finalBlock
    result.finalState (finalFrames ++ callerTail) eventIndex events world
    (.externalCall handler.imported handler.arguments handler.continuationRva)
    checked
  have returned := handler.response.nativeReturned
  rw [handler.nativeEnvironmentExact, handler.worldExact,
    handler.eventIndexExact] at returned
  have returnedExact :
      candidate.environment.action eventIndex {
        imported := handler.imported
        arguments := handler.arguments.map
          (Expr.eval (finalBlock.terminalState result.finalState))
        state := finalBlock.terminal.after
          (finalBlock.terminalState result.finalState)
      } world =
        .returned handler.response.candidateResult := by
    simpa [nativeOperationExternalEvent] using returned
  change
    finalBlock.after result.finalState (finalFrames ++ callerTail) eventIndex
        events world =
      _
  rw [exact]
  simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
    applyNativeWorldExternalAction, nativeOperationExternalEvent,
    returnedExact]

def checkedNativeOperationTopLevelReturn
    (block : CheckedNativeOperationBlock candidate)
    (target : Expr) (calls : List NativeCallFrame) : Bool :=
  block.terminal.cutpoint.postcondition.outcome.expected ==
      some (.returned target) &&
    calls.isEmpty

structure CheckedNativeOperationTopLevelReturn
    {candidate : ExactNativeWorldProgram}
    {startBlock : CheckedNativeOperationBlock candidate}
    {startFrames : List NativeCallFrame}
    {finalBlock : CheckedNativeOperationBlock candidate}
    {finalFrames : List NativeCallFrame}
    {route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
      finalBlock finalFrames}
    {state : MachineState} {callerTail : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    (result : CheckedNativeOperationLocalRouteFinalResult route state callerTail
      eventIndex events world) where
  target : Expr
  checked :
    checkedNativeOperationTopLevelReturn finalBlock target
      (finalFrames ++ callerTail) = true

theorem CheckedNativeOperationTopLevelReturn.afterExact
    {candidate : ExactNativeWorldProgram}
    {startBlock : CheckedNativeOperationBlock candidate}
    {startFrames : List NativeCallFrame}
    {finalBlock : CheckedNativeOperationBlock candidate}
    {finalFrames : List NativeCallFrame}
    {route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
      finalBlock finalFrames}
    {state : MachineState} {callerTail : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    {result : CheckedNativeOperationLocalRouteFinalResult route state callerTail
      eventIndex events world}
    (handler : CheckedNativeOperationTopLevelReturn result) :
    result.after =
      .returned (finalBlock.terminal.after result.terminalState) events world := by
  have checked := handler.checked
  simp only [checkedNativeOperationTopLevelReturn, Bool.and_eq_true,
    beq_iff_eq] at checked
  have callsEmpty : finalFrames ++ callerTail = [] := by
    simpa using List.isEmpty_iff.mp checked.2
  have exact := checkedNativeOperationTerminalOutcome finalBlock
    result.finalState (finalFrames ++ callerTail) eventIndex events world
    (.returned handler.target) checked.1
  change
    finalBlock.after result.finalState (finalFrames ++ callerTail) eventIndex
        events world =
      _
  rw [exact]
  simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
    callsEmpty, CheckedNativeOperationLocalRouteFinalResult.terminalState]

def checkedNativeOperationCallerReturn
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls nextCalls : List NativeCallFrame)
    (target : Expr) (continuationRva returnAddress : Nat) : Bool :=
  block.terminal.cutpoint.postcondition.outcome.expected ==
      some (.returned target) &&
    target.eval (block.terminalState state) ==
      BitVec.ofNat 32 returnAddress &&
    nativeOperationSuccessorCallFrames?
        (.returned continuationRva returnAddress) calls ==
      some nextCalls

theorem checkedNativeOperationCallerReturn_afterExact
    (candidate : ExactNativeWorldProgram)
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls nextCalls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) (target : Expr)
    (continuationRva returnAddress : Nat)
    (checked :
      checkedNativeOperationCallerReturn block state calls nextCalls target
        continuationRva returnAddress = true) :
    block.after state calls eventIndex events world =
      .running continuationRva 0
        (block.terminal.after (block.terminalState state))
        nextCalls eventIndex events world := by
  simp only [checkedNativeOperationCallerReturn, Bool.and_eq_true,
    beq_iff_eq] at checked
  have outcomeExact := checked.1.1
  have targetExact := checked.1.2
  have framesExact := checked.2
  have exact := checkedNativeOperationTerminalOutcome block state calls
    eventIndex events world (.returned target) outcomeExact
  have callsExact :=
    nativeOperationSuccessorCallFrames?_returned_exact continuationRva
      returnAddress calls nextCalls framesExact
  rw [callsExact] at exact ⊢
  rw [exact]
  simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
    targetExact, expectedNativeOperationCallFrame]

structure CheckedNativeOperationCallerReturn
    {candidate : ExactNativeWorldProgram}
    {startBlock : CheckedNativeOperationBlock candidate}
    {startFrames : List NativeCallFrame}
    {finalBlock : CheckedNativeOperationBlock candidate}
    {finalFrames : List NativeCallFrame}
    {route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
      finalBlock finalFrames}
    {state : MachineState} {callerTail : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    (result : CheckedNativeOperationLocalRouteFinalResult route state callerTail
      eventIndex events world) where
  target : Expr
  continuationRva : Nat
  returnAddress : Nat
  nextCalls : List NativeCallFrame
  checked :
    checkedNativeOperationCallerReturn finalBlock result.finalState
      (finalFrames ++ callerTail) nextCalls target continuationRva
      returnAddress = true

theorem CheckedNativeOperationCallerReturn.afterExact
    {candidate : ExactNativeWorldProgram}
    {startBlock : CheckedNativeOperationBlock candidate}
    {startFrames : List NativeCallFrame}
    {finalBlock : CheckedNativeOperationBlock candidate}
    {finalFrames : List NativeCallFrame}
    {route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
      finalBlock finalFrames}
    {state : MachineState} {callerTail : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    {result : CheckedNativeOperationLocalRouteFinalResult route state callerTail
      eventIndex events world}
    (handler : CheckedNativeOperationCallerReturn result) :
    result.after =
      .running handler.continuationRva 0
        (finalBlock.terminal.after result.terminalState)
        handler.nextCalls eventIndex events world := by
  change
    finalBlock.after result.finalState (finalFrames ++ callerTail) eventIndex
        events world =
      .running handler.continuationRva 0
        (finalBlock.terminal.after
          (finalBlock.terminalState result.finalState))
        handler.nextCalls eventIndex events world
  exact checkedNativeOperationCallerReturn_afterExact candidate finalBlock
    result.finalState (finalFrames ++ callerTail) handler.nextCalls eventIndex
    events world handler.target handler.continuationRva handler.returnAddress
    handler.checked

inductive CheckedNativeOperationBoundaryHandler
    {candidate : ExactNativeWorldProgram}
    {startBlock : CheckedNativeOperationBlock candidate}
    {startFrames : List NativeCallFrame}
    {finalBlock : CheckedNativeOperationBlock candidate}
    {finalFrames : List NativeCallFrame}
    {route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
      finalBlock finalFrames}
    {state : MachineState} {callerTail : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    (result : CheckedNativeOperationLocalRouteFinalResult route state callerTail
      eventIndex events world) : Type
  | nestedInternal
      (handler : CheckedNativeOperationNestedInternalCall result)
  | finiteIndirect
      (handler : CheckedNativeOperationFiniteIndirectCall result)
  | externalHandoff
      (handler : CheckedNativeOperationExternalHandoff result)
  | topLevelReturn
      (handler : CheckedNativeOperationTopLevelReturn result)
  | callerReturn
      (handler : CheckedNativeOperationCallerReturn result)

/-! A boundary step stores only checked route data and a typed handler. -/

structure CheckedNativeOperationBoundaryStep
    (candidate : ExactNativeWorldProgram) where
  startBlock : CheckedNativeOperationBlock candidate
  startFrames : List NativeCallFrame
  finalBlock : CheckedNativeOperationBlock candidate
  finalFrames : List NativeCallFrame
  route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
    finalBlock finalFrames
  state : MachineState
  callerTail : List NativeCallFrame
  eventIndex : Nat
  events : List NativeExternalEvent
  world : RelationalWorld
  sourceHolds :
    (checkedNativeOperationBlockSourceInvariant startBlock).Holds state
  handler : CheckedNativeOperationBoundaryHandler
    (route.executeThroughFinal state callerTail eventIndex events world
      sourceHolds)

def CheckedNativeOperationBoundaryStep.execution
    (step : CheckedNativeOperationBoundaryStep candidate) :=
  step.route.executeThroughFinal step.state step.callerTail step.eventIndex
    step.events step.world step.sourceHolds

def CheckedNativeOperationBoundaryStep.before
    (step : CheckedNativeOperationBoundaryStep candidate) :
    NativeWorldExecution :=
  .running step.startBlock.entryRva step.startBlock.entrySlot step.state
    (step.startFrames ++ step.callerTail) step.eventIndex step.events step.world

def CheckedNativeOperationBoundaryStep.after
    (step : CheckedNativeOperationBoundaryStep candidate) :
    NativeWorldExecution :=
  step.execution.after

def CheckedNativeOperationBoundaryStep.observations
    (step : CheckedNativeOperationBoundaryStep candidate) :
    List WorldRelationalObservable :=
  step.execution.observations

theorem CheckedNativeOperationBoundaryStep.path
    (step : CheckedNativeOperationBoundaryStep candidate) :
    NonemptyRelatedPath candidate.transitionSystem step.before
      step.observations step.after :=
  step.execution.path

inductive CheckedNativeOperationBoundaryRoute
    (candidate : ExactNativeWorldProgram) :
    NativeWorldExecution -> List WorldRelationalObservable ->
      NativeWorldExecution -> Type
  | last (step : CheckedNativeOperationBoundaryStep candidate) :
      CheckedNativeOperationBoundaryRoute candidate step.before
        step.observations step.after
  | cons
      (step : CheckedNativeOperationBoundaryStep candidate)
      (tail : CheckedNativeOperationBoundaryRoute candidate step.after
        tailObservations after) :
      CheckedNativeOperationBoundaryRoute candidate step.before
        (step.observations ++ tailObservations) after

theorem CheckedNativeOperationBoundaryRoute.execute
    (route : CheckedNativeOperationBoundaryRoute candidate before observations
      after) :
    NonemptyRelatedPath candidate.transitionSystem before observations after := by
  induction route with
  | last step => exact step.path
  | cons step tail induction => exact step.path.trans induction

noncomputable def CheckedNativeOperationBoundaryRoute.toCheckedPath
    (route : CheckedNativeOperationBoundaryRoute candidate before observations
      after) :
    CheckedNativeOperationPath candidate before :=
  CheckedNativeOperationPath.ofNonempty route.execute

theorem CheckedNativeOperationBoundaryRoute.toCheckedPath_after
    (route : CheckedNativeOperationBoundaryRoute candidate before observations
      after) :
    route.toCheckedPath.after = after :=
  CheckedNativeOperationPath.ofNonempty_after route.execute

theorem CheckedNativeOperationBoundaryRoute.toCheckedPath_observations
    (route : CheckedNativeOperationBoundaryRoute candidate before observations
      after) :
    route.toCheckedPath.observations = observations :=
  CheckedNativeOperationPath.ofNonempty_observations route.execute

#print axioms CheckedNativeOperationNestedInternalCall.afterExact
#print axioms CheckedNativeOperationFiniteIndirectCall.afterExact
#print axioms CheckedNativeOperationExternalHandoff.afterExact
#print axioms CheckedNativeOperationTopLevelReturn.afterExact
#print axioms checkedNativeOperationCallerReturn_afterExact
#print axioms CheckedNativeOperationCallerReturn.afterExact
#print axioms CheckedNativeOperationLocalRoute.executeThroughFinal
#print axioms CheckedNativeOperationLocalRouteFinalResult.path
#print axioms CheckedNativeOperationLocalRouteFinalResult.terminalSourceHolds
#print axioms
  CheckedNativeOperationLocalRouteFinalResult.terminalPostconditionHolds
#print axioms
  CheckedNativeOperationLocalRouteFinalResult.terminalTransitionExact
#print axioms CheckedNativeOperationBoundaryStep.path
#print axioms CheckedNativeOperationBoundaryRoute.execute
#print axioms CheckedNativeOperationBoundaryRoute.toCheckedPath_after
#print axioms CheckedNativeOperationBoundaryRoute.toCheckedPath_observations

end

end StageA.Relational.InterpreterKernelOperationBoundaryChecker
