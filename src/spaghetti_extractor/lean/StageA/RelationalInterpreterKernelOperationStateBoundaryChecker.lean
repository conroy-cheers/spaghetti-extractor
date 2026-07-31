import StageA.RelationalInterpreterKernelOperationBoundaryChecker
import StageA.RelationalInterpreterKernelOperationStateRouteChecker

namespace StageA.Relational.InterpreterKernelOperationStateBoundaryChecker

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterKernelOperationBoundaryChecker
open StageA.Relational.InterpreterKernelOperationFrameChecker
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationReplay
open StageA.Relational.InterpreterKernelOperationStateRouteChecker
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

noncomputable section

/-!
# Typed boundaries for state-indexed native routes

The older boundary API consumes a route selected entirely by a static
invariant. Compiler-generated code selects branches from concrete intermediate
states, so this module applies the same checked terminal classifiers directly
to `CheckedNativeOperationStateRoute`.

No endpoint is accepted from the generator. The route computes its final
state, call frames, event prefix, world, observations, and exact transition.
Each handler only classifies the exact final block outcome.
-/

/-- Classify one checked block as a direct internal call without first
wrapping it in a one-block route.  The endpoint state and pushed call frame
remain computed by the checked instruction semantics. -/
theorem checkedNativeOperationBlockNestedInternalCall_afterExact
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (targetRva continuationRva returnAddress : Nat)
    (checked :
      checkedNativeOperationNestedInternalCall candidate block targetRva
        continuationRva returnAddress = true) :
    block.after state calls eventIndex events world =
      .running targetRva 0
        (block.terminal.after (block.terminalState state))
        (expectedNativeOperationCallFrame continuationRva returnAddress ::
          calls)
        eventIndex events world := by
  simp only [checkedNativeOperationNestedInternalCall, Bool.and_eq_true,
    beq_iff_eq] at checked
  have exact := checkedNativeOperationTerminalOutcome block state calls
    eventIndex events world (.call targetRva continuationRva returnAddress)
    checked.1
  simpa [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
    expectedNativeOperationCallFrame] using exact

structure CheckedNativeOperationStateNestedInternalCall
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld) where
  targetRva : Nat
  continuationRva : Nat
  returnAddress : Nat
  checked :
    checkedNativeOperationNestedInternalCall candidate finalBlock targetRva
      continuationRva returnAddress = true

theorem CheckedNativeOperationStateNestedInternalCall.afterExact
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    {route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld}
    (handler : CheckedNativeOperationStateNestedInternalCall route) :
    route.after =
      .running handler.targetRva 0
        (finalBlock.terminal.after (finalBlock.terminalState finalState))
        (expectedNativeOperationCallFrame handler.continuationRva
            handler.returnAddress :: finalCalls)
        finalEventIndex finalEvents finalWorld := by
  have checked := handler.checked
  simp only [checkedNativeOperationNestedInternalCall, Bool.and_eq_true,
    beq_iff_eq] at checked
  have exact := checkedNativeOperationTerminalOutcome finalBlock finalState
    finalCalls finalEventIndex finalEvents finalWorld
    (.call handler.targetRva handler.continuationRva handler.returnAddress)
    checked.1
  simpa [CheckedNativeOperationStateRoute.after,
    evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
    expectedNativeOperationCallFrame] using exact

structure CheckedNativeOperationStateFiniteIndirectCall
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld) where
  target : Expr
  targetRva : Nat
  continuationRva : Nat
  returnAddress : Nat
  checked :
    checkedNativeOperationFiniteIndirectCall candidate finalBlock finalState
      finalWorld target targetRva continuationRva returnAddress = true

theorem CheckedNativeOperationStateFiniteIndirectCall.afterExact
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    {route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld}
    (handler : CheckedNativeOperationStateFiniteIndirectCall route) :
    route.after =
      .running handler.targetRva 0
        (finalBlock.terminal.after (finalBlock.terminalState finalState))
        (expectedNativeOperationCallFrame handler.continuationRva
            handler.returnAddress :: finalCalls)
        finalEventIndex finalEvents finalWorld := by
  have checked := handler.checked
  simp only [checkedNativeOperationFiniteIndirectCall, Bool.and_eq_true,
    beq_iff_eq] at checked
  have exact := checkedNativeOperationTerminalOutcome finalBlock finalState
    finalCalls finalEventIndex finalEvents finalWorld
    (.indirectCall handler.target handler.continuationRva
      handler.returnAddress) checked.1.1
  simpa [CheckedNativeOperationStateRoute.after,
    evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
    checked.2, expectedNativeOperationCallFrame] using exact

structure CheckedNativeOperationStateExternalHandoff
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld) where
  semanticEvent : CallEvent
  imported : PEImport
  arguments : List Expr
  continuationRva : Nat
  checked :
    checkedNativeOperationExternalHandoff finalBlock imported arguments
      continuationRva = true
  response : CheckedOneToOneKernelExternalResponse semanticEvent
    (nativeOperationExternalEvent finalBlock finalState imported arguments)
  nativeEnvironmentExact : response.nativeEnvironment = candidate.environment
  worldExact : response.world = finalWorld
  eventIndexExact : response.eventIndex = finalEventIndex

theorem CheckedNativeOperationStateExternalHandoff.afterExact
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    {route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld}
    (handler : CheckedNativeOperationStateExternalHandoff route) :
    route.after =
      .running handler.continuationRva 0 handler.response.candidateResult.state
        finalCalls (finalEventIndex + 1)
        (finalEvents ++ [nativeOperationExternalEvent finalBlock finalState
          handler.imported handler.arguments])
        handler.response.candidateResult.world := by
  have checked := handler.checked
  simp only [checkedNativeOperationExternalHandoff, beq_iff_eq] at checked
  have exact := checkedNativeOperationTerminalOutcome finalBlock finalState
    finalCalls finalEventIndex finalEvents finalWorld
    (.externalCall handler.imported handler.arguments handler.continuationRva)
    checked
  have returned := handler.response.nativeReturned
  rw [handler.nativeEnvironmentExact, handler.worldExact,
    handler.eventIndexExact] at returned
  have returnedExact :
      candidate.environment.action finalEventIndex {
        imported := handler.imported
        arguments := handler.arguments.map
          (Expr.eval (finalBlock.terminalState finalState))
        state := finalBlock.terminal.after
          (finalBlock.terminalState finalState)
      } finalWorld =
        .returned handler.response.candidateResult := by
    simpa [nativeOperationExternalEvent] using returned
  change finalBlock.after finalState finalCalls finalEventIndex finalEvents
      finalWorld = _
  rw [exact]
  simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
    applyNativeWorldExternalAction, nativeOperationExternalEvent,
    returnedExact]

structure CheckedNativeOperationStateTopLevelReturn
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld) where
  target : Expr
  checked :
    checkedNativeOperationTopLevelReturn finalBlock target finalCalls = true

theorem CheckedNativeOperationStateTopLevelReturn.afterExact
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    {route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld}
    (handler : CheckedNativeOperationStateTopLevelReturn route) :
    route.after =
      .returned (finalBlock.terminal.after
        (finalBlock.terminalState finalState)) finalEvents finalWorld := by
  have checked := handler.checked
  simp only [checkedNativeOperationTopLevelReturn, Bool.and_eq_true,
    beq_iff_eq] at checked
  have callsEmpty : finalCalls = [] := by
    simpa using List.isEmpty_iff.mp checked.2
  have exact := checkedNativeOperationTerminalOutcome finalBlock finalState
    finalCalls finalEventIndex finalEvents finalWorld
    (.returned handler.target) checked.1
  change finalBlock.after finalState finalCalls finalEventIndex finalEvents
      finalWorld = _
  rw [exact]
  simp [evalNativeOperationOutcomeExpr, transitionFromNativeWorldOutcome,
    callsEmpty]

structure CheckedNativeOperationStateCallerReturn
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld) where
  target : Expr
  continuationRva : Nat
  returnAddress : Nat
  nextCalls : List NativeCallFrame
  checked :
    checkedNativeOperationCallerReturn finalBlock finalState finalCalls
      nextCalls target continuationRva returnAddress = true

theorem CheckedNativeOperationStateCallerReturn.afterExact
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    {route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld}
    (handler : CheckedNativeOperationStateCallerReturn route) :
    route.after =
      .running handler.continuationRva 0
        (finalBlock.terminal.after (finalBlock.terminalState finalState))
        handler.nextCalls finalEventIndex finalEvents finalWorld := by
  change finalBlock.after finalState finalCalls finalEventIndex finalEvents
      finalWorld = _
  exact checkedNativeOperationCallerReturn_afterExact candidate finalBlock
    finalState finalCalls handler.nextCalls finalEventIndex finalEvents
    finalWorld handler.target handler.continuationRva handler.returnAddress
    handler.checked

inductive CheckedNativeOperationStateBoundaryHandler
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld) :
    Type
  | nestedInternal
      (handler : CheckedNativeOperationStateNestedInternalCall route)
  | finiteIndirect
      (handler : CheckedNativeOperationStateFiniteIndirectCall route)
  | externalHandoff
      (handler : CheckedNativeOperationStateExternalHandoff route)
  | topLevelReturn
      (handler : CheckedNativeOperationStateTopLevelReturn route)
  | callerReturn
      (handler : CheckedNativeOperationStateCallerReturn route)

/-- One exact state-indexed route ending at a typed machine boundary. -/
structure CheckedNativeOperationStateBoundaryStep
    (candidate : ExactNativeWorldProgram)
    (blocks : List (CheckedNativeOperationBlock candidate)) where
  sourceBlock : CheckedNativeOperationBlock candidate
  finalBlock : CheckedNativeOperationBlock candidate
  sourceState : MachineState
  finalState : MachineState
  sourceCalls : List NativeCallFrame
  finalCalls : List NativeCallFrame
  sourceEventIndex : Nat
  finalEventIndex : Nat
  sourceEvents : List NativeExternalEvent
  finalEvents : List NativeExternalEvent
  sourceWorld : RelationalWorld
  finalWorld : RelationalWorld
  route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
    sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
    finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld
  handler : CheckedNativeOperationStateBoundaryHandler route

def CheckedNativeOperationStateBoundaryStep.before
    (step : CheckedNativeOperationStateBoundaryStep candidate blocks) :
    NativeWorldExecution :=
  step.route.before

def CheckedNativeOperationStateBoundaryStep.after
    (step : CheckedNativeOperationStateBoundaryStep candidate blocks) :
    NativeWorldExecution :=
  step.route.after

def CheckedNativeOperationStateBoundaryStep.observations
    (step : CheckedNativeOperationStateBoundaryStep candidate blocks) :
    List WorldRelationalObservable :=
  step.route.observations

theorem CheckedNativeOperationStateBoundaryStep.path
    (step : CheckedNativeOperationStateBoundaryStep candidate blocks) :
    NonemptyRelatedPath candidate.transitionSystem step.before
      step.observations step.after :=
  step.route.path

/-- Boundary-aware native execution. Chaining is indexed by the exact machine
execution produced by the preceding route, so nested calls, returns, indirect
targets, and external responses cannot submit a replacement continuation. -/
inductive CheckedNativeOperationStateBoundaryRoute
    (candidate : ExactNativeWorldProgram)
    (blocks : List (CheckedNativeOperationBlock candidate)) :
    NativeWorldExecution -> List WorldRelationalObservable ->
      NativeWorldExecution -> Type
  | last (step : CheckedNativeOperationStateBoundaryStep candidate blocks) :
      CheckedNativeOperationStateBoundaryRoute candidate blocks step.before
        step.observations step.after
  | cons
      (step : CheckedNativeOperationStateBoundaryStep candidate blocks)
      (tail : CheckedNativeOperationStateBoundaryRoute candidate blocks
        step.after tailObservations after) :
      CheckedNativeOperationStateBoundaryRoute candidate blocks step.before
        (step.observations ++ tailObservations) after

/-- Package one exact route ending in a checked direct internal call as a
boundary route. The execution indices are inherited from `route`; no endpoint
or continuation can be supplied independently. -/
def checkedNativeOperationStateBoundaryRouteOfNestedInternalCall
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld)
    (handler : CheckedNativeOperationStateNestedInternalCall route) :
    CheckedNativeOperationStateBoundaryRoute candidate blocks route.before
      route.observations route.after :=
  .last {
    sourceBlock
    finalBlock
    sourceState
    finalState
    sourceCalls
    finalCalls
    sourceEventIndex
    finalEventIndex
    sourceEvents
    finalEvents
    sourceWorld
    finalWorld
    route
    handler := .nestedInternal handler
  }

/-- Package one exact route ending in a checked return to its caller. -/
def checkedNativeOperationStateBoundaryRouteOfCallerReturn
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld)
    (handler : CheckedNativeOperationStateCallerReturn route) :
    CheckedNativeOperationStateBoundaryRoute candidate blocks route.before
      route.observations route.after :=
  .last {
    sourceBlock
    finalBlock
    sourceState
    finalState
    sourceCalls
    finalCalls
    sourceEventIndex
    finalEventIndex
    sourceEvents
    finalEvents
    sourceWorld
    finalWorld
    route
    handler := .callerReturn handler
  }

theorem CheckedNativeOperationStateBoundaryRoute.execute
    (route : CheckedNativeOperationStateBoundaryRoute candidate blocks before
      observations after) :
    NonemptyRelatedPath candidate.transitionSystem before observations after := by
  induction route with
  | last step =>
      exact step.path
  | cons step tail induction =>
      exact step.path.trans induction

noncomputable def CheckedNativeOperationStateBoundaryRoute.toCheckedPath
    (route : CheckedNativeOperationStateBoundaryRoute candidate blocks before
      observations after) :
    CheckedNativeOperationPath candidate before :=
  CheckedNativeOperationPath.ofNonempty route.execute

theorem CheckedNativeOperationStateBoundaryRoute.toCheckedPath_after
    (route : CheckedNativeOperationStateBoundaryRoute candidate blocks before
      observations after) :
    route.toCheckedPath.after = after :=
  CheckedNativeOperationPath.ofNonempty_after route.execute

theorem CheckedNativeOperationStateBoundaryRoute.toCheckedPath_observations
    (route : CheckedNativeOperationStateBoundaryRoute candidate blocks before
      observations after) :
    route.toCheckedPath.observations = observations :=
  CheckedNativeOperationPath.ofNonempty_observations route.execute

#print axioms CheckedNativeOperationStateNestedInternalCall.afterExact
#print axioms checkedNativeOperationBlockNestedInternalCall_afterExact
#print axioms CheckedNativeOperationStateFiniteIndirectCall.afterExact
#print axioms CheckedNativeOperationStateExternalHandoff.afterExact
#print axioms CheckedNativeOperationStateTopLevelReturn.afterExact
#print axioms CheckedNativeOperationStateCallerReturn.afterExact
#print axioms CheckedNativeOperationStateBoundaryStep.path
#print axioms checkedNativeOperationStateBoundaryRouteOfNestedInternalCall
#print axioms checkedNativeOperationStateBoundaryRouteOfCallerReturn
#print axioms CheckedNativeOperationStateBoundaryRoute.execute
#print axioms CheckedNativeOperationStateBoundaryRoute.toCheckedPath_after
#print axioms
  CheckedNativeOperationStateBoundaryRoute.toCheckedPath_observations

end

end StageA.Relational.InterpreterKernelOperationStateBoundaryChecker
