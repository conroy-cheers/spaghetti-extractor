import StageA.RelationalInterpreterKernelOperationStateRouteChecker

namespace StageA.Relational.InterpreterKernelOperationBoundedStateRoute

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationControlChecker
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationGraphChecker
open StageA.Relational.InterpreterKernelOperationStateRouteChecker
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

/-!
# Bounded state-indexed native routes

Some exact machine paths contain a concrete finite loop even though their
static control-flow graph is cyclic. Stack probes are a common example. An
RVA-only rank cannot certify such a path because the same block may be visited
more than once.

This checker follows only exact graph successors produced by
`checkedNativeOperationGraphSuccessor?`. It accepts a route only if a declared
stop RVA is reached within the supplied block budget. Exhaustion, a
non-local boundary, a missing graph target, or a failed invariant link returns
`none`. The budget is proof data and never widens execution semantics.
-/

structure CheckedNativeOperationStateRouteToStopWithinResult
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    (stopRvas : List Nat)
    (sourceBlock : CheckedNativeOperationBlock candidate)
    (sourceState : MachineState) (sourceCalls : List NativeCallFrame)
    (sourceEventIndex : Nat) (sourceEvents : List NativeExternalEvent)
    (sourceWorld : RelationalWorld) where
  finalBlock : CheckedNativeOperationBlock candidate
  finalState : MachineState
  finalCalls : List NativeCallFrame
  finalEventIndex : Nat
  finalEvents : List NativeExternalEvent
  finalWorld : RelationalWorld
  route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
    sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
    finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld
  stopped : finalBlock.entryRva ∈ stopRvas

def checkedNativeOperationStateRouteToStopWithin?
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    (stopRvas : List Nat) (budget : Nat)
    (sourceBlock : CheckedNativeOperationBlock candidate)
    (sourceMember : sourceBlock ∈ blocks)
    (sourceState : MachineState) (sourceCalls : List NativeCallFrame)
    (sourceEventIndex : Nat) (sourceEvents : List NativeExternalEvent)
    (sourceWorld : RelationalWorld)
    (sourceHolds :
      (checkedNativeOperationBlockSourceInvariant sourceBlock).Holds
        sourceState) :
    Option (CheckedNativeOperationStateRouteToStopWithinResult
      (blocks := blocks) stopRvas sourceBlock sourceState sourceCalls
      sourceEventIndex sourceEvents sourceWorld) :=
  if stopped : sourceBlock.entryRva ∈ stopRvas then
    some {
      finalBlock := sourceBlock
      finalState := sourceState
      finalCalls := sourceCalls
      finalEventIndex := sourceEventIndex
      finalEvents := sourceEvents
      finalWorld := sourceWorld
      route := .final sourceBlock sourceState sourceCalls sourceEventIndex
        sourceEvents sourceWorld sourceMember sourceHolds
      stopped
    }
  else
    match budget with
    | 0 => none
    | remaining + 1 =>
        if localChecked :
            nativeOperationOutcomeAlwaysRunningLocal
                sourceBlock.terminal.cutpoint.postcondition.outcome = true then
          match checkedNativeOperationGraphSuccessor? blocks sourceBlock
              sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld with
          | none => none
          | some successor =>
              match checkedNativeOperationStateRouteToStopWithin? stopRvas
                  remaining successor.target successor.targetMember
                  successor.targetState successor.targetCalls
                  successor.targetEventIndex successor.targetEvents
                  successor.targetWorld
                  (successor.targetInvariantHolds sourceHolds) with
              | none => none
              | some tail =>
                  some {
                    finalBlock := tail.finalBlock
                    finalState := tail.finalState
                    finalCalls := tail.finalCalls
                    finalEventIndex := tail.finalEventIndex
                    finalEvents := tail.finalEvents
                    finalWorld := tail.finalWorld
                    route := .step sourceBlock sourceState sourceCalls
                      sourceEventIndex sourceEvents sourceWorld sourceMember
                      sourceHolds localChecked successor tail.route
                    stopped := tail.stopped
                  }
        else none
termination_by budget

theorem CheckedNativeOperationStateRouteToStopWithinResult.path
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {stopRvas : List Nat}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceState : MachineState} {sourceCalls : List NativeCallFrame}
    {sourceEventIndex : Nat} {sourceEvents : List NativeExternalEvent}
    {sourceWorld : RelationalWorld}
    (result : CheckedNativeOperationStateRouteToStopWithinResult
      (blocks := blocks) stopRvas sourceBlock sourceState sourceCalls
      sourceEventIndex sourceEvents sourceWorld) :
    NonemptyRelatedPath candidate.transitionSystem result.route.before
      result.route.observations result.route.after :=
  result.route.path

#print axioms checkedNativeOperationStateRouteToStopWithin?
#print axioms CheckedNativeOperationStateRouteToStopWithinResult.path

end StageA.Relational.InterpreterKernelOperationBoundedStateRoute
