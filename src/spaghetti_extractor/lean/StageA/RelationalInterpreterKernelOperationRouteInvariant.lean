import StageA.RelationalInterpreterKernelOperationRankedStateRoute

namespace StageA.Relational.InterpreterKernelOperationRouteInvariant

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationGraphChecker
open StageA.Relational.InterpreterKernelOperationRankedStateRoute
open StageA.Relational.InterpreterKernelOperationStateRouteChecker
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

/-!
# Invariants over checked state-indexed routes

Rank certificates establish termination at a typed cutpoint, but deliberately
do not choose branches.  Request and loop facts must therefore travel through
the exact successor selected by each decoded block.  This module supplies the
generic induction principle used by generated ABI, call-frame, and semantic
postconditions.

The invariant ranges over the complete native execution context.  This keeps
the interface usable for stack frames, external-event prefixes, and relational
worlds even though ordinary local edges preserve those fields.
-/

structure CheckedNativeOperationRouteInvariant
    (candidate : ExactNativeWorldProgram)
    (blocks : List (CheckedNativeOperationBlock candidate)) where
  Holds : CheckedNativeOperationBlock candidate -> MachineState ->
    List NativeCallFrame -> Nat -> List NativeExternalEvent ->
    RelationalWorld -> Prop
  preserved :
    ∀ source state calls eventIndex events world
      (successor : CheckedNativeOperationGraphSuccessor blocks source state
        calls eventIndex events world),
      Holds source state calls eventIndex events world ->
      Holds successor.target successor.targetState successor.targetCalls
        successor.targetEventIndex successor.targetEvents successor.targetWorld

theorem CheckedNativeOperationStateRoute.invariantPreserved
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    (invariant : CheckedNativeOperationRouteInvariant candidate blocks)
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld)
    (sourceHolds : invariant.Holds sourceBlock sourceState sourceCalls
      sourceEventIndex sourceEvents sourceWorld) :
    invariant.Holds finalBlock finalState finalCalls finalEventIndex finalEvents
      finalWorld := by
  induction route with
  | final => exact sourceHolds
  | step source state calls eventIndex events world _ _ _ successor tail ih =>
      exact ih (invariant.preserved source state calls eventIndex events world
        successor sourceHolds)

/-- A proposition checked at every reachable stop under one route invariant.
The proposition may classify an endpoint RVA, establish a call-boundary ABI,
or expose a finite disjunction for a later typed boundary checker. -/
structure CheckedNativeOperationStopPostcondition
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    (policy : CheckedNativeOperationRankedRoutePolicy candidate blocks)
    (invariant : CheckedNativeOperationRouteInvariant candidate blocks) where
  Holds : CheckedNativeOperationBlock candidate -> MachineState ->
    List NativeCallFrame -> Nat -> List NativeExternalEvent ->
    RelationalWorld -> Prop
  atStop :
    ∀ block state calls eventIndex events world,
      invariant.Holds block state calls eventIndex events world ->
      policy.stop block.entryRva = true ->
      Holds block state calls eventIndex events world

theorem CheckedNativeOperationStateRouteToStop.postcondition
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {policy : CheckedNativeOperationRankedRoutePolicy candidate blocks}
    (invariant : CheckedNativeOperationRouteInvariant candidate blocks)
    (postcondition :
      CheckedNativeOperationStopPostcondition policy invariant)
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceState : MachineState} {sourceCalls : List NativeCallFrame}
    {sourceEventIndex : Nat} {sourceEvents : List NativeExternalEvent}
    {sourceWorld : RelationalWorld}
    (result : CheckedNativeOperationStateRouteToStop policy sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld)
    (sourceHolds : invariant.Holds sourceBlock sourceState sourceCalls
      sourceEventIndex sourceEvents sourceWorld) :
    postcondition.Holds result.finalBlock result.finalState result.finalCalls
      result.finalEventIndex result.finalEvents result.finalWorld :=
  postcondition.atStop result.finalBlock result.finalState result.finalCalls
    result.finalEventIndex result.finalEvents result.finalWorld
    (CheckedNativeOperationStateRoute.invariantPreserved invariant result.route
      sourceHolds) result.stopped

/-- Common endpoint specialization.  It is still proved from the checked
invariant at every stop; the expected RVA is not accepted as a route result. -/
def checkedNativeOperationStopAtRva
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    (policy : CheckedNativeOperationRankedRoutePolicy candidate blocks)
    (invariant : CheckedNativeOperationRouteInvariant candidate blocks)
    (expectedRva : Nat)
    (checked :
      ∀ block state calls eventIndex events world,
        invariant.Holds block state calls eventIndex events world ->
        policy.stop block.entryRva = true ->
        block.entryRva = expectedRva) :
    CheckedNativeOperationStopPostcondition policy invariant := {
  Holds := fun block _ _ _ _ _ => block.entryRva = expectedRva
  atStop := checked
}

theorem CheckedNativeOperationStateRouteToStop.finalRvaExact
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {policy : CheckedNativeOperationRankedRoutePolicy candidate blocks}
    (invariant : CheckedNativeOperationRouteInvariant candidate blocks)
    (expectedRva : Nat)
    (checked :
      ∀ block state calls eventIndex events world,
        invariant.Holds block state calls eventIndex events world ->
        policy.stop block.entryRva = true ->
        block.entryRva = expectedRva)
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceState : MachineState} {sourceCalls : List NativeCallFrame}
    {sourceEventIndex : Nat} {sourceEvents : List NativeExternalEvent}
    {sourceWorld : RelationalWorld}
    (result : CheckedNativeOperationStateRouteToStop policy sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld)
    (sourceHolds : invariant.Holds sourceBlock sourceState sourceCalls
      sourceEventIndex sourceEvents sourceWorld) :
    result.finalBlock.entryRva = expectedRva :=
  CheckedNativeOperationStateRouteToStop.postcondition invariant
    (checkedNativeOperationStopAtRva policy invariant expectedRva checked)
    result sourceHolds

#print axioms CheckedNativeOperationStateRoute.invariantPreserved
#print axioms CheckedNativeOperationStateRouteToStop.postcondition
#print axioms checkedNativeOperationStopAtRva
#print axioms CheckedNativeOperationStateRouteToStop.finalRvaExact

end StageA.Relational.InterpreterKernelOperationRouteInvariant
