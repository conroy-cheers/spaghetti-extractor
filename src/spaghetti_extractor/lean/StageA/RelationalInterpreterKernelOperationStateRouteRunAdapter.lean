import StageA.RelationalInterpreterKernelOperationStateRouteChecker
import StageA.RelationalInterpreterKernelRun

namespace StageA.Relational.InterpreterKernelOperationStateRouteRunAdapter

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationStateRouteChecker
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterKernelRun
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact state-route adapter for Run chunks

The Run proof consumes exact finite candidate chunks.  Their length may depend
on compiler-generated branches and therefore must come from the checked route,
not from a hardcoded template count.  This adapter preserves that dependency:
the chunk fuel is definitionally `route.fuel`, and its computed result is
identified by the route's exact execution theorem.
-/

def runFunctionChunkOfStateRoute
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
    RunFunctionNativeChunk candidate route.before route.fuel := {
  positive := route.fuelPositive
}

theorem runFunctionChunkOfStateRoute_resultExact
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
    (runFunctionChunkOfStateRoute route).result =
      (route.after, route.observations) := by
  exact route.runExact

theorem runFunctionChunkOfStateRoute_afterExact
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
    (runFunctionChunkOfStateRoute route).after = route.after :=
  congrArg Prod.fst (runFunctionChunkOfStateRoute_resultExact route)

theorem runFunctionChunkOfStateRoute_observationsExact
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
    (runFunctionChunkOfStateRoute route).observations = route.observations :=
  congrArg Prod.snd (runFunctionChunkOfStateRoute_resultExact route)

def runFunctionChunkOfStateRoutePrefix
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
    (distinct : sourceBlock.entryRva ≠ finalBlock.entryRva) :
    RunFunctionNativeChunk candidate route.before route.prefixFuel := {
  positive := route.prefixFuelPositive_of_entryRva_ne distinct
}

theorem runFunctionChunkOfStateRoutePrefix_resultExact
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
    (distinct : sourceBlock.entryRva ≠ finalBlock.entryRva) :
    (runFunctionChunkOfStateRoutePrefix route distinct).result =
      (route.prefixAfter, route.prefixObservations) :=
  route.prefixRunExact

theorem runFunctionChunkOfStateRoutePrefix_afterExact
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
    (distinct : sourceBlock.entryRva ≠ finalBlock.entryRva) :
    (runFunctionChunkOfStateRoutePrefix route distinct).after =
      route.prefixAfter :=
  congrArg Prod.fst
    (runFunctionChunkOfStateRoutePrefix_resultExact route distinct)

theorem runFunctionChunkOfStateRoutePrefix_observationsExact
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
    (distinct : sourceBlock.entryRva ≠ finalBlock.entryRva) :
    (runFunctionChunkOfStateRoutePrefix route distinct).observations =
      route.prefixObservations :=
  congrArg Prod.snd
    (runFunctionChunkOfStateRoutePrefix_resultExact route distinct)

#print axioms runFunctionChunkOfStateRoute_resultExact
#print axioms runFunctionChunkOfStateRoute_afterExact
#print axioms runFunctionChunkOfStateRoute_observationsExact
#print axioms runFunctionChunkOfStateRoutePrefix_resultExact
#print axioms runFunctionChunkOfStateRoutePrefix_afterExact
#print axioms runFunctionChunkOfStateRoutePrefix_observationsExact

end StageA.Relational.InterpreterKernelOperationStateRouteRunAdapter
