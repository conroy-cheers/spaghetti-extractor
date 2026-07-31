import StageA.RelationalInterpreterKernelOperationGraphChecker

namespace StageA.Relational.InterpreterKernelOperationStateRouteChecker

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationControlChecker
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationGraphChecker
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

/-!
# State-indexed native-operation routes

The static route checker is useful when one invariant selects every branch in
advance.  Compiler-generated interpreters instead select branches from the
request and from intermediate semantic results.  This checker records those
choices only after the exact checked block has computed its successor.

Each interior edge is a `CheckedNativeOperationGraphSuccessor`, whose endpoint
is definitionally tied to `source.after`.  The certificate cannot submit a
replacement post-state or path.  Indirect and external outcomes are excluded
from an interior edge and must remain typed boundaries.
-/

def nativeOperationOutcomeLocallyComposable :
    NativeOperationOutcomePostcondition -> Bool
  | .returned _
  | .jumped _
  | .branched ..
  | .called ..
  | .bulkCopy ..
  | .bulkFill ..
  | .checkedContinue ..
  | .atomicCompareExchange .. => true
  | .running
  | .indirectCall ..
  | .indirectJump _
  | .externalCall ..
  | .externalJump .. => false

def nativeOperationOutcomeAlwaysRunningLocal :
    NativeOperationOutcomePostcondition -> Bool
  | .jumped _
  | .branched .. => true
  | .running
  | .returned _
  | .called ..
  | .bulkCopy ..
  | .bulkFill ..
  | .indirectCall ..
  | .indirectJump _
  | .externalCall ..
  | .externalJump ..
  | .atomicCompareExchange ..
  | .checkedContinue .. => false

theorem nativeOperationOutcomeAlwaysRunningLocal_locallyComposable
    (outcome : NativeOperationOutcomePostcondition)
    (checked : nativeOperationOutcomeAlwaysRunningLocal outcome = true) :
    nativeOperationOutcomeLocallyComposable outcome = true := by
  cases outcome <;> simp_all [nativeOperationOutcomeAlwaysRunningLocal,
    nativeOperationOutcomeLocallyComposable]

theorem nativeOperationOutcomeAlwaysRunningLocal_statePreserving
    (outcome : NativeOperationOutcomePostcondition)
    (checked : nativeOperationOutcomeAlwaysRunningLocal outcome = true) :
    nativeOperationOutcomeStatePreserving outcome = true := by
  cases outcome <;> simp_all [nativeOperationOutcomeAlwaysRunningLocal,
    nativeOperationOutcomeStatePreserving]

theorem checkedNativeOperationGraphSuccessor_contextPreserved
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {source : CheckedNativeOperationBlock candidate}
    {state : MachineState} {calls : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    (successor : CheckedNativeOperationGraphSuccessor blocks source state calls
      eventIndex events world)
    (localChecked :
      nativeOperationOutcomeAlwaysRunningLocal
        source.terminal.cutpoint.postcondition.outcome = true) :
    successor.targetCalls = calls ∧
      successor.targetEventIndex = eventIndex ∧
      successor.targetEvents = events ∧
      successor.targetWorld = world ∧
      source.observations state calls eventIndex events world = [] := by
  have afterExact := successor.afterExact
  rw [source.afterExpected] at afterExact
  rw [source.observationsExpected]
  cases outcomeExact :
      source.terminal.cutpoint.postcondition.outcome <;>
    simp_all [nativeOperationOutcomeAlwaysRunningLocal,
      CheckedNativeOperationBlock.expectedTerminalTransition,
      NativeOperationOutcomePostcondition.expected,
      transitionFromNativeWorldOutcome, evalNativeOperationOutcomeExpr]

/-- A finite route whose branch choices are indexed by the concrete state at
each checked block.  The final block is retained but not executed by the
inductive prefix; `path` below executes it exactly once, so every route is
nonempty, including `final`. -/
inductive CheckedNativeOperationStateRoute
    (candidate : ExactNativeWorldProgram)
    (blocks : List (CheckedNativeOperationBlock candidate)) :
    (sourceBlock : CheckedNativeOperationBlock candidate) ->
      (sourceState : MachineState) ->
      (sourceCalls : List NativeCallFrame) ->
      (sourceEventIndex : Nat) ->
      (sourceEvents : List NativeExternalEvent) ->
      (sourceWorld : RelationalWorld) ->
      (finalBlock : CheckedNativeOperationBlock candidate) ->
      (finalState : MachineState) ->
      (finalCalls : List NativeCallFrame) ->
      (finalEventIndex : Nat) ->
      (finalEvents : List NativeExternalEvent) ->
      (finalWorld : RelationalWorld) -> Type
  | final
      (block : CheckedNativeOperationBlock candidate)
      (state : MachineState) (calls : List NativeCallFrame)
      (eventIndex : Nat) (events : List NativeExternalEvent)
      (world : RelationalWorld)
      (member : block ∈ blocks)
      (sourceHolds :
        (checkedNativeOperationBlockSourceInvariant block).Holds state) :
      CheckedNativeOperationStateRoute candidate blocks block state calls
        eventIndex events world block state calls eventIndex events world
  | step
      (source : CheckedNativeOperationBlock candidate)
      (state : MachineState) (calls : List NativeCallFrame)
      (eventIndex : Nat) (events : List NativeExternalEvent)
      (world : RelationalWorld)
      (sourceMember : source ∈ blocks)
      (sourceHolds :
        (checkedNativeOperationBlockSourceInvariant source).Holds state)
      (alwaysRunningLocal :
        nativeOperationOutcomeAlwaysRunningLocal
          source.terminal.cutpoint.postcondition.outcome = true)
      (successor : CheckedNativeOperationGraphSuccessor blocks source state
        calls eventIndex events world)
      (tail : CheckedNativeOperationStateRoute candidate blocks
        successor.target successor.targetState successor.targetCalls
        successor.targetEventIndex successor.targetEvents successor.targetWorld
        finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld) :
      CheckedNativeOperationStateRoute candidate blocks source state calls
        eventIndex events world finalBlock finalState finalCalls finalEventIndex
        finalEvents finalWorld

def CheckedNativeOperationStateRoute.before
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (_route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld) :
    NativeWorldExecution :=
  .running sourceBlock.entryRva sourceBlock.entrySlot sourceState sourceCalls
    sourceEventIndex sourceEvents sourceWorld

def CheckedNativeOperationStateRoute.after
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (_route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld) :
    NativeWorldExecution :=
  finalBlock.after finalState finalCalls finalEventIndex finalEvents finalWorld

/-! The prefix view executes every interior block but stops immediately before
the final block.  It is permitted to have zero fuel when the source is already
the final cutpoint.  Boundary adapters use this view to expose call, return, and
external-event cutpoints without executing them prematurely. -/

def CheckedNativeOperationStateRoute.prefixAfter
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceState finalState : MachineState}
    {sourceCalls finalCalls : List NativeCallFrame}
    {sourceEventIndex finalEventIndex : Nat}
    {sourceEvents finalEvents : List NativeExternalEvent}
    {sourceWorld finalWorld : RelationalWorld}
    (_route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
      finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld) :
    NativeWorldExecution :=
  .running finalBlock.entryRva finalBlock.entrySlot finalState finalCalls
    finalEventIndex finalEvents finalWorld

def CheckedNativeOperationStateRoute.prefixObservations
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
    List WorldRelationalObservable :=
  match route with
  | .final .. => []
  | .step source state calls eventIndex events world _ _ _ _ tail =>
      source.observations state calls eventIndex events world ++
        tail.prefixObservations

def CheckedNativeOperationStateRoute.prefixFuel
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
    Nat :=
  match route with
  | .final .. => 0
  | .step source _ _ _ _ _ _ _ _ _ tail =>
      source.fuel + tail.prefixFuel

def CheckedNativeOperationStateRoute.observations
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
    List WorldRelationalObservable :=
  match route with
  | .final block state calls eventIndex events world .. =>
      block.observations state calls eventIndex events world
  | .step source state calls eventIndex events world _ _ _ _ tail =>
      source.observations state calls eventIndex events world ++
        tail.observations

def CheckedNativeOperationStateRoute.fuel
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
    Nat :=
  match route with
  | .final block .. => block.fuel
  | .step source _ _ _ _ _ _ _ _ _ tail =>
      source.fuel + tail.fuel

theorem CheckedNativeOperationStateRoute.fuelPositive
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
    0 < route.fuel := by
  induction route with
  | final block state calls eventIndex events world member sourceHolds =>
      cases runningExact : block.running <;>
        simp [CheckedNativeOperationStateRoute.fuel,
          CheckedNativeOperationBlock.fuel, runningExact]
  | step source state calls eventIndex events world sourceMember sourceHolds
      alwaysRunningLocal successor tail induction =>
      exact Nat.add_pos_right source.fuel induction

theorem CheckedNativeOperationStateRoute.runExact
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
    runRelatedSteps candidate.transitionSystem route.fuel route.before =
      (route.after, route.observations) := by
  induction route with
  | final block state calls eventIndex events world member sourceHolds =>
      exact block.runExact state calls eventIndex events world
  | step source state calls eventIndex events world sourceMember sourceHolds
      alwaysRunningLocal successor tail induction =>
      rw [show
        CheckedNativeOperationStateRoute.fuel
            (.step source state calls eventIndex events world sourceMember
              sourceHolds alwaysRunningLocal successor tail) =
          source.fuel + tail.fuel by rfl]
      rw [runRelatedSteps_add]
      simp only [CheckedNativeOperationStateRoute.before,
        CheckedNativeOperationStateRoute.after,
        CheckedNativeOperationStateRoute.observations]
      rw [source.runExact state calls eventIndex events world]
      rw [successor.afterExact]
      have tailExact :
          runRelatedSteps candidate.transitionSystem tail.fuel
              (NativeWorldExecution.running successor.target.entryRva
                successor.target.entrySlot successor.targetState
                successor.targetCalls successor.targetEventIndex
                successor.targetEvents successor.targetWorld) =
            (tail.after, tail.observations) := by
        simpa only [CheckedNativeOperationStateRoute.before] using induction
      rw [tailExact]
      rfl

theorem CheckedNativeOperationStateRoute.prefixRunExact
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
    runRelatedSteps candidate.transitionSystem route.prefixFuel route.before =
      (route.prefixAfter, route.prefixObservations) := by
  induction route with
  | final block state calls eventIndex events world member sourceHolds =>
      simp [CheckedNativeOperationStateRoute.prefixFuel,
        CheckedNativeOperationStateRoute.before,
        CheckedNativeOperationStateRoute.prefixAfter,
        CheckedNativeOperationStateRoute.prefixObservations, runRelatedSteps]
  | step source state calls eventIndex events world sourceMember sourceHolds
      alwaysRunningLocal successor tail induction =>
      rw [show
        CheckedNativeOperationStateRoute.prefixFuel
            (.step source state calls eventIndex events world sourceMember
              sourceHolds alwaysRunningLocal successor tail) =
          source.fuel + tail.prefixFuel by rfl]
      rw [runRelatedSteps_add]
      simp only [CheckedNativeOperationStateRoute.before,
        CheckedNativeOperationStateRoute.prefixAfter,
        CheckedNativeOperationStateRoute.prefixObservations]
      rw [source.runExact state calls eventIndex events world]
      rw [successor.afterExact]
      have tailExact :
          runRelatedSteps candidate.transitionSystem tail.prefixFuel
              (NativeWorldExecution.running successor.target.entryRva
                successor.target.entrySlot successor.targetState
                successor.targetCalls successor.targetEventIndex
                successor.targetEvents successor.targetWorld) =
            (tail.prefixAfter, tail.prefixObservations) := by
        simpa only [CheckedNativeOperationStateRoute.before] using induction
      rw [tailExact]
      rfl

theorem CheckedNativeOperationStateRoute.prefixFuelPositive_of_entryRva_ne
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
    0 < route.prefixFuel := by
  cases route with
  | final block state calls eventIndex events world member sourceHolds =>
      exact False.elim (distinct rfl)
  | step source state calls eventIndex events world sourceMember sourceHolds
      alwaysRunningLocal successor tail =>
      have sourcePositive : 0 < sourceBlock.fuel := by
        cases runningExact : sourceBlock.running <;>
          simp [CheckedNativeOperationBlock.fuel, runningExact]
      exact Nat.add_pos_left sourcePositive tail.prefixFuel

theorem CheckedNativeOperationStateRoute.prefixContextPreserved
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
    finalCalls = sourceCalls ∧
      finalEventIndex = sourceEventIndex ∧
      finalEvents = sourceEvents ∧
      finalWorld = sourceWorld ∧
      route.prefixObservations = [] := by
  induction route with
  | final block state calls eventIndex events world member sourceHolds =>
      simp [CheckedNativeOperationStateRoute.prefixObservations]
  | step source state calls eventIndex events world sourceMember sourceHolds
      alwaysRunningLocal successor tail induction =>
      have preserved :=
        checkedNativeOperationGraphSuccessor_contextPreserved successor
          alwaysRunningLocal
      refine ⟨induction.1.trans preserved.1, ?_⟩
      refine ⟨induction.2.1.trans preserved.2.1, ?_⟩
      refine ⟨induction.2.2.1.trans preserved.2.2.1, ?_⟩
      refine ⟨induction.2.2.2.1.trans preserved.2.2.2.1, ?_⟩
      simp [CheckedNativeOperationStateRoute.prefixObservations, preserved.2.2.2.2,
        induction.2.2.2.2]

theorem CheckedNativeOperationStateRoute.finalSourceHolds
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
    (checkedNativeOperationBlockSourceInvariant finalBlock).Holds finalState := by
  induction route with
  | final block state calls eventIndex events world member sourceHolds =>
      exact sourceHolds
  | step source state calls eventIndex events world sourceMember sourceHolds
      alwaysRunningLocal successor tail induction =>
      exact induction

theorem CheckedNativeOperationStateRoute.path
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
    NonemptyRelatedPath candidate.transitionSystem route.before
      route.observations route.after := by
  induction route with
  | final block state calls eventIndex events world member sourceHolds =>
      exact block.path state calls eventIndex events world
  | step source state calls eventIndex events world sourceMember sourceHolds
      alwaysRunningLocal successor tail induction =>
      exact successor.path.trans induction

#print axioms CheckedNativeOperationStateRoute.finalSourceHolds
#print axioms nativeOperationOutcomeAlwaysRunningLocal_statePreserving
#print axioms CheckedNativeOperationStateRoute.fuelPositive
#print axioms CheckedNativeOperationStateRoute.runExact
#print axioms CheckedNativeOperationStateRoute.prefixRunExact
#print axioms CheckedNativeOperationStateRoute.prefixFuelPositive_of_entryRva_ne
#print axioms CheckedNativeOperationStateRoute.prefixContextPreserved
#print axioms CheckedNativeOperationStateRoute.path

end StageA.Relational.InterpreterKernelOperationStateRouteChecker
