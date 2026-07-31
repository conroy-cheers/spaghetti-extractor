import StageA.RelationalInterpreterKernelOperationFrameChecker

namespace StageA.Relational.InterpreterKernelOperationRouteChecker

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationControlChecker
open StageA.Relational.InterpreterKernelOperationFrameChecker
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

/-!
# Finite checked local operation routes

A route is a nonempty finite chain of decoded local block connections. Its
call-frame prefix is transformed by the reflective frame checker at every
edge. The caller-owned frame tail is parametric and remains untouched.
-/

inductive CheckedNativeOperationLocalRoute
    (candidate : ExactNativeWorldProgram) :
    CheckedNativeOperationBlock candidate -> List NativeCallFrame ->
      CheckedNativeOperationBlock candidate -> List NativeCallFrame -> Type
  | last
      (connection : CheckedNativeOperationLocalConnection candidate)
      (frames nextFrames : List NativeCallFrame)
      (framesChecked :
        nativeOperationSuccessorCallFrames?
            connection.source.edge.control.successor frames =
          some nextFrames) :
      CheckedNativeOperationLocalRoute candidate
        connection.source.edge.block frames connection.target nextFrames
  | cons
      (connection : CheckedNativeOperationLocalConnection candidate)
      (frames nextFrames : List NativeCallFrame)
      (framesChecked :
        nativeOperationSuccessorCallFrames?
            connection.source.edge.control.successor frames =
          some nextFrames)
      (tail : CheckedNativeOperationLocalRoute candidate connection.target
        nextFrames finalBlock finalFrames) :
      CheckedNativeOperationLocalRoute candidate
        connection.source.edge.block frames finalBlock finalFrames

theorem CheckedNativeOperationLocalRoute.execute
    {candidate : ExactNativeWorldProgram}
    {startBlock : CheckedNativeOperationBlock candidate}
    {startFrames : List NativeCallFrame}
    {finalBlock : CheckedNativeOperationBlock candidate}
    {finalFrames : List NativeCallFrame}
    (route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
      finalBlock finalFrames)
    (state : MachineState) (callerTail : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds :
      (checkedNativeOperationBlockSourceInvariant startBlock).Holds state) :
    ∃ finalState observations,
      NonemptyRelatedPath candidate.transitionSystem
        (.running startBlock.entryRva startBlock.entrySlot state
          (startFrames ++ callerTail) eventIndex events world)
        observations
        (.running finalBlock.entryRva finalBlock.entrySlot finalState
          (finalFrames ++ callerTail) eventIndex events world) ∧
      (checkedNativeOperationBlockSourceInvariant finalBlock).Holds
        finalState := by
  induction route generalizing state with
  | last connection frames nextFrames framesChecked =>
      have followed :=
        CheckedNativeOperationLocalConnection.followFrames connection state
          frames nextFrames callerTail eventIndex events world sourceHolds
          framesChecked
      refine ⟨connection.source.edge.block.terminal.after
        (connection.source.edge.block.terminalState state),
        connection.source.edge.block.observations state
          (frames ++ callerTail) eventIndex events world, ?_, followed.2⟩
      have path := connection.source.edge.block.path state
        (frames ++ callerTail) eventIndex events world
      rw [followed.1] at path
      exact path
  | cons connection frames nextFrames framesChecked tail induction =>
      have followed :=
        CheckedNativeOperationLocalConnection.followFrames connection state
          frames nextFrames callerTail eventIndex events world sourceHolds
          framesChecked
      let middleState :=
        connection.source.edge.block.terminal.after
          (connection.source.edge.block.terminalState state)
      obtain ⟨finalState, tailObservations, tailPath, finalHolds⟩ :=
        induction middleState followed.2
      let firstObservations :=
        connection.source.edge.block.observations state
          (frames ++ callerTail) eventIndex events world
      have firstPath := connection.source.edge.block.path state
        (frames ++ callerTail) eventIndex events world
      rw [followed.1] at firstPath
      refine ⟨finalState, firstObservations ++ tailObservations, ?_,
        finalHolds⟩
      exact firstPath.trans tailPath

/-!
`execute` stops at the entry of the route's final block.  Boundary composition
needs the exact transition produced by that block as well.  The package below
retains only the final entry state and the checked prefix path; its terminal
state, terminal transition, observations, and postcondition facts are computed
from the checked block.
-/

structure CheckedNativeOperationLocalRouteFinalResult
    {candidate : ExactNativeWorldProgram}
    {startBlock : CheckedNativeOperationBlock candidate}
    {startFrames : List NativeCallFrame}
    {finalBlock : CheckedNativeOperationBlock candidate}
    {finalFrames : List NativeCallFrame}
    (route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
      finalBlock finalFrames)
    (state : MachineState) (callerTail : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) where
  finalState : MachineState
  prefixObservations : List WorldRelationalObservable
  prefixPath :
    NonemptyRelatedPath candidate.transitionSystem
      (.running startBlock.entryRva startBlock.entrySlot state
        (startFrames ++ callerTail) eventIndex events world)
      prefixObservations
      (.running finalBlock.entryRva finalBlock.entrySlot finalState
        (finalFrames ++ callerTail) eventIndex events world)
  finalSourceHolds :
    (checkedNativeOperationBlockSourceInvariant finalBlock).Holds finalState

def CheckedNativeOperationLocalRouteFinalResult.terminalState
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
      eventIndex events world) : MachineState :=
  finalBlock.terminalState result.finalState

def CheckedNativeOperationLocalRouteFinalResult.after
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
      eventIndex events world) : NativeWorldExecution :=
  finalBlock.after result.finalState (finalFrames ++ callerTail) eventIndex
    events world

def CheckedNativeOperationLocalRouteFinalResult.observations
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
      eventIndex events world) : List WorldRelationalObservable :=
  result.prefixObservations ++
    finalBlock.observations result.finalState (finalFrames ++ callerTail)
      eventIndex events world

theorem CheckedNativeOperationLocalRouteFinalResult.path
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
      eventIndex events world) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running startBlock.entryRva startBlock.entrySlot state
        (startFrames ++ callerTail) eventIndex events world)
      result.observations result.after := by
  exact result.prefixPath.trans
    (finalBlock.path result.finalState (finalFrames ++ callerTail) eventIndex
      events world)

theorem CheckedNativeOperationLocalRouteFinalResult.terminalSourceHolds
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
      eventIndex events world) :
    finalBlock.terminal.cutpoint.source.Holds result.terminalState := by
  exact finalBlock.terminalSourceHolds result.finalState
    (checkedNativeOperationBlockSourceInvariantHolds finalBlock
      result.finalState result.finalSourceHolds)

theorem CheckedNativeOperationLocalRouteFinalResult.terminalPostconditionHolds
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
      eventIndex events world) :
    finalBlock.terminal.cutpoint.target.Holds
      (finalBlock.terminal.after result.terminalState) := by
  exact finalBlock.terminalInvariantHolds result.finalState
    (checkedNativeOperationBlockSourceInvariantHolds finalBlock
      result.finalState result.finalSourceHolds)

theorem CheckedNativeOperationLocalRouteFinalResult.terminalTransitionExact
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
      eventIndex events world) :
    result.after =
      (finalBlock.expectedTerminalTransition result.finalState
        (finalFrames ++ callerTail) eventIndex events world).next := by
  exact finalBlock.afterExpected result.finalState (finalFrames ++ callerTail)
    eventIndex events world

noncomputable def CheckedNativeOperationLocalRoute.executeThroughFinal
    {candidate : ExactNativeWorldProgram}
    {startBlock : CheckedNativeOperationBlock candidate}
    {startFrames : List NativeCallFrame}
    {finalBlock : CheckedNativeOperationBlock candidate}
    {finalFrames : List NativeCallFrame}
    (route : CheckedNativeOperationLocalRoute candidate startBlock startFrames
      finalBlock finalFrames)
    (state : MachineState) (callerTail : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds :
      (checkedNativeOperationBlockSourceInvariant startBlock).Holds state) :
    CheckedNativeOperationLocalRouteFinalResult route state callerTail eventIndex
      events world := by
  induction route generalizing state with
  | last connection frames nextFrames framesChecked =>
      have followed :=
        CheckedNativeOperationLocalConnection.followFrames connection state
          frames nextFrames callerTail eventIndex events world sourceHolds
          framesChecked
      let finalState :=
        connection.source.edge.block.terminal.after
          (connection.source.edge.block.terminalState state)
      let observations :=
        connection.source.edge.block.observations state
          (frames ++ callerTail) eventIndex events world
      have path := connection.source.edge.block.path state
        (frames ++ callerTail) eventIndex events world
      rw [followed.1] at path
      exact {
        finalState
        prefixObservations := observations
        prefixPath := path
        finalSourceHolds := followed.2
      }
  | cons connection frames nextFrames framesChecked tail induction =>
      have followed :=
        CheckedNativeOperationLocalConnection.followFrames connection state
          frames nextFrames callerTail eventIndex events world sourceHolds
          framesChecked
      let middleState :=
        connection.source.edge.block.terminal.after
          (connection.source.edge.block.terminalState state)
      let tailResult := induction middleState followed.2
      let observations :=
        connection.source.edge.block.observations state
          (frames ++ callerTail) eventIndex events world
      have path := connection.source.edge.block.path state
        (frames ++ callerTail) eventIndex events world
      rw [followed.1] at path
      exact {
        finalState := tailResult.finalState
        prefixObservations := observations ++ tailResult.prefixObservations
        prefixPath := path.trans tailResult.prefixPath
        finalSourceHolds := tailResult.finalSourceHolds
      }

#print axioms CheckedNativeOperationLocalRoute.execute
#print axioms CheckedNativeOperationLocalRouteFinalResult.path
#print axioms CheckedNativeOperationLocalRouteFinalResult.terminalSourceHolds
#print axioms
  CheckedNativeOperationLocalRouteFinalResult.terminalPostconditionHolds
#print axioms
  CheckedNativeOperationLocalRouteFinalResult.terminalTransitionExact
#print axioms CheckedNativeOperationLocalRoute.executeThroughFinal

end StageA.Relational.InterpreterKernelOperationRouteChecker
