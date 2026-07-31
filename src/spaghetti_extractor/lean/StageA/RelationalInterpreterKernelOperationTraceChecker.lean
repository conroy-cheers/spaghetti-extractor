import StageA.RelationalInterpreterKernelOperationCutpointChecker

namespace StageA.Relational.InterpreterKernelOperationTraceChecker

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationReplay
open StageA.Relational.InterpreterNativeWorld

/-! Finite exact running traces assembled without endpoint submissions. -/

structure CheckedNativeOperationRunningEdge
    (candidate : ExactNativeWorldProgram) where
  instruction : KernelInstruction
  undefinedSlot : Nat
  replay : CheckedNativeOperationRunningInstruction candidate instruction
    undefinedSlot
  cutpoint : CheckedNativeOperationRunningCutpoint replay

def CheckedNativeOperationRunningEdge.entryRva
    (edge : CheckedNativeOperationRunningEdge candidate) : Nat :=
  edge.instruction.rva

def CheckedNativeOperationRunningEdge.nextRva
    (edge : CheckedNativeOperationRunningEdge candidate) : Nat :=
  edge.instruction.rva + edge.replay.decoded.size

def CheckedNativeOperationRunningEdge.nextSlot
    (edge : CheckedNativeOperationRunningEdge candidate) : Nat :=
  edge.undefinedSlot + 1

def CheckedNativeOperationRunningEdge.after
    (edge : CheckedNativeOperationRunningEdge candidate)
    (state : MachineState) : MachineState :=
  concreteBehaviorNextMachineState (edge.replay.behavior.eval state) state

def checkedNativeOperationRunningTrace :
    List (CheckedNativeOperationRunningEdge candidate) -> Bool
  | [] | [_] => true
  | first :: second :: tail =>
      first.nextRva == second.entryRva &&
        first.nextSlot == second.undefinedSlot &&
        first.cutpoint.target == second.cutpoint.source &&
        checkedNativeOperationRunningTrace (second :: tail)

def runCheckedNativeOperationRunningTrace :
    List (CheckedNativeOperationRunningEdge candidate) ->
      MachineState -> MachineState
  | [], state => state
  | edge :: tail, state =>
      runCheckedNativeOperationRunningTrace tail (edge.after state)

def checkedNativeOperationRunningTraceFinalRva :
    List (CheckedNativeOperationRunningEdge candidate) -> Nat
  | [] => 0
  | [edge] => edge.nextRva
  | _ :: second :: tail =>
      checkedNativeOperationRunningTraceFinalRva (second :: tail)

def checkedNativeOperationRunningTraceFinalSlot :
    List (CheckedNativeOperationRunningEdge candidate) -> Nat
  | [] => 0
  | [edge] => edge.nextSlot
  | _ :: second :: tail =>
      checkedNativeOperationRunningTraceFinalSlot (second :: tail)

structure CheckedNativeOperationRunningTrace
    (candidate : ExactNativeWorldProgram) where
  first : CheckedNativeOperationRunningEdge candidate
  tail : List (CheckedNativeOperationRunningEdge candidate)
  checked : checkedNativeOperationRunningTrace (first :: tail) = true

def CheckedNativeOperationRunningTrace.edges
    (trace : CheckedNativeOperationRunningTrace candidate) :
    List (CheckedNativeOperationRunningEdge candidate) :=
  trace.first :: trace.tail

def CheckedNativeOperationRunningTrace.after
    (trace : CheckedNativeOperationRunningTrace candidate)
    (state : MachineState) : MachineState :=
  runCheckedNativeOperationRunningTrace trace.edges state

def CheckedNativeOperationRunningTrace.finalRva
    (trace : CheckedNativeOperationRunningTrace candidate) : Nat :=
  checkedNativeOperationRunningTraceFinalRva trace.edges

def CheckedNativeOperationRunningTrace.finalSlot
    (trace : CheckedNativeOperationRunningTrace candidate) : Nat :=
  checkedNativeOperationRunningTraceFinalSlot trace.edges

private theorem runningTraceExact
    (candidate : ExactNativeWorldProgram) :
    ∀ (edges : List (CheckedNativeOperationRunningEdge candidate)),
      checkedNativeOperationRunningTrace edges = true ->
      ∀ first rest,
        edges = first :: rest ->
        ∀ state calls eventIndex events world,
          runRelatedSteps candidate.transitionSystem edges.length
              (.running first.entryRva first.undefinedSlot state calls
                eventIndex events world) =
            (.running (checkedNativeOperationRunningTraceFinalRva edges)
              (checkedNativeOperationRunningTraceFinalSlot edges)
              (runCheckedNativeOperationRunningTrace edges state)
              calls eventIndex events world, []) := by
  intro edges
  induction edges with
  | nil =>
      intro _ first rest impossible
      contradiction
  | cons edge tail induction =>
      intro checked first rest exact
      injection exact with firstExact restExact
      subst first
      subst rest
      cases tail with
      | nil =>
          simp [runRelatedSteps,
            CheckedNativeOperationRunningEdge.entryRva,
            CheckedNativeOperationRunningEdge.after,
            CheckedNativeOperationRunningEdge.nextRva,
            CheckedNativeOperationRunningEdge.nextSlot,
            runCheckedNativeOperationRunningTrace,
            checkedNativeOperationRunningTraceFinalRva,
            checkedNativeOperationRunningTraceFinalSlot,
            edge.replay.worldStepExact]
      | cons next remaining =>
          simp only [checkedNativeOperationRunningTrace,
            Bool.and_eq_true, beq_iff_eq] at checked
          rcases checked with
            ⟨⟨⟨nextRvaExact, nextSlotExact⟩, invariantExact⟩,
              tailChecked⟩
          intro state calls eventIndex events world
          rw [show (edge :: next :: remaining).length =
            1 + (next :: remaining).length by simp [Nat.add_comm]]
          have firstRun :
              runRelatedSteps candidate.transitionSystem 1
                  (.running edge.entryRva edge.undefinedSlot state calls
                    eventIndex events world) =
                (.running edge.nextRva edge.nextSlot (edge.after state) calls
                  eventIndex events world, []) := by
            simp [runRelatedSteps,
              CheckedNativeOperationRunningEdge.entryRva,
              CheckedNativeOperationRunningEdge.nextRva,
              CheckedNativeOperationRunningEdge.nextSlot,
              CheckedNativeOperationRunningEdge.after,
              edge.replay.worldStepExact]
          rw [runRelatedSteps_add]
          rw [firstRun]
          dsimp
          have tailExact := induction tailChecked next remaining rfl
            (edge.after state) calls eventIndex events world
          rw [nextRvaExact, nextSlotExact]
          rw [Prod.eta]
          have tailExact' :
              runRelatedSteps candidate.transitionSystem
                  (remaining.length + 1)
                  (.running next.entryRva next.undefinedSlot
                    (edge.after state) calls eventIndex events world) =
                (.running
                  (checkedNativeOperationRunningTraceFinalRva
                    (next :: remaining))
                  (checkedNativeOperationRunningTraceFinalSlot
                    (next :: remaining))
                  (runCheckedNativeOperationRunningTrace (next :: remaining)
                    (edge.after state))
                  calls eventIndex events world, []) := by
            simpa using tailExact
          rw [tailExact']
          rfl

theorem CheckedNativeOperationRunningTrace.runExact
    (trace : CheckedNativeOperationRunningTrace candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    runRelatedSteps candidate.transitionSystem trace.edges.length
        (.running trace.first.entryRva trace.first.undefinedSlot state calls
          eventIndex events world) =
      (.running trace.finalRva trace.finalSlot (trace.after state) calls
        eventIndex events world, []) :=
  runningTraceExact candidate trace.edges trace.checked trace.first trace.tail
    rfl state calls eventIndex events world

private theorem runningTraceInvariant
    (candidate : ExactNativeWorldProgram) :
    ∀ (edges : List (CheckedNativeOperationRunningEdge candidate)),
      checkedNativeOperationRunningTrace edges = true ->
      ∀ first rest,
        edges = first :: rest ->
        ∀ state,
          first.cutpoint.source.Holds state ->
          match edges.getLast? with
          | none => False
          | some last =>
              last.cutpoint.target.Holds
                (runCheckedNativeOperationRunningTrace edges state) := by
  intro edges
  induction edges with
  | nil =>
      intro _ first rest impossible
      contradiction
  | cons edge tail induction =>
      intro checked first rest exact
      injection exact with firstExact restExact
      subst first
      subst rest
      cases tail with
      | nil =>
          intro state sourceHolds
          simpa using edge.cutpoint.replayTargetHolds state sourceHolds
      | cons next remaining =>
          simp only [checkedNativeOperationRunningTrace,
            Bool.and_eq_true, beq_iff_eq] at checked
          rcases checked with
            ⟨⟨⟨_nextRvaExact, _nextSlotExact⟩, invariantExact⟩,
              tailChecked⟩
          intro state sourceHolds
          have nextHolds := edge.cutpoint.replayTargetHolds state sourceHolds
          rw [invariantExact] at nextHolds
          exact induction tailChecked next remaining rfl
            (edge.after state) nextHolds

theorem CheckedNativeOperationRunningTrace.invariantHolds
    (trace : CheckedNativeOperationRunningTrace candidate)
    (state : MachineState)
    (sourceHolds : trace.first.cutpoint.source.Holds state) :
    match trace.edges.getLast? with
    | none => False
    | some last => last.cutpoint.target.Holds (trace.after state) :=
  runningTraceInvariant candidate trace.edges trace.checked trace.first
    trace.tail rfl state sourceHolds

structure CheckedNativeOperationStoppedEdge
    (candidate : ExactNativeWorldProgram) where
  instruction : KernelInstruction
  undefinedSlot : Nat
  replay : CheckedNativeOperationStoppedInstruction candidate instruction
    undefinedSlot
  cutpoint : CheckedNativeOperationStoppedCutpoint replay

def CheckedNativeOperationStoppedEdge.entryRva
    (edge : CheckedNativeOperationStoppedEdge candidate) : Nat :=
  edge.instruction.rva

def CheckedNativeOperationStoppedEdge.after
    (edge : CheckedNativeOperationStoppedEdge candidate)
    (state : MachineState) : MachineState :=
  concreteBehaviorNextMachineState (edge.replay.behavior.eval state) state

def CheckedNativeOperationRunningTrace.finalTarget
    (trace : CheckedNativeOperationRunningTrace candidate) :
    NativeOperationInvariant :=
  (trace.edges.getLast?.map (fun edge => edge.cutpoint.target)).getD
    trace.first.cutpoint.target

theorem CheckedNativeOperationRunningTrace.finalTargetHolds
    (trace : CheckedNativeOperationRunningTrace candidate)
    (state : MachineState)
    (sourceHolds : trace.first.cutpoint.source.Holds state) :
    trace.finalTarget.Holds (trace.after state) := by
  have invariant := trace.invariantHolds state sourceHolds
  unfold CheckedNativeOperationRunningTrace.finalTarget
  cases lastExact : trace.edges.getLast? with
  | none =>
      simp [lastExact] at invariant
  | some last =>
      simpa [lastExact] using invariant

def checkedNativeOperationBlock
    (running : Option (CheckedNativeOperationRunningTrace candidate))
    (terminal : CheckedNativeOperationStoppedEdge candidate) : Bool :=
  match running with
  | none => true
  | some running =>
      running.finalRva == terminal.entryRva &&
        running.finalSlot == terminal.undefinedSlot &&
        running.finalTarget == terminal.cutpoint.source

structure CheckedNativeOperationBlock
    (candidate : ExactNativeWorldProgram) where
  running : Option (CheckedNativeOperationRunningTrace candidate)
  terminal : CheckedNativeOperationStoppedEdge candidate
  checked : checkedNativeOperationBlock running terminal = true

def CheckedNativeOperationBlock.entryRva
    (block : CheckedNativeOperationBlock candidate) : Nat :=
  block.running.map (fun trace => trace.first.entryRva) |>.getD
    block.terminal.entryRva

def CheckedNativeOperationBlock.entrySlot
    (block : CheckedNativeOperationBlock candidate) : Nat :=
  block.running.map (fun trace => trace.first.undefinedSlot) |>.getD
    block.terminal.undefinedSlot

def CheckedNativeOperationBlock.terminalState
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) : MachineState :=
  block.running.map (fun trace => trace.after state) |>.getD state

def CheckedNativeOperationBlock.beforeTerminal
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) : NativeWorldExecution :=
  .running block.terminal.entryRva block.terminal.undefinedSlot
    (block.terminalState state) calls eventIndex events world

def CheckedNativeOperationBlock.after
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) : NativeWorldExecution :=
  (candidate.transitionSystem.step
    (block.beforeTerminal state calls eventIndex events world)).next

def CheckedNativeOperationBlock.observations
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) : List WorldRelationalObservable :=
  (candidate.transitionSystem.step
    (block.beforeTerminal state calls eventIndex events world)).observation.toList

def CheckedNativeOperationBlock.fuel
    (block : CheckedNativeOperationBlock candidate) : Nat :=
  match block.running with
  | none => 1
  | some trace => trace.edges.length + 1

theorem CheckedNativeOperationBlock.runExact
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    runRelatedSteps candidate.transitionSystem block.fuel
        (.running block.entryRva block.entrySlot state calls eventIndex events
          world) =
      (block.after state calls eventIndex events world,
        block.observations state calls eventIndex events world) := by
  cases runningExact : block.running with
  | none =>
      have terminalStateExact : block.terminalState state = state := by
        simp [CheckedNativeOperationBlock.terminalState, runningExact]
      simp [CheckedNativeOperationBlock.fuel,
        CheckedNativeOperationBlock.entryRva,
        CheckedNativeOperationBlock.entrySlot,
        CheckedNativeOperationBlock.beforeTerminal,
        CheckedNativeOperationBlock.after,
        CheckedNativeOperationBlock.observations, runningExact,
        terminalStateExact, runRelatedSteps]
  | some running =>
      have checked := block.checked
      simp only [checkedNativeOperationBlock, runningExact,
        Bool.and_eq_true, beq_iff_eq] at checked
      rcases checked with
        ⟨⟨finalRvaExact, finalSlotExact⟩, invariantExact⟩
      have entryRvaExact : block.entryRva = running.first.entryRva := by
        simp [CheckedNativeOperationBlock.entryRva, runningExact]
      have entrySlotExact :
          block.entrySlot = running.first.undefinedSlot := by
        simp [CheckedNativeOperationBlock.entrySlot, runningExact]
      have terminalStateExact :
          block.terminalState state = running.after state := by
        simp [CheckedNativeOperationBlock.terminalState, runningExact]
      have fuelExact : block.fuel = running.edges.length + 1 := by
        simp [CheckedNativeOperationBlock.fuel, runningExact]
      rw [fuelExact, entryRvaExact, entrySlotExact]
      rw [runRelatedSteps_add]
      rw [running.runExact state calls eventIndex events world]
      dsimp
      rw [finalRvaExact, finalSlotExact]
      simp [runRelatedSteps, CheckedNativeOperationBlock.entryRva,
        CheckedNativeOperationBlock.entrySlot,
        CheckedNativeOperationBlock.beforeTerminal,
        CheckedNativeOperationBlock.after,
        CheckedNativeOperationBlock.observations,
        terminalStateExact]

theorem CheckedNativeOperationBlock.path
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running block.entryRva block.entrySlot state calls eventIndex events
        world)
      (block.observations state calls eventIndex events world)
      (block.after state calls eventIndex events world) := by
  refine ⟨block.fuel, ?_, block.runExact state calls eventIndex events world⟩
  cases runningExact : block.running <;>
    simp [CheckedNativeOperationBlock.fuel, runningExact]

def CheckedNativeOperationBlock.toCheckedPath
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    CheckedNativeOperationPath candidate
      (.running block.entryRva block.entrySlot state calls eventIndex events
        world) := {
  fuel := block.fuel
  positive := by
    cases runningExact : block.running <;>
      simp [CheckedNativeOperationBlock.fuel, runningExact]
}

theorem CheckedNativeOperationBlock.toCheckedPath_after
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    (block.toCheckedPath state calls eventIndex events world).after =
      block.after state calls eventIndex events world :=
  congrArg Prod.fst (block.runExact state calls eventIndex events world)

theorem CheckedNativeOperationBlock.toCheckedPath_observations
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    (block.toCheckedPath state calls eventIndex events world).observations =
      block.observations state calls eventIndex events world :=
  congrArg Prod.snd (block.runExact state calls eventIndex events world)

theorem CheckedNativeOperationBlock.terminalWorldStepExpected
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    candidate.transitionSystem.step
        (block.beforeTerminal state calls eventIndex events world) =
      transitionFromNativeWorldOutcome candidate.pe candidate.environment
        candidate.callableExternal candidate.indirectTargets
        block.terminal.instruction.rva
        (concreteBehaviorNextMachineState
          (block.terminal.replay.behavior.eval (block.terminalState state))
          (block.terminalState state))
        calls eventIndex events world
        ((block.terminal.cutpoint.postcondition.outcome.expected.map
          (evalNativeOperationOutcomeExpr
            (block.terminalState state))).getD (.jump 0)) := by
  simpa [CheckedNativeOperationBlock.beforeTerminal,
    CheckedNativeOperationStoppedEdge.entryRva] using
    block.terminal.cutpoint.worldStepExpected (block.terminalState state) calls
      eventIndex events world

def CheckedNativeOperationBlock.expectedTerminalTransition
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    RelatedTransition NativeWorldExecution WorldRelationalObservable :=
  transitionFromNativeWorldOutcome candidate.pe candidate.environment
    candidate.callableExternal candidate.indirectTargets
    block.terminal.instruction.rva
    (concreteBehaviorNextMachineState
      (block.terminal.replay.behavior.eval (block.terminalState state))
      (block.terminalState state))
    calls eventIndex events world
    ((block.terminal.cutpoint.postcondition.outcome.expected.map
      (evalNativeOperationOutcomeExpr (block.terminalState state))).getD
        (.jump 0))

theorem CheckedNativeOperationBlock.afterExpected
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    block.after state calls eventIndex events world =
      (block.expectedTerminalTransition state calls eventIndex events world).next := by
  unfold CheckedNativeOperationBlock.after
    CheckedNativeOperationBlock.expectedTerminalTransition
  exact congrArg RelatedTransition.next
    (block.terminalWorldStepExpected state calls eventIndex events world)

theorem CheckedNativeOperationBlock.observationsExpected
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    block.observations state calls eventIndex events world =
      (block.expectedTerminalTransition state calls eventIndex events
        world).observation.toList := by
  unfold CheckedNativeOperationBlock.observations
    CheckedNativeOperationBlock.expectedTerminalTransition
  exact congrArg (fun transition => transition.observation.toList)
    (block.terminalWorldStepExpected state calls eventIndex events world)

theorem CheckedNativeOperationBlock.terminalInvariantHolds
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState)
    (sourceHolds :
      match block.running with
      | none => block.terminal.cutpoint.source.Holds state
      | some running => running.first.cutpoint.source.Holds state) :
    block.terminal.cutpoint.target.Holds
      (block.terminal.after (block.terminalState state)) := by
  cases runningExact : block.running with
  | none =>
      rw [runningExact] at sourceHolds
      simpa [CheckedNativeOperationBlock.terminalState, runningExact] using
        block.terminal.cutpoint.replayTargetHolds state sourceHolds
  | some running =>
      rw [runningExact] at sourceHolds
      have checked := block.checked
      simp only [checkedNativeOperationBlock, runningExact,
        Bool.and_eq_true, beq_iff_eq] at checked
      have runningHolds := running.finalTargetHolds state sourceHolds
      rw [checked.2] at runningHolds
      simpa [CheckedNativeOperationBlock.terminalState, runningExact] using
        block.terminal.cutpoint.replayTargetHolds (running.after state)
          runningHolds

theorem CheckedNativeOperationBlock.terminalSourceHolds
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState)
    (sourceHolds :
      match block.running with
      | none => block.terminal.cutpoint.source.Holds state
      | some running => running.first.cutpoint.source.Holds state) :
    block.terminal.cutpoint.source.Holds (block.terminalState state) := by
  cases runningExact : block.running with
  | none =>
      rw [runningExact] at sourceHolds
      simpa [CheckedNativeOperationBlock.terminalState, runningExact] using
        sourceHolds
  | some running =>
      rw [runningExact] at sourceHolds
      have checked := block.checked
      simp only [checkedNativeOperationBlock, runningExact,
        Bool.and_eq_true, beq_iff_eq] at checked
      have runningHolds := running.finalTargetHolds state sourceHolds
      rw [checked.2] at runningHolds
      simpa [CheckedNativeOperationBlock.terminalState, runningExact] using
        runningHolds

#print axioms CheckedNativeOperationRunningTrace.runExact
#print axioms CheckedNativeOperationRunningTrace.invariantHolds
#print axioms CheckedNativeOperationBlock.runExact
#print axioms CheckedNativeOperationBlock.path
#print axioms CheckedNativeOperationBlock.toCheckedPath_after
#print axioms CheckedNativeOperationBlock.toCheckedPath_observations
#print axioms CheckedNativeOperationBlock.terminalWorldStepExpected
#print axioms CheckedNativeOperationBlock.afterExpected
#print axioms CheckedNativeOperationBlock.observationsExpected
#print axioms CheckedNativeOperationBlock.terminalInvariantHolds
#print axioms CheckedNativeOperationBlock.terminalSourceHolds

end StageA.Relational.InterpreterKernelOperationTraceChecker
