import StageA.RelationalInterpreterKernelOperationFrameChecker
import StageA.RelationalInterpreterKernelOperationStateRouteChecker

namespace StageA.Relational.InterpreterKernelOperationPredicateRoute

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationControlChecker
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationFrameChecker
open StageA.Relational.InterpreterKernelOperationGraphChecker
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationStateRouteChecker
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

/-!
# Predicate-indexed native operation routes

Compiler control flow is selected by values in the exact candidate state.
This module transports checked Boolean predicates through exact instruction
semantics and uses them to select local branch successors. Generated modules
submit only normalized effects, predicate inventories, and graph targets; Lean
checks every pullback and executes the exact PE bytes.

The route deliberately stops at call, return, indirect, and external
boundaries. Those transitions use the separate checked frame and environment
interfaces.
-/

structure CheckedNativeOperationPredicateStep
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (source target : NativeOperationInvariant) where
  effect : NormalizedSymbolicBehavior
  effectExact :
    operationInvariantEffect? edge.replay.behavior = some effect
  invariantChecked :
    nativeOperationInvariantEdgeChecked source target effect = true

theorem CheckedNativeOperationPredicateStep.sound
    {candidate : ExactNativeWorldProgram}
    {edge : CheckedNativeOperationRunningEdge candidate}
    {source target : NativeOperationInvariant}
    (step : CheckedNativeOperationPredicateStep edge source target)
    (state : MachineState) (sourceHolds : source.Holds state) :
    target.Holds (edge.after state) := by
  unfold CheckedNativeOperationRunningEdge.after
  rw [← operationInvariantEffect?_nextMachineState edge.replay.behavior
    step.effect step.effectExact state]
  exact nativeOperationInvariantEdgeChecked_sound source target step.effect
    step.invariantChecked state sourceHolds

inductive CheckedNativeOperationPredicateTrace
    (candidate : ExactNativeWorldProgram) :
    List (CheckedNativeOperationRunningEdge candidate) ->
      NativeOperationInvariant -> NativeOperationInvariant -> Type
  | one
      (edge : CheckedNativeOperationRunningEdge candidate)
      (source target : NativeOperationInvariant)
      (step : CheckedNativeOperationPredicateStep edge source target) :
      CheckedNativeOperationPredicateTrace candidate [edge] source target
  | cons
      (edge : CheckedNativeOperationRunningEdge candidate)
      (rest : List (CheckedNativeOperationRunningEdge candidate))
      (source middle target : NativeOperationInvariant)
      (step : CheckedNativeOperationPredicateStep edge source middle)
      (tail : CheckedNativeOperationPredicateTrace candidate rest middle target) :
      CheckedNativeOperationPredicateTrace candidate (edge :: rest) source target

theorem CheckedNativeOperationPredicateTrace.sound
    {candidate : ExactNativeWorldProgram}
    {edges : List (CheckedNativeOperationRunningEdge candidate)}
    {source target : NativeOperationInvariant}
    (replay : CheckedNativeOperationPredicateTrace candidate edges source target)
    (state : MachineState) (sourceHolds : source.Holds state) :
    target.Holds (runCheckedNativeOperationRunningTrace edges state) := by
  induction replay generalizing state with
  | one edge source target step =>
      simpa [runCheckedNativeOperationRunningTrace] using
        step.sound state sourceHolds
  | cons edge rest source middle target step tail induction =>
      simp only [runCheckedNativeOperationRunningTrace]
      exact induction (edge.after state) (step.sound state sourceHolds)

/-- Compute the weakest supported entry invariant for a complete running
instruction trace.  The target predicate is pulled backwards once through
each exact symbolic instruction effect.  Failure is explicit when any
instruction leaves the reviewed normalized fragment. -/
def checkedNativeOperationPredicateTracePullback? :
    {candidate : ExactNativeWorldProgram} ->
      List (CheckedNativeOperationRunningEdge candidate) ->
      NativeOperationInvariant -> Option NativeOperationInvariant
  | _, [], target => some target
  | _, edge :: rest, target => do
      let middle <-
        checkedNativeOperationPredicateTracePullback? rest target
      let effect <- operationInvariantEffect? edge.replay.behavior
      middle.pullback? effect

/-- Environment-free form of trace pullback. Exact replay objects are needed
for semantic soundness, but their behavior summaries are sufficient to compute
the invariant certificate. -/
def checkedNativeOperationPredicateBehaviorTracePullback? :
    List SymbolicBehavior -> NativeOperationInvariant ->
      Option NativeOperationInvariant
  | [], target => some target
  | behavior :: rest, target => do
      let middle <-
        checkedNativeOperationPredicateBehaviorTracePullback? rest target
      let effect <- operationInvariantEffect? behavior
      middle.pullback? effect

theorem checkedNativeOperationPredicateTracePullback?_eq_behaviors
    {candidate : ExactNativeWorldProgram}
    (edges : List (CheckedNativeOperationRunningEdge candidate))
    (target : NativeOperationInvariant) :
    checkedNativeOperationPredicateTracePullback? edges target =
      checkedNativeOperationPredicateBehaviorTracePullback?
        (edges.map (fun edge => edge.replay.behavior)) target := by
  induction edges with
  | nil =>
      simp [checkedNativeOperationPredicateTracePullback?,
        checkedNativeOperationPredicateBehaviorTracePullback?]
  | cons edge rest induction =>
      simp only [checkedNativeOperationPredicateTracePullback?,
        checkedNativeOperationPredicateBehaviorTracePullback?, List.map_cons]
      rw [induction]

theorem checkedNativeOperationPredicateTracePullback?_sound
    {candidate : ExactNativeWorldProgram}
    (edges : List (CheckedNativeOperationRunningEdge candidate))
    (target source : NativeOperationInvariant)
    (checked :
      checkedNativeOperationPredicateTracePullback? edges target =
        some source)
    (state : MachineState) (sourceHolds : source.Holds state) :
    target.Holds (runCheckedNativeOperationRunningTrace edges state) := by
  induction edges generalizing source state with
  | nil =>
      simp only [checkedNativeOperationPredicateTracePullback?,
        Option.some.injEq] at checked
      subst source
      simpa [runCheckedNativeOperationRunningTrace] using sourceHolds
  | cons edge rest induction =>
      simp only [checkedNativeOperationPredicateTracePullback?] at checked
      cases middleExact :
          checkedNativeOperationPredicateTracePullback? rest target with
      | none =>
          simp [middleExact] at checked
      | some middle =>
          cases effectExact :
              operationInvariantEffect? edge.replay.behavior with
          | none =>
              simp [middleExact, effectExact] at checked
          | some effect =>
              cases sourceExact : middle.pullback? effect with
              | none =>
                  simp [middleExact, effectExact, sourceExact] at checked
              | some pulled =>
                  simp [middleExact, effectExact, sourceExact] at checked
                  subst source
                  have middleHolds :
                      middle.Holds (edge.after state) := by
                    unfold CheckedNativeOperationRunningEdge.after
                    rw [← operationInvariantEffect?_nextMachineState
                      edge.replay.behavior effect effectExact state]
                    exact NativeOperationInvariant.pullback?_sound
                      middle pulled effect sourceExact state sourceHolds
                  simp only [runCheckedNativeOperationRunningTrace]
                  exact induction middle middleExact (edge.after state)
                    middleHolds

/-- Select the unique local successor that reaches `targetRva`.  Calls,
returns, indirect control, and external boundaries are intentionally absent:
they are discharged by their typed boundary checkers. -/
def nativeOperationLocalSuccessorForTarget? :
    NativeOperationOutcomePostcondition -> Nat ->
      Option NativeOperationLocalSuccessor
  | .jumped target, expected =>
      if target == expected then some (.jump target) else none
  | .branched _ taken fallthrough, expected =>
      if taken == expected && fallthrough != expected then
        some (.branchTrue taken)
      else if fallthrough == expected && taken != expected then
        some (.branchFalse fallthrough)
      else
        none
  | .bulkCopy _ continuation, expected =>
      if continuation == expected then some (.bulkCopy continuation) else none
  | .bulkFill _ continuation, expected =>
      if continuation == expected then some (.bulkFill continuation) else none
  | .bulkScan _ continuation, expected =>
      if continuation == expected then some (.bulkScan continuation) else none
  | .checkedContinue _ continuation, expected =>
      if continuation == expected then
        some (.checkedContinue continuation)
      else
        none
  | .atomicCompareExchange _ _ _ continuation, expected =>
      if continuation == expected then
        some (.atomicCompareExchange continuation)
      else
        none
  | _, _ => none

/-- Predicates needed solely to select one checked local successor. -/
def nativeOperationLocalSuccessorSelectorInvariant? :
    NativeOperationOutcomePostcondition -> NativeOperationLocalSuccessor ->
      Option NativeOperationInvariant
  | .jumped target, .jump expected =>
      if target == expected then some trivialNativeOperationInvariant else none
  | .branched condition taken _, .branchTrue expected =>
      if taken == expected then some { predicates := [condition] } else none
  | .branched condition _ fallthrough, .branchFalse expected =>
      if fallthrough == expected then
        some { predicates := [.not condition] }
      else
        none
  | .bulkCopy _ continuation, .bulkCopy expected =>
      if continuation == expected then
        some trivialNativeOperationInvariant
      else
        none
  | .bulkFill _ continuation, .bulkFill expected =>
      if continuation == expected then
        some trivialNativeOperationInvariant
      else
        none
  | .bulkScan _ continuation, .bulkScan expected =>
      if continuation == expected then
        some trivialNativeOperationInvariant
      else
        none
  | .checkedContinue valid continuation, .checkedContinue expected =>
      if continuation == expected then some { predicates := [valid] } else none
  | .atomicCompareExchange _ _ _ continuation,
      .atomicCompareExchange expected =>
      if continuation == expected then
        some trivialNativeOperationInvariant
      else
        none
  | _, _ => none

/-- Compute the terminal invariant for a selected local edge.  It combines
the exact pullback of the target invariant with the predicate that chooses the
successor. -/
def nativeOperationSelectedTerminalInvariant?
    (behavior : SymbolicBehavior)
    (outcome : NativeOperationOutcomePostcondition)
    (successor : NativeOperationLocalSuccessor)
    (target : NativeOperationInvariant) :
    Option NativeOperationInvariant := do
  let effect <- operationInvariantEffect? behavior
  let pulled <- target.pullback? effect
  let selector <-
    nativeOperationLocalSuccessorSelectorInvariant? outcome successor
  pure { predicates := selector.predicates ++ pulled.predicates }

theorem nativeOperationSelectedTerminalInvariant?_targetChecked
    (behavior : SymbolicBehavior)
    (outcome : NativeOperationOutcomePostcondition)
    (successor : NativeOperationLocalSuccessor)
    (target terminal : NativeOperationInvariant)
    (selected :
      nativeOperationSelectedTerminalInvariant? behavior outcome successor
        target = some terminal) :
    ∃ effect,
      operationInvariantEffect? behavior = some effect ∧
        nativeOperationInvariantEdgeChecked terminal target effect = true := by
  simp only [nativeOperationSelectedTerminalInvariant?] at selected
  cases effectExact : operationInvariantEffect? behavior with
  | none =>
      simp [effectExact] at selected
  | some effect =>
      cases pulledExact : target.pullback? effect with
      | none =>
          simp [effectExact, pulledExact] at selected
      | some pulled =>
          cases selectorExact :
              nativeOperationLocalSuccessorSelectorInvariant? outcome successor
          with
          | none =>
              simp [effectExact, pulledExact, selectorExact] at selected
          | some selector =>
              simp [effectExact, pulledExact, selectorExact] at selected
              subst terminal
              refine ⟨effect, rfl, ?_⟩
              have pulledChecked :
                  nativeOperationInvariantEdgeChecked pulled target effect =
                    true :=
                nativeOperationInvariantEdgeChecked_of_pullback pulled target
                  effect pulledExact
              simp only [nativeOperationInvariantEdgeChecked,
                List.all_eq_true] at pulledChecked ⊢
              intro predicate member
              have row := pulledChecked predicate member
              cases exact :
                  predicate.edgePullbackExpression effect with
              | none =>
                  simp [exact] at row
              | some sourcePredicate =>
                  have sourceMember :
                      sourcePredicate ∈ pulled.predicates := by
                    simpa [exact] using row
                  simpa [exact] using
                    List.mem_append_right selector.predicates sourceMember

structure CheckedNativeOperationRunningTracePredicateReplay
    {candidate : ExactNativeWorldProgram}
    (trace : CheckedNativeOperationRunningTrace candidate)
    (source target : NativeOperationInvariant) where
  replay :
    CheckedNativeOperationPredicateTrace candidate trace.edges source target

theorem CheckedNativeOperationRunningTracePredicateReplay.sound
    {candidate : ExactNativeWorldProgram}
    {trace : CheckedNativeOperationRunningTrace candidate}
    {source target : NativeOperationInvariant}
    (replay :
      CheckedNativeOperationRunningTracePredicateReplay trace source target)
    (state : MachineState) (sourceHolds : source.Holds state) :
    target.Holds (trace.after state) := by
  exact replay.replay.sound state sourceHolds

inductive CheckedNativeOperationBlockPredicatePrelude
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate) :
    NativeOperationInvariant -> NativeOperationInvariant -> Type
  | noRunning
      (invariant : NativeOperationInvariant)
      (runningExact : block.running = none) :
      CheckedNativeOperationBlockPredicatePrelude block invariant invariant
  | running
      (trace : CheckedNativeOperationRunningTrace candidate)
      (source terminal : NativeOperationInvariant)
      (runningExact : block.running = some trace)
      (replay :
        CheckedNativeOperationRunningTracePredicateReplay trace source terminal) :
      CheckedNativeOperationBlockPredicatePrelude block source terminal
  | runningPullback
      (trace : CheckedNativeOperationRunningTrace candidate)
      (source terminal : NativeOperationInvariant)
      (runningExact : block.running = some trace)
      (checked :
        checkedNativeOperationPredicateTracePullback? trace.edges terminal =
          some source) :
      CheckedNativeOperationBlockPredicatePrelude block source terminal
  | runningStaticPullback
      (trace : CheckedNativeOperationRunningTrace candidate)
      (source terminal : NativeOperationInvariant)
      (runningExact : block.running = some trace)
      (behaviors : List SymbolicBehavior)
      (behaviorsExact :
        trace.edges.map (fun edge => edge.replay.behavior) = behaviors)
      (checked :
        checkedNativeOperationPredicateBehaviorTracePullback? behaviors
          terminal = some source) :
      CheckedNativeOperationBlockPredicatePrelude block source terminal

theorem CheckedNativeOperationBlockPredicatePrelude.sound
    {candidate : ExactNativeWorldProgram}
    {block : CheckedNativeOperationBlock candidate}
    {source terminal : NativeOperationInvariant}
    (prelude :
      CheckedNativeOperationBlockPredicatePrelude block source terminal)
    (state : MachineState) (sourceHolds : source.Holds state) :
    terminal.Holds (block.terminalState state) := by
  cases prelude with
  | noRunning invariant runningExact =>
      simpa [CheckedNativeOperationBlock.terminalState, runningExact] using
        sourceHolds
  | running trace source terminal runningExact replay =>
      simpa [CheckedNativeOperationBlock.terminalState, runningExact] using
        replay.sound state sourceHolds
  | runningPullback trace source terminal runningExact checked =>
      simpa [CheckedNativeOperationBlock.terminalState, runningExact] using
        checkedNativeOperationPredicateTracePullback?_sound trace.edges
          terminal source checked state sourceHolds
  | runningStaticPullback trace source terminal runningExact behaviors
      behaviorsExact checked =>
      have dynamicChecked :
          checkedNativeOperationPredicateTracePullback? trace.edges terminal =
            some source := by
        rw [checkedNativeOperationPredicateTracePullback?_eq_behaviors,
          behaviorsExact]
        exact checked
      simpa [CheckedNativeOperationBlock.terminalState, runningExact] using
        checkedNativeOperationPredicateTracePullback?_sound trace.edges
          terminal source dynamicChecked state sourceHolds

/-- One checked local block transition. `terminalInvariant` carries both the
selected branch guard and the pullbacks needed by the successor invariant.
The successor frame computation is evaluated rather than asserted. -/
structure CheckedNativeOperationPredicateBlockStep
    {candidate : ExactNativeWorldProgram}
    (blocks : List (CheckedNativeOperationBlock candidate))
    (sourceBlock : CheckedNativeOperationBlock candidate)
    (sourceInvariant : NativeOperationInvariant)
    (targetBlock : CheckedNativeOperationBlock candidate)
    (targetInvariant : NativeOperationInvariant) where
  sourceMember : sourceBlock ∈ blocks
  targetMember : targetBlock ∈ blocks
  terminalInvariant : NativeOperationInvariant
  prelude :
    CheckedNativeOperationBlockPredicatePrelude sourceBlock sourceInvariant
      terminalInvariant
  terminalEffect : NormalizedSymbolicBehavior
  terminalEffectExact :
    operationInvariantEffect? sourceBlock.terminal.replay.behavior =
      some terminalEffect
  terminalInvariantChecked :
    nativeOperationInvariantEdgeChecked terminalInvariant targetInvariant
      terminalEffect = true
  successor : NativeOperationLocalSuccessor
  successorChecked :
    checkedNativeOperationLocalSuccessor terminalInvariant
      sourceBlock.terminal.cutpoint.postcondition.outcome.expected successor =
        true
  statePreserving : successor.statePreserving = true
  framesPreserved : ∀ frames,
    nativeOperationSuccessorCallFrames? successor frames = some frames
  alwaysRunningLocal :
    nativeOperationOutcomeAlwaysRunningLocal
      sourceBlock.terminal.cutpoint.postcondition.outcome = true
  graphInvariantChecked :
    checkedNativeOperationInvariantLink sourceBlock targetBlock = true
  targetRvaExact : successor.targetRva = targetBlock.entryRva
  targetSlotExact : targetBlock.entrySlot = 0

def CheckedNativeOperationPredicateBlockStep.targetState
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetInvariant : NativeOperationInvariant}
    (_step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
      sourceInvariant targetBlock targetInvariant)
    (state : MachineState) : MachineState :=
  sourceBlock.terminal.after (sourceBlock.terminalState state)

theorem CheckedNativeOperationPredicateBlockStep.targetInvariantHolds
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetInvariant : NativeOperationInvariant}
    (step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
      sourceInvariant targetBlock targetInvariant)
    (state : MachineState) (sourceHolds : sourceInvariant.Holds state) :
    targetInvariant.Holds (step.targetState state) := by
  have terminalHolds := step.prelude.sound state sourceHolds
  unfold CheckedNativeOperationPredicateBlockStep.targetState
    CheckedNativeOperationStoppedEdge.after
  rw [← operationInvariantEffect?_nextMachineState
    sourceBlock.terminal.replay.behavior step.terminalEffect
    step.terminalEffectExact (sourceBlock.terminalState state)]
  exact nativeOperationInvariantEdgeChecked_sound step.terminalInvariant
    targetInvariant step.terminalEffect step.terminalInvariantChecked
    (sourceBlock.terminalState state) terminalHolds

/-- Use an exact terminal-state projection in place of re-evaluating the
generated weakest precondition for the running prefix. -/
theorem CheckedNativeOperationPredicateBlockStep.targetInvariantHoldsOfTerminalHolds
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetInvariant : NativeOperationInvariant}
    (step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
      sourceInvariant targetBlock targetInvariant)
    (state : MachineState)
    (terminalHolds :
      step.terminalInvariant.Holds (sourceBlock.terminalState state)) :
    targetInvariant.Holds (step.targetState state) := by
  unfold CheckedNativeOperationPredicateBlockStep.targetState
    CheckedNativeOperationStoppedEdge.after
  rw [← operationInvariantEffect?_nextMachineState
    sourceBlock.terminal.replay.behavior step.terminalEffect
    step.terminalEffectExact (sourceBlock.terminalState state)]
  exact nativeOperationInvariantEdgeChecked_sound step.terminalInvariant
    targetInvariant step.terminalEffect step.terminalInvariantChecked
    (sourceBlock.terminalState state) terminalHolds

/-- Execute the checked local successor from a compact terminal-state fact.
The source block still executes its exact decoded running trace. -/
theorem CheckedNativeOperationPredicateBlockStep.afterExactOfControlInvariant
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetInvariant : NativeOperationInvariant}
    (step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
      sourceInvariant targetBlock targetInvariant)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (controlInvariant : NativeOperationInvariant)
    (controlChecked :
      checkedNativeOperationLocalSuccessor controlInvariant
        sourceBlock.terminal.cutpoint.postcondition.outcome.expected
        step.successor = true)
    (controlHolds :
      controlInvariant.Holds (sourceBlock.terminalState state)) :
    sourceBlock.after state calls eventIndex events world =
      .running targetBlock.entryRva targetBlock.entrySlot
        (step.targetState state) calls eventIndex events world := by
  rw [sourceBlock.afterExpected]
  unfold CheckedNativeOperationBlock.expectedTerminalTransition
  cases outcomeExact :
      sourceBlock.terminal.cutpoint.postcondition.outcome.expected with
  | none =>
      have impossible := controlChecked
      simp [checkedNativeOperationLocalSuccessor, outcomeExact] at impossible
  | some outcome =>
      simp only [Option.map_some, Option.getD_some]
      rw [outcomeExact] at controlChecked
      have selected :=
        nativeOperationStatePreservingSuccessorCallFrames candidate
          controlInvariant outcome step.successor
          sourceBlock.terminal.instruction.rva
          (sourceBlock.terminalState state) (step.targetState state)
          calls calls [] eventIndex events world controlChecked
          step.statePreserving controlHolds (step.framesPreserved calls)
      rw [step.targetRvaExact, ← step.targetSlotExact] at selected
      simpa [CheckedNativeOperationPredicateBlockStep.targetState,
        CheckedNativeOperationStoppedEdge.after] using selected

theorem CheckedNativeOperationPredicateBlockStep.afterExactOfTerminalHolds
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetInvariant : NativeOperationInvariant}
    (step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
      sourceInvariant targetBlock targetInvariant)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (terminalHolds :
      step.terminalInvariant.Holds (sourceBlock.terminalState state)) :
    sourceBlock.after state calls eventIndex events world =
      .running targetBlock.entryRva targetBlock.entrySlot
        (step.targetState state) calls eventIndex events world := by
  exact step.afterExactOfControlInvariant state calls eventIndex events world
    step.terminalInvariant step.successorChecked terminalHolds

theorem CheckedNativeOperationPredicateBlockStep.afterExact
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetInvariant : NativeOperationInvariant}
    (step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
      sourceInvariant targetBlock targetInvariant)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds : sourceInvariant.Holds state) :
    sourceBlock.after state calls eventIndex events world =
      .running targetBlock.entryRva targetBlock.entrySlot
        (step.targetState state) calls eventIndex events world := by
  have terminalHolds := step.prelude.sound state sourceHolds
  rw [sourceBlock.afterExpected]
  unfold CheckedNativeOperationBlock.expectedTerminalTransition
  cases outcomeExact :
      sourceBlock.terminal.cutpoint.postcondition.outcome.expected with
  | none =>
      have impossible := step.successorChecked
      simp [checkedNativeOperationLocalSuccessor, outcomeExact] at impossible
  | some outcome =>
      simp only [Option.map_some, Option.getD_some]
      have successorChecked := step.successorChecked
      rw [outcomeExact] at successorChecked
      have selected :=
        nativeOperationStatePreservingSuccessorCallFrames candidate
          step.terminalInvariant outcome step.successor
          sourceBlock.terminal.instruction.rva
          (sourceBlock.terminalState state) (step.targetState state)
          calls calls [] eventIndex events world successorChecked
          step.statePreserving terminalHolds (step.framesPreserved calls)
      rw [step.targetRvaExact, ← step.targetSlotExact] at selected
      simpa [CheckedNativeOperationPredicateBlockStep.targetState,
        CheckedNativeOperationStoppedEdge.after] using selected

theorem CheckedNativeOperationPredicateBlockStep.observationsEmptyOfTerminalHolds
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetInvariant : NativeOperationInvariant}
    (step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
      sourceInvariant targetBlock targetInvariant)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (terminalHolds :
      step.terminalInvariant.Holds (sourceBlock.terminalState state)) :
    sourceBlock.observations state calls eventIndex events world = [] := by
  let successor : CheckedNativeOperationGraphSuccessor blocks sourceBlock
      state calls eventIndex events world := {
    target := targetBlock
    targetMember := step.targetMember
    targetState := step.targetState state
    targetCalls := calls
    targetEventIndex := eventIndex
    targetEvents := events
    targetWorld := world
    afterExact := step.afterExactOfTerminalHolds state calls eventIndex events
      world terminalHolds
    invariantChecked := step.graphInvariantChecked
  }
  have preserved :=
    checkedNativeOperationGraphSuccessor_contextPreserved successor
      step.alwaysRunningLocal
  exact preserved.2.2.2.2

theorem CheckedNativeOperationPredicateBlockStep.observationsEmptyOfControlInvariant
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetInvariant : NativeOperationInvariant}
    (step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
      sourceInvariant targetBlock targetInvariant)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (controlInvariant : NativeOperationInvariant)
    (controlChecked :
      checkedNativeOperationLocalSuccessor controlInvariant
        sourceBlock.terminal.cutpoint.postcondition.outcome.expected
        step.successor = true)
    (controlHolds :
      controlInvariant.Holds (sourceBlock.terminalState state)) :
    sourceBlock.observations state calls eventIndex events world = [] := by
  let successor : CheckedNativeOperationGraphSuccessor blocks sourceBlock
      state calls eventIndex events world := {
    target := targetBlock
    targetMember := step.targetMember
    targetState := step.targetState state
    targetCalls := calls
    targetEventIndex := eventIndex
    targetEvents := events
    targetWorld := world
    afterExact := step.afterExactOfControlInvariant state calls eventIndex
      events world controlInvariant controlChecked controlHolds
    invariantChecked := step.graphInvariantChecked
  }
  have preserved :=
    checkedNativeOperationGraphSuccessor_contextPreserved successor
      step.alwaysRunningLocal
  exact preserved.2.2.2.2

def CheckedNativeOperationPredicateBlockStep.graphSuccessor
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetInvariant : NativeOperationInvariant}
    (step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
      sourceInvariant targetBlock targetInvariant)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds : sourceInvariant.Holds state) :
    CheckedNativeOperationGraphSuccessor blocks sourceBlock state calls
      eventIndex events world := {
  target := targetBlock
  targetMember := step.targetMember
  targetState := step.targetState state
  targetCalls := calls
  targetEventIndex := eventIndex
  targetEvents := events
  targetWorld := world
  afterExact := step.afterExact state calls eventIndex events world sourceHolds
  invariantChecked := step.graphInvariantChecked
}

theorem CheckedNativeOperationPredicateBlockStep.observationsEmpty
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetInvariant : NativeOperationInvariant}
    (step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
      sourceInvariant targetBlock targetInvariant)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds : sourceInvariant.Holds state) :
    sourceBlock.observations state calls eventIndex events world = [] := by
  have preserved :=
    checkedNativeOperationGraphSuccessor_contextPreserved
      (step.graphSuccessor state calls eventIndex events world sourceHolds)
      step.alwaysRunningLocal
  exact preserved.2.2.2.2

/-- One exact silent block path discharged from compact terminal-state facts. -/
theorem CheckedNativeOperationPredicateBlockStep.executeOfTerminalHolds
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetInvariant : NativeOperationInvariant}
    (step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
      sourceInvariant targetBlock targetInvariant)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (terminalHolds :
      step.terminalInvariant.Holds (sourceBlock.terminalState state)) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running sourceBlock.entryRva sourceBlock.entrySlot state calls
        eventIndex events world)
      []
      (.running targetBlock.entryRva targetBlock.entrySlot
        (step.targetState state) calls eventIndex events world) := by
  have path := sourceBlock.path state calls eventIndex events world
  rw [step.afterExactOfTerminalHolds state calls eventIndex events world
    terminalHolds] at path
  simpa [step.observationsEmptyOfTerminalHolds state calls eventIndex events
    world terminalHolds] using path

/-- One exact silent block path whose local branch is justified independently
of any future-state invariant synthesis. -/
theorem CheckedNativeOperationPredicateBlockStep.executeOfControlInvariant
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant : NativeOperationInvariant}
    {targetBlock : CheckedNativeOperationBlock candidate}
    {targetInvariant : NativeOperationInvariant}
    (step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
      sourceInvariant targetBlock targetInvariant)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (controlInvariant : NativeOperationInvariant)
    (controlChecked :
      checkedNativeOperationLocalSuccessor controlInvariant
        sourceBlock.terminal.cutpoint.postcondition.outcome.expected
        step.successor = true)
    (controlHolds :
      controlInvariant.Holds (sourceBlock.terminalState state)) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running sourceBlock.entryRva sourceBlock.entrySlot state calls
        eventIndex events world)
      []
      (.running targetBlock.entryRva targetBlock.entrySlot
        (step.targetState state) calls eventIndex events world) := by
  have path := sourceBlock.path state calls eventIndex events world
  rw [step.afterExactOfControlInvariant state calls eventIndex events world
    controlInvariant controlChecked controlHolds] at path
  simpa [step.observationsEmptyOfControlInvariant state calls eventIndex events
    world controlInvariant controlChecked controlHolds] using path

inductive CheckedNativeOperationPredicateRoute
    (candidate : ExactNativeWorldProgram)
    (blocks : List (CheckedNativeOperationBlock candidate)) :
    CheckedNativeOperationBlock candidate -> NativeOperationInvariant ->
      CheckedNativeOperationBlock candidate -> NativeOperationInvariant -> Type
  | one
      (sourceBlock targetBlock : CheckedNativeOperationBlock candidate)
      (sourceInvariant targetInvariant : NativeOperationInvariant)
      (step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
        sourceInvariant targetBlock targetInvariant) :
      CheckedNativeOperationPredicateRoute candidate blocks sourceBlock
        sourceInvariant targetBlock targetInvariant
  | cons
      (sourceBlock middleBlock finalBlock :
        CheckedNativeOperationBlock candidate)
      (sourceInvariant middleInvariant finalInvariant :
        NativeOperationInvariant)
      (step : CheckedNativeOperationPredicateBlockStep blocks sourceBlock
        sourceInvariant middleBlock middleInvariant)
      (tail : CheckedNativeOperationPredicateRoute candidate blocks middleBlock
        middleInvariant finalBlock finalInvariant) :
      CheckedNativeOperationPredicateRoute candidate blocks sourceBlock
        sourceInvariant finalBlock finalInvariant

def runCheckedNativeOperationPredicateRoute
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant finalInvariant : NativeOperationInvariant}
    (route : CheckedNativeOperationPredicateRoute candidate blocks sourceBlock
      sourceInvariant finalBlock finalInvariant)
    (state : MachineState) : MachineState :=
  match route with
  | .one _ _ _ _ step => step.targetState state
  | .cons _ _ _ _ _ _ step tail =>
      runCheckedNativeOperationPredicateRoute tail (step.targetState state)

theorem CheckedNativeOperationPredicateRoute.execute
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant finalInvariant : NativeOperationInvariant}
    (route : CheckedNativeOperationPredicateRoute candidate blocks sourceBlock
      sourceInvariant finalBlock finalInvariant)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds : sourceInvariant.Holds state) :
    ∃ finalState,
      NonemptyRelatedPath candidate.transitionSystem
        (.running sourceBlock.entryRva sourceBlock.entrySlot state calls
          eventIndex events world)
        []
        (.running finalBlock.entryRva finalBlock.entrySlot finalState calls
          eventIndex events world) ∧
      finalInvariant.Holds finalState := by
  induction route generalizing state with
  | one sourceBlock targetBlock sourceInvariant targetInvariant step =>
      refine ⟨step.targetState state, ?_,
        step.targetInvariantHolds state sourceHolds⟩
      have path := sourceBlock.path state calls eventIndex events world
      rw [step.afterExact state calls eventIndex events world sourceHolds] at path
      simpa [step.observationsEmpty state calls eventIndex events world
        sourceHolds] using path
  | cons sourceBlock middleBlock finalBlock sourceInvariant middleInvariant
      finalInvariant step tail induction =>
      have middleHolds := step.targetInvariantHolds state sourceHolds
      obtain ⟨finalState, tailPath, finalHolds⟩ :=
        induction (step.targetState state) middleHolds
      have firstPath := sourceBlock.path state calls eventIndex events world
      rw [step.afterExact state calls eventIndex events world sourceHolds] at firstPath
      have firstSilent :
          sourceBlock.observations state calls eventIndex events world = [] :=
        step.observationsEmpty state calls eventIndex events world sourceHolds
      rw [firstSilent] at firstPath
      exact ⟨finalState, firstPath.trans tailPath, finalHolds⟩

/-- Execute a predicate route while retaining its definitionally computed
endpoint.  Generated composition artifacts use this form when a following
effectful block consumes the exact machine state. -/
theorem CheckedNativeOperationPredicateRoute.executeExact
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {sourceBlock finalBlock : CheckedNativeOperationBlock candidate}
    {sourceInvariant finalInvariant : NativeOperationInvariant}
    (route : CheckedNativeOperationPredicateRoute candidate blocks sourceBlock
      sourceInvariant finalBlock finalInvariant)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds : sourceInvariant.Holds state) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running sourceBlock.entryRva sourceBlock.entrySlot state calls
        eventIndex events world)
      []
      (.running finalBlock.entryRva finalBlock.entrySlot
        (runCheckedNativeOperationPredicateRoute route state) calls
        eventIndex events world) ∧
    finalInvariant.Holds
      (runCheckedNativeOperationPredicateRoute route state) := by
  induction route generalizing state with
  | one sourceBlock targetBlock sourceInvariant targetInvariant step =>
      constructor
      · have path := sourceBlock.path state calls eventIndex events world
        rw [step.afterExact state calls eventIndex events world sourceHolds] at path
        simpa [runCheckedNativeOperationPredicateRoute,
          step.observationsEmpty state calls eventIndex events world sourceHolds]
          using path
      · simpa [runCheckedNativeOperationPredicateRoute] using
          step.targetInvariantHolds state sourceHolds
  | cons sourceBlock middleBlock finalBlock sourceInvariant middleInvariant
      finalInvariant step tail induction =>
      have middleHolds := step.targetInvariantHolds state sourceHolds
      obtain ⟨tailPath, finalHolds⟩ :=
        induction (step.targetState state) middleHolds
      have firstPath := sourceBlock.path state calls eventIndex events world
      rw [step.afterExact state calls eventIndex events world sourceHolds] at firstPath
      have firstSilent :
          sourceBlock.observations state calls eventIndex events world = [] :=
        step.observationsEmpty state calls eventIndex events world sourceHolds
      rw [firstSilent] at firstPath
      exact ⟨by
        simpa [runCheckedNativeOperationPredicateRoute] using
          firstPath.trans tailPath,
        by simpa [runCheckedNativeOperationPredicateRoute] using finalHolds⟩

#print axioms CheckedNativeOperationPredicateStep.sound
#print axioms CheckedNativeOperationPredicateTrace.sound
#print axioms CheckedNativeOperationBlockPredicatePrelude.sound
#print axioms CheckedNativeOperationPredicateBlockStep.targetInvariantHolds
#print axioms CheckedNativeOperationPredicateBlockStep.afterExact
#print axioms CheckedNativeOperationPredicateBlockStep.observationsEmpty
#print axioms CheckedNativeOperationPredicateRoute.execute
#print axioms CheckedNativeOperationPredicateRoute.executeExact
#print axioms checkedNativeOperationPredicateTracePullback?_sound
#print axioms nativeOperationSelectedTerminalInvariant?_targetChecked

end StageA.Relational.InterpreterKernelOperationPredicateRoute
