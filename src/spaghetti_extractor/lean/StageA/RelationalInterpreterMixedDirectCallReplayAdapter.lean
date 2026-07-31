import StageA.RelationalInternalDirectCallComposition
import StageA.RelationalInterpreterMixedSemanticOperationComponent

namespace StageA.Relational.InterpreterMixedDirectCallReplayAdapter

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallComposition
open StageA.Relational.InterpreterMixedSemanticOperationComponent

/-!
# Exact direct-call summary replay

`ActualDirectCallReturnExecution` contains two pieces of executable evidence:

* the exact decoded call-entry transition; and
* a `WorldCallRun` whose every successor is the canonical decoded PE
  transition and whose endpoint is the checked continuation.

This module converts those facts into the finite-path representation consumed
by mixed semantic-operation composition. It never accepts a submitted fuel,
endpoint, observation list, or `NonemptyRelatedPath`.
-/

/-- A `WorldCallRun` is exactly a possibly-empty execution of the decoded PE
transition system. The witness fuel is hidden existentially because
`WorldCallRun` is proof evidence rather than an executable trace datatype. -/
theorem WorldCallRun.existsRunRelatedStepsExact
    {program : DecodedWorldProgram} {continuationTargetId : Nat}
    {before : WorldExecution} {observations : List WorldRelationalObservable}
    {after : WorldExecution}
    (run : WorldCallRun program continuationTargetId before observations after) :
    exists fuel,
      runRelatedSteps program.pe32TransitionSystem fuel before =
        (after, observations) := by
  induction run with
  | doneRunning =>
      exact ⟨0, rfl⟩
  | doneCallback =>
      exact ⟨0, rfl⟩
  | step notAtContinuation mayProgress tail induction =>
      rcases induction with ⟨fuel, tailExact⟩
      refine ⟨Nat.succ fuel, ?_⟩
      simp only [runRelatedSteps]
      rw [tailExact]

/-- Prefix the exact call-entry transition to the checked callee/return run.
The resulting path is nonempty even when the callee entry is already the
declared continuation. -/
theorem ActualDirectCallReturnExecution.originalNonemptyRelatedPath
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution context tree binding
      originalProgram candidateProgram) :
    NonemptyRelatedPath originalProgram.pe32TransitionSystem
      actual.source.original.execution actual.originalObservations
      actual.originalExit.execution := by
  rcases WorldCallRun.existsRunRelatedStepsExact actual.originalRun with
    ⟨calleeFuel, calleeRunExact⟩
  refine ⟨Nat.succ calleeFuel, Nat.zero_lt_succ calleeFuel, ?_⟩
  simp only [runRelatedSteps, actual.originalCallStep]
  rw [calleeRunExact]
  simp

/-- Retained replay artifact used by the semantic-operation bridge. Its path
fuel is selected only from the theorem above, and its endpoint and observations
are tied back to the operational direct-call certificate. -/
structure CheckedOriginalDirectCallReplay
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution context tree binding
      originalProgram candidateProgram) where
  path : CheckedOriginalSemanticOperationPath originalProgram
    actual.source.original.execution
  afterExact : path.after = actual.originalExit.execution
  observationsExact : path.observations = actual.originalObservations

/-- Construct the retained replay from exact operational evidence. No caller
chooses the replay length or states an independent path proposition. -/
noncomputable def ActualDirectCallReturnExecution.checkedOriginalReplay
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution context tree binding
      originalProgram candidateProgram) :
    CheckedOriginalDirectCallReplay actual := by
  let replayProof :=
    ActualDirectCallReturnExecution.originalNonemptyRelatedPath actual
  let fuel := Classical.choose replayProof
  have fuelFacts := Classical.choose_spec replayProof
  let path : CheckedOriginalSemanticOperationPath originalProgram
      actual.source.original.execution := {
    fuel
    positive := fuelFacts.1
  }
  have resultExact :
      path.result =
        (actual.originalExit.execution, actual.originalObservations) := by
    exact fuelFacts.2
  exact {
    path
    afterExact := congrArg Prod.fst resultExact
    observationsExact := congrArg Prod.snd resultExact
  }

theorem CheckedOriginalDirectCallReplay.nonemptyPath
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    {actual : ActualDirectCallReturnExecution context tree binding
      originalProgram candidateProgram}
    (replay : CheckedOriginalDirectCallReplay actual) :
    NonemptyRelatedPath originalProgram.pe32TransitionSystem
      actual.source.original.execution replay.path.observations
      replay.path.after :=
  replay.path.path

/-- Runtime-context facts required by
`CheckedOriginalDirectCallReturnCluster`.

The existing operational direct-call certificate already records target,
machine-state, call-stack, and relational-world restoration. It does not record
the corresponding event-index and callback-stack equalities. They are explicit
here so an external call or callback transition cannot be silently treated as a
pure internal call/return cluster. -/
structure CheckedOriginalDirectCallRuntimeContextRestored
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution context tree binding
      originalProgram candidateProgram) : Prop where
  entryEventIndex :
    actual.originalEntry.eventIndex = actual.source.original.eventIndex
  entryCallbacks :
    actual.originalEntry.callbacks = actual.source.original.callbacks
  exitEventIndex :
    actual.originalExit.eventIndex = actual.source.original.eventIndex
  exitCallbacks :
    actual.originalExit.callbacks = actual.source.original.callbacks

/-- Recover the exact running or callback-running cluster shape. The case split
is performed on the checked source point; no execution mode is submitted by a
caller. -/
noncomputable def CheckedOriginalDirectCallReplay.cluster
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    {actual : ActualDirectCallReturnExecution context tree binding
      originalProgram candidateProgram}
    (replay : CheckedOriginalDirectCallReplay actual)
    (restored : CheckedOriginalDirectCallRuntimeContextRestored actual) :
    CheckedOriginalDirectCallReturnCluster originalProgram
      actual.source.original.execution replay.path := by
  cases sourceCallbacks : actual.source.original.callbacks with
  | none =>
      apply CheckedOriginalDirectCallReturnCluster.running
        binding.sourceTargetId binding.continuationTargetId binding.calleeTargetId
        actual.source.original.state actual.originalEntry.state
        actual.originalExit.state actual.source.original.calls
        actual.source.original.eventIndex actual.source.original.world
      · simp [WorldExecutionPoint.execution, sourceCallbacks,
          actual.source.originalTarget]
      · rw [actual.originalCallStep]
        simp only [WorldExecutionPoint.execution]
        rw [restored.entryCallbacks, sourceCallbacks]
        simp only
        rw [actual.originalEntryTarget, actual.originalEntryCalls,
          restored.entryEventIndex, actual.entryWorld.1]
      · rw [replay.afterExact]
        simp only [WorldExecutionPoint.execution]
        rw [restored.exitCallbacks, sourceCallbacks]
        simp only
        rw [actual.originalExitTarget, actual.originalExitCalls,
          restored.exitEventIndex, actual.exitWorld.1]
  | some callbacks =>
      apply CheckedOriginalDirectCallReturnCluster.callbackRunning
        binding.sourceTargetId binding.continuationTargetId binding.calleeTargetId
        actual.source.original.state actual.originalEntry.state
        actual.originalExit.state actual.source.original.calls
        actual.source.original.eventIndex actual.source.original.world callbacks
      · simp [WorldExecutionPoint.execution, sourceCallbacks,
          actual.source.originalTarget]
      · rw [actual.originalCallStep]
        simp only [WorldExecutionPoint.execution]
        rw [restored.entryCallbacks, sourceCallbacks]
        simp only
        rw [actual.originalEntryTarget, actual.originalEntryCalls,
          restored.entryEventIndex, actual.entryWorld.1]
      · rw [replay.afterExact]
        simp only [WorldExecutionPoint.execution]
        rw [restored.exitCallbacks, sourceCallbacks]
        simp only
        rw [actual.originalExitTarget, actual.originalExitCalls,
          restored.exitEventIndex, actual.exitWorld.1]

noncomputable def CheckedOriginalDirectCallReplay.pathShape
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    {actual : ActualDirectCallReturnExecution context tree binding
      originalProgram candidateProgram}
    (replay : CheckedOriginalDirectCallReplay actual)
    (restored : CheckedOriginalDirectCallRuntimeContextRestored actual) :
    CheckedOriginalSemanticOperationPathShape originalProgram
      actual.source.original.execution replay.path :=
  .directCallReturn (replay.cluster restored)

end StageA.Relational.InterpreterMixedDirectCallReplayAdapter
