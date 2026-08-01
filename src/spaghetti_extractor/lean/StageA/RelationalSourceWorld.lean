import StageA.RelationalC0
import StageA.RelationalCertificates

namespace StageA.Relational.SourceWorld

open StageA.Formal
open StageA.Relational.Interpreter

/-!
One-sided exact-PE to source-kernel composition.

The source side deliberately has a distinct state type, but its correspondence
with `WorldExecution` is fixed here.  A generated certificate cannot choose an
arbitrary relation that forgets machine state, control state, the runtime call
stack, event position, callbacks, faults, termination, or the relational
world.

The source kernel remains an explicit semantic input.  Binding a rendered
source project and its compiled artifact to that kernel is a separate compiler
correctness obligation; this module proves only the exact-PE-to-kernel layer.
-/

/-- A logical root is the initial running entry of the selected side of a
decoded program.  Calls and observations start empty; the code-map witness
ties the target identifier to the exact parsed PE entrypoint. -/
def WorldExecution.IsProgramEntry (program : DecodedWorldProgram) :
    WorldExecution -> Prop
  | .running targetId _ calls eventIndex _ =>
      calls = [] /\ eventIndex = 0 /\
        exists target,
          program.context.codeMap.get? targetId = some target /\
            (if program.candidate then target.candidateRva
              else target.originalRva) =
              (if program.candidate then
                program.context.candidatePe.entrypointRva
              else program.context.originalPe.entrypointRva)
  | _ => False

/-- Source-kernel execution state with the same whole-program control and
external-world vocabulary as exact PE execution. -/
inductive Execution where
  | running (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
  | returned (state : MachineState) (world : RelationalWorld)
  | terminated (world : RelationalWorld)
  | awaitingExternal (suspension : WorldExternalSuspension)
      (callbacks : List WorldExternalCallbackRuntime)
  | callbackRunning (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (callbacks : List WorldExternalCallbackRuntime)
  | fault (cause : ModeledFault)
  | blocked (reason : ExecutionBlock)

/-- Forget only the source-kernel wrapper.  Every semantically relevant field
is retained. -/
def Execution.toWorldExecution : Execution -> WorldExecution
  | .running targetId state calls eventIndex world =>
      .running targetId state calls eventIndex world
  | .returned state world => .returned state world
  | .terminated world => .terminated world
  | .awaitingExternal suspension callbacks =>
      .awaitingExternal suspension callbacks
  | .callbackRunning targetId state calls eventIndex world callbacks =>
      .callbackRunning targetId state calls eventIndex world callbacks
  | .fault cause => .fault cause
  | .blocked reason => .blocked reason

/-- Introduce the source-kernel wrapper without changing any execution data. -/
def Execution.ofWorldExecution : WorldExecution -> Execution
  | .running targetId state calls eventIndex world =>
      .running targetId state calls eventIndex world
  | .returned state world => .returned state world
  | .terminated world => .terminated world
  | .awaitingExternal suspension callbacks =>
      .awaitingExternal suspension callbacks
  | .callbackRunning targetId state calls eventIndex world callbacks =>
      .callbackRunning targetId state calls eventIndex world callbacks
  | .fault cause => .fault cause
  | .blocked reason => .blocked reason

@[simp]
theorem Execution.toWorldExecution_ofWorldExecution (execution : WorldExecution) :
    (Execution.ofWorldExecution execution).toWorldExecution = execution := by
  cases execution <;> rfl

@[simp]
theorem Execution.ofWorldExecution_toWorldExecution (execution : Execution) :
    Execution.ofWorldExecution execution.toWorldExecution = execution := by
  cases execution <;> rfl

/-- Original-to-source observations are exact because the semantic source
kernel carries the original abstract machine state.  A proof block is not a
program behavior and is therefore unrelated even to an identical marker. -/
def sourceObservationsRelated :
    Option WorldRelationalObservable -> Option WorldRelationalObservable -> Prop
  | some (.proofBlocked _), _ => False
  | _, some (.proofBlocked _) => False
  | original, source => original = source

theorem sourceObservationsRelated_refl
    (observation : Option WorldRelationalObservable)
    (proofOpen : forall reason, observation ≠ some (.proofBlocked reason)) :
    sourceObservationsRelated observation observation := by
  cases observation with
  | none => rfl
  | some observed =>
      cases observed <;> simp_all [sourceObservationsRelated]

/-- A rooted invariant over exact original-PE execution.  The root is explicit
in the type so a later launch theorem must select it, while `stepClosed` proves
that the domain contains every state reached from that root. -/
structure CheckedExecutionDomain (program : DecodedWorldProgram)
    (root : WorldExecution) where
  holds : WorldExecution -> Prop
  rootHolds : holds root
  stepClosed : forall before,
    holds before -> holds (program.pe32TransitionSystem.step before).next

theorem CheckedExecutionDomain.runRelatedSteps
    {program : DecodedWorldProgram} {root : WorldExecution}
    (domain : CheckedExecutionDomain program root)
    (fuel : Nat) (before : WorldExecution)
    (beforeHolds : domain.holds before) :
    domain.holds
      (StageA.Relational.runRelatedSteps program.pe32TransitionSystem fuel
        before).1 := by
  induction fuel generalizing before with
  | zero =>
      simpa [StageA.Relational.runRelatedSteps] using beforeHolds
  | succ fuel induction =>
      simp only [StageA.Relational.runRelatedSteps]
      exact induction (program.pe32TransitionSystem.step before).next
        (domain.stepClosed before beforeHolds)

theorem CheckedExecutionDomain.pathClosed
    {program : DecodedWorldProgram} {root before after : WorldExecution}
    (domain : CheckedExecutionDomain program root)
    {observations : List WorldRelationalObservable}
    (beforeHolds : domain.holds before)
    (path : NonemptyRelatedPath program.pe32TransitionSystem before
      observations after) :
    domain.holds after := by
  rcases path with ⟨fuel, _positive, exactRun⟩
  have holds := domain.runRelatedSteps fuel before beforeHolds
  rw [exactRun] at holds
  exact holds

/-- The sole state correspondence accepted by this layer.  Exact projection is
conjoined with membership in a checked domain rooted in original execution. -/
def ExecutionsMatch {program : DecodedWorldProgram} {root : WorldExecution}
    (domain : CheckedExecutionDomain program root)
    (original : WorldExecution) (source : Execution) : Prop :=
  source.toWorldExecution = original ∧ domain.holds original

theorem ExecutionsMatch.exact
    {program : DecodedWorldProgram} {root : WorldExecution}
    (domain : CheckedExecutionDomain program root)
    (original : WorldExecution) (member : domain.holds original) :
    ExecutionsMatch domain original (.ofWorldExecution original) := by
  exact ⟨by simp, member⟩

theorem ExecutionsMatch.root
    {program : DecodedWorldProgram} {root : WorldExecution}
    (domain : CheckedExecutionDomain program root) :
    ExecutionsMatch domain root (.ofWorldExecution root) :=
  ExecutionsMatch.exact domain root domain.rootHolds

/-- One source-kernel transition.  Interpreter events and completion are kept
alongside the externally observable transition so source/compiler bindings do
not have to reconstruct them from a projected trace. -/
structure KernelTransition where
  next : Execution
  observation : Option WorldRelationalObservable
  macroResult : Option MacroResult
  interpreterEvents : List InterpreterEvent
  completion : Option Completion
  metadataExact :
    match macroResult with
    | none => interpreterEvents = [] ∧ completion = none
    | some result =>
        interpreterEvents = result.events ∧ completion = some result.completion

/-- A source semantic kernel.  The record inventory and interpreter environment
are retained as first-class inputs for a later checked source binding; the
whole-program transition is world-aware and therefore is not reduced to the
current flat `Source.sourceStep` API. -/
structure Kernel where
  records : List ProgramRecord
  environment : Interpreter.Environment
  step : Execution -> KernelTransition

def Kernel.transitionSystem (kernel : Kernel) :
    RelatedTransitionSystem Execution WorldRelationalObservable := {
  step := fun execution =>
    let transition := kernel.step execution
    { next := transition.next, observation := transition.observation }
}

/-- Explicit compatibility obligation for source profiles that use the current
flat `ProgramRecord.interpret` entry point.  It is intentionally separate from
whole-program composition: calls, callbacks, and external-world updates need a
richer binding than this interface can express. -/
structure ActiveInterpreterBinding (kernel : Kernel) : Prop where
  running : forall targetId state calls eventIndex world,
    exists result,
      (kernel.step (.running targetId state calls eventIndex world)).macroResult =
          some result ∧
        Source.sourceStep kernel.records targetId kernel.environment state =
          some result
  callbackRunning : forall targetId state calls eventIndex world callbacks,
    exists result,
      (kernel.step (.callbackRunning targetId state calls eventIndex world
        callbacks)).macroResult = some result ∧
        Source.sourceStep kernel.records targetId kernel.environment state =
          some result

/-- The trace retained while executing source-kernel transitions. -/
structure KernelPathResult where
  next : Execution
  observations : List WorldRelationalObservable
  interpreterEvents : List InterpreterEvent
  completions : List Completion

def runKernelSteps (kernel : Kernel) : Nat -> Execution -> KernelPathResult
  | 0, execution => {
      next := execution
      observations := []
      interpreterEvents := []
      completions := []
    }
  | fuel + 1, execution =>
      let transition := kernel.step execution
      let tail := runKernelSteps kernel fuel transition.next
      {
        next := tail.next
        observations := transition.observation.toList ++ tail.observations
        interpreterEvents := transition.interpreterEvents ++ tail.interpreterEvents
        completions := transition.completion.toList ++ tail.completions
      }

theorem runKernelSteps_projects (kernel : Kernel) :
    forall fuel execution,
      runRelatedSteps kernel.transitionSystem fuel execution =
        ((runKernelSteps kernel fuel execution).next,
          (runKernelSteps kernel fuel execution).observations) := by
  intro fuel
  induction fuel with
  | zero =>
      intro execution
      rfl
  | succ fuel induction =>
      intro execution
      simp only [runRelatedSteps, runKernelSteps, Kernel.transitionSystem]
      have tail := induction (kernel.step execution).next
      simp only [Kernel.transitionSystem] at tail
      rw [tail]

/-- A positive source path retaining both externally observable events and the
interpreter-level event/completion evidence used by source bindings. -/
def NonemptyKernelPath (kernel : Kernel) (before : Execution)
    (observations : List WorldRelationalObservable)
    (interpreterEvents : List InterpreterEvent) (completions : List Completion)
    (after : Execution) : Prop :=
  exists fuel, 0 < fuel ∧ runKernelSteps kernel fuel before = {
    next := after
    observations
    interpreterEvents
    completions
  }

theorem NonemptyKernelPath.toRelatedPath {kernel : Kernel}
    {before after : Execution} {observations : List WorldRelationalObservable}
    {interpreterEvents : List InterpreterEvent}
    {completions : List Completion}
    (path : NonemptyKernelPath kernel before observations interpreterEvents
      completions after) :
    NonemptyRelatedPath kernel.transitionSystem before observations after := by
  rcases path with ⟨fuel, positive, executed⟩
  refine ⟨fuel, positive, ?_⟩
  rw [runKernelSteps_projects]
  rw [executed]

/-- One checked heterogeneous chunk.  Both paths are concrete positive paths;
the observation relation is the repository's fail-closed world relation, and
the successor state relation is fixed by `ExecutionsMatch`. -/
structure ExactOriginalPEChunk (original : DecodedWorldProgram)
    (kernel : Kernel) (root : WorldExecution)
    (domain : CheckedExecutionDomain original root)
    (originalBefore : WorldExecution)
    (sourceBefore : Execution) where
  originalObservations : List WorldRelationalObservable
  sourceObservations : List WorldRelationalObservable
  sourceInterpreterEvents : List InterpreterEvent
  sourceCompletions : List Completion
  originalAfter : WorldExecution
  sourceAfter : Execution
  originalPath : NonemptyRelatedPath original.pe32TransitionSystem
    originalBefore originalObservations originalAfter
  sourcePath : NonemptyKernelPath kernel sourceBefore sourceObservations
    sourceInterpreterEvents sourceCompletions sourceAfter
  observationsRelated : RelatedObservationLists sourceObservationsRelated
    originalObservations sourceObservations
  afterProjection : sourceAfter.toWorldExecution = originalAfter

/-- A total chunk producer.  This is the compositional proof object generated
from local semantic certificates and graph closure. -/
structure ChunkComposition (original : DecodedWorldProgram)
    (kernel : Kernel) (root : WorldExecution)
    (domain : CheckedExecutionDomain original root) where
  chunk : forall originalBefore sourceBefore,
    ExecutionsMatch domain originalBefore sourceBefore ->
      ExactOriginalPEChunk original kernel root domain originalBefore sourceBefore

/-- Acceptance-facing logical equivalence between exact PE execution and the
source kernel. -/
def ExactOriginalPESourceKernelObservationallyEquivalent
    (original : DecodedWorldProgram) (kernel : Kernel)
    (root : WorldExecution)
    (domain : CheckedExecutionDomain original root) : Prop :=
  ChunkedRelationalBisimulation original.pe32TransitionSystem
    kernel.transitionSystem (ExecutionsMatch domain)
    sourceObservationsRelated

theorem ChunkComposition.chunksRefine {original : DecodedWorldProgram}
    {kernel : Kernel} {root : WorldExecution}
    {domain : CheckedExecutionDomain original root}
    (composition : ChunkComposition original kernel root domain) :
    ExactOriginalPESourceKernelObservationallyEquivalent original kernel
      root domain := by
  intro originalBefore sourceBefore beforeMatches
  let chunk := composition.chunk originalBefore sourceBefore beforeMatches
  exact ⟨chunk.originalObservations, chunk.sourceObservations,
    chunk.originalAfter, chunk.sourceAfter, chunk.originalPath,
    chunk.sourcePath.toRelatedPath, chunk.observationsRelated,
    ⟨chunk.afterProjection,
      domain.pathClosed beforeMatches.2 chunk.originalPath⟩⟩

theorem ChunkComposition.relatedTrace {original : DecodedWorldProgram}
    {kernel : Kernel} {root : WorldExecution}
    {domain : CheckedExecutionDomain original root}
    (composition : ChunkComposition original kernel root domain) :
    forall fuel originalExecution sourceExecution,
      ExecutionsMatch domain originalExecution sourceExecution ->
        ChunkedRelatedTrace original.pe32TransitionSystem kernel.transitionSystem
          (ExecutionsMatch domain)
          sourceObservationsRelated
          fuel originalExecution sourceExecution :=
  chunkedRelationalBisimulation_trace original.pe32TransitionSystem
    kernel.transitionSystem (ExecutionsMatch domain)
    sourceObservationsRelated
    composition.chunksRefine

/-- Start the chunked simulation at the checked domain root.  The source root
must project exactly to that root; domain membership is supplied only by the
checked domain certificate. -/
theorem ChunkComposition.rootedTrace {original : DecodedWorldProgram}
    {kernel : Kernel} {root : WorldExecution}
    {domain : CheckedExecutionDomain original root}
    (composition : ChunkComposition original kernel root domain)
    (fuel : Nat) (sourceRoot : Execution)
    (sourceRootExact : sourceRoot.toWorldExecution = root) :
    ChunkedRelatedTrace original.pe32TransitionSystem kernel.transitionSystem
      (ExecutionsMatch domain)
      sourceObservationsRelated
      fuel root sourceRoot := by
  exact composition.relatedTrace fuel root sourceRoot
    ⟨sourceRootExact, domain.rootHolds⟩

end StageA.Relational.SourceWorld
