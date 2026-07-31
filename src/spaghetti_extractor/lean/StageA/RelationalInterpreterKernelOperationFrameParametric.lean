import StageA.RelationalInterpreterKernelStepNative

namespace StageA.Relational.InterpreterKernelOperationFrameParametric

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterNativeWorld

/-!
Generic frame/event/world-parametric operation refinement.

A standalone native operation starts with an empty logical call stack, event
index zero, and an empty event history.  A caller needs the same operation
below an existing call-frame tail and event prefix.  This module makes the
required simulation explicit:

* `NativeWorldFrameContext.embed` appends the caller frame tail and shifts the
  event context without changing machine state;
* standalone imported actions are selected from an environment reindexed by
  the caller event index;
* the operation producer selects one explicit fuel whose strict prefixes are
  running, event-index exact, and compatible with the caller return address;
* every selected pre-terminal standalone state refines one exact contextual
  step; and
* padded terminal paths and paths for incompatible caller frames cannot inhabit
  the selected-path interface.

None of these properties is assumed for every environment or program.  They
are fields of a certificate for the exact candidate operation.
-/

/-- Caller-owned execution context appended below a standalone operation. -/
structure NativeWorldFrameContext where
  frame : NativeCallFrame
  tail : List NativeCallFrame
  eventIndex : Nat
  eventPrefix : List NativeExternalEvent

/-- The logical caller frame must agree with the concrete hardware return word
already present at the callee entry stack pointer.  This is a call-site fact,
not a property of an arbitrary frame context. -/
def NativeWorldFrameContext.entryCompatible
    (context : NativeWorldFrameContext) (before : MachineState) : Prop :=
  Memory.read32 before.memory before.registers.esp =
    context.frame.returnAddress

/-- Embed one standalone execution under an existing frame and event context.
The returned case is the expected nested-call endpoint. -/
def NativeWorldFrameContext.embed
    (context : NativeWorldFrameContext) : NativeWorldExecution ->
      NativeWorldExecution
  | .running rva undefinedSlot state calls localIndex localEvents world =>
      .running rva undefinedSlot state
        (calls ++ context.frame :: context.tail)
        (context.eventIndex + localIndex)
        (context.eventPrefix ++ localEvents) world
  | .returned state localEvents world =>
      .running context.frame.continuationRva 0 state context.tail
        (context.eventIndex + localEvents.length)
        (context.eventPrefix ++ localEvents) world
  | .terminated localEvents world =>
      .terminated (context.eventPrefix ++ localEvents) world
  | .fault cause => .fault cause
  | .blocked reason => .blocked reason

def nativeWorldExecutionIsRunning : NativeWorldExecution -> Prop
  | .running .. => True
  | _ => False

/-- The native executor advances its external-event index once per recorded
import event.  The standalone-to-context embedding needs this equality when a
top-level return becomes a caller continuation. -/
def nativeWorldExecutionEventIndexExact : NativeWorldExecution -> Prop
  | .running _ _ _ _ eventIndex events _ => eventIndex = events.length
  | .returned .. | .terminated .. | .fault .. | .blocked .. => True

/-- Present a caller-indexed imported environment as a standalone local-index
environment.  This is the source of truth for imported action selection; no
global shift-invariance property is assumed. -/
def reindexNativeWorldEnvironment
    (environment : NativeWorldEnvironment) (offset : Nat) :
    NativeWorldEnvironment := {
  action := fun localIndex event world =>
    environment.action (offset + localIndex) event world
}

/-- Keep the exact candidate static semantics while reindexing imported
actions for one caller context. -/
def reindexExactNativeWorldProgram
    (candidate : ExactNativeWorldProgram) (offset : Nat) :
    ExactNativeWorldProgram := {
  candidate with
  environment := reindexNativeWorldEnvironment candidate.environment offset
}

/-- Callable external results still need explicit index stability because only
the imported `NativeWorldEnvironment` is reindexed.  Candidates with the
optional callable executor disabled discharge this condition vacuously. -/
structure NativeWorldFrameEnvironmentStable
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext) : Prop where
  callableResult : forall config,
    candidate.callableExternal = some config ->
      forall localIndex event,
        config.environment.result (context.eventIndex + localIndex) event =
          config.environment.result localIndex event

/-- A top-level hardware return may be redirected into the caller frame only
when its concrete return word agrees with that frame.  Nested returns already
have a standalone frame and therefore do not consult this condition. -/
def NativeWorldFrameReturnCompatibleAt
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (execution : NativeWorldExecution) : Prop :=
  match execution with
  | .running rva undefinedSlot state [] _ _ _ =>
      match stepKernelPE32Instruction candidate.pe candidate.imports
          (.running rva undefinedSlot state) with
      | .stopped (.returned target) _ =>
          target = context.frame.returnAddress
      | _ => True
  | _ => True

/-- A resolved callable tail requires an existing runtime continuation.  A
standalone execution with an empty call stack blocks, whereas the contextual
execution could consume the newly appended caller frame.  Such a step must be
excluded by exact path evidence rather than silently assigned contextual
semantics that the standalone executor does not have. -/
def NativeWorldFrameCallableTailCompatibleAt
    (candidate : ExactNativeWorldProgram)
    (execution : NativeWorldExecution) : Prop :=
  match execution with
  | .running rva undefinedSlot state [] _ _ world =>
      match stepKernelPE32Instruction candidate.pe candidate.imports
          (.running rva undefinedSlot state) with
      | .stopped (.indirectJump target) _ =>
          match candidate.indirectTargets.resolve? candidate.pe world rva .jump
              target with
          | some (.callableResource resourceId) =>
              match candidate.callableExternal with
              | none => True
              | some config =>
                  match resolveNativeCallableResource config world resourceId
                      target .jump with
                  | .callable .. => False
                  | _ => True
          | _ => True
      | _ => True
  | _ => True

/-- Exact one-step state refinement.  Observations are intentionally not
equated: a standalone top-level return is observable, while the corresponding
nested return is an internal continuation step. -/
def NativeWorldFrameStepRefinesAt
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (execution : NativeWorldExecution) : Prop :=
  (candidate.transitionSystem.step (context.embed execution)).next =
    context.embed
      ((reindexExactNativeWorldProgram candidate
        context.eventIndex).transitionSystem.step
        execution).next

/-- Exposed witness for one standalone dispatch path.  Unlike the ordinary
existential path interface, its fuel is available to a frame-refinement
certificate. -/
structure StandaloneNativeWorldPath
    (candidate : ExactNativeWorldProgram)
    (before after : NativeWorldExecution)
    (observations : List WorldRelationalObservable)
    (fuel : Nat) : Prop where
  positive : 0 < fuel
  exact :
    runRelatedSteps candidate.transitionSystem fuel before =
      (after, observations)

/-- The exact standalone path selected by the operation producer for one caller
context.  Fuel is data carried by this witness rather than a universally
quantified path parameter.  `prefixesRunning` rejects terminal padding;
`returnCompatible` rejects paths selected for a different concrete caller;
and `eventIndexExact` ties imported action selection to the exact event prefix.
-/
structure ProducerSelectedStandaloneNativeWorldPath
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (before after : NativeWorldExecution)
    (observations : List WorldRelationalObservable) where
  fuel : Nat
  path : StandaloneNativeWorldPath
    (reindexExactNativeWorldProgram candidate context.eventIndex)
    before after observations fuel
  prefixesRunning : forall consumed, consumed < fuel ->
    nativeWorldExecutionIsRunning
      (runRelatedSteps
        (reindexExactNativeWorldProgram candidate
          context.eventIndex).transitionSystem
        consumed before).1
  eventIndexExact : forall consumed, consumed < fuel ->
    nativeWorldExecutionEventIndexExact
      (runRelatedSteps
        (reindexExactNativeWorldProgram candidate
          context.eventIndex).transitionSystem
        consumed before).1
  returnCompatible : forall consumed, consumed < fuel ->
    NativeWorldFrameReturnCompatibleAt candidate context
      (runRelatedSteps
        (reindexExactNativeWorldProgram candidate
          context.eventIndex).transitionSystem
        consumed before).1

/-- Path-local hypotheses needed by the generic lifting theorem.  They are
required only for the producer-selected canonical path.

`stepRefines` is deliberately conditional on the explicit environment and
callable-tail hypotheses.  The selected path itself supplies running,
event-index, and caller-return compatibility. -/
structure NativeWorldFramePathRefinement
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    {before after : NativeWorldExecution}
    {observations : List WorldRelationalObservable}
    (selected : ProducerSelectedStandaloneNativeWorldPath candidate context
      before after observations) :
    Prop where
  environmentStable : NativeWorldFrameEnvironmentStable candidate context
  callableTailCompatible : forall consumed, consumed < selected.fuel ->
    NativeWorldFrameCallableTailCompatibleAt candidate
      (runRelatedSteps
        (reindexExactNativeWorldProgram candidate
          context.eventIndex).transitionSystem
        consumed before).1
  stepRefines : forall consumed (_beforeEnd : consumed < selected.fuel),
    nativeWorldExecutionIsRunning
      (runRelatedSteps
        (reindexExactNativeWorldProgram candidate
          context.eventIndex).transitionSystem
        consumed before).1 ->
    nativeWorldExecutionEventIndexExact
      (runRelatedSteps
        (reindexExactNativeWorldProgram candidate
          context.eventIndex).transitionSystem
        consumed before).1 ->
    NativeWorldFrameEnvironmentStable candidate context ->
    NativeWorldFrameReturnCompatibleAt candidate context
      (runRelatedSteps
        (reindexExactNativeWorldProgram candidate
          context.eventIndex).transitionSystem
        consumed before).1 ->
    NativeWorldFrameCallableTailCompatibleAt candidate
      (runRelatedSteps
        (reindexExactNativeWorldProgram candidate
          context.eventIndex).transitionSystem
        consumed before).1 ->
    NativeWorldFrameStepRefinesAt candidate context
      (runRelatedSteps
        (reindexExactNativeWorldProgram candidate
          context.eventIndex).transitionSystem
        consumed before).1

/-- State projection of a finite run is preserved by the context embedding
when every reached step refines. -/
theorem runRelatedSteps_frameContext_fst
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (before : NativeWorldExecution)
    (fuel : Nat)
    (stepRefines : forall consumed, consumed < fuel ->
      NativeWorldFrameStepRefinesAt candidate context
        (runRelatedSteps
          (reindexExactNativeWorldProgram candidate
            context.eventIndex).transitionSystem
          consumed before).1) :
    (runRelatedSteps candidate.transitionSystem fuel
      (context.embed before)).1 =
      context.embed
        (runRelatedSteps
          (reindexExactNativeWorldProgram candidate
            context.eventIndex).transitionSystem
          fuel before).1 := by
  induction fuel generalizing before with
  | zero => rfl
  | succ fuel induction =>
      have head := stepRefines 0 (Nat.zero_lt_succ fuel)
      simp only [runRelatedSteps] at head ⊢
      rw [head]
      apply induction
      intro consumed consumedBefore
      have refined :=
        stepRefines (consumed + 1) (Nat.succ_lt_succ consumedBefore)
      simpa only [runRelatedSteps, Nat.add_comm consumed 1] using refined

/-- Lift an exact standalone path into its caller context.  The contextual
observation list is computed from the exact transition system and is not
submitted by the certificate. -/
theorem ProducerSelectedStandaloneNativeWorldPath.liftFrameContext
    {candidate : ExactNativeWorldProgram}
    {context : NativeWorldFrameContext}
    {before after : NativeWorldExecution}
    {standaloneObservations : List WorldRelationalObservable}
    (selected : ProducerSelectedStandaloneNativeWorldPath candidate context
      before after standaloneObservations)
    (refinement : NativeWorldFramePathRefinement candidate context selected) :
    exists observations,
      NonemptyRelatedPath candidate.transitionSystem
        (context.embed before) observations (context.embed after) := by
  have stepRefines : forall consumed, consumed < selected.fuel ->
      NativeWorldFrameStepRefinesAt candidate context
        (runRelatedSteps
          (reindexExactNativeWorldProgram candidate
            context.eventIndex).transitionSystem
          consumed before).1 := by
    intro consumed beforeEnd
    exact refinement.stepRefines consumed beforeEnd
      (selected.prefixesRunning consumed beforeEnd)
      (selected.eventIndexExact consumed beforeEnd)
      refinement.environmentStable
      (selected.returnCompatible consumed beforeEnd)
      (refinement.callableTailCompatible consumed beforeEnd)
  have endpoint :=
    runRelatedSteps_frameContext_fst candidate context before selected.fuel
      stepRefines
  rw [selected.path.exact] at endpoint
  let contextual :=
    runRelatedSteps candidate.transitionSystem selected.fuel
      (context.embed before)
  refine ⟨contextual.2, selected.fuel, selected.path.positive, ?_⟩
  have firstExact : contextual.1 = context.embed after := by
    simpa [contextual] using endpoint
  exact Prod.ext firstExact rfl

/-- Standalone operation dispatch over the exact native-world executor. -/
def StandaloneNativeWorldDispatches
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld) :
    KernelDispatchRelation :=
  fun entryRva before after events =>
    exists afterWorld observations,
      NativeWorldDispatches candidate entryRva before world after events
        afterWorld observations

/-- The standalone result selected by the operation producer for this exact
caller context.  The selected path runs under the caller-indexed imported
environment and carries its canonical-fuel evidence. -/
structure ProducerSelectedStandaloneNativeWorldResult
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (world : RelationalWorld)
    (entryRva : Nat) (before after : MachineState)
    (events : List NativeExternalEvent) where
  afterWorld : RelationalWorld
  observations : List WorldRelationalObservable
  selected : ProducerSelectedStandaloneNativeWorldPath candidate context
    (.running entryRva 0 before [] 0 [] world)
    (.returned after events afterWorld) observations

def ProducerSelectedStandaloneNativeWorldDispatches
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (world : RelationalWorld) : KernelDispatchRelation :=
  fun entryRva before after events =>
    Nonempty (ProducerSelectedStandaloneNativeWorldResult candidate context
      world entryRva before after events)

/-- Detailed endpoint obtained by the generic frame lifting theorem. -/
structure FrameParametricNativeWorldResult
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (world : RelationalWorld)
    (entryRva : Nat) (before after : MachineState)
    (events : List NativeExternalEvent) where
  afterWorld : RelationalWorld
  observations : List WorldRelationalObservable
  path : NonemptyRelatedPath candidate.transitionSystem
    (context.embed (.running entryRva 0 before [] 0 [] world))
    observations
    (context.embed (.returned after events afterWorld))

def FrameParametricNativeWorldDispatches
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (world : RelationalWorld) : KernelDispatchRelation :=
  fun entryRva before after events =>
    Nonempty (FrameParametricNativeWorldResult candidate context world entryRva
      before after events)

/-- Operation refinement with one additional checked predicate on the concrete
entry state.  It is used for caller-frame facts that cannot soundly be
quantified over every possible frame independently of the request. -/
def KernelOperationRefinesUsingWhen
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (dispatches : KernelDispatchRelation) (operation : KernelOperation)
    (EntryCompatible : MachineState -> Prop) : Prop :=
  ∀ request before,
    request.operation = operation ->
    abi.requestRelated request before ->
    EntryCompatible before ->
    ∀ response,
      AbstractKernelTransition request response ->
      ∃ entryRva after nativeEvents,
        program.functionEntry? operation.role = some entryRva ∧
        dispatches entryRva before after nativeEvents ∧
        abi.responseRelated request response after nativeEvents ∧
        MemoryAgreesOutside (abi.scratchFootprint request)
          after.memory before.memory

/-- A call site discharges the concrete frame-entry condition for every
operation request it admits. -/
def KernelOperationFrameEntryAuthority
    (abi : KernelABIRelation) (operation : KernelOperation)
    (context : NativeWorldFrameContext) : Prop :=
  ∀ request before,
    request.operation = operation ->
    abi.requestRelated request before ->
    context.entryCompatible before

/-- Operation-level certificate.  `producer` selects a canonical standalone
path for the exact caller context used by the operation proof.
`selectedPathRefinement` qualifies only that producer-selected path; it does
not quantify over padded terminal paths or paths for incompatible callers. -/
structure KernelOperationFrameParametricCertificate
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram)
    (operation : KernelOperation) : Prop where
  producer : forall context world,
    KernelOperationRefinesUsingWhen program abi
      (ProducerSelectedStandaloneNativeWorldDispatches candidate context world)
      operation context.entryCompatible
  selectedPathRefinement : forall context world entryRva before after events
      afterWorld observations
    (selected : ProducerSelectedStandaloneNativeWorldPath candidate context
      (.running entryRva 0 before [] 0 [] world)
      (.returned after events afterWorld) observations),
    NativeWorldFramePathRefinement candidate context selected

theorem KernelOperationFrameParametricCertificate.refinesInContext
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {candidate : ExactNativeWorldProgram} {operation : KernelOperation}
    (certificate : KernelOperationFrameParametricCertificate program abi
      candidate operation)
    (context : NativeWorldFrameContext) (world : RelationalWorld)
    (entry : KernelOperationFrameEntryAuthority abi operation context) :
    KernelOperationRefinesUsing program abi
      (FrameParametricNativeWorldDispatches candidate context world)
      operation := by
  intro request before operationMatches requestRelated response transition
  have entryCompatible :=
    entry request before operationMatches requestRelated
  obtain ⟨entryRva, after, events, entryExact, dispatch, responseRelated,
      memoryFrame⟩ :=
    certificate.producer context world request before operationMatches
      requestRelated entryCompatible response transition
  obtain ⟨result⟩ := dispatch
  have refinement := certificate.selectedPathRefinement context world entryRva
    before after events result.afterWorld result.observations result.selected
  obtain ⟨contextualObservations, contextualPath⟩ :=
    result.selected.liftFrameContext refinement
  exact ⟨entryRva, after, events, entryExact, ⟨{
    afterWorld := result.afterWorld
    observations := contextualObservations
    path := contextualPath
  }⟩, responseRelated, memoryFrame⟩

#print axioms runRelatedSteps_frameContext_fst
#print axioms ProducerSelectedStandaloneNativeWorldPath.liftFrameContext
#print axioms KernelOperationRefinesUsingWhen
#print axioms KernelOperationFrameEntryAuthority
#print axioms KernelOperationFrameParametricCertificate.refinesInContext

end StageA.Relational.InterpreterKernelOperationFrameParametric
