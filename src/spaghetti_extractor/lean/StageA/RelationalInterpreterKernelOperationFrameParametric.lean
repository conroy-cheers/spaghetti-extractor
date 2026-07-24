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
* external actions must be stable at the shifted event index, including their
  successor worlds;
* every pre-terminal standalone state must refine one exact contextual step;
* a top-level machine return must agree with the supplied logical frame; and
* the standalone path must not contain terminal stuttering before its endpoint.

None of these properties is assumed for every environment or program.  They
are fields of a certificate for the exact candidate operation.
-/

/-- Caller-owned execution context appended below a standalone operation. -/
structure NativeWorldFrameContext where
  frame : NativeCallFrame
  tail : List NativeCallFrame
  eventIndex : Nat
  eventPrefix : List NativeExternalEvent

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

/-- Exact stability required when a standalone event at local index `i` is
replayed at caller index `context.eventIndex + i`.  Equality includes the
returned machine state and successor world.  Callable external results use
the same condition when that optional executor is enabled. -/
structure NativeWorldFrameEnvironmentStable
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext) : Prop where
  importedAction : forall localIndex event world,
    candidate.environment.action (context.eventIndex + localIndex) event world =
      candidate.environment.action localIndex event world
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
          if candidate.indirectTargets.allows candidate.pe world rva .jump
              target != true then
            True
          else
            match candidate.callableExternal with
            | none => True
            | some config =>
                match resolveNativeCallableIndirect candidate.pe config world
                    target .jump with
                | .callable .. => False
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
    context.embed (candidate.transitionSystem.step execution).next

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

/-- Path-local hypotheses needed by the generic lifting theorem.  They are
required only at states reached before this exact endpoint.

`stepRefines` is deliberately conditional on the explicit environment and
return hypotheses.  A future generic executor theorem can discharge it once
for the supported native semantics; generated operation proofs cannot bypass
either condition. -/
structure NativeWorldFramePathRefinement
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    {before after : NativeWorldExecution}
    {observations : List WorldRelationalObservable}
    {fuel : Nat}
    (path : StandaloneNativeWorldPath candidate before after observations fuel) :
    Prop where
  environmentStable : NativeWorldFrameEnvironmentStable candidate context
  prefixesRunning : forall consumed, consumed < fuel ->
    nativeWorldExecutionIsRunning
      (runRelatedSteps candidate.transitionSystem consumed before).1
  eventIndexExact : forall consumed, consumed < fuel ->
    nativeWorldExecutionEventIndexExact
      (runRelatedSteps candidate.transitionSystem consumed before).1
  returnCompatible : forall consumed, consumed < fuel ->
    NativeWorldFrameReturnCompatibleAt candidate context
      (runRelatedSteps candidate.transitionSystem consumed before).1
  callableTailCompatible : forall consumed, consumed < fuel ->
    NativeWorldFrameCallableTailCompatibleAt candidate
      (runRelatedSteps candidate.transitionSystem consumed before).1
  stepRefines : forall consumed (beforeEnd : consumed < fuel),
    nativeWorldExecutionIsRunning
      (runRelatedSteps candidate.transitionSystem consumed before).1 ->
    nativeWorldExecutionEventIndexExact
      (runRelatedSteps candidate.transitionSystem consumed before).1 ->
    NativeWorldFrameEnvironmentStable candidate context ->
    NativeWorldFrameReturnCompatibleAt candidate context
      (runRelatedSteps candidate.transitionSystem consumed before).1 ->
    NativeWorldFrameCallableTailCompatibleAt candidate
      (runRelatedSteps candidate.transitionSystem consumed before).1 ->
    NativeWorldFrameStepRefinesAt candidate context
      (runRelatedSteps candidate.transitionSystem consumed before).1

/-- State projection of a finite run is preserved by the context embedding
when every reached step refines. -/
theorem runRelatedSteps_frameContext_fst
    (candidate : ExactNativeWorldProgram)
    (context : NativeWorldFrameContext)
    (before : NativeWorldExecution)
    (fuel : Nat)
    (stepRefines : forall consumed, consumed < fuel ->
      NativeWorldFrameStepRefinesAt candidate context
        (runRelatedSteps candidate.transitionSystem consumed before).1) :
    (runRelatedSteps candidate.transitionSystem fuel
      (context.embed before)).1 =
      context.embed
        (runRelatedSteps candidate.transitionSystem fuel before).1 := by
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
theorem StandaloneNativeWorldPath.liftFrameContext
    {candidate : ExactNativeWorldProgram}
    {context : NativeWorldFrameContext}
    {before after : NativeWorldExecution}
    {standaloneObservations : List WorldRelationalObservable}
    {fuel : Nat}
    (path : StandaloneNativeWorldPath candidate before after
      standaloneObservations fuel)
    (refinement : NativeWorldFramePathRefinement candidate context path) :
    exists observations,
      NonemptyRelatedPath candidate.transitionSystem
        (context.embed before) observations (context.embed after) := by
  have stepRefines : forall consumed, consumed < fuel ->
      NativeWorldFrameStepRefinesAt candidate context
        (runRelatedSteps candidate.transitionSystem consumed before).1 := by
    intro consumed beforeEnd
    exact refinement.stepRefines consumed beforeEnd
      (refinement.prefixesRunning consumed beforeEnd)
      (refinement.eventIndexExact consumed beforeEnd)
      refinement.environmentStable
      (refinement.returnCompatible consumed beforeEnd)
      (refinement.callableTailCompatible consumed beforeEnd)
  have endpoint :=
    runRelatedSteps_frameContext_fst candidate context before fuel stepRefines
  rw [path.exact] at endpoint
  let contextual :=
    runRelatedSteps candidate.transitionSystem fuel
      (context.embed before)
  refine ⟨contextual.2, fuel, path.positive, ?_⟩
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

/-- Operation-level certificate.  `standalone` retains the existing operation
proof.  `contextRefinement` is the exact smaller upstream hypothesis: qualify
the concrete standalone path at every requested caller context. -/
structure KernelOperationFrameParametricCertificate
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram)
    (operation : KernelOperation) : Prop where
  standalone : forall world,
    KernelOperationRefinesUsing program abi
      (StandaloneNativeWorldDispatches candidate world) operation
  contextRefinement : forall context world entryRva before after events
      afterWorld observations fuel
      (path : StandaloneNativeWorldPath candidate
        (.running entryRva 0 before [] 0 [] world)
        (.returned after events afterWorld) observations fuel),
    NativeWorldFramePathRefinement candidate context path

theorem KernelOperationFrameParametricCertificate.refinesInContext
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {candidate : ExactNativeWorldProgram} {operation : KernelOperation}
    (certificate : KernelOperationFrameParametricCertificate program abi
      candidate operation)
    (context : NativeWorldFrameContext) (world : RelationalWorld) :
    KernelOperationRefinesUsing program abi
      (FrameParametricNativeWorldDispatches candidate context world)
      operation := by
  intro request before operationMatches requestRelated response transition
  obtain ⟨entryRva, after, events, entryExact, dispatch, responseRelated,
      memoryFrame⟩ :=
    certificate.standalone world request before operationMatches requestRelated
      response transition
  obtain ⟨afterWorld, observations, standalonePath⟩ := dispatch
  obtain ⟨fuel, positive, exact⟩ := standalonePath
  have path : StandaloneNativeWorldPath candidate
      (.running entryRva 0 before [] 0 [] world)
      (.returned after events afterWorld) observations fuel := {
    positive
    exact
  }
  have refinement := certificate.contextRefinement context world entryRva before
    after events afterWorld observations fuel path
  obtain ⟨contextualObservations, contextualPath⟩ :=
    path.liftFrameContext refinement
  exact ⟨entryRva, after, events, entryExact, ⟨{
    afterWorld
    observations := contextualObservations
    path := contextualPath
  }⟩, responseRelated, memoryFrame⟩

#print axioms runRelatedSteps_frameContext_fst
#print axioms StandaloneNativeWorldPath.liftFrameContext
#print axioms KernelOperationFrameParametricCertificate.refinesInContext

end StageA.Relational.InterpreterKernelOperationFrameParametric
