import StageA.RelationalInterpreterMixedSemanticOperationComponent
import StageA.RelationalInterpreterSemanticRefinement

namespace StageA.Relational.InterpreterMixedOriginalSemanticReplay

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedSemanticOperationComponent
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterSemanticRefinement
open StageA.Relational.InterpreterTransfer

/-!
# Bounded ordinary original semantic replay

This module closes the operational bookkeeping between an exact ordinary
decoded source and the one-step original replay used by mixed kernel
composition. The replay fuel, endpoint, and observations are computed.

The remaining semantic premise is deliberately engine-level:
`ExactOriginalSemanticSequentialFusion` equates the concrete machine produced
by the normalization runner with the concrete evaluation of the independently
fetched symbolic PE span. It is universal in the input state and interpreter
environment. It is not an equality for a submitted world endpoint or path.

The bounded profile excludes x87, external transfers, calls, deferred bulk
effects, and failing checked continuations. Direct calls require the existing
finite call/return replay adapter instead of a one-step endpoint.
-/

/-- Exact running mode at one decoded source. The callback stack is retained,
so a callback execution cannot be silently reclassified as ordinary running
execution. -/
inductive ExactOriginalSemanticBefore (sourceTargetId : Nat) :
    WorldExecution -> Type where
  | running (state : MachineState) (calls : List Nat) (eventIndex : Nat)
      (world : RelationalWorld) :
      ExactOriginalSemanticBefore sourceTargetId
        (.running sourceTargetId state calls eventIndex world)
  | callbackRunning (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (callbacks : List WorldExternalCallbackRuntime) :
      ExactOriginalSemanticBefore sourceTargetId
        (.callbackRunning sourceTargetId state calls eventIndex world callbacks)

def ExactOriginalSemanticBefore.state
    (before : ExactOriginalSemanticBefore sourceTargetId execution) :
    MachineState :=
  match before with
  | .running state .. | .callbackRunning state .. => state

def ExactOriginalSemanticBefore.calls
    (before : ExactOriginalSemanticBefore sourceTargetId execution) :
    List Nat :=
  match before with
  | .running _ calls .. | .callbackRunning _ calls .. => calls

def ExactOriginalSemanticBefore.eventIndex
    (before : ExactOriginalSemanticBefore sourceTargetId execution) : Nat :=
  match before with
  | .running _ _ eventIndex .. | .callbackRunning _ _ eventIndex .. =>
      eventIndex

def ExactOriginalSemanticBefore.world
    (before : ExactOriginalSemanticBefore sourceTargetId execution) :
    RelationalWorld :=
  match before with
  | .running _ _ _ world | .callbackRunning _ _ _ world _ => world

def ExactOriginalSemanticBefore.callbacks
    (before : ExactOriginalSemanticBefore sourceTargetId execution) :
    List WorldExternalCallbackRuntime :=
  match before with
  | .running .. => []
  | .callbackRunning _ _ _ _ callbacks => callbacks

/-- Recover the exact execution mode from the classifier's source predicate.
No machine state or execution constructor is supplied separately. -/
theorem ExactOriginalSemanticBefore.ofAtSource
    (atSource : originalExecutionAtTargetId sourceTargetId execution) :
    Nonempty (ExactOriginalSemanticBefore sourceTargetId execution) := by
  cases execution with
  | running targetId state calls eventIndex world =>
      simp only [originalExecutionAtTargetId] at atSource
      subst targetId
      exact ⟨.running state calls eventIndex world⟩
  | callbackRunning targetId state calls eventIndex world callbacks =>
      simp only [originalExecutionAtTargetId] at atSource
      subst targetId
      exact ⟨.callbackRunning state calls eventIndex world callbacks⟩
  | returned | terminated | awaitingExternal | fault | blocked =>
      simp [originalExecutionAtTargetId] at atSource

/-- Symbolic outcomes for which a single original world step can retain the
ordinary record machine. Calls are excluded because their record semantics
executes the callee while the world step only enters it. -/
inductive BoundedOrdinarySymbolicOutcome :
    Option OutcomeExpr -> Prop where
  | returned (target : Expr) :
      BoundedOrdinarySymbolicOutcome (some (.returned target))
  | jump (targetRva : Nat) :
      BoundedOrdinarySymbolicOutcome (some (.jump targetRva))
  | branch (condition : BoolExpr) (taken fallthrough : Nat) :
      BoundedOrdinarySymbolicOutcome
        (some (.branch condition taken fallthrough))
  | indirectJump (target : Expr) :
      BoundedOrdinarySymbolicOutcome (some (.indirectJump target))
  | checkedContinue (valid : BoolExpr) (continuationRva : Nat) :
      BoundedOrdinarySymbolicOutcome
        (some (.checkedContinue valid continuationRva))

theorem applyMachineImportCallContracts_eq_some_of_boundedOrdinary
    (contracts : List MachineImportCallContract)
    (symbolic : SymbolicBehavior)
    (ordinary : BoundedOrdinarySymbolicOutcome symbolic.outcome) :
    applyMachineImportCallContracts contracts symbolic = some symbolic := by
  generalize outcomeExact : symbolic.outcome = outcome at ordinary ⊢
  cases ordinary <;>
    simp [applyMachineImportCallContracts, outcomeExact]

/-- Exact decoded-program facts needed to identify the ordinary PE behavior
used by `pe32TransitionSystem`. The symbolic result is produced by independent
PE fetch/decode execution, not copied from a semantic record. -/
structure ExactOrdinaryOriginalSemanticSourceFacts
    (context : OriginalDecodedStaticContext)
    (original : DecodedWorldProgram)
    (sourceTargetId : Nat)
    (source : OriginalDecodedSource) where
  carrier : ExactDecodedOriginalCarrierBinding context original
  region : RegionRelation
  regionExact :
    regionById original.regions sourceTargetId = some region
  regionSpanExact : region.original = source.region.span
  symbolic : SymbolicBehavior
  symbolicExact :
    executePE32SymbolicSpan context.pe context.imports source.region.span =
      some symbolic
  nonX87 :
    StageA.Relational.X87.spanStartsWithX87Command context.pe
      source.region.span = false
  boundedOrdinary : BoundedOrdinarySymbolicOutcome symbolic.outcome

/-- Select the carrier region and independently executed symbolic span from
existing exact carrier and region-adequacy theorems. -/
noncomputable def ExactOrdinaryOriginalSemanticSourceFacts.ofCarrier
    (carrier : ExactDecodedOriginalCarrierBinding context original)
    (sourceExact : context.source? sourceTargetId = some source)
    (adequate :
      RegionInstructionAdequate context.pe context.imports source.region.span)
    (nonX87 :
      StageA.Relational.X87.spanStartsWithX87Command context.pe
        source.region.span = false)
    (ordinary : forall symbolic,
      executePE32SymbolicSpan context.pe context.imports source.region.span =
        some symbolic ->
      BoundedOrdinarySymbolicOutcome symbolic.outcome) :
    ExactOrdinaryOriginalSemanticSourceFacts context original sourceTargetId
      source := by
  let regionExists := carrier.sourceRegionsBound sourceTargetId source sourceExact
  let region := Classical.choose regionExists
  have regionFacts := Classical.choose_spec regionExists
  let symbolic := Classical.choose adequate
  have symbolicFacts := Classical.choose_spec adequate
  exact {
    carrier
    region
    regionExact := regionFacts.1
    regionSpanExact := regionFacts.2.2.1
    symbolic
    symbolicExact := symbolicFacts.1
    nonX87
    boundedOrdinary := ordinary symbolic symbolicFacts.1
  }

theorem evalBehavior_x87Fault_none
    (candidate : Bool) (targets : List CodeTargetPair)
    (state : MachineState) (symbolic : SymbolicBehavior)
    (behavior : RelationalBehavior)
    (evaluated :
      evalBehavior candidate targets state symbolic = some behavior) :
    behavior.x87Fault = none := by
  unfold evalBehavior at evaluated
  cases normalized :
      normalizeSymbolicBehavior candidate targets symbolic with
  | none => simp [normalized] at evaluated
  | some value =>
      simp [normalized] at evaluated
      subst behavior
      rfl

theorem ExactOrdinaryOriginalSemanticSourceFacts.pe32BehaviorExact
    (facts : ExactOrdinaryOriginalSemanticSourceFacts context original
      sourceTargetId source)
    (state : MachineState) (calls : List Nat)
    (behavior : RelationalBehavior)
    (evaluated :
      evalBehavior false facts.region.targets state facts.symbolic =
        some behavior) :
    pe32WorldRegionBehaviorWithCalls original sourceTargetId state calls =
      some behavior := by
  simp [pe32WorldRegionBehaviorWithCalls, facts.regionExact,
    facts.carrier.originalRole, facts.carrier.peBound,
    facts.carrier.importsBound, facts.regionSpanExact, facts.nonX87,
    facts.symbolicExact,
    applyMachineImportCallContracts_eq_some_of_boundedOrdinary
      (original.machineImportContractsAt sourceTargetId calls) facts.symbolic
      facts.boundedOrdinary,
    evaluated]

@[simp] theorem originalExecutionMachine?_resumeWorldExecution
    (callbacks : List WorldExternalCallbackRuntime)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld) :
    originalExecutionMachine?
        (resumeWorldExecution callbacks targetId state calls eventIndex world) =
      some state := by
  cases callbacks <;> rfl

/-- Successful non-external ordinary control outcomes. Every constructor names
the exact branch selected by `transitionFromWorldOutcome`; there is no
constructor carrying an independently asserted successor or endpoint. -/
inductive CheckedOriginalOrdinaryControlSuccessor
    (program : DecodedWorldProgram) (sourceTargetId : Nat)
    (state : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime) :
    PureOutcome -> Prop where
  | returnedRoot (target : Word)
      (callsExact : calls = []) (callbacksExact : callbacks = []) :
      CheckedOriginalOrdinaryControlSuccessor program sourceTargetId state calls
        eventIndex world callbacks (.returned target)
  | returnedCallback (target : Word)
      (callback : WorldExternalCallbackRuntime)
      (outerCallbacks : List WorldExternalCallbackRuntime)
      (callsExact : calls = [])
      (callbacksExact : callbacks = callback :: outerCallbacks)
      (targetExact : target = callback.entry.returnAddress) :
      CheckedOriginalOrdinaryControlSuccessor program sourceTargetId state calls
        eventIndex world callbacks (.returned target)
  | returnedCaller (target : Word) (continuation : Nat) (tail : List Nat)
      (callsExact : calls = continuation :: tail)
      (resolvedExact :
        resolveMappedCodeTarget program.candidate
          (if program.candidate then program.context.candidatePe.imageBase
            else program.context.originalPe.imageBase)
          program.context.codeMap.entries.toList target = some continuation) :
      CheckedOriginalOrdinaryControlSuccessor program sourceTargetId state calls
        eventIndex world callbacks (.returned target)
  | jump (target : Nat) :
      CheckedOriginalOrdinaryControlSuccessor program sourceTargetId state calls
        eventIndex world callbacks (.jump target)
  | branch (condition : Bool) (taken fallthrough : Nat) :
      CheckedOriginalOrdinaryControlSuccessor program sourceTargetId state calls
        eventIndex world callbacks (.branch condition taken fallthrough)
  | indexedIndirectJump (target : Word) (resolved : Nat)
      (callableProgramExact : program.callableProgram = none)
      (callableEnvironmentExact : program.callableEnvironment = none)
      (resolvedExact :
        program.context.codeMap.resolveRawEip program.candidate
          (if program.candidate then program.context.candidatePe.imageBase
            else program.context.originalPe.imageBase) target = some resolved) :
      CheckedOriginalOrdinaryControlSuccessor program sourceTargetId state calls
        eventIndex world callbacks (.indirectJump target)
  | callableIndirectJump (target : Word) (resolved : Nat)
      (callableProgram :
        CallableExternalExecution.OriginalCallableProgram)
      (callableEnvironment :
        CallableExternalExecution.OriginalCallableExternalEnvironment)
      (callableProgramExact : program.callableProgram = some callableProgram)
      (callableEnvironmentExact :
        program.callableEnvironment = some callableEnvironment)
      (resolvedExact :
        CallableExternalExecution.resolveDecodedCallableIndirect
          program.candidate callableProgram world target .jump =
            CallableExternalExecution.OriginalIndirectResolution.internal
              resolved) :
      CheckedOriginalOrdinaryControlSuccessor program sourceTargetId state calls
        eventIndex world callbacks (.indirectJump target)
  | checkedContinue (continuation : Nat) :
      CheckedOriginalOrdinaryControlSuccessor program sourceTargetId state calls
        eventIndex world callbacks (.checkedContinue true continuation)

theorem CheckedOriginalOrdinaryControlSuccessor.machineExact
    (successor : CheckedOriginalOrdinaryControlSuccessor program sourceTargetId
      state calls eventIndex world callbacks outcome) :
    originalExecutionMachine?
        (transitionFromWorldOutcome program sourceTargetId state calls eventIndex
          world callbacks outcome).next =
      some state := by
  cases successor with
  | returnedRoot target callsExact callbacksExact =>
      subst calls
      subst callbacks
      rfl
  | returnedCallback target callback outerCallbacks callsExact callbacksExact
      targetExact =>
      subst calls
      subst callbacks
      subst target
      simp [transitionFromWorldOutcome]
      change some state = some state
      rfl
  | returnedCaller target continuation tail callsExact resolvedExact =>
      subst calls
      simp [transitionFromWorldOutcome, resolvedExact]
  | jump target =>
      simp [transitionFromWorldOutcome]
  | branch condition taken fallthrough =>
      simp [transitionFromWorldOutcome]
  | indexedIndirectJump target resolved callableProgramExact
      callableEnvironmentExact resolvedExact =>
      simp [transitionFromWorldOutcome, callableProgramExact,
        callableEnvironmentExact, resolvedExact]
  | callableIndirectJump target resolved callableProgram callableEnvironment
      callableProgramExact callableEnvironmentExact resolvedExact =>
      simp [transitionFromWorldOutcome, callableProgramExact,
        callableEnvironmentExact, resolvedExact]
  | checkedContinue continuation =>
      simp [transitionFromWorldOutcome]

/-- Pointwise exact execution facts for one ordinary source state. The checked
successor records only resolver/control branch evidence, never an endpoint. -/
structure ExactOrdinaryOriginalSemanticStepFacts
    (original : DecodedWorldProgram) (sourceTargetId : Nat)
    (sourceFacts : ExactOrdinaryOriginalSemanticSourceFacts context original
      sourceTargetId source)
    (originalBefore : WorldExecution) where
  before : ExactOriginalSemanticBefore sourceTargetId originalBefore
  behavior : RelationalBehavior
  evaluatedExact :
    evalBehavior false sourceFacts.region.targets before.state
      sourceFacts.symbolic = some behavior
  successor :
    CheckedOriginalOrdinaryControlSuccessor original sourceTargetId
      (behavior.nextMachineState before.state) before.calls before.eventIndex
      before.world before.callbacks behavior.outcome

theorem ExactOrdinaryOriginalSemanticStepFacts.originalMachineExact
    (facts : ExactOrdinaryOriginalSemanticStepFacts original sourceTargetId
      sourceFacts originalBefore) :
    originalExecutionMachine? originalBefore = some facts.before.state := by
  rcases facts with ⟨before, behavior, evaluated, successor⟩
  cases before <;> rfl

theorem ExactOrdinaryOriginalSemanticStepFacts.stepMachineExact
    (facts : ExactOrdinaryOriginalSemanticStepFacts original sourceTargetId
      sourceFacts originalBefore) :
    originalExecutionMachine?
        (original.pe32TransitionSystem.step originalBefore).next =
      some (facts.behavior.nextMachineState facts.before.state) := by
  rcases facts with ⟨before, behavior, evaluated, successor⟩
  cases before with
  | running state calls eventIndex world =>
      have behaviorExact := sourceFacts.pe32BehaviorExact state calls behavior
        evaluated
      have noX87Fault := evalBehavior_x87Fault_none false
        sourceFacts.region.targets state sourceFacts.symbolic behavior evaluated
      change originalExecutionMachine?
          (stepPE32WorldExecution original
            (.running sourceTargetId state calls eventIndex world)).next =
        some (behavior.nextMachineState state)
      simp [stepPE32WorldExecution, behaviorExact, transitionFromWorldBehavior,
        noX87Fault]
      exact successor.machineExact
  | callbackRunning state calls eventIndex world callbacks =>
      have behaviorExact := sourceFacts.pe32BehaviorExact state calls behavior
        evaluated
      have noX87Fault := evalBehavior_x87Fault_none false
        sourceFacts.region.targets state sourceFacts.symbolic behavior evaluated
      change originalExecutionMachine?
          (stepPE32WorldExecution original
            (.callbackRunning sourceTargetId state calls eventIndex world
              callbacks)).next =
        some (behavior.nextMachineState state)
      simp [stepPE32WorldExecution, behaviorExact, transitionFromWorldBehavior,
        noX87Fault]
      exact successor.machineExact

/-- Sequential exact instruction execution used by normalization agrees with
concrete evaluation of the fused symbolic PE span. This is universal and
contains no world endpoint or submitted path. -/
def ExactOriginalSemanticSequentialFusion
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (reachability :
      ExactOriginalDecodedReachability context authority launch root)
    (candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (source : ExactOriginalSemanticSource context authority launch root
      reachability candidate candidateAuthority)
    (binding : ExactOriginalSemanticTransferBinding context authority launch root
      reachability candidate candidateAuthority source)
    (original : DecodedWorldProgram)
    (sourceFacts : ExactOrdinaryOriginalSemanticSourceFacts context original
      source.targetId source.source) : Prop :=
  forall state environment behavior result,
    evalBehavior false sourceFacts.region.targets state sourceFacts.symbolic =
      some behavior ->
    runExactNormalizedPath context.pe binding.path environment state =
      some result ->
    machineFromFormal (behavior.nextMachineState state) = result.state

/-- A cached exact-span/transfer theorem closes the contextual sequential
fusion obligation through the already checked normalization certificate. -/
theorem ExactOriginalSemanticSequentialFusion.ofFusedMachineRefinement
    (binding : ExactOriginalSemanticTransferBinding context authority launch
      root reachability candidate candidateAuthority source)
    (sourceFacts : ExactOrdinaryOriginalSemanticSourceFacts context original
      source.targetId source.source)
    (fused :
      ExactSemanticTransferFusedMachineRefinement context.pe context.imports
        source.source.region.span binding.transfer) :
    ExactOriginalSemanticSequentialFusion context authority launch root
      reachability candidate candidateAuthority source binding original
      sourceFacts := by
  intro state environment behavior result evaluated sequential
  apply fused sourceFacts.region.targets state environment sourceFacts.symbolic
    behavior result sourceFacts.symbolicExact evaluated
  rw [binding.decodedSemanticRefinement state environment]
  exact sequential

/-- The exact interpreter-Step effect associated with this source and input
state. -/
def exactOrdinaryOriginalInterpreterStepEffect
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (source : ExactOriginalSemanticSource context authority launch root
      reachability candidate candidateAuthority)
    (state : MachineState)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (result : MacroResult)
    (resultExact :
      source.record.interpret environment (machineFromFormal state) =
        some result)
    (derivation : CheckedInterpreterStepDerivation
      candidateAuthority.semanticRecords environment resolveCodeTarget
      source.source.target.rva (machineFromFormal state) (some result)) :
    ExactOriginalSemanticKernelEffect candidateAuthority.semanticRecords
      source.source.target.rva source.record state
      (.interpreterStep candidateAuthority.semanticRecords environment
        source.source.target.rva (machineFromFormal state))
      (.interpreterStep (some result)) :=
  .interpreterStep environment resolveCodeTarget (some result) resultExact
    derivation

/-- Retained result for a computed one-step ordinary replay. -/
structure CheckedOrdinaryOriginalInterpreterStepReplay
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (reachability :
      ExactOriginalDecodedReachability context authority launch root)
    (original : DecodedWorldProgram)
    (candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (source : ExactOriginalSemanticSource context authority launch root
      reachability candidate candidateAuthority)
    (sourceFacts : ExactOrdinaryOriginalSemanticSourceFacts context original
      source.targetId source.source)
    (stepFacts : ExactOrdinaryOriginalSemanticStepFacts original source.targetId
      sourceFacts originalBefore)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (result : MacroResult)
    (resultExact :
      source.record.interpret environment
        (machineFromFormal stepFacts.before.state) = some result)
    (derivation : CheckedInterpreterStepDerivation
      candidateAuthority.semanticRecords environment resolveCodeTarget
      source.source.target.rva (machineFromFormal stepFacts.before.state)
      (some result)) : Prop where
  endpointMatches :
    (exactOrdinaryOriginalInterpreterStepEffect candidateAuthority source
      stepFacts.before.state environment resolveCodeTarget result resultExact
      derivation).EndpointMatches
        (CheckedOriginalSemanticOperationPath.one original originalBefore).after

def checkedOrdinaryOriginalSemanticPath
    (original : DecodedWorldProgram) (originalBefore : WorldExecution) :
    CheckedOriginalSemanticOperationPath original originalBefore :=
  CheckedOriginalSemanticOperationPath.one original originalBefore

def checkedOrdinaryOriginalSemanticPathShape
    (original : DecodedWorldProgram) (originalBefore : WorldExecution) :
    CheckedOriginalSemanticOperationPathShape original originalBefore
      (checkedOrdinaryOriginalSemanticPath original originalBefore) :=
  .singleStep rfl

theorem checkedOrdinaryOriginalSemanticPath_path
    (original : DecodedWorldProgram) (originalBefore : WorldExecution) :
    NonemptyRelatedPath original.pe32TransitionSystem originalBefore
      (checkedOrdinaryOriginalSemanticPath original
        originalBefore).observations
      (checkedOrdinaryOriginalSemanticPath original originalBefore).after :=
  (checkedOrdinaryOriginalSemanticPath original originalBefore).path

/-- Construct the checked one-step replay. Normalization rewrites the raw
record result to the exact sequential runner; fusion supplies the sole
remaining machine equality. -/
def CheckedOrdinaryOriginalInterpreterStepReplay.ofExact
    {context : OriginalDecodedStaticContext}
    {authority : ExactOriginalDecodedAuthority context}
    {launch : PE32ConsoleLaunchV2}
    {root : DirectExactOriginalDecodedLaunchRoot context launch}
    {reachability :
      ExactOriginalDecodedReachability context authority launch root}
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {source : ExactOriginalSemanticSource context authority launch root
      reachability candidate candidateAuthority}
    {sourceFacts : ExactOrdinaryOriginalSemanticSourceFacts context original
      source.targetId source.source}
    {originalBefore : WorldExecution}
    {stepFacts : ExactOrdinaryOriginalSemanticStepFacts original source.targetId
      sourceFacts originalBefore}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat}
    {result : MacroResult}
    (binding : ExactOriginalSemanticTransferBinding context authority launch root
      reachability candidate candidateAuthority source)
    (fusion :
      ExactOriginalSemanticSequentialFusion context authority launch root
        reachability candidate candidateAuthority source binding original
        sourceFacts)
    (resultExact :
      source.record.interpret environment
        (machineFromFormal stepFacts.before.state) = some result)
    (derivation : CheckedInterpreterStepDerivation
      candidateAuthority.semanticRecords environment resolveCodeTarget
      source.source.target.rva (machineFromFormal stepFacts.before.state)
      (some result)) :
    CheckedOrdinaryOriginalInterpreterStepReplay context authority launch root
      reachability original candidate candidateAuthority source sourceFacts
      (originalBefore := originalBefore) stepFacts environment resolveCodeTarget
      result resultExact derivation := by
  have sequentialExact :
      runExactNormalizedPath context.pe binding.path environment
          stepFacts.before.state =
        some result := by
    calc
      runExactNormalizedPath context.pe binding.path environment
          stepFacts.before.state =
          source.record.interpret environment
            (machineFromFormal stepFacts.before.state) :=
        (binding.recordMacroStepExact environment
          stepFacts.before.state).symm
      _ = some result := resultExact
  have stateExact :
      machineFromFormal
          (stepFacts.behavior.nextMachineState stepFacts.before.state) =
        result.state :=
    fusion stepFacts.before.state environment stepFacts.behavior result
      stepFacts.evaluatedExact sequentialExact
  refine { endpointMatches := ?_ }
  change exists afterState,
    originalExecutionMachine?
        (CheckedOriginalSemanticOperationPath.one original
          originalBefore).after = some afterState /\
      machineFromFormal afterState = result.state
  refine ⟨stepFacts.behavior.nextMachineState stepFacts.before.state, ?_, stateExact⟩
  simpa [CheckedOriginalSemanticOperationPath.one,
    CheckedOriginalSemanticOperationPath.after,
    CheckedOriginalSemanticOperationPath.result, runRelatedSteps] using
    stepFacts.stepMachineExact

#print axioms ExactOriginalSemanticBefore.ofAtSource
#print axioms ExactOrdinaryOriginalSemanticSourceFacts.ofCarrier
#print axioms
  ExactOrdinaryOriginalSemanticSourceFacts.pe32BehaviorExact
#print axioms
  ExactOriginalSemanticSequentialFusion.ofFusedMachineRefinement
#print axioms CheckedOriginalOrdinaryControlSuccessor.machineExact
#print axioms ExactOrdinaryOriginalSemanticStepFacts.stepMachineExact
#print axioms CheckedOrdinaryOriginalInterpreterStepReplay.ofExact
#print axioms checkedOrdinaryOriginalSemanticPath_path

end StageA.Relational.InterpreterMixedOriginalSemanticReplay
