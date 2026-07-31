import StageA.RelationalInterpreterKernelOperationReplay
import StageA.RelationalInterpreterKernelStepOperation
import StageA.RelationalInterpreterMixedConstructiveSourceClassifier
import StageA.RelationalInterpreterNormalization

namespace StageA.Relational.InterpreterMixedSemanticOperationComponent

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterKernelOperationReplay
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterMixedConstructiveSourceClassifier
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterTransfer

/-!
# Exact semantic source to checked kernel operation

This module is the proof-producing bridge between an exact decoded-original
semantic source and one checked candidate kernel operation. It deliberately
does not accept independently supplied path endpoints, observation lists, or
native events:

* the original endpoint and observations are computed from positive fuel in
  the decoded PE transition system;
* a retained shape certificate distinguishes an exact one-step effect from an
  exact finite direct-call/return cluster;
* the candidate path is selected by the operation dispatch and represented by
  `CheckedNativeOperationPath`, whose endpoint and observations are computed;
* the abstract request is constrained by a checked semantic derivation; and
* invariant preservation is stated only at those two computed endpoints.

The classifier relation and its `beforeRelated` proof index the dynamic
evidence. They are not replaced by a second classification pass.
-/

/-- Exact association of one classifier-selected original source with the
normalization theorem for the same raw semantic-table record and PE span. -/
structure ExactOriginalSemanticTransferBinding
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (reachability : ExactOriginalDecodedReachability context authority launch root)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (source : ExactOriginalSemanticSource context authority launch root
      reachability candidate candidateAuthority) where
  path : ExactNormalizedTransferPath
  transfer : SemanticTransfer
  pathRecordExact : path.record = source.record
  pathSourceExact : path.sourceRva = source.source.target.rva
  pathStopExact : path.stopRva = source.source.region.span.stop
  normalization :
    ExactProgramRecordNormalizationCertificate context.pe path transfer

theorem ExactOriginalSemanticTransferBinding.decodedSemanticRefinement
    (binding : ExactOriginalSemanticTransferBinding context authority launch root
      reachability candidate candidateAuthority source) :
    SemanticTransferRefinesExactPath context.pe binding.path binding.transfer :=
  binding.normalization.normalization.semanticRefinement

/-- Strongest generic decoded effect available from normalization: executing
the exact source record is equal to replaying the exact decoded PE path. -/
theorem ExactOriginalSemanticTransferBinding.recordMacroStepExact
    (binding : ExactOriginalSemanticTransferBinding context authority launch root
      reachability candidate candidateAuthority source)
    (environment : StageA.Relational.Interpreter.Environment)
    (state : MachineState) :
    source.record.interpret environment (machineFromFormal state) =
      runExactNormalizedPath context.pe binding.path environment state := by
  rw [← binding.pathRecordExact]
  exact binding.normalization.rawMacroStep environment state

/-- A finite original path whose endpoint and observations are computed from
the exact decoded PE transition system. This supports both a local semantic
step and a whole checked call/return cluster. -/
structure CheckedOriginalSemanticOperationPath
    (original : DecodedWorldProgram) (before : WorldExecution) where
  fuel : Nat
  positive : 0 < fuel

def CheckedOriginalSemanticOperationPath.result
    {original : DecodedWorldProgram} {before : WorldExecution}
    (path : CheckedOriginalSemanticOperationPath original before) :
    WorldExecution × List WorldRelationalObservable :=
  runRelatedSteps original.pe32TransitionSystem path.fuel before

def CheckedOriginalSemanticOperationPath.after
    {original : DecodedWorldProgram} {before : WorldExecution}
    (path : CheckedOriginalSemanticOperationPath original before) :
    WorldExecution :=
  path.result.1

def CheckedOriginalSemanticOperationPath.observations
    {original : DecodedWorldProgram} {before : WorldExecution}
    (path : CheckedOriginalSemanticOperationPath original before) :
    List WorldRelationalObservable :=
  path.result.2

theorem CheckedOriginalSemanticOperationPath.path
    {original : DecodedWorldProgram} {before : WorldExecution}
    (path : CheckedOriginalSemanticOperationPath original before) :
    NonemptyRelatedPath original.pe32TransitionSystem before path.observations
      path.after :=
  ⟨path.fuel, path.positive, rfl⟩

def CheckedOriginalSemanticOperationPath.one
    (original : DecodedWorldProgram) (before : WorldExecution) :
    CheckedOriginalSemanticOperationPath original before := {
  fuel := 1
  positive := Nat.zero_lt_succ 0
}

/-- Exact finite direct-call execution from a call source through its callee
and back to the continuation. The endpoint is the computed endpoint of
`path`; source, continuation, stack, event, and world equalities are proof
fields, not a second executable semantics.

Both ordinary and callback execution modes are represented. -/
inductive CheckedOriginalDirectCallReturnCluster
    (original : DecodedWorldProgram) (before : WorldExecution)
    (path : CheckedOriginalSemanticOperationPath original before) : Type where
  | running
      (sourceTargetId continuationTargetId calleeTargetId : Nat)
      (sourceState entryState afterState : MachineState)
      (calls : List Nat) (eventIndex : Nat) (world : RelationalWorld)
      (beforeExact :
        before = .running sourceTargetId sourceState calls eventIndex world)
      (callStepExact :
        original.pe32TransitionSystem.step before = {
          next := .running calleeTargetId entryState
            (continuationTargetId :: calls) eventIndex world
          observation := none
        })
      (afterExact :
        path.after = .running continuationTargetId afterState calls eventIndex
          world) :
      CheckedOriginalDirectCallReturnCluster original before path
  | callbackRunning
      (sourceTargetId continuationTargetId calleeTargetId : Nat)
      (sourceState entryState afterState : MachineState)
      (calls : List Nat) (eventIndex : Nat) (world : RelationalWorld)
      (callbacks : List WorldExternalCallbackRuntime)
      (beforeExact :
        before = .callbackRunning sourceTargetId sourceState calls eventIndex
          world callbacks)
      (callStepExact :
        original.pe32TransitionSystem.step before = {
          next := .callbackRunning calleeTargetId entryState
            (continuationTargetId :: calls) eventIndex world callbacks
          observation := none
        })
      (afterExact :
        path.after = .callbackRunning continuationTargetId afterState calls
          eventIndex world callbacks) :
      CheckedOriginalDirectCallReturnCluster original before path

/-- The checked operational shape retained for route composition. A local
effect consumes exactly one PE transition. A direct call consumes the whole
finite call/return cluster and restores its active caller context. -/
inductive CheckedOriginalSemanticOperationPathShape
    (original : DecodedWorldProgram) (before : WorldExecution)
    (path : CheckedOriginalSemanticOperationPath original before) : Type where
  | singleStep (fuelExact : path.fuel = 1) :
      CheckedOriginalSemanticOperationPathShape original before path
  | directCallReturn
      (cluster :
        CheckedOriginalDirectCallReturnCluster original before path) :
      CheckedOriginalSemanticOperationPathShape original before path

/-- A checked abstract kernel request whose origin is the selected exact
semantic source. Each constructor fixes the request and response shape.

The Invoke constructor additionally retains membership of the exact call site
inside the checked source Step derivation. An event or request cannot be
introduced merely by matching its target RVA. -/
inductive ExactOriginalSemanticKernelEffect
    (records : List ProgramRecord) (sourceRva : Nat) (record : ProgramRecord)
    (originalState : MachineState) :
    AbstractKernelRequest -> AbstractKernelResponse -> Type where
  | programLookup
      (lookupExact : lookupProgramRecord records sourceRva = some record) :
      ExactOriginalSemanticKernelEffect records sourceRva record originalState
        (.programLookup records sourceRva) (.programLookup (some record))
  | interpreterStep
      (environment : StageA.Relational.Interpreter.Environment)
      (resolveCodeTarget : Word -> Option Nat)
      (result : Option MacroResult)
      (resultExact :
        record.interpret environment (machineFromFormal originalState) = result)
      (derivation : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva (machineFromFormal originalState) result) :
      ExactOriginalSemanticKernelEffect records sourceRva record originalState
        (.interpreterStep records environment sourceRva
          (machineFromFormal originalState))
        (.interpreterStep result)
  | runFunction
      (environment : StageA.Relational.Interpreter.Environment)
      (resolveCodeTarget : Word -> Option Nat)
      (result : CallResult)
      (derivation : CheckedRunFunctionDerivation records environment
        resolveCodeTarget sourceRva (machineFromFormal originalState) result) :
      ExactOriginalSemanticKernelEffect records sourceRva record originalState
        (.runFunction records environment resolveCodeTarget sourceRva
          (machineFromFormal originalState))
        (.call result)
  | invokeCall
      (environment : StageA.Relational.Interpreter.Environment)
      (resolveCodeTarget : Word -> Option Nat)
      (stepResult : Option MacroResult)
      (stepResultExact :
        record.interpret environment (machineFromFormal originalState) =
          stepResult)
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva (machineFromFormal originalState) stepResult)
      (site : CheckedInterpreterStepInvokeSite records environment
        resolveCodeTarget)
      (contains : CheckedInterpreterStepDerivationContainsInvoke records
        environment resolveCodeTarget site step)
      (eventTargetExact : site.event.targetRva.toNat = sourceRva) :
      ExactOriginalSemanticKernelEffect records sourceRva record originalState
        site.request site.response

theorem ExactOriginalSemanticKernelEffect.requestRecordsExact
    (effect : ExactOriginalSemanticKernelEffect records sourceRva record
      originalState request response) :
    kernelRequestSemanticRecords request = records := by
  cases effect <;> rfl

theorem ExactOriginalSemanticKernelEffect.requestSourceExact
    (effect : ExactOriginalSemanticKernelEffect records sourceRva record
      originalState request response) :
    kernelRequestSourceRva request = sourceRva := by
  cases effect with
  | programLookup => rfl
  | interpreterStep => rfl
  | runFunction => rfl
  | invokeCall _ _ _ _ _ site _ eventTargetExact =>
      simpa [CheckedInterpreterStepInvokeSite.request,
        kernelRequestSourceRva] using eventTargetExact

theorem ExactOriginalSemanticKernelEffect.transition
    (effect : ExactOriginalSemanticKernelEffect records sourceRva record
      originalState request response) :
    AbstractKernelTransition request response := by
  cases effect with
  | programLookup lookupExact =>
      simpa [lookupExact] using
        (AbstractKernelTransition.programLookup records sourceRva)
  | interpreterStep _ _ _ _ derivation =>
      exact derivation.toAbstractKernelTransition
  | runFunction _ _ _ derivation =>
      exact derivation.toAbstractKernelTransition
  | invokeCall _ _ _ _ _ site _ _ =>
      exact site.derivation.toAbstractKernelTransition

/-- Exact semantic result retained at the computed original endpoint.

Program lookup has no machine result. An unavailable Step has no result state.
Every successful Step, Run, or Invoke result must agree with the machine
extracted from the exact operational endpoint. -/
def ExactOriginalSemanticKernelEffect.EndpointMatches
    (effect : ExactOriginalSemanticKernelEffect records sourceRva record
      originalState request response)
    (after : WorldExecution) : Prop :=
  match effect with
  | .programLookup _ => True
  | .interpreterStep _ _ result _ _ =>
      match result with
      | none => True
      | some result =>
          ∃ afterState,
            originalExecutionMachine? after = some afterState ∧
              machineFromFormal afterState = result.state
  | .runFunction _ _ result _ =>
      ∃ afterState,
        originalExecutionMachine? after = some afterState ∧
          machineFromFormal afterState = result.state
  | .invokeCall _ _ _ _ _ site _ _ =>
      ∃ afterState,
        originalExecutionMachine? after = some afterState ∧
          machineFromFormal afterState = site.result.state

/-- Dynamic request evidence extracted from the exact before-state relation and
the exact classifier equation. The request itself is supplied only through
`ExactOriginalSemanticKernelEffect`. -/
structure CheckedMixedSemanticOperationBefore
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (abi : KernelABIRelation)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (sourceRva : Nat) (record : ProgramRecord)
    (operation : KernelOperation)
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution)
    (ClassificationEvidence : Prop)
    (_beforeRelated : invariant.holds originalBefore candidateBefore)
    (_classified : ClassificationEvidence) where
  originalState : MachineState
  originalMachineExact :
    originalExecutionMachine? originalBefore = some originalState
  beforeMachine : MachineState
  candidateMachineExact : candidateBefore.machine? = some beforeMachine
  request : AbstractKernelRequest
  response : AbstractKernelResponse
  effect : ExactOriginalSemanticKernelEffect candidateAuthority.semanticRecords
    sourceRva record originalState request response
  requestOperationExact : request.operation = operation
  requestRelated : abi.requestRelated request beforeMachine
  originalReplay :
    CheckedOriginalSemanticOperationPath original originalBefore
  originalPathShape :
    CheckedOriginalSemanticOperationPathShape original originalBefore
      originalReplay
  originalEffectAfterExact :
    effect.EndpointMatches originalReplay.after

/-- Candidate replay selected by the exact dispatch returned from
`KernelOperationRefinesUsing`. Its endpoint and observations are computed from
`path`; the equalities only identify that endpoint with the dispatch result. -/
structure CheckedCandidateKernelOperationReplay
    (candidate : ExactNativeWorldProgram)
    (candidateBefore : NativeWorldExecution)
    (afterMachine : MachineState)
    (nativeEvents : List NativeExternalEvent) where
  path : CheckedNativeOperationPath candidate candidateBefore
  afterMachineExact : path.after.machine? = some afterMachine
  afterEventsExact : nativeExecutionEvents? path.after = some nativeEvents

/-- Relational closure at the two computed endpoints. This is the only
invariant-preservation premise retained by the generic bridge. -/
structure CheckedMixedSemanticOperationClosure
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution)
    (originalReplay :
      CheckedOriginalSemanticOperationPath original originalBefore)
    (replay : CheckedCandidateKernelOperationReplay candidate candidateBefore
      afterMachine nativeEvents) : Prop where
  observationsChecked : CheckedMixedKernelObservations contract
    originalReplay.observations
    replay.path.observations
  afterRelated : invariant.holds
    originalReplay.after replay.path.after

/-- Minimal checked dynamic interface. The classifier premises index every
field. Candidate replay must eliminate the exact dispatch selected by the
operation theorem, and closure is requested only for that replay. -/
structure CheckedMixedSemanticOperationEvidence
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (contract : MixedRelationContract)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (program : CompiledKernelProgram)
    (abi : KernelABIRelation)
    (dispatches : KernelDispatchRelation)
    (sourceRva : Nat) (record : ProgramRecord)
    (operation : KernelOperation) (entryRva : Nat)
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution)
    (ClassificationEvidence : Prop)
    (beforeRelated : invariant.holds originalBefore candidateBefore)
    (classified : ClassificationEvidence) where
  before : CheckedMixedSemanticOperationBefore original candidate
    candidateAuthority abi invariant sourceRva record operation originalBefore
    candidateBefore ClassificationEvidence beforeRelated classified
  candidateReplay : forall afterMachine nativeEvents,
    dispatches entryRva before.beforeMachine afterMachine nativeEvents ->
      Nonempty (CheckedCandidateKernelOperationReplay candidate candidateBefore
        afterMachine nativeEvents)
  close : forall afterMachine nativeEvents
      (_dispatched :
        dispatches entryRva before.beforeMachine afterMachine nativeEvents)
      (replay : CheckedCandidateKernelOperationReplay candidate candidateBefore
        afterMachine nativeEvents),
    CheckedMixedSemanticOperationClosure original candidate contract invariant
      originalBefore candidateBefore before.originalReplay replay

/-- Retaining bridge result. The existing component certificate is available
through `component`, while exact decoded semantic refinement and the computed
original effect remain available to downstream route composition. -/
structure MixedSemanticKernelOperationComponentCertificate
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (reachability : ExactOriginalDecodedReachability context authority launch root)
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (contract : MixedRelationContract)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (program : CompiledKernelProgram)
    (abi : KernelABIRelation)
    (dispatches : KernelDispatchRelation)
    (source : ExactOriginalSemanticSource context authority launch root
      reachability candidate candidateAuthority)
    (binding : ExactOriginalSemanticTransferBinding context authority launch root
      reachability candidate candidateAuthority source)
    (operation : KernelOperation) (entryRva : Nat)
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution) where
  originalState : MachineState
  originalMachineExact :
    originalExecutionMachine? originalBefore = some originalState
  request : AbstractKernelRequest
  response : AbstractKernelResponse
  exactOriginalEffect :
    ExactOriginalSemanticKernelEffect candidateAuthority.semanticRecords
      source.source.target.rva source.record originalState request response
  originalReplay :
    CheckedOriginalSemanticOperationPath original originalBefore
  originalPathShape :
    CheckedOriginalSemanticOperationPathShape original originalBefore
      originalReplay
  originalEffectAfterExact :
    exactOriginalEffect.EndpointMatches originalReplay.after
  component : MixedKernelOperationComponentCertificate original candidate contract
    invariant program abi dispatches candidateAuthority source.source.target.rva
    operation entryRva originalBefore candidateBefore
  originalAfterExact :
    component.paths.originalAfter = originalReplay.after
  originalObservationsExact : component.paths.originalObservations =
    originalReplay.observations

theorem MixedSemanticKernelOperationComponentCertificate.originalPath
    (certificate : MixedSemanticKernelOperationComponentCertificate context
      authority launch root reachability original candidate candidateAuthority
      contract invariant program abi dispatches source binding operation entryRva
      originalBefore candidateBefore) :
    NonemptyRelatedPath original.pe32TransitionSystem originalBefore
      certificate.originalReplay.observations
      certificate.originalReplay.after :=
  certificate.originalReplay.path

theorem MixedSemanticKernelOperationComponentCertificate.decodedSemanticRefinement
    (_certificate : MixedSemanticKernelOperationComponentCertificate context
      authority launch root reachability original candidate candidateAuthority
      contract invariant program abi dispatches source binding operation entryRva
      originalBefore candidateBefore) :
    SemanticTransferRefinesExactPath context.pe binding.path binding.transfer :=
  binding.decodedSemanticRefinement

theorem MixedSemanticKernelOperationComponentCertificate.recordMacroStepExact
    (_certificate : MixedSemanticKernelOperationComponentCertificate context
      authority launch root reachability original candidate candidateAuthority
      contract invariant program abi dispatches source binding operation entryRva
      originalBefore candidateBefore)
    (environment : StageA.Relational.Interpreter.Environment)
    (state : MachineState) :
    source.record.interpret environment (machineFromFormal state) =
      runExactNormalizedPath context.pe binding.path environment state :=
  binding.recordMacroStepExact environment state

def MixedSemanticKernelOperationComponentCertificate.toMixedKernelOperationComponentCertificate
    (certificate : MixedSemanticKernelOperationComponentCertificate context
      authority launch root reachability original candidate candidateAuthority
      contract invariant program abi dispatches source binding operation entryRva
      originalBefore candidateBefore) :
    MixedKernelOperationComponentCertificate original candidate contract invariant
      program abi dispatches candidateAuthority source.source.target.rva operation
      entryRva originalBefore candidateBefore :=
  certificate.component

noncomputable def CheckedMixedSemanticOperationEvidence.toComponentCertificate
    (binding : ExactOriginalSemanticTransferBinding context authority launch root
      reachability candidate candidateAuthority source)
    (evidence : CheckedMixedSemanticOperationEvidence original candidate
      candidateAuthority contract invariant program abi dispatches
      source.source.target.rva source.record operation entryRva originalBefore
      candidateBefore ClassificationEvidence beforeRelated classified)
    (entryExact : program.functionEntry? operation.role = some entryRva)
    (operationRefines :
      KernelOperationRefinesUsing program abi dispatches operation) :
    MixedSemanticKernelOperationComponentCertificate context authority launch root
      reachability original candidate candidateAuthority contract invariant program
      abi dispatches source binding operation entryRva originalBefore
      candidateBefore := by
  classical
  have appliedAtEntry : exists afterMachine nativeEvents,
      dispatches entryRva evidence.before.beforeMachine afterMachine nativeEvents /\
        abi.responseRelated evidence.before.request evidence.before.response
          afterMachine nativeEvents /\
        MemoryAgreesOutside (abi.scratchFootprint evidence.before.request)
          afterMachine.memory evidence.before.beforeMachine.memory := by
    obtain ⟨selectedEntryRva, afterMachine, nativeEvents, selectedEntryExact,
        dispatched, responseRelated, frame⟩ :=
      operationRefines evidence.before.request evidence.before.beforeMachine
        evidence.before.requestOperationExact evidence.before.requestRelated
        evidence.before.response evidence.before.effect.transition
    have sameEntry : selectedEntryRva = entryRva :=
      Option.some.inj (selectedEntryExact.symm.trans entryExact)
    subst selectedEntryRva
    exact ⟨afterMachine, nativeEvents, dispatched, responseRelated, frame⟩
  let afterMachine := Classical.choose appliedAtEntry
  have afterWitness := Classical.choose_spec appliedAtEntry
  let nativeEvents := Classical.choose afterWitness
  have appliedFacts := Classical.choose_spec afterWitness
  have dispatched := appliedFacts.1
  have replayNonempty := evidence.candidateReplay afterMachine nativeEvents
    dispatched
  let replay := Classical.choice replayNonempty
  have closed := evidence.close afterMachine nativeEvents dispatched replay
  let paths : MixedKernelChunkPaths original candidate contract invariant
      originalBefore candidateBefore := {
    originalObservations := evidence.before.originalReplay.observations
    candidateObservations := replay.path.observations
    originalAfter := evidence.before.originalReplay.after
    candidateAfter := replay.path.after
    originalPath := evidence.before.originalReplay.path
    candidatePath := replay.path.path
    observationsChecked := closed.observationsChecked
    afterRelated := closed.afterRelated
  }
  let component : MixedKernelOperationComponentCertificate original candidate
      contract invariant program abi dispatches candidateAuthority
      source.source.target.rva operation entryRva originalBefore
      candidateBefore := {
    request := evidence.before.request
    response := evidence.before.response
    beforeMachine := evidence.before.beforeMachine
    candidateMachineExact := evidence.before.candidateMachineExact
    requestOperationExact := evidence.before.requestOperationExact
    requestRecordsExact := evidence.before.effect.requestRecordsExact
    requestSourceExact := evidence.before.effect.requestSourceExact
    requestRelated := evidence.before.requestRelated
    transition := evidence.before.effect.transition
    operationRefines
    afterMachine
    nativeEvents
    entryExact := by
      simpa [evidence.before.requestOperationExact] using entryExact
    dispatched
    responseRelated := appliedFacts.2.1
    frame := appliedFacts.2.2
    paths
    candidateAfterMachineExact := replay.afterMachineExact
    candidateAfterEventsExact := replay.afterEventsExact
  }
  exact {
    originalState := evidence.before.originalState
    originalMachineExact := evidence.before.originalMachineExact
    request := evidence.before.request
    response := evidence.before.response
    exactOriginalEffect := evidence.before.effect
    originalReplay := evidence.before.originalReplay
    originalPathShape := evidence.before.originalPathShape
    originalEffectAfterExact := evidence.before.originalEffectAfterExact
    component
    originalAfterExact := rfl
    originalObservationsExact := rfl
  }

#print axioms ExactOriginalSemanticTransferBinding.decodedSemanticRefinement
#print axioms ExactOriginalSemanticTransferBinding.recordMacroStepExact
#print axioms CheckedOriginalSemanticOperationPath.path
#print axioms ExactOriginalSemanticKernelEffect.transition
#print axioms
  MixedSemanticKernelOperationComponentCertificate.originalPath
#print axioms
  MixedSemanticKernelOperationComponentCertificate.decodedSemanticRefinement
#print axioms
  MixedSemanticKernelOperationComponentCertificate.recordMacroStepExact
#print axioms
  CheckedMixedSemanticOperationEvidence.toComponentCertificate

end StageA.Relational.InterpreterMixedSemanticOperationComponent
