import StageA.RelationalInterpreterMixedOriginal

namespace StageA.Relational.InterpreterMixedKernelComposition

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

/-! # Decoded-original/native-kernel composition

This module is the generic assembly boundary between local compiled-kernel
operation proofs and the mixed decoded-original/native-candidate theorem.  It
does not accept a whole-program path or a proposition saying that every state
refines.  Instead, a closed source classifier selects one typed local case.
Operation cases apply `KernelOperationRefinesUsing` to an exact request, while
the remaining cases contain nonempty paths in the two exact transition
systems.

There is deliberately no constructor for a blocked or unclassified state.
Consequently, a classifier can be total on `MixedExecutionInvariant.holds`
only after the binding has closed every reachable proof frontier.
-/

def kernelRequestSemanticRecords : AbstractKernelRequest ->
    List ProgramRecord
  | .programLookup records _ | .interpreterStep records .. |
      .runFunction records .. | .invokeCall records .. => records

def kernelRequestSourceRva : AbstractKernelRequest -> Nat
  | .programLookup _ sourceRva | .interpreterStep _ _ sourceRva _ |
      .runFunction _ _ _ sourceRva _ => sourceRva
  | .invokeCall _ _ _ event _ => event.targetRva.toNat

/-- The exact original source and exact candidate-table record selected for
one semantic transfer.  `lookupExact` rules out an ambiguous or unrelated
record at the same source RVA. -/
structure ExactOriginalSemanticSource
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (reachability : ExactOriginalDecodedReachability context authority launch root)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate) where
  targetId : Nat
  source : OriginalDecodedSource
  sourceExact : context.source? targetId = some source
  reachable : targetId ∈ reachability.targetIds
  record : ProgramRecord
  recordSourceExact : record.sourceRva = source.target.rva
  lookupExact : lookupProgramRecord candidateAuthority.semanticRecords
      source.target.rva = some record

def originalExecutionAtTargetId (targetId : Nat) : WorldExecution -> Prop
  | .running current .. | .callbackRunning current .. => current = targetId
  | _ => False

/-- An external protocol continuation can be classified at either its decoded
call source or its checked suspension. -/
def originalExecutionAtBoundarySource (targetId : Nat) : WorldExecution -> Prop
  | .running current .. | .callbackRunning current .. => current = targetId
  | .awaitingExternal suspension _ => suspension.sourceTargetId = targetId
  | _ => False

def nativeExecutionAtRva (rva : Nat) : NativeWorldExecution -> Prop
  | .running current .. => current = rva
  | _ => False

/-- The relational world extracted from the exact running candidate state
selected by a source classifier.  There is no constructor for returned,
terminated, faulted, or blocked states: callers must first prove that the
candidate is running at the classified RVA. -/
structure ExactNativeRunningWorldAtRva
    (rva : Nat) (before : NativeWorldExecution) where
  world : RelationalWorld
  worldExact : nativeExecutionWorld? before = some world

def exactNativeRunningWorldAtRva
    (atRva : nativeExecutionAtRva rva before) :
    ExactNativeRunningWorldAtRva rva before := by
  cases before with
  | running current undefinedSlot state calls eventIndex events world =>
      exact ⟨world, rfl⟩
  | returned state events world =>
      simp [nativeExecutionAtRva] at atRva
  | terminated events world =>
      simp [nativeExecutionAtRva] at atRva
  | fault cause =>
      simp [nativeExecutionAtRva] at atRva
  | blocked reason =>
      simp [nativeExecutionAtRva] at atRva

def nativeExecutionEvents? : NativeWorldExecution ->
    Option (List NativeExternalEvent)
  | .running _ _ _ _ _ events _ | .returned _ events _ |
      .terminated events _ => some events
  | .fault _ | .blocked _ => none

/-- Exact pointwise observable trace for one local mixed chunk.  Chunking is a
proof-engineering boundary, not an observable boundary: a finite kernel path
may cross any number of API calls, but every event remains paired in order.
`MixedRelationContract.eventObservationsRelated` has no proof-blocked case, so
this wrapper cannot hide a blocked transition. -/
structure CheckedMixedKernelObservations
    (contract : MixedRelationContract)
    (originalObservations candidateObservations :
      List WorldRelationalObservable) : Prop where
  pointwise : RelatedObservationLists contract.eventObservationsRelated
    originalObservations candidateObservations

theorem CheckedMixedKernelObservations.related
    (checked : CheckedMixedKernelObservations contract
      originalObservations candidateObservations) :
    RelatedObservationLists contract.eventObservationsRelated
      originalObservations candidateObservations :=
  checked.pointwise

/-- Exact local paths and their inductive endpoint.  This is a component-sized
proof object: both paths consume at least one transition and retain every
observable event. -/
structure MixedKernelChunkPaths
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution) where
  originalObservations : List WorldRelationalObservable
  candidateObservations : List WorldRelationalObservable
  originalAfter : WorldExecution
  candidateAfter : NativeWorldExecution
  originalPath : NonemptyRelatedPath original.pe32TransitionSystem
    originalBefore originalObservations originalAfter
  candidatePath : NonemptyRelatedPath candidate.transitionSystem
    candidateBefore candidateObservations candidateAfter
  observationsChecked : CheckedMixedKernelObservations contract
    originalObservations candidateObservations
  afterRelated : invariant.holds originalAfter candidateAfter

def MixedKernelChunkPaths.toComponent
    (paths : MixedKernelChunkPaths original candidate contract invariant
      originalBefore candidateBefore)
    (beforeRelated : invariant.holds originalBefore candidateBefore) :
    MixedWorldComponentChunkRefinement original candidate contract invariant
      originalBefore candidateBefore := {
  beforeRelated
  originalObservations := paths.originalObservations
  candidateObservations := paths.candidateObservations
  originalAfter := paths.originalAfter
  candidateAfter := paths.candidateAfter
  originalPath := paths.originalPath
  candidatePath := paths.candidatePath
  observationsRelated := paths.observationsChecked.related
  afterRelated := paths.afterRelated
}

/-- A semantic component cannot merely cite a local theorem.  It must apply
that theorem to an exact table request and carry one selected result with all
of the theorem's operation-level facts and the two exact operational paths. -/
structure MixedKernelOperationComponentCertificate
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (program : CompiledKernelProgram)
    (abi : KernelABIRelation)
    (dispatches : KernelDispatchRelation)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (sourceRva : Nat)
    (operation : KernelOperation)
    (entryRva : Nat)
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution) where
  request : AbstractKernelRequest
  response : AbstractKernelResponse
  beforeMachine : MachineState
  candidateMachineExact : candidateBefore.machine? = some beforeMachine
  requestOperationExact : request.operation = operation
  requestRecordsExact : kernelRequestSemanticRecords request =
    candidateAuthority.semanticRecords
  requestSourceExact : kernelRequestSourceRva request = sourceRva
  requestRelated : abi.requestRelated request beforeMachine
  transition : AbstractKernelTransition request response
  operationRefines : KernelOperationRefinesUsing program abi dispatches operation
  afterMachine : MachineState
  nativeEvents : List NativeExternalEvent
  entryExact : program.functionEntry? request.operation.role = some entryRva
  dispatched : dispatches entryRva beforeMachine afterMachine nativeEvents
  responseRelated : abi.responseRelated request response afterMachine nativeEvents
  frame : MemoryAgreesOutside (abi.scratchFootprint request)
    afterMachine.memory beforeMachine.memory
  paths : MixedKernelChunkPaths original candidate contract invariant
    originalBefore candidateBefore
  candidateAfterMachineExact : paths.candidateAfter.machine? = some afterMachine
  candidateAfterEventsExact : nativeExecutionEvents? paths.candidateAfter =
    some nativeEvents

theorem MixedKernelOperationComponentCertificate.operationApplied
    (certificate : MixedKernelOperationComponentCertificate original candidate
      contract invariant program abi dispatches candidateAuthority sourceRva
      operation entryRva originalBefore candidateBefore) :
    exists operationEntryRva afterMachine
        nativeEvents,
      program.functionEntry? operation.role = some operationEntryRva ∧
        dispatches operationEntryRva certificate.beforeMachine afterMachine nativeEvents ∧
        abi.responseRelated certificate.request certificate.response afterMachine
          nativeEvents ∧
        MemoryAgreesOutside (abi.scratchFootprint certificate.request)
          afterMachine.memory certificate.beforeMachine.memory := by
  exact certificate.operationRefines certificate.request certificate.beforeMachine
    certificate.requestOperationExact certificate.requestRelated
    certificate.response certificate.transition

def MixedKernelOperationComponentCertificate.toComponent
    (certificate : MixedKernelOperationComponentCertificate original candidate
      contract invariant program abi dispatches candidateAuthority sourceRva
      operation entryRva originalBefore candidateBefore)
    (beforeRelated : invariant.holds originalBefore candidateBefore) :
    MixedWorldComponentChunkRefinement original candidate contract invariant
      originalBefore candidateBefore :=
  certificate.paths.toComponent beforeRelated

/-- The source classifier contains only executable proof boundaries.  The
semantic and external-operation constructors bind candidate operation entries
to the checked `CompiledKernelProgram`; the external-boundary constructor is
reserved for an exact one-to-one protocol/callback path. -/
inductive MixedKernelRelatedSourceCase
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (launch : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext launch)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (program : CompiledKernelProgram)
    (candidateRootRva : Nat) :
    WorldExecution -> NativeWorldExecution -> Type where
  | launchDispatch
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launch originalRoot reachability candidate candidateAuthority)
      (sourceIsRoot : source.targetId = launch.rootTargetId)
      (originalAtSource : originalExecutionAtTargetId source.targetId originalBefore)
      (candidateAtRoot : nativeExecutionAtRva candidateRootRva candidateBefore) :
      MixedKernelRelatedSourceCase originalContext originalAuthority launch
        originalRoot reachability candidate candidateAuthority program candidateRootRva
        originalBefore candidateBefore
  | semanticTransfer
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launch originalRoot reachability candidate candidateAuthority)
      (operation : KernelOperation)
      (entryRva : Nat)
      (originalAtSource : originalExecutionAtTargetId source.targetId originalBefore)
      (candidateAtEntry : nativeExecutionAtRva entryRva candidateBefore)
      (entryExact : program.functionEntry? operation.role = some entryRva) :
      MixedKernelRelatedSourceCase originalContext originalAuthority launch
        originalRoot reachability candidate candidateAuthority program candidateRootRva
        originalBefore candidateBefore
  | externalOperation
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launch originalRoot reachability candidate candidateAuthority)
      (operation : KernelOperation)
      (entryRva : Nat)
      (originalAtSource : originalExecutionAtBoundarySource source.targetId
        originalBefore)
      (candidateAtEntry : nativeExecutionAtRva entryRva candidateBefore)
      (entryExact : program.functionEntry? operation.role = some entryRva) :
      MixedKernelRelatedSourceCase originalContext originalAuthority launch
        originalRoot reachability candidate candidateAuthority program candidateRootRva
        originalBefore candidateBefore
  | externalBoundary
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launch originalRoot reachability candidate candidateAuthority)
      (candidateRva : Nat)
      (originalAtSource : originalExecutionAtBoundarySource source.targetId
        originalBefore)
      (candidateAtSource : nativeExecutionAtRva candidateRva candidateBefore) :
      MixedKernelRelatedSourceCase originalContext originalAuthority launch
        originalRoot reachability candidate candidateAuthority program candidateRootRva
        originalBefore candidateBefore
  | returned (originalState candidateState : MachineState)
      (originalWorld candidateWorld : RelationalWorld)
      (candidateEvents : List NativeExternalEvent) :
      MixedKernelRelatedSourceCase originalContext originalAuthority launch
        originalRoot reachability candidate candidateAuthority program candidateRootRva
        (.returned originalState originalWorld)
        (.returned candidateState candidateEvents candidateWorld)
  | terminated (originalWorld candidateWorld : RelationalWorld)
      (candidateEvents : List NativeExternalEvent) :
      MixedKernelRelatedSourceCase originalContext originalAuthority launch
        originalRoot reachability candidate candidateAuthority program candidateRootRva
        (.terminated originalWorld) (.terminated candidateEvents candidateWorld)
  | fault (cause : ModeledFault) :
      MixedKernelRelatedSourceCase originalContext originalAuthority launch
        originalRoot reachability candidate candidateAuthority program candidateRootRva
        (.fault cause) (.fault cause)

/-- Classification is the sole exhaustive premise.  Its codomain has no
blocked fallback and every executable constructor carries exact source and
candidate-entry evidence. -/
structure MixedKernelSourceClassifier
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (launch : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext launch)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (program : CompiledKernelProgram)
    (candidateRootRva : Nat)
    (invariant : MixedExecutionInvariant reachability.targetIds contract) where
  classify : forall originalBefore candidateBefore,
    invariant.holds originalBefore candidateBefore ->
    MixedKernelRelatedSourceCase originalContext originalAuthority launch originalRoot
      reachability candidate candidateAuthority program candidateRootRva
      originalBefore candidateBefore

/-- Recurring composition may classify only runtime states.  Launch is a
one-time prefix handled before `ChunkedRelationalBisimulation`; retaining this
predicate on the classifier result prevents the launch arm from reappearing in
any later chunk. -/
def MixedKernelRelatedSourceCase.RuntimeOnly :
    MixedKernelRelatedSourceCase originalContext originalAuthority launch
      originalRoot reachability candidate candidateAuthority program
      candidateRootRva originalBefore candidateBefore -> Prop
  | .launchDispatch .. => False
  | .semanticTransfer .. | .externalOperation .. | .externalBoundary .. |
      .returned .. | .terminated .. | .fault .. => True

/-- A source classifier whose result is checked to exclude the launch arm for
every state admitted by the runtime invariant. -/
structure MixedKernelRuntimeSourceClassifier
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (launch : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext launch)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (program : CompiledKernelProgram)
    (candidateRootRva : Nat)
    (invariant : MixedExecutionInvariant reachability.targetIds contract) where
  classifier : MixedKernelSourceClassifier originalContext originalAuthority
    launch originalRoot reachability candidate candidateAuthority program
    candidateRootRva invariant
  runtimeOnly : forall originalBefore candidateBefore
      (related : invariant.holds originalBefore candidateBefore),
    (classifier.classify originalBefore candidateBefore related).RuntimeOnly

/-- All nonterminal local obligations, selected only after the closed source
classifier has established the exact boundary shape. -/
structure CheckedMixedKernelComponentCases
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (contract : MixedRelationContract)
    (launch : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext launch)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot)
    (candidateRootRva : Nat)
    (program : CompiledKernelProgram)
    (abi : KernelABIRelation)
    (dispatches : RelationalWorld -> KernelDispatchRelation)
    (invariant : MixedExecutionInvariant reachability.targetIds contract) where
  classifier : MixedKernelRuntimeSourceClassifier originalContext
    originalAuthority launch originalRoot reachability candidate
    candidateAuthority program candidateRootRva invariant
  semanticChunk : forall originalBefore candidateBefore
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launch originalRoot reachability candidate candidateAuthority)
      (operation : KernelOperation) (entryRva : Nat)
      (beforeRelated : invariant.holds originalBefore candidateBefore)
      (originalAtSource :
        originalExecutionAtTargetId source.targetId originalBefore)
      (candidateAtEntry : nativeExecutionAtRva entryRva candidateBefore)
      (candidateWorld : RelationalWorld)
      (candidateWorldExact :
        nativeExecutionWorld? candidateBefore = some candidateWorld)
      (entryExact :
        program.functionEntry? operation.role = some entryRva)
      (classified :
        classifier.classifier.classify originalBefore candidateBefore
            beforeRelated =
          .semanticTransfer source operation entryRva originalAtSource
            candidateAtEntry entryExact),
    MixedKernelOperationComponentCertificate original candidate contract invariant
      program abi (dispatches candidateWorld) candidateAuthority
      source.source.target.rva operation entryRva originalBefore candidateBefore
  externalOperationChunk : forall originalBefore candidateBefore
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launch originalRoot reachability candidate candidateAuthority)
      (operation : KernelOperation) (entryRva : Nat)
      (beforeRelated : invariant.holds originalBefore candidateBefore)
      (originalAtSource :
        originalExecutionAtBoundarySource source.targetId originalBefore)
      (candidateAtEntry : nativeExecutionAtRva entryRva candidateBefore)
      (candidateWorld : RelationalWorld)
      (candidateWorldExact :
        nativeExecutionWorld? candidateBefore = some candidateWorld)
      (entryExact :
        program.functionEntry? operation.role = some entryRva)
      (classified :
        classifier.classifier.classify originalBefore candidateBefore
            beforeRelated =
          .externalOperation source operation entryRva originalAtSource
            candidateAtEntry entryExact),
    MixedKernelOperationComponentCertificate original candidate contract invariant
      program abi (dispatches candidateWorld) candidateAuthority
      source.source.target.rva operation entryRva originalBefore candidateBefore
  externalBoundaryChunk : forall originalBefore candidateBefore
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launch originalRoot reachability candidate candidateAuthority)
      (candidateRva : Nat)
      (beforeRelated : invariant.holds originalBefore candidateBefore)
      (originalAtSource :
        originalExecutionAtBoundarySource source.targetId originalBefore)
      (candidateAtSource :
        nativeExecutionAtRva candidateRva candidateBefore)
      (classified :
        classifier.classifier.classify originalBefore candidateBefore
            beforeRelated =
          .externalBoundary source candidateRva originalAtSource
            candidateAtSource),
    MixedKernelChunkPaths original candidate contract invariant
      originalBefore candidateBefore

private def terminalReturnedComponent
    (beforeRelated : invariant.holds
      (.returned originalState originalWorld)
      (.returned candidateState candidateEvents candidateWorld)) :
    MixedWorldComponentChunkRefinement original candidate contract invariant
      (.returned originalState originalWorld)
      (.returned candidateState candidateEvents candidateWorld) := by
  refine {
    beforeRelated
    originalObservations := []
    candidateObservations := []
    originalAfter := .returned originalState originalWorld
    candidateAfter := .returned candidateState candidateEvents candidateWorld
    originalPath := ?_
    candidatePath := ?_
    observationsRelated := by trivial
    afterRelated := beforeRelated
  }
  · simpa [DecodedWorldProgram.pe32TransitionSystem,
      stepPE32WorldExecution] using
      (nonemptyRelatedPath_one original.pe32TransitionSystem
        (.returned originalState originalWorld))
  · simpa [ExactNativeWorldProgram.transitionSystem,
      stepPE32NativeWorldExecution] using
      (nonemptyRelatedPath_one candidate.transitionSystem
        (.returned candidateState candidateEvents candidateWorld))

private def terminalTerminatedComponent
    (beforeRelated : invariant.holds (.terminated originalWorld)
      (.terminated candidateEvents candidateWorld)) :
    MixedWorldComponentChunkRefinement original candidate contract invariant
      (.terminated originalWorld) (.terminated candidateEvents candidateWorld) := by
  refine {
    beforeRelated
    originalObservations := []
    candidateObservations := []
    originalAfter := .terminated originalWorld
    candidateAfter := .terminated candidateEvents candidateWorld
    originalPath := ?_
    candidatePath := ?_
    observationsRelated := by trivial
    afterRelated := beforeRelated
  }
  · simpa [DecodedWorldProgram.pe32TransitionSystem,
      stepPE32WorldExecution] using
      (nonemptyRelatedPath_one original.pe32TransitionSystem
        (.terminated originalWorld))
  · simpa [ExactNativeWorldProgram.transitionSystem,
      stepPE32NativeWorldExecution] using
      (nonemptyRelatedPath_one candidate.transitionSystem
        (.terminated candidateEvents candidateWorld))

private def terminalFaultComponent
    (beforeRelated : invariant.holds (.fault cause) (.fault cause)) :
    MixedWorldComponentChunkRefinement original candidate contract invariant
      (.fault cause) (.fault cause) := by
  refine {
    beforeRelated
    originalObservations := []
    candidateObservations := []
    originalAfter := .fault cause
    candidateAfter := .fault cause
    originalPath := ?_
    candidatePath := ?_
    observationsRelated := by trivial
    afterRelated := beforeRelated
  }
  · simpa [DecodedWorldProgram.pe32TransitionSystem,
      stepPE32WorldExecution] using
      (nonemptyRelatedPath_one original.pe32TransitionSystem (.fault cause))
  · simpa [ExactNativeWorldProgram.transitionSystem,
      stepPE32NativeWorldExecution] using
      (nonemptyRelatedPath_one candidate.transitionSystem (.fault cause))

/-- Reduce the mixed component obligation to the checked classifier and its
local operation/boundary cases. -/
def CheckedMixedKernelComponentCases.component
    (cases : CheckedMixedKernelComponentCases originalContext originalAuthority
      original candidate candidateAuthority contract launch originalRoot reachability
      candidateRootRva program abi dispatches invariant)
    (originalBefore : WorldExecution) (candidateBefore : NativeWorldExecution)
    (beforeRelated : invariant.holds originalBefore candidateBefore) :
    MixedWorldComponentChunkRefinement original candidate contract invariant
      originalBefore candidateBefore := by
  have runtimeOnly := cases.classifier.runtimeOnly originalBefore candidateBefore
    beforeRelated
  cases classified : cases.classifier.classifier.classify originalBefore
      candidateBefore beforeRelated with
  | launchDispatch source sourceIsRoot originalAtSource candidateAtRoot =>
      rw [classified] at runtimeOnly
      exact False.elim runtimeOnly
  | semanticTransfer source operation entryRva originalAtSource candidateAtEntry
      entryExact =>
      let candidateRunning := exactNativeRunningWorldAtRva candidateAtEntry
      exact (cases.semanticChunk originalBefore candidateBefore source operation
        entryRva beforeRelated originalAtSource candidateAtEntry
        candidateRunning.world candidateRunning.worldExact entryExact classified).toComponent
          beforeRelated
  | externalOperation source operation entryRva originalAtSource candidateAtEntry
      entryExact =>
      let candidateRunning := exactNativeRunningWorldAtRva candidateAtEntry
      exact (cases.externalOperationChunk originalBefore candidateBefore source
        operation entryRva beforeRelated originalAtSource candidateAtEntry
        candidateRunning.world candidateRunning.worldExact entryExact
        classified).toComponent
          beforeRelated
  | externalBoundary source candidateRva originalAtSource candidateAtSource =>
      exact (cases.externalBoundaryChunk originalBefore candidateBefore source
        candidateRva beforeRelated originalAtSource candidateAtSource
        classified).toComponent beforeRelated
  | returned originalState candidateState originalWorld candidateWorld
      candidateEvents =>
      exact terminalReturnedComponent beforeRelated
  | terminated originalWorld candidateWorld candidateEvents =>
      exact terminalTerminatedComponent beforeRelated
  | fault cause => exact terminalFaultComponent beforeRelated

/-- Construct the existing mixed-world composition without duplicating its
launch or acceptance logic.  The `component` field is definitionally reduced
to the closed classifier above. -/
def CheckedMixedKernelComponentCases.toMixedWorldChunkComposition
    (cases : CheckedMixedKernelComponentCases originalContext originalAuthority
      original candidate candidateAuthority contract launch originalRoot reachability
      candidateRootRva program abi dispatches invariant)
    : MixedWorldChunkComposition originalContext originalAuthority original candidate
      candidateAuthority programBinding contract launch originalRoot reachability
      candidateRootRva candidateRoot := {
  invariant
  component := cases.component
}

#print axioms CheckedMixedKernelObservations.related
#print axioms MixedKernelOperationComponentCertificate.operationApplied
#print axioms MixedKernelOperationComponentCertificate.toComponent
#print axioms CheckedMixedKernelComponentCases.component
#print axioms CheckedMixedKernelComponentCases.toMixedWorldChunkComposition

end StageA.Relational.InterpreterMixedKernelComposition
