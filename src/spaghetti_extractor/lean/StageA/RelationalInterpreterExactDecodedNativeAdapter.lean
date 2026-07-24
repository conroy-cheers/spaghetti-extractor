import StageA.RelationalInterpreterMixedComponentComposition
import StageA.RelationalInterpreterWholeProgramAcceptance
import StageA.RelationalInterpreterWorldBridge

namespace StageA.Relational.InterpreterExactDecodedNativeAdapter

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterAcceptance
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedComponentComposition
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWholeProgramAcceptance
open StageA.Relational.InterpreterWorldBridge

/-!
# Exact decoded-candidate/native-candidate adapter assembly

This layer specializes the checked interpreter-kernel products to the missing
candidate-carrier bridge.  The decoded side is explicitly the candidate view
of `StaticProofContext`; the native side executes the same exact candidate PE
one instruction at a time.

Static artifact authority, operation refinements, launch-root parsing, and
launch-frame recovery are assembled here.  The remaining path premises are
intentionally operational: a total classifier must select a supported source
case, and that case must produce nonempty paths with exactly equal retained
observations.  No Boolean result can manufacture those paths.
-/

/-- Exact native artifact and compiled-kernel evidence shared by every local
candidate-carrier chunk.
-/
structure ExactDecodedNativeKernelEvidence
    (context : StaticProofContext)
    (native : ExactNativeWorldProgram) where
  candidatePeBound : native.pe = context.candidatePe
  candidateImportsBound : native.imports = context.candidateImports
  nativeAuthority : ExactNativeCandidateAuthority native
  programTable : ExactCompiledProgramTable context
  kernelCore : ExactCompiledInterpreterKernelCore context programTable
  operations : CheckedKernelOperationRefinementFamily kernelCore.program
    kernelCore.abi

/-- Static binding of an arbitrary decoded program to the candidate half of
the canonical context and to the exact native PE.
-/
structure ExactDecodedCandidateProgramBinding
    (context : StaticProofContext)
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram) where
  decodedRole : decoded.candidate = true
  decodedContext : decoded.context = context
  candidatePeBound : decoded.context.candidatePe = native.pe
  candidateImportsBound : decoded.context.candidateImports = native.imports

def exactDecodedCandidateProgramBinding
    (evidence : ExactDecodedNativeKernelEvidence context native)
    (regions : List RegionRelation)
    (externalCallSites : List ExternalCallSiteContract)
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment) :
    ExactDecodedCandidateProgramBinding context
      (decodedCandidateProgram context regions externalCallSites environment
        protocolEnvironment)
      native := {
  decodedRole := rfl
  decodedContext := rfl
  candidatePeBound := evidence.candidatePeBound.symm
  candidateImportsBound := evidence.candidateImportsBound.symm
}

/-- Deterministic launch frames selected from the checked candidate PE launch
inventory.  Choice is used only to project the witness already proved by
`candidateNativeLaunchCallFrames?_exists`.
-/
noncomputable def exactDecodedNativeLaunchCalls
    {native : ExactNativeWorldProgram}
    {launch : PE32ConsoleLaunchV2}
    {candidateRootRva : Nat}
    (root : DirectExactCandidateNativeLaunchRoot native launch candidateRootRva)
    (frameCount : launch.frameOffsets.length =
      launch.continuationTargetIds.length)
    (state : MachineState) : List NativeCallFrame :=
  Classical.choose
    (candidateNativeLaunchCallFrames?_exists root frameCount state)

theorem exactDecodedNativeLaunchCalls_exact
    {native : ExactNativeWorldProgram}
    {launch : PE32ConsoleLaunchV2}
    {candidateRootRva : Nat}
    (root : DirectExactCandidateNativeLaunchRoot native launch candidateRootRva)
    (frameCount : launch.frameOffsets.length =
      launch.continuationTargetIds.length)
    (state : MachineState) :
    candidateNativeLaunchCallFrames? native launch state =
      some (exactDecodedNativeLaunchCalls root frameCount state) :=
  Classical.choose_spec
    (candidateNativeLaunchCallFrames?_exists root frameCount state)

/-- One exact candidate-carrier chunk.  This is deliberately smaller than a
whole-program simulation: it covers only one source selected by the closed
classifier below.
-/
structure ExactDecodedNativeComponentChunk
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram)
    (relation : WorldExecution -> NativeWorldExecution -> Prop)
    (decodedBefore : WorldExecution)
    (nativeBefore : NativeWorldExecution) where
  decodedObservations : List WorldRelationalObservable
  nativeObservations : List WorldRelationalObservable
  decodedAfter : WorldExecution
  nativeAfter : NativeWorldExecution
  decodedPath : NonemptyRelatedPath decoded.pe32TransitionSystem decodedBefore
    decodedObservations decodedAfter
  nativePath : NonemptyRelatedPath native.transitionSystem nativeBefore
    nativeObservations nativeAfter
  observationsExact : decodedObservations = nativeObservations
  afterRelated : relation decodedAfter nativeAfter

/-- Exhaustive supported source families for the generated interpreter
candidate.  There is no blocked, unknown, or catch-all constructor.
-/
inductive ExactDecodedNativeSourceCase
    (program : CompiledKernelProgram) :
    WorldExecution -> NativeWorldExecution -> Type where
  | launchWrapper :
      ExactDecodedNativeSourceCase program decodedBefore nativeBefore
  | kernelOperation
      (operation : KernelOperation) (entryRva : Nat)
      (entryExact : program.functionEntry? operation.role = some entryRva) :
      ExactDecodedNativeSourceCase program decodedBefore nativeBefore
  | externalBoundary :
      ExactDecodedNativeSourceCase program decodedBefore nativeBefore
  | x87Replay :
      ExactDecodedNativeSourceCase program decodedBefore nativeBefore
  | returned
      (decodedState nativeState : MachineState)
      (world : RelationalWorld) (events : List NativeExternalEvent) :
      ExactDecodedNativeSourceCase program
        (.returned decodedState world)
        (.returned nativeState events world)
  | terminated (world : RelationalWorld)
      (events : List NativeExternalEvent) :
      ExactDecodedNativeSourceCase program
        (.terminated world) (.terminated events world)
  | fault (cause : ModeledFault) :
      ExactDecodedNativeSourceCase program (.fault cause) (.fault cause)

/-- Remaining semantic premises after exact artifact, kernel, operation, and
launch evidence have been assembled.

The four chunk factories are path obligations.  The kernel factory receives
the already checked operation refinement selected from `operations`; callers
cannot substitute an unrelated dispatch theorem.
-/
structure ExactDecodedNativeComponentPremises
    (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (launch : PE32ConsoleLaunchV2)
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram)
    (evidence : ExactDecodedNativeKernelEvidence context native)
    (candidateRootRva : Nat)
    (candidateRoot : DirectExactCandidateNativeLaunchRoot native launch
      candidateRootRva)
    (frameCount : launch.frameOffsets.length =
      launch.continuationTargetIds.length) where
  relation : WorldExecution -> NativeWorldExecution -> Prop
  classify : forall decodedBefore nativeBefore,
    relation decodedBefore nativeBefore ->
      ExactDecodedNativeSourceCase evidence.kernelCore.program
        decodedBefore nativeBefore
  rootsRelated : forall world originalState candidateState,
    launch.StatesRelated context graph reachability world originalState
        candidateState ->
      relation
        (.running launch.rootTargetId candidateState
          launch.continuationTargetIds 0 world)
        (.running candidateRootRva 0 candidateState
          (exactDecodedNativeLaunchCalls candidateRoot frameCount candidateState)
          0 [] world)
  launchChunk : forall decodedBefore nativeBefore,
    relation decodedBefore nativeBefore ->
      ExactDecodedNativeComponentChunk decoded native relation
        decodedBefore nativeBefore
  kernelChunk : forall decodedBefore nativeBefore,
    relation decodedBefore nativeBefore ->
      forall operation entryRva,
        evidence.kernelCore.program.functionEntry? operation.role =
            some entryRva ->
        KernelOperationRefinesUsing evidence.kernelCore.program
          evidence.kernelCore.abi
          (combinedKernelDispatchRelation evidence.operations.dispatchFamily)
          operation ->
        ExactDecodedNativeComponentChunk decoded native relation
          decodedBefore nativeBefore
  externalBoundaryChunk : forall decodedBefore nativeBefore,
    relation decodedBefore nativeBefore ->
      ExactDecodedNativeComponentChunk decoded native relation
        decodedBefore nativeBefore
  x87ReplayChunk : forall decodedBefore nativeBefore,
    relation decodedBefore nativeBefore ->
      ExactDecodedNativeComponentChunk decoded native relation
        decodedBefore nativeBefore

private def terminalReturnedChunk
    (beforeRelated : relation
      (.returned decodedState world)
      (.returned nativeState events world)) :
    ExactDecodedNativeComponentChunk decoded native relation
      (.returned decodedState world)
      (.returned nativeState events world) := {
  decodedObservations := []
  nativeObservations := []
  decodedAfter := .returned decodedState world
  nativeAfter := .returned nativeState events world
  decodedPath := by
    simpa [DecodedWorldProgram.pe32TransitionSystem,
      stepPE32WorldExecution] using
      (nonemptyRelatedPath_one decoded.pe32TransitionSystem
        (.returned decodedState world))
  nativePath := by
    simpa [ExactNativeWorldProgram.transitionSystem,
      stepPE32NativeWorldExecution] using
      (nonemptyRelatedPath_one native.transitionSystem
        (.returned nativeState events world))
  observationsExact := rfl
  afterRelated := beforeRelated
}

private def terminalTerminatedChunk
    (beforeRelated : relation
      (.terminated world) (.terminated events world)) :
    ExactDecodedNativeComponentChunk decoded native relation
      (.terminated world) (.terminated events world) := {
  decodedObservations := []
  nativeObservations := []
  decodedAfter := .terminated world
  nativeAfter := .terminated events world
  decodedPath := by
    simpa [DecodedWorldProgram.pe32TransitionSystem,
      stepPE32WorldExecution] using
      (nonemptyRelatedPath_one decoded.pe32TransitionSystem
        (.terminated world))
  nativePath := by
    simpa [ExactNativeWorldProgram.transitionSystem,
      stepPE32NativeWorldExecution] using
      (nonemptyRelatedPath_one native.transitionSystem
        (.terminated events world))
  observationsExact := rfl
  afterRelated := beforeRelated
}

private def terminalFaultChunk
    (beforeRelated : relation (.fault cause) (.fault cause)) :
    ExactDecodedNativeComponentChunk decoded native relation
      (.fault cause) (.fault cause) := {
  decodedObservations := []
  nativeObservations := []
  decodedAfter := .fault cause
  nativeAfter := .fault cause
  decodedPath := by
    simpa [DecodedWorldProgram.pe32TransitionSystem,
      stepPE32WorldExecution] using
      (nonemptyRelatedPath_one decoded.pe32TransitionSystem (.fault cause))
  nativePath := by
    simpa [ExactNativeWorldProgram.transitionSystem,
      stepPE32NativeWorldExecution] using
      (nonemptyRelatedPath_one native.transitionSystem (.fault cause))
  observationsExact := rfl
  afterRelated := beforeRelated
}

def ExactDecodedNativeComponentPremises.component
    (premises : ExactDecodedNativeComponentPremises context graph reachability
      launch decoded native evidence candidateRootRva candidateRoot frameCount)
    (decodedBefore : WorldExecution) (nativeBefore : NativeWorldExecution)
    (beforeRelated : premises.relation decodedBefore nativeBefore) :
    ExactDecodedNativeComponentChunk decoded native premises.relation
      decodedBefore nativeBefore := by
  cases premises.classify decodedBefore nativeBefore beforeRelated with
  | launchWrapper =>
      exact premises.launchChunk decodedBefore nativeBefore beforeRelated
  | kernelOperation operation entryRva entryExact =>
      exact premises.kernelChunk decodedBefore nativeBefore beforeRelated
        operation entryRva entryExact
        (evidence.operations.combinedRefines operation)
  | externalBoundary =>
      exact premises.externalBoundaryChunk decodedBefore nativeBefore
        beforeRelated
  | x87Replay =>
      exact premises.x87ReplayChunk decodedBefore nativeBefore beforeRelated
  | returned decodedState nativeState world events =>
      exact terminalReturnedChunk beforeRelated
  | terminated world events =>
      exact terminalTerminatedChunk beforeRelated
  | fault cause =>
      exact terminalFaultChunk beforeRelated

/-- Assemble the full exact decoded/native chunk adapter.  Static bindings,
native authority, operation selection, launch frames, and terminal behavior
are discharged here; only the typed component premises remain supplied.
-/
noncomputable def ExactDecodedNativeComponentPremises.toChunkAdapter
    (premises : ExactDecodedNativeComponentPremises context graph reachability
      launch decoded native evidence candidateRootRva candidateRoot frameCount)
    (binding : ExactDecodedCandidateProgramBinding context decoded native) :
    ExactDecodedNativeChunkAdapter context graph reachability launch decoded
      native := {
  decodedRole := binding.decodedRole
  decodedContext := binding.decodedContext
  candidatePeBound := binding.candidatePeBound
  candidateImportsBound := binding.candidateImportsBound
  nativeAuthority := evidence.nativeAuthority
  candidateRootRva
  candidateRoot
  candidateLaunchCalls :=
    exactDecodedNativeLaunchCalls candidateRoot frameCount
  candidateLaunchCallsExact :=
    exactDecodedNativeLaunchCalls_exact candidateRoot frameCount
  relation := premises.relation
  rootsRelated := premises.rootsRelated
  chunksRefineExact := by
    intro decodedBefore nativeBefore related
    let chunk := premises.component decodedBefore nativeBefore related
    exact ⟨chunk.decodedObservations, chunk.nativeObservations,
      chunk.decodedAfter, chunk.nativeAfter, chunk.decodedPath,
      chunk.nativePath, chunk.observationsExact, chunk.afterRelated⟩
}

#print axioms exactDecodedCandidateProgramBinding
#print axioms exactDecodedNativeLaunchCalls_exact
#print axioms ExactDecodedNativeComponentPremises.component
#print axioms ExactDecodedNativeComponentPremises.toChunkAdapter

end StageA.Relational.InterpreterExactDecodedNativeAdapter
