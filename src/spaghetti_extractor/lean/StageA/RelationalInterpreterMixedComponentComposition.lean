import StageA.RelationalInterpreterMixedKernelComposition
import StageA.RelationalInterpreterMixedProfile

namespace StageA.Relational.InterpreterMixedComponentComposition

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedLaunchRefinement
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

/-! # Environment-parametric mixed component composition

This module turns four independently checked kernel-operation refinements and
environment-indexed local path certificates into the single component
composition consumed by mixed whole-program acceptance.

The constructors deliberately do not infer a source classifier, local paths,
launch frames, or an external protocol bridge.  Those are semantic proof
frontiers and remain explicit typed premises.  What this layer contributes is
coherence: the same operation dispatch family, invariant, classifier, and path
factories are used for every original/candidate environment pair.
-/

/-- Four operation-specific native dispatch relations and their local
refinement theorems.  Keeping the relations separate lets each operation proof
retain its natural execution predicate; `dispatchFamily` below assembles the
single indexed family required by whole-program composition. -/
structure CheckedKernelOperationRefinementFamily
    (program : CompiledKernelProgram) (abi : KernelABIRelation) where
  programLookupDispatch : KernelDispatchRelation
  interpreterStepDispatch : KernelDispatchRelation
  runFunctionDispatch : KernelDispatchRelation
  invokeCallDispatch : KernelDispatchRelation
  programLookupRefines : KernelOperationRefinesUsing program abi
    programLookupDispatch .programLookup
  interpreterStepRefines : KernelOperationRefinesUsing program abi
    interpreterStepDispatch .interpreterStep
  runFunctionRefines : KernelOperationRefinesUsing program abi
    runFunctionDispatch .runFunction
  invokeCallRefines : KernelOperationRefinesUsing program abi
    invokeCallDispatch .invokeCall

def CheckedKernelOperationRefinementFamily.dispatchFamily
    (checked : CheckedKernelOperationRefinementFamily program abi) :
    KernelOperationDispatchFamily
  | .programLookup => checked.programLookupDispatch
  | .interpreterStep => checked.interpreterStepDispatch
  | .runFunction => checked.runFunctionDispatch
  | .invokeCall => checked.invokeCallDispatch

theorem CheckedKernelOperationRefinementFamily.refines
    (checked : CheckedKernelOperationRefinementFamily program abi)
    (operation : KernelOperation) :
    KernelOperationRefinesUsing program abi
      (checked.dispatchFamily operation) operation := by
  cases operation with
  | programLookup => exact checked.programLookupRefines
  | interpreterStep => exact checked.interpreterStepRefines
  | runFunction => exact checked.runFunctionRefines
  | invokeCall => exact checked.invokeCallRefines

theorem CheckedKernelOperationRefinementFamily.combinedRefines
    (checked : CheckedKernelOperationRefinementFamily program abi)
    (operation : KernelOperation) :
    KernelOperationRefinesUsing program abi
      (combinedKernelDispatchRelation checked.dispatchFamily) operation :=
  kernelOperationRefinesUsing_combined checked.dispatchFamily
    (checked.refines operation)

abbrev OriginalProgramWithEnvironment
    (original : DecodedWorldProgram)
    (environment : WorldExternalProtocolEnvironment) : DecodedWorldProgram :=
  decodedWorldProgramWithProtocolEnvironment original environment

abbrev CandidateProgramWithEnvironment
    (candidate : ExactNativeWorldProgram)
    (environment : NativeWorldEnvironment) : ExactNativeWorldProgram :=
  exactNativeWorldProgramWithEnvironment candidate environment

abbrev CandidateAuthorityWithEnvironment
    (authority : ExactNativeCandidateAuthority candidate)
    (environment : NativeWorldEnvironment) :
    ExactNativeCandidateAuthority
      (CandidateProgramWithEnvironment candidate environment) :=
  exactNativeCandidateAuthorityWithEnvironment authority environment

abbrev MixedEnvironmentPairRefines
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedExternalFrameContract)
    (originalEnvironment : WorldExternalProtocolEnvironment)
    (candidateEnvironment : NativeWorldEnvironment) : Prop :=
  ExactOneToOneMixedExternalEnvironmentsRefine
    (OriginalProgramWithEnvironment original originalEnvironment)
    (CandidateProgramWithEnvironment candidate candidateEnvironment)
    contract frames

/-- The remaining semantic premises for mixed component composition.

Every path-producing field is indexed by the concrete environment pair and by
the proof that the pair obeys the exact one-to-one external protocol.  This
prevents a certificate proved for one favorable environment from being reused
as the universal whole-program environment composition.
-/

abbrev CanonicalOriginalMixedLaunchExecution
    (launch : PE32ConsoleLaunchV2) (state : MachineState)
    (world : RelationalWorld) : WorldExecution :=
  .running launch.rootTargetId state launch.continuationTargetIds 0 world

abbrev CanonicalCandidateMixedLaunchExecution
    (candidateRootRva : Nat) (state : MachineState)
    (calls : List NativeCallFrame) (world : RelationalWorld) :
    NativeWorldExecution :=
  .running candidateRootRva 0 state calls 0 [] world

/-- The two cross-system launch facts not established by canonical native
wrapper replay: a silent decoded-original path and closure of the caller's
actual invariant at the two selected endpoints. -/
structure CanonicalMixedLaunchChunkRemainingPremises
    (original : DecodedWorldProgram)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (originalBefore : WorldExecution)
    (candidateAfter : NativeWorldExecution) where
  originalAfter : WorldExecution
  originalPath : NonemptyRelatedPath original.pe32TransitionSystem
    originalBefore [] originalAfter
  afterRelated : invariant.holds originalAfter candidateAfter

/-- Canonical launch shapes and the exact residual mixed premises.

The type is indexed by `beforeRelated`, rather than accepting a path object
that duplicates the invariant selected by component composition.  The
remaining factory is indexed by the concrete endpoint and runtime relation
established by `CanonicalMixedLaunchWrapperRefinement`.
-/
structure CanonicalMixedLaunchComponentPremises
    (originalContext : OriginalDecodedStaticContext)
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (launch : PE32ConsoleLaunchV2)
    (candidateRootRva : Nat)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (candidateLaunchCalls : MachineState -> List NativeCallFrame)
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution)
    (_beforeRelated : invariant.holds originalBefore candidateBefore) where
  originalWorld : RelationalWorld
  candidateWorld : RelationalWorld
  originalState : MachineState
  candidateState : MachineState
  originalBeforeExact : originalBefore =
    CanonicalOriginalMixedLaunchExecution launch originalState originalWorld
  candidateBeforeExact : candidateBefore =
    CanonicalCandidateMixedLaunchExecution candidateRootRva candidateState
      (candidateLaunchCalls candidateState) candidateWorld
  launchStatesRelated : MixedLaunchStatesRelated originalContext candidate
    contract originalWorld candidateWorld originalState candidateState
  remaining : forall candidateAfter candidateAfterState,
    candidateAfter.machine? = some candidateAfterState ->
    contract.runtimeStatesRelated originalWorld candidateWorld originalState
        candidateAfterState ->
      CanonicalMixedLaunchChunkRemainingPremises original invariant
        originalBefore candidateAfter

/-- Canonical wrapper refinement supplies the complete native side of a mixed
launch chunk.  Only the decoded silent path and endpoint invariant are selected
from `premises.remaining`. -/
theorem CanonicalMixedLaunchWrapperRefinement.launchChunk_nonempty
    (refinement : CanonicalMixedLaunchWrapperRefinement originalContext
      candidate contract launch)
    (root : CanonicalNativeLaunchRoot)
    (rootExact : root.rva? candidate.pe = some candidateRootRva)
    (candidateLaunchCalls : MachineState -> List NativeCallFrame)
    (candidateLaunchCallsExact : forall candidateState,
      candidateNativeLaunchCallFrames? candidate launch candidateState =
        some (candidateLaunchCalls candidateState))
    (beforeRelated : invariant.holds originalBefore candidateBefore)
    (premises : CanonicalMixedLaunchComponentPremises originalContext original
      candidate contract launch candidateRootRva invariant candidateLaunchCalls
      originalBefore candidateBefore beforeRelated) :
    Nonempty (MixedKernelChunkPaths original candidate contract invariant
      originalBefore candidateBefore) := by
  rcases premises with
    ⟨originalWorld, candidateWorld, originalState, candidateState,
      originalBeforeExact, candidateBeforeExact, launchStatesRelated, remaining⟩
  subst originalBefore
  subst candidateBefore
  rcases refinement.rootsEstablishRuntime root candidateRootRva originalWorld
      candidateWorld originalState candidateState
      (candidateLaunchCalls candidateState) rootExact launchStatesRelated
      (candidateLaunchCallsExact candidateState) with
    ⟨route, result, candidateAfterState, _, _, replayed, observationsExact,
      candidateAfterMachine, runtimeStatesRelated⟩
  have candidatePath :=
    (route.replay?_sound candidate refinement.reflected.cutpoints
      (CanonicalCandidateMixedLaunchExecution candidateRootRva candidateState
        (candidateLaunchCalls candidateState) candidateWorld)
      result replayed).2.2
  let residual := remaining result.after candidateAfterState
    candidateAfterMachine runtimeStatesRelated
  refine ⟨{
    originalObservations := []
    candidateObservations := []
    originalAfter := residual.originalAfter
    candidateAfter := result.after
    originalPath := residual.originalPath
    candidatePath := ?_
    observationsChecked := ⟨by trivial⟩
    afterRelated := residual.afterRelated
  }⟩
  simpa [observationsExact] using candidatePath

noncomputable def CanonicalMixedLaunchWrapperRefinement.launchChunk
    (refinement : CanonicalMixedLaunchWrapperRefinement originalContext
      candidate contract launch)
    (root : CanonicalNativeLaunchRoot)
    (rootExact : root.rva? candidate.pe = some candidateRootRva)
    (candidateLaunchCalls : MachineState -> List NativeCallFrame)
    (candidateLaunchCallsExact : forall candidateState,
      candidateNativeLaunchCallFrames? candidate launch candidateState =
        some (candidateLaunchCalls candidateState))
    (beforeRelated : invariant.holds originalBefore candidateBefore)
    (premises : CanonicalMixedLaunchComponentPremises originalContext original
      candidate contract launch candidateRootRva invariant candidateLaunchCalls
      originalBefore candidateBefore beforeRelated) :
    MixedKernelChunkPaths original candidate contract invariant
      originalBefore candidateBefore :=
  Classical.choice
    (CanonicalMixedLaunchWrapperRefinement.launchChunk_nonempty refinement root
      rootExact candidateLaunchCalls candidateLaunchCallsExact beforeRelated
      premises)

structure EnvironmentParametricMixedComponentPremises
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (contract : MixedRelationContract)
    (externalFrames : MixedExternalFrameContract)
    (launch : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext launch)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot)
    (candidateRootRva : Nat)
    (program : CompiledKernelProgram)
    (abi : KernelABIRelation)
    (operations : CheckedKernelOperationRefinementFamily program abi)
    (invariant : MixedExecutionInvariant reachability.targetIds contract) where
  classifier : forall candidateEnvironment,
    MixedKernelSourceClassifier originalContext originalAuthority launch
      originalRoot reachability
      (CandidateProgramWithEnvironment candidate candidateEnvironment)
      (CandidateAuthorityWithEnvironment candidateAuthority candidateEnvironment)
      program candidateRootRva invariant
  candidateLaunchCalls :
    NativeWorldEnvironment -> MachineState -> List NativeCallFrame
  candidateLaunchCallsExact : forall candidateEnvironment candidateState,
    candidateNativeLaunchCallFrames?
        (CandidateProgramWithEnvironment candidate candidateEnvironment)
        launch candidateState =
      some (candidateLaunchCalls candidateEnvironment candidateState)
  launchWrapperRefines : forall originalEnvironment candidateEnvironment,
    MixedEnvironmentPairRefines original candidate contract externalFrames
        originalEnvironment candidateEnvironment ->
      CanonicalMixedLaunchWrapperRefinement originalContext
        (CandidateProgramWithEnvironment candidate candidateEnvironment)
        contract launch
  launchChunk : forall originalEnvironment candidateEnvironment,
    MixedEnvironmentPairRefines original candidate contract externalFrames
        originalEnvironment candidateEnvironment ->
      forall originalBefore candidateBefore
        (source : ExactOriginalSemanticSource originalContext originalAuthority
          launch originalRoot reachability
          (CandidateProgramWithEnvironment candidate candidateEnvironment)
          (CandidateAuthorityWithEnvironment candidateAuthority
            candidateEnvironment)),
        (beforeRelated : invariant.holds originalBefore candidateBefore) ->
        source.targetId = launch.rootTargetId ->
        originalExecutionAtTargetId source.targetId originalBefore ->
        nativeExecutionAtRva candidateRootRva candidateBefore ->
        CanonicalMixedLaunchComponentPremises originalContext
          (OriginalProgramWithEnvironment original originalEnvironment)
          (CandidateProgramWithEnvironment candidate candidateEnvironment)
          contract launch candidateRootRva invariant
          (candidateLaunchCalls candidateEnvironment)
          originalBefore candidateBefore beforeRelated
  semanticChunkFactory : forall originalEnvironment candidateEnvironment,
    MixedEnvironmentPairRefines original candidate contract externalFrames
        originalEnvironment candidateEnvironment ->
      forall originalBefore candidateBefore
        (source : ExactOriginalSemanticSource originalContext originalAuthority
          launch originalRoot reachability
          (CandidateProgramWithEnvironment candidate candidateEnvironment)
          (CandidateAuthorityWithEnvironment candidateAuthority
            candidateEnvironment))
        (operation : KernelOperation) (entryRva : Nat),
        originalExecutionAtTargetId source.targetId originalBefore ->
        nativeExecutionAtRva entryRva candidateBefore ->
        program.functionEntry? operation.role = some entryRva ->
        KernelOperationRefinesUsing program abi
          (combinedKernelDispatchRelation operations.dispatchFamily) operation ->
        MixedKernelOperationComponentCertificate
          (OriginalProgramWithEnvironment original originalEnvironment)
          (CandidateProgramWithEnvironment candidate candidateEnvironment)
          contract invariant program abi
          (combinedKernelDispatchRelation operations.dispatchFamily)
          (CandidateAuthorityWithEnvironment candidateAuthority
            candidateEnvironment)
          source.source.target.rva operation entryRva originalBefore candidateBefore
  externalOperationChunkFactory :
      forall originalEnvironment candidateEnvironment,
    MixedEnvironmentPairRefines original candidate contract externalFrames
        originalEnvironment candidateEnvironment ->
      forall originalBefore candidateBefore
        (source : ExactOriginalSemanticSource originalContext originalAuthority
          launch originalRoot reachability
          (CandidateProgramWithEnvironment candidate candidateEnvironment)
          (CandidateAuthorityWithEnvironment candidateAuthority
            candidateEnvironment))
        (operation : KernelOperation) (entryRva : Nat),
        originalExecutionAtBoundarySource source.targetId originalBefore ->
        nativeExecutionAtRva entryRva candidateBefore ->
        program.functionEntry? operation.role = some entryRva ->
        KernelOperationRefinesUsing program abi
          (combinedKernelDispatchRelation operations.dispatchFamily) operation ->
        MixedKernelOperationComponentCertificate
          (OriginalProgramWithEnvironment original originalEnvironment)
          (CandidateProgramWithEnvironment candidate candidateEnvironment)
          contract invariant program abi
          (combinedKernelDispatchRelation operations.dispatchFamily)
          (CandidateAuthorityWithEnvironment candidateAuthority
            candidateEnvironment)
          source.source.target.rva operation entryRva originalBefore candidateBefore
  externalBoundaryChunk : forall originalEnvironment candidateEnvironment,
    MixedEnvironmentPairRefines original candidate contract externalFrames
        originalEnvironment candidateEnvironment ->
      forall originalBefore candidateBefore
        (source : ExactOriginalSemanticSource originalContext originalAuthority
          launch originalRoot reachability
          (CandidateProgramWithEnvironment candidate candidateEnvironment)
          (CandidateAuthorityWithEnvironment candidateAuthority
            candidateEnvironment))
        (candidateRva : Nat),
        originalExecutionAtBoundarySource source.targetId originalBefore ->
        nativeExecutionAtRva candidateRva candidateBefore ->
        MixedKernelChunkPaths
          (OriginalProgramWithEnvironment original originalEnvironment)
          (CandidateProgramWithEnvironment candidate candidateEnvironment)
          contract invariant originalBefore candidateBefore
  rootsRelated : forall candidateEnvironment originalWorld candidateWorld
      originalState candidateState,
    MixedLaunchStatesRelated originalContext
        (CandidateProgramWithEnvironment candidate candidateEnvironment)
        contract originalWorld candidateWorld originalState candidateState ->
      invariant.holds
        (.running launch.rootTargetId originalState
          launch.continuationTargetIds 0 originalWorld)
        (.running candidateRootRva 0 candidateState
          (candidateLaunchCalls candidateEnvironment candidateState)
          0 [] candidateWorld)

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
    (beforeRelated : invariant.holds
      (.terminated originalWorld) (.terminated candidateEvents candidateWorld)) :
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

/-- Instantiate the closed source classifier for one environment pair and
select the corresponding component.  Launch is handled here, where the actual
`beforeRelated` proof is available; this avoids the old unindexed launch-path
factory. -/
noncomputable def EnvironmentParametricMixedComponentPremises.componentCases
    (premises : EnvironmentParametricMixedComponentPremises originalContext
      originalAuthority original candidate candidateAuthority contract externalFrames
      launch originalRoot reachability candidateRootRva program abi operations invariant)
    (candidateRoot : DirectExactCandidateNativeLaunchRoot candidate launch
      candidateRootRva)
    (originalEnvironment : WorldExternalProtocolEnvironment)
    (candidateEnvironment : NativeWorldEnvironment)
    (environmentsRefine : MixedEnvironmentPairRefines original candidate contract
      externalFrames originalEnvironment candidateEnvironment)
    (originalBefore : WorldExecution) (candidateBefore : NativeWorldExecution)
    (beforeRelated : invariant.holds originalBefore candidateBefore) :
    MixedWorldComponentChunkRefinement
      (OriginalProgramWithEnvironment original originalEnvironment)
      (CandidateProgramWithEnvironment candidate candidateEnvironment)
      contract invariant originalBefore candidateBefore := by
  cases (premises.classifier candidateEnvironment).classify originalBefore
      candidateBefore beforeRelated with
  | launchDispatch source sourceIsRoot originalAtSource candidateAtRoot =>
      let candidateRootWithEnvironment :=
        directExactCandidateNativeLaunchRootWithEnvironment candidateRoot
          candidateEnvironment
      let canonicalRoot := canonicalNativeInitialLaunchRoot
        (CandidateProgramWithEnvironment candidate candidateEnvironment)
      have canonicalRootExact :=
        directExactCandidateNativeLaunchRoot_canonicalRootExact
          candidateRootWithEnvironment
      let launchPremises :=
        premises.launchChunk originalEnvironment candidateEnvironment
          environmentsRefine originalBefore candidateBefore source beforeRelated
          sourceIsRoot originalAtSource candidateAtRoot
      exact (CanonicalMixedLaunchWrapperRefinement.launchChunk
        (premises.launchWrapperRefines originalEnvironment candidateEnvironment
          environmentsRefine) canonicalRoot canonicalRootExact
        (premises.candidateLaunchCalls candidateEnvironment)
        (premises.candidateLaunchCallsExact candidateEnvironment) beforeRelated
        launchPremises).toComponent beforeRelated
  | semanticTransfer source operation entryRva originalAtSource candidateAtEntry
      entryExact =>
      exact (premises.semanticChunkFactory originalEnvironment
        candidateEnvironment environmentsRefine originalBefore candidateBefore
        source operation entryRva originalAtSource candidateAtEntry entryExact
        (operations.combinedRefines operation)).toComponent beforeRelated
  | externalOperation source operation entryRva originalAtSource candidateAtEntry
      entryExact =>
      exact (premises.externalOperationChunkFactory originalEnvironment
        candidateEnvironment environmentsRefine originalBefore candidateBefore
        source operation entryRva originalAtSource candidateAtEntry entryExact
        (operations.combinedRefines operation)).toComponent beforeRelated
  | externalBoundary source candidateRva originalAtSource candidateAtSource =>
      exact (premises.externalBoundaryChunk originalEnvironment
        candidateEnvironment environmentsRefine originalBefore candidateBefore
        source candidateRva originalAtSource candidateAtSource).toComponent
        beforeRelated
  | returned originalState candidateState originalWorld candidateWorld
      candidateEvents =>
      exact terminalReturnedComponent beforeRelated
  | terminated originalWorld candidateWorld candidateEvents =>
      exact terminalTerminatedComponent beforeRelated
  | fault cause =>
      exact terminalFaultComponent beforeRelated

/-- The universal environment composition required by mixed whole-program
acceptance.  No base or favored environment is selected. -/
noncomputable def EnvironmentParametricMixedComponentPremises.environmentComposition
    (premises : EnvironmentParametricMixedComponentPremises originalContext
      originalAuthority original candidate candidateAuthority contract externalFrames
      launch originalRoot reachability candidateRootRva program abi operations invariant)
    (programBinding : ExactMixedProgramBinding originalContext original)
    (candidateRoot : DirectExactCandidateNativeLaunchRoot candidate launch
      candidateRootRva)
    (originalEnvironment : WorldExternalProtocolEnvironment)
    (candidateEnvironment : NativeWorldEnvironment)
    (environmentsRefine : MixedEnvironmentPairRefines original candidate contract
      externalFrames originalEnvironment candidateEnvironment) :
    MixedWorldChunkComposition originalContext originalAuthority
      (OriginalProgramWithEnvironment original originalEnvironment)
      (CandidateProgramWithEnvironment candidate candidateEnvironment)
      (CandidateAuthorityWithEnvironment candidateAuthority candidateEnvironment)
      (exactMixedProgramBindingWithProtocolEnvironment programBinding
        originalEnvironment)
      contract launch originalRoot reachability candidateRootRva
      (directExactCandidateNativeLaunchRootWithEnvironment candidateRoot
    candidateEnvironment) := {
  invariant
  candidateLaunchCalls := premises.candidateLaunchCalls candidateEnvironment
  candidateLaunchCallsExact :=
    premises.candidateLaunchCallsExact candidateEnvironment
  rootsRelated := premises.rootsRelated candidateEnvironment
  component := premises.componentCases candidateRoot originalEnvironment
    candidateEnvironment environmentsRefine
}

noncomputable def EnvironmentParametricMixedComponentPremises.environmentCompositions
    (premises : EnvironmentParametricMixedComponentPremises originalContext
      originalAuthority original candidate candidateAuthority contract externalFrames
      launch originalRoot reachability candidateRootRva program abi operations invariant)
    (programBinding : ExactMixedProgramBinding originalContext original)
    (candidateRoot : DirectExactCandidateNativeLaunchRoot candidate launch
      candidateRootRva) :
    forall originalEnvironment candidateEnvironment,
      MixedEnvironmentPairRefines original candidate contract externalFrames
          originalEnvironment candidateEnvironment ->
        MixedWorldChunkComposition originalContext originalAuthority
          (OriginalProgramWithEnvironment original originalEnvironment)
          (CandidateProgramWithEnvironment candidate candidateEnvironment)
          (CandidateAuthorityWithEnvironment candidateAuthority candidateEnvironment)
          (exactMixedProgramBindingWithProtocolEnvironment programBinding
            originalEnvironment)
          contract launch originalRoot reachability candidateRootRva
          (directExactCandidateNativeLaunchRootWithEnvironment candidateRoot
            candidateEnvironment) :=
  premises.environmentComposition programBinding candidateRoot

#print axioms CheckedKernelOperationRefinementFamily.refines
#print axioms CheckedKernelOperationRefinementFamily.combinedRefines
#print axioms CanonicalMixedLaunchWrapperRefinement.launchChunk_nonempty
#print axioms CanonicalMixedLaunchWrapperRefinement.launchChunk
#print axioms EnvironmentParametricMixedComponentPremises.componentCases
#print axioms EnvironmentParametricMixedComponentPremises.environmentComposition
#print axioms EnvironmentParametricMixedComponentPremises.environmentCompositions

end StageA.Relational.InterpreterMixedComponentComposition
