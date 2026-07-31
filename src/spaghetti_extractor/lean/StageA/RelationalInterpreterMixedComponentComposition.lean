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
single indexed family required by intermediate, single-world consumers.

This compatibility structure is not accepted by environment-parametric mixed
composition.  In particular, it cannot promote a dispatch relation closed over
one launch world into the world-indexed family used by recurring runtime
composition. -/
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

/-- Acceptance-facing operation authority.  Both dispatch and refinement are
indexed by the relational world extracted from the exact running
`candidateBefore`; no favored launch world is retained in this interface. -/
structure CheckedWorldKernelOperationRefinementFamily
    (program : CompiledKernelProgram) (abi : KernelABIRelation) where
  dispatchFamily : RelationalWorld -> KernelOperationDispatchFamily
  refines : forall world operation,
    KernelOperationRefinesUsing program abi
      (dispatchFamily world operation) operation

theorem CheckedWorldKernelOperationRefinementFamily.combinedRefines
    (checked : CheckedWorldKernelOperationRefinementFamily program abi)
    (world : RelationalWorld) (operation : KernelOperation) :
    KernelOperationRefinesUsing program abi
      (combinedKernelDispatchRelation (checked.dispatchFamily world)) operation :=
  kernelOperationRefinesUsing_combined (checked.dispatchFamily world)
    (checked.refines world operation)

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

/-- The sole semantic fact not supplied by exact wrapper replay: the checked
runtime invariant at the replay endpoint.  The original remains at its
canonical root, so this premise cannot hide an original execution path. -/
structure CanonicalMixedLaunchPrefixEndpoint
    (originalContext : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (launch : PE32ConsoleLaunchV2)
    (reflected : ExactNativeLaunchGraphCertificate)
    (root : CanonicalNativeLaunchRoot)
    (rootRva : Nat)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract) where
  afterRelated : forall originalWorld candidateWorld originalState
      candidateState calls route result candidateAfterState,
    root.rva? candidate.pe = some rootRva ->
    MixedLaunchStatesRelated originalContext candidate contract
        originalWorld candidateWorld originalState candidateState ->
    candidateNativeLaunchCallFrames? candidate launch candidateState = some calls ->
    route ∈ reflected.routes ->
    route.source = .canonicalRoot root ->
    route.replay? candidate reflected.cutpoints
        (CanonicalCandidateMixedLaunchExecution rootRva candidateState calls
          candidateWorld) = some result ->
    result.observations = [] ->
    result.after.machine? = some candidateAfterState ->
    contract.runtimeStatesRelated originalWorld candidateWorld originalState
        candidateAfterState ->
      invariant.holds
        (CanonicalOriginalMixedLaunchExecution launch originalState originalWorld)
        result.after

/-- Exact native replay inhabits the unique asymmetric launch path.  This
theorem stays in `Prop`, so it may eliminate the existential replay theorem
without enlarging Lean's trusted elimination rules. -/
theorem canonicalMixedLaunchPrefixPaths_nonempty
    (refinement : CanonicalMixedLaunchWrapperRefinement originalContext
      candidate contract launch)
    (root : CanonicalNativeLaunchRoot)
    (rootExact : root.rva? candidate.pe = some candidateRootRva)
    (candidateLaunchCalls : MachineState -> List NativeCallFrame)
    (candidateLaunchCallsExact : forall candidateState,
      candidateNativeLaunchCallFrames? candidate launch candidateState =
        some (candidateLaunchCalls candidateState))
    (endpoint : CanonicalMixedLaunchPrefixEndpoint originalContext candidate
      contract launch refinement.reflected root candidateRootRva invariant) :
    forall originalWorld candidateWorld originalState candidateState,
      MixedLaunchStatesRelated originalContext candidate contract
          originalWorld candidateWorld originalState candidateState ->
        Nonempty (MixedWorldLaunchPrefixPaths original candidate contract invariant
          (CanonicalOriginalMixedLaunchExecution launch originalState originalWorld)
          (CanonicalCandidateMixedLaunchExecution candidateRootRva candidateState
            (candidateLaunchCalls candidateState) candidateWorld)) := by
  intro originalWorld candidateWorld originalState candidateState launchRelated
  rcases refinement.rootsEstablishRuntime root candidateRootRva originalWorld
      candidateWorld originalState candidateState
      (candidateLaunchCalls candidateState) rootExact launchRelated
      (candidateLaunchCallsExact candidateState) with
    ⟨route, result, candidateAfterState, routeMember, routeSource, replayed,
      observationsExact,
      candidateAfterMachine, runtimeStatesRelated⟩
  have candidatePath :=
    (route.replay?_sound candidate refinement.reflected.cutpoints
      (CanonicalCandidateMixedLaunchExecution candidateRootRva candidateState
        (candidateLaunchCalls candidateState) candidateWorld)
      result replayed).2.2
  refine ⟨{
    candidateAfter := result.after
    originalIdentity := rfl
    candidatePath := ?_
    afterRelated := endpoint.afterRelated originalWorld candidateWorld
      originalState candidateState
      (candidateLaunchCalls candidateState) route result candidateAfterState
      rootExact launchRelated
      (candidateLaunchCallsExact candidateState) routeMember routeSource replayed
      observationsExact candidateAfterMachine runtimeStatesRelated
  }⟩
  simpa [observationsExact] using candidatePath

/-- Build the unique asymmetric launch prefix from exact native wrapper replay.
The decoded original is definitionally unchanged for zero steps; the candidate
path is nonempty and silent; the endpoint is admitted only through the runtime
invariant. -/
noncomputable def canonicalMixedLaunchPrefixCertificate
    (refinement : CanonicalMixedLaunchWrapperRefinement originalContext
      candidate contract launch)
    (root : CanonicalNativeLaunchRoot)
    (rootExact : root.rva? candidate.pe = some candidateRootRva)
    (candidateLaunchCalls : MachineState -> List NativeCallFrame)
    (candidateLaunchCallsExact : forall candidateState,
      candidateNativeLaunchCallFrames? candidate launch candidateState =
        some (candidateLaunchCalls candidateState))
    (endpoint : CanonicalMixedLaunchPrefixEndpoint originalContext candidate
      contract launch refinement.reflected root candidateRootRva invariant) :
    MixedWorldLaunchPrefixCertificate originalContext original candidate contract
      launch candidateRootRva invariant where
  candidateLaunchCalls := candidateLaunchCalls
  candidateLaunchCallsExact := candidateLaunchCallsExact
  launchPaths := by
    intro originalWorld candidateWorld originalState candidateState launchRelated
    exact Classical.choice
      (canonicalMixedLaunchPrefixPaths_nonempty refinement root rootExact
        candidateLaunchCalls
        candidateLaunchCallsExact endpoint originalWorld candidateWorld
        originalState candidateState launchRelated)

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
    (operations : CheckedWorldKernelOperationRefinementFamily program abi)
    (invariant : MixedExecutionInvariant reachability.targetIds contract) where
  classifier : forall candidateEnvironment,
    MixedKernelRuntimeSourceClassifier originalContext originalAuthority launch
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
  launchPrefixEndpoint : forall originalEnvironment candidateEnvironment,
    (environmentRefines :
      MixedEnvironmentPairRefines original candidate contract externalFrames
        originalEnvironment candidateEnvironment) ->
      CanonicalMixedLaunchPrefixEndpoint originalContext
        (CandidateProgramWithEnvironment candidate candidateEnvironment)
        contract launch
        (launchWrapperRefines originalEnvironment candidateEnvironment
          environmentRefines).reflected
        (canonicalNativeInitialLaunchRoot
          (CandidateProgramWithEnvironment candidate candidateEnvironment))
        candidateRootRva invariant
  semanticChunkFactory : forall originalEnvironment candidateEnvironment,
    MixedEnvironmentPairRefines original candidate contract externalFrames
        originalEnvironment candidateEnvironment ->
      forall originalBefore candidateBefore
        (source : ExactOriginalSemanticSource originalContext originalAuthority
          launch originalRoot reachability
          (CandidateProgramWithEnvironment candidate candidateEnvironment)
          (CandidateAuthorityWithEnvironment candidateAuthority
            candidateEnvironment))
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
          (classifier candidateEnvironment).classifier.classify
              originalBefore candidateBefore beforeRelated =
            .semanticTransfer source operation entryRva originalAtSource
              candidateAtEntry entryExact),
        KernelOperationRefinesUsing program abi
          (combinedKernelDispatchRelation
            (operations.dispatchFamily candidateWorld)) operation ->
        MixedKernelOperationComponentCertificate
          (OriginalProgramWithEnvironment original originalEnvironment)
          (CandidateProgramWithEnvironment candidate candidateEnvironment)
          contract invariant program abi
          (combinedKernelDispatchRelation
            (operations.dispatchFamily candidateWorld))
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
          (classifier candidateEnvironment).classifier.classify
              originalBefore candidateBefore beforeRelated =
            .externalOperation source operation entryRva originalAtSource
              candidateAtEntry entryExact),
        KernelOperationRefinesUsing program abi
          (combinedKernelDispatchRelation
            (operations.dispatchFamily candidateWorld)) operation ->
        MixedKernelOperationComponentCertificate
          (OriginalProgramWithEnvironment original originalEnvironment)
          (CandidateProgramWithEnvironment candidate candidateEnvironment)
          contract invariant program abi
          (combinedKernelDispatchRelation
            (operations.dispatchFamily candidateWorld))
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
        (candidateRva : Nat)
        (beforeRelated : invariant.holds originalBefore candidateBefore)
        (originalAtSource :
          originalExecutionAtBoundarySource source.targetId originalBefore)
        (candidateAtSource :
          nativeExecutionAtRva candidateRva candidateBefore)
        (classified :
          (classifier candidateEnvironment).classifier.classify
              originalBefore candidateBefore beforeRelated =
            .externalBoundary source candidateRva originalAtSource
              candidateAtSource),
        MixedKernelChunkPaths
          (OriginalProgramWithEnvironment original originalEnvironment)
          (CandidateProgramWithEnvironment candidate candidateEnvironment)
          contract invariant originalBefore candidateBefore

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
  have runtimeOnly :=
    (premises.classifier candidateEnvironment).runtimeOnly originalBefore
      candidateBefore beforeRelated
  cases classified :
      (premises.classifier candidateEnvironment).classifier.classify
        originalBefore candidateBefore beforeRelated with
  | launchDispatch source sourceIsRoot originalAtSource candidateAtRoot =>
      rw [classified] at runtimeOnly
      exact False.elim runtimeOnly
  | semanticTransfer source operation entryRva originalAtSource candidateAtEntry
      entryExact =>
      let candidateRunning := exactNativeRunningWorldAtRva candidateAtEntry
      exact (premises.semanticChunkFactory originalEnvironment
        candidateEnvironment environmentsRefine originalBefore candidateBefore
        source operation entryRva beforeRelated originalAtSource
        candidateAtEntry candidateRunning.world candidateRunning.worldExact
        entryExact classified
        (operations.combinedRefines candidateRunning.world operation)).toComponent
          beforeRelated
  | externalOperation source operation entryRva originalAtSource candidateAtEntry
      entryExact =>
      let candidateRunning := exactNativeRunningWorldAtRva candidateAtEntry
      exact (premises.externalOperationChunkFactory originalEnvironment
        candidateEnvironment environmentsRefine originalBefore candidateBefore
        source operation entryRva beforeRelated originalAtSource
        candidateAtEntry candidateRunning.world candidateRunning.worldExact
        entryExact classified
        (operations.combinedRefines candidateRunning.world operation)).toComponent
          beforeRelated
  | externalBoundary source candidateRva originalAtSource candidateAtSource =>
      exact (premises.externalBoundaryChunk originalEnvironment
        candidateEnvironment environmentsRefine originalBefore candidateBefore
        source candidateRva beforeRelated originalAtSource candidateAtSource
        classified).toComponent beforeRelated
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
  component := premises.componentCases candidateRoot originalEnvironment
    candidateEnvironment environmentsRefine
}

noncomputable def EnvironmentParametricMixedComponentPremises.environmentLaunchPrefix
    (premises : EnvironmentParametricMixedComponentPremises originalContext
      originalAuthority original candidate candidateAuthority contract externalFrames
      launch originalRoot reachability candidateRootRva program abi operations invariant)
    (candidateRoot : DirectExactCandidateNativeLaunchRoot candidate launch
      candidateRootRva)
    (originalEnvironment : WorldExternalProtocolEnvironment)
    (candidateEnvironment : NativeWorldEnvironment)
    (environmentsRefine : MixedEnvironmentPairRefines original candidate contract
      externalFrames originalEnvironment candidateEnvironment) :
    MixedWorldLaunchPrefixCertificate originalContext
      (OriginalProgramWithEnvironment original originalEnvironment)
      (CandidateProgramWithEnvironment candidate candidateEnvironment)
      contract launch candidateRootRva invariant := by
  let candidateRootWithEnvironment :=
    directExactCandidateNativeLaunchRootWithEnvironment candidateRoot
      candidateEnvironment
  let root := canonicalNativeInitialLaunchRoot
    (CandidateProgramWithEnvironment candidate candidateEnvironment)
  have rootExact :=
    directExactCandidateNativeLaunchRoot_canonicalRootExact
      candidateRootWithEnvironment
  exact
    canonicalMixedLaunchPrefixCertificate
      (premises.launchWrapperRefines originalEnvironment candidateEnvironment
        environmentsRefine) root rootExact
        (premises.candidateLaunchCalls candidateEnvironment)
        (premises.candidateLaunchCallsExact candidateEnvironment)
        (premises.launchPrefixEndpoint originalEnvironment candidateEnvironment
          environmentsRefine)

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
#print axioms CheckedWorldKernelOperationRefinementFamily.combinedRefines
#print axioms canonicalMixedLaunchPrefixPaths_nonempty
#print axioms canonicalMixedLaunchPrefixCertificate
#print axioms EnvironmentParametricMixedComponentPremises.componentCases
#print axioms EnvironmentParametricMixedComponentPremises.environmentComposition
#print axioms EnvironmentParametricMixedComponentPremises.environmentLaunchPrefix
#print axioms EnvironmentParametricMixedComponentPremises.environmentCompositions

end StageA.Relational.InterpreterMixedComponentComposition
