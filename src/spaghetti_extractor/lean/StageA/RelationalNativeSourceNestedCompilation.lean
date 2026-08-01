import StageA.RelationalInterpreterMixedEnvironment
import StageA.RelationalInterpreterNativeWorldProjection
import StageA.RelationalNativeSource

namespace StageA.Relational.NativeSource

open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterNativeWorldProjection
open StageA.Relational.SourceWorld

/-! # Callback-capable native-source compilation

The original native-source theorem targets the synchronous native carrier.
This module retains that theorem unchanged and adds the corresponding authority
for `ExactNestedNativeWorldProgram`.  Callback suspensions and external-frame
stacks are therefore part of the compiled execution state quantified by the
final theorem rather than evidence discarded below acceptance.
-/

/-- One static compiled artifact equipped with its callback-capable operational
environment.  `baseExact` prevents replacing any byte-derived authority while
adding the nested carrier. -/
structure ExactNestedNativeCompilation
    (compilation : ExactNativeCompilation) where
  program : ExactNestedNativeWorldProgram
  baseExact : program.base = compilation.machineAuthority.program

/-- Phase relation retained by the nested compiler hypothesis.  The compiler's
own simulation relation remains stronger; this fixed projection prevents it
from relating incompatible callback depth, protocol phase, event position, or
terminal outcome. -/
def NestedExecutionPhaseMatches :
    SourceExecution -> NestedNativeWorldExecution -> Prop
  | .running _ _ _ sourceEventIndex sourceWorld,
      .running _ _ _ _ compiledEventIndex _ compiledWorld externalFrames =>
      sourceEventIndex = compiledEventIndex /\ sourceWorld = compiledWorld /\
        externalFrames = []
  | .callbackRunning _ _ _ sourceEventIndex sourceWorld sourceFrames,
      .running _ _ _ _ compiledEventIndex _ compiledWorld compiledFrames =>
      sourceEventIndex = compiledEventIndex /\ sourceWorld = compiledWorld /\
        sourceFrames.length = compiledFrames.length /\ 0 < sourceFrames.length
  | .awaitingExternal sourceSuspension sourceFrames,
      .awaitingExternal compiledSuspension compiledFrames =>
      sourceSuspension.eventIndex = compiledSuspension.eventIndex /\
        sourceSuspension.phaseIndex = compiledSuspension.phaseIndex /\
        sourceSuspension.world = compiledSuspension.world /\
        sourceFrames.length = compiledFrames.length
  | .returned _ sourceWorld, .returned _ _ compiledWorld =>
      sourceWorld = compiledWorld
  | .terminated sourceWorld, .terminated _ compiledWorld =>
      sourceWorld = compiledWorld
  | .fault sourceCause, .fault compiledCause => sourceCause = compiledCause
  | _, _ => False

/-- Exact compiled launch with no pre-existing external callback frames. -/
structure CheckedNestedCompiledPE32ConsoleLaunch
    {compilation : ExactNativeCompilation}
    (nested : ExactNestedNativeCompilation compilation)
    (compiledRoot : NestedNativeWorldExecution) : Prop where
  launch : exists compiledState compiledWorld,
    compiledRoot = .running compilation.artifact.pe.entrypointRva 0
      compiledState [] 0 [] compiledWorld [] /\
    PreferredBaseImageMemory compilation.artifact.pe
      compilation.machineAuthority.importCertificate.imports compiledState.memory /\
    NativeImportAddressesMemoryHold compilation.artifact.pe
      compilation.machineAuthority.importCertificate.imports compiledWorld
      compiledState.memory

/-- Source and nested compiled launches selected by the pinned lowering
hypothesis. -/
structure CheckedNestedNativeCompilationLaunch
    {compilation : ExactNativeCompilation}
    (nested : ExactNestedNativeCompilation compilation)
    (sourceRoot : SourceExecution)
    (compiledRoot : NestedNativeWorldExecution) : Prop where
  sourceLaunch : CheckedNativeSourcePE32ConsoleLaunch compilation.project
    sourceRoot
  compiledLaunch : CheckedNestedCompiledPE32ConsoleLaunch nested compiledRoot
  phaseMatches : NestedExecutionPhaseMatches sourceRoot compiledRoot

def NestedNativeCompilationLaunchRealizable
    {compilation : ExactNativeCompilation}
    (nested : ExactNestedNativeCompilation compilation) : Prop :=
  exists compiledRoot, CheckedNestedCompiledPE32ConsoleLaunch nested compiledRoot

/-- Every ordinary exact launch embeds into the nested carrier with an empty
external-frame stack. -/
def CheckedCompiledPE32ConsoleLaunch.toNested
    {compilation : ExactNativeCompilation}
    (nested : ExactNestedNativeCompilation compilation)
    {compiledRoot : NativeWorldExecution}
    (launch : CheckedCompiledPE32ConsoleLaunch compilation.machineAuthority
      compiledRoot) :
    CheckedNestedCompiledPE32ConsoleLaunch nested
      (liftNativeWorldExecution compiledRoot) := by
  rcases launch.launch with ⟨state, world, rootExact, image, imports⟩
  refine { launch := ⟨state, world, ?_, image, imports⟩ }
  rw [rootExact]
  rfl

theorem nestedNativeCompilationLaunchRealizable_of_base
    {compilation : ExactNativeCompilation}
    (nested : ExactNestedNativeCompilation compilation)
    (base : NativeCompilationLaunchRealizable compilation.machineAuthority) :
    NestedNativeCompilationLaunchRealizable nested := by
  rcases base with ⟨root, launch⟩
  exact ⟨liftNativeWorldExecution root, launch.toNested nested⟩

/-- Semantic consequence required from a correct callback-capable pinned
lowering stack.  Every source macro-path, including callback entry, callback
return, protocol continuation, and termination, is reproduced with the exact
same observation list by the nested PE carrier. -/
structure NestedNativeCompilationSimulation
    (kernel : Kernel) (compiledProgram : ExactNestedNativeWorldProgram)
    (sourceRoot : SourceExecution)
    (compiledRoot : NestedNativeWorldExecution) where
  relation : SourceExecution -> NestedNativeWorldExecution -> Prop
  rootRelated : relation sourceRoot compiledRoot
  phaseMatches : forall source compiled,
    relation source compiled -> NestedExecutionPhaseMatches source compiled
  compilePath : forall sourceBefore compiledBefore observations sourceAfter,
    relation sourceBefore compiledBefore ->
      NonemptyRelatedPath kernel.transitionSystem sourceBefore observations
        sourceAfter ->
      exists compiledAfter,
        NonemptyRelatedPath compiledProgram.transitionSystem compiledBefore
          observations compiledAfter /\
        relation sourceAfter compiledAfter

/-- Callback-capable counterpart of the sole compiler correctness premise.
It remains bidirectional over checked launches and does not assert any
original-binary fact. -/
structure CorrectPinnedNestedNativeSourceStackHypothesis
    (compilation : ExactNativeCompilation)
    (nested : ExactNestedNativeCompilation compilation) : Prop where
  compiledLaunch : forall compiledRoot,
    CheckedNestedCompiledPE32ConsoleLaunch nested compiledRoot ->
      exists sourceRoot,
        CheckedNestedNativeCompilationLaunch nested sourceRoot compiledRoot /\
          Nonempty (NestedNativeCompilationSimulation compilation.project.kernel
            nested.program sourceRoot compiledRoot)
  sourceLaunch : forall sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch compilation.project sourceRoot ->
      exists compiledRoot,
        CheckedNestedNativeCompilationLaunch nested sourceRoot compiledRoot /\
          Nonempty (NestedNativeCompilationSimulation compilation.project.kernel
            nested.program sourceRoot compiledRoot)

def OriginalNestedCompiledExecutionsMatch
    (original : DecodedWorldProgram) (root : WorldExecution)
    (domain : CheckedExecutionDomain original root)
    (compiledRelation : SourceExecution -> NestedNativeWorldExecution -> Prop) :
    RawEipWorldExecution -> NestedNativeWorldExecution -> Prop :=
  fun originalExecution compiledExecution =>
    exists sourceExecution,
      RawEipSourceExecutionsMatch original root domain originalExecution
          sourceExecution /\
        compiledRelation sourceExecution compiledExecution

/-- Final exact-original to nested-compiled observational equivalence. -/
def ExactRawOriginalPENestedCompiledArtifactObservationalEquivalence
    (original : DecodedWorldProgram) (root : WorldExecution)
    (domain : CheckedExecutionDomain original root)
    (profile : PinnedNativeSourceToolchainProfile)
    (project : NativeSourceProject) (artifact : CompiledArtifact)
    (machineAuthority : ExactCompiledPE32Authority artifact)
    (nestedProgram : ExactNestedNativeWorldProgram)
    (compiledRoot : NestedNativeWorldExecution) : Prop :=
  project.Valid /\ profile.FullStackPinned /\
    project.profile = profile.sourceProfile /\
    artifact.BuiltFrom profile project /\
    nestedProgram.base = machineAuthority.program /\
    exists executionRelation :
        RawEipWorldExecution -> NestedNativeWorldExecution -> Prop,
      (forall originalRaw,
        root.ConcretizesToRawEip original originalRaw ->
          executionRelation originalRaw compiledRoot) /\
      (forall originalRaw compiledRaw,
        executionRelation originalRaw compiledRaw ->
          exists sourceExecution,
            RawEipSourceExecutionsMatch original root domain originalRaw
                sourceExecution /\
              NestedExecutionPhaseMatches sourceExecution compiledRaw) /\
      ChunkedRelationalBisimulation original.pe32RawEipTransitionSystem
        nestedProgram.transitionSystem executionRelation
        sourceObservationsRelated

theorem compiledNestedArtifactEquivalentUnderPinnedNativeSourceStackHypothesis
    (compilation : ExactNativeCompilation)
    (nested : ExactNestedNativeCompilation compilation)
    (sourceRoot : SourceExecution)
    (compiledRoot : NestedNativeWorldExecution)
    (launchChecked : CheckedNestedNativeCompilationLaunch nested sourceRoot
      compiledRoot)
    {domain : CheckedExecutionDomain compilation.project.program.worldProgram
      sourceRoot.toWorldExecution}
    (checkedProject : CheckedNativeSourceProject compilation.project
      sourceRoot.toWorldExecution domain)
    (simulation : NestedNativeCompilationSimulation compilation.project.kernel
      nested.program sourceRoot compiledRoot) :
    ExactRawOriginalPENestedCompiledArtifactObservationalEquivalence
      compilation.project.program.worldProgram sourceRoot.toWorldExecution
      domain compilation.profile compilation.project compilation.artifact
      compilation.machineAuthority nested.program compiledRoot := by
  let sourceEquivalent := checkedProject.sourceEquivalent
  let relation := OriginalNestedCompiledExecutionsMatch
    compilation.project.program.worldProgram sourceRoot.toWorldExecution domain
    simulation.relation
  refine ⟨compilation.projectValid, compilation.profilePinned,
    compilation.profileMatches, compilation.builtFrom, nested.baseExact,
    relation, ?_, ?_, ?_⟩
  · intro originalRaw originalConcrete
    refine ⟨sourceRoot, ?_, simulation.rootRelated⟩
    exact ⟨sourceRoot.toWorldExecution, originalConcrete,
      by simpa using ExecutionsMatch.root domain⟩
  · intro originalRaw compiledRaw related
    rcases related with ⟨sourceExecution, originalSource, sourceCompiled⟩
    exact ⟨sourceExecution, originalSource,
      simulation.phaseMatches sourceExecution compiledRaw sourceCompiled⟩
  · intro originalBefore compiledBefore beforeRelated
    rcases beforeRelated with
      ⟨sourceBefore, originalSourceBefore, sourceCompiledBefore⟩
    rcases sourceEquivalent originalBefore sourceBefore originalSourceBefore with
      ⟨originalObservations, sourceObservations, originalAfter, sourceAfter,
        originalPath, sourcePath, observationsRelated, originalSourceAfter⟩
    rcases simulation.compilePath sourceBefore compiledBefore
        sourceObservations sourceAfter sourceCompiledBefore sourcePath with
      ⟨compiledAfter, compiledPath, sourceCompiledAfter⟩
    exact ⟨originalObservations, sourceObservations, originalAfter,
      compiledAfter, originalPath, compiledPath, observationsRelated,
      ⟨sourceAfter, originalSourceAfter, sourceCompiledAfter⟩⟩

def ExactRawOriginalPENestedCompiledArtifactLaunchFamilyEquivalence
    (compilation : ExactNativeCompilation)
    (nested : ExactNestedNativeCompilation compilation) : Prop :=
  NestedNativeCompilationLaunchRealizable nested /\
    forall compiledRoot,
      CheckedNestedCompiledPE32ConsoleLaunch nested compiledRoot ->
        exists sourceRoot,
          exists sourceLaunch : CheckedNativeSourceLaunch compilation.project
              sourceRoot,
            ExactRawOriginalPENestedCompiledArtifactObservationalEquivalence
              compilation.project.program.worldProgram
              sourceRoot.toWorldExecution sourceLaunch.domain
              compilation.profile compilation.project compilation.artifact
              compilation.machineAuthority nested.program compiledRoot

theorem compiledNestedArtifactLaunchFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    (compilation : ExactNativeCompilation)
    (nested : ExactNestedNativeCompilation compilation)
    (sourceFamily : CheckedNativeSourceLaunchFamily compilation.project)
    (launchRealizable : NestedNativeCompilationLaunchRealizable nested)
    (toolchainCorrect : CorrectPinnedNestedNativeSourceStackHypothesis compilation
      nested) :
    ExactRawOriginalPENestedCompiledArtifactLaunchFamilyEquivalence compilation
      nested := by
  refine ⟨launchRealizable, ?_⟩
  intro compiledRoot compiledLaunch
  rcases toolchainCorrect.compiledLaunch compiledRoot compiledLaunch with
    ⟨sourceRoot, launchChecked, ⟨simulation⟩⟩
  rcases sourceFamily.source sourceRoot launchChecked.sourceLaunch with
    ⟨sourceLaunch⟩
  refine ⟨sourceRoot, sourceLaunch, ?_⟩
  exact compiledNestedArtifactEquivalentUnderPinnedNativeSourceStackHypothesis
    compilation nested sourceRoot compiledRoot launchChecked
      sourceLaunch.checkedProject simulation

/-! The original synchronous declarations remain the callback-free
specialization.  No consumer is forced through the nested carrier when the
checked machine inventory contains no protocol sites. -/
abbrev CallbackFreeNativeCompilationSimulation := NativeCompilationSimulation
abbrev CallbackFreeCorrectPinnedNativeSourceStackHypothesis :=
  CorrectPinnedNativeSourceStackHypothesis
abbrev CallbackFreeCompiledArtifactLaunchFamilyEquivalence :=
  ExactRawOriginalPECompiledArtifactLaunchFamilyEquivalence

end StageA.Relational.NativeSource
