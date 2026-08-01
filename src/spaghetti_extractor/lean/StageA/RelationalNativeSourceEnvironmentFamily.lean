import StageA.RelationalNativeSource
import StageA.RelationalInterpreterWorldBridge

namespace StageA.Relational.NativeSource

open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWorldBridge

/-! # Environment-parametric native-source acceptance

`RelationalNativeSource` proves the launch-family theorem for one exact source
environment and one exact compiled-machine environment.  This module retains
that theorem as the per-environment lemma and adds the outer quantifier needed
for an open family of corresponding external response schedules.

The correspondence object is intentionally stronger than equality of event
names.  It binds both environments to the programs that execute them and
carries the existing machine-level external-call evidence for every declared
lockstep site.
-/

/-- Checked correspondence for one source/native external-environment pair.

The equality fields prevent an environment proof from being reused with a
project or compiled authority that executes a different environment.  Static
PE/import binding and machine-level API refinement are retained explicitly in
the same witness. -/
structure NativeSourceExternalEnvironmentCorrespondence
    (context : StaticProofContext) (sites : List OpaqueLockstepCallSite)
    (compilation : ExactNativeCompilation)
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment) : Prop where
  sourceEnvironmentExact :
    compilation.project.worldProgram.environment = sourceEnvironment
  nativeEnvironmentExact :
    compilation.machineAuthority.environment = nativeEnvironment
  programBinding : ExactWorldNativeProgramBinding context
    compilation.project.worldProgram compilation.machineAuthority.program
    sourceEnvironment
  externalEvidence : ExactWorldNativeExternalEvidence context
    compilation.project.worldProgram compilation.machineAuthority.program sites
    sourceEnvironment

@[simp]
theorem NativeSourceExternalEnvironmentCorrespondence.sourceProgramEnvironment
    {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {sourceEnvironment : WorldExternalEnvironment}
    {nativeEnvironment : NativeWorldEnvironment}
    (correspondence : NativeSourceExternalEnvironmentCorrespondence context sites
      compilation sourceEnvironment nativeEnvironment) :
    compilation.project.worldProgram.environment = sourceEnvironment :=
  correspondence.sourceEnvironmentExact

@[simp]
theorem NativeSourceExternalEnvironmentCorrespondence.compiledProgramEnvironment
    {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {sourceEnvironment : WorldExternalEnvironment}
    {nativeEnvironment : NativeWorldEnvironment}
    (correspondence : NativeSourceExternalEnvironmentCorrespondence context sites
      compilation sourceEnvironment nativeEnvironment) :
    compilation.machineAuthority.program.environment = nativeEnvironment := by
  exact correspondence.nativeEnvironmentExact

/-- Environment-family acceptance target.  Besides quantifying over every
corresponding pair, it requires at least one checked pair so an empty relation
cannot authorize a vacuous family theorem. -/
def ExactRawOriginalPECompiledArtifactEnvironmentFamilyEquivalence
    (context : StaticProofContext) (sites : List OpaqueLockstepCallSite)
    (compilationAt : WorldExternalEnvironment -> NativeWorldEnvironment ->
      ExactNativeCompilation) : Prop :=
  (exists sourceEnvironment nativeEnvironment,
      NativeSourceExternalEnvironmentCorrespondence context sites
        (compilationAt sourceEnvironment nativeEnvironment)
        sourceEnvironment nativeEnvironment) /\
    forall sourceEnvironment nativeEnvironment,
      NativeSourceExternalEnvironmentCorrespondence context sites
        (compilationAt sourceEnvironment nativeEnvironment)
        sourceEnvironment nativeEnvironment ->
      ExactRawOriginalPECompiledArtifactLaunchFamilyEquivalence
        (compilationAt sourceEnvironment nativeEnvironment)

/-- Pair-indexed inputs to environment-family acceptance.  In particular, the
compiler-stack hypothesis is supplied after the correspondence witness, so it
cannot be a theorem about one hidden fixed response schedule. -/
structure CheckedNativeSourceEnvironmentFamily
    (context : StaticProofContext) (sites : List OpaqueLockstepCallSite)
    (compilationAt : WorldExternalEnvironment -> NativeWorldEnvironment ->
      ExactNativeCompilation) : Prop where
  pairRealizable : exists sourceEnvironment nativeEnvironment,
    NativeSourceExternalEnvironmentCorrespondence context sites
      (compilationAt sourceEnvironment nativeEnvironment)
      sourceEnvironment nativeEnvironment
  sourceFamily : forall sourceEnvironment nativeEnvironment,
    NativeSourceExternalEnvironmentCorrespondence context sites
      (compilationAt sourceEnvironment nativeEnvironment)
      sourceEnvironment nativeEnvironment ->
    CheckedNativeSourceLaunchFamily
      (compilationAt sourceEnvironment nativeEnvironment).project
  launchRealizable : forall sourceEnvironment nativeEnvironment,
    NativeSourceExternalEnvironmentCorrespondence context sites
      (compilationAt sourceEnvironment nativeEnvironment)
      sourceEnvironment nativeEnvironment ->
    NativeCompilationLaunchRealizable
      (compilationAt sourceEnvironment nativeEnvironment).machineAuthority
  toolchainCorrect : forall sourceEnvironment nativeEnvironment,
    NativeSourceExternalEnvironmentCorrespondence context sites
      (compilationAt sourceEnvironment nativeEnvironment)
      sourceEnvironment nativeEnvironment ->
    CorrectPinnedNativeSourceStackHypothesis
      (compilationAt sourceEnvironment nativeEnvironment)

/-- Lift the fixed-environment launch-family theorem pointwise over every
checked source/native environment pair. -/
theorem compiledArtifactEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilationAt : WorldExternalEnvironment -> NativeWorldEnvironment ->
      ExactNativeCompilation}
    (family : CheckedNativeSourceEnvironmentFamily context sites compilationAt) :
    ExactRawOriginalPECompiledArtifactEnvironmentFamilyEquivalence context sites
      compilationAt := by
  refine ⟨family.pairRealizable, ?_⟩
  intro sourceEnvironment nativeEnvironment correspondence
  exact compiledArtifactLaunchFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    (compilationAt sourceEnvironment nativeEnvironment)
    (family.sourceFamily sourceEnvironment nativeEnvironment correspondence)
    (family.launchRealizable sourceEnvironment nativeEnvironment correspondence)
    (family.toolchainCorrect sourceEnvironment nativeEnvironment correspondence)

end StageA.Relational.NativeSource
