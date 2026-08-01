import StageA.RelationalNativeSourceEnvironmentFamily

namespace StageA.Relational.NativeSource

open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWorldBridge

/-! # Static construction of native-source environment families

The native-source acceptance theorem quantifies over source and native external
environments.  This module separates the environment-independent compilation
artifacts from those environment parameters.  Re-targeting changes only the
operational environment fields; exact source identities, compiled PE bytes,
imports, relocations, and Nix provenance remain those of the checked static
compilation.

External correspondence is not inferred from equal names or made universal.
Every admitted pair still carries `ExactWorldNativeExternalEvidence`, including
the machine-level boundary and result relation for every lockstep site.
-/

/-- Replace only the external environment of a decoded original program. -/
def decodedWorldProgramWithExternalEnvironment
    (program : DecodedWorldProgram) (environment : WorldExternalEnvironment) :
    DecodedWorldProgram :=
  { program with environment := environment }

/-- Re-index checked source input by an environment-retargeted world program.
The context, original PE, records, and exact x87 witnesses are unchanged. -/
def checkedNativeProgramInputWithExternalEnvironment
    {worldProgram : DecodedWorldProgram}
    (input : CheckedNativeProgramInput worldProgram)
    (environment : WorldExternalEnvironment) :
    CheckedNativeProgramInput
      (decodedWorldProgramWithExternalEnvironment worldProgram environment) := {
  ir := {
    records := input.ir.records
    x87Witnesses := input.ir.x87Witnesses
  }
  recordsUnique := input.recordsUnique
  x87SourcesUnique := input.x87SourcesUnique
}

/-- Retarget a checked source project without changing any static artifact or
Nix identity. -/
def nativeSourceProjectWithExternalEnvironment
    (project : NativeSourceProject) (environment : WorldExternalEnvironment) :
    NativeSourceProject := {
  profile := project.profile
  worldProgram :=
    decodedWorldProgramWithExternalEnvironment project.worldProgram environment
  checkedInput :=
    checkedNativeProgramInputWithExternalEnvironment project.checkedInput environment
  bundleManifest := project.bundleManifest
  rendererInputArtifact := project.rendererInputArtifact
  sourceArtifacts := project.sourceArtifacts
  nixIdentity := project.nixIdentity
}

@[simp]
theorem nativeSourceProjectWithExternalEnvironment_worldEnvironment
    (project : NativeSourceProject) (environment : WorldExternalEnvironment) :
    (nativeSourceProjectWithExternalEnvironment project environment).worldProgram.environment =
      environment :=
  rfl

theorem nativeSourceProjectValidWithExternalEnvironment
    {project : NativeSourceProject} (environment : WorldExternalEnvironment)
    (valid : project.Valid) :
    (nativeSourceProjectWithExternalEnvironment project environment).Valid := by
  simpa [NativeSourceProject.Valid, nativeSourceProjectWithExternalEnvironment,
    checkedNativeProgramInputWithExternalEnvironment,
    decodedWorldProgramWithExternalEnvironment,
    CanonicalNativeProgramIR.x87SourceRvas] using valid

/-- Replace only the operational native environment.  All byte-derived
authority fields and their proofs are reused unchanged. -/
def exactCompiledPE32AuthorityWithEnvironment
    {artifact : CompiledArtifact}
    (authority : ExactCompiledPE32Authority artifact)
    (environment : NativeWorldEnvironment) :
    ExactCompiledPE32Authority artifact := {
  importCertificate := authority.importCertificate
  relocations := authority.relocations
  environment := environment
  callableExternal := authority.callableExternal
  indirectTargets := authority.indirectTargets
  importsParsed := authority.importsParsed
  relocationsParsed := authority.relocationsParsed
  loaderImageValid := authority.loaderImageValid
  callableBound := authority.callableBound
  indirectTargetsValid := authority.indirectTargetsValid
}

@[simp]
theorem exactCompiledPE32AuthorityWithEnvironment_programEnvironment
    {artifact : CompiledArtifact}
    (authority : ExactCompiledPE32Authority artifact)
    (environment : NativeWorldEnvironment) :
    (exactCompiledPE32AuthorityWithEnvironment authority environment).program.environment =
      environment :=
  rfl

/-- Build the exact environment-indexed compilation from one checked static
compilation. -/
def exactNativeCompilationAtEnvironments
    (compilation : ExactNativeCompilation)
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment) : ExactNativeCompilation := {
  profile := compilation.profile
  project := nativeSourceProjectWithExternalEnvironment compilation.project
    sourceEnvironment
  artifact := compilation.artifact
  machineAuthority :=
    exactCompiledPE32AuthorityWithEnvironment compilation.machineAuthority
      nativeEnvironment
  projectValid := nativeSourceProjectValidWithExternalEnvironment sourceEnvironment
    compilation.projectValid
  profilePinned := compilation.profilePinned
  profileMatches := compilation.profileMatches
  builtFrom := {
    buildIdentityValid := compilation.builtFrom.buildIdentityValid
    sourceProjectExact := compilation.builtFrom.sourceProjectExact
    toolchainExact := compilation.builtFrom.toolchainExact
  }
}

@[simp]
theorem exactNativeCompilationAtEnvironments_sourceEnvironment
    (compilation : ExactNativeCompilation)
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment) :
    (exactNativeCompilationAtEnvironments compilation sourceEnvironment
      nativeEnvironment).project.worldProgram.environment = sourceEnvironment :=
  rfl

@[simp]
theorem exactNativeCompilationAtEnvironments_nativeEnvironment
    (compilation : ExactNativeCompilation)
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment) :
    (exactNativeCompilationAtEnvironments compilation sourceEnvironment
      nativeEnvironment).machineAuthority.program.environment =
        nativeEnvironment :=
  rfl

/-- Environment-independent facts tying the checked source project and exact
compiled artifact to the common static proof context. -/
structure StaticNativeSourceEnvironmentFamilyAuthority
    (context : StaticProofContext) (compilation : ExactNativeCompilation) :
    Prop where
  sourceContext : compilation.project.worldProgram.context = context
  sourceRole : compilation.project.worldProgram.candidate = false
  compiledPe : compilation.artifact.pe = context.candidatePe
  compiledImports :
    compilation.machineAuthority.importCertificate.imports =
      context.candidateImports

/-- Checked evidence attached to the explicit relation that admits external
environment pairs.  Launch evidence is deliberately available only after a
proof that the pair is admitted.  The separate `pairRealizable` field prevents
an empty relation from satisfying the interface vacuously, while
`externalEvidenceAt` retains exact one-to-one machine-call evidence at every
admitted pair. -/
structure CheckedNativeSourceAdmittedPairEvidence
    (context : StaticProofContext) (sites : List OpaqueLockstepCallSite)
    (compilation : ExactNativeCompilation)
    (pairRelated : WorldExternalEnvironment -> NativeWorldEnvironment -> Prop) :
    Prop where
  pairRealizable : exists sourceEnvironment nativeEnvironment,
    pairRelated sourceEnvironment nativeEnvironment
  externalEvidenceAt : forall sourceEnvironment nativeEnvironment,
    pairRelated sourceEnvironment nativeEnvironment ->
    ExactWorldNativeExternalEvidence context
      (exactNativeCompilationAtEnvironments compilation sourceEnvironment
        nativeEnvironment).project.worldProgram
      (exactNativeCompilationAtEnvironments compilation sourceEnvironment
        nativeEnvironment).machineAuthority.program sites sourceEnvironment
  sourceFamilyAt : forall sourceEnvironment nativeEnvironment,
    pairRelated sourceEnvironment nativeEnvironment ->
    CheckedNativeSourceLaunchFamily
      (nativeSourceProjectWithExternalEnvironment compilation.project
        sourceEnvironment)
  launchRealizableAt : forall sourceEnvironment nativeEnvironment,
    pairRelated sourceEnvironment nativeEnvironment ->
    NativeCompilationLaunchRealizable
      (exactCompiledPE32AuthorityWithEnvironment compilation.machineAuthority
        nativeEnvironment)

/-- The final environment family is scoped by the checked admission relation.
This avoids silently strengthening relation-indexed launch evidence into a
claim about every conceivable external-evidence witness.  Each admitted pair
still exports its exact machine-level correspondence alongside the behavioral
equivalence theorem. -/
def ExactRawOriginalPECompiledArtifactAdmittedEnvironmentFamilyEquivalence
    (context : StaticProofContext) (sites : List OpaqueLockstepCallSite)
    (compilation : ExactNativeCompilation)
    (pairRelated : WorldExternalEnvironment -> NativeWorldEnvironment -> Prop) :
    Prop :=
  (exists sourceEnvironment nativeEnvironment,
      pairRelated sourceEnvironment nativeEnvironment) /\
    forall sourceEnvironment nativeEnvironment,
      pairRelated sourceEnvironment nativeEnvironment ->
      NativeSourceExternalEnvironmentCorrespondence context sites
          (exactNativeCompilationAtEnvironments compilation sourceEnvironment
            nativeEnvironment) sourceEnvironment nativeEnvironment /\
        ExactRawOriginalPECompiledArtifactLaunchFamilyEquivalence
          (exactNativeCompilationAtEnvironments compilation sourceEnvironment
            nativeEnvironment)

/-- All checked evidence needed to lift one static compilation over exactly the
external-environment pairs admitted by `pairRelated`. -/
structure CheckedNativeSourceAdmittedEnvironmentFamily
    (context : StaticProofContext) (sites : List OpaqueLockstepCallSite)
    (compilation : ExactNativeCompilation)
    (pairRelated : WorldExternalEnvironment -> NativeWorldEnvironment -> Prop) :
    Prop where
  staticAuthority :
    StaticNativeSourceEnvironmentFamilyAuthority context compilation
  admittedPairs :
    CheckedNativeSourceAdmittedPairEvidence context sites compilation pairRelated
  toolchainCorrectAt : forall sourceEnvironment nativeEnvironment,
    pairRelated sourceEnvironment nativeEnvironment ->
    CorrectPinnedNativeSourceStackHypothesis
      (exactNativeCompilationAtEnvironments compilation sourceEnvironment
        nativeEnvironment)

/-- Static authority constructs the program-binding part of correspondence;
the machine-level external evidence remains a separate mandatory input. -/
theorem StaticNativeSourceEnvironmentFamilyAuthority.programBindingAt
    {context : StaticProofContext} {compilation : ExactNativeCompilation}
    (authority : StaticNativeSourceEnvironmentFamilyAuthority context compilation)
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment) :
    ExactWorldNativeProgramBinding context
      (exactNativeCompilationAtEnvironments compilation sourceEnvironment
        nativeEnvironment).project.worldProgram
      (exactNativeCompilationAtEnvironments compilation sourceEnvironment
        nativeEnvironment).machineAuthority.program
      sourceEnvironment := by
  refine {
    originalContext := ?_
    originalRole := ?_
    originalEnvironment := rfl
    candidatePe := ?_
    candidateImports := ?_
  }
  · exact authority.sourceContext
  · exact authority.sourceRole
  · exact authority.compiledPe
  · exact authority.compiledImports

/-- Construct one non-vacuous correspondence witness.  Exact external
evidence is retained verbatim rather than reduced to environment equality. -/
def NativeSourceExternalEnvironmentCorrespondence.ofStaticEvidence
    {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    (authority : StaticNativeSourceEnvironmentFamilyAuthority context compilation)
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment)
    (externalEvidence : ExactWorldNativeExternalEvidence context
      (exactNativeCompilationAtEnvironments compilation sourceEnvironment
        nativeEnvironment).project.worldProgram
      (exactNativeCompilationAtEnvironments compilation sourceEnvironment
        nativeEnvironment).machineAuthority.program sites sourceEnvironment) :
    NativeSourceExternalEnvironmentCorrespondence context sites
      (exactNativeCompilationAtEnvironments compilation sourceEnvironment
        nativeEnvironment)
      sourceEnvironment nativeEnvironment := {
  sourceEnvironmentExact := rfl
  nativeEnvironmentExact := rfl
  programBinding := authority.programBindingAt sourceEnvironment nativeEnvironment
  externalEvidence := externalEvidence
}

/-- Lift the fixed-environment theorem over the checked admission relation.
The admission witness is threaded unchanged through external evidence, source
launch coverage, compiled launch realizability, and the pinned-stack
hypothesis. -/
theorem compiledArtifactAdmittedEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {pairRelated : WorldExternalEnvironment -> NativeWorldEnvironment -> Prop}
    (family : CheckedNativeSourceAdmittedEnvironmentFamily context sites
      compilation pairRelated) :
    ExactRawOriginalPECompiledArtifactAdmittedEnvironmentFamilyEquivalence
      context sites compilation pairRelated := by
  refine ⟨family.admittedPairs.pairRealizable, ?_⟩
  intro sourceEnvironment nativeEnvironment related
  let correspondence :=
    NativeSourceExternalEnvironmentCorrespondence.ofStaticEvidence
      family.staticAuthority sourceEnvironment nativeEnvironment
      (family.admittedPairs.externalEvidenceAt sourceEnvironment
        nativeEnvironment related)
  refine ⟨correspondence, ?_⟩
  exact compiledArtifactLaunchFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    (exactNativeCompilationAtEnvironments compilation sourceEnvironment
      nativeEnvironment)
    (family.admittedPairs.sourceFamilyAt sourceEnvironment nativeEnvironment
      related)
    (family.admittedPairs.launchRealizableAt sourceEnvironment nativeEnvironment
      related)
    (family.toolchainCorrectAt sourceEnvironment nativeEnvironment related)

end StageA.Relational.NativeSource
