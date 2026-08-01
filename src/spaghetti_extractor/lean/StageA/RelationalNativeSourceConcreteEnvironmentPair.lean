import StageA.RelationalNativeSourceEnvironmentFamilyEvidence

namespace StageA.Relational.NativeSource

open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWorldBridge

/-! # Concrete checked source/native environment pairs

An external environment is intentionally abstract, but it is not unconstrained.
This module packages one concrete pair only after Lean has checked every
lockstep call site, the returned machine-level ABI effects, source execution,
and native launch realizability.  The resulting singleton relation is useful
for establishing non-vacuity without claiming anything about unrelated
environment schedules.
-/

/-- The full result relation for a returning source/native call.  The opaque
lockstep relation supplies continuation `StateRel` and runtime-frame
preservation.  The remaining clauses reconnect the site to the source
machine-call contract and check both sides' ABI effects explicitly. -/
def OpaqueWorldNativeABIResultRelated
    (context : StaticProofContext) (program : DecodedWorldProgram)
    (site : OpaqueLockstepCallSite)
    (originalEvent : WorldExternalEvent)
    (candidateEvent : StageA.Relational.InterpreterKernel.NativeExternalEvent)
    (originalResult candidateResult : WorldExternalResult) : Prop :=
  exists callSite contract,
    callSite ∈ program.externalCallSites /\
      site.matchesExternalCallSite context callSite = true /\
      machineImportCallContractById? context callSite.machineContractId =
        some contract /\
      machineCallResultConforms false context contract originalEvent
        originalResult /\
      machineCallResultConforms true context contract
        (nativeExternalEventToWorldExternalEvent candidateEvent site.id
          originalEvent.world)
        candidateResult /\
      machineCallResultRegistersRelated context originalResult.world contract
        originalEvent.arguments originalResult.state candidateResult.state = true /\
      OpaqueLockstepResultRelated context site originalEvent
        (nativeExternalEventToWorldExternalEvent candidateEvent site.id
          originalEvent.world)
        originalResult candidateResult

/-- One closed, non-vacuous environment pair.  `externalEvidence` proves exact
1:1 coverage of the complete source external-site inventory.  `returningABI`
strengthens each returning result with the resolved machine-call contract;
matching imports alone can never inhabit this structure. -/
structure CheckedConcreteWorldNativeEnvironmentPair
    (context : StaticProofContext) (sites : List OpaqueLockstepCallSite)
    (compilation : ExactNativeCompilation) where
  sourceEnvironment : WorldExternalEnvironment
  nativeEnvironment : NativeWorldEnvironment
  externalEvidence : ExactWorldNativeExternalEvidence context
    (exactNativeCompilationAtEnvironments compilation sourceEnvironment
      nativeEnvironment).project.worldProgram
    (exactNativeCompilationAtEnvironments compilation sourceEnvironment
      nativeEnvironment).machineAuthority.program sites sourceEnvironment
  returningABI : forall site, site ∈ sites -> site.disposition = .returns ->
    forall eventIndex originalEvent candidateEvent,
      OpaqueLockstepBoundaryRelated context site originalEvent
        (nativeExternalEventToWorldExternalEvent candidateEvent site.id
          originalEvent.world) ->
      exists candidateResult,
        nativeEnvironment.action eventIndex candidateEvent originalEvent.world =
          .returned candidateResult /\
        OpaqueWorldNativeABIResultRelated context
          (exactNativeCompilationAtEnvironments compilation sourceEnvironment
            nativeEnvironment).project.worldProgram
          site originalEvent candidateEvent
          (sourceEnvironment.result eventIndex originalEvent) candidateResult
  sourceFamily : CheckedNativeSourceLaunchFamily
    (exactNativeCompilationAtEnvironments compilation sourceEnvironment
      nativeEnvironment).project
  launchRealizable : NativeCompilationLaunchRealizable
    (exactNativeCompilationAtEnvironments compilation sourceEnvironment
      nativeEnvironment).machineAuthority

/-- Admit exactly the checked pair.  This is deliberately not widened to every
pair that happens to share import names. -/
def CheckedConcreteWorldNativeEnvironmentPair.Related
    {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    (pair : CheckedConcreteWorldNativeEnvironmentPair context sites compilation)
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment) : Prop :=
  sourceEnvironment = pair.sourceEnvironment /\
    nativeEnvironment = pair.nativeEnvironment

theorem CheckedConcreteWorldNativeEnvironmentPair.realizable
    {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    (pair : CheckedConcreteWorldNativeEnvironmentPair context sites compilation) :
    exists sourceEnvironment nativeEnvironment,
      pair.Related sourceEnvironment nativeEnvironment := by
  exact ⟨pair.sourceEnvironment, pair.nativeEnvironment, rfl, rfl⟩

theorem CheckedConcreteWorldNativeEnvironmentPair.externalEvidenceAt
    {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    (pair : CheckedConcreteWorldNativeEnvironmentPair context sites compilation)
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment)
    (related : pair.Related sourceEnvironment nativeEnvironment) :
    ExactWorldNativeExternalEvidence context
      (exactNativeCompilationAtEnvironments compilation sourceEnvironment
        nativeEnvironment).project.worldProgram
      (exactNativeCompilationAtEnvironments compilation sourceEnvironment
        nativeEnvironment).machineAuthority.program sites sourceEnvironment := by
  rcases related with ⟨rfl, rfl⟩
  exact pair.externalEvidence

theorem CheckedConcreteWorldNativeEnvironmentPair.sourceFamilyAt
    {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    (pair : CheckedConcreteWorldNativeEnvironmentPair context sites compilation)
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment)
    (related : pair.Related sourceEnvironment nativeEnvironment) :
    CheckedNativeSourceLaunchFamily
      (exactNativeCompilationAtEnvironments compilation sourceEnvironment
        nativeEnvironment).project := by
  rcases related with ⟨rfl, rfl⟩
  exact pair.sourceFamily

theorem CheckedConcreteWorldNativeEnvironmentPair.launchRealizableAt
    {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    (pair : CheckedConcreteWorldNativeEnvironmentPair context sites compilation)
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment)
    (related : pair.Related sourceEnvironment nativeEnvironment) :
    NativeCompilationLaunchRealizable
      (exactNativeCompilationAtEnvironments compilation sourceEnvironment
        nativeEnvironment).machineAuthority := by
  rcases related with ⟨rfl, rfl⟩
  exact pair.launchRealizable

def CheckedConcreteWorldNativeEnvironmentPair.admittedEvidence
    {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    (pair : CheckedConcreteWorldNativeEnvironmentPair context sites compilation) :
    CheckedNativeSourceAdmittedPairEvidence context sites compilation
      pair.Related := {
  pairRealizable := pair.realizable
  externalEvidenceAt := pair.externalEvidenceAt
  sourceFamilyAt := pair.sourceFamilyAt
  launchRealizableAt := pair.launchRealizableAt
}

end StageA.Relational.NativeSource
