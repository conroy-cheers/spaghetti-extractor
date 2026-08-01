import StageA.RelationalNativeSourceAdmittedProtocolResponseFamily
import StageA.RelationalNativeSourceNestedCompilation

namespace StageA.Relational.NativeSource

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment

/-! # Final admitted nested environment-family acceptance

This is the acceptance adapter for callback/protocol response families.  Unlike
the synchronous adapter, its compiled execution theorem is stated over
`ExactNestedNativeWorldProgram` and `NestedNativeWorldExecution`; callback
frames cannot be projected away before final observational equivalence.
-/

def exactNestedNativeCompilationAtResponseEnvironments
    (compilation : ExactNativeCompilation)
    (sourceEnvironment : SourceWorldResponseEnvironment)
    (nativeEnvironment : NativeWorldResponseEnvironment) :
    ExactNestedNativeCompilation
      (exactNativeCompilationAtResponseEnvironments compilation sourceEnvironment
        nativeEnvironment.ordinary) := {
  program := nativeEnvironment.nestedProgram
    (exactNativeCompilationAtResponseEnvironments compilation sourceEnvironment
      nativeEnvironment.ordinary).machineAuthority.program
  baseExact := rfl
}

/-- Broad final statement.  Every admitted response family member retains its
complete 1:1 ordinary/protocol evidence and obtains a launch-universal theorem
over the callback-capable compiled carrier. -/
def ExactRawOriginalPENestedCompiledArtifactAdmittedEnvironmentFamilyEquivalence
    (context : StaticProofContext)
    (classified : List CheckedMachineExternalSite)
    (ordinarySites : List OpaqueLockstepCallSite)
    (compilation : ExactNativeCompilation)
    (mixed : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (pairRelated : SourceWorldResponseEnvironment ->
      NativeWorldResponseEnvironment -> Prop) : Prop :=
  (exists sourceEnvironment nativeEnvironment,
      pairRelated sourceEnvironment nativeEnvironment) /\
    forall sourceEnvironment nativeEnvironment,
      pairRelated sourceEnvironment nativeEnvironment ->
        exists admitted : AdmittedWorldNativeProtocolResponsePair context
            classified ordinarySites compilation mixed frames sourceEnvironment
            nativeEnvironment,
          ExactRawOriginalPENestedCompiledArtifactLaunchFamilyEquivalence
            (exactNativeCompilationAtResponseEnvironments compilation
              sourceEnvironment
              nativeEnvironment.ordinary)
            (exactNestedNativeCompilationAtResponseEnvironments compilation
              sourceEnvironment nativeEnvironment)

/-- Checked pair-indexed inputs for the final nested theorem.  The response
schedule, source launch family, and launch inhabitance come from the admitted
pair itself; only compiler correctness remains a separate conditional premise. -/
structure CheckedNestedNativeSourceAdmittedEnvironmentFamily
    (context : StaticProofContext)
    (classified : List CheckedMachineExternalSite)
    (ordinarySites : List OpaqueLockstepCallSite)
    (compilation : ExactNativeCompilation)
    (mixed : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (pairRelated : SourceWorldResponseEnvironment ->
      NativeWorldResponseEnvironment -> Prop) : Prop where
  pairRealizable : exists sourceEnvironment nativeEnvironment,
    pairRelated sourceEnvironment nativeEnvironment
  admittedAt : forall sourceEnvironment nativeEnvironment,
    pairRelated sourceEnvironment nativeEnvironment ->
      Nonempty (AdmittedWorldNativeProtocolResponsePair context classified
        ordinarySites compilation mixed frames sourceEnvironment
        nativeEnvironment)
  toolchainCorrectAt : forall sourceEnvironment nativeEnvironment,
      pairRelated sourceEnvironment nativeEnvironment ->
      CorrectPinnedNestedNativeSourceStackHypothesis
        (exactNativeCompilationAtResponseEnvironments compilation
          sourceEnvironment
          nativeEnvironment.ordinary)
        (exactNestedNativeCompilationAtResponseEnvironments compilation
          sourceEnvironment nativeEnvironment)

theorem compiledNestedArtifactAdmittedEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    {context : StaticProofContext}
    {classified : List CheckedMachineExternalSite}
    {ordinarySites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {mixed : MixedRelationContract}
    {frames : MixedNestedExternalFrameContract}
    {pairRelated : SourceWorldResponseEnvironment ->
      NativeWorldResponseEnvironment -> Prop}
    (family : CheckedNestedNativeSourceAdmittedEnvironmentFamily context
      classified ordinarySites compilation mixed frames pairRelated) :
    ExactRawOriginalPENestedCompiledArtifactAdmittedEnvironmentFamilyEquivalence
      context classified ordinarySites compilation mixed frames pairRelated := by
  refine ⟨family.pairRealizable, ?_⟩
  intro sourceEnvironment nativeEnvironment related
  rcases family.admittedAt sourceEnvironment nativeEnvironment related with
    ⟨admitted⟩
  let nested := exactNestedNativeCompilationAtResponseEnvironments compilation
    sourceEnvironment nativeEnvironment
  have nestedLaunch : NestedNativeCompilationLaunchRealizable nested :=
    nestedNativeCompilationLaunchRealizable_of_base nested
      admitted.launchRealizable
  refine ⟨admitted, ?_⟩
  exact compiledNestedArtifactLaunchFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    (exactNativeCompilationAtResponseEnvironments compilation sourceEnvironment
      nativeEnvironment.ordinary)
    nested admitted.sourceFamily nestedLaunch
    (family.toolchainCorrectAt sourceEnvironment nativeEnvironment related)

/-- Assemble the final adapter directly from the broad checked response
family.  `Related` remains the full admitted predicate; the canonical member
is used only by `pairRealizable`. -/
def CheckedWorldNativeAdmittedProtocolResponseFamily.toNestedAcceptance
    {context : StaticProofContext}
    {classified : List CheckedMachineExternalSite}
    {ordinarySites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {mixed : MixedRelationContract}
    {frames : MixedNestedExternalFrameContract}
    (responseFamily : CheckedWorldNativeAdmittedProtocolResponseFamily context
      classified ordinarySites compilation mixed frames)
    (completion : responseFamily.Completion)
    (toolchainCorrectAt : forall sourceEnvironment nativeEnvironment,
      responseFamily.Related sourceEnvironment nativeEnvironment ->
        CorrectPinnedNestedNativeSourceStackHypothesis
          (exactNativeCompilationAtResponseEnvironments compilation
            sourceEnvironment
            nativeEnvironment.ordinary)
          (exactNestedNativeCompilationAtResponseEnvironments compilation
            sourceEnvironment nativeEnvironment)) :
    CheckedNestedNativeSourceAdmittedEnvironmentFamily context classified
      ordinarySites compilation mixed frames responseFamily.Related := {
  pairRealizable := completion.realizable
  admittedAt := fun _ _ related => related
  toolchainCorrectAt := toolchainCorrectAt
}

end StageA.Relational.NativeSource
