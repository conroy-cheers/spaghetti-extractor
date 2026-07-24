import StageA.RelationalInterpreterExactDecodedNativeComponents

namespace StageA.Relational.InterpreterExactDecodedNativeExternalComponent

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterExactDecodedNativeComponents
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact decoded/native external-component bridge

The exact one-to-one environment theorem already derives both nonempty paths,
the related external observations, rejection of callback/blocked native
actions, and the exact related successor shapes.  This layer retains only the
typed boundary facts needed to invoke that theorem and the endpoint invariant
needed by whole-program composition.

The base native carrier has no nested callback stack at a running source, so
the decoded callback list is fixed to `[]`.  API behavior remains abstract in
the universally quantified environment-refinement premise.
-/

/-- Exact boundary and invariant evidence not derived by one-to-one environment
refinement.

The suspension and dispatch are dependent witnesses.  The five proposition
fields are the exact decoded transition, native source identity, boundary and
frame relations, and the invariant at the exact successor pair.
-/
structure ExactDecodedNativeExternalComponentRemainingPremises
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram)
    (invariant : MixedExecutionInvariant reachabilityTargetIds
      exactDecodedNativeIdentityContract)
    (frames : MixedExternalFrameContract)
    (decodedBefore : WorldExecution)
    (nativeBefore : NativeWorldExecution) where
  suspension : WorldExternalSuspension
  dispatch : ExactNativeExternalDispatch native
  originalDispatch : ExactOriginalExternalDispatch decoded decodedBefore
    suspension []
  nativeBeforeExact : dispatch.before = nativeBefore
  boundaryRelated :
    exactDecodedNativeIdentityContract.externalBoundariesRelated suspension
      dispatch.boundary
  frameBoundary : MixedExternalFrameBoundaryRelated frames suspension []
    dispatch.continuationRva dispatch.calls
  afterRelated : invariant.holds
    (originalExternalAfter decoded suspension []) dispatch.after

/-- Assemble the existing exact external-component certificate.

No path, observation, action, successor, `ExactMixedExternalInteractionChunk`,
or callback-stack premise is accepted here.  Those facts are fixed or derived
by `exactMixedExternalInteractionChunk`.
-/
def exactDecodedNativeExternalComponentCertificateOfRefinement
    (environmentsRefine : ExactOneToOneMixedExternalEnvironmentsRefine decoded
      native exactDecodedNativeIdentityContract frames)
    (remaining : ExactDecodedNativeExternalComponentRemainingPremises decoded
      native invariant frames decodedBefore nativeBefore) :
    ExactDecodedNativeExternalComponentCertificate decoded native invariant
      decodedBefore nativeBefore := {
  frames
  suspension := remaining.suspension
  callbacks := []
  dispatch := remaining.dispatch
  nativeBeforeExact := remaining.nativeBeforeExact
  interaction := exactMixedExternalInteractionChunk decoded native
    exactDecodedNativeIdentityContract frames decodedBefore remaining.suspension
    [] remaining.dispatch remaining.originalDispatch remaining.boundaryRelated
    remaining.frameBoundary environmentsRefine
  afterRelated := remaining.afterRelated
}

/-- The smallest classified-boundary input expected by the whole-program
component assembly.  The existing carrier fact and classifier equation are
arguments, not duplicated fields in each boundary witness. -/
def ExactDecodedNativeClassifiedExternalBoundaryPremises
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram)
    (invariant : MixedExecutionInvariant reachabilityTargetIds
      exactDecodedNativeIdentityContract)
    (program : CompiledKernelProgram)
    (launch : PE32ConsoleLaunchV2)
    (frames : MixedExternalFrameContract) : Type :=
  forall targetId state calls eventIndex world nativeBefore,
    invariant.holds
        (.running targetId state calls eventIndex world) nativeBefore ->
      exactDecodedNativeExecutableFamily? decoded program launch targetId state
          calls = some .externalBoundary ->
      ExactDecodedNativeExternalComponentRemainingPremises decoded native
        invariant frames (.running targetId state calls eventIndex world)
        nativeBefore

/-- Acceptance-facing external-component factory with exactly the signature of
`ExactDecodedNativeComponentAssembly.externalComponent`. -/
def ExactDecodedNativeExternalComponentFactory
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram)
    (invariant : MixedExecutionInvariant reachabilityTargetIds
      exactDecodedNativeIdentityContract)
    (program : CompiledKernelProgram)
    (launch : PE32ConsoleLaunchV2) : Type :=
  forall targetId state calls eventIndex world nativeBefore,
    invariant.holds
        (.running targetId state calls eventIndex world) nativeBefore ->
      exactDecodedNativeExecutableFamily? decoded program launch targetId state
          calls = some .externalBoundary ->
      ExactDecodedNativeExternalComponentCertificate decoded native invariant
        (.running targetId state calls eventIndex world) nativeBefore

def exactDecodedNativeExternalComponentFactoryOfRefinement
    (remaining : ExactDecodedNativeClassifiedExternalBoundaryPremises decoded
      native invariant program launch frames)
    (environmentsRefine : ExactOneToOneMixedExternalEnvironmentsRefine decoded
      native exactDecodedNativeIdentityContract frames) :
    ExactDecodedNativeExternalComponentFactory decoded native invariant program
      launch := by
  intro targetId state calls eventIndex world nativeBefore beforeRelated classified
  exact exactDecodedNativeExternalComponentCertificateOfRefinement
    environmentsRefine
    (remaining targetId state calls eventIndex world nativeBefore beforeRelated
      classified)

/-- Remaining classified-boundary facts for every environment pair that meets
the exact one-to-one premise.  No concrete pair is selected by this type. -/
def ExactDecodedNativeExternalBoundaryPremisesForRefiningEnvironments
    (decodedTemplate : DecodedWorldProgram)
    (nativeTemplate : ExactNativeWorldProgram)
    (invariant : MixedExecutionInvariant reachabilityTargetIds
      exactDecodedNativeIdentityContract)
    (program : CompiledKernelProgram)
    (launch : PE32ConsoleLaunchV2)
    (frames : MixedExternalFrameContract) : Type :=
  forall originalEnvironment candidateEnvironment,
    ExactOneToOneMixedExternalEnvironmentsRefine
        (decodedWorldProgramWithProtocolEnvironment decodedTemplate
          originalEnvironment)
        (exactNativeWorldProgramWithEnvironment nativeTemplate
          candidateEnvironment)
        exactDecodedNativeIdentityContract frames ->
      ExactDecodedNativeClassifiedExternalBoundaryPremises
        (decodedWorldProgramWithProtocolEnvironment decodedTemplate
          originalEnvironment)
        (exactNativeWorldProgramWithEnvironment nativeTemplate
          candidateEnvironment)
        invariant program launch frames

/-- Constructive acceptance-facing factories for every refining environment
pair.  This is a `Type` because each factory returns dependent certificates. -/
def ExactDecodedNativeExternalComponentFactoriesForRefiningEnvironments
    (decodedTemplate : DecodedWorldProgram)
    (nativeTemplate : ExactNativeWorldProgram)
    (invariant : MixedExecutionInvariant reachabilityTargetIds
      exactDecodedNativeIdentityContract)
    (program : CompiledKernelProgram)
    (launch : PE32ConsoleLaunchV2)
    (frames : MixedExternalFrameContract) : Type :=
  forall originalEnvironment candidateEnvironment,
    ExactOneToOneMixedExternalEnvironmentsRefine
        (decodedWorldProgramWithProtocolEnvironment decodedTemplate
          originalEnvironment)
        (exactNativeWorldProgramWithEnvironment nativeTemplate
          candidateEnvironment)
        exactDecodedNativeIdentityContract frames ->
      ExactDecodedNativeExternalComponentFactory
        (decodedWorldProgramWithProtocolEnvironment decodedTemplate
          originalEnvironment)
        (exactNativeWorldProgramWithEnvironment nativeTemplate
          candidateEnvironment)
        invariant program launch

/-- Build the constructive universally parameterized factory without choosing
an environment pair. -/
def exactDecodedNativeExternalComponentFactoriesForRefiningEnvironments
    (remaining :
      ExactDecodedNativeExternalBoundaryPremisesForRefiningEnvironments
        decodedTemplate nativeTemplate invariant program launch frames) :
    ExactDecodedNativeExternalComponentFactoriesForRefiningEnvironments
      decodedTemplate nativeTemplate invariant program launch frames := by
  intro originalEnvironment candidateEnvironment environmentsRefine
  exact exactDecodedNativeExternalComponentFactoryOfRefinement
    (remaining originalEnvironment candidateEnvironment environmentsRefine)
    environmentsRefine

/-- Universal theorem form used by whole-program acceptance statements.  It
does not select or construct a favorable environment pair. -/
def ExactDecodedNativeExternalComponentsForRefiningEnvironments
    (decodedTemplate : DecodedWorldProgram)
    (nativeTemplate : ExactNativeWorldProgram)
    (invariant : MixedExecutionInvariant reachabilityTargetIds
      exactDecodedNativeIdentityContract)
    (program : CompiledKernelProgram)
    (launch : PE32ConsoleLaunchV2)
    (frames : MixedExternalFrameContract) : Prop :=
  forall originalEnvironment candidateEnvironment,
    (environmentsRefine : ExactOneToOneMixedExternalEnvironmentsRefine
      (decodedWorldProgramWithProtocolEnvironment decodedTemplate
        originalEnvironment)
      (exactNativeWorldProgramWithEnvironment nativeTemplate
        candidateEnvironment)
      exactDecodedNativeIdentityContract frames) ->
    Nonempty (ExactDecodedNativeExternalComponentFactory
      (decodedWorldProgramWithProtocolEnvironment decodedTemplate
        originalEnvironment)
      (exactNativeWorldProgramWithEnvironment nativeTemplate
        candidateEnvironment)
      invariant program launch)

theorem exactDecodedNativeExternalComponentForRefiningEnvironments
    (remaining :
      ExactDecodedNativeExternalBoundaryPremisesForRefiningEnvironments
        decodedTemplate nativeTemplate invariant program launch frames) :
    ExactDecodedNativeExternalComponentsForRefiningEnvironments decodedTemplate
      nativeTemplate invariant program launch frames := by
  intro originalEnvironment candidateEnvironment environmentsRefine
  exact ⟨exactDecodedNativeExternalComponentFactoryOfRefinement
    (remaining originalEnvironment candidateEnvironment environmentsRefine)
    environmentsRefine⟩

#print axioms exactDecodedNativeExternalComponentCertificateOfRefinement
#print axioms exactDecodedNativeExternalComponentFactoryOfRefinement
#print axioms exactDecodedNativeExternalComponentFactoriesForRefiningEnvironments
#print axioms exactDecodedNativeExternalComponentForRefiningEnvironments

end StageA.Relational.InterpreterExactDecodedNativeExternalComponent
