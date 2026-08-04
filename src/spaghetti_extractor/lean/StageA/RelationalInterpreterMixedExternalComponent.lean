import StageA.RelationalInterpreterMixedEnvironment
import StageA.RelationalInterpreterMixedConstructiveSourceClassifier
import StageA.RelationalInterpreterMixedKernelComposition

namespace StageA.Relational.InterpreterMixedExternalComponent

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedConstructiveSourceClassifier
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact mixed external-boundary components

This module turns checked machine-boundary evidence into the external component
used by environment-parametric mixed composition.  The evidence does not carry
paths, observation lists, successor endpoints, or an endpoint invariant proof.
Those are derived from the exact transition equations and the one-to-one
environment premise.

Invariant preservation is stated over the exact successor relation.  This
keeps the remaining semantic obligation independent of a selected environment
response while still requiring every returned, terminated, or fault successor
admitted by the checked boundary to re-establish the invariant.
-/

def mixedExternalOriginalProgramWithEnvironment
    (program : DecodedWorldProgram)
    (environment : WorldExternalProtocolEnvironment) : DecodedWorldProgram :=
  { program with protocolEnvironment := environment }

def mixedExternalCandidateProgramWithEnvironment
    (program : ExactNativeWorldProgram)
    (environment : NativeWorldEnvironment) : ExactNativeWorldProgram :=
  { program with environment := environment }

def mixedExternalCandidateAuthorityWithEnvironment
    (authority : ExactNativeCandidateAuthority candidate)
    (environment : NativeWorldEnvironment) :
    ExactNativeCandidateAuthority
      (mixedExternalCandidateProgramWithEnvironment candidate environment) := {
  importCertificate := authority.importCertificate
  relocations := authority.relocations
  tableRva := authority.tableRva
  countRva := authority.countRva
  semanticRecords := authority.semanticRecords
  peParsed := authority.peParsed
  importsBound := authority.importsBound
  importsParsed := authority.importsParsed
  relocationsParsed := authority.relocationsParsed
  loaderImageValid := authority.loaderImageValid
  table := authority.table
}

/-- Runtime-specific machine relation at an external successor.

The ambient invariant admits either the launch relation or the runtime
relation.  External actions occur after launch, so their successor evidence
must select the runtime branch before it may be projected back into the
phase-aware invariant. -/
def MixedExternalSuccessorRuntimeStatesRelated
    (contract : MixedRelationContract)
    (originalAfter : WorldExecution)
    (candidateAfter : NativeWorldExecution) : Prop :=
  forall originalWorld candidateWorld originalState candidateState,
    originalExecutionWorld? originalAfter = some originalWorld ->
    nativeExecutionWorld? candidateAfter = some candidateWorld ->
    originalExecutionMachine? originalAfter = some originalState ->
    candidateAfter.machine? = some candidateState ->
    contract.runtimeStatesRelated originalWorld candidateWorld originalState
      candidateState

/-- Exact one-to-one external successor evidence carries the runtime relation
for every successor with machine state.  Termination and modeled faults have
no machine-state projection, so the property is vacuous there. -/
theorem mixedExternalSuccessors_runtimeStatesRelated
    (related : MixedExternalSuccessorsRelated contract frames suspension
      callbacks dispatch originalAfter candidateAfter) :
    MixedExternalSuccessorRuntimeStatesRelated contract originalAfter
      candidateAfter := by
  intro originalWorld candidateWorld originalState candidateState
    originalWorldExact candidateWorldExact originalStateExact
    candidateStateExact
  cases related with
  | returned originalResult candidateResult worldsRelated statesRelated
      continuationsRelated callFramesRelated =>
      cases callbacks
      all_goals
        simp [resumeWorldExecution, originalExecutionWorld?] at originalWorldExact
        simp [resumeWorldExecution, originalExecutionMachine?] at originalStateExact
        simp [nativeExecutionWorld?] at candidateWorldExact
        simp [NativeWorldExecution.machine?] at candidateStateExact
        subst originalWorld
        subst candidateWorld
        subst originalState
        subst candidateState
        exact statesRelated
  | terminated originalSuccessorWorld candidateSuccessorWorld worldsRelated =>
      simp [originalExecutionMachine?] at originalStateExact
  | fault originalCause candidateCause causesRelated =>
      simp [originalExecutionWorld?] at originalWorldExact

/-- Checked operational evidence at one callback-free external boundary.

`successorsPreserveInvariant` is deliberately quantified over the exact
successor relation.  A caller cannot use it to submit a favorable endpoint:
the endpoint is computed from `dispatch` and the concrete environment action.
-/
structure ExactMixedExternalBoundaryEvidence
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedExternalFrameContract)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution) where
  suspension : WorldExternalSuspension
  dispatch : ExactNativeExternalDispatch candidate
  originalDispatch : ExactOriginalExternalDispatch original originalBefore
    suspension []
  candidateBeforeExact : dispatch.before = candidateBefore
  boundaryRelated :
    contract.externalBoundariesRelated suspension dispatch.boundary
  frameBoundary : MixedExternalFrameBoundaryRelated frames suspension []
    dispatch.continuationRva dispatch.calls
  successorsPreserveInvariant :
    (exactSuccessors :
      MixedExternalSuccessorsRelated contract frames suspension [] dispatch
        (originalExternalAfter original suspension []) dispatch.after) ->
    MixedExternalSuccessorRuntimeStatesRelated contract
        (originalExternalAfter original suspension []) dispatch.after ->
      invariant.holds
        (originalExternalAfter original suspension []) dispatch.after

/-- Derive the complete machine-level 1:1 external-event chunk.

Both paths, the related singleton observations, and the exact successor pair
come from `exactMixedExternalInteractionChunk`.  The endpoint invariant follows
by applying the evidence's successor-shape closure to that derived successor.
-/
def ExactMixedExternalBoundaryEvidence.toChunk
    (evidence : ExactMixedExternalBoundaryEvidence original candidate contract
      frames invariant originalBefore candidateBefore)
    (environmentsRefine : ExactOneToOneMixedExternalEnvironmentsRefine original
      candidate contract frames) :
    MixedKernelChunkPaths original candidate contract invariant originalBefore
      candidateBefore := by
  let interaction := exactMixedExternalInteractionChunk original candidate
    contract frames originalBefore evidence.suspension [] evidence.dispatch
    evidence.originalDispatch evidence.boundaryRelated evidence.frameBoundary
    environmentsRefine
  exact {
    originalObservations := [originalExternalObservation evidence.suspension]
    candidateObservations := [evidence.dispatch.observation]
    originalAfter := originalExternalAfter original evidence.suspension []
    candidateAfter := evidence.dispatch.after
    originalPath := interaction.originalPath
    candidatePath := by
      simpa [evidence.candidateBeforeExact] using interaction.candidatePath
    observationsChecked := {
      pointwise := interaction.observationsRelated
    }
    afterRelated :=
      evidence.successorsPreserveInvariant interaction.successorsRelated
        (mixedExternalSuccessors_runtimeStatesRelated
          interaction.successorsRelated)
  }

/-- Exact checked evidence expected at every source classified as an external
boundary.  Source and candidate-RVA premises retain the authority selected by
the total mixed classifier. -/
def ExactMixedExternalBoundaryEvidenceFactory
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (contract : MixedRelationContract)
    (frames : MixedExternalFrameContract)
    (launch : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext launch)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot)
    (invariant : MixedExecutionInvariant reachability.targetIds contract) :
    Type :=
  forall originalBefore candidateBefore
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launch originalRoot reachability candidate candidateAuthority)
      (candidateRva : Nat),
    originalExecutionAtBoundarySource source.targetId originalBefore ->
    nativeExecutionAtRva candidateRva candidateBefore ->
    ExactMixedExternalBoundaryEvidence original candidate contract frames
      invariant originalBefore candidateBefore

/-- Acceptance-facing external chunk factory with the signature consumed by
`EnvironmentParametricMixedComponentPremises.externalBoundaryChunk`. -/
def ExactMixedExternalBoundaryChunkFactory
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
    (invariant : MixedExecutionInvariant reachability.targetIds contract) :
    Type :=
  forall originalBefore candidateBefore
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launch originalRoot reachability candidate candidateAuthority)
      (candidateRva : Nat),
    originalExecutionAtBoundarySource source.targetId originalBefore ->
    nativeExecutionAtRva candidateRva candidateBefore ->
    MixedKernelChunkPaths original candidate contract invariant originalBefore
      candidateBefore

def exactMixedExternalBoundaryChunkFactoryOfEvidence
    (environmentsRefine : ExactOneToOneMixedExternalEnvironmentsRefine original
      candidate contract frames)
    (evidence : ExactMixedExternalBoundaryEvidenceFactory originalContext
      originalAuthority original candidate candidateAuthority contract frames
      launch originalRoot reachability invariant) :
    ExactMixedExternalBoundaryChunkFactory originalContext originalAuthority
      original candidate candidateAuthority contract launch originalRoot
      reachability invariant := by
  intro originalBefore candidateBefore source candidateRva originalAtSource
    candidateAtSource
  exact (evidence originalBefore candidateBefore source candidateRva
    originalAtSource candidateAtSource).toChunk environmentsRefine

/-- Checked boundary evidence for every concrete environment pair satisfying
the exact one-to-one protocol relation. -/
def ExactMixedExternalBoundaryEvidenceFactoriesForRefiningEnvironments
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (originalTemplate : DecodedWorldProgram)
    (candidateTemplate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidateTemplate)
    (contract : MixedRelationContract)
    (frames : MixedExternalFrameContract)
    (launch : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext launch)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot)
    (invariant : MixedExecutionInvariant reachability.targetIds contract) :
    Type :=
  forall originalEnvironment candidateEnvironment,
    (environmentsRefine : ExactOneToOneMixedExternalEnvironmentsRefine
      (mixedExternalOriginalProgramWithEnvironment originalTemplate
        originalEnvironment)
      (mixedExternalCandidateProgramWithEnvironment candidateTemplate
        candidateEnvironment)
      contract frames) ->
    ExactMixedExternalBoundaryEvidenceFactory originalContext originalAuthority
      (mixedExternalOriginalProgramWithEnvironment originalTemplate
        originalEnvironment)
      (mixedExternalCandidateProgramWithEnvironment candidateTemplate
        candidateEnvironment)
      (mixedExternalCandidateAuthorityWithEnvironment candidateAuthority
        candidateEnvironment)
      contract frames launch originalRoot reachability invariant

/-- Complete external chunk factories for every refining environment pair. -/
def ExactMixedExternalBoundaryChunkFactoriesForRefiningEnvironments
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (originalTemplate : DecodedWorldProgram)
    (candidateTemplate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidateTemplate)
    (contract : MixedRelationContract)
    (frames : MixedExternalFrameContract)
    (launch : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext launch)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot)
    (invariant : MixedExecutionInvariant reachability.targetIds contract) :
    Type :=
  forall originalEnvironment candidateEnvironment,
    (environmentsRefine : ExactOneToOneMixedExternalEnvironmentsRefine
      (mixedExternalOriginalProgramWithEnvironment originalTemplate
        originalEnvironment)
      (mixedExternalCandidateProgramWithEnvironment candidateTemplate
        candidateEnvironment)
      contract frames) ->
    ExactMixedExternalBoundaryChunkFactory originalContext originalAuthority
      (mixedExternalOriginalProgramWithEnvironment originalTemplate
        originalEnvironment)
      (mixedExternalCandidateProgramWithEnvironment candidateTemplate
        candidateEnvironment)
      (mixedExternalCandidateAuthorityWithEnvironment candidateAuthority
        candidateEnvironment)
      contract launch originalRoot reachability invariant

def exactMixedExternalBoundaryChunkFactoriesForRefiningEnvironments
    (evidence :
      ExactMixedExternalBoundaryEvidenceFactoriesForRefiningEnvironments
        originalContext originalAuthority originalTemplate candidateTemplate
        candidateAuthority contract frames launch originalRoot reachability
        invariant) :
    ExactMixedExternalBoundaryChunkFactoriesForRefiningEnvironments
      originalContext originalAuthority originalTemplate candidateTemplate
      candidateAuthority contract frames launch originalRoot reachability
      invariant := by
  intro originalEnvironment candidateEnvironment environmentsRefine
  exact exactMixedExternalBoundaryChunkFactoryOfEvidence environmentsRefine
    (evidence originalEnvironment candidateEnvironment environmentsRefine)

/-- Whether checked source-classification evidence is an actual external
boundary.  This predicate is indexed by the evidence selected from the exact
original/candidate state pair. -/
def constructiveMixedKernelSourceEvidenceIsExternalBoundary :
    ConstructiveMixedKernelSourceEvidence originalContext originalAuthority
      launch originalRoot reachability candidate candidateAuthority program
      candidateRootRva originalBefore candidateBefore -> Prop
  | .externalBoundary .. => True
  | _ => False

/-- External-boundary discriminator for the composition-facing classifier
result. -/
def mixedKernelRelatedSourceCaseIsExternalBoundary :
    MixedKernelRelatedSourceCase originalContext originalAuthority launch
      originalRoot reachability candidate candidateAuthority program
      candidateRootRva originalBefore candidateBefore -> Prop
  | .externalBoundary .. => True
  | _ => False

/-- Whether checked source-classification evidence selects the dedicated
external-operation constructor. External events inside semantic-transfer
chunks do not satisfy this discriminator. -/
def constructiveMixedKernelSourceEvidenceIsExternalOperation :
    ConstructiveMixedKernelSourceEvidence originalContext originalAuthority
      launch originalRoot reachability candidate candidateAuthority program
      candidateRootRva originalBefore candidateBefore -> Prop
  | .externalOperation .. => True
  | _ => False

/-- External-operation discriminator for the composition-facing classifier
result. -/
def mixedKernelRelatedSourceCaseIsExternalOperation :
    MixedKernelRelatedSourceCase originalContext originalAuthority launch
      originalRoot reachability candidate candidateAuthority program
      candidateRootRva originalBefore candidateBefore -> Prop
  | .externalOperation .. => True
  | _ => False

/-- Translating constructive evidence to the composition classifier preserves
the external-boundary discriminator. -/
theorem constructiveEvidence_toRelatedSourceCase_isExternalBoundary
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore) :
    mixedKernelRelatedSourceCaseIsExternalBoundary evidence.toRelatedSourceCase =
      constructiveMixedKernelSourceEvidenceIsExternalBoundary evidence := by
  cases evidence <;>
    simp [mixedKernelRelatedSourceCaseIsExternalBoundary,
      constructiveMixedKernelSourceEvidenceIsExternalBoundary,
      ConstructiveMixedKernelSourceEvidence.toRelatedSourceCase]

/-- Translating constructive evidence to the composition classifier preserves
the external-operation discriminator. -/
theorem constructiveEvidence_toRelatedSourceCase_isExternalOperation
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore) :
    mixedKernelRelatedSourceCaseIsExternalOperation evidence.toRelatedSourceCase =
      constructiveMixedKernelSourceEvidenceIsExternalOperation evidence := by
  cases evidence <;>
    simp [mixedKernelRelatedSourceCaseIsExternalOperation,
      constructiveMixedKernelSourceEvidenceIsExternalOperation,
      ConstructiveMixedKernelSourceEvidence.toRelatedSourceCase]

/-- The checked source-evidence selector has no external-boundary cases.
Unlike a second reduction of `MixedKernelSourceClassifier.classify`, this
authority retains the exact classifier-state equation used by the
constructive invariant. -/
def ConstructiveMixedKernelClassificationHasNoExternalBoundaries
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva)) : Prop :=
  forall originalBefore candidateBefore
      (evidence : ConstructiveMixedKernelSourceEvidence originalContext
        originalAuthority launch originalRoot reachability candidate
        candidateAuthority program candidateRootRva originalBefore
        candidateBefore),
    constructiveMixedKernelSourceEvidence? rules originalBefore
        candidateBefore = some evidence ->
      Not (constructiveMixedKernelSourceEvidenceIsExternalBoundary evidence)

/-- The checked source-evidence selector has no dedicated external-operation
cases. Semantic-transfer chunks may still contain exact external events; this
predicate excludes only the separate classifier constructor. -/
def ConstructiveMixedKernelClassificationHasNoExternalOperations
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva)) : Prop :=
  forall originalBefore candidateBefore
      (evidence : ConstructiveMixedKernelSourceEvidence originalContext
        originalAuthority launch originalRoot reachability candidate
        candidateAuthority program candidateRootRva originalBefore
        candidateBefore),
    constructiveMixedKernelSourceEvidence? rules originalBefore
        candidateBefore = some evidence ->
      Not (constructiveMixedKernelSourceEvidenceIsExternalOperation evidence)

/-- The classifier-selected runtime phase facts and the exact operational
boundary evidence are kept together.  This lives in `Type` because the
operational evidence contains executable proof data. -/
structure ClassifiedExactMixedExternalBoundaryEvidence
    (contract : MixedRelationContract)
    (invariant : MixedExecutionInvariant reachability.targetIds contract)
    (original : DecodedWorldProgram)
    (frames : MixedExternalFrameContract)
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore) where
  phaseFacts : ConstructiveMixedKernelPhaseStateFacts contract evidence
  boundaryEvidence : ExactMixedExternalBoundaryEvidence original candidate
    contract frames invariant originalBefore candidateBefore

/-- Evidence requested only for exact classification equations selecting an
actual external boundary. Non-boundary cases return `PUnit`; they cannot
smuggle a path, observation list, endpoint, or endpoint relation into this
layer. -/
def ClassifiedExactMixedExternalBoundaryEvidenceFactory
    (contract : MixedRelationContract)
    (invariant : MixedExecutionInvariant reachability.targetIds contract)
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva))
    (original : DecodedWorldProgram)
    (frames : MixedExternalFrameContract) : Type :=
  forall originalBefore candidateBefore
      (_beforeRelated : invariant.holds originalBefore candidateBefore)
      (evidence : ConstructiveMixedKernelSourceEvidence originalContext
        originalAuthority launch originalRoot reachability candidate
        candidateAuthority program candidateRootRva originalBefore
        candidateBefore)
      (_classifiedExact : constructiveMixedKernelSourceEvidence? rules
        originalBefore candidateBefore = some evidence),
    match evidence with
    | .externalBoundary .. =>
        ClassifiedExactMixedExternalBoundaryEvidence contract invariant original
          frames evidence
    | _ => PUnit

/-- Acceptance-facing classified chunk factory. Its result is a chunk only
for an actual external-boundary classifier result. -/
def ClassifiedExactMixedExternalBoundaryChunkFactory
    (contract : MixedRelationContract)
    (invariant : MixedExecutionInvariant reachability.targetIds contract)
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva))
    (original : DecodedWorldProgram) : Type :=
  forall originalBefore candidateBefore
      (_beforeRelated : invariant.holds originalBefore candidateBefore)
      (evidence : ConstructiveMixedKernelSourceEvidence originalContext
        originalAuthority launch originalRoot reachability candidate
        candidateAuthority program candidateRootRva originalBefore
        candidateBefore)
      (_classifiedExact : constructiveMixedKernelSourceEvidence? rules
        originalBefore candidateBefore = some evidence),
    match evidence with
    | .externalBoundary .. =>
        MixedKernelChunkPaths original candidate contract invariant
          originalBefore candidateBefore
    | _ => PUnit

/-- Derive classified chunks from exact dispatch evidence and the 1:1
environment theorem. -/
def classifiedExactMixedExternalBoundaryChunkFactoryOfEvidence
    (contract : MixedRelationContract)
    (invariant : MixedExecutionInvariant reachability.targetIds contract)
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva))
    (environmentsRefine : ExactOneToOneMixedExternalEnvironmentsRefine original
      candidate contract frames)
    (evidence : ClassifiedExactMixedExternalBoundaryEvidenceFactory contract
      invariant rules original frames) :
    ClassifiedExactMixedExternalBoundaryChunkFactory contract invariant
      rules original := by
  intro originalBefore candidateBefore beforeRelated classified classifiedExact
  cases classified
  case externalBoundary source owner candidateRva originalAtSource
      candidateAtSource =>
    have checkedEvidence := evidence originalBefore candidateBefore
      beforeRelated _ classifiedExact
    exact checkedEvidence.boundaryEvidence.toChunk environmentsRefine
  all_goals exact PUnit.unit

/-- A no-boundary classification has a closed evidence factory. The external
branch is eliminated from the exact source-evidence equation; no operational
evidence is fabricated. -/
def classifiedExactMixedExternalBoundaryEvidenceFactoryOfNoCases
    (contract : MixedRelationContract)
    (invariant : MixedExecutionInvariant reachability.targetIds contract)
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva))
    (noExternalBoundaries :
      ConstructiveMixedKernelClassificationHasNoExternalBoundaries rules) :
    ClassifiedExactMixedExternalBoundaryEvidenceFactory contract invariant
      rules original frames := by
  intro originalBefore candidateBefore beforeRelated classified classifiedExact
  cases classified
  case externalBoundary =>
    exact False.elim (noExternalBoundaries originalBefore candidateBefore _
      classifiedExact (by trivial))
  all_goals exact PUnit.unit

private def constructiveRuleIsExternalBoundary :
    ConstructiveMixedKernelSourceRule originalContext originalAuthority launch
      originalRoot reachability candidate candidateAuthority program
      candidateRootRva -> Prop
  | .externalBoundary .. => True
  | _ => False

private def constructiveRuleIsExternalOperation :
    ConstructiveMixedKernelSourceRule originalContext originalAuthority launch
      originalRoot reachability candidate candidateAuthority program
      candidateRootRva -> Prop
  | .externalOperation .. => True
  | _ => False

private theorem nonExternalRule_producesNonExternalEvidence
    (rule : ConstructiveMixedKernelSourceRule originalContext originalAuthority
      launch originalRoot reachability candidate candidateAuthority program
      candidateRootRva)
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore candidateBefore)
    (notExternal : Not (constructiveRuleIsExternalBoundary rule))
    (selected : rule.evidence? originalBefore candidateBefore = some evidence) :
    Not (constructiveMixedKernelSourceEvidenceIsExternalBoundary evidence) := by
  cases rule with
  | launch source sourceIsRoot =>
      cases carrierExact :
          exactConstructiveMixedLaunchCarrier? candidate launch
            candidateRootRva originalBefore candidateBefore with
      | none =>
          simp [ConstructiveMixedKernelSourceRule.evidence?, carrierExact]
            at selected
      | some carrier =>
          simp [ConstructiveMixedKernelSourceRule.evidence?, carrierExact]
            at selected
          subst evidence
          simp [constructiveMixedKernelSourceEvidenceIsExternalBoundary]
  | semanticTransfer source entry =>
      simp [ConstructiveMixedKernelSourceRule.evidence?] at selected
      obtain ⟨_, _, selected⟩ := selected
      subst evidence
      simp [constructiveMixedKernelSourceEvidenceIsExternalBoundary]
  | externalOperation source entry =>
      simp [ConstructiveMixedKernelSourceRule.evidence?] at selected
      obtain ⟨_, _, selected⟩ := selected
      subst evidence
      simp [constructiveMixedKernelSourceEvidenceIsExternalBoundary]
  | externalBoundary source owner candidateRva =>
      simp [constructiveRuleIsExternalBoundary] at notExternal

private theorem nonExternalOperationRule_producesNonExternalOperationEvidence
    (rule : ConstructiveMixedKernelSourceRule originalContext originalAuthority
      launch originalRoot reachability candidate candidateAuthority program
      candidateRootRva)
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore candidateBefore)
    (notExternal : Not (constructiveRuleIsExternalOperation rule))
    (selected : rule.evidence? originalBefore candidateBefore = some evidence) :
    Not (constructiveMixedKernelSourceEvidenceIsExternalOperation evidence) := by
  cases rule with
  | launch source sourceIsRoot =>
      cases carrierExact :
          exactConstructiveMixedLaunchCarrier? candidate launch
            candidateRootRva originalBefore candidateBefore with
      | none =>
          simp [ConstructiveMixedKernelSourceRule.evidence?, carrierExact]
            at selected
      | some carrier =>
          simp [ConstructiveMixedKernelSourceRule.evidence?, carrierExact]
            at selected
          subst evidence
          simp [constructiveMixedKernelSourceEvidenceIsExternalOperation]
  | semanticTransfer source entry =>
      simp [ConstructiveMixedKernelSourceRule.evidence?] at selected
      obtain ⟨_, _, selected⟩ := selected
      subst evidence
      simp [constructiveMixedKernelSourceEvidenceIsExternalOperation]
  | externalOperation source entry =>
      simp [constructiveRuleIsExternalOperation] at notExternal
  | externalBoundary source owner candidateRva =>
      simp [ConstructiveMixedKernelSourceRule.evidence?] at selected
      obtain ⟨_, _, selected⟩ := selected
      subst evidence
      simp [constructiveMixedKernelSourceEvidenceIsExternalOperation]

private theorem constructiveSemanticRule_notExternal
    (coverage : ExactOriginalSemanticSourceCoverage originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority)
    (stepEntry : ExactCandidateKernelEntry program)
    (rule : ConstructiveMixedKernelSourceRule originalContext originalAuthority
      launch originalRoot reachability candidate candidateAuthority program
      candidateRootRva)
    (member : rule ∈ constructiveSemanticRulesWithLaunch
      (candidateRootRva := candidateRootRva) coverage stepEntry) :
    Not (constructiveRuleIsExternalBoundary rule) := by
  rw [constructiveSemanticRulesWithLaunch] at member
  obtain ⟨source, _, rfl⟩ := List.mem_map.mp member
  by_cases sourceIsRoot : source.targetId = launch.rootTargetId <;>
    simp [sourceIsRoot, constructiveRuleIsExternalBoundary]

private theorem selectedConstructiveSemanticEvidence_notExternal
    (coverage : ExactOriginalSemanticSourceCoverage originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority)
    (stepEntry : ExactCandidateKernelEntry program)
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore candidateBefore)
    (selected : uniqueConstructiveMixedKernelActiveEvidence?
      (constructiveSemanticRulesWithLaunch (candidateRootRva := candidateRootRva)
        coverage stepEntry) originalBefore candidateBefore = some evidence) :
    Not (constructiveMixedKernelSourceEvidenceIsExternalBoundary evidence) := by
  unfold uniqueConstructiveMixedKernelActiveEvidence? at selected
  generalize activeExact :
      constructiveMixedKernelActiveEvidence
        (constructiveSemanticRulesWithLaunch
          (candidateRootRva := candidateRootRva) coverage stepEntry)
        originalBefore candidateBefore = active at selected
  cases active with
  | nil => contradiction
  | cons head tail =>
      cases tail with
      | nil =>
          simp only [Option.some.injEq] at selected
          subst head
          have evidenceMember :
              evidence ∈ constructiveMixedKernelActiveEvidence
                (constructiveSemanticRulesWithLaunch
                  (candidateRootRva := candidateRootRva) coverage stepEntry)
                originalBefore candidateBefore := by
            rw [activeExact]
            simp
          rw [constructiveMixedKernelActiveEvidence] at evidenceMember
          obtain ⟨rule, ruleMember, ruleSelected⟩ :=
            List.mem_filterMap.mp evidenceMember
          exact nonExternalRule_producesNonExternalEvidence rule evidence
            (constructiveSemanticRule_notExternal coverage stepEntry rule
              ruleMember)
            ruleSelected
      | cons other rest => contradiction

private theorem constructiveSemanticEvidence_notExternal
    (coverage : ExactOriginalSemanticSourceCoverage originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority)
    (stepEntry : ExactCandidateKernelEntry program)
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore candidateBefore)
    (selected : constructiveMixedKernelSourceEvidence?
      (constructiveSemanticRulesWithLaunch (candidateRootRva := candidateRootRva)
        coverage stepEntry) originalBefore candidateBefore = some evidence) :
    Not (constructiveMixedKernelSourceEvidenceIsExternalBoundary evidence) := by
  cases originalBefore <;> cases candidateBefore <;>
    simp only [constructiveMixedKernelSourceEvidence?] at selected
  all_goals
    first
    | exact selectedConstructiveSemanticEvidence_notExternal coverage stepEntry
        evidence selected
    | {
      simp only [Option.some.injEq] at selected
      subst evidence
      simp [constructiveMixedKernelSourceEvidenceIsExternalBoundary]
    }
    | {
      split at selected
      next causesMatch =>
        cases causesMatch
        cases selected
        simp [constructiveMixedKernelSourceEvidenceIsExternalBoundary]
      next => contradiction
    }

/-- The stock launch-plus-semantic-transfer classifier contains no external
boundary constructor. External events reached inside those operation chunks
remain checked by the operation's exact event trace. -/
theorem constructiveSemanticRulesWithLaunch_hasNoExternalBoundaries
    (coverage : ExactOriginalSemanticSourceCoverage originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority)
    (stepEntry : ExactCandidateKernelEntry program) :
    ConstructiveMixedKernelClassificationHasNoExternalBoundaries
      (constructiveSemanticRulesWithLaunch (candidateRootRva := candidateRootRva)
        coverage stepEntry) := by
  intro originalBefore candidateBefore evidence classifiedExact
  exact constructiveSemanticEvidence_notExternal coverage stepEntry evidence
    classifiedExact

private theorem constructiveRootBoundaryRule_notExternalOperation
    (coverage : ExactOriginalSemanticSourceCoverage originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority)
    (stepEntry : ExactCandidateKernelEntry program)
    (candidateBoundaryRva : Nat)
    (rule : ConstructiveMixedKernelSourceRule originalContext originalAuthority
      launch originalRoot reachability candidate candidateAuthority program
      candidateRootRva)
    (member : rule ∈ constructiveSemanticRulesWithRootBoundary
      (candidateRootRva := candidateRootRva) coverage stepEntry
      candidateBoundaryRva) :
    Not (constructiveRuleIsExternalOperation rule) := by
  rw [constructiveSemanticRulesWithRootBoundary] at member
  obtain ⟨source, _, rfl⟩ := List.mem_map.mp member
  by_cases sourceIsRoot : source.targetId = launch.rootTargetId <;>
    simp [sourceIsRoot, constructiveRuleIsExternalOperation]

private theorem selectedConstructiveRootBoundaryEvidence_notExternalOperation
    (coverage : ExactOriginalSemanticSourceCoverage originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority)
    (stepEntry : ExactCandidateKernelEntry program)
    (candidateBoundaryRva : Nat)
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore candidateBefore)
    (selected : uniqueConstructiveMixedKernelActiveEvidence?
      (constructiveSemanticRulesWithRootBoundary
        (candidateRootRva := candidateRootRva) coverage stepEntry
        candidateBoundaryRva) originalBefore candidateBefore = some evidence) :
    Not (constructiveMixedKernelSourceEvidenceIsExternalOperation evidence) := by
  unfold uniqueConstructiveMixedKernelActiveEvidence? at selected
  generalize activeExact :
      constructiveMixedKernelActiveEvidence
        (constructiveSemanticRulesWithRootBoundary
          (candidateRootRva := candidateRootRva) coverage stepEntry
          candidateBoundaryRva)
        originalBefore candidateBefore = active at selected
  cases active with
  | nil => contradiction
  | cons head tail =>
      cases tail with
      | nil =>
          simp only [Option.some.injEq] at selected
          subst head
          have evidenceMember :
              evidence ∈ constructiveMixedKernelActiveEvidence
                (constructiveSemanticRulesWithRootBoundary
                  (candidateRootRva := candidateRootRva) coverage stepEntry
                  candidateBoundaryRva)
                originalBefore candidateBefore := by
            rw [activeExact]
            simp
          rw [constructiveMixedKernelActiveEvidence] at evidenceMember
          obtain ⟨rule, ruleMember, ruleSelected⟩ :=
            List.mem_filterMap.mp evidenceMember
          exact
            nonExternalOperationRule_producesNonExternalOperationEvidence
              rule evidence
              (constructiveRootBoundaryRule_notExternalOperation coverage
                stepEntry candidateBoundaryRva rule ruleMember)
              ruleSelected
      | cons other rest => contradiction

private theorem constructiveRootBoundaryEvidence_notExternalOperation
    (coverage : ExactOriginalSemanticSourceCoverage originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority)
    (stepEntry : ExactCandidateKernelEntry program)
    (candidateBoundaryRva : Nat)
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore candidateBefore)
    (selected : constructiveMixedKernelSourceEvidence?
      (constructiveSemanticRulesWithRootBoundary
        (candidateRootRva := candidateRootRva) coverage stepEntry
        candidateBoundaryRva) originalBefore candidateBefore = some evidence) :
    Not (constructiveMixedKernelSourceEvidenceIsExternalOperation evidence) := by
  cases originalBefore <;> cases candidateBefore <;>
    simp only [constructiveMixedKernelSourceEvidence?] at selected
  all_goals
    first
    | exact
        selectedConstructiveRootBoundaryEvidence_notExternalOperation coverage
          stepEntry candidateBoundaryRva evidence selected
    | {
      simp only [Option.some.injEq] at selected
      subst evidence
      simp [constructiveMixedKernelSourceEvidenceIsExternalOperation]
    }
    | {
      split at selected
      next causesMatch =>
        cases causesMatch
        cases selected
        simp [constructiveMixedKernelSourceEvidenceIsExternalOperation]
      next => contradiction
    }

/-- The canonical runtime inventory consists of semantic transfers plus one
root boundary and therefore cannot select a dedicated external-operation
case. External calls reached by a semantic transfer remain part of that
transfer's exact checked event trace. -/
theorem constructiveSemanticRulesWithRootBoundary_hasNoExternalOperations
    (coverage : ExactOriginalSemanticSourceCoverage originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority)
    (stepEntry : ExactCandidateKernelEntry program)
    (candidateBoundaryRva : Nat) :
    ConstructiveMixedKernelClassificationHasNoExternalOperations
      (constructiveSemanticRulesWithRootBoundary
        (candidateRootRva := candidateRootRva) coverage stepEntry
        candidateBoundaryRva) := by
  intro originalBefore candidateBefore evidence classifiedExact
  exact constructiveRootBoundaryEvidence_notExternalOperation coverage
    stepEntry candidateBoundaryRva evidence classifiedExact

/-- A constructive runtime classifier cannot select a dedicated
external-operation case when the exact selected rule inventory excludes that
constructor. -/
theorem constructiveRuntimeExternalOperationSelection_impossible
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva))
    (noExternalOperations :
      ConstructiveMixedKernelClassificationHasNoExternalOperations rules)
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution)
    (beforeRelated :
      (constructiveMixedKernelRuntimeInvariant originalContext
        originalAuthority launch originalRoot reachability candidate
        candidateAuthority program candidateRootRva contract rules).holds
        originalBefore candidateBefore)
    (source : ExactOriginalSemanticSource originalContext originalAuthority
      launch originalRoot reachability candidate candidateAuthority)
    (operation : KernelOperation)
    (entryRva : Nat)
    (originalAtSource :
      originalExecutionAtBoundarySource source.targetId originalBefore)
    (candidateAtEntry :
      nativeExecutionAtRva entryRva candidateBefore)
    (entryExact : program.functionEntry? operation.role = some entryRva)
    (classified :
      ((constructiveMixedKernelRuntimeSourceClassifier originalContext
          originalAuthority launch originalRoot reachability candidate
          candidateAuthority program candidateRootRva contract rules).classifier.classify
          originalBefore candidateBefore beforeRelated) =
        MixedKernelRelatedSourceCase.externalOperation source operation entryRva
          originalAtSource candidateAtEntry entryExact) :
    False := by
  let evidence := Classical.choose beforeRelated
  have selected :
      constructiveMixedKernelSourceEvidence? rules originalBefore
          candidateBefore = some evidence :=
    (Classical.choose_spec beforeRelated).2.2.1
  have notOperation :
      Not (constructiveMixedKernelSourceEvidenceIsExternalOperation evidence) :=
    noExternalOperations originalBefore candidateBefore evidence selected
  have evidenceCase :
      evidence.toRelatedSourceCase =
        MixedKernelRelatedSourceCase.externalOperation source operation entryRva
          originalAtSource candidateAtEntry entryExact := by
    simpa [constructiveMixedKernelRuntimeSourceClassifier, evidence] using
      classified
  have relatedOperation :
      mixedKernelRelatedSourceCaseIsExternalOperation
        evidence.toRelatedSourceCase := by
    rw [evidenceCase]
    trivial
  have evidenceOperation :
      constructiveMixedKernelSourceEvidenceIsExternalOperation evidence := by
    rw [← constructiveEvidence_toRelatedSourceCase_isExternalOperation evidence]
    exact relatedOperation
  exact notOperation evidenceOperation

/-- Closed external-operation component factory for a runtime classifier whose
checked rule inventory has no dedicated external-operation cases. The unused
operation proof is still accepted so this result has the exact acceptance
interface. -/
noncomputable def constructiveRuntimeExternalOperationComponentOfNoCases
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva))
    (noExternalOperations :
      ConstructiveMixedKernelClassificationHasNoExternalOperations rules)
    {abi : KernelABIRelation}
    {dispatches : RelationalWorld -> KernelDispatchRelation} :
    forall originalBefore candidateBefore
        (source : ExactOriginalSemanticSource originalContext originalAuthority
          launch originalRoot reachability candidate candidateAuthority)
        (operation : KernelOperation)
        (entryRva : Nat)
        (beforeRelated :
          (constructiveMixedKernelRuntimeInvariant originalContext
            originalAuthority launch originalRoot reachability candidate
            candidateAuthority program candidateRootRva contract rules).holds
            originalBefore candidateBefore)
        (originalAtSource :
          originalExecutionAtBoundarySource source.targetId originalBefore)
        (candidateAtEntry :
          nativeExecutionAtRva entryRva candidateBefore)
        (candidateWorld : RelationalWorld)
        (candidateWorldExact :
          nativeExecutionWorld? candidateBefore = some candidateWorld)
        (entryExact :
          program.functionEntry? operation.role = some entryRva)
        (classified :
          ((constructiveMixedKernelRuntimeSourceClassifier originalContext
              originalAuthority launch originalRoot reachability candidate
              candidateAuthority program candidateRootRva contract rules).classifier.classify
              originalBefore candidateBefore beforeRelated) =
            MixedKernelRelatedSourceCase.externalOperation source operation
              entryRva originalAtSource candidateAtEntry entryExact),
      KernelOperationRefinesUsing program abi (dispatches candidateWorld)
          operation ->
        MixedKernelOperationComponentCertificate original candidate contract
          (constructiveMixedKernelRuntimeInvariant originalContext
            originalAuthority launch originalRoot reachability candidate
            candidateAuthority program candidateRootRva contract rules)
          program abi (dispatches candidateWorld) candidateAuthority
          source.source.target.rva operation entryRva originalBefore
          candidateBefore := by
  intro originalBefore candidateBefore source operation entryRva beforeRelated
    originalAtSource candidateAtEntry candidateWorld candidateWorldExact
    entryExact classified operationRefines
  exact False.elim
    (constructiveRuntimeExternalOperationSelection_impossible rules
      noExternalOperations originalBefore candidateBefore beforeRelated source
      operation entryRva originalAtSource candidateAtEntry entryExact
      classified)

/-- A constructive runtime classifier cannot select an external-boundary case
when its exact rule inventory proves that no selected evidence has that shape.
The contradiction is derived from the same witness stored in the runtime
invariant; no second classification pass is trusted. -/
theorem constructiveRuntimeExternalBoundarySelection_impossible
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva))
    (noExternalBoundaries :
      ConstructiveMixedKernelClassificationHasNoExternalBoundaries rules)
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution)
    (beforeRelated :
      (constructiveMixedKernelRuntimeInvariant originalContext
        originalAuthority launch originalRoot reachability candidate
        candidateAuthority program candidateRootRva contract rules).holds
        originalBefore candidateBefore)
    (source : ExactOriginalSemanticSource originalContext originalAuthority
      launch originalRoot reachability candidate candidateAuthority)
    (candidateRva : Nat)
    (originalAtSource :
      originalExecutionAtBoundarySource source.targetId originalBefore)
    (candidateAtSource :
      nativeExecutionAtRva candidateRva candidateBefore)
    (classified :
      ((constructiveMixedKernelRuntimeSourceClassifier originalContext
          originalAuthority launch originalRoot reachability candidate
          candidateAuthority program candidateRootRva contract rules).classifier.classify
          originalBefore candidateBefore beforeRelated) =
        MixedKernelRelatedSourceCase.externalBoundary source candidateRva
          originalAtSource candidateAtSource) :
    False := by
  let evidence := Classical.choose beforeRelated
  have selected :
      constructiveMixedKernelSourceEvidence? rules originalBefore
          candidateBefore = some evidence :=
    (Classical.choose_spec beforeRelated).2.2.1
  have notBoundary :
      Not (constructiveMixedKernelSourceEvidenceIsExternalBoundary evidence) :=
    noExternalBoundaries originalBefore candidateBefore evidence selected
  have evidenceCase :
      evidence.toRelatedSourceCase =
        MixedKernelRelatedSourceCase.externalBoundary source candidateRva
          originalAtSource candidateAtSource := by
    simpa [constructiveMixedKernelRuntimeSourceClassifier, evidence] using
      classified
  have relatedBoundary :
      mixedKernelRelatedSourceCaseIsExternalBoundary
        evidence.toRelatedSourceCase := by
    rw [evidenceCase]
    trivial
  have evidenceBoundary :
      constructiveMixedKernelSourceEvidenceIsExternalBoundary evidence := by
    rw [← constructiveEvidence_toRelatedSourceCase_isExternalBoundary evidence]
    exact relatedBoundary
  exact notBoundary evidenceBoundary

/-- Closed external-boundary chunk factory for a constructive runtime
classifier whose checked rule inventory has no external-boundary cases. -/
noncomputable def constructiveRuntimeExternalBoundaryChunkOfNoCases
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launch originalRoot reachability candidate
      candidateAuthority program candidateRootRva))
    (noExternalBoundaries :
      ConstructiveMixedKernelClassificationHasNoExternalBoundaries rules) :
    forall originalBefore candidateBefore
        (source : ExactOriginalSemanticSource originalContext originalAuthority
          launch originalRoot reachability candidate candidateAuthority)
        (candidateRva : Nat)
        (beforeRelated :
          (constructiveMixedKernelRuntimeInvariant originalContext
            originalAuthority launch originalRoot reachability candidate
            candidateAuthority program candidateRootRva contract rules).holds
            originalBefore candidateBefore)
        (originalAtSource :
          originalExecutionAtBoundarySource source.targetId originalBefore)
        (candidateAtSource :
          nativeExecutionAtRva candidateRva candidateBefore)
        (classified :
          ((constructiveMixedKernelRuntimeSourceClassifier originalContext
              originalAuthority launch originalRoot reachability candidate
              candidateAuthority program candidateRootRva contract rules).classifier.classify
              originalBefore candidateBefore beforeRelated) =
            MixedKernelRelatedSourceCase.externalBoundary source candidateRva
              originalAtSource candidateAtSource),
      MixedKernelChunkPaths original candidate contract
        (constructiveMixedKernelRuntimeInvariant originalContext
          originalAuthority launch originalRoot reachability candidate
          candidateAuthority program candidateRootRva contract rules)
        originalBefore candidateBefore := by
  intro originalBefore candidateBefore source candidateRva beforeRelated
    originalAtSource candidateAtSource classified
  exact False.elim
    (constructiveRuntimeExternalBoundarySelection_impossible rules
      noExternalBoundaries originalBefore candidateBefore beforeRelated source
      candidateRva originalAtSource candidateAtSource classified)

#print axioms mixedExternalSuccessors_runtimeStatesRelated
#print axioms ExactMixedExternalBoundaryEvidence.toChunk
#print axioms exactMixedExternalBoundaryChunkFactoryOfEvidence
#print axioms
  exactMixedExternalBoundaryChunkFactoriesForRefiningEnvironments
#print axioms classifiedExactMixedExternalBoundaryChunkFactoryOfEvidence
#print axioms
  classifiedExactMixedExternalBoundaryEvidenceFactoryOfNoCases
#print axioms
  constructiveSemanticRulesWithLaunch_hasNoExternalBoundaries
#print axioms
  constructiveSemanticRulesWithRootBoundary_hasNoExternalOperations
#print axioms
  constructiveEvidence_toRelatedSourceCase_isExternalBoundary
#print axioms
  constructiveEvidence_toRelatedSourceCase_isExternalOperation
#print axioms constructiveRuntimeExternalOperationSelection_impossible
#print axioms constructiveRuntimeExternalOperationComponentOfNoCases
#print axioms constructiveRuntimeExternalBoundarySelection_impossible
#print axioms constructiveRuntimeExternalBoundaryChunkOfNoCases

end StageA.Relational.InterpreterMixedExternalComponent
