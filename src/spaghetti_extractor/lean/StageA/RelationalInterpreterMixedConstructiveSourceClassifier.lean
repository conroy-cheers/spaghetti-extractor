import StageA.RelationalInterpreterMixedKernelComposition
import StageA.RelationalInterpreterNativeLaunch

namespace StageA.Relational.InterpreterMixedConstructiveSourceClassifier

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

/-! # Constructive mixed-kernel source classification

The mixed-kernel composition theorem consumes a total
`MixedKernelSourceClassifier`.  This module derives that classifier by
interpreting a finite list of typed source rules.  Admitted invariant states
must satisfy the relational state facts and produce exactly one checked source
witness.  No separately supplied classification function is accepted.
-/

/-- The relational facts required by `MixedExecutionInvariant` for one state
pair.  They are checked alongside the source classification instead of being
hidden in a generated classifier. -/
structure ConstructiveMixedKernelStateFacts
    (reachabilityTargetIds : List Nat)
    (contract : MixedRelationContract)
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution) : Prop where
  originalReachable :
    OriginalExecutionReachable reachabilityTargetIds originalBefore
  candidateProofOpen : NativeExecutionProofOpen candidateBefore
  worldsRelated : forall originalWorld candidateWorld,
    originalExecutionWorld? originalBefore = some originalWorld ->
    nativeExecutionWorld? candidateBefore = some candidateWorld ->
    contract.worldsRelated originalWorld candidateWorld

instance instDecidableOriginalExecutionAtTargetId
    (targetId : Nat) (execution : WorldExecution) :
    Decidable (originalExecutionAtTargetId targetId execution) := by
  cases execution <;>
    simp [originalExecutionAtTargetId] <;>
    infer_instance

instance instDecidableOriginalExecutionAtBoundarySource
    (targetId : Nat) (execution : WorldExecution) :
    Decidable (originalExecutionAtBoundarySource targetId execution) := by
  cases execution <;>
    simp [originalExecutionAtBoundarySource] <;>
    infer_instance

instance instDecidableNativeExecutionAtRva
    (rva : Nat) (execution : NativeWorldExecution) :
    Decidable (nativeExecutionAtRva rva execution) := by
  cases execution <;>
    simp [nativeExecutionAtRva] <;>
    infer_instance

/-- One finite check connects every decoded reachable source to the exact
PE-backed semantic table.  It is intentionally stated over source RVAs: the
table certificate separately proves those keys unique, so this check cannot
silently select an ambiguous record. -/
def exactOriginalSemanticSourceCoverageChecked
    (context : OriginalDecodedStaticContext)
    (targetIds candidateSourceRvas : List Nat) : Bool :=
  targetIds.all fun targetId =>
    match context.source? targetId with
    | none => false
    | some source => candidateSourceRvas.contains source.target.rva

theorem exactOriginalSemanticSourceCoverageChecked_sourceRva_mem
    (checked : exactOriginalSemanticSourceCoverageChecked context targetIds
      candidateSourceRvas = true)
    (reachable : targetId ∈ targetIds)
    (sourceExact : context.source? targetId = some source) :
    source.target.rva ∈ candidateSourceRvas := by
  simp only [exactOriginalSemanticSourceCoverageChecked, List.all_eq_true]
    at checked
  have row := checked targetId reachable
  simp only [sourceExact] at row
  simpa using row

/-- A record present under a unique source-RVA inventory is exactly the record
returned by the semantic lookup. -/
theorem lookupProgramRecord_eq_some_of_mem_sourceRva
    (unique : (records.map fun value => value.sourceRva).Nodup)
    (member : record ∈ records) :
    lookupProgramRecord records record.sourceRva = some record := by
  induction records with
  | nil => simp at member
  | cons head tail induction =>
      simp only [List.map_cons, List.nodup_cons] at unique
      rcases List.mem_cons.mp member with rfl | inTail
      · simp [lookupProgramRecord]
      · have sourceRvaNe : head.sourceRva ≠ record.sourceRva := by
          intro same
          apply unique.1
          exact List.mem_map.mpr ⟨record, inTail, same.symm⟩
        change List.find? (fun value => value.sourceRva == record.sourceRva)
          (head :: tail) = some record
        simp only [List.find?_cons]
        rw [show (head.sourceRva == record.sourceRva) = false by
          simp [sourceRvaNe]]
        exact induction unique.2 inTail

/-- Compact authority for all exact original-to-semantic-table source
associations.  Generated modules check one finite RVA-coverage inventory rather
than restating an independent lookup proof for every reachable block. -/
structure ExactOriginalSemanticSourceCoverage
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (reachability : ExactOriginalDecodedReachability context authority launch
      root)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate) where
  candidateSourceRvas : List Nat
  candidateSourceRvasExact :
    candidateAuthority.semanticRecords.map (fun record => record.sourceRva) =
      candidateSourceRvas
  checked : exactOriginalSemanticSourceCoverageChecked context
    reachability.targetIds candidateSourceRvas = true

/-- Recover the exact dependent source witness for any checked reachable target.
The selected candidate record comes from the unique PE-decoded table itself;
there is no generated record or lookup assertion to trust. -/
noncomputable def ExactOriginalSemanticSourceCoverage.source
    (coverage : ExactOriginalSemanticSourceCoverage context authority launch
      root reachability candidate candidateAuthority)
    (targetId : Nat) (reachable : targetId ∈ reachability.targetIds) :
    ExactOriginalSemanticSource context authority launch root reachability
      candidate candidateAuthority := by
  let source := Classical.choose (reachability.sourcesExist targetId reachable)
  have sourceExact : context.source? targetId = some source :=
    Classical.choose_spec (reachability.sourcesExist targetId reachable)
  have sourceRvaCovered : source.target.rva ∈ coverage.candidateSourceRvas :=
    exactOriginalSemanticSourceCoverageChecked_sourceRva_mem coverage.checked
      reachable sourceExact
  have sourceRvaPresent : source.target.rva ∈
      candidateAuthority.semanticRecords.map (fun record => record.sourceRva) := by
    rw [coverage.candidateSourceRvasExact]
    exact sourceRvaCovered
  let recordExists := List.mem_map.mp sourceRvaPresent
  let record := Classical.choose recordExists
  have recordFacts : record ∈ candidateAuthority.semanticRecords ∧
      record.sourceRva = source.target.rva := Classical.choose_spec recordExists
  exact {
    targetId
    source
    sourceExact
    reachable
    record
    recordSourceExact := recordFacts.2
    lookupExact := by
      rw [← recordFacts.2]
      exact lookupProgramRecord_eq_some_of_mem_sourceRva
        candidateAuthority.table.sourceRvasUnique recordFacts.1
  }

/-- The complete exact source inventory, derived directly from reachability.
`List.attach` carries each membership proof, so generated artifacts do not need
one proof declaration per target. -/
noncomputable def ExactOriginalSemanticSourceCoverage.sources
    (coverage : ExactOriginalSemanticSourceCoverage context authority launch
      root reachability candidate candidateAuthority) :
    List (ExactOriginalSemanticSource context authority launch root reachability
      candidate candidateAuthority) :=
  reachability.targetIds.attach.map fun target =>
    coverage.source target.1 target.2

theorem ExactOriginalSemanticSourceCoverage.sources_targetIds
    (coverage : ExactOriginalSemanticSourceCoverage context authority launch
      root reachability candidate candidateAuthority) :
    coverage.sources.map (fun source => source.targetId) =
      reachability.targetIds := by
  simp [ExactOriginalSemanticSourceCoverage.sources,
    ExactOriginalSemanticSourceCoverage.source]

#print axioms exactOriginalSemanticSourceCoverageChecked_sourceRva_mem
#print axioms lookupProgramRecord_eq_some_of_mem_sourceRva
#print axioms ExactOriginalSemanticSourceCoverage.source
#print axioms ExactOriginalSemanticSourceCoverage.sources_targetIds

/-- A candidate operation entry selected from the checked compiled-kernel
program. -/
structure ExactCandidateKernelEntry
    (program : CompiledKernelProgram) where
  operation : KernelOperation
  entryRva : Nat
  entryExact : program.functionEntry? operation.role = some entryRva

/-- Constructive evidence for every source family admitted by mixed-kernel
composition.  Executable constructors retain the exact decoded source,
checked reachability, current candidate entry, and checked kernel function
entry where applicable. -/
inductive ExactConstructiveMixedLaunchCarrier
    (candidate : ExactNativeWorldProgram)
    (launchProfile : PE32ConsoleLaunchV2)
    (candidateRootRva : Nat) :
    WorldExecution -> NativeWorldExecution -> Type where
  | canonical
      (originalState candidateState : MachineState)
      (originalWorld candidateWorld : RelationalWorld)
      (calls : List NativeCallFrame)
      (callsExact :
        candidateNativeLaunchCallFrames? candidate launchProfile
            candidateState = some calls) :
      ExactConstructiveMixedLaunchCarrier candidate launchProfile
        candidateRootRva
        (.running launchProfile.rootTargetId originalState
          launchProfile.continuationTargetIds 0 originalWorld)
        (.running candidateRootRva 0 candidateState calls 0 [] candidateWorld)

def exactConstructiveMixedLaunchCarrier?
    (candidate : ExactNativeWorldProgram)
    (launchProfile : PE32ConsoleLaunchV2)
    (candidateRootRva : Nat) :
    (originalBefore : WorldExecution) ->
    (candidateBefore : NativeWorldExecution) ->
    Option (ExactConstructiveMixedLaunchCarrier candidate launchProfile
      candidateRootRva originalBefore candidateBefore)
  | .running originalTarget originalState originalContinuations
        originalUndefined originalWorld,
      .running candidateTarget candidateUndefined candidateState calls
        candidateEventIndex candidateEvents candidateWorld =>
      if originalTargetExact :
          originalTarget = launchProfile.rootTargetId then
        if originalContinuationsExact :
            originalContinuations = launchProfile.continuationTargetIds then
          if originalUndefinedExact : originalUndefined = 0 then
            if candidateTargetExact : candidateTarget = candidateRootRva then
              if candidateUndefinedExact : candidateUndefined = 0 then
                if candidateEventIndexExact : candidateEventIndex = 0 then
                  if candidateEventsExact : candidateEvents = [] then
                    if callsExact :
                        candidateNativeLaunchCallFrames? candidate launchProfile
                            candidateState = some calls then
                      some (by
                        subst originalTarget
                        subst originalContinuations
                        subst originalUndefined
                        subst candidateTarget
                        subst candidateUndefined
                        subst candidateEventIndex
                        subst candidateEvents
                        exact .canonical originalState candidateState
                          originalWorld candidateWorld calls callsExact)
                    else none
                  else none
                else none
              else none
            else none
          else none
        else none
      else none
  | _, _ => none

theorem ExactConstructiveMixedLaunchCarrier.originalAtSource
    (carrier : ExactConstructiveMixedLaunchCarrier candidate launchProfile
      candidateRootRva originalBefore candidateBefore)
    (sourceIsRoot : sourceTargetId = launchProfile.rootTargetId) :
    originalExecutionAtTargetId sourceTargetId originalBefore := by
  cases carrier
  simpa [originalExecutionAtTargetId] using sourceIsRoot.symm

theorem ExactConstructiveMixedLaunchCarrier.candidateAtRoot
    (carrier : ExactConstructiveMixedLaunchCarrier candidate launchProfile
      candidateRootRva originalBefore candidateBefore) :
    nativeExecutionAtRva candidateRootRva candidateBefore := by
  cases carrier
  rfl

inductive ConstructiveMixedKernelSourceEvidence
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (launchProfile : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext
      launchProfile)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launchProfile originalRoot)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (program : CompiledKernelProgram)
    (candidateRootRva : Nat) :
    WorldExecution -> NativeWorldExecution -> Type where
  | launch
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority)
      (sourceIsRoot : source.targetId = launchProfile.rootTargetId)
      (originalAtSource :
        originalExecutionAtTargetId source.targetId originalBefore)
      (candidateAtRoot : nativeExecutionAtRva candidateRootRva candidateBefore)
      (carrier : ExactConstructiveMixedLaunchCarrier candidate launchProfile
        candidateRootRva originalBefore candidateBefore) :
      ConstructiveMixedKernelSourceEvidence originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority
        program candidateRootRva originalBefore candidateBefore
  | semanticTransfer
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority)
      (entry : ExactCandidateKernelEntry program)
      (originalAtSource :
        originalExecutionAtTargetId source.targetId originalBefore)
      (candidateAtEntry :
        nativeExecutionAtRva entry.entryRva candidateBefore) :
      ConstructiveMixedKernelSourceEvidence originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority
        program candidateRootRva originalBefore candidateBefore
  | externalOperation
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority)
      (entry : ExactCandidateKernelEntry program)
      (originalAtSource :
        originalExecutionAtBoundarySource source.targetId originalBefore)
      (candidateAtEntry :
        nativeExecutionAtRva entry.entryRva candidateBefore) :
      ConstructiveMixedKernelSourceEvidence originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority
        program candidateRootRva originalBefore candidateBefore
  | externalBoundary
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority)
      (owner : ExactCandidateKernelEntry program)
      (candidateRva : Nat)
      (originalAtSource :
        originalExecutionAtBoundarySource source.targetId originalBefore)
      (candidateAtSource : nativeExecutionAtRva candidateRva candidateBefore) :
      ConstructiveMixedKernelSourceEvidence originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority
        program candidateRootRva originalBefore candidateBefore
  | returned
      (originalState candidateState : MachineState)
      (originalWorld candidateWorld : RelationalWorld)
      (candidateEvents : List NativeExternalEvent) :
      ConstructiveMixedKernelSourceEvidence originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority
        program candidateRootRva
        (.returned originalState originalWorld)
        (.returned candidateState candidateEvents candidateWorld)
  | terminated
      (originalWorld candidateWorld : RelationalWorld)
      (candidateEvents : List NativeExternalEvent) :
      ConstructiveMixedKernelSourceEvidence originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority
        program candidateRootRva
        (.terminated originalWorld) (.terminated candidateEvents candidateWorld)
  | matchingFault (cause : ModeledFault) :
      ConstructiveMixedKernelSourceEvidence originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority
        program candidateRootRva (.fault cause) (.fault cause)

/-- The two machine-relation phases selected by exact classifier evidence. -/
inductive ConstructiveMixedKernelPhase where
  | launch
  | runtime
  deriving DecidableEq

/-- Phase is computed from the exact classifier witness, never submitted as a
separate proof input. -/
def ConstructiveMixedKernelSourceEvidence.phase
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore) : ConstructiveMixedKernelPhase :=
  match evidence with
  | .launch .. => .launch
  | .semanticTransfer .. | .externalOperation .. | .externalBoundary .. |
      .returned .. | .terminated .. | .matchingFault .. => .runtime

/-- The launch relation is admissible only for the unique launch classifier
arm. Every ordinary semantic, external, return, termination, and fault arm
uses the runtime relation. This prevents a weak pre-wrapper launch relation
from being propagated through ordinary execution. -/
def ConstructiveMixedKernelPhaseMachineStatesRelated
    (contract : MixedRelationContract)
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore)
    (originalWorld candidateWorld : RelationalWorld)
    (originalState candidateState : MachineState) : Prop :=
  match evidence.phase with
  | .launch =>
      MixedLaunchStatesRelated originalContext candidate contract
        originalWorld candidateWorld originalState candidateState
  | .runtime =>
      contract.runtimeStatesRelated originalWorld candidateWorld
        originalState candidateState

/-- Machine-state facts indexed by the exact classifier witness. The witness,
rather than a submitted phase flag, selects the only admissible relation. -/
structure ConstructiveMixedKernelPhaseStateFacts
    (contract : MixedRelationContract)
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore) : Prop where
  machineStatesRelated : forall originalWorld candidateWorld
      originalState candidateState,
    originalExecutionWorld? originalBefore = some originalWorld ->
    nativeExecutionWorld? candidateBefore = some candidateWorld ->
    originalExecutionMachine? originalBefore = some originalState ->
    candidateBefore.machine? = some candidateState ->
    ConstructiveMixedKernelPhaseMachineStatesRelated contract evidence
      originalWorld candidateWorld originalState candidateState

theorem ConstructiveMixedKernelPhaseStateFacts.executionMachineStatesRelated
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {launchProfile : PE32ConsoleLaunchV2}
    {originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext
      launchProfile}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launchProfile originalRoot}
    {candidate : ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {program : CompiledKernelProgram}
    {candidateRootRva : Nat}
    {contract : MixedRelationContract}
    {originalBefore : WorldExecution}
    {candidateBefore : NativeWorldExecution}
    {evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore}
    (facts : ConstructiveMixedKernelPhaseStateFacts contract evidence)
    (originalWorldExact :
      originalExecutionWorld? originalBefore = some originalWorld)
    (candidateWorldExact :
      nativeExecutionWorld? candidateBefore = some candidateWorld)
    (originalStateExact :
      originalExecutionMachine? originalBefore = some originalState)
    (candidateStateExact :
      candidateBefore.machine? = some candidateState) :
    MixedExecutionMachineStatesRelated contract originalWorld candidateWorld
      originalState candidateState := by
  have related := facts.machineStatesRelated originalWorld candidateWorld
    originalState candidateState originalWorldExact candidateWorldExact
    originalStateExact candidateStateExact
  cases phaseExact : evidence.phase with
  | launch =>
      exact Or.inl (by
        have launchRelated :
            MixedLaunchStatesRelated originalContext candidate contract
              originalWorld candidateWorld originalState candidateState := by
          simpa only [ConstructiveMixedKernelPhaseMachineStatesRelated,
            phaseExact] using related
        exact launchRelated.2.2.2)
  | runtime =>
      exact Or.inr (by
        simpa only [ConstructiveMixedKernelPhaseMachineStatesRelated,
          phaseExact] using related)

/-- Finite, proof-carrying source rules.  The external-boundary rule retains
the checked enclosing operation entry even when the current native RVA is an
internal boundary within that operation. -/
inductive ConstructiveMixedKernelSourceRule
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (launchProfile : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext
      launchProfile)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launchProfile originalRoot)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (program : CompiledKernelProgram)
    (candidateRootRva : Nat) where
  | launch
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority)
      (sourceIsRoot : source.targetId = launchProfile.rootTargetId)
  | semanticTransfer
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority)
      (entry : ExactCandidateKernelEntry program)
  | externalOperation
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority)
      (entry : ExactCandidateKernelEntry program)
  | externalBoundary
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority)
      (owner : ExactCandidateKernelEntry program)
      (candidateRva : Nat)

def ConstructiveMixedKernelSourceRule.sourceTargetId
    (rule : ConstructiveMixedKernelSourceRule originalContext originalAuthority
      launchProfile originalRoot reachability candidate candidateAuthority
      program candidateRootRva) : Nat :=
  match rule with
  | .launch source _ | .semanticTransfer source _ |
      .externalOperation source _ | .externalBoundary source .. =>
      source.targetId

/-- Conservative first-pass rule inventory for a candidate whose checked
interpreter-step operation is the synchronization point between decoded source
states.  This only classifies states; every resulting chunk still requires a
`MixedKernelOperationComponentCertificate`. -/
noncomputable def constructiveSemanticRulesWithLaunch
    (coverage : ExactOriginalSemanticSourceCoverage originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority)
    (stepEntry : ExactCandidateKernelEntry program) :
    List (ConstructiveMixedKernelSourceRule originalContext originalAuthority
      launchProfile originalRoot reachability candidate candidateAuthority
      program candidateRootRva) :=
  coverage.sources.map fun source =>
    if sourceIsRoot : source.targetId = launchProfile.rootTargetId then
      .launch source sourceIsRoot
    else
      .semanticTransfer source stepEntry

/-- Runtime source inventory used after the one-time launch prefix.  Unlike
`constructiveSemanticRulesWithLaunch`, the canonical original root is an
ordinary semantic source: the original has not advanced during the candidate
wrapper prefix, so its first recurring chunk must execute that root. -/
noncomputable def constructiveSemanticRules
    (coverage : ExactOriginalSemanticSourceCoverage originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority)
    (stepEntry : ExactCandidateKernelEntry program) :
    List (ConstructiveMixedKernelSourceRule originalContext originalAuthority
      launchProfile originalRoot reachability candidate candidateAuthority
      program candidateRootRva) :=
  coverage.sources.map fun source =>
    .semanticTransfer source stepEntry

/-- Runtime inventory for a native callback/driver boundary reached by the
one-time launch prefix.  The exact original launch source is paired with that
checked candidate boundary; every other source remains an ordinary kernel
semantic transfer.  This is useful when a native launch wrapper initializes the
runtime and then enters a callback coordinator before the first kernel
operation entry. -/
noncomputable def constructiveSemanticRulesWithRootBoundary
    (coverage : ExactOriginalSemanticSourceCoverage originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority)
    (stepEntry : ExactCandidateKernelEntry program)
    (candidateBoundaryRva : Nat) :
    List (ConstructiveMixedKernelSourceRule originalContext originalAuthority
      launchProfile originalRoot reachability candidate candidateAuthority
      program candidateRootRva) :=
  coverage.sources.map fun source =>
    if sourceIsRoot : source.targetId = launchProfile.rootTargetId then
      .externalBoundary source stepEntry candidateBoundaryRva
    else
      .semanticTransfer source stepEntry

theorem constructiveSemanticRules_targetIds
    (coverage : ExactOriginalSemanticSourceCoverage originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority)
    (stepEntry : ExactCandidateKernelEntry program) :
    (constructiveSemanticRules (candidateRootRva := candidateRootRva)
      coverage stepEntry).map
        ConstructiveMixedKernelSourceRule.sourceTargetId =
      reachability.targetIds := by
  rw [constructiveSemanticRules, List.map_map]
  simpa [Function.comp_def,
    ConstructiveMixedKernelSourceRule.sourceTargetId] using
    coverage.sources_targetIds

theorem constructiveSemanticRulesWithRootBoundary_targetIds
    (coverage : ExactOriginalSemanticSourceCoverage originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority)
    (stepEntry : ExactCandidateKernelEntry program)
    (candidateBoundaryRva : Nat) :
    (constructiveSemanticRulesWithRootBoundary
        (candidateRootRva := candidateRootRva) coverage stepEntry
        candidateBoundaryRva).map
        ConstructiveMixedKernelSourceRule.sourceTargetId =
      reachability.targetIds := by
  rw [constructiveSemanticRulesWithRootBoundary, List.map_map]
  calc
    coverage.sources.map
          (ConstructiveMixedKernelSourceRule.sourceTargetId ∘ fun source =>
            if sourceIsRoot : source.targetId = launchProfile.rootTargetId then
              ConstructiveMixedKernelSourceRule.externalBoundary source
                stepEntry candidateBoundaryRva
            else
              ConstructiveMixedKernelSourceRule.semanticTransfer source
                stepEntry) =
        coverage.sources.map (fun source => source.targetId) := by
      apply List.map_congr_left
      intro source _
      by_cases sourceIsRoot :
          source.targetId = launchProfile.rootTargetId <;>
        simp [sourceIsRoot, ConstructiveMixedKernelSourceRule.sourceTargetId]
    _ = reachability.targetIds := coverage.sources_targetIds

theorem constructiveSemanticRulesWithLaunch_targetIds
    (coverage : ExactOriginalSemanticSourceCoverage originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority)
    (stepEntry : ExactCandidateKernelEntry program) :
    (constructiveSemanticRulesWithLaunch (candidateRootRva := candidateRootRva)
      coverage stepEntry).map
        ConstructiveMixedKernelSourceRule.sourceTargetId =
      reachability.targetIds := by
  rw [constructiveSemanticRulesWithLaunch, List.map_map]
  calc
    coverage.sources.map
          (ConstructiveMixedKernelSourceRule.sourceTargetId ∘ fun source =>
            if sourceIsRoot : source.targetId = launchProfile.rootTargetId then
              ConstructiveMixedKernelSourceRule.launch source sourceIsRoot
            else ConstructiveMixedKernelSourceRule.semanticTransfer source
              stepEntry) =
        coverage.sources.map (fun source => source.targetId) := by
      apply List.map_congr_left
      intro source _
      by_cases sourceIsRoot : source.targetId = launchProfile.rootTargetId <;>
        simp [sourceIsRoot, ConstructiveMixedKernelSourceRule.sourceTargetId]
    _ = reachability.targetIds := coverage.sources_targetIds

#print axioms constructiveSemanticRulesWithLaunch_targetIds
#print axioms constructiveSemanticRules_targetIds
#print axioms constructiveSemanticRulesWithRootBoundary_targetIds

def ConstructiveMixedKernelSourceRule.evidence?
    (rule : ConstructiveMixedKernelSourceRule originalContext originalAuthority
      launchProfile originalRoot reachability candidate candidateAuthority
      program candidateRootRva)
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution) :
    Option (ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore) :=
  match rule with
  | .launch source sourceIsRoot =>
      match exactConstructiveMixedLaunchCarrier? candidate launchProfile
          candidateRootRva originalBefore candidateBefore with
      | some carrier =>
          some (.launch source sourceIsRoot
            (carrier.originalAtSource sourceIsRoot)
            carrier.candidateAtRoot carrier)
      | none => none
  | .semanticTransfer source entry =>
      if originalAtSource :
          originalExecutionAtTargetId source.targetId originalBefore then
        if candidateAtEntry :
            nativeExecutionAtRva entry.entryRva candidateBefore then
          some (.semanticTransfer source entry originalAtSource candidateAtEntry)
        else
          none
      else
        none
  | .externalOperation source entry =>
      if originalAtSource :
          originalExecutionAtBoundarySource source.targetId originalBefore then
        if candidateAtEntry :
            nativeExecutionAtRva entry.entryRva candidateBefore then
          some (.externalOperation source entry originalAtSource candidateAtEntry)
        else
          none
      else
        none
  | .externalBoundary source owner candidateRva =>
      if originalAtSource :
          originalExecutionAtBoundarySource source.targetId originalBefore then
        if candidateAtSource :
            nativeExecutionAtRva candidateRva candidateBefore then
          some (.externalBoundary source owner candidateRva originalAtSource
            candidateAtSource)
        else
          none
      else
        none

def constructiveMixedKernelActiveEvidence
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva))
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution) :
    List (ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore) :=
  rules.filterMap fun rule => rule.evidence? originalBefore candidateBefore

/-- Select an active source only when exactly one typed rule matches.  Missing
and ambiguous inventories both return `none`. -/
def uniqueConstructiveMixedKernelActiveEvidence?
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva))
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution) :
    Option (ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore) :=
  match constructiveMixedKernelActiveEvidence rules originalBefore
      candidateBefore with
  | [evidence] => some evidence
  | _ => none

/-- Deterministic classifier over the exact carrier shapes.  Matching terminal
states are structural; all active states require one unique proof-carrying
rule. -/
def constructiveMixedKernelSourceEvidence?
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva)) :
    (originalBefore : WorldExecution) ->
    (candidateBefore : NativeWorldExecution) ->
    Option (ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore)
  | .returned originalState originalWorld,
      .returned candidateState candidateEvents candidateWorld =>
      some (.returned originalState candidateState originalWorld candidateWorld
        candidateEvents)
  | .terminated originalWorld, .terminated candidateEvents candidateWorld =>
      some (.terminated originalWorld candidateWorld candidateEvents)
  | .fault originalCause, .fault candidateCause =>
      if causesMatch : originalCause = candidateCause then
        match causesMatch with
        | rfl => some (.matchingFault originalCause)
      else
        none
  | originalBefore, candidateBefore =>
      uniqueConstructiveMixedKernelActiveEvidence? rules originalBefore
        candidateBefore

def ConstructiveMixedKernelSourceEvidence.toRelatedSourceCase
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {launchProfile : PE32ConsoleLaunchV2}
    {originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext
      launchProfile}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launchProfile originalRoot}
    {candidate : ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {program : CompiledKernelProgram}
    {candidateRootRva : Nat}
    {originalBefore : WorldExecution}
    {candidateBefore : NativeWorldExecution}
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore) :
    MixedKernelRelatedSourceCase originalContext originalAuthority launchProfile
      originalRoot reachability candidate candidateAuthority program
      candidateRootRva originalBefore candidateBefore :=
  match evidence with
  | .launch source sourceIsRoot originalAtSource candidateAtRoot _ =>
      .launchDispatch source sourceIsRoot originalAtSource candidateAtRoot
  | .semanticTransfer source entry originalAtSource candidateAtEntry =>
      .semanticTransfer source entry.operation entry.entryRva
        originalAtSource candidateAtEntry entry.entryExact
  | .externalOperation source entry originalAtSource candidateAtEntry =>
      .externalOperation source entry.operation entry.entryRva
        originalAtSource candidateAtEntry entry.entryExact
  | .externalBoundary source _ candidateRva originalAtSource
      candidateAtSource =>
      .externalBoundary source candidateRva originalAtSource candidateAtSource
  | .returned originalState candidateState originalWorld candidateWorld
      candidateEvents =>
      .returned originalState candidateState originalWorld candidateWorld
        candidateEvents
  | .terminated originalWorld candidateWorld candidateEvents =>
      .terminated originalWorld candidateWorld candidateEvents
  | .matchingFault cause => .fault cause

/-- The authoritative invariant generated from finite source rules.  A state
pair is admitted only when all relational facts hold and the deterministic
classifier produces one typed witness. -/
def constructiveMixedKernelInvariant
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (launchProfile : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext
      launchProfile)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launchProfile originalRoot)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (program : CompiledKernelProgram)
    (candidateRootRva : Nat)
    (contract : MixedRelationContract)
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva)) :
    MixedExecutionInvariant reachability.targetIds contract where
  holds originalBefore candidateBefore :=
    exists evidence,
      ConstructiveMixedKernelStateFacts reachability.targetIds contract
          originalBefore candidateBefore /\
        ConstructiveMixedKernelPhaseStateFacts contract evidence /\
        constructiveMixedKernelSourceEvidence? rules originalBefore
          candidateBefore = some evidence
  originalReachable := by
    intro originalBefore candidateBefore admitted
    exact (Classical.choose_spec admitted).1.originalReachable
  candidateProofOpen := by
    intro originalBefore candidateBefore admitted
    exact (Classical.choose_spec admitted).1.candidateProofOpen
  worldsRelated := by
    intro originalBefore candidateBefore originalWorld candidateWorld
      admitted originalWorldExact candidateWorldExact
    exact (Classical.choose_spec admitted).1.worldsRelated
      originalWorld candidateWorld
      originalWorldExact candidateWorldExact
  machineStatesRelated := by
    intro originalBefore candidateBefore originalWorld candidateWorld
      originalState candidateState admitted originalWorldExact
      candidateWorldExact originalStateExact candidateStateExact
    exact (Classical.choose_spec admitted).2.1.executionMachineStatesRelated
      originalWorldExact candidateWorldExact originalStateExact
      candidateStateExact

/-- Runtime-only counterpart of `constructiveMixedKernelInvariant`.  The exact
classifier witness remains part of the relation, but its phase must be
`.runtime`; the unique launch witness is consumed by the separate finite launch
prefix and can never enter recurring chunk composition. -/
def constructiveMixedKernelRuntimeInvariant
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (launchProfile : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext
      launchProfile)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launchProfile originalRoot)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (program : CompiledKernelProgram)
    (candidateRootRva : Nat)
    (contract : MixedRelationContract)
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva)) :
    MixedExecutionInvariant reachability.targetIds contract where
  holds originalBefore candidateBefore :=
    exists evidence,
      ConstructiveMixedKernelStateFacts reachability.targetIds contract
          originalBefore candidateBefore /\
        ConstructiveMixedKernelPhaseStateFacts contract evidence /\
        constructiveMixedKernelSourceEvidence? rules originalBefore
            candidateBefore = some evidence /\
        evidence.phase = .runtime
  originalReachable := by
    intro originalBefore candidateBefore admitted
    exact (Classical.choose_spec admitted).1.originalReachable
  candidateProofOpen := by
    intro originalBefore candidateBefore admitted
    exact (Classical.choose_spec admitted).1.candidateProofOpen
  worldsRelated := by
    intro originalBefore candidateBefore originalWorld candidateWorld
      admitted originalWorldExact candidateWorldExact
    exact (Classical.choose_spec admitted).1.worldsRelated
      originalWorld candidateWorld originalWorldExact candidateWorldExact
  machineStatesRelated := by
    intro originalBefore candidateBefore originalWorld candidateWorld
      originalState candidateState admitted originalWorldExact
      candidateWorldExact originalStateExact candidateStateExact
    exact (Classical.choose_spec admitted).2.1.executionMachineStatesRelated
      originalWorldExact candidateWorldExact originalStateExact
      candidateStateExact

theorem constructiveMixedKernelInvariant_holds
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {launchProfile : PE32ConsoleLaunchV2}
    {originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext
      launchProfile}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launchProfile originalRoot}
    {candidate : ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {program : CompiledKernelProgram}
    {candidateRootRva : Nat}
    {contract : MixedRelationContract}
    {rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva)}
    {originalBefore : WorldExecution}
    {candidateBefore : NativeWorldExecution}
    {evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore}
    (facts : ConstructiveMixedKernelStateFacts reachability.targetIds contract
      originalBefore candidateBefore)
    (phaseFacts : ConstructiveMixedKernelPhaseStateFacts contract evidence)
    (classified : constructiveMixedKernelSourceEvidence? rules originalBefore
      candidateBefore = some evidence) :
    (constructiveMixedKernelInvariant originalContext originalAuthority
      launchProfile originalRoot reachability candidate candidateAuthority
      program candidateRootRva contract rules).holds
      originalBefore candidateBefore := by
  exact ⟨evidence, facts, phaseFacts, classified⟩

theorem constructiveMixedKernelRuntimeInvariant_holds
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {launchProfile : PE32ConsoleLaunchV2}
    {originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext
      launchProfile}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launchProfile originalRoot}
    {candidate : ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {program : CompiledKernelProgram}
    {candidateRootRva : Nat}
    {contract : MixedRelationContract}
    {rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva)}
    {originalBefore : WorldExecution}
    {candidateBefore : NativeWorldExecution}
    {evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore}
    (facts : ConstructiveMixedKernelStateFacts reachability.targetIds contract
      originalBefore candidateBefore)
    (phaseFacts : ConstructiveMixedKernelPhaseStateFacts contract evidence)
    (classified : constructiveMixedKernelSourceEvidence? rules originalBefore
      candidateBefore = some evidence)
    (runtime : evidence.phase = .runtime) :
    (constructiveMixedKernelRuntimeInvariant originalContext originalAuthority
      launchProfile originalRoot reachability candidate candidateAuthority
      program candidateRootRva contract rules).holds
      originalBefore candidateBefore :=
  ⟨evidence, facts, phaseFacts, classified, runtime⟩

theorem ConstructiveMixedKernelSourceEvidence.toRelatedSourceCase_runtimeOnly
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore)
    (runtime : evidence.phase = .runtime) :
    evidence.toRelatedSourceCase.RuntimeOnly := by
  cases evidence <;>
    simp_all [ConstructiveMixedKernelSourceEvidence.phase,
      ConstructiveMixedKernelSourceEvidence.toRelatedSourceCase,
      MixedKernelRelatedSourceCase.RuntimeOnly]

/-- The total classifier is obtained by evaluating the same finite rule
inventory used by the invariant. -/
noncomputable def constructiveMixedKernelSourceClassifier
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (launchProfile : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext
      launchProfile)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launchProfile originalRoot)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (program : CompiledKernelProgram)
    (candidateRootRva : Nat)
    (contract : MixedRelationContract)
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva)) :
    MixedKernelSourceClassifier originalContext originalAuthority launchProfile
      originalRoot reachability candidate candidateAuthority program
      candidateRootRva
      (constructiveMixedKernelInvariant originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority
        program candidateRootRva contract rules) where
  classify := by
    intro originalBefore candidateBefore admitted
    exact (Classical.choose admitted).toRelatedSourceCase

noncomputable def constructiveMixedKernelRuntimeSourceClassifier
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (launchProfile : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext
      launchProfile)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launchProfile originalRoot)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (program : CompiledKernelProgram)
    (candidateRootRva : Nat)
    (contract : MixedRelationContract)
    (rules : List (ConstructiveMixedKernelSourceRule originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva)) :
    MixedKernelRuntimeSourceClassifier originalContext originalAuthority
      launchProfile originalRoot reachability candidate candidateAuthority
      program candidateRootRva
      (constructiveMixedKernelRuntimeInvariant originalContext originalAuthority
        launchProfile originalRoot reachability candidate candidateAuthority
        program candidateRootRva contract rules) where
  classifier := {
    classify := by
      intro originalBefore candidateBefore admitted
      exact (Classical.choose admitted).toRelatedSourceCase
  }
  runtimeOnly := by
    intro originalBefore candidateBefore admitted
    exact (Classical.choose admitted).toRelatedSourceCase_runtimeOnly
      (Classical.choose_spec admitted).2.2.2

#print axioms ConstructiveMixedKernelPhaseStateFacts.executionMachineStatesRelated
#print axioms constructiveMixedKernelInvariant_holds
#print axioms constructiveMixedKernelRuntimeInvariant_holds
#print axioms constructiveMixedKernelRuntimeSourceClassifier

end StageA.Relational.InterpreterMixedConstructiveSourceClassifier
