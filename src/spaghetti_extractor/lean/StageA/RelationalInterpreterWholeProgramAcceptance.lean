import StageA.RelationalCertificates
import StageA.RelationalInterpreterMixedContext
import StageA.RelationalInterpreterNativeLaunch
import StageA.RelationalInterpreterNativeWorld

namespace StageA.Relational.InterpreterWholeProgramAcceptance

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact-native whole-program acceptance

`pe32ProgramsEquivalent` checks two decoded PE programs over `WorldExecution`.
The round-trip candidate executes the exact candidate bytes one instruction at
a time over `NativeWorldExecution`.  These carriers are intentionally not
identified: decoded execution stores target identifiers, while native
execution stores RVAs, explicit return frames, and the native event history.

This module connects them with a local macro-step adapter.  For every related
decoded/native candidate state, the adapter must show that the next exact
decoded PE transition is implemented by a nonempty path of exact native
instruction transitions, with exactly the same observations.  This is a
one-step semantic obligation, not a submitted whole-program equivalence claim.

The final theorem first invokes `pe32ProgramsEquivalent`; it then composes its
checked decoded-candidate step with the exact-native macro-step witness.  A
proof-blocked native transition cannot be hidden because all observations are
retained and the adapter requires exact observation-list equality.
-/

def decodedOriginalProgram (context : StaticProofContext)
    (regions : List RegionRelation)
    (externalCallSites : List ExternalCallSiteContract)
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment) :
    DecodedWorldProgram := {
  candidate := false
  context
  regions
  externalCallSites
  environment
  protocolEnvironment
}

def decodedCandidateProgram (context : StaticProofContext)
    (regions : List RegionRelation)
    (externalCallSites : List ExternalCallSiteContract)
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment) :
    DecodedWorldProgram := {
  candidate := true
  context
  regions
  externalCallSites
  environment
  protocolEnvironment
}

/-- Local, exact operational adapter from one decoded candidate PE macro-step
to a nonempty path of exact native instruction steps.  Static provenance,
launch provenance, and the initial carrier relation are all explicit fields.
-/
structure ExactDecodedNativeMacroStepAdapter
    (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (launch : PE32ConsoleLaunchV2)
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram) where
  decodedRole : decoded.candidate = true
  decodedContext : decoded.context = context
  candidatePeBound : decoded.context.candidatePe = native.pe
  candidateImportsBound : decoded.context.candidateImports = native.imports
  nativeAuthority : ExactNativeCandidateAuthority native
  candidateRootRva : Nat
  candidateRoot : DirectExactCandidateNativeLaunchRoot native launch
    candidateRootRva
  candidateLaunchCalls : MachineState -> List NativeCallFrame
  candidateLaunchCallsExact : forall candidateState,
    candidateNativeLaunchCallFrames? native launch candidateState =
      some (candidateLaunchCalls candidateState)
  relation : WorldExecution -> NativeWorldExecution -> Prop
  rootsRelated : forall world originalState candidateState,
    launch.StatesRelated context graph reachability world originalState
        candidateState ->
      relation
        (.running launch.rootTargetId candidateState
          launch.continuationTargetIds 0 world)
        (.running candidateRootRva 0 candidateState
          (candidateLaunchCalls candidateState) 0 [] world)
  stepRefines : forall decodedBefore nativeBefore,
    relation decodedBefore nativeBefore ->
      let decodedStep := decoded.pe32TransitionSystem.step decodedBefore
      exists nativeObservations nativeAfter,
        NonemptyRelatedPath native.transitionSystem nativeBefore
          nativeObservations nativeAfter /\
        nativeObservations = decodedStep.observation.toList /\
        relation decodedStep.next nativeAfter

/-- Exact finite-chunk adapter for candidates whose decoded external protocol
or callback carrier takes several transitions per native instruction path.
Both sides consume at least one transition, and the retained observation lists
must be equal, not merely related through an address correspondence intended
for two different binaries.
-/
structure ExactDecodedNativeChunkAdapter
    (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (launch : PE32ConsoleLaunchV2)
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram) where
  decodedRole : decoded.candidate = true
  decodedContext : decoded.context = context
  candidatePeBound : decoded.context.candidatePe = native.pe
  candidateImportsBound : decoded.context.candidateImports = native.imports
  nativeAuthority : ExactNativeCandidateAuthority native
  candidateRootRva : Nat
  candidateRoot : DirectExactCandidateNativeLaunchRoot native launch
    candidateRootRva
  candidateLaunchCalls : MachineState -> List NativeCallFrame
  candidateLaunchCallsExact : forall candidateState,
    candidateNativeLaunchCallFrames? native launch candidateState =
      some (candidateLaunchCalls candidateState)
  relation : WorldExecution -> NativeWorldExecution -> Prop
  rootsRelated : forall world originalState candidateState,
    launch.StatesRelated context graph reachability world originalState
        candidateState ->
      relation
        (.running launch.rootTargetId candidateState
          launch.continuationTargetIds 0 world)
        (.running candidateRootRva 0 candidateState
          (candidateLaunchCalls candidateState) 0 [] world)
  chunksRefineExact : forall decodedBefore nativeBefore,
    relation decodedBefore nativeBefore ->
      exists decodedObservations nativeObservations decodedAfter nativeAfter,
        NonemptyRelatedPath decoded.pe32TransitionSystem decodedBefore
          decodedObservations decodedAfter /\
        NonemptyRelatedPath native.transitionSystem nativeBefore
          nativeObservations nativeAfter /\
        decodedObservations = nativeObservations /\
        relation decodedAfter nativeAfter

def ExactDecodedNativeMacroStepAdapter.toChunkAdapter
    (adapter : ExactDecodedNativeMacroStepAdapter context graph reachability
      launch decoded native) :
    ExactDecodedNativeChunkAdapter context graph reachability launch decoded
      native := {
  decodedRole := adapter.decodedRole
  decodedContext := adapter.decodedContext
  candidatePeBound := adapter.candidatePeBound
  candidateImportsBound := adapter.candidateImportsBound
  nativeAuthority := adapter.nativeAuthority
  candidateRootRva := adapter.candidateRootRva
  candidateRoot := adapter.candidateRoot
  candidateLaunchCalls := adapter.candidateLaunchCalls
  candidateLaunchCallsExact := adapter.candidateLaunchCallsExact
  relation := adapter.relation
  rootsRelated := adapter.rootsRelated
  chunksRefineExact := by
    intro decodedBefore nativeBefore related
    rcases adapter.stepRefines decodedBefore nativeBefore related with
      ⟨nativeObservations, nativeAfter, nativePath,
        nativeObservationsExact, afterRelated⟩
    let decodedStep := decoded.pe32TransitionSystem.step decodedBefore
    exact ⟨decodedStep.observation.toList, nativeObservations,
      decodedStep.next, nativeAfter,
      nonemptyRelatedPath_one decoded.pe32TransitionSystem decodedBefore,
      nativePath, nativeObservationsExact.symm, afterRelated⟩
}

/-- The existing decoded whole-program certificate plus the exact-native local
finite-chunk adapter.  Neither field is an assumed final equivalence proposition.
-/
structure ExactNativeWholeProgramAcceptanceBridge
    (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (regions : List RegionRelation)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (externalCallSites : List ExternalCallSiteContract)
    (launch : PE32ConsoleLaunchV2)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (originalProtocolEnvironment candidateProtocolEnvironment :
      WorldExternalProtocolEnvironment)
    (native : ExactNativeWorldProgram) where
  decodedCertificate : WholeProgramCertificate context graph regions invariants
    reachability control callbackTargets externalCallSites launch
    originalEnvironment candidateEnvironment originalProtocolEnvironment
    candidateProtocolEnvironment
  nativeAdapter : ExactDecodedNativeChunkAdapter context graph reachability
    launch
    (decodedCandidateProgram context regions externalCallSites
      candidateEnvironment candidateProtocolEnvironment)
    native

/-- Heterogeneous whole-program result.  The original executes exact decoded
PE regions and the candidate executes exact native PE instructions.  The
launch root and native call frames are themselves checked against the exact
candidate PE.
-/
def PE32ProgramsExactNativeChunkObservationallyEquivalent
    (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (regions : List RegionRelation)
    (reachability : RelationalProductReachabilityEvidence)
    (externalCallSites : List ExternalCallSiteContract)
    (launch : PE32ConsoleLaunchV2)
    (originalEnvironment : WorldExternalEnvironment)
    (originalProtocolEnvironment : WorldExternalProtocolEnvironment)
    (native : ExactNativeWorldProgram) : Prop :=
  let original := decodedOriginalProgram context regions externalCallSites
    originalEnvironment originalProtocolEnvironment
  launch.Realizable context graph reachability /\
    exists _nativeAuthority : ExactNativeCandidateAuthority native,
      exists candidateRootRva : Nat,
        DirectExactCandidateNativeLaunchRoot native launch candidateRootRva /\
          exists candidateLaunchCalls : MachineState -> List NativeCallFrame,
            (forall candidateState,
              candidateNativeLaunchCallFrames? native launch candidateState =
                some (candidateLaunchCalls candidateState)) /\
            exists executionRelation :
                WorldExecution -> NativeWorldExecution -> Prop,
              (forall world originalState candidateState,
                launch.StatesRelated context graph reachability world
                    originalState candidateState ->
                  executionRelation
                    (.running launch.rootTargetId originalState
                      launch.continuationTargetIds 0 world)
                    (.running candidateRootRva 0 candidateState
                      (candidateLaunchCalls candidateState) 0 [] world)) /\
              ChunkedRelationalBisimulation original.pe32TransitionSystem
                native.transitionSystem executionRelation
                (worldRelationalObservationsRelated context)

theorem relatedObservationLists_of_option
    {originalObservation candidateObservation : Type}
    (relation :
      Option originalObservation -> Option candidateObservation -> Prop)
    (sameShape : forall original candidate,
      relation original candidate -> original.isSome = candidate.isSome)
    {original : Option originalObservation}
    {candidate : Option candidateObservation}
    (related : relation original candidate) :
    RelatedObservationLists relation original.toList candidate.toList := by
  cases original with
  | none =>
      cases candidate with
      | none => simp [RelatedObservationLists]
      | some candidate =>
          have impossible := sameShape none (some candidate) related
          simp at impossible
  | some original =>
      cases candidate with
      | none =>
          have impossible := sameShape (some original) none related
          simp at impossible
      | some candidate =>
          exact ⟨related, trivial⟩

theorem relatedObservationLists_append
    {originalObservation candidateObservation : Type}
    (relation :
      Option originalObservation -> Option candidateObservation -> Prop)
    {originalLeft originalRight : List originalObservation}
    {candidateLeft candidateRight : List candidateObservation}
    (left : RelatedObservationLists relation originalLeft candidateLeft)
    (right : RelatedObservationLists relation originalRight candidateRight) :
    RelatedObservationLists relation
      (originalLeft ++ originalRight) (candidateLeft ++ candidateRight) := by
  induction originalLeft generalizing candidateLeft with
  | nil =>
      cases candidateLeft <;> simp_all [RelatedObservationLists]
  | cons original originalTail induction =>
      cases candidateLeft with
      | nil => simp [RelatedObservationLists] at left
      | cons candidate candidateTail =>
          rcases left with ⟨head, tail⟩
          exact ⟨head, induction tail⟩

theorem lockstep_runRelatedSteps
    {originalState candidateState originalObservation candidateObservation : Type}
    (original : RelatedTransitionSystem originalState originalObservation)
    (candidate : RelatedTransitionSystem candidateState candidateObservation)
    (stateRelation : originalState -> candidateState -> Prop)
    (observationRelation :
      Option originalObservation -> Option candidateObservation -> Prop)
    (sameShape : forall originalObservation candidateObservation,
      observationRelation originalObservation candidateObservation ->
        originalObservation.isSome = candidateObservation.isSome)
    (lockstep : RelationalWeakBisimulation original candidate stateRelation
      observationRelation) :
    forall fuel originalBefore candidateBefore,
      stateRelation originalBefore candidateBefore ->
        RelatedObservationLists observationRelation
          (runRelatedSteps original fuel originalBefore).2
          (runRelatedSteps candidate fuel candidateBefore).2 /\
        stateRelation
          (runRelatedSteps original fuel originalBefore).1
          (runRelatedSteps candidate fuel candidateBefore).1 := by
  intro fuel
  induction fuel with
  | zero =>
      intro originalBefore candidateBefore related
      exact ⟨trivial, related⟩
  | succ fuel induction =>
      intro originalBefore candidateBefore related
      have step := lockstep originalBefore candidateBefore related
      have head := relatedObservationLists_of_option observationRelation
        sameShape step.1
      have tail := induction
        (original.step originalBefore).next
        (candidate.step candidateBefore).next step.2
      constructor
      · simpa only [runRelatedSteps] using
          relatedObservationLists_append observationRelation head tail.1
      · simpa only [runRelatedSteps] using tail.2

theorem lockstep_refines_nonempty_candidate_path
    {originalState candidateState originalObservation candidateObservation : Type}
    (original : RelatedTransitionSystem originalState originalObservation)
    (candidate : RelatedTransitionSystem candidateState candidateObservation)
    (stateRelation : originalState -> candidateState -> Prop)
    (observationRelation :
      Option originalObservation -> Option candidateObservation -> Prop)
    (sameShape : forall originalObservation candidateObservation,
      observationRelation originalObservation candidateObservation ->
        originalObservation.isSome = candidateObservation.isSome)
    (lockstep : RelationalWeakBisimulation original candidate stateRelation
      observationRelation)
    (originalBefore : originalState) (candidateBefore candidateAfter : candidateState)
    (candidateObservations : List candidateObservation)
    (beforeRelated : stateRelation originalBefore candidateBefore)
    (candidatePath : NonemptyRelatedPath candidate candidateBefore
      candidateObservations candidateAfter) :
    exists originalObservations originalAfter,
      NonemptyRelatedPath original originalBefore originalObservations originalAfter /\
      RelatedObservationLists observationRelation originalObservations
        candidateObservations /\
      stateRelation originalAfter candidateAfter := by
  rcases candidatePath with ⟨fuel, positive, candidateRun⟩
  have replay := lockstep_runRelatedSteps original candidate stateRelation
    observationRelation sameShape lockstep fuel originalBefore candidateBefore
    beforeRelated
  cases originalRun :
      runRelatedSteps original fuel originalBefore with
  | mk originalAfter originalObservations =>
      rw [originalRun, candidateRun] at replay
      exact ⟨originalObservations, originalAfter,
        ⟨fuel, positive, originalRun⟩, replay.1, replay.2⟩

/-- The acceptance bridge invokes the sole decoded whole-program theorem and
then replays its lockstep proof across each exact candidate/native finite
chunk.  The two remaining proof families are visible in the bridge type:
`WholeProgramCertificate` and `ExactDecodedNativeChunkAdapter`.
-/
theorem pe32ProgramsEquivalent_exactNative
    (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (regions : List RegionRelation)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (externalCallSites : List ExternalCallSiteContract)
    (launch : PE32ConsoleLaunchV2)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (originalProtocolEnvironment candidateProtocolEnvironment :
      WorldExternalProtocolEnvironment)
    (native : ExactNativeWorldProgram)
    (bridge : ExactNativeWholeProgramAcceptanceBridge context graph regions
      invariants reachability control callbackTargets externalCallSites launch
      originalEnvironment candidateEnvironment originalProtocolEnvironment
      candidateProtocolEnvironment native) :
    PE32ProgramsExactNativeChunkObservationallyEquivalent context graph regions
      reachability externalCallSites launch
      originalEnvironment originalProtocolEnvironment native := by
  let original := decodedOriginalProgram context regions externalCallSites
    originalEnvironment originalProtocolEnvironment
  let decodedCandidate := decodedCandidateProgram context regions
    externalCallSites candidateEnvironment candidateProtocolEnvironment
  have decodedEquivalent :
      PE32ProgramsObservationallyEquivalent context graph invariants reachability
        control launch original decodedCandidate :=
    pe32ProgramsEquivalent context graph regions invariants reachability control
      callbackTargets externalCallSites launch originalEnvironment
      candidateEnvironment originalProtocolEnvironment
      candidateProtocolEnvironment bridge.decodedCertificate
  rcases decodedEquivalent with
    ⟨launchRealizable, decodedRelation, decodedRootsRelated,
      decodedStepRefines⟩
  let combinedRelation : WorldExecution -> NativeWorldExecution -> Prop :=
    fun originalExecution nativeExecution =>
      exists decodedExecution,
        decodedRelation originalExecution decodedExecution /\
          bridge.nativeAdapter.relation decodedExecution nativeExecution
  refine ⟨launchRealizable, bridge.nativeAdapter.nativeAuthority,
    bridge.nativeAdapter.candidateRootRva,
    bridge.nativeAdapter.candidateRoot,
    bridge.nativeAdapter.candidateLaunchCalls,
    bridge.nativeAdapter.candidateLaunchCallsExact,
    combinedRelation, ?_, ?_⟩
  · intro world originalState candidateState initial
    refine ⟨.running launch.rootTargetId candidateState
      launch.continuationTargetIds 0 world,
      decodedRootsRelated world originalState candidateState initial, ?_⟩
    exact bridge.nativeAdapter.rootsRelated world originalState candidateState
      initial
  · intro originalBefore nativeBefore related
    rcases related with
      ⟨decodedBefore, originalDecodedRelated, decodedNativeRelated⟩
    have decodedStep := decodedStepRefines originalBefore decodedBefore
      originalDecodedRelated
    rcases bridge.nativeAdapter.chunksRefineExact decodedBefore nativeBefore
        decodedNativeRelated with
      ⟨decodedObservations, nativeObservations, decodedAfter, nativeAfter,
        decodedPath, nativePath, observationsExact,
        decodedNativeAfterRelated⟩
    rcases lockstep_refines_nonempty_candidate_path
        original.pe32TransitionSystem decodedCandidate.pe32TransitionSystem
        decodedRelation (worldRelationalObservationsRelated context)
        (worldRelationalObservationsRelated_sameShape context)
        decodedStepRefines originalBefore decodedBefore decodedAfter
        decodedObservations originalDecodedRelated decodedPath with
      ⟨originalObservations, originalAfter, originalPath,
        observationsRelated, originalDecodedAfterRelated⟩
    refine ⟨originalObservations, nativeObservations,
      originalAfter, nativeAfter, originalPath, nativePath, ?_, ?_⟩
    · simpa [observationsExact] using observationsRelated
    · exact ⟨decodedAfter, originalDecodedAfterRelated,
        decodedNativeAfterRelated⟩

#print axioms relatedObservationLists_of_option
#print axioms relatedObservationLists_append
#print axioms lockstep_runRelatedSteps
#print axioms lockstep_refines_nonempty_candidate_path
#print axioms pe32ProgramsEquivalent_exactNative

end StageA.Relational.InterpreterWholeProgramAcceptance
