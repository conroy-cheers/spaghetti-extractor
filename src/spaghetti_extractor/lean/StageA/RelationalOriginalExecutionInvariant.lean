import StageA.RelationalInterpreterMixedWorldBridge

namespace StageA.Relational.OriginalExecutionInvariant

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

/-!
# Original execution invariants

Whole-program mixed composition may need facts which concern only the decoded
original execution, such as code-pointer provenance.  Those facts must not be
added to `MixedExecutionInvariant.holds` as unsupported assertions.

`OriginalWorldExecutionInvariant` requires preservation by the exact PE32
transition function.  `MixedWorldChunkComposition.withOriginalInvariant`
conjoins such an invariant with an existing mixed invariant and transports it
through every concrete original path in the composition.  This provides the
non-circular bridge from launch facts and decoded execution to indirect-control
and mutable-memory authority.
-/

structure OriginalWorldExecutionInvariant
    (program : DecodedWorldProgram) where
  holds : WorldExecution -> Prop
  stepClosed : forall before,
    holds before ->
      holds (program.pe32TransitionSystem.step before).next

def OriginalWorldExecutionInvariant.and
    {program : DecodedWorldProgram}
    (left right : OriginalWorldExecutionInvariant program) :
    OriginalWorldExecutionInvariant program where
  holds execution := left.holds execution /\ right.holds execution
  stepClosed before holds :=
    ⟨left.stepClosed before holds.1, right.stepClosed before holds.2⟩

def OriginalWorldExecutionInvariant.all
    {program : DecodedWorldProgram}
    (invariants : List (OriginalWorldExecutionInvariant program)) :
    OriginalWorldExecutionInvariant program where
  holds execution :=
    forall invariant, invariant ∈ invariants -> invariant.holds execution
  stepClosed before holds invariant member :=
    invariant.stepClosed before (holds invariant member)

theorem OriginalWorldExecutionInvariant.all_member
    {program : DecodedWorldProgram}
    {invariants : List (OriginalWorldExecutionInvariant program)}
    {execution : WorldExecution}
    (combined :
      (OriginalWorldExecutionInvariant.all invariants).holds execution)
    (invariant : OriginalWorldExecutionInvariant program)
    (member : invariant ∈ invariants) :
    invariant.holds execution :=
  combined invariant member

theorem OriginalWorldExecutionInvariant.runRelatedSteps
    {program : DecodedWorldProgram}
    (invariant : OriginalWorldExecutionInvariant program)
    (fuel : Nat) (before : WorldExecution)
    (beforeHolds : invariant.holds before) :
    invariant.holds
      (StageA.Relational.runRelatedSteps program.pe32TransitionSystem
        fuel before).1 := by
  induction fuel generalizing before with
  | zero =>
      simpa [StageA.Relational.runRelatedSteps] using beforeHolds
  | succ fuel induction =>
      simp only [StageA.Relational.runRelatedSteps]
      exact induction
        (program.pe32TransitionSystem.step before).next
        (invariant.stepClosed before beforeHolds)

theorem OriginalWorldExecutionInvariant.pathClosed
    {program : DecodedWorldProgram}
    (invariant : OriginalWorldExecutionInvariant program)
    {before after : WorldExecution}
    {observations : List WorldRelationalObservable}
    (beforeHolds : invariant.holds before)
    (path : NonemptyRelatedPath program.pe32TransitionSystem
      before observations after) :
    invariant.holds after := by
  rcases path with ⟨fuel, _positive, exactRun⟩
  have holds := invariant.runRelatedSteps fuel before beforeHolds
  rw [exactRun] at holds
  exact holds

def strengthenMixedExecutionInvariant
    {program : DecodedWorldProgram}
    (mixed : MixedExecutionInvariant reachabilityTargetIds contract)
    (original : OriginalWorldExecutionInvariant program) :
    MixedExecutionInvariant reachabilityTargetIds contract where
  holds originalExecution candidateExecution :=
    mixed.holds originalExecution candidateExecution /\
      original.holds originalExecution
  originalReachable originalExecution candidateExecution related :=
    mixed.originalReachable originalExecution candidateExecution related.1
  candidateProofOpen originalExecution candidateExecution related :=
    mixed.candidateProofOpen originalExecution candidateExecution related.1
  worldsRelated originalExecution candidateExecution originalWorld candidateWorld
      related originalWorldExact candidateWorldExact :=
    mixed.worldsRelated originalExecution candidateExecution originalWorld
      candidateWorld related.1 originalWorldExact candidateWorldExact
  machineStatesRelated originalExecution candidateExecution originalWorld
      candidateWorld originalState candidateState related originalWorldExact
      candidateWorldExact originalStateExact candidateStateExact :=
    mixed.machineStatesRelated originalExecution candidateExecution originalWorld
      candidateWorld originalState candidateState related.1 originalWorldExact
      candidateWorldExact originalStateExact candidateStateExact

theorem strengthenMixedExecutionInvariant_original
    {program : DecodedWorldProgram}
    {mixed : MixedExecutionInvariant reachabilityTargetIds contract}
    {original : OriginalWorldExecutionInvariant program}
    {originalExecution : WorldExecution}
    {candidateExecution : NativeWorldExecution}
    (related :
      (strengthenMixedExecutionInvariant mixed original).holds
        originalExecution candidateExecution) :
    original.holds originalExecution :=
  related.2

/-- Strengthen an already checked mixed composition with an independently
proved invariant over the exact original transition system.  The original
path in each chunk, rather than a generated status field, establishes the
successor fact. -/
def strengthenMixedWorldChunkComposition
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {original : DecodedWorldProgram}
    {candidate : ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {programBinding : ExactMixedProgramBinding originalContext original}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    {originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext launch}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot}
    {candidateRootRva : Nat}
    {candidateRoot : DirectExactCandidateNativeLaunchRoot candidate launch
      candidateRootRva}
    (composition : MixedWorldChunkComposition originalContext originalAuthority
      original candidate candidateAuthority programBinding contract launch
      originalRoot reachability candidateRootRva candidateRoot)
    (originalInvariant : OriginalWorldExecutionInvariant original) :
    MixedWorldChunkComposition originalContext originalAuthority
      original candidate candidateAuthority programBinding contract launch
      originalRoot reachability candidateRootRva candidateRoot where
  invariant :=
    strengthenMixedExecutionInvariant composition.invariant originalInvariant
  component originalBefore candidateBefore related := by
    let prior := composition.component originalBefore candidateBefore related.1
    exact {
      beforeRelated := related
      originalObservations := prior.originalObservations
      candidateObservations := prior.candidateObservations
      originalAfter := prior.originalAfter
      candidateAfter := prior.candidateAfter
      originalPath := prior.originalPath
      candidatePath := prior.candidatePath
      observationsRelated := prior.observationsRelated
      afterRelated := ⟨prior.afterRelated,
        originalInvariant.pathClosed related.2 prior.originalPath⟩
    }

/-- Transport a one-time launch prefix across an independently proved original
invariant.  The original side is the exact zero-step root retained by the
prefix, so only the root fact is required here. -/
def strengthenMixedWorldLaunchPrefixCertificate
    {reachabilityTargetIds : List Nat}
    {contract : MixedRelationContract}
    {base : MixedExecutionInvariant reachabilityTargetIds contract}
    (certificate : MixedWorldLaunchPrefixCertificate originalContext original
      candidate contract launch candidateRootRva base)
    (originalInvariant : OriginalWorldExecutionInvariant original)
    (rootHolds : forall originalWorld candidateWorld originalState candidateState,
      MixedLaunchStatesRelated originalContext candidate contract
          originalWorld candidateWorld originalState candidateState ->
        originalInvariant.holds
          (.running launch.rootTargetId originalState
            launch.continuationTargetIds 0 originalWorld)) :
    MixedWorldLaunchPrefixCertificate originalContext original candidate contract
      launch candidateRootRva
      (strengthenMixedExecutionInvariant base originalInvariant) where
  candidateLaunchCalls := certificate.candidateLaunchCalls
  candidateLaunchCallsExact := certificate.candidateLaunchCallsExact
  launchPaths := by
    intro originalWorld candidateWorld originalState candidateState launchRelated
    let prior := certificate.launchPaths originalWorld candidateWorld originalState
      candidateState launchRelated
    exact {
      candidateAfter := prior.candidateAfter
      originalIdentity := prior.originalIdentity
      candidatePath := prior.candidatePath
      afterRelated := ⟨prior.afterRelated,
        rootHolds originalWorld candidateWorld originalState candidateState
          launchRelated⟩
    }

#print axioms OriginalWorldExecutionInvariant.pathClosed
#print axioms OriginalWorldExecutionInvariant.all_member
#print axioms strengthenMixedWorldChunkComposition
#print axioms strengthenMixedWorldLaunchPrefixCertificate

end StageA.Relational.OriginalExecutionInvariant
