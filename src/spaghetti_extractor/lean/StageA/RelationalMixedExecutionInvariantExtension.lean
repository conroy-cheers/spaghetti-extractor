import StageA.RelationalInterpreterMixedWorldBridge

namespace StageA.Relational.MixedExecutionInvariantExtension

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

/-!
# Paired mixed-execution invariant extensions

Some inductive facts, including value provenance across external calls, depend
on both sides of a checked chunk.  They cannot be established soundly by an
original-only transition invariant.

This module extends an existing mixed invariant with facts preserved by its
exact paired chunks.  The extension receives the checked original and candidate
paths and their pointwise-related observations.  It cannot introduce a
successor fact from a generated status field.
-/

structure MixedWorldExecutionInvariantExtension
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (reachabilityTargetIds : List Nat)
    (base : MixedExecutionInvariant reachabilityTargetIds contract) where
  holds : WorldExecution -> NativeWorldExecution -> Prop
  chunkClosed : forall originalBefore candidateBefore,
    holds originalBefore candidateBefore ->
      (chunk : MixedWorldComponentChunkRefinement original candidate contract
        base originalBefore candidateBefore) ->
      holds chunk.originalAfter chunk.candidateAfter

def MixedWorldExecutionInvariantExtension.and
    (left right : MixedWorldExecutionInvariantExtension original candidate
      contract reachabilityTargetIds base) :
    MixedWorldExecutionInvariantExtension original candidate contract
      reachabilityTargetIds base where
  holds originalExecution candidateExecution :=
    left.holds originalExecution candidateExecution /\
      right.holds originalExecution candidateExecution
  chunkClosed originalBefore candidateBefore beforeHolds chunk :=
    ⟨left.chunkClosed originalBefore candidateBefore beforeHolds.1 chunk,
      right.chunkClosed originalBefore candidateBefore beforeHolds.2 chunk⟩

def MixedWorldExecutionInvariantExtension.all
    (extensions : List (MixedWorldExecutionInvariantExtension original candidate
      contract reachabilityTargetIds base)) :
    MixedWorldExecutionInvariantExtension original candidate contract
      reachabilityTargetIds base where
  holds originalExecution candidateExecution :=
    forall extension, extension ∈ extensions ->
      extension.holds originalExecution candidateExecution
  chunkClosed originalBefore candidateBefore beforeHolds chunk extension member :=
    extension.chunkClosed originalBefore candidateBefore
      (beforeHolds extension member) chunk

theorem MixedWorldExecutionInvariantExtension.all_member
    {extensions : List (MixedWorldExecutionInvariantExtension original candidate
      contract reachabilityTargetIds base)}
    {originalExecution : WorldExecution}
    {candidateExecution : NativeWorldExecution}
    (combined :
      (MixedWorldExecutionInvariantExtension.all extensions).holds
        originalExecution candidateExecution)
    (extension : MixedWorldExecutionInvariantExtension original candidate
      contract reachabilityTargetIds base)
    (member : extension ∈ extensions) :
    extension.holds originalExecution candidateExecution :=
  combined extension member

def MixedWorldExecutionInvariantExtension.strengthen
    (extension : MixedWorldExecutionInvariantExtension original candidate
      contract reachabilityTargetIds base) :
    MixedExecutionInvariant reachabilityTargetIds contract where
  holds originalExecution candidateExecution :=
    base.holds originalExecution candidateExecution /\
      extension.holds originalExecution candidateExecution
  originalReachable originalExecution candidateExecution related :=
    base.originalReachable originalExecution candidateExecution related.1
  candidateProofOpen originalExecution candidateExecution related :=
    base.candidateProofOpen originalExecution candidateExecution related.1
  worldsRelated originalExecution candidateExecution originalWorld candidateWorld
      related originalWorldExact candidateWorldExact :=
    base.worldsRelated originalExecution candidateExecution originalWorld
      candidateWorld related.1 originalWorldExact candidateWorldExact
  runtimeStatesRelated originalExecution candidateExecution originalWorld
      candidateWorld originalState candidateState related originalWorldExact
      candidateWorldExact originalStateExact candidateStateExact :=
    base.runtimeStatesRelated originalExecution candidateExecution originalWorld
      candidateWorld originalState candidateState related.1 originalWorldExact
      candidateWorldExact originalStateExact candidateStateExact

theorem MixedWorldExecutionInvariantExtension.holds_of_strengthened
    (extension : MixedWorldExecutionInvariantExtension original candidate
      contract reachabilityTargetIds base)
    (related : extension.strengthen.holds originalExecution candidateExecution) :
    extension.holds originalExecution candidateExecution :=
  related.2

/-- Strengthen a complete mixed composition once with any finite collection of
paired, chunk-inductive facts. -/
def MixedWorldChunkComposition.withInvariantExtension
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
    (extension : MixedWorldExecutionInvariantExtension original candidate
      contract reachability.targetIds composition.invariant)
    (rootHolds : forall originalWorld candidateWorld originalState candidateState,
      MixedLaunchStatesRelated originalContext candidate contract
          originalWorld candidateWorld originalState candidateState ->
        extension.holds
          (.running launch.rootTargetId originalState
            launch.continuationTargetIds 0 originalWorld)
          (.running candidateRootRva 0 candidateState
            (composition.candidateLaunchCalls candidateState) 0 []
            candidateWorld)) :
    MixedWorldChunkComposition originalContext originalAuthority
      original candidate candidateAuthority programBinding contract launch
      originalRoot reachability candidateRootRva candidateRoot where
  invariant := extension.strengthen
  candidateLaunchCalls := composition.candidateLaunchCalls
  candidateLaunchCallsExact := composition.candidateLaunchCallsExact
  rootsRelated originalWorld candidateWorld originalState candidateState launched :=
    ⟨composition.rootsRelated originalWorld candidateWorld originalState
        candidateState launched,
      rootHolds originalWorld candidateWorld originalState candidateState launched⟩
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
        extension.chunkClosed originalBefore candidateBefore related.2 prior⟩
    }

#print axioms MixedWorldExecutionInvariantExtension.all_member
#print axioms MixedWorldExecutionInvariantExtension.holds_of_strengthened
#print axioms MixedWorldChunkComposition.withInvariantExtension

end StageA.Relational.MixedExecutionInvariantExtension
