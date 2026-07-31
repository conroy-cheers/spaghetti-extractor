import StageA.RelationalRuntimeValueCarry
import StageA.RelationalStackDynamicIndirectMixedOriginalComposition

namespace StageA.Relational.GuardedRuntimeCut

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.MixedExecutionInvariantExtension
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.OriginalStackDynamicControlClosure
open StageA.Relational.RuntimeValueCarry
open StageA.Relational.StackDynamicIndirectMixedOriginalComposition

/-!
# Exact guarded runtime cuts

Generated data names every decoded incoming edge and guard. Lean rechecks that
finite inventory. Operational exclusion is supplied only through a paired,
chunk-inductive extension of the authoritative mixed invariant; this module
has no submitted path, universal incoming classifier, or one-instruction guard
premise.
-/

structure IncomingGuard where
  edge : IncomingPair
  guardId : String
deriving Repr, DecidableEq, BEq

structure Certificate where
  frontierId : String
  sourceTargetId : Nat
  incomingGuards : List IncomingGuard
deriving Repr, DecidableEq

def Certificate.incomingPairs (certificate : Certificate) :
    List IncomingPair :=
  certificate.incomingGuards.map (·.edge)

def Certificate.checked
    (context : OriginalDecodedStaticContext) (certificate : Certificate) : Bool :=
  certificate.frontierId != "" &&
    !certificate.incomingGuards.isEmpty &&
    noDuplicates certificate.incomingGuards &&
    noDuplicates (certificate.incomingGuards.map (·.guardId)) &&
    (certificate.incomingGuards.all fun guard =>
      guard.guardId != "" &&
        guard.edge.targetTargetId == certificate.sourceTargetId) &&
    match context.source? certificate.sourceTargetId with
    | none => false
    | some source =>
        !source.region.root &&
          sameFiniteSet certificate.incomingPairs
            (decodedIncomingPairsFor context [certificate.sourceTargetId])

structure CheckedCertificate
    (context : OriginalDecodedStaticContext) where
  decodedAuthority : ExactOriginalDecodedAuthority context
  certificate : Certificate
  checked : certificate.checked context = true

theorem Certificate.exactIncoming_of_checked
    {context : OriginalDecodedStaticContext} {certificate : Certificate}
    (checked : certificate.checked context = true) :
    sameFiniteSet certificate.incomingPairs
      (decodedIncomingPairsFor context [certificate.sourceTargetId]) = true := by
  unfold Certificate.checked at checked
  simp only [Bool.and_eq_true] at checked
  have sourceChecked := checked.2
  cases found : context.source? certificate.sourceTargetId with
  | none => simp [found] at sourceChecked
  | some source =>
      simp only [found, Bool.and_eq_true] at sourceChecked
      exact sourceChecked.2

structure CheckedMixedOperationalCut
    (context : OriginalDecodedStaticContext)
    (original : DecodedWorldProgram)
    (candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (reachabilityTargetIds : List Nat)
    (base : MixedExecutionInvariant reachabilityTargetIds contract)
    (checkedCut : CheckedCertificate context) where
  programBinding : ExactMixedProgramBinding context original
  chunkClosed : forall originalBefore candidateBefore,
    OriginalSourceFactAt checkedCut.certificate.sourceTargetId
        (fun _world _state => False) originalBefore ->
      (chunk : MixedWorldComponentChunkRefinement original candidate contract
        base originalBefore candidateBefore) ->
      OriginalSourceFactAt checkedCut.certificate.sourceTargetId
        (fun _world _state => False) chunk.originalAfter

def CheckedMixedOperationalCut.toExtension
    (operational :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base checkedCut) :
    MixedWorldExecutionInvariantExtension original candidate contract
      reachabilityTargetIds base where
  holds originalExecution _candidateExecution :=
    OriginalSourceFactAt checkedCut.certificate.sourceTargetId
      (fun _world _state => False) originalExecution
  chunkClosed := operational.chunkClosed

def CheckedMixedOperationalCut.sourceFalseProjection
    (operational :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base checkedCut) :
    OriginalSourceFactMixedProjection operational.toExtension
      checkedCut.certificate.sourceTargetId (fun _world _state => False) where
  project _ _ holds := holds

theorem CheckedMixedOperationalCut.sourceUninhabited
    (operational :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base checkedCut) :
    ActualMixedOriginalStackDynamicSourceUninhabited
      operational.toExtension.strengthen
      checkedCut.certificate.sourceTargetId :=
  actualMixedOriginalStackDynamicSourceUninhabited_of_mixedProjection
    operational.sourceFalseProjection

#print axioms CheckedMixedOperationalCut.toExtension
#print axioms CheckedMixedOperationalCut.sourceFalseProjection
#print axioms CheckedMixedOperationalCut.sourceUninhabited

end StageA.Relational.GuardedRuntimeCut
