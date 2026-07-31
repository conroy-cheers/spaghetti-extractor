import StageA.RelationalInterpreterMixedLaunchOperationBridge
import StageA.RelationalInterpreterMixedLaunchRefinement

namespace StageA.Relational.InterpreterMixedLaunchOperationRankedRoute

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedBoundaryOperation
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedLaunchOperationBridge
open StageA.Relational.InterpreterMixedLaunchRefinement
open StageA.Relational.InterpreterNativeWorld

/-!
# Ranked exact native routes

Candidate launch wrappers may perform finite validation loops before entering
the first recurring interpreter operation.  Unrolling those loops duplicates
exact instruction replay and produces very large proof terms.  This module
instead composes already checked, observation-free path chunks under a
well-founded rank.

The rank and invariant are proof obligations over the exact native transition
system.  A generated graph, block replay, or semantic summary may prove one
`advance` result, but neither a graph edge nor a diagnostic field can replace
that proof.
-/

/-- One exact PE-backed direct-call anchor used to connect independently
checked route components. -/
structure ExactNativeDirectCallAnchor where
  instruction : KernelInstruction
  targetRva : Nat
deriving Repr, DecidableEq

def ExactNativeDirectCallAnchor.checked
    (anchor : ExactNativeDirectCallAnchor)
    (pe : PE32) (imports : List PEImport) : Bool :=
  match anchor.instruction.semantics? pe imports with
  | some (.stop behavior) =>
      match behavior.outcome with
      | some (.call targetRva _ _) => targetRva == anchor.targetRva
      | _ => false
  | _ => false

/-- The Boolean anchor checker exposes only a call decoded and interpreted
from the exact PE bytes. -/
theorem ExactNativeDirectCallAnchor.checked_sound
    (anchor : ExactNativeDirectCallAnchor)
    (pe : PE32) (imports : List PEImport)
    (checked : anchor.checked pe imports = true) :
    exists behavior continuationRva returnAddress,
      anchor.instruction.semantics? pe imports = some (.stop behavior) /\
        behavior.outcome =
          some (.call anchor.targetRva continuationRva returnAddress) := by
  unfold ExactNativeDirectCallAnchor.checked at checked
  cases semanticsExact : anchor.instruction.semantics? pe imports with
  | none => simp [semanticsExact] at checked
  | some semantics =>
      cases semantics with
      | next state => simp [semanticsExact] at checked
      | stop behavior =>
          cases outcomeExact : behavior.outcome with
          | none => simp [semanticsExact, outcomeExact] at checked
          | some outcome =>
              cases outcome <;>
                simp [semanticsExact, outcomeExact] at checked
              case call targetRva continuationRva returnAddress =>
                subst targetRva
                exact ⟨behavior, continuationRva, returnAddress,
                  rfl, by simpa using outcomeExact⟩

/-- An exact instruction plus the complete immediate successor inventory
computed by the reviewed symbolic x86 semantics. -/
structure ExactNativeControlAnchor where
  instruction : KernelInstruction
  successors : List Nat
deriving Repr, DecidableEq

def ExactNativeControlAnchor.checked
    (anchor : ExactNativeControlAnchor)
    (pe : PE32) (imports : List PEImport) : Bool :=
  ordinaryNativeLaunchSuccessors? pe imports anchor.instruction ==
    some anchor.successors

theorem ExactNativeControlAnchor.checked_sound
    (anchor : ExactNativeControlAnchor)
    (pe : PE32) (imports : List PEImport)
    (checked : anchor.checked pe imports = true) :
    ordinaryNativeLaunchSuccessors? pe imports anchor.instruction =
      some anchor.successors := by
  simpa [ExactNativeControlAnchor.checked] using checked

/-- A checked route from one exact native execution to a destination
predicate.  Each progress result is a real nonempty path in the candidate
transition system and strictly decreases the supplied rank. -/
structure ExactNativeSilentRankedRoute
    (candidate : ExactNativeWorldProgram)
    (before : NativeWorldExecution)
    (destination : NativeWorldExecution -> Prop) where
  invariant : NativeWorldExecution -> Prop
  rank : NativeWorldExecution -> Nat
  beforeHolds : invariant before
  beforeNotDestination : Not (destination before)
  advance : forall current,
    invariant current ->
    Not (destination current) ->
    exists next,
      NonemptyRelatedPath candidate.transitionSystem current [] next /\
        invariant next /\
        rank next < rank current

/-- Well-founded ranked progress either starts at the destination or produces
a nonempty silent path to it. -/
theorem ExactNativeSilentRankedRoute.reachesOrIs
    (route : ExactNativeSilentRankedRoute candidate before destination)
    (current : NativeWorldExecution)
    (currentHolds : route.invariant current) :
    exists after,
      destination after /\
        (current = after \/
          NonemptyRelatedPath candidate.transitionSystem current [] after) := by
  let relation : NativeWorldExecution -> NativeWorldExecution -> Prop :=
    fun left right => route.rank left < route.rank right
  have wellFounded : WellFounded relation := by
    exact (measure route.rank).wf
  induction current using wellFounded.induction with
  | h current induction =>
      by_cases atDestination : destination current
      · exact ⟨current, atDestination, Or.inl rfl⟩
      · obtain ⟨next, progress, nextHolds, decreases⟩ :=
          route.advance current currentHolds atDestination
        obtain ⟨after, afterDestination, nextExact | tail⟩ :=
          induction next decreases nextHolds
        · subst next
          exact ⟨after, afterDestination, Or.inr progress⟩
        · exact ⟨after, afterDestination,
            Or.inr (progress.trans tail)⟩

/-- The source is explicitly outside the destination, so ranked progress
produces a nonempty path rather than the identity case. -/
theorem ExactNativeSilentRankedRoute.reaches
    (route : ExactNativeSilentRankedRoute candidate before destination) :
    exists after,
      destination after /\
        NonemptyRelatedPath candidate.transitionSystem before [] after := by
  obtain ⟨after, afterDestination, beforeExact | path⟩ :=
    route.reachesOrIs before route.beforeHolds
  · subst after
    exact False.elim (route.beforeNotDestination afterDestination)
  · exact ⟨after, afterDestination, path⟩

/-- Exact endpoint shape required by `ExactNativeLaunchOperationPrefix`.
The caller-frame tail, event index, event trace, and world are inherited from
the callback boundary.  Only the checked nested operation-frame prefix and
operation machine state may be introduced by the route. -/
def nativeLaunchOperationDestination
    (descriptor : NativeCallbackWrapperDescriptor)
    (boundary : ExactNativeCallbackWrapperBoundaryFrame candidate descriptor
      boundaryBefore)
    (execution : NativeWorldExecution) : Prop :=
  exists operationState operationFrames,
    execution =
      .running descriptor.operationEntryRva 0 operationState
        (operationFrames ++ boundary.callerFrames)
        boundary.eventIndex boundary.events boundary.world

/-- One callback-boundary frame plus a ranked exact route to the operation
entry. -/
structure ExactNativeLaunchOperationRankedRoute
    (candidate : ExactNativeWorldProgram)
    (descriptor : NativeCallbackWrapperDescriptor)
    (boundaryBefore : NativeWorldExecution) where
  boundary :
    ExactNativeCallbackWrapperBoundaryFrame candidate descriptor boundaryBefore
  route :
    ExactNativeSilentRankedRoute candidate boundaryBefore
      (nativeLaunchOperationDestination descriptor boundary)

/-- A ranked route constructs the existing launch-operation prefix without
submitting its endpoint, path, or frame stack as a separate premise. -/
theorem ExactNativeLaunchOperationRankedRoute.prefixExists
    (ranked : ExactNativeLaunchOperationRankedRoute candidate descriptor
      boundaryBefore) :
    Nonempty (ExactNativeLaunchOperationPrefix candidate descriptor
      boundaryBefore) := by
  obtain ⟨after, ⟨operationState, operationFrames, afterExact⟩, path⟩ :=
    ranked.route.reaches
  subst after
  exact ⟨{
    boundary := ranked.boundary
    operationState
    operationFrames
    candidatePrefix := path
  }⟩

/-- Splice a ranked exact launch route into the existing mixed boundary
bridge without selecting the existential route endpoint through choice.  The
operation proof provider receives the exact prefix constructed by ranked
progress. -/
theorem ExactNativeLaunchOperationRankedRoute.boundaryBridgeExists
    (ranked : ExactNativeLaunchOperationRankedRoute candidate descriptor
      boundaryBefore)
    (certificate : forall launchPrefix :
      ExactNativeLaunchOperationPrefix candidate descriptor boundaryBefore,
      MixedKernelOperationComponentCertificate original candidate contract
        invariant program abi dispatches candidateAuthority sourceRva
        owner.operation owner.entryRva originalBefore
          launchPrefix.operationExecution) :
    Nonempty (
      ExactMixedKernelBoundaryToOperationBridge original candidate contract
        invariant program abi dispatches candidateAuthority sourceRva owner
        originalBefore boundaryBefore) := by
  obtain ⟨launchPrefix⟩ := ranked.prefixExists
  exact ⟨launchPrefix.toBoundaryBridge (certificate launchPrefix)⟩

#print axioms ExactNativeSilentRankedRoute.reachesOrIs
#print axioms ExactNativeSilentRankedRoute.reaches
#print axioms ExactNativeDirectCallAnchor.checked_sound
#print axioms ExactNativeControlAnchor.checked_sound
#print axioms ExactNativeLaunchOperationRankedRoute.prefixExists
#print axioms ExactNativeLaunchOperationRankedRoute.boundaryBridgeExists

end StageA.Relational.InterpreterMixedLaunchOperationRankedRoute
