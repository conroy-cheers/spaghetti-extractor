import StageA.RelationalOriginalCombinedExecutionInvariant
import StageA.RelationalSourceProgramCertificate

namespace StageA.Relational.OriginalCombinedTargetStepIndex

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalRuntimeMemoryPartition
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.ProgramCertificate

/-!
# Indexed one-sided whole-program invariant closure

This module is the root-independent composition boundary between exact active
target transition certificates and the complete original execution invariant.
Every reachable target identifier occurs exactly once in the transition index.
Each indexed target carries preservation proofs for all invariant families,
and external resumption has one separate preservation certificate.

The index does not derive reachability from itself and does not consume a
rooted execution domain.  Its preservation proofs take the complete combined
pre-state predicate, allowing value-flow, static-word, call-frame, and indirect
target facts to support one another without introducing circular reachability.
-/

/-- The seven independently cacheable post-state families whose conjunction is
the complete original invariant. -/
structure OriginalCombinedPostFamilies
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    (after : WorldExecution) : Prop where
  reachability :
    OriginalExecutionReachable inventory.reachableTargets.targetIds after
  staticWords : inventory.staticWords.Holds program.context after
  callFrames : OriginalCallFrameExecutionHolds program.context after
  valueFlows : inventory.valueFlows.Holds after
  registerTargets :
    OriginalRegisterTargetsHold inventory.registerTargets after
  stackDynamicTargets :
    OriginalStackDynamicTargetsHold inventory.stackDynamicTargets after
  runtimeMemory : OriginalRuntimeMemoryPartition.ExecutionHolds
    program.context after

def OriginalCombinedPostFamilies.toHolds
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {after : WorldExecution}
    (families : OriginalCombinedPostFamilies inventory after) :
    inventory.Holds after :=
  ⟨families.reachability, families.staticWords, families.callFrames,
    families.valueFlows, families.registerTargets,
    families.stackDynamicTargets, families.runtimeMemory⟩

def OriginalCombinedPostFamilies.ofHolds
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {after : WorldExecution}
    (holds : inventory.Holds after) :
    OriginalCombinedPostFamilies inventory after :=
  ⟨holds.1, holds.2.1, holds.2.2.1, holds.2.2.2.1,
    holds.2.2.2.2.1, holds.2.2.2.2.2.1,
    holds.2.2.2.2.2.2⟩

/-- Preservation attached to one exact active-target transition certificate.
The conclusion names the authoritative exact-PE transition, while the indexed
certificate retains the independently checked source/decoded transition tie. -/
structure OriginalCombinedTargetFamilyPreservation
    {pe : PE32} {sourceProgram : Program}
    {binding : ExactBinding pe sourceProgram}
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory sourceProgram.worldProgram
      originalContext)
    (certificate : ActiveTargetTransitionCertificate binding) : Prop where
  running : forall state calls eventIndex world,
    inventory.Holds
        (.running certificate.targetId state calls eventIndex world) ->
      OriginalCombinedPostFamilies inventory
        (sourceProgram.worldProgram.pe32TransitionSystem.step
          (.running certificate.targetId state calls eventIndex world)).next
  callbackRunning : forall state calls eventIndex world callbacks,
    inventory.Holds
        (.callbackRunning certificate.targetId state calls eventIndex world
          callbacks) ->
      OriginalCombinedPostFamilies inventory
        (sourceProgram.worldProgram.pe32TransitionSystem.step
          (.callbackRunning certificate.targetId state calls eventIndex world
            callbacks)).next

/-- The external environment is the only non-target-indexed progressing case.
It must preserve all six families for every admitted suspension and callback
stack. -/
structure OriginalCombinedAwaitingExternalPreservation
    {program : DecodedWorldProgram}
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program originalContext) :
    Prop where
  preserves : forall suspension callbacks,
    inventory.Holds (.awaitingExternal suspension callbacks) ->
      OriginalCombinedPostFamilies inventory
        (program.pe32TransitionSystem.step
          (.awaitingExternal suspension callbacks)).next

/-- Complete, unique target-indexed preservation authority.  Equality with the
reachable inventory prevents both omitted and extra target certificates; the
underlying `ActiveTargetTransitionIndex` rejects duplicate target IDs. -/
structure OriginalCombinedTargetStepIndex
    {pe : PE32} {sourceProgram : Program}
    (binding : ExactBinding pe sourceProgram)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory sourceProgram.worldProgram
      originalContext) where
  transitions : ActiveTargetTransitionIndex binding
  targetIdsExact :
    transitions.certificates.map (fun certificate => certificate.targetId) =
      inventory.reachableTargets.targetIds
  preserves : forall certificate,
    certificate ∈ transitions.certificates ->
      OriginalCombinedTargetFamilyPreservation originalContext inventory
        certificate

theorem findTargetCertificate?_member
    {pe : PE32} {sourceProgram : Program}
    {binding : ExactBinding pe sourceProgram}
    {certificates : List (ActiveTargetTransitionCertificate binding)}
    {targetId : Nat}
    {certificate : ActiveTargetTransitionCertificate binding}
    (found : findTargetCertificate? certificates targetId = some certificate) :
    certificate ∈ certificates := by
  induction certificates with
  | nil => cases found
  | cons head tail induction =>
      simp only [findTargetCertificate?] at found
      split at found
      · simp only [Option.some.injEq] at found
        subst certificate
        exact List.mem_cons_self
      · exact List.mem_cons_of_mem head (induction found)

theorem OriginalCombinedTargetStepIndex.find?_member
    {pe : PE32} {sourceProgram : Program}
    {binding : ExactBinding pe sourceProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory sourceProgram.worldProgram
      originalContext}
    (index : OriginalCombinedTargetStepIndex binding originalContext inventory)
    {targetId : Nat}
    {certificate : ActiveTargetTransitionCertificate binding}
    (found : index.transitions.find? targetId = some certificate) :
    certificate ∈ index.transitions.certificates := by
  exact findTargetCertificate?_member found

/-- Every reachable target has exactly one checked transition certificate.
Existence follows from exact inventory equality; uniqueness follows from the
underlying target-ID `Nodup` proof. -/
theorem OriginalCombinedTargetStepIndex.find?_of_reachable
    {pe : PE32} {sourceProgram : Program}
    {binding : ExactBinding pe sourceProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory sourceProgram.worldProgram
      originalContext}
    (index : OriginalCombinedTargetStepIndex binding originalContext inventory)
    {targetId : Nat}
    (reachable : targetId ∈ inventory.reachableTargets.targetIds) :
    exists certificate, index.transitions.find? targetId = some certificate := by
  apply index.transitions.find?_isSome_of_target_mem
  rw [index.targetIdsExact]
  exact reachable

/-- A missing target certificate contradicts construction of the exact index.
This theorem is useful at generated checker boundaries: omission cannot be
deferred to execution. -/
theorem OriginalCombinedTargetStepIndex.omittedTargetFalse
    {pe : PE32} {sourceProgram : Program}
    {binding : ExactBinding pe sourceProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory sourceProgram.worldProgram
      originalContext}
    (index : OriginalCombinedTargetStepIndex binding originalContext inventory)
    {targetId : Nat}
    (reachable : targetId ∈ inventory.reachableTargets.targetIds)
    (omitted : index.transitions.find? targetId = none) : False := by
  rcases index.find?_of_reachable reachable with ⟨certificate, found⟩
  rw [omitted] at found
  contradiction

/-- The underlying checked index exposes its duplicate-rejection fact without
requiring downstream proofs to traverse the generated certificate list. -/
theorem OriginalCombinedTargetStepIndex.targetIdsUnique
    {pe : PE32} {sourceProgram : Program}
    {binding : ExactBinding pe sourceProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory sourceProgram.worldProgram
      originalContext}
    (index : OriginalCombinedTargetStepIndex binding originalContext inventory) :
    (index.transitions.certificates.map
      (fun certificate => certificate.targetId)).Nodup :=
  index.transitions.targetIdsUnique

/-- Case analysis over the authoritative execution state.  Running and
callback-running cases use the exact target index; external suspension uses
its explicit environment certificate.  Returned, terminated, and fault states
are fixed points of the exact transition.  A blocked pre-state is impossible
under the combined invariant. -/
theorem originalCombinedPostFamilies_of_indexedTargets
    {pe : PE32} {sourceProgram : Program}
    {binding : ExactBinding pe sourceProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory sourceProgram.worldProgram
      originalContext}
    (index : OriginalCombinedTargetStepIndex binding originalContext inventory)
    (external : OriginalCombinedAwaitingExternalPreservation originalContext
      inventory)
    (before : WorldExecution) (holds : inventory.Holds before) :
    OriginalCombinedPostFamilies inventory
      (sourceProgram.worldProgram.pe32TransitionSystem.step before).next := by
  cases before with
  | running targetId state calls eventIndex world =>
      rcases index.find?_of_reachable holds.1.1 with ⟨certificate, found⟩
      have targetExact := index.transitions.find?_targetExact found
      have member := index.find?_member found
      have preservation := index.preserves certificate member
      subst targetId
      exact preservation.running state calls eventIndex world holds
  | callbackRunning targetId state calls eventIndex world callbacks =>
      rcases index.find?_of_reachable holds.1.1 with ⟨certificate, found⟩
      have targetExact := index.transitions.find?_targetExact found
      have member := index.find?_member found
      have preservation := index.preserves certificate member
      subst targetId
      exact preservation.callbackRunning state calls eventIndex world callbacks
        holds
  | awaitingExternal suspension callbacks =>
      exact external.preserves suspension callbacks holds
  | returned state world =>
      simpa [DecodedWorldProgram.pe32TransitionSystem,
        stepPE32WorldExecution] using
        (OriginalCombinedPostFamilies.ofHolds holds)
  | terminated world =>
      simpa [DecodedWorldProgram.pe32TransitionSystem,
        stepPE32WorldExecution] using
        (OriginalCombinedPostFamilies.ofHolds holds)
  | fault cause =>
      simpa [DecodedWorldProgram.pe32TransitionSystem,
        stepPE32WorldExecution] using
        (OriginalCombinedPostFamilies.ofHolds holds)
  | blocked reason =>
      exact False.elim (inventory.blockedFalse reason holds)

/-- Cache-friendly whole-program family closure assembled from independently
compiled target and external preservation certificates. -/
def originalCombinedStepFamilies_of_indexedTargets
    {pe : PE32} {sourceProgram : Program}
    {binding : ExactBinding pe sourceProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory sourceProgram.worldProgram
      originalContext}
    (index : OriginalCombinedTargetStepIndex binding originalContext inventory)
    (external : OriginalCombinedAwaitingExternalPreservation originalContext
      inventory) :
    CheckedOriginalCombinedExecutionStepFamilies sourceProgram.worldProgram
      originalContext inventory where
  reachabilityClosed before holds :=
    (originalCombinedPostFamilies_of_indexedTargets index external before
      holds).reachability
  staticWordsClosed before holds :=
    (originalCombinedPostFamilies_of_indexedTargets index external before
      holds).staticWords
  callFramesClosed before holds :=
    (originalCombinedPostFamilies_of_indexedTargets index external before
      holds).callFrames
  valueFlowsClosed before holds :=
    (originalCombinedPostFamilies_of_indexedTargets index external before
      holds).valueFlows
  registerTargetsClosed before holds :=
    (originalCombinedPostFamilies_of_indexedTargets index external before
      holds).registerTargets
  stackDynamicTargetsClosed before holds :=
    (originalCombinedPostFamilies_of_indexedTargets index external before
      holds).stackDynamicTargets
  runtimeMemoryClosed before holds :=
    (originalCombinedPostFamilies_of_indexedTargets index external before
      holds).runtimeMemory

def originalCombinedInvariant_of_indexedTargets
    {pe : PE32} {sourceProgram : Program}
    {binding : ExactBinding pe sourceProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory sourceProgram.worldProgram
      originalContext}
    (index : OriginalCombinedTargetStepIndex binding originalContext inventory)
    (external : OriginalCombinedAwaitingExternalPreservation originalContext
      inventory) :
    CheckedOriginalCombinedExecutionInvariant sourceProgram.worldProgram
      originalContext inventory :=
  (originalCombinedStepFamilies_of_indexedTargets index external).toCheckedInvariant

#print axioms OriginalCombinedTargetStepIndex.omittedTargetFalse
#print axioms OriginalCombinedTargetStepIndex.targetIdsUnique
#print axioms originalCombinedPostFamilies_of_indexedTargets
#print axioms originalCombinedStepFamilies_of_indexedTargets
#print axioms originalCombinedInvariant_of_indexedTargets

end StageA.Relational.OriginalCombinedTargetStepIndex
