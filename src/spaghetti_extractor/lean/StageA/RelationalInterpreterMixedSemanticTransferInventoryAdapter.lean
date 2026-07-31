import StageA.RelationalInterpreterAcceptance
import StageA.RelationalInterpreterMixedSemanticOperationComponent

namespace StageA.Relational.InterpreterMixedSemanticTransferInventoryAdapter

open StageA.Relational
open StageA.Relational.InterpreterAcceptance
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedSemanticOperationComponent
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact transfer-inventory adapter

The round-trip acceptance inventory proves that every required ordinary source
RVA has an exact normalization refinement. The mixed semantic-operation layer
uses the same refinement, but additionally indexes it by an
`ExactOriginalSemanticSource`, whose record comes from the exact candidate
semantic table and whose stop RVA comes from the exact decoded source region.

`ExactOriginalTransferInventory` currently exposes refinements existentially,
not through a canonical checked index. Consequently generated code must select
an `ExactOriginalTransferRefinement` and provide the structural equalities
below. These equalities carry no semantics: the universal semantic theorem is
reused directly from `refinement.certificate`.

A future indexed inventory can construct this selection automatically without
changing the adapter or the downstream binding.
-/

/-- One exact inventory-required refinement associated with one exact mixed
semantic source.

The required generated facts are:

* the acceptance proof context and one-sided decoded context use the same
  original PE;
* the source RVA is required by the checked transfer inventory;
* the selected exact refinement starts at that source RVA;
* its raw record is the exact semantic-table record selected for the source;
* its path ends at the exact decoded region stop.

No completion count, status, theorem name, or independently restated semantic
claim is represented. -/
structure ExactOriginalTransferInventorySelection
    (acceptanceContext : StaticProofContext)
    (inventory : ExactOriginalTransferInventory acceptanceContext)
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (reachability : ExactOriginalDecodedReachability context authority launch root)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (source : ExactOriginalSemanticSource context authority launch root
      reachability candidate candidateAuthority) where
  refinement : ExactOriginalTransferRefinement acceptanceContext
  originalPeExact : acceptanceContext.originalPe = context.pe
  required :
    source.source.target.rva ∈ inventory.requiredSourceRvas
  sourceRvaExact :
    refinement.path.sourceRva = source.source.target.rva
  sourceRecordExact :
    refinement.path.record = source.record
  regionStopExact :
    refinement.path.stopRva = source.source.region.span.stop

/-- The checked inventory really covers the selected source. This projection is
diagnostic evidence for generators; downstream semantic authority remains the
more precise selected refinement certificate. -/
theorem ExactOriginalTransferInventorySelection.inventoryRefinementAt
    (selection : ExactOriginalTransferInventorySelection acceptanceContext inventory
      context authority launch root reachability candidate candidateAuthority source) :
    ExactOriginalTransferRefinementAt acceptanceContext
      source.source.target.rva :=
  inventory.refinementAt source.source.target.rva selection.required

/-- Repackage the existing exact acceptance refinement for the mixed
semantic-operation component. No decoding, normalization, or semantic
refinement is recomputed. -/
def ExactOriginalTransferInventorySelection.toSemanticTransferBinding
    (selection : ExactOriginalTransferInventorySelection acceptanceContext inventory
      context authority launch root reachability candidate candidateAuthority source) :
    ExactOriginalSemanticTransferBinding context authority launch root reachability
      candidate candidateAuthority source := {
  path := selection.refinement.path
  transfer := selection.refinement.transfer
  pathRecordExact := selection.sourceRecordExact
  pathSourceExact := selection.sourceRvaExact
  pathStopExact := selection.regionStopExact
  normalization := by
    simpa [selection.originalPeExact] using selection.refinement.certificate
}

theorem ExactOriginalTransferInventorySelection.bindingRecordExact
    (selection : ExactOriginalTransferInventorySelection acceptanceContext inventory
      context authority launch root reachability candidate candidateAuthority source) :
    selection.toSemanticTransferBinding.path.record = source.record :=
  selection.sourceRecordExact

theorem ExactOriginalTransferInventorySelection.bindingSourceRvaExact
    (selection : ExactOriginalTransferInventorySelection acceptanceContext inventory
      context authority launch root reachability candidate candidateAuthority source) :
    selection.toSemanticTransferBinding.path.sourceRva =
      source.source.target.rva :=
  selection.sourceRvaExact

theorem ExactOriginalTransferInventorySelection.bindingRegionStopExact
    (selection : ExactOriginalTransferInventorySelection acceptanceContext inventory
      context authority launch root reachability candidate candidateAuthority source) :
    selection.toSemanticTransferBinding.path.stopRva =
      source.source.region.span.stop :=
  selection.regionStopExact

end StageA.Relational.InterpreterMixedSemanticTransferInventoryAdapter
