from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.internal_direct_call_composition import (
    INTERNAL_DIRECT_CALL_COMPOSITION_LEAN_FILENAME,
    InternalDirectCallCompositionLeanBindings,
    internal_direct_call_composition_source,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound"}


def _copy_module_closure(source_root: Path, destination: Path, module: str) -> None:
    pending = [module]
    copied: set[str] = set()
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        source = source_root / f"{current}.lean"
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(text))


_SEMANTIC_EXAMPLES = r"""import StageA.RelationalInternalDirectCallComposition

namespace StageA.InternalDirectCallCompositionSemanticExamples

open StageA.Relational
open StageA.Relational.InternalDirectCallComposition

theorem directOrBranchStepUsesCanonicalSegment
    {context : StaticProofContext} {tree : SummaryTree}
    {before after : PairedCalleeCursor}
    (step : ExactInternalSegmentStep context tree.certificate before after) :
    RelationalSegmentRefinement context step.authority.segment
      step.authority.sourceInvariant step.authority.targetInvariant :=
  step.authority.refinement

theorem directOrBranchStepRestoresStateRel
    {context : StaticProofContext} {tree : SummaryTree}
    {before after : PairedCalleeCursor}
    (step : ExactInternalSegmentStep context tree.certificate before after) :
    StateRel context after.world step.authority.targetInvariant
      after.original after.candidate :=
  step.targetRelated

theorem nestedStepConsumesChildSemanticContract
    {context : StaticProofContext} {parent child : SummaryTree}
    {before after : PairedCalleeCursor}
    (step : ExactNestedSummaryStep context parent child before after) :
    requestedCallReturnRegistersHold child.certificate before.original before.candidate
      after.original after.candidate :=
  step.child.preserves _ _ _ _ _ _ step.invoked

theorem finiteOriginCallConsumesProvenanceAndChildContract
    {context : StaticProofContext} {parent child : SummaryTree}
    {before after : PairedCalleeCursor}
    (step : ExactFiniteOriginCallStep context parent child before after) :
    requestedCallReturnRegistersHold child.certificate before.original before.candidate
      after.original after.candidate /\
      (StageA.Relational.ValueProvenance.IndirectDestination.internalCode
        step.target.targetId).Matches context before.world
        (step.authority.certificate.target.original.eval before.original)
        (step.authority.certificate.target.candidate.eval before.candidate) :=
  ⟨step.child.preserves _ _ _ _ _ _ step.invoked, step.selectedTarget⟩

theorem importStepUsesGroundedMachineResult
    {context : StaticProofContext} {tree : SummaryTree}
    {before after : PairedCalleeCursor}
    (step : ExactMachineImportStep context tree before after)
    (register : StageA.Formal.Reg)
    (member : register ∈ tree.certificate.requestedRegisters) :
    before.original.registers.get register = after.original.registers.get register /\
      before.candidate.registers.get register = after.candidate.registers.get register :=
  step.requestedPreserved register member

theorem importStepCarriesCanonicalExternalRefinement
    {context : StaticProofContext} {tree : SummaryTree}
    {before after : PairedCalleeCursor}
    (step : ExactMachineImportStep context tree before after) :
    RelationalExternalCallRefinement context step.authority.site
      step.authority.segment step.authority.sourceInvariant :=
  step.authority.canonicalRefinement

theorem returnStepCarriesLiveRuntimeFrame
    {context : StaticProofContext} {tree : SummaryTree}
    {before : PairedCalleeCursor}
    (step : ExactReturningStep context tree before) :
    callFrameHolds context step.frame before :=
  step.frameAtReturn

theorem saveRestoreGroundingCarriesExactCheckerResult
    {context : StaticProofContext} {tree : SummaryTree}
    (witness : StageA.Relational.InternalDirectCallRegisterSummary.StackSaveRestoreWitness)
    (member : witness ∈ tree.certificate.stackWitnesses)
    (checked : witness.checked tree.certificate context.originalPe
      context.candidatePe context.originalImports context.candidateImports = true) :
    RequestedRegisterGrounding context tree witness.register :=
  .saveRestore witness member checked

theorem saveRestoreCannotBeClaimedWithoutGrounding
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree)
    (register : StageA.Formal.Reg)
    (member : register ∈ tree.certificate.requestedRegisters) :
    RequestedRegisterGrounding context tree register :=
  premises.registerGrounded register member

theorem omittedEdgeCannotHideBehindSummary
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree)
    (edge : SummaryEdge) (member : edge ∈ tree.certificate.edges) :
    SemanticEdgeAuthority context tree edge :=
  premises.graphComplete.everyEdge edge member

theorem omittedReturnCannotHideBehindSummary
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree)
    (entry : StageA.Relational.InternalDirectCallRegisterSummary.ReturnInventoryEntry)
    (member : entry ∈ tree.certificate.returns) :
    exists region originalBehavior candidateBehavior,
      StageA.Relational.InternalDirectCallRegisterSummary.findRegion?
          tree.certificate.calleeRegions entry.returnRegionId = some region /\
      StageA.Formal.regionBehaviorWithImports context.originalPe context.originalImports
          region.original = some originalBehavior /\
      StageA.Formal.regionBehaviorWithImports context.candidatePe context.candidateImports
          region.candidate = some candidateBehavior :=
  premises.graphComplete.everyReturn entry member

theorem mutationFrameOrImportRejectionBlocksIntegration
    {context : StaticProofContext} {tree : SummaryTree}
    (rejected : tree.checked context.originalPe context.candidatePe
      context.originalImports context.candidateImports = false) :
    IntegratedSummaryPremises context tree -> False :=
  noIntegratedSummaryPremises_of_structural_rejection rejected

theorem everyFiniteReturningPathCloses
    {context : StaticProofContext} {tree : SummaryTree}
    {entry : PairedCalleeCursor}
    (invariant : CalleeInductiveInvariant context tree entry)
    (execution : FiniteReturningExecution context tree entry) :
    ReturningExecutionResult context tree entry execution :=
  finiteReturningExecution_preserves invariant execution

theorem identityCheckedFiniteReturnPreservesWithoutTotalTermination
    {context : StaticProofContext} {tree : SummaryTree}
    {entry : PairedCalleeCursor}
    (execution : FiniteReturningExecution context tree entry)
    (register : StageA.Formal.Reg) (registerNotEsp : register ≠ .esp)
    (requested : register ∈ tree.certificate.requestedRegisters)
    (checked : tree.certificate.identityRegisterChecked context.originalPe
      context.candidatePe context.originalImports context.candidateImports
      register = true) :
    execution.returning.afterOriginal.registers.get register =
        entry.original.registers.get register /\
      execution.returning.afterCandidate.registers.get register =
        entry.candidate.registers.get register :=
  execution.identityRegisterPreserved register registerNotEsp requested checked

theorem incompleteLoopCannotAuthorize
    {context : StaticProofContext} {tree : SummaryTree} (reason : String) :
    ¬ (LoopDischarge.incomplete reason : LoopDischarge context tree).Complete :=
  LoopDischarge.incomplete_not_complete reason

theorem incompleteOperationalTerminationCannotAuthorize
    {context : StaticProofContext} {tree : SummaryTree}
    {originalProgram candidateProgram : DecodedWorldProgram} (reason : String) :
    ¬ (CallRegionTerminationCertificate.incomplete reason :
      CallRegionTerminationCertificate context tree originalProgram candidateProgram).Complete :=
  CallRegionTerminationCertificate.incomplete_not_complete reason

def checkedClassifierCoversEveryReachablePoint
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    {source : RelatedDirectCallSource context tree binding}
    {entry : ExactOperationalDirectCallEntry context tree binding
      originalProgram candidateProgram source}
    (certificate : CheckedFiniteCallRegionExecution context tree binding
      originalProgram candidateProgram source entry)
    (point : PairedOperationalCalleePoint)
    (reachable : FiniteCalleePath context tree entry.point.cursor point.cursor) :
    ExactOperationalCalleeClassification context tree binding originalProgram
      candidateProgram source entry point :=
  certificate.classify point reachable

noncomputable def checkedOperationalGraphReturns
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    {source : RelatedDirectCallSource context tree binding}
    {entry : ExactOperationalDirectCallEntry context tree binding
      originalProgram candidateProgram source}
    (certificate : CheckedFiniteCallRegionExecution context tree binding
      originalProgram candidateProgram source entry) :
    CheckedOperationalReturnResult context tree binding originalProgram
      candidateProgram source entry entry.point :=
  certificate.returns entry.point .entry

theorem finiteGraphRejectsSelfLoop
    {tree : SummaryTree} (ranking : FiniteCallRegionRanking tree)
    (edge : SummaryEdge) (member : edge ∈ tree.certificate.edges)
    (self : edge.targetRegionId = edge.sourceRegionId) : False := by
  have decrease := ranking.decreases edge member
  rw [self] at decrease
  exact (Nat.lt_irrefl _ decrease)

theorem rankedSccRejectsNondecreasingCycle
    {context : StaticProofContext} {tree : SummaryTree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (ranking : RankedCallRegionSCC context tree originalProgram candidateProgram)
    (point : PairedOperationalCalleePoint)
    (step : ExactOperationalCalleeStep context tree originalProgram candidateProgram
      point point) : False :=
  Nat.lt_irrefl _ (ranking.decreases point point step)

def completePremisesProduceNestedContract
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree) :
    DirectCallSemanticContract context tree :=
  premises.toSemanticContract

theorem actualWorldCallReturnPreservesRequestedRegisters
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree)
    (actual : ActualDirectCallReturnExecution context tree premises.callEntry
      premises.operational.originalProgram premises.operational.candidateProgram) :
    requestedCallReturnRegistersHold tree.certificate
      actual.source.original.state actual.source.candidate.state
      actual.originalExit.state actual.candidateExit.state :=
  actualDirectCallReturn_preserves premises actual

theorem exactCallerStackArgumentReachesCallee
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree)
    (actual : ActualDirectCallReturnExecution context tree premises.callEntry
      premises.operational.originalProgram premises.operational.candidateProgram)
    (word : RuntimeFrameArgumentWord) (member : word ∈ premises.callEntry.argumentWords) :
    word.holds context actual.source.original.world actual.frame
      actual.originalEntry.state.memory actual.candidateEntry.state.memory = true :=
  actualDirectCallReturn_entryArgumentWord premises actual word member

theorem calleeStaticSlotPostconditionFeedsContinuation
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree)
    (actual : ActualDirectCallReturnExecution context tree premises.callEntry
      premises.operational.originalProgram premises.operational.candidateProgram)
    (slot : StaticWordRelationSlotPair) (member : slot ∈ context.staticWordRelationSlots) :
    slot.memoryHolds context actual.source.original.world
      actual.originalExit.state.memory actual.candidateExit.state.memory = true :=
  actualDirectCallReturn_staticWordSlot premises actual slot member

theorem callerArgumentRelationCanFlowToStaticSlot
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree)
    (actual : ActualDirectCallReturnExecution context tree premises.callEntry
      premises.operational.originalProgram premises.operational.candidateProgram)
    (word : RuntimeFrameArgumentWord) (wordMember : word ∈ premises.callEntry.argumentWords)
    (slot : StaticWordRelationSlotPair) (slotMember : slot ∈ context.staticWordRelationSlots)
    (copy : RuntimeFrameArgumentStaticWrite word slot actual.frame
      actual.originalEntry.state.memory actual.candidateEntry.state.memory
      actual.originalExit.state.memory actual.candidateExit.state.memory) :
    word.holds context actual.source.original.world actual.frame
          actual.originalEntry.state.memory actual.candidateEntry.state.memory = true /\
      slot.memoryHolds context actual.source.original.world
          actual.originalExit.state.memory actual.candidateExit.state.memory = true :=
  actualDirectCallReturn_argumentToStaticSlot premises actual word wordMember
    slot slotMember copy

theorem faultCannotSatisfyCallReturn
    (program : DecodedWorldProgram) (continuation : Nat) (cause : ModeledFault)
    (observations after) :
    Not (WorldCallRun program continuation (.fault cause) observations after) :=
  WorldCallRun.not_from_fault program continuation cause observations after

#print axioms directOrBranchStepUsesCanonicalSegment
#print axioms directOrBranchStepRestoresStateRel
#print axioms nestedStepConsumesChildSemanticContract
#print axioms importStepUsesGroundedMachineResult
#print axioms importStepCarriesCanonicalExternalRefinement
#print axioms returnStepCarriesLiveRuntimeFrame
#print axioms saveRestoreGroundingCarriesExactCheckerResult
#print axioms saveRestoreCannotBeClaimedWithoutGrounding
#print axioms omittedEdgeCannotHideBehindSummary
#print axioms omittedReturnCannotHideBehindSummary
#print axioms mutationFrameOrImportRejectionBlocksIntegration
#print axioms everyFiniteReturningPathCloses
#print axioms identityCheckedFiniteReturnPreservesWithoutTotalTermination
#print axioms incompleteLoopCannotAuthorize
#print axioms incompleteOperationalTerminationCannotAuthorize
#print axioms checkedClassifierCoversEveryReachablePoint
#print axioms checkedOperationalGraphReturns
#print axioms finiteGraphRejectsSelfLoop
#print axioms rankedSccRejectsNondecreasingCycle
#print axioms completePremisesProduceNestedContract
#print axioms actualWorldCallReturnPreservesRequestedRegisters
#print axioms exactCallerStackArgumentReachesCallee
#print axioms calleeStaticSlotPostconditionFeedsContinuation
#print axioms callerArgumentRelationCanFlowToStaticSlot
#print axioms faultCannotSatisfyCallReturn

end StageA.InternalDirectCallCompositionSemanticExamples
"""


_INCOMPLETE_FIXTURE = r"""import StageA.RelationalInternalDirectCallComposition

namespace StageA.InternalDirectCallCompositionFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

def pe : PE32 := {
  bytes := .empty
  peOffset := 0
  entrypointRva := 0
  imageBase := 4194304
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 1
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := []
}

def context : StaticProofContext := {
  originalPe := pe
  candidatePe := pe
  originalImportCertificate := { descriptors := [] }
  candidateImportCertificate := { descriptors := [] }
  originalRelocations := []
  candidateRelocations := []
  codeMap := {
    entries := .leaf []
    originalAddresses := .leaf []
    candidateAddresses := .leaf []
  }
  dataMap := { entries := #[], originalOrder := [], candidateOrder := [] }
  roots := []
  observations := {}
}

def region : ExactRegionPair := {
  id := 0
  original := { start := 0, size := 1 }
  candidate := { start := 0, size := 1 }
}

def certificate : Certificate := {
  summaryId := 1
  caller := region
  callsite := region
  calleeEntry := region
  continuation := region
  calleeRegions := [region]
  edges := []
  returns := []
  requestedRegisters := [.esi]
}

def tree : InternalDirectCallRegisterSummary.SummaryTree := .node certificate []

end StageA.InternalDirectCallCompositionFixture
"""


_EXACT_OPERATIONAL_FIXTURE = r"""import StageA.RelationalInternalDirectCallComposition

namespace StageA.InternalDirectCallCompositionExactOperationalFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallComposition
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxHeartbeats 1000000

def pe : PE32 := {
  bytes := ByteTree.ofBytes [
    0xe8, 0x05, 0x00, 0x00, 0x00,
    0xc3,
    0x90, 0x90, 0x90, 0x90,
    0x56, 0xeb, 0x00,
    0xbe, 0x78, 0x56, 0x34, 0x12, 0xeb, 0x00,
    0x5e, 0xc3
  ]
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 22
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{
    virtualSize := 22
    virtualAddress := 0
    rawSize := 22
    rawPointer := 0
    characteristics := 0x60000020
  }]
}

def targets : List CodeTargetPair := [
  { id := 0, regionIndex := 0, originalRva := 0, candidateRva := 0 },
  { id := 1, regionIndex := 1, originalRva := 5, candidateRva := 5 },
  { id := 2, regionIndex := 10, originalRva := 10, candidateRva := 10 },
  { id := 3, regionIndex := 11, originalRva := 13, candidateRva := 13 },
  { id := 4, regionIndex := 12, originalRva := 20, candidateRva := 20 }
]

def codeMap : StaticCodeMap := {
  entries := .leaf targets
  originalAddresses := .leaf [
    { targetId := 0, kind := .canonical },
    { targetId := 1, kind := .canonical },
    { targetId := 2, kind := .canonical },
    { targetId := 3, kind := .canonical },
    { targetId := 4, kind := .canonical }
  ]
  candidateAddresses := .leaf [
    { targetId := 0, kind := .canonical },
    { targetId := 1, kind := .canonical },
    { targetId := 2, kind := .canonical },
    { targetId := 3, kind := .canonical },
    { targetId := 4, kind := .canonical }
  ]
}

def context : StaticProofContext := {
  originalPe := pe
  candidatePe := pe
  originalImportCertificate := { descriptors := [] }
  candidateImportCertificate := { descriptors := [] }
  originalRelocations := []
  candidateRelocations := []
  codeMap := codeMap
  dataMap := { entries := #[], originalOrder := [], candidateOrder := [] }
  roots := []
  observations := {}
}

def region (id start size : Nat) (root : Bool) : RegionRelation := {
  id := id
  original := { start := start, size := size }
  candidate := { start := start, size := size }
  root := root
  inputs := []
  outputs := []
  targets := targets
}

def regions : List RegionRelation := [
  region 0 0 5 true,
  region 1 5 1 false,
  region 2 10 3 false,
  region 3 13 7 false,
  region 4 20 2 false
]

def exactRegion (id start size : Nat) : ExactRegionPair := {
  id := id
  original := { start := start, size := size }
  candidate := { start := start, size := size }
}

def certificate : Certificate := {
  summaryId := 1
  caller := exactRegion 0 0 5
  callsite := exactRegion 0 0 5
  calleeEntry := exactRegion 10 10 3
  continuation := exactRegion 1 5 1
  calleeRegions := [
    exactRegion 10 10 3,
    exactRegion 11 13 7,
    exactRegion 12 20 2
  ]
  edges := [
    { sourceRegionId := 10, targetRegionId := 11, kind := .direct },
    { sourceRegionId := 11, targetRegionId := 12, kind := .direct }
  ]
  returns := [{ returnRegionId := 12, continuationRegionId := 1 }]
  requestedRegisters := [.esi]
  originalFrameBytes := 4
  candidateFrameBytes := 4
  stackWitnesses := [{
    register := .esi
    saveRegionId := 10
    restoreRegionIds := [12]
    originalFrameBytes := 4
    candidateFrameBytes := 4
    originalSaveOffset := 4
    candidateSaveOffset := 4
  }]
  graphClosureWitness := {
    nodes := [
      {
        forwardRank := 0
        reverseRank := 2
        reverseNextRegionIndex := some 1
        reverseNextEdgeIndex := some 0
      },
      {
        forwardRank := 1
        forwardParentRegionIndex := some 0
        forwardParentEdgeIndex := some 0
        reverseRank := 1
        reverseNextRegionIndex := some 2
        reverseNextEdgeIndex := some 1
      },
      {
        forwardRank := 2
        forwardParentRegionIndex := some 1
        forwardParentEdgeIndex := some 1
        reverseRank := 0
      }
    ]
  }
}

def tree : InternalDirectCallRegisterSummary.SummaryTree := .node certificate []

theorem structuralChecked :
    tree.checked pe pe [] [] = true := by
  decide

def environment : WorldExternalEnvironment := {
  result := fun _ event => { state := event.state, world := event.world }
}

def originalProgram : DecodedWorldProgram := {
  candidate := false
  context := context
  regions := regions
  externalCallSites := []
  environment := environment
}

def candidateProgram : DecodedWorldProgram := {
  candidate := true
  context := context
  regions := regions
  externalCallSites := []
  environment := environment
}

def memory : Memory :=
  Memory.write32 (fun _ => 0) 0x800000 0x40000a

def sourceState : MachineState := {
  registers := {
    eax := 0, ebx := 0, ecx := 0, edx := 0,
    esi := 0x89abcdef, edi := 0, ebp := 0, esp := 0x800000
  }
  memory := memory
}

def sourceExecution : WorldExecution :=
  .running 0 sourceState [] 0 .empty

def entryExecution : WorldExecution :=
  (originalProgram.pe32TransitionSystem.step sourceExecution).next

def bodyExecution : WorldExecution :=
  (originalProgram.pe32TransitionSystem.step entryExecution).next

def restoreExecution : WorldExecution :=
  (originalProgram.pe32TransitionSystem.step bodyExecution).next

def exitExecution : WorldExecution :=
  (originalProgram.pe32TransitionSystem.step restoreExecution).next

def candidateEntryExecution : WorldExecution :=
  (candidateProgram.pe32TransitionSystem.step sourceExecution).next

def candidateBodyExecution : WorldExecution :=
  (candidateProgram.pe32TransitionSystem.step candidateEntryExecution).next

def candidateRestoreExecution : WorldExecution :=
  (candidateProgram.pe32TransitionSystem.step candidateBodyExecution).next

def candidateExitExecution : WorldExecution :=
  (candidateProgram.pe32TransitionSystem.step candidateRestoreExecution).next

def executionState : WorldExecution -> MachineState
  | .running _ state _ _ _ => state
  | .callbackRunning _ state _ _ _ _ => state
  | .returned state _ => state
  | _ => sourceState

theorem callStepIsExact :
    originalProgram.pe32TransitionSystem.step sourceExecution = {
      next := entryExecution, observation := none
    } := by
  rfl

theorem candidateCallStepIsExact :
    candidateProgram.pe32TransitionSystem.step sourceExecution = {
      next := candidateEntryExecution, observation := none
    } := by
  rfl

theorem entryExecutionShape : entryExecution =
    .running 2 (executionState entryExecution) [1] 0 .empty := by
  rfl

theorem bodyExecutionShape : bodyExecution =
    .running 3 (executionState bodyExecution) [1] 0 .empty := by
  rfl

theorem restoreExecutionShape : restoreExecution =
    .running 4 (executionState restoreExecution) [1] 0 .empty := by
  rfl

theorem exitExecutionShape : exitExecution =
    .running 1 (executionState exitExecution) [] 0 .empty := by
  rfl

theorem candidateEntryExecutionShape : candidateEntryExecution =
    .running 2 (executionState candidateEntryExecution) [1] 0 .empty := by
  rfl

theorem candidateBodyExecutionShape : candidateBodyExecution =
    .running 3 (executionState candidateBodyExecution) [1] 0 .empty := by
  rfl

theorem candidateRestoreExecutionShape : candidateRestoreExecution =
    .running 4 (executionState candidateRestoreExecution) [1] 0 .empty := by
  rfl

theorem candidateExitExecutionShape : candidateExitExecution =
    .running 1 (executionState candidateExitExecution) [] 0 .empty := by
  rfl

theorem exactPushMutatePopReturnRun :
    WorldCallRun originalProgram 1 entryExecution [] exitExecution := by
  apply WorldCallRun.step
  · rw [entryExecutionShape]
    decide
  · rw [entryExecutionShape]
    trivial
  · apply WorldCallRun.step
    · change worldExecutionRunningTarget? bodyExecution ≠ some 1
      rw [bodyExecutionShape]
      decide
    · change worldExecutionMayProgress bodyExecution
      rw [bodyExecutionShape]
      trivial
    · apply WorldCallRun.step
      · change worldExecutionRunningTarget? restoreExecution ≠ some 1
        rw [restoreExecutionShape]
        decide
      · change worldExecutionMayProgress restoreExecution
        rw [restoreExecutionShape]
        trivial
      · change WorldCallRun originalProgram 1 exitExecution [] exitExecution
        rw [exitExecutionShape]
        exact WorldCallRun.doneRunning _ _ _ _

theorem exactCandidatePushMutatePopReturnRun :
    WorldCallRun candidateProgram 1 candidateEntryExecution []
      candidateExitExecution := by
  apply WorldCallRun.step
  · rw [candidateEntryExecutionShape]
    decide
  · rw [candidateEntryExecutionShape]
    trivial
  · apply WorldCallRun.step
    · change worldExecutionRunningTarget? candidateBodyExecution ≠ some 1
      rw [candidateBodyExecutionShape]
      decide
    · change worldExecutionMayProgress candidateBodyExecution
      rw [candidateBodyExecutionShape]
      trivial
    · apply WorldCallRun.step
      · change worldExecutionRunningTarget? candidateRestoreExecution ≠ some 1
        rw [candidateRestoreExecutionShape]
        decide
      · change worldExecutionMayProgress candidateRestoreExecution
        rw [candidateRestoreExecutionShape]
        trivial
      · change WorldCallRun candidateProgram 1 candidateExitExecution []
          candidateExitExecution
        rw [candidateExitExecutionShape]
        exact WorldCallRun.doneRunning _ _ _ _

theorem exactOriginalRunIsUnique
    {observations after}
    (other : WorldCallRun originalProgram 1 entryExecution observations after) :
    observations = [] /\ after = exitExecution := by
  rcases exactPushMutatePopReturnRun.deterministic other with
    ⟨observationsEqual, afterEqual⟩
  exact ⟨observationsEqual.symm, afterEqual.symm⟩

def callPush : DirectCallPushClaim := {
  calleeTargetId := 2
  continuationTargetId := 1
  originalReturnAddress := 0x400005
  candidateReturnAddress := 0x400005
  originalStackAddress := stackSub 4
  candidateStackAddress := stackSub 4
}

def frame : RelationalRuntimeCallFrame := {
  continuationTargetId := 1
  originalReturnAddress := 0x400005
  candidateReturnAddress := 0x400005
  originalStackAddress := 0x7ffffc
  candidateStackAddress := 0x7ffffc
}

theorem runtimeFrameExact :
    callPush.runtimeFrame context sourceState sourceState = some frame := by
  rfl

theorem runtimeFrameValid : frame.valid context = true := by
  decide

theorem runtimeFrameAtEntry :
    frame.memoryHolds (executionState entryExecution).memory
      (executionState entryExecution).memory := by
  unfold RelationalRuntimeCallFrame.memoryHolds
  constructor <;> rfl

def callerArgumentWord : RuntimeFrameArgumentWord := {
  originalOffset := 4
  candidateOffset := 4
  relation := .fixedCodePointer 2
}

theorem callerArgumentChecked :
    callerArgumentWord.checked context = true := by
  decide

theorem callerArgumentAtCalleeEntry :
    callerArgumentWord.holds context .empty frame
      (executionState entryExecution).memory
      (executionState candidateEntryExecution).memory = true := by
  decide

theorem actualRequestedRegisterPreserved
    (_run : WorldCallRun originalProgram 1 entryExecution [] exitExecution) :
    requestedCallReturnRegistersHold certificate sourceState sourceState
      (executionState exitExecution) (executionState exitExecution) := by
  simp [requestedCallReturnRegistersHold, certificate]
  decide

structure ConcreteExactPECallReturnWitness : Prop where
  structural : tree.checked pe pe [] [] = true
  call : originalProgram.pe32TransitionSystem.step sourceExecution = {
    next := entryExecution, observation := none
  }
  candidateCall : candidateProgram.pe32TransitionSystem.step sourceExecution = {
    next := candidateEntryExecution, observation := none
  }
  run : WorldCallRun originalProgram 1 entryExecution [] exitExecution
  candidateRun : WorldCallRun candidateProgram 1 candidateEntryExecution []
    candidateExitExecution
  exactFrame : callPush.runtimeFrame context sourceState sourceState = some frame
  validFrame : frame.valid context = true
  frameMemory : frame.memoryHolds (executionState entryExecution).memory
    (executionState entryExecution).memory
  callerArgument : callerArgumentWord.holds context .empty frame
    (executionState entryExecution).memory
    (executionState candidateEntryExecution).memory = true
  requested : requestedCallReturnRegistersHold certificate sourceState sourceState
    (executionState exitExecution) (executionState exitExecution)

def concreteWitness : ConcreteExactPECallReturnWitness := {
  structural := structuralChecked
  call := callStepIsExact
  candidateCall := candidateCallStepIsExact
  run := exactPushMutatePopReturnRun
  candidateRun := exactCandidatePushMutatePopReturnRun
  exactFrame := runtimeFrameExact
  validFrame := runtimeFrameValid
  frameMemory := runtimeFrameAtEntry
  callerArgument := callerArgumentAtCalleeEntry
  requested := actualRequestedRegisterPreserved exactPushMutatePopReturnRun
}

/-- The shared kernel does not yet derive `OperationalCallReturnCompleteness`
from `WorldCallRun`; the exact fixture therefore remains explicit non-authority
despite carrying a real paired PE execution witness. -/
def integratedPremises : Option (IntegratedSummaryPremises context tree) := none

theorem exactFixtureRemainsNonAuthority :
    StandaloneAcceptanceAuthority integratedPremises = false := rfl

def mutatedPe : PE32 := {
  pe with
  bytes := ByteTree.ofBytes [
    0xe8, 0x05, 0x00, 0x00, 0x00,
    0xc3,
    0x90, 0x90, 0x90, 0x90,
    0x56, 0xeb, 0x00,
    0xbe, 0x78, 0x56, 0x34, 0x12, 0xeb, 0x00,
    0x5f, 0xc3
  ]
}

def mutatedContext : StaticProofContext := {
  context with originalPe := mutatedPe, candidatePe := mutatedPe
}

def mutatedProgram : DecodedWorldProgram := {
  originalProgram with context := mutatedContext
}

def mutatedEntry : WorldExecution :=
  (mutatedProgram.pe32TransitionSystem.step sourceExecution).next

def mutatedBody : WorldExecution :=
  (mutatedProgram.pe32TransitionSystem.step mutatedEntry).next

def mutatedRestore : WorldExecution :=
  (mutatedProgram.pe32TransitionSystem.step mutatedBody).next

def mutatedExit : WorldExecution :=
  (mutatedProgram.pe32TransitionSystem.step mutatedRestore).next

theorem mutatedSummaryRejected :
    tree.checked mutatedPe mutatedPe [] [] = false := by
  decide

theorem mutatedRegisterViolation :
    (executionState mutatedExit).registers.esi ≠ sourceState.registers.esi := by
  decide

def omittedProgram : DecodedWorldProgram := {
  originalProgram with
  regions := [region 0 0 5 true, region 1 5 1 false,
    region 2 10 3 false, region 4 20 2 false]
}

def omittedEntry : WorldExecution :=
  (omittedProgram.pe32TransitionSystem.step sourceExecution).next

def omittedBody : WorldExecution :=
  (omittedProgram.pe32TransitionSystem.step omittedEntry).next

theorem omittedBodyShape : omittedBody =
    .running 3 (executionState omittedBody) [1] 0 .empty := by
  rfl

theorem omittedBodyStepBlocks :
    (omittedProgram.pe32TransitionSystem.step omittedBody).next =
      .blocked (.missingRegionBehavior 3) := by
  rw [omittedBodyShape]
  rfl

theorem omittedBodyCannotReachContinuation (observations after) :
    Not (WorldCallRun omittedProgram 1 omittedBody observations after) := by
  intro run
  cases run with
  | step notAtContinuation mayProgress tail =>
      rw [omittedBodyStepBlocks] at tail
      exact WorldCallRun.not_from_blocked omittedProgram 1
        (.missingRegionBehavior 3) _ _ tail

#print axioms exactPushMutatePopReturnRun
#print axioms exactCandidatePushMutatePopReturnRun
#print axioms structuralChecked
#print axioms concreteWitness
#print axioms callerArgumentAtCalleeEntry
#print axioms exactFixtureRemainsNonAuthority
#print axioms mutatedSummaryRejected
#print axioms mutatedRegisterViolation
#print axioms omittedBodyCannotReachContinuation

end StageA.InternalDirectCallCompositionExactOperationalFixture
"""


_ARGUMENT_STATIC_WRITE_FIXTURE = r"""import StageA.RelationalInternalDirectCallComposition

namespace StageA.InternalDirectCallArgumentStaticWriteFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallComposition

def pe : PE32 := {
  bytes := ByteTree.ofBytes [
    0xe8, 0x01, 0x00, 0x00, 0x00,
    0xc3,
    0x8b, 0x44, 0x24, 0x04,
    0xa3, 0x00, 0x10, 0x40, 0x00,
    0xc3,
    0x00, 0x00, 0x00, 0x00
  ]
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 0x1004
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{
    virtualSize := 16
    virtualAddress := 0
    rawSize := 16
    rawPointer := 0
    characteristics := 0x60000020
  }, {
    virtualSize := 4
    virtualAddress := 0x1000
    rawSize := 4
    rawPointer := 16
    characteristics := 0xc0000040
  }]
}

def targets : List CodeTargetPair := [
  { id := 0, regionIndex := 0, originalRva := 0, candidateRva := 0 },
  { id := 1, regionIndex := 1, originalRva := 5, candidateRva := 5 },
  { id := 2, regionIndex := 10, originalRva := 6, candidateRva := 6 },
  { id := 3, regionIndex := 11, originalRva := 10, candidateRva := 10 },
  { id := 4, regionIndex := 12, originalRva := 15, candidateRva := 15 }
]

def codeMap : StaticCodeMap := {
  entries := .leaf targets
  originalAddresses := .leaf [
    { targetId := 0, kind := .canonical }, { targetId := 1, kind := .canonical },
    { targetId := 2, kind := .canonical }, { targetId := 3, kind := .canonical },
    { targetId := 4, kind := .canonical }
  ]
  candidateAddresses := .leaf [
    { targetId := 0, kind := .canonical }, { targetId := 1, kind := .canonical },
    { targetId := 2, kind := .canonical }, { targetId := 3, kind := .canonical },
    { targetId := 4, kind := .canonical }
  ]
}

def slot : StaticWordRelationSlotPair := {
  id := 0
  originalAddress := 0x401000
  candidateAddress := 0x401000
  relation := .fixedCodePointer 2
}

def context : StaticProofContext := {
  originalPe := pe
  candidatePe := pe
  originalImportCertificate := { descriptors := [] }
  candidateImportCertificate := { descriptors := [] }
  originalRelocations := []
  candidateRelocations := []
  codeMap := codeMap
  dataMap := { entries := #[], originalOrder := [], candidateOrder := [] }
  staticWordRelationSlots := [slot]
  roots := []
  observations := {}
}

def region (id start size : Nat) (root : Bool) : RegionRelation := {
  id := id
  original := { start := start, size := size }
  candidate := { start := start, size := size }
  root := root
  inputs := []
  outputs := []
  targets := targets
}

def regions : List RegionRelation := [
  region 0 0 5 true,
  region 1 5 1 false,
  region 2 6 4 false,
  region 3 10 5 false,
  region 4 15 1 false
]

def environment : WorldExternalEnvironment := {
  result := fun _ event => { state := event.state, world := event.world }
}

def originalProgram : DecodedWorldProgram := {
  candidate := false
  context := context
  regions := regions
  externalCallSites := []
  environment := environment
}

def candidateProgram : DecodedWorldProgram := {
  candidate := true
  context := context
  regions := regions
  externalCallSites := []
  environment := environment
}

def memory : Memory :=
  Memory.write32 (Memory.write32 (fun _ => 0) 0x800000 0x400006)
    slot.originalAddress 0

def sourceState : MachineState := {
  registers := {
    eax := 0, ebx := 0, ecx := 0, edx := 0,
    esi := 0, edi := 0, ebp := 0, esp := 0x800000
  }
  memory := memory
}

def sourceExecution : WorldExecution := .running 0 sourceState [] 0 .empty
def entryExecution := (originalProgram.pe32TransitionSystem.step sourceExecution).next
def loadExecution := (originalProgram.pe32TransitionSystem.step entryExecution).next
def writeExecution := (originalProgram.pe32TransitionSystem.step loadExecution).next
def exitExecution := (originalProgram.pe32TransitionSystem.step writeExecution).next
def candidateEntryExecution :=
  (candidateProgram.pe32TransitionSystem.step sourceExecution).next
def candidateLoadExecution :=
  (candidateProgram.pe32TransitionSystem.step candidateEntryExecution).next
def candidateWriteExecution :=
  (candidateProgram.pe32TransitionSystem.step candidateLoadExecution).next
def candidateExitExecution :=
  (candidateProgram.pe32TransitionSystem.step candidateWriteExecution).next

def executionState : WorldExecution -> MachineState
  | .running _ state _ _ _ => state
  | .callbackRunning _ state _ _ _ _ => state
  | .returned state _ => state
  | _ => sourceState

theorem entryShape : entryExecution =
    .running 2 (executionState entryExecution) [1] 0 .empty := by rfl
theorem loadShape : loadExecution =
    .running 3 (executionState loadExecution) [1] 0 .empty := by rfl
theorem writeShape : writeExecution =
    .running 4 (executionState writeExecution) [1] 0 .empty := by rfl
theorem exitShape : exitExecution =
    .running 1 (executionState exitExecution) [] 0 .empty := by rfl
theorem candidateEntryShape : candidateEntryExecution =
    .running 2 (executionState candidateEntryExecution) [1] 0 .empty := by rfl
theorem candidateLoadShape : candidateLoadExecution =
    .running 3 (executionState candidateLoadExecution) [1] 0 .empty := by rfl
theorem candidateWriteShape : candidateWriteExecution =
    .running 4 (executionState candidateWriteExecution) [1] 0 .empty := by rfl
theorem candidateExitShape : candidateExitExecution =
    .running 1 (executionState candidateExitExecution) [] 0 .empty := by rfl

def frame : RelationalRuntimeCallFrame := {
  continuationTargetId := 1
  originalReturnAddress := 0x400005
  candidateReturnAddress := 0x400005
  originalStackAddress := 0x7ffffc
  candidateStackAddress := 0x7ffffc
}

def argument : RuntimeFrameArgumentWord := {
  originalOffset := 4
  candidateOffset := 4
  relation := .fixedCodePointer 2
}

theorem argumentChecked : argument.checked context = true := by decide

theorem argumentAtEntry : argument.holds context .empty frame
    (executionState entryExecution).memory
    (executionState candidateEntryExecution).memory = true := by decide

def exactCopy : RuntimeFrameArgumentStaticWrite argument slot frame
    (executionState entryExecution).memory
    (executionState candidateEntryExecution).memory
    (executionState exitExecution).memory
    (executionState candidateExitExecution).memory := {
  sameRelation := rfl
  originalCopied := by decide
  candidateCopied := by decide
}

theorem slotReceivesRelocatedCodePointer : slot.memoryHolds context .empty
    (executionState exitExecution).memory
    (executionState candidateExitExecution).memory = true :=
  exactCopy.slotHolds argumentAtEntry

theorem originalRunIsCanonical : WorldCallRun originalProgram 1 entryExecution []
    exitExecution := by
  apply WorldCallRun.step
  · rw [entryShape]; decide
  · rw [entryShape]; trivial
  · apply WorldCallRun.step
    · change worldExecutionRunningTarget? loadExecution ≠ some 1
      rw [loadShape]; decide
    · change worldExecutionMayProgress loadExecution
      rw [loadShape]; trivial
    · apply WorldCallRun.step
      · change worldExecutionRunningTarget? writeExecution ≠ some 1
        rw [writeShape]; decide
      · change worldExecutionMayProgress writeExecution
        rw [writeShape]; trivial
      · change WorldCallRun originalProgram 1 exitExecution [] exitExecution
        rw [exitShape]
        exact WorldCallRun.doneRunning _ _ _ _

def mutatedPe : PE32 := {
  pe with bytes := ByteTree.ofBytes [
    0xe8, 0x01, 0x00, 0x00, 0x00,
    0xc3,
    0x8b, 0x44, 0x24, 0x04,
    0xa3, 0x04, 0x10, 0x40, 0x00,
    0xc3,
    0x00, 0x00, 0x00, 0x00
  ]
}

def mutatedContext : StaticProofContext := {
  context with originalPe := mutatedPe, candidatePe := mutatedPe
}
def mutatedProgram : DecodedWorldProgram := {
  originalProgram with context := mutatedContext
}
def mutatedEntry := (mutatedProgram.pe32TransitionSystem.step sourceExecution).next
def mutatedLoad := (mutatedProgram.pe32TransitionSystem.step mutatedEntry).next
def mutatedWrite := (mutatedProgram.pe32TransitionSystem.step mutatedLoad).next

theorem mutatedDestinationDoesNotSatisfySlot :
    slot.memoryHolds mutatedContext .empty
      (executionState mutatedWrite).memory (executionState mutatedWrite).memory = false := by
  decide

#print axioms argumentAtEntry
#print axioms slotReceivesRelocatedCodePointer
#print axioms originalRunIsCanonical
#print axioms mutatedDestinationDoesNotSatisfySlot

end StageA.InternalDirectCallArgumentStaticWriteFixture
"""

_CALLER_FRAME_WORD_ENTRY_FIXTURE = r"""import StageA.RelationalInternalDirectCallComposition

namespace StageA.InternalDirectCallCallerFrameWordEntryFixture

open StageA.Formal
open StageA.Relational
open StageA.Relational.InternalDirectCallComposition

def stackAfterCall : Expr :=
  .sub (.inputReg .esp) (.constant 4)

def disjointCallBehavior : NormalizedSymbolicBehavior := {
  registers := { initialSymbolic.registers with esp := stackAfterCall }
  x87 := initialSymbolicX87
  writes := [
    (.inputReg .esp, .constant 2),
    (stackAfterCall, .constant 0x401000)
  ]
  flags := none
  outcome := .call 1 2
}

def callerWord : ReturnSlotExactWordPair := {
  originalOffset := 32
  candidateOffset := 32
}

def calleeEntryWord : ReturnSlotExactWordPair := {
  originalOffset := 36
  candidateOffset := 36
}

def checkedClaim : CallerFrameWordEntryClaim := {
  source := callerWord
  entry := calleeEntryWord
  originalStack := .subRight .input 4
  candidateStack := .subRight .input 4
  originalWrites := [.input, .subRight .input 4]
  candidateWrites := [.input, .subRight .input 4]
}

theorem derivedClaimExact :
    CallerFrameWordEntryClaim.derive? callerWord calleeEntryWord
      disjointCallBehavior disjointCallBehavior = some checkedClaim := by
  decide

theorem claimChecks :
    checkedClaim.checked disjointCallBehavior disjointCallBehavior = true := by
  decide

theorem callerWordReachesCalleeEntry
    (originalState candidateState : MachineState) :
    Memory.read32
          ((disjointCallBehavior.eval originalState).nextMachineState
            originalState).memory
          (((disjointCallBehavior.eval originalState).nextMachineState
              originalState).registers.esp + 36) =
        Memory.read32 originalState.memory (originalState.registers.esp + 32) /\
      Memory.read32
          ((disjointCallBehavior.eval candidateState).nextMachineState
            candidateState).memory
          (((disjointCallBehavior.eval candidateState).nextMachineState
              candidateState).registers.esp + 36) =
        Memory.read32 candidateState.memory (candidateState.registers.esp + 32) :=
  checkedClaim.memoryPreserved_of_checked disjointCallBehavior
    disjointCallBehavior originalState candidateState claimChecks

def overlappingBehavior : NormalizedSymbolicBehavior := {
  disjointCallBehavior with
  writes := [
    ((Expr.inputReg .esp).offset 32, .constant 0),
    (stackAfterCall, .constant 0x401000)
  ]
}

def overlappingClaim : CallerFrameWordEntryClaim := {
  checkedClaim with
  originalWrites := [.addRight .input 32, .subRight .input 4]
  candidateWrites := [.addRight .input 32, .subRight .input 4]
}

theorem overlappingWriteRejected :
    overlappingClaim.checked overlappingBehavior overlappingBehavior = false := by
  decide

#print axioms callerWordReachesCalleeEntry
#print axioms derivedClaimExact
#print axioms overlappingWriteRejected

end StageA.InternalDirectCallCallerFrameWordEntryFixture
"""


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAInternalDirectCallCompositionKernelTests(unittest.TestCase):
    source_root = (
        Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
    )

    def _compile_source(self, bundle: str, source: str, extra: dict[str, str] | None = None) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                self.source_root,
                stage_a,
                "RelationalInternalDirectCallComposition",
            )
            for filename, text in (extra or {}).items():
                (stage_a / filename).write_text(text, encoding="utf-8")
            (stage_a / f"{bundle}.lean").write_text(source, encoding="utf-8")
            return _run_lean_relational(root, bundle=bundle)

    def _assert_checked(self, result: dict) -> None:
        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 1, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)

    def test_reviewed_module_has_no_escape_hatches(self) -> None:
        source = (
            self.source_root / "RelationalInternalDirectCallComposition.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "native_decide", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        self.assertIn("RelationalSegmentRefinement", source)
        self.assertIn("RelationalExternalCallRefinement", source)
        self.assertIn("RelationalRuntimeCallFrame", source)
        self.assertIn("child : DirectCallSemanticContract", source)
        self.assertIn("RankedLoopDischarge", source)
        self.assertIn("RequestedRegisterGrounding", source)
        self.assertIn("CheckedDirectCallSummaryProvenance", source)
        self.assertIn("WorldCallRun", source)
        self.assertIn("pe32TransitionSystem.step", source)
        self.assertIn("returnsFromEverySource", source)
        self.assertIn("CheckedFiniteCallRegionExecution", source)
        self.assertIn("CallRegionTerminationCertificate", source)
        self.assertIn("FiniteCallRegionRanking", source)
        self.assertIn("RankedCallRegionSCC", source)
        self.assertIn("RuntimeFrameArgumentStaticWrite", source)
        self.assertNotIn("  lift : forall actual", source)
        self.assertNotIn("  returnsFromEverySource : forall source", source)
        self.assertIn("ActualDirectCallReturnExecution", source)
        self.assertIn("actualDirectCallReturn_preserves", source)
        self.assertIn("argumentWords", source)
        self.assertIn("actualDirectCallReturn_staticWordSlot", source)
        self.assertIn("CallerFrameWordsPreserved", source)
        self.assertIn("CheckedReturningCallerFrameWordCertificate", source)

    def test_semantic_direct_branch_nested_import_stack_and_loop_interfaces(self) -> None:
        result = self._compile_source(
            "InternalDirectCallCompositionSemanticExamples", _SEMANTIC_EXAMPLES
        )
        self._assert_checked(result)

    def test_exact_pe_push_mutate_pop_return_operational_run(self) -> None:
        result = self._compile_source(
            "InternalDirectCallCompositionExactOperationalFixture",
            _EXACT_OPERATIONAL_FIXTURE,
        )
        self._assert_checked(result)

    def test_exact_frame_argument_is_copied_to_static_code_pointer_slot(self) -> None:
        result = self._compile_source(
            "InternalDirectCallArgumentStaticWriteFixture",
            _ARGUMENT_STATIC_WRITE_FIXTURE,
        )
        self._assert_checked(result)

    def test_caller_frame_word_enters_callee_and_overlap_fails_closed(self) -> None:
        result = self._compile_source(
            "InternalDirectCallCallerFrameWordEntryFixture",
            _CALLER_FRAME_WORD_ENTRY_FIXTURE,
        )
        self._assert_checked(result)

    def test_incomplete_generated_binding_is_kernel_checked_non_authority(self) -> None:
        generated = internal_direct_call_composition_source(
            InternalDirectCallCompositionLeanBindings(
                context="StageA.InternalDirectCallCompositionFixture.context",
                summary_tree="StageA.InternalDirectCallCompositionFixture.tree",
                imports=("StageA.InternalDirectCallCompositionFixture",),
            ),
            expectation="incomplete",
        )
        result = self._compile_source(
            INTERNAL_DIRECT_CALL_COMPOSITION_LEAN_FILENAME.removesuffix(".lean"),
            generated,
            {"InternalDirectCallCompositionFixture.lean": _INCOMPLETE_FIXTURE},
        )
        self._assert_checked(result)


if __name__ == "__main__":
    unittest.main()
