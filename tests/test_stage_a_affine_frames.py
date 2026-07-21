from tests.stage_a_relational_support import *
from copy import deepcopy

from spaghetti_extractor.relational.lean.common import (
    _lean_byte_tree_definitions,
    _lean_pe,
)
from spaghetti_extractor.relational.lean.affine_frames import (
    relational_affine_frame_profile_source,
    write_relational_affine_frame_semantic_modules,
)
from spaghetti_extractor.stage_binary import StageAInputError


class StageAAffineFrameLeanTests(StageARelationalTestBase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for affine-frame proofs")
    def test_affine_family_transfer_and_canonical_shift_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture_image = _pe32_image(b"\x83\xc4\x04")
            fixture_path = Path(temporary) / "affine-frame-fixture.exe"
            fixture_path.write_bytes(fixture_image)
            fixture_binary = _parse_stage_a_pe(fixture_path)
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src" / "spaghetti_extractor" / "lean" / "StageA"
            )
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            (stage_a / "AffineFrameFixture.lean").write_text(
                """import StageA.RelationalAffineLinkedExecution

namespace StageA.AffineFrameFixture

open StageA.Formal StageA.Relational

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

"""
                + _lean_byte_tree_definitions("fixtureBytes", fixture_image)
                + "\n\n"
                + f"def fixturePe : PE32 := {_lean_pe(fixture_binary, 'fixtureBytes')}\n\n"
                + """def fixtureContext : StaticProofContext := {
  originalPe := fixturePe
  candidatePe := fixturePe
  originalImportCertificate := { descriptors := [] }
  candidateImportCertificate := { descriptors := [] }
  originalRelocations := []
  candidateRelocations := []
  codeMap := {
    entries := .empty
    originalAddresses := .empty
    candidateAddresses := .empty
  }
  dataMap := {
    entries := #[]
    originalOrder := []
    candidateOrder := []
  }
  roots := []
  observations := {}
}

def semanticRegion : RegionRelation := {
  id := 0
  original := { start := 4096, size := 3 }
  candidate := { start := 4096, size := 3 }
  root := true
  inputs := []
  outputs := []
  targets := [{
    id := 0
    originalRva := 4099
    candidateRva := 4099
  }]
}

def fallbackNormalized : NormalizedSymbolicBehavior := {
  registers := initialSymbolic.registers
  x87 := initialSymbolic.x87
  writes := []
  flags := initialSymbolic.flags
  outcome := .jump 0
}

def semanticOriginalBehavior : SymbolicBehavior :=
  (regionBehaviorWithMachineCallContracts fixtureContext.originalPe
    fixtureContext.originalImports fixtureContext.machineImportCallContracts
    semanticRegion.original).getD initialSymbolic

def semanticCandidateBehavior : SymbolicBehavior :=
  (regionBehaviorWithMachineCallContracts fixtureContext.candidatePe
    fixtureContext.candidateImports fixtureContext.machineImportCallContracts
    semanticRegion.candidate).getD initialSymbolic

def semanticOriginalNormalized : NormalizedSymbolicBehavior :=
  (normalizeSymbolicBehavior false semanticRegion.targets
    semanticOriginalBehavior).getD fallbackNormalized

def semanticCandidateNormalized : NormalizedSymbolicBehavior :=
  (normalizeSymbolicBehavior true semanticRegion.targets
    semanticCandidateBehavior).getD fallbackNormalized

def sourceFamily : ReturnSlotAffineFamily := {
  originalRegister := .esp
  originalBase := 4
  candidateRegister := .esp
  candidateBase := 20
  translationStride := 16
}

def sourceOffsets : ReturnSlotOffsetPair := {
  originalRegister := .esp
  originalOffset := 36
  candidateRegister := .esp
  candidateOffset := 52
}

def transfer : ReturnSlotTransferRule := {
  originalSourceRegister := .esp
  candidateSourceRegister := .esp
  originalTargetRegister := .ebp
  candidateTargetRegister := .ebp
  originalOutput := .addRight .input 8
  candidateOutput := .addRight .input 12
  originalDelta := 8
  candidateDelta := 12
}

def rawTargetFamily : ReturnSlotAffineFamily := {
  originalRegister := .ebp
  originalBase := 4294967292
  candidateRegister := .ebp
  candidateBase := 8
  translationStride := 16
}

def targetOffsets : ReturnSlotOffsetPair := {
  originalRegister := .ebp
  originalOffset := 28
  candidateRegister := .ebp
  candidateOffset := 40
}

def canonicalTargetFamily : ReturnSlotAffineFamily := {
  originalRegister := .ebp
  originalBase := 12
  candidateRegister := .ebp
  candidateBase := 24
  translationStride := 16
}

def canonicalShift : ReturnSlotAffineFamilyShiftClaim := {
  shiftCoefficient := 1
}

example : sourceFamily.valid = true := by decide

example : sourceFamily.contains sourceOffsets := by
  refine \u27e8rfl, rfl, 2, ?_, ?_\u27e9 <;> decide

example : transfer.applyAffineFamily sourceFamily = some rawTargetFamily := by
  decide

example : transfer.apply sourceOffsets = some targetOffsets := by decide

example : rawTargetFamily.contains targetOffsets := by
  exact transfer.applyAffineFamily_contains sourceFamily rawTargetFamily
    sourceOffsets targetOffsets (by decide) (by decide)
      (by refine \u27e8rfl, rfl, 2, ?_, ?_\u27e9 <;> decide)

example : canonicalShift.checked rawTargetFamily canonicalTargetFamily = true := by
  decide

example : canonicalTargetFamily.contains targetOffsets := by
  exact (canonicalShift.contains_iff_of_checked rawTargetFamily
    canonicalTargetFamily targetOffsets (by decide)).mp
      (transfer.applyAffineFamily_contains sourceFamily rawTargetFamily
        sourceOffsets targetOffsets (by decide) (by decide)
          (by refine \u27e8rfl, rfl, 2, ?_, ?_\u27e9 <;> decide))

def cyclicFamily : ReturnSlotAffineFamily := {
  originalRegister := .esp
  originalBase := 0
  candidateRegister := .esp
  candidateBase := 0
  translationStride := 4
}

def cyclicState : ReturnSlotAffineFrameState := {
  nodeId := 0
  family := cyclicFamily
}

def cyclicRule : ReturnSlotTransferRule := {
  originalSourceRegister := .esp
  candidateSourceRegister := .esp
  originalTargetRegister := .esp
  candidateTargetRegister := .esp
  originalOutput := .addRight .input 4
  candidateOutput := .addRight .input 4
  originalDelta := 4
  candidateDelta := 4
}

def cyclicRawTarget : ReturnSlotAffineFamily := {
  originalRegister := .esp
  originalBase := 4294967292
  candidateRegister := .esp
  candidateBase := 4294967292
  translationStride := 4
}

def cyclicTransition : ReturnSlotAffineFrameTransitionClaim := {
  source := cyclicState
  edgeId := 0
  rule := cyclicRule
  rawTargetFamily := cyclicRawTarget
  canonicalShift := { shiftCoefficient := 1 }
  target := cyclicState
}

def cyclicSeed : ReturnSlotAffineFrameSeed := {
  edgeId := 0
  nodeId := 0
  offsets := {
    originalRegister := .esp
    originalOffset := 8
    candidateRegister := .esp
    candidateOffset := 8
  }
  coefficient := 2
}

def cyclicGraph : RelationalProductGraph := {
  nodes := #[{
    id := 0
    targetId := 0
    root := true
    outgoingEdgeIds := [0]
  }]
  edges := #[{
    id := 0
    sourceNodeId := 0
    targetNodeId := 0
    sourceTargetId := 0
    targetTargetId := 0
    kind := .jump
    originalGuard := unconditionalProductGuard
    candidateGuard := unconditionalProductGuard
    infeasible := false
  }]
  rootNodeIds := [0]
}

def cyclicProfile : ReturnSlotAffineFrameProfile := {
  states := [cyclicState]
  transitions := [cyclicTransition]
  seeds := [cyclicSeed]
}

def cyclicSemanticClaim : ReturnSlotAffineFrameSemanticTransitionClaim := {
  transition := cyclicTransition
  region := semanticRegion
  originalBehavior := semanticOriginalBehavior
  candidateBehavior := semanticCandidateBehavior
  originalNormalized := semanticOriginalNormalized
  candidateNormalized := semanticCandidateNormalized
}

example : cyclicSemanticClaim.checked fixtureContext cyclicGraph = true := by
  native_decide

example : semanticOriginalNormalized.writes = [] := by native_decide

example : semanticCandidateNormalized.writes = [] := by native_decide

example : cyclicProfile.checked cyclicGraph = true := by native_decide

example : ({ cyclicProfile with transitions := [] }).checked cyclicGraph = false := by
  native_decide

example : ({ cyclicProfile with
    transitions := [{ cyclicTransition with edgeId := 1 }] }).checked cyclicGraph = false := by
  native_decide

example : ({ cyclicProfile with
    seeds := [{ cyclicSeed with coefficient := 1 }] }).checked cyclicGraph = false := by
  native_decide

example : cyclicFamily.contains cyclicSeed.offsets := by
  rcases cyclicProfile.seed_contains_of_checked cyclicGraph cyclicSeed
    (by native_decide) (by simp [cyclicProfile]) with
      ⟨state, member, node, contains⟩
  simp [cyclicProfile] at member
  subst state
  exact contains

def payloadWord : ReturnSlotExactWordPair := {
  originalOffset := 4
  candidateOffset := 8
}

def payloadImport : ImportRegisterRelation := {
  original := .ebx
  candidate := .esi
  imported := {
    dll := [116, 101, 115, 116, 46, 100, 108, 108]
    name := .symbol [102, 114, 97, 109, 101]
  }
}

def payloadRelation : RegisterRelationPair := {
  original := .edi
  candidate := .ebp
  relation := .exact
}

def affineShape : ReturnSlotAffineInventoryShape := {
  locations := .affineFamily 0
  exactWords := [payloadWord]
  preservedImports := [payloadImport]
  preservedRelations := [payloadRelation]
}

def affineInventory : ReturnSlotOffsetInventory := {
  locations := [cyclicSeed.offsets]
  exactWords := [payloadWord]
  preservedImports := [payloadImport]
  preservedRelations := [payloadRelation]
}

def secondAffineLocation : ReturnSlotOffsetPair := {
  originalRegister := .esp
  originalOffset := 12
  candidateRegister := .esp
  candidateOffset := 12
}

def secondAffineInventory : ReturnSlotOffsetInventory := {
  locations := [secondAffineLocation]
  exactWords := [payloadWord]
  preservedImports := [payloadImport]
  preservedRelations := [payloadRelation]
}

theorem affineRealizes : affineShape.Realizes cyclicProfile 0 affineInventory := by
  refine ⟨⟨rfl, rfl, rfl⟩, cyclicState, 2, cyclicSeed.offsets,
    by decide, rfl, ?_, rfl⟩
  refine ⟨rfl, rfl, ?_, ?_⟩ <;> decide

theorem secondAffineRealizes :
    affineShape.Realizes cyclicProfile 0 secondAffineInventory := by
  refine ⟨⟨rfl, rfl, rfl⟩, cyclicState, 3, secondAffineLocation,
    by decide, rfl, ?_, rfl⟩
  refine ⟨rfl, rfl, ?_, ?_⟩ <;> decide

example : cyclicSeed.offsets != secondAffineLocation := by native_decide

example : affineInventory.exactWords = affineShape.exactWords ∧
    affineInventory.preservedImports = affineShape.preservedImports ∧
    affineInventory.preservedRelations = affineShape.preservedRelations :=
  affineShape.payload_eq_of_realizes cyclicProfile 0 affineInventory affineRealizes

example : ∃ state coefficient location,
    cyclicProfile.states[0]? = some state ∧
      state.nodeId = 0 ∧
      location ∈ affineInventory.locations ∧
      state.family.ContainsAt coefficient location ∧
      state.family.contains location :=
  affineShape.realizes_affine_contains cyclicProfile 0 affineInventory 0 rfl
    affineRealizes

example : affineInventory.checked = true :=
  affineShape.realizes_checked cyclicProfile 0 affineInventory
    (by native_decide) affineRealizes

def exactShape : ReturnSlotAffineInventoryShape := {
  locations := .exact [cyclicSeed.offsets, secondAffineLocation]
  exactWords := [payloadWord]
  preservedImports := [payloadImport]
  preservedRelations := [payloadRelation]
}

def exactInventory : ReturnSlotOffsetInventory :=
  exactShape.toInventory [cyclicSeed.offsets, secondAffineLocation]

def missingFamilyProfile : ReturnSlotAffineFrameProfile := {
  states := []
  transitions := []
  seeds := []
}

example : exactShape.checked missingFamilyProfile 99 = true := by native_decide

example : exactShape.Realizes missingFamilyProfile 99 exactInventory := by
  exact ⟨⟨rfl, rfl, rfl⟩, rfl⟩

def tamperedWords : ReturnSlotOffsetInventory := {
  affineInventory with exactWords := []
}

def tamperedImports : ReturnSlotOffsetInventory := {
  affineInventory with preservedImports := []
}

def tamperedRelations : ReturnSlotOffsetInventory := {
  affineInventory with preservedRelations := []
}

example : ¬ affineShape.Realizes cyclicProfile 0 tamperedWords := by
  simp [ReturnSlotAffineInventoryShape.Realizes,
    ReturnSlotAffineInventoryShape.PayloadMatches, affineShape, tamperedWords,
    affineInventory]

example : ¬ affineShape.Realizes cyclicProfile 0 tamperedImports := by
  simp [ReturnSlotAffineInventoryShape.Realizes,
    ReturnSlotAffineInventoryShape.PayloadMatches, affineShape, tamperedImports,
    affineInventory]

example : ¬ affineShape.Realizes cyclicProfile 0 tamperedRelations := by
  simp [ReturnSlotAffineInventoryShape.Realizes,
    ReturnSlotAffineInventoryShape.PayloadMatches, affineShape, tamperedRelations,
    affineInventory]

example : affineShape.checked missingFamilyProfile 0 = false := by native_decide

example : ¬ affineShape.Realizes missingFamilyProfile 0 affineInventory := by
  simp [ReturnSlotAffineInventoryShape.Realizes, affineShape, missingFamilyProfile]

def transitionBinding : ReturnSlotAffineFrameSemanticTransitionBinding := {
  sourceShape := affineShape
  targetShape := affineShape
  claim := cyclicSemanticClaim
}

example : transitionBinding.checked fixtureContext cyclicProfile cyclicGraph = true := by
  native_decide

def tamperedBindingShape : ReturnSlotAffineInventoryShape := {
  affineShape with locations := .affineFamily 1
}

def tamperedBinding : ReturnSlotAffineFrameSemanticTransitionBinding := {
  transitionBinding with targetShape := tamperedBindingShape
}

example : tamperedBinding.checked fixtureContext cyclicProfile cyclicGraph = false := by
  native_decide

def tamperedPayloadShape : ReturnSlotAffineInventoryShape := {
  affineShape with exactWords := []
}

def tamperedPayloadBinding : ReturnSlotAffineFrameSemanticTransitionBinding := {
  transitionBinding with targetShape := tamperedPayloadShape
}

example : tamperedPayloadBinding.checked fixtureContext cyclicProfile
    cyclicGraph = false := by
  native_decide

def semanticOriginalAfter (state : MachineState) : MachineState :=
  (semanticOriginalNormalized.eval state).nextMachineState state

def semanticCandidateAfter (state : MachineState) : MachineState :=
  (semanticCandidateNormalized.eval state).nextMachineState state

theorem transitionBindingTransfersCoefficientTwo
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame) (continuation : Nat)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds fixtureContext
      originalState candidateState [frame] [continuation]
      (some affineInventory) [])
    (originalMemory :
      (semanticOriginalAfter originalState).memory = originalState.memory)
    (candidateMemory :
      (semanticCandidateAfter candidateState).memory = candidateState.memory) :
    ∃ targetInventory,
      affineShape.Realizes cyclicProfile 0 targetInventory ∧
        RelationalLinkedRuntimeCallStackHolds fixtureContext
          (semanticOriginalAfter originalState)
          (semanticCandidateAfter candidateState)
          [frame] [continuation] (some targetInventory) [] := by
  exact transitionBinding.afterNoWrite fixtureContext cyclicProfile cyclicGraph
    originalState candidateState frame continuation affineInventory
    (by native_decide) affineRealizes stackHolds originalMemory candidateMemory

theorem transitionBindingTransfersCoefficientThree
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame) (continuation : Nat)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds fixtureContext
      originalState candidateState [frame] [continuation]
      (some secondAffineInventory) [])
    (originalMemory :
      (semanticOriginalAfter originalState).memory = originalState.memory)
    (candidateMemory :
      (semanticCandidateAfter candidateState).memory = candidateState.memory) :
    ∃ targetInventory,
      affineShape.Realizes cyclicProfile 0 targetInventory ∧
        RelationalLinkedRuntimeCallStackHolds fixtureContext
          (semanticOriginalAfter originalState)
          (semanticCandidateAfter candidateState)
          [frame] [continuation] (some targetInventory) [] := by
  exact transitionBinding.afterNoWrite fixtureContext cyclicProfile cyclicGraph
    originalState candidateState frame continuation secondAffineInventory
    (by native_decide) secondAffineRealizes stackHolds originalMemory candidateMemory

def affineControlState : AffineLinkedProductControlState := {
  nodeId := 0
  continuation := some 0
  activeShape := some affineShape
  minimumDepth := 1
}

def affineControl : AffineLinkedProductControlProfile := {
  states := [affineControlState]
}

example : affineControl.checked cyclicProfile cyclicGraph = true := by
  native_decide

def ordinaryControlBinding : AffineLinkedOrdinaryTransitionBinding := {
  sourceControlStateIndex := 0
  targetControlStateIndex := 0
  edgeId := 0
  continuationTargetId := 0
  frameBinding := transitionBinding
}

example : ordinaryControlBinding.checked fixtureContext affineControl
    cyclicProfile cyclicGraph = true := by native_decide

def ordinaryControlBindings : List AffineLinkedOrdinaryTransitionBinding :=
  [ordinaryControlBinding]

example : ordinaryControlBindings.all (fun binding =>
    binding.checked fixtureContext affineControl cyclicProfile cyclicGraph) = true := by
  native_decide

example : affineOrdinaryBindingsCoverActiveNodeEdge ordinaryControlBindings
    affineControl 0 0 transitionBinding = true := by native_decide

theorem ordinaryControlDispatchSelectsRuntimeShape
    (continuations : List Nat) :
    ∃ binding ∈ ordinaryControlBindings,
      binding.checked fixtureContext affineControl cyclicProfile cyclicGraph = true ∧
        binding.edgeId = 0 ∧
        binding.frameBinding.claim.transition.source.nodeId = 0 ∧
        binding.frameBinding = transitionBinding ∧
        0 = binding.continuationTargetId ∧
        binding.frameBinding.sourceShape.Realizes cyclicProfile
          binding.frameBinding.claim.transition.source.nodeId affineInventory := by
  exact affineOrdinaryBinding_of_allowed ordinaryControlBindings fixtureContext
    affineControl cyclicProfile cyclicGraph transitionBinding 0 0 0 continuations affineInventory
    (by native_decide) (by native_decide) (by
      refine ⟨by native_decide, affineControlState, by simp [affineControl], ?_,
        by simp [affineControlState]⟩
      exact ⟨rfl, rfl, by simpa [affineControlState] using affineRealizes⟩)

example : ordinaryControlBinding.frameBinding.checked fixtureContext
    cyclicProfile cyclicGraph = true :=
  ordinaryControlBinding.frame_checked_of_checked fixtureContext affineControl
    cyclicProfile cyclicGraph (by native_decide)

def wrongControlEdge : AffineLinkedOrdinaryTransitionBinding := {
  ordinaryControlBinding with edgeId := 1
}

def missingControlSource : AffineLinkedOrdinaryTransitionBinding := {
  ordinaryControlBinding with sourceControlStateIndex := 1
}

def wrongControlContinuation : AffineLinkedOrdinaryTransitionBinding := {
  ordinaryControlBinding with continuationTargetId := 1
}

example : wrongControlEdge.checked fixtureContext affineControl
    cyclicProfile cyclicGraph = false := by native_decide

example : missingControlSource.checked fixtureContext affineControl
    cyclicProfile cyclicGraph = false := by native_decide

example : wrongControlContinuation.checked fixtureContext affineControl
    cyclicProfile cyclicGraph = false := by native_decide

theorem ordinaryControlBindingTransfersNested
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds fixtureContext
      originalState candidateState (frame :: frames) (0 :: continuations)
      (some affineInventory) links)
    (originalMemory :
      (semanticOriginalAfter originalState).memory = originalState.memory)
    (candidateMemory :
      (semanticCandidateAfter candidateState).memory = candidateState.memory) :
    ∃ targetInventory,
      affineShape.Realizes cyclicProfile 0 targetInventory ∧
        RelationalLinkedRuntimeCallStackHolds fixtureContext
          (semanticOriginalAfter originalState)
          (semanticCandidateAfter candidateState)
          (frame :: frames) (0 :: continuations) (some targetInventory) links ∧
        affineControl.Allows cyclicProfile cyclicGraph 0
          (0 :: continuations) (some targetInventory) := by
  exact ordinaryControlBinding.afterNoWriteNested fixtureContext affineControl
    cyclicProfile cyclicGraph originalState candidateState frame frames 0
    continuations links affineInventory (by native_decide) affineRealizes rfl
    stackHolds originalMemory candidateMemory

theorem ordinaryControlBindingTransfersNestedFacts
    (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds fixtureContext
      originalState candidateState (frame :: frames) (0 :: continuations)
      (some affineInventory) links)
    (factsHold : RelationalLinkedRuntimeCallFactsHold fixtureContext world
      (some affineInventory) originalState.registers candidateState.registers)
    (originalMemory :
      (semanticOriginalAfter originalState).memory = originalState.memory)
    (candidateMemory :
      (semanticCandidateAfter candidateState).memory = candidateState.memory) :
    ∃ targetInventory,
      affineShape.Realizes cyclicProfile 0 targetInventory ∧
        RelationalLinkedRuntimeCallStackHolds fixtureContext
          (semanticOriginalAfter originalState)
          (semanticCandidateAfter candidateState)
          (frame :: frames) (0 :: continuations) (some targetInventory) links ∧
        affineControl.Allows cyclicProfile cyclicGraph 0
          (0 :: continuations) (some targetInventory) ∧
        RelationalLinkedRuntimeCallFactsHold fixtureContext world
          (some targetInventory)
          (semanticOriginalNormalized.eval originalState).registers
          (semanticCandidateNormalized.eval candidateState).registers := by
  exact ordinaryControlBinding.afterNoWriteNestedWithFacts fixtureContext
    affineControl cyclicProfile cyclicGraph world originalState candidateState
    frame frames 0 continuations links affineInventory (by native_decide)
    affineRealizes rfl stackHolds factsHold originalMemory candidateMemory

theorem ordinaryControlBindingProducesLinkedSuccessor
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (eventIndex : Nat)
    (targetInvariant : StateInvariant)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds fixtureContext
      originalState candidateState (frame :: frames) (0 :: continuations)
      (some affineInventory) links)
    (linksAllowed : affineControl.LinksAllowed cyclicProfile cyclicGraph links)
    (factsHold : RelationalLinkedRuntimeCallFactsHold fixtureContext world
      (some affineInventory) originalState.registers candidateState.registers)
    (targetInvariantFound : invariants.nodeInvariants[0]? = some targetInvariant)
    (targetReachable : reachability.contains 0 = true)
    (stackTargetsMapped : RelationalRuntimeCallTargetsMapped cyclicGraph reachability
      (0 :: continuations))
    (nextStatesRelated : StateRel fixtureContext world targetInvariant
      (semanticOriginalAfter originalState)
      (semanticCandidateAfter candidateState))
    (originalMemory :
      (semanticOriginalAfter originalState).memory = originalState.memory)
    (candidateMemory :
      (semanticCandidateAfter candidateState).memory = candidateState.memory) :
    LinkedWorldExecutionsRelated fixtureContext cyclicGraph invariants reachability
      (affineControl.authority cyclicProfile cyclicGraph) callbackTargets sites
      (.running 0 (semanticOriginalAfter originalState)
        (0 :: continuations) eventIndex world)
      (.running 0 (semanticCandidateAfter candidateState)
        (0 :: continuations) eventIndex world) := by
  exact ordinaryControlBinding.nextRunningRelated fixtureContext affineControl
    cyclicProfile cyclicGraph invariants reachability callbackTargets sites world
    originalState candidateState frame frames 0 continuations links affineInventory
    eventIndex cyclicGraph.nodes[0] targetInvariant (by native_decide) affineRealizes
    rfl stackHolds linksAllowed factsHold (by native_decide) targetInvariantFound
    targetReachable stackTargetsMapped nextStatesRelated originalMemory candidateMemory

example : affineControl.Allows cyclicProfile cyclicGraph 0 [0]
    (some affineInventory) := by
  refine ⟨by native_decide, affineControlState, by simp [affineControl], ?_, by decide⟩
  exact ⟨rfl, rfl, by simpa [affineControlState] using affineRealizes⟩

def shallowAuthority : LinkedControlAuthority :=
  affineControl.shallowAuthority cyclicProfile cyclicGraph

example : shallowAuthority.allows 0 [0] (some affineInventory) := by
  change affineControl.Allows cyclicProfile cyclicGraph 0 [0]
    (some affineInventory)
  refine ⟨by native_decide, affineControlState, by simp [affineControl], ?_, by decide⟩
  exact ⟨rfl, rfl, by simpa [affineControlState] using affineRealizes⟩

example : shallowAuthority.linksAllowed [] := rfl

example : ¬ shallowAuthority.linksAllowed [{
    callSourceTargetId := 0
    originalGap := 4
    candidateGap := 4
  }] := by
  simp [shallowAuthority,
    AffineLinkedProductControlProfile.shallowAuthority]

/- A caller, callee-entry, and resume graph for nested affine links.  Both the
inner and suspended inventories are deliberately checked at the callee-entry
node: the suspended inventory uses the post-push register state. -/
def nestedInnerState : ReturnSlotAffineFrameState := {
  nodeId := 1
  family := cyclicFamily
}

def nestedResumeState : ReturnSlotAffineFrameState := {
  nodeId := 2
  family := cyclicFamily
}

def nestedInnerTransition : ReturnSlotAffineFrameTransitionClaim := {
  source := nestedInnerState
  edgeId := 1
  rule := cyclicRule
  rawTargetFamily := cyclicRawTarget
  canonicalShift := { shiftCoefficient := 1 }
  target := nestedInnerState
}

def nestedResumeTransition : ReturnSlotAffineFrameTransitionClaim := {
  source := nestedResumeState
  edgeId := 2
  rule := cyclicRule
  rawTargetFamily := cyclicRawTarget
  canonicalShift := { shiftCoefficient := 1 }
  target := nestedResumeState
}

def nestedGraph : RelationalProductGraph := {
  nodes := #[
    { id := 0, targetId := 10, root := true, outgoingEdgeIds := [0] },
    { id := 1, targetId := 11, root := false, outgoingEdgeIds := [1] },
    { id := 2, targetId := 12, root := false, outgoingEdgeIds := [2] }
  ]
  edges := #[
    {
      id := 0
      sourceNodeId := 0
      targetNodeId := 1
      sourceTargetId := 10
      targetTargetId := 11
      kind := .call
      originalGuard := unconditionalProductGuard
      candidateGuard := unconditionalProductGuard
      infeasible := false
    },
    {
      id := 1
      sourceNodeId := 1
      targetNodeId := 1
      sourceTargetId := 11
      targetTargetId := 11
      kind := .jump
      originalGuard := unconditionalProductGuard
      candidateGuard := unconditionalProductGuard
      infeasible := false
    },
    {
      id := 2
      sourceNodeId := 2
      targetNodeId := 2
      sourceTargetId := 12
      targetTargetId := 12
      kind := .jump
      originalGuard := unconditionalProductGuard
      candidateGuard := unconditionalProductGuard
      infeasible := false
    }
  ]
  rootNodeIds := [0]
}

def nestedAffineProfile : ReturnSlotAffineFrameProfile := {
  states := [nestedInnerState, nestedResumeState]
  transitions := [nestedInnerTransition, nestedResumeTransition]
  seeds := []
}

def nestedInnerShape : ReturnSlotAffineInventoryShape := {
  locations := .affineFamily 0
  exactWords := [payloadWord]
  preservedImports := [payloadImport]
  preservedRelations := [payloadRelation]
}

def nestedResumeShape : ReturnSlotAffineInventoryShape := {
  locations := .affineFamily 1
  exactWords := [payloadWord]
  preservedImports := [payloadImport]
  preservedRelations := [payloadRelation]
}

def thirdAffineLocation : ReturnSlotOffsetPair := {
  originalRegister := .esp
  originalOffset := 16
  candidateRegister := .esp
  candidateOffset := 16
}

def thirdAffineInventory : ReturnSlotOffsetInventory := {
  locations := [thirdAffineLocation]
  exactWords := [payloadWord]
  preservedImports := [payloadImport]
  preservedRelations := [payloadRelation]
}

theorem nestedInnerTwoRealizes :
    nestedInnerShape.Realizes nestedAffineProfile 1 affineInventory := by
  refine ⟨⟨rfl, rfl, rfl⟩, nestedInnerState, 2, cyclicSeed.offsets,
    by decide, rfl, ?_, rfl⟩
  refine ⟨rfl, rfl, ?_, ?_⟩ <;> decide

theorem nestedInnerThreeRealizes :
    nestedInnerShape.Realizes nestedAffineProfile 1 secondAffineInventory := by
  refine ⟨⟨rfl, rfl, rfl⟩, nestedInnerState, 3, secondAffineLocation,
    by decide, rfl, ?_, rfl⟩
  refine ⟨rfl, rfl, ?_, ?_⟩ <;> decide

theorem nestedInnerFourRealizes :
    nestedInnerShape.Realizes nestedAffineProfile 1 thirdAffineInventory := by
  refine ⟨⟨rfl, rfl, rfl⟩, nestedInnerState, 4, thirdAffineLocation,
    by decide, rfl, ?_, rfl⟩
  refine ⟨rfl, rfl, ?_, ?_⟩ <;> decide

theorem nestedResumeTwoRealizes :
    nestedResumeShape.Realizes nestedAffineProfile 2 affineInventory := by
  refine ⟨⟨rfl, rfl, rfl⟩, nestedResumeState, 2, cyclicSeed.offsets,
    by decide, rfl, ?_, rfl⟩
  refine ⟨rfl, rfl, ?_, ?_⟩ <;> decide

theorem nestedResumeThreeRealizes :
    nestedResumeShape.Realizes nestedAffineProfile 2 secondAffineInventory := by
  refine ⟨⟨rfl, rfl, rfl⟩, nestedResumeState, 3, secondAffineLocation,
    by decide, rfl, ?_, rfl⟩
  refine ⟨rfl, rfl, ?_, ?_⟩ <;> decide

def nestedLinkShape : RelationalRuntimeCallFrameAffineLinkShape := {
  callEdgeId := 0
  callSourceNodeId := 0
  callSourceTargetId := 10
  innerInventoryNodeId := 1
  suspendedInventoryNodeId := 1
  resumeInventoryNodeId := 2
  resumeTargetId := 12
  resumeContinuation := 99
  originalGap := 4
  candidateGap := 4
  innerShape := nestedInnerShape
  suspendedShape := nestedInnerShape
  resumeShape := nestedResumeShape
}

def nestedLinkCoefficientTwo : RelationalRuntimeCallFrameLink := {
  callSourceTargetId := 10
  resumeNodeId := 2
  resumeTargetId := 12
  resumeContinuation := 99
  innerInventory := affineInventory
  suspendedInventory := secondAffineInventory
  resumeInventory := affineInventory
  originalGap := 4
  candidateGap := 4
}

def nestedLinkCoefficientThree : RelationalRuntimeCallFrameLink := {
  callSourceTargetId := 10
  resumeNodeId := 2
  resumeTargetId := 12
  resumeContinuation := 99
  innerInventory := secondAffineInventory
  suspendedInventory := thirdAffineInventory
  resumeInventory := secondAffineInventory
  originalGap := 4
  candidateGap := 4
}

theorem nestedLinkTwoRealizes :
    nestedLinkShape.Realizes nestedAffineProfile nestedLinkCoefficientTwo := by
  exact {
    linkChecked := by native_decide
    callSourceTargetExact := rfl
    resumeNodeExact := rfl
    resumeTargetExact := rfl
    resumeContinuationExact := rfl
    originalGapExact := rfl
    candidateGapExact := rfl
    innerRealizes := nestedInnerTwoRealizes
    suspendedRealizes := nestedInnerThreeRealizes
    resumeRealizes := nestedResumeTwoRealizes
  }

theorem nestedLinkThreeRealizes :
    nestedLinkShape.Realizes nestedAffineProfile nestedLinkCoefficientThree := by
  exact {
    linkChecked := by native_decide
    callSourceTargetExact := rfl
    resumeNodeExact := rfl
    resumeTargetExact := rfl
    resumeContinuationExact := rfl
    originalGapExact := rfl
    candidateGapExact := rfl
    innerRealizes := nestedInnerThreeRealizes
    suspendedRealizes := nestedInnerFourRealizes
    resumeRealizes := nestedResumeThreeRealizes
  }

theorem transitionBindingTransfersWithDormantLink
    (originalState candidateState : MachineState)
    (frame dormantFrame : RelationalRuntimeCallFrame)
    (continuation dormantContinuation : Nat)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds fixtureContext
      originalState candidateState [frame, dormantFrame]
      [continuation, dormantContinuation] (some affineInventory)
      [nestedLinkCoefficientTwo])
    (originalMemory :
      (semanticOriginalAfter originalState).memory = originalState.memory)
    (candidateMemory :
      (semanticCandidateAfter candidateState).memory = candidateState.memory) :
    ∃ targetInventory,
      affineShape.Realizes cyclicProfile 0 targetInventory ∧
        RelationalLinkedRuntimeCallStackHolds fixtureContext
          (semanticOriginalAfter originalState)
          (semanticCandidateAfter candidateState)
          [frame, dormantFrame] [continuation, dormantContinuation]
          (some targetInventory) [nestedLinkCoefficientTwo] := by
  exact transitionBinding.afterNoWriteNested fixtureContext cyclicProfile
    cyclicGraph originalState candidateState frame [dormantFrame] continuation
    [dormantContinuation] [nestedLinkCoefficientTwo] affineInventory
    (by native_decide) affineRealizes stackHolds originalMemory candidateMemory

example : nestedLinkCoefficientTwo.innerInventory.locations !=
    nestedLinkCoefficientThree.innerInventory.locations := by native_decide

def nestedResumeControlState : AffineLinkedProductControlState := {
  nodeId := 2
  continuation := some 99
  activeShape := some nestedResumeShape
  minimumDepth := 1
}

def nestedControl : AffineLinkedProductControlProfile := {
  states := [nestedResumeControlState]
  linkShapes := [nestedLinkShape]
}

example : nestedAffineProfile.checked nestedGraph = true := by native_decide

example : nestedLinkShape.checked nestedAffineProfile nestedGraph = true := by
  native_decide

example : nestedControl.checked nestedAffineProfile nestedGraph = true := by
  native_decide

theorem nestedLinksAllowed : nestedControl.LinksAllowed nestedAffineProfile
    nestedGraph [nestedLinkCoefficientTwo, nestedLinkCoefficientThree] := by
  apply AffineLinkedProductControlProfile.LinksAllowed.cons nestedControl
    nestedAffineProfile nestedGraph nestedLinkShape nestedLinkCoefficientTwo
  · native_decide
  · exact nestedLinkTwoRealizes
  · apply AffineLinkedProductControlProfile.LinksAllowed.cons nestedControl
      nestedAffineProfile nestedGraph nestedLinkShape nestedLinkCoefficientThree
    · native_decide
    · exact nestedLinkThreeRealizes
    · exact AffineLinkedProductControlProfile.LinksAllowed.nil nestedControl
        nestedAffineProfile nestedGraph (by native_decide)

def nestedAuthority : LinkedControlAuthority :=
  nestedControl.authority nestedAffineProfile nestedGraph

example : nestedAuthority.linksAllowed
    [nestedLinkCoefficientTwo, nestedLinkCoefficientThree] := nestedLinksAllowed

example : nestedAuthority.linksAllowed [nestedLinkCoefficientThree] := by
  exact AffineLinkedProductControlProfile.LinksAllowed.tail nestedControl
    nestedAffineProfile nestedGraph nestedLinkCoefficientTwo
    [nestedLinkCoefficientThree] nestedLinksAllowed

example : nestedControl.selectsUniqueResumeShape nestedAffineProfile nestedGraph
    12 nestedLinkShape = true := by native_decide

example : nestedControl.Allows nestedAffineProfile nestedGraph 2 [99]
    (some affineInventory) := by
  exact nestedControl.allowsResumeOfRealizedHead nestedAffineProfile nestedGraph
    nestedLinkShape nestedLinkCoefficientTwo [] [] (by native_decide)
      (AffineLinkedProductControlProfile.LinksAllowed.cons nestedControl
        nestedAffineProfile nestedGraph nestedLinkShape nestedLinkCoefficientTwo []
        (by native_decide) nestedLinkTwoRealizes
        (AffineLinkedProductControlProfile.LinksAllowed.nil nestedControl
          nestedAffineProfile nestedGraph (by native_decide)))

def tamperedNestedEdgeShape : RelationalRuntimeCallFrameAffineLinkShape := {
  nestedLinkShape with callEdgeId := 3
}

def tamperedNestedNodeShape : RelationalRuntimeCallFrameAffineLinkShape := {
  nestedLinkShape with suspendedInventoryNodeId := 0
}

def tamperedNestedGapShape : RelationalRuntimeCallFrameAffineLinkShape := {
  nestedLinkShape with originalGap := 3
}

example : tamperedNestedEdgeShape.checked nestedAffineProfile nestedGraph = false := by
  native_decide

example : tamperedNestedNodeShape.checked nestedAffineProfile nestedGraph = false := by
  native_decide

example : tamperedNestedGapShape.checked nestedAffineProfile nestedGraph = false := by
  native_decide

def tamperedNestedGapLink : RelationalRuntimeCallFrameLink := {
  nestedLinkCoefficientTwo with originalGap := 8
}

def tamperedNestedTargetLink : RelationalRuntimeCallFrameLink := {
  nestedLinkCoefficientTwo with resumeTargetId := 13
}

def tamperedNestedContinuationLink : RelationalRuntimeCallFrameLink := {
  nestedLinkCoefficientTwo with resumeContinuation := 100
}

example : ¬ nestedLinkShape.Realizes nestedAffineProfile tamperedNestedGapLink := by
  intro realized
  have impossible := realized.originalGapExact
  simp [tamperedNestedGapLink, nestedLinkCoefficientTwo,
    nestedLinkShape] at impossible

example : ¬ nestedLinkShape.Realizes nestedAffineProfile
    tamperedNestedTargetLink := by
  intro realized
  have impossible := realized.resumeTargetExact
  simp [tamperedNestedTargetLink, nestedLinkCoefficientTwo,
    nestedLinkShape] at impossible

example : ¬ nestedLinkShape.Realizes nestedAffineProfile
    tamperedNestedContinuationLink := by
  intro realized
  have impossible := realized.resumeContinuationExact
  simp [tamperedNestedContinuationLink, nestedLinkCoefficientTwo,
    nestedLinkShape] at impossible

def tamperedNestedPayloadInventory : ReturnSlotOffsetInventory := {
  affineInventory with exactWords := []
}

def tamperedNestedPayloadLink : RelationalRuntimeCallFrameLink := {
  nestedLinkCoefficientTwo with innerInventory := tamperedNestedPayloadInventory
}

example : ¬ nestedLinkShape.Realizes nestedAffineProfile
    tamperedNestedPayloadLink := by
  intro realized
  have impossible := realized.innerRealizes.1.1
  simp [tamperedNestedPayloadLink, tamperedNestedPayloadInventory,
    nestedLinkCoefficientTwo, nestedLinkShape, nestedInnerShape] at impossible

end StageA.AffineFrameFixture
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                lean_dir, bundle="AffineFrameFixture"
            )
            self.assertEqual(result["status"], "checked", result)
            self.assertNotIn("sorryAx", result["stdout"])


class StageAAffineFrameGeneratorTests(unittest.TestCase):
    @staticmethod
    def _family(original_base, candidate_base):
        return {
            "original_register": "esp",
            "original_base": original_base,
            "candidate_register": "esp",
            "candidate_base": candidate_base,
            "translation_stride": 4,
            "cardinality": 2**30,
        }

    @staticmethod
    def _rule():
        return {
            "original_source_register": "esp",
            "candidate_source_register": "esp",
            "original_target_register": "esp",
            "candidate_target_register": "esp",
            "original_output_witness": {"kind": "input"},
            "candidate_output_witness": {"kind": "input"},
            "original_delta": 0,
            "candidate_delta": 0,
        }

    @classmethod
    def _transition(
        cls, transition_id, source_state_id, target_state_id, edge_id, states
    ):
        source = states[source_state_id]
        target = states[target_state_id]
        return {
            "id": transition_id,
            "source_state_id": source_state_id,
            "target_state_id": target_state_id,
            "source_node": source["node_id"],
            "source_family": deepcopy(source["family"]),
            "edge_index": edge_id,
            "rule": cls._rule(),
            "raw_target_family": deepcopy(target["family"]),
            "canonical_shift_coefficient": 0,
            "target_node": target["node_id"],
            "target_family": deepcopy(target["family"]),
        }

    @classmethod
    def _artifact(cls):
        states = [
            {
                "id": 0,
                "node_id": 0,
                "family": cls._family(0, 8),
                "seed_rooted": False,
            },
            {
                "id": 1,
                "node_id": 0,
                "family": cls._family(4, 12),
                "seed_rooted": True,
            },
            {
                "id": 2,
                "node_id": 1,
                "family": cls._family(4, 12),
                "seed_rooted": True,
            },
        ]
        transitions = [
            cls._transition(0, 0, 0, 0, states),
            cls._transition(1, 1, 2, 1, states),
            cls._transition(2, 2, 1, 2, states),
        ]
        transitions[0]["seed_rooted"] = False
        transitions[1]["seed_rooted"] = True
        transitions[2]["seed_rooted"] = True
        return {
            "format": "stage-a-runtime-frame-affine-viability-v1",
            "certificate": {
                "viable_families": states,
                "viable_transitions": transitions,
                "viable_seeds": [{
                    "id": 0,
                    "edge_index": 3,
                    "source_node_id": 1,
                    "node_id": 0,
                    "target_state_id": 1,
                    "coefficient": 1,
                    "location": {
                        "original_register": "esp",
                        "original": 8,
                        "candidate_register": "esp",
                        "candidate": 16,
                    },
                    "direct_call_push_claim": {
                        "callee_target_id": 0,
                        "continuation_target_id": 0,
                        "original_return_address": 4096,
                        "candidate_return_address": 4096,
                        "original_stack_address": {
                            "op": "input_reg",
                            "reg": "esp",
                        },
                        "candidate_stack_address": {
                            "op": "input_reg",
                            "reg": "esp",
                        },
                    },
                }],
                "required_transition_bindings": [
                    {
                        "source_state_id": transition_id,
                        "edge_index": transition_id,
                        "candidate_transition_ids": [transition_id],
                        "status": "selected",
                        "selected_transition_id": transition_id,
                    }
                    for transition_id in range(3)
                ],
                "seed_rooted_state_ids": [1, 2],
                "seed_rooted_transition_ids": [1, 2],
                "orphan_state_ids": [0],
                "orphan_transition_ids": [0],
            },
        }

    @staticmethod
    def _semantic_inputs():
        return {
            "contract": {"regions": [{}, {}]},
            "product_graph": {
                "nodes": [
                    {"id": 0, "target_id": 0},
                    {"id": 1, "target_id": 1},
                ],
                "edges": [{
                    "id": 3,
                    "source_node_id": 1,
                    "target_node_id": 0,
                }],
            },
            "decode_chunk_regions": [[0, 1]],
        }

    def test_generator_uses_explicit_ids_seed_binding_and_rooted_inventory(self):
        artifact = self._artifact()

        profile = relational_affine_frame_profile_source(artifact)

        self.assertNotIn("runtimeFrameAffineTransition0", profile)
        self.assertIn("def runtimeFrameAffineTransition1", profile)
        self.assertIn("def runtimeFrameAffineTransition2", profile)
        self.assertIn("coefficient := BitVec.ofNat 32 1", profile)
        state_inventory = profile[
            profile.index("def runtimeFrameAffineStates"):
            profile.index("def runtimeFrameAffineTransition1")
        ]
        self.assertEqual(state_inventory.count("{ nodeId := 0, family :="), 1)

        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            modules = write_relational_affine_frame_semantic_modules(
                lean_dir,
                artifact,
                **self._semantic_inputs(),
            )
            chunk = (
                lean_dir / "StageA" / "RelationalAffineFrameSemanticChunk0.lean"
            ).read_text(encoding="utf-8")

        self.assertEqual(modules[-1], "RelationalAffineFrameSemanticProfile")
        self.assertNotIn("runtimeFrameAffineSemanticTransition0", chunk)
        self.assertLess(
            chunk.index("runtimeFrameAffineSemanticTransition1"),
            chunk.index("runtimeFrameAffineSemanticTransition2"),
        )

    def test_generator_rejects_malformed_explicit_affine_authority(self):
        def missing_state_id(certificate):
            del certificate["viable_families"][0]["id"]

        def duplicate_transition_id(certificate):
            certificate["viable_transitions"][1]["id"] = 0

        def noncanonical_seed_id(certificate):
            certificate["viable_seeds"][0]["id"] = 1

        def unknown_target_reference(certificate):
            certificate["viable_transitions"][1]["target_state_id"] = 99

        def missing_target_reference(certificate):
            del certificate["viable_transitions"][1]["target_state_id"]

        def tampered_target_payload(certificate):
            certificate["viable_transitions"][1]["target_family"] = self._family(
                8, 16
            )

        def tampered_seed_coefficient(certificate):
            certificate["viable_seeds"][0]["coefficient"] = 0

        def missing_seed_coefficient(certificate):
            del certificate["viable_seeds"][0]["coefficient"]

        def ambiguous_binding(certificate):
            binding = certificate["required_transition_bindings"][1]
            binding["status"] = "blocked_ambiguity"
            del binding["selected_transition_id"]

        def missing_selected_binding(certificate):
            del certificate["required_transition_bindings"][2]

        def request_orphan_state(certificate):
            certificate["seed_rooted_state_ids"] = [0, 1, 2]

        cases = [
            ("missing state id", missing_state_id, "natural number"),
            ("duplicate transition id", duplicate_transition_id, "duplicate ids"),
            ("noncanonical seed id", noncanonical_seed_id, "canonical"),
            ("unknown target reference", unknown_target_reference, "unknown state"),
            ("missing target reference", missing_target_reference, "natural number"),
            ("tampered target payload", tampered_target_payload, "target payload"),
            ("tampered seed coefficient", tampered_seed_coefficient, "coefficient"),
            ("missing seed coefficient", missing_seed_coefficient, "32-bit"),
            ("ambiguous binding", ambiguous_binding, "invalid ambiguity evidence"),
            ("missing selected binding", missing_selected_binding, "exactly covered"),
            ("orphan requested", request_orphan_state, "exact seed closure"),
        ]
        for name, mutate, message in cases:
            with self.subTest(name=name):
                artifact = deepcopy(self._artifact())
                mutate(artifact["certificate"])
                with self.assertRaisesRegex(StageAInputError, message):
                    relational_affine_frame_profile_source(artifact)

    def test_semantic_generator_rejects_tampered_selected_binding(self):
        artifact = self._artifact()
        artifact["certificate"]["required_transition_bindings"][1][
            "selected_transition_id"
        ] = 2

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                StageAInputError, "invalid selection"
            ):
                write_relational_affine_frame_semantic_modules(
                    Path(temporary),
                    artifact,
                    **self._semantic_inputs(),
                )


if __name__ == "__main__":
    unittest.main()
