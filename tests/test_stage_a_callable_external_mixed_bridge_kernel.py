from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


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


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageACallableExternalMixedBridgeKernelTests(unittest.TestCase):
    def test_bridge_and_fail_closed_fixtures_are_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        layer = (
            source_root / "RelationalCallableExternalMixedBridge.lean"
        ).read_text(encoding="utf-8")
        self.assertNotIn("native_decide", layer)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", layer), marker)
        self.assertNotIn("MixedWorldAcceptanceCertificate", layer)
        self.assertNotIn("NativeCallableObservationProjectionPremise", layer)
        self.assertIn("indirectTargetsValid", layer)
        self.assertIn("ExactDecodedOriginalCallableProgramBinding.ofWithCallable", layer)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalCallableExternalMixedBridge"
            )
            (stage_a / "CallableExternalMixedBridgeKernel.lean").write_text(
                _KERNEL_SOURCE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="CallableExternalMixedBridgeKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 7, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


_KERNEL_SOURCE = r"""import StageA.RelationalCallableExternalMixedBridge

namespace StageA.CallableExternalMixedBridgeKernel

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalCapability
open StageA.Relational.CallableExternalExecution
open StageA.Relational.CallableExternalMixedBridge
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

def pe : PE32 := {
  bytes := .empty
  peOffset := 0
  entrypointRva := 4096
  imageBase := 4194304
  sectionAlignment := 4096
  fileAlignment := 512
  sizeOfImage := 12288
  sizeOfHeaders := 512
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{
    virtualSize := 1
    virtualAddress := 4096
    rawSize := 0
    rawPointer := 0
    characteristics := 0x60000020
  }]
}

def codeMap : StaticCodeMap := {
  entries := .leaf [{ id := 0, originalRva := 4096, candidateRva := 4096 }]
  originalAddresses := .leaf [{ targetId := 0, kind := .canonical }]
  candidateAddresses := .leaf [{ targetId := 0, kind := .canonical }]
}

def context : StaticProofContext := {
  originalPe := pe
  candidatePe := pe
  originalImportCertificate := { descriptors := [] }
  candidateImportCertificate := { descriptors := [] }
  originalRelocations := []
  candidateRelocations := []
  codeMap
  dataMap := { entries := #[], originalOrder := [], candidateOrder := [] }
  roots := []
  observations := {}
}

def capability : CallableExternalCapability := {
  id := 7
  resourceId := 7
  resolverContractId := 2
  resolverSiteId := 3
}

def abi : ResolvedExternalABIContract := {
  id := 11
  capabilityId := 7
  transfer := .call
  argumentSources := []
  stackResultDelta := 0
  preservedRegisters := []
  clobberedRegisters := []
  memoryEffect := .none
}

def resource : OpaqueResourcePair := {
  id := 7
  original := BitVec.ofNat 32 7340032
  candidate := BitVec.ofNat 32 7405568
}

def beforeWorld : RelationalWorld := {}

def issuedWorld : RelationalWorld := {
  opaqueResources := [resource]
}

def callableProgram : OriginalCallableProgram := {
  context
  resolverContracts := []
  capabilities := [capability]
  resolvedABIContracts := [abi]
  externalSites := []
}

def kernelFrontier : CandidateKernelCallableFrontier :=
  canonicalCandidateKernelCallableFrontier [capability] [abi]

example : CallableWorldValidity context beforeWorld := by
  exact ⟨by decide +kernel, by decide +kernel⟩

example : ExactlyOneFreshCallableResourceIssued context beforeWorld issuedWorld
    resource := by
  exact ⟨by decide +kernel, rfl, rfl, rfl, rfl, rfl, rfl⟩

example : CallableWorldValidity context issuedWorld := by
  exact ⟨by decide +kernel, by decide +kernel⟩

example : resolveOriginalIndirect callableProgram issuedWorld resource.original
    .call = .callable capability abi resource := by decide +kernel

example : kernelFrontier.classifyIndirect context issuedWorld resource.candidate
    .call = .callable capability abi resource := by decide +kernel

example : resource.original != resource.candidate := by decide +kernel

theorem tinyResolvedNoWritePreservesWord
    (before after : Memory) (slot : Word) (same : before = after) :
    Memory.read32 after slot = Memory.read32 before slot := by
  apply resolvedExternalMemoryEffectHolds_preservesWord abi [] before after slot
  · exact Or.inl rfl
  · simpa [resolvedExternalMemoryEffectHolds, abi] using same
  · intro offset beforeFour
    simp [ExternalWriteFootprintsAvoidWord, abi]

def resolverObservation : CallableExternalObservation := {
  globalExternalIndex := 0
  identity := .resolver 3 2 7
  arguments := []
  world := beforeWorld
}

def resolvedOriginalObservation : CallableExternalObservation := {
  globalExternalIndex := 1
  identity := .resolved 7 7 11 .call
  arguments := []
  world := issuedWorld
}

def resolvedCandidateObservation : CallableExternalObservation := {
  globalExternalIndex := 1
  identity := .resolved 7 7 11 .call
  arguments := []
  world := issuedWorld
}

/-- The resolver-issued pair permits the same capability event even though
the two concrete callable words differ. -/
theorem tinyResolverThenResolvedCall :
    RuntimeCallableTracesRelated context
      [resolverObservation, resolvedOriginalObservation]
      [resolverObservation, resolvedCandidateObservation] /\
    resolveOriginalIndirect callableProgram issuedWorld resource.original
        .call = .callable capability abi resource /\
    kernelFrontier.classifyIndirect context issuedWorld resource.candidate
        .call = .callable capability abi resource /\
    resource.original != resource.candidate := by
  refine ⟨?_, by decide +kernel, by decide +kernel, by decide +kernel⟩
  exact .cons (by simp [CallableExternalObservationsRelated,
      resolverObservation, beforeWorld, externalCallArgumentsRelated,
      wordsRelated])
    (.cons (by simp [CallableExternalObservationsRelated,
      resolvedOriginalObservation, resolvedCandidateObservation, issuedWorld,
      externalCallArgumentsRelated, wordsRelated]) .nil)

example : kernelFrontier.classifyIndirect context issuedWorld resource.original
    .call = .unmapped := by decide +kernel

def collisionResource : OpaqueResourcePair := {
  id := 7
  original := BitVec.ofNat 32 7340048
  candidate := BitVec.ofNat 32 4198400
}

def collisionWorld : RelationalWorld := {
  opaqueResources := [collisionResource]
}

example : collisionWorld.valid context = false := by decide +kernel

example : kernelFrontier.classifyIndirect context collisionWorld
    collisionResource.candidate .call = .invalidWorld := by decide +kernel

def badImport : ImportAddressPair := {
  id := 9
  imported := { dll := [120], name := .symbol [121] }
  originalIatRva := 0
  candidateIatRva := 0
  originalAddress := BitVec.ofNat 32 1
  candidateAddress := BitVec.ofNat 32 2
}

def mutatedImportWorld : RelationalWorld := {
  issuedWorld with importAddresses := [badImport]
}

example : mutatedImportWorld.valid context = true := by decide +kernel

example : mutatedImportWorld.importAddressesStaticValid context = false := by
  decide +kernel

example : kernelFrontier.classifyIndirect context mutatedImportWorld
    resource.candidate .call = .invalidWorld := by decide +kernel

example : Not (RuntimeCallableTracesRelated context
    [resolverObservation] []) :=
  runtimeCallableTracesRejectOmittedEvent context resolverObservation

example : Not (RuntimeCallableTracesRelated context
    [resolverObservation, resolvedOriginalObservation]
    [resolvedOriginalObservation, resolverObservation]) := by
  apply runtimeCallableTracesRejectReorderedEvents
  decide +kernel

def nativeEnvironment : NativeWorldEnvironment := {
  action := fun _ _ _ => .blocked .missingRuntimeContinuation
}

def resolvedEnvironment : ResolvedExternalEnvironment := {
  result := fun _ event => { state := event.state, world := event.world }
}

def callableConfig : NativeCallableExternalConfig := {
  context
  capabilities := [capability]
  resolvedABIContracts := [abi]
  environment := resolvedEnvironment
}

def candidateProgram : ExactNativeWorldProgram := {
  pe
  imports := []
  environment := nativeEnvironment
  callableExternal := some callableConfig
}

def callableTargets : NativeIndirectTargetInventory := {
  targetSets := [{
    sourceRva := 17
    transfer := .call
    targets := [.callableResource resource.id]
  }]
}

example : callableTargets.allows pe issuedWorld 17 .call resource.candidate = true := by
  decide +kernel

def zeroState : MachineState := {
  registers := {
    eax := 0, ebx := 0, ecx := 0, edx := 0,
    esi := 0, edi := 0, ebp := 0, esp := 0
  }
  memory := fun _ => 0
}

def originalEnvironment : OriginalCallableExternalEnvironment := {
  result := fun _ event => { state := event.state, world := event.world }
}

def decodedWithoutCallable : DecodedWorldProgram := {
  candidate := false
  context
  regions := []
  externalCallSites := []
  environment := { result := fun _ event => {
    state := event.state
    world := event.world
  } }
}

example :
    (decodedWorldProgramWithCallable decodedWithoutCallable callableProgram
      originalEnvironment).callableProgram = some callableProgram := rfl

example
    (originalContext :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext)
    (binding : ExactDecodedOriginalCarrierBinding originalContext
      decodedWithoutCallable) :
    ExactDecodedOriginalCarrierBinding originalContext
      (decodedWorldProgramWithCallable decodedWithoutCallable callableProgram
        originalEnvironment) :=
  binding.withCallable callableProgram originalEnvironment

example
    (programValid : callableProgram.Valid)
    (contextExact : callableProgram.context = decodedWithoutCallable.context) :
    ExactDecodedOriginalCallableProgramBinding
      (decodedWorldProgramWithCallable decodedWithoutCallable callableProgram
        originalEnvironment) callableProgram originalEnvironment :=
  ExactDecodedOriginalCallableProgramBinding.ofWithCallable
    decodedWithoutCallable callableProgram originalEnvironment rfl
      contextExact programValid

def decodedOriginal : DecodedWorldProgram := {
  candidate := false
  context
  regions := []
  externalCallSites := []
  environment := { result := fun _ event => {
    state := event.state
    world := event.world
  } }
  callableProgram := some callableProgram
  callableEnvironment := some originalEnvironment
}

def decodedCandidate : DecodedWorldProgram := {
  candidate := true
  context
  regions := []
  externalCallSites := []
  environment := { result := fun _ event => {
    state := event.state
    world := event.world
  } }
  callableProgram := some callableProgram
  callableEnvironment := some originalEnvironment
}

/-- Original decoded execution performs the same strict classification and
emits the shared identity directly from the operational transition. -/
example :
    (transitionFromWorldOutcome decodedOriginal 0 zeroState [] 4 issuedWorld []
      (.indirectCall resource.original 23)).observation =
      some (.callableExternal {
        globalExternalIndex := 4
        identity := .resolved capability.id capability.resourceId abi.id .call
        arguments := []
        world := issuedWorld
      }) := by
  decide +kernel

/-- Candidate decoded execution uses the candidate halves of the canonical
code/import/resource maps rather than rejecting callable execution. -/
example :
    resolveDecodedCallableIndirect true callableProgram issuedWorld
        resource.candidate .call =
      .callable capability abi resource := by
  decide +kernel

example :
    (transitionFromWorldOutcome decodedCandidate 0 zeroState [] 4 issuedWorld []
      (.indirectCall resource.candidate 23)).observation =
      some (.callableExternal {
        globalExternalIndex := 4
        identity := .resolved capability.id capability.resourceId abi.id .call
        arguments := []
        world := issuedWorld
      }) := by
  decide +kernel

example :
    (applyNativeWorldResolvedCallableCall callableConfig capability abi
      resource.candidate 23 zeroState [] 4 [] issuedWorld).observation =
      some (.callableExternal {
        globalExternalIndex := 4
        identity := .resolved capability.id capability.resourceId abi.id .call
        arguments := []
        world := issuedWorld
      }) := by
  rfl

#print axioms tinyResolverThenResolvedCall
#print axioms tinyResolvedNoWritePreservesWord
#print axioms resolveCandidateCallableIndirect_usesCandidateValue
#print axioms resolveCandidateCallableIndirect_rejectsInvalidWorld
#print axioms exactlyOneFreshCallableResourceIssued_preservesValidity
#print axioms resolvedExternalSideResultConforms_preservesValidity
#print axioms machineCallResultConforms_preservesStaticWordInvariant
#print axioms resolvedExternalSideResultConforms_preservesReachableStaticPointerSlot
#print axioms CandidateNativeCallableTransitionEvidence.indirectCallContinuation
#print axioms CandidateNativeCallableTransitionEvidence.indirectTailFrame
#print axioms CallableMixedChunkEventFact.toMixedKernelChunkPaths
#print axioms callableMixedChunkEventFact_of_runtimeSteps

end StageA.CallableExternalMixedBridgeKernel
"""


if __name__ == "__main__":
    unittest.main()
