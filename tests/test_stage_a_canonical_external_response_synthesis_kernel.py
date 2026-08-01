from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}


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


_KERNEL = r'''import StageA.RelationalCanonicalExternalResponseSynthesis

namespace StageA.CanonicalExternalResponseSynthesisKernel

open StageA.Formal
open StageA.Relational
open StageA.Relational.NativeSource
open StageA.Relational.CanonicalExternalResponseSynthesis

def zeroWord : Word := BitVec.ofNat 32 0

def concreteRegisters : Registers Word := {
  eax := zeroWord
  ebx := zeroWord
  ecx := zeroWord
  edx := zeroWord
  esi := zeroWord
  edi := zeroWord
  ebp := zeroWord
  esp := BitVec.ofNat 32 0x1000
}

def concreteState : MachineState := {
  registers := concreteRegisters
  memory := fun _ => BitVec.ofNat 8 0
}

def returningContract : MachineImportCallContract := {
  id := 1
  imported := { dll := [], name := .symbol [] }
  stackArgumentOffsets := []
  stackResultDelta := 4
  preservedRegisters := [.eax, .ebx, .ecx, .edx, .esi, .edi, .ebp]
  clobberedRegisters := []
  memoryEffect := .none
  worldEffect := .none
}

def concreteEvent (world : RelationalWorld) : WorldExternalEvent := {
  siteId := 1
  imported := returningContract.imported
  arguments := []
  state := concreteState
  world
}

def preserveUpdate (context : StaticProofContext) (world : RelationalWorld)
    (valid : world.valid context = true) :
    CheckedPairedWorldUpdate context .none [] [] world := {
  plan := .preserve
  checked := by simpa [PairedWorldUpdatePlan.matches,
    PairedWorldUpdatePlan.after, valid]
}

def emptyRegisterResults (context : StaticProofContext)
    (world : RelationalWorld) :
    CheckedCanonicalRegisterResults context returningContract [] world
      concreteState concreteState := {
  results := []
  originalABI := by decide
  candidateABI := by decide
  related := by simp [machineCallResultRegistersRelated, returningContract]
}

def canonicalPair (context : StaticProofContext) (world : RelationalWorld)
    (valid : world.valid context = true) :
    CheckedCanonicalExternalResponsePair context returningContract
      (concreteEvent world) (concreteEvent world) :=
  synthesizeCanonicalExternalResponsePair context returningContract
    (concreteEvent world) (concreteEvent world) (by decide) rfl rfl rfl rfl
    (by
      simpa [externalCallArgumentsRelated, concreteEvent] using
        (wordsRelated_self context.originalPe.imageBase
          context.candidatePe.imageBase context.codeMap.entries.toList
          (context.relationalValueTargets world) ([] : List Word))) rfl
    (by trivial) (by trivial) (preserveUpdate context world valid)
    (emptyRegisterResults context world)
    (by simp [freshDynamicResultRegistersChecked, returningContract])

theorem canonicalPairOriginalConforms (context : StaticProofContext)
    (world : RelationalWorld) (valid : world.valid context = true) :
    machineCallResultConforms false context returningContract
      (concreteEvent world) (canonicalPair context world valid).originalResult :=
  (canonicalPair context world valid).originalConforms

theorem canonicalPairCandidateConforms (context : StaticProofContext)
    (world : RelationalWorld) (valid : world.valid context = true) :
    machineCallResultConforms true context returningContract
      (concreteEvent world) (canonicalPair context world valid).candidateResult :=
  (canonicalPair context world valid).candidateConforms

def dynamicRange : DynamicAddressRangePair := {
  id := 4
  originalBase := BitVec.ofNat 32 0x2000
  candidateBase := BitVec.ofNat 32 0x3000
  size := 16
}

def releaseUpdate (context : StaticProofContext) (before : RelationalWorld)
    (member : before.dynamicRanges.contains dynamicRange = true)
    (valid : ({ before with dynamicRanges :=
      before.dynamicRanges.erase dynamicRange }).valid context = true) :
    CheckedPairedWorldUpdate context (.dynamicRangeRelease 0)
      [dynamicRange.originalBase] [dynamicRange.candidateBase] before := {
  plan := .releaseDynamicRange dynamicRange
  checked := by
    have memberProp : dynamicRange ∈ before.dynamicRanges :=
      List.contains_iff_mem.mp member
    simp only [PairedWorldUpdatePlan.matches, PairedWorldUpdatePlan.after,
      valid, Bool.true_and]
    simp [dynamicRange]
    exact memberProp
}

theorem releaseUpdateConformsOnBothSides (context : StaticProofContext)
    (before : RelationalWorld)
    (member : before.dynamicRanges.contains dynamicRange = true)
    (valid : ({ before with dynamicRanges :=
      before.dynamicRanges.erase dynamicRange }).valid context = true) :
    machineCallWorldEffectHolds false context (.dynamicRangeRelease 0)
        [dynamicRange.originalBase] before
        (releaseUpdate context before member valid).after /\
      machineCallWorldEffectHolds true context (.dynamicRangeRelease 0)
        [dynamicRange.candidateBase] before
        (releaseUpdate context before member valid).after :=
  ⟨(releaseUpdate context before member valid).original_holds,
    (releaseUpdate context before member valid).candidate_holds⟩

def callback : RegisteredCallbackPair := {
  targetId := 9
  originalAddress := BitVec.ofNat 32 0x401000
  candidateAddress := BitVec.ofNat 32 0x501000
}

def callbackUpdate (context : StaticProofContext) (before : RelationalWorld)
    (callbackValid : callback.valid context = true)
    (afterValid : ({ before with registeredCallbacks :=
      callback :: before.registeredCallbacks }).valid context = true) :
    CheckedPairedWorldUpdate context (.callbackRegistration 0)
      [callback.originalAddress] [callback.candidateAddress] before := {
  plan := .registerCallback callback
  checked := by
    simp [PairedWorldUpdatePlan.matches, PairedWorldUpdatePlan.after,
      callbackValid, afterValid]
}

theorem callbackUpdateConformsOnBothSides (context : StaticProofContext)
    (before : RelationalWorld) (callbackValid : callback.valid context = true)
    (afterValid : ({ before with registeredCallbacks :=
      callback :: before.registeredCallbacks }).valid context = true) :
    machineCallWorldEffectHolds false context (.callbackRegistration 0)
        [callback.originalAddress] before
        (callbackUpdate context before callbackValid afterValid).after /\
      machineCallWorldEffectHolds true context (.callbackRegistration 0)
        [callback.candidateAddress] before
        (callbackUpdate context before callbackValid afterValid).after :=
  ⟨(callbackUpdate context before callbackValid afterValid).original_holds,
    (callbackUpdate context before callbackValid afterValid).candidate_holds⟩

def opaqueUpdate (context : StaticProofContext) (before : RelationalWorld)
    (resources : List OpaqueResourcePair)
    (fresh : forall resource, resource ∈ resources ->
      resource ∉ before.opaqueResources)
    (afterValid : ({ before with opaqueResources :=
      before.opaqueResources ++ resources }).valid context = true) :
    CheckedPairedWorldUpdate context .opaqueResources [] [] before := {
  plan := .addOpaqueResources resources
  checked := by
    simp [PairedWorldUpdatePlan.matches, PairedWorldUpdatePlan.after,
      afterValid]
    exact fresh
}

theorem opaqueUpdateConformsOnBothSides (context : StaticProofContext)
    (before : RelationalWorld) (resources : List OpaqueResourcePair)
    (fresh : forall resource, resource ∈ resources ->
      resource ∉ before.opaqueResources)
    (afterValid : ({ before with opaqueResources :=
      before.opaqueResources ++ resources }).valid context = true) :
    machineCallWorldEffectHolds false context .opaqueResources [] before
        (opaqueUpdate context before resources fresh afterValid).after /\
      machineCallWorldEffectHolds true context .opaqueResources [] before
        (opaqueUpdate context before resources fresh afterValid).after :=
  ⟨(opaqueUpdate context before resources fresh afterValid).original_holds,
    (opaqueUpdate context before resources fresh afterValid).candidate_holds⟩

def tlsUpdate (context : StaticProofContext) (before : RelationalWorld)
    (tls : RelationalTlsState)
    (afterValid : ({ before with tlsState := tls }).valid context = true) :
    CheckedPairedWorldUpdate context .tlsState [] [] before := {
  plan := .setTlsState tls
  checked := by
    simp [PairedWorldUpdatePlan.matches, PairedWorldUpdatePlan.after, afterValid]
}

theorem tlsUpdateConformsOnBothSides (context : StaticProofContext)
    (before : RelationalWorld) (tls : RelationalTlsState)
    (afterValid : ({ before with tlsState := tls }).valid context = true) :
    machineCallWorldEffectHolds false context .tlsState [] before
        (tlsUpdate context before tls afterValid).after /\
      machineCallWorldEffectHolds true context .tlsState [] before
        (tlsUpdate context before tls afterValid).after :=
  ⟨(tlsUpdate context before tls afterValid).original_holds,
    (tlsUpdate context before tls afterValid).candidate_holds⟩

theorem admissibleReadOnlyResponseMayPreserveMemory
    (candidate : Bool) (contract : MachineImportCallContract)
    (event : WorldExternalEvent) (afterWorld : RelationalWorld)
    (effect : contract.memoryEffect = .readOnly)
    (admissible : MachineMemoryEffectInputAdmissible contract event) :
    machineCallMemoryEffectHoldsWithWorld candidate contract event.arguments
      event.world afterWorld event.state.memory event.state.memory :=
  unchangedMemoryEffectHolds candidate contract event afterWorld admissible

theorem admissibleArgumentRangeResponseMayPreserveMemory
    (candidate : Bool) (contract : MachineImportCallContract)
    (event : WorldExternalEvent) (afterWorld : RelationalWorld)
    (effect : contract.memoryEffect = .argumentRanges)
    (admissible : MachineMemoryEffectInputAdmissible contract event) :
    machineCallMemoryEffectHoldsWithWorld candidate contract event.arguments
      event.world afterWorld event.state.memory event.state.memory :=
  unchangedMemoryEffectHolds candidate contract event afterWorld admissible

def allocationContract : MachineImportCallContract := {
  id := 2
  imported := { dll := [], name := .symbol [] }
  stackArgumentOffsets := []
  stackResultDelta := 0
  preservedRegisters := [.ebx, .ecx, .edx, .esi, .edi, .ebp]
  clobberedRegisters := [.eax]
  resultRegisterRelations := [{
    register := .eax
    relation := .dynamicRangeBase (.fixed 16) 16 [] false
  }]
  memoryEffect := .newDynamicRanges
  worldEffect := .dynamicRanges
}

def allocationOriginalState : MachineState := {
  concreteState with
  registers := concreteState.registers.set .eax dynamicRange.originalBase
}

def allocationCandidateState : MachineState := {
  concreteState with
  registers := concreteState.registers.set .eax dynamicRange.candidateBase
}

def allocationEvent : WorldExternalEvent := {
  siteId := 2
  imported := allocationContract.imported
  arguments := []
  state := concreteState
  world := RelationalWorld.empty
}

def allocationUpdate (context : StaticProofContext)
    (afterValid : ({ RelationalWorld.empty with dynamicRanges :=
      [dynamicRange] }).valid context = true) :
    CheckedPairedWorldUpdate context .dynamicRanges [] []
      RelationalWorld.empty := {
  plan := .addDynamicRanges [dynamicRange]
  checked := by
    simpa [PairedWorldUpdatePlan.matches, PairedWorldUpdatePlan.after,
      RelationalWorld.empty, afterValid]
}

def allocationRegisters (context : StaticProofContext)
    (afterValid : ({ RelationalWorld.empty with dynamicRanges :=
      [dynamicRange] }).valid context = true) :
    CheckedCanonicalRegisterResults context allocationContract []
      (allocationUpdate context afterValid).after concreteState concreteState := {
  results := [{
    register := .eax
    original := dynamicRange.originalBase
    candidate := dynamicRange.candidateBase
  }]
  originalABI := by decide
  candidateABI := by decide
  related := by
    change dynamicRangeBaseResultHolds []
      ({ RelationalWorld.empty with dynamicRanges := [dynamicRange] })
      (.fixed 16) 16 [] false dynamicRange.originalBase
      dynamicRange.candidateBase = true
    decide
}

def allocationPair (context : StaticProofContext)
    (afterValid : ({ RelationalWorld.empty with dynamicRanges :=
      [dynamicRange] }).valid context = true) :
    CheckedCanonicalExternalResponsePair context allocationContract
      allocationEvent allocationEvent :=
  synthesizeCanonicalExternalResponsePair context allocationContract
    allocationEvent allocationEvent (by decide) rfl rfl rfl rfl
    (by
      simpa [externalCallArgumentsRelated, allocationEvent] using
        (wordsRelated_self context.originalPe.imageBase
          context.candidatePe.imageBase context.codeMap.entries.toList
          (context.relationalValueTargets RelationalWorld.empty)
          ([] : List Word))) rfl (by trivial) (by trivial)
    (allocationUpdate context afterValid) (allocationRegisters context afterValid)
    (by
      change freshDynamicResultRegistersChecked allocationContract []
        (.addDynamicRanges [dynamicRange]) allocationOriginalState
        allocationCandidateState = true
      decide)

theorem allocationPairConforms (context : StaticProofContext)
    (afterValid : ({ RelationalWorld.empty with dynamicRanges :=
      [dynamicRange] }).valid context = true) :
    machineCallResultConforms false context allocationContract allocationEvent
        (allocationPair context afterValid).originalResult /\
      machineCallResultConforms true context allocationContract allocationEvent
        (allocationPair context afterValid).candidateResult :=
  ⟨(allocationPair context afterValid).originalConforms,
    (allocationPair context afterValid).candidateConforms⟩

theorem freshAllocationResultChecks :
    freshDynamicResultRegistersChecked allocationContract []
      (.addDynamicRanges [dynamicRange]) allocationOriginalState
      allocationCandidateState = true := by decide

theorem oldRangeCannotAuthorizeFreshAllocation :
    freshDynamicResultRegistersChecked allocationContract [] .preserve
      allocationOriginalState allocationCandidateState = false := by decide

#print axioms canonicalPairOriginalConforms
#print axioms canonicalPairCandidateConforms
#print axioms releaseUpdateConformsOnBothSides
#print axioms callbackUpdateConformsOnBothSides
#print axioms opaqueUpdateConformsOnBothSides
#print axioms tlsUpdateConformsOnBothSides
#print axioms admissibleReadOnlyResponseMayPreserveMemory
#print axioms admissibleArgumentRangeResponseMayPreserveMemory
#print axioms allocationPairConforms
#print axioms freshAllocationResultChecks
#print axioms oldRangeCannotAuthorizeFreshAllocation

end StageA.CanonicalExternalResponseSynthesisKernel
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageACanonicalExternalResponseSynthesisKernelTests(unittest.TestCase):
    def test_generic_response_synthesis_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalCanonicalExternalResponseSynthesis.lean"
        ).read_text(encoding="utf-8")
        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bGnu\b",
            r"authorizing_lean_terms",
            r"status\s*==",
        ):
            self.assertNotRegex(module_text, forbidden)
        for required in (
            "PairedWorldUpdatePlan",
            "CheckedPairedWorldUpdate",
            "freshDynamicResultRegistersChecked",
            "CheckedCanonicalExternalResponsePair",
            "synthesizeCanonicalExternalResponsePair",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalCanonicalExternalResponseSynthesis",
            )
            (stage_a / "CanonicalExternalResponseSynthesisKernel.lean").write_text(
                _KERNEL, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="CanonicalExternalResponseSynthesisKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 11, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
