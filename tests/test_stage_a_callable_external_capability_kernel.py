from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.callable_external_capability import (
    relational_callable_external_capability_source,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_callable_external_capability import _artifact


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
class StageACallableExternalCapabilityKernelTests(unittest.TestCase):
    def test_hardened_capability_layer_is_kernel_checked(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        layer = (
            source_root / "RelationalCallableExternalCapability.lean"
        ).read_text(encoding="utf-8")
        self.assertNotIn("native_decide", layer)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", layer), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalCallableExternalExecution"
            )
            (stage_a / "GeneratedCallableExternalCapability.lean").write_text(
                relational_callable_external_capability_source(_artifact()),
                encoding="utf-8",
            )
            (stage_a / "CallableExternalCapabilityKernel.lean").write_text(
                _KERNEL_SOURCE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="CallableExternalCapabilityKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 5, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


_KERNEL_SOURCE = r"""import StageA.GeneratedCallableExternalCapability

namespace StageA.CallableExternalCapabilityKernel

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalCapability
open StageA.GeneratedRelational.CallableExternalCapability

def resolverImported : ExternalTarget := {
  dll := [114, 101, 115, 111, 108, 118, 101, 114, 46, 100, 108, 108]
  name := .symbol [114, 101, 115, 111, 108, 118, 101]
}

def callableResolverMachineContract : MachineImportCallContract := {
  id := 17
  imported := resolverImported
  stackArgumentOffsets := [0, 4]
  stackResultDelta := 0
  preservedRegisters := [.ebp, .ebx, .edi, .esi]
  clobberedRegisters := [.eax, .ecx, .edx]
  resultRegisterRelations := []
  memoryEffect := .none
  worldEffect := .opaqueResources
}

def ordinaryRelatedWordMachineContract : MachineImportCallContract := {
  callableResolverMachineContract with
  resultRegisterRelations := [{ register := .eax, relation := .relatedWord }]
}

def wrongArgumentResolver : ResolverCallContract := {
  resolverCallContract3 with argumentSources := [.register .ecx, .stackWord 4]
}

def broadMemoryABI : ResolvedExternalABIContract := {
  resolvedExternalABIContract50 with memoryEffect := .relationalState
}

def mutatingWorldABI : ResolvedExternalABIContract := {
  resolvedExternalABIContract50 with worldEffect := .opaqueResources
}

def extractionState : MachineState := {
  registers := {
    eax := BitVec.ofNat 32 1
    ebx := BitVec.ofNat 32 2
    ecx := BitVec.ofNat 32 3
    edx := BitVec.ofNat 32 4
    esi := BitVec.ofNat 32 5
    edi := BitVec.ofNat 32 6
    ebp := BitVec.ofNat 32 7
    esp := BitVec.ofNat 32 4096
  }
  memory := fun _ => BitVec.ofNat 8 0
}

example : callableResolverMachineContract.shapeValid = true := by decide

example : resolverCallContract3.validForMachineContract
    callableResolverMachineContract = true := by decide

example : ordinaryRelatedWordMachineContract.shapeValid = true := by decide

example : resolverCallContract3.validForMachineContract
    ordinaryRelatedWordMachineContract = false := by decide

example : wrongArgumentResolver.validForMachineContract
    callableResolverMachineContract = false := by decide

example : resolvedExternalABIContract50.shapeValid = true := by decide

example : resolvedExternalABIContract51.shapeValid = true := by decide

example : broadMemoryABI.shapeValid = false := by decide

example : mutatingWorldABI.shapeValid = false := by decide

example : callableArgumentsExtracted
    [.register .ecx, .constant (BitVec.ofNat 32 9)] extractionState
    [BitVec.ofNat 32 3, BitVec.ofNat 32 9] := by rfl

example (context : StaticProofContext) (before after : RelationalWorld)
    (resource : OpaqueResourcePair)
    (issued : ExactlyOneFreshCallableResourceIssued context before after resource) :
    after.opaqueResources = before.opaqueResources ++ [resource] :=
  issued.2.2.2.2.2.2

example (context : StaticProofContext)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (event : WorldExternalEvent) (result : WorldExternalResult)
    (conforms : ResolverCapabilitySideResultConforms false context machine
      resolver capability event result) :
    resolverIdentityArgumentsHoldOn false context capability event = true :=
  conforms.immutableIdentity

example (context : StaticProofContext)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (event : WorldExternalEvent) (result : WorldExternalResult)
    (conforms : ResolverCapabilitySideResultConforms false context machine
      resolver capability event result)
    (nonzero : result.state.registers.get resolver.resultRegister !=
      BitVec.ofNat 32 0) :
    ∃ resource : OpaqueResourcePair,
      resource.original != BitVec.ofNat 32 0 ∧
        resource.candidate != BitVec.ofNat 32 0 := by
  rcases conforms.resultCase with unavailable | issuedResource
  · simp [unavailable.2.1] at nonzero
  rcases issuedResource with
    ⟨resource, _issued, _resourceId, _resultValue, originalNonzero,
      candidateNonzero⟩
  exact ⟨resource, originalNonzero, candidateNonzero⟩

example (context : StaticProofContext)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract)
    (event : ResolvedExternalEvent) (result : WorldExternalResult)
    (conforms : ResolvedExternalSideResultConforms false context capability abi
      event result) :
    resolvedExternalMemoryEffectHolds abi event.arguments event.state.memory
      result.state.memory :=
  conforms.memoryHolds

#print axioms ResolverCapabilityResultRelated.available
#print axioms CallableCapabilityAvailable.carry
#print axioms resolverCapabilityResultsRelated
#print axioms resolvedExternalResultsRelated
#print axioms resolvedExternalMemoryEffectHolds
#print axioms ExactlyOneFreshCallableResourceIssued

end StageA.CallableExternalCapabilityKernel
"""


if __name__ == "__main__":
    unittest.main()
