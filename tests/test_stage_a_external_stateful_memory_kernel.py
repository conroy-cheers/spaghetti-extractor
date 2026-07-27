from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES


class StageAExternalStatefulMemoryKernelTests(unittest.TestCase):
    @unittest.skipUnless(
        shutil.which("lean"), "Lean is required for stateful memory proofs"
    )
    def test_relational_state_memory_mode_is_kernel_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src"
                / "spaghetti_extractor"
                / "lean"
                / "StageA"
            )
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )

            (stage_a / "ExternalStatefulMemory.lean").write_text(
                """import StageA.RelationalEnvironment

namespace StageA.ExternalStatefulMemory

open StageA.Formal StageA.Relational

def contract : MachineImportCallContract := {
  id := 11
  imported := {
    dll := [109, 115, 118, 99, 114, 116, 46, 100, 108, 108]
    name := .symbol [102, 102, 108, 117, 115, 104]
  }
  stackArgumentOffsets := [0]
  stackResultDelta := 0
  preservedRegisters := [.ebp, .ebx, .edi, .esi]
  clobberedRegisters := [.eax, .ecx, .edx]
  resultRegisterRelations := [{
    register := .eax
    relation := .exact
  }]
  disposition := .returns
  memoryEffect := .relationalState
  memoryFootprints := []
  worldEffect := .none
}

def invalidFootprintContract : MachineImportCallContract := {
  contract with
  memoryFootprints := [{
    access := .write
    baseArgument := 0
    offset := 0
    size := .fixed 4
    nullable := false
  }]
}

def protocolContract : MachineImportCallContract := {
  contract with
  disposition := .protocol
}

def beforeMemory : Memory := fun _ => 0

def changedAddress : Word := BitVec.ofNat 32 4096

def afterMemory : Memory := fun address =>
  if address == changedAddress then 1 else beforeMemory address

example : contract.shapeValid = true := by decide

example : invalidFootprintContract.shapeValid = false := by decide

example : protocolContract.shapeValid = true := by decide

example : Not (beforeMemory = afterMemory) := by
  intro equalMemory
  have equalByte := congrFun equalMemory changedAddress
  simp [beforeMemory, afterMemory, changedAddress] at equalByte

-- relationalState deliberately imposes no independent, per-side frame claim.
example : machineCallMemoryEffectHolds contract [] beforeMemory afterMemory := by
  simp [machineCallMemoryEffectHolds, contract]

-- Pair refinement remains authoritative: every returning environment refinement
-- still yields the target StateRel in addition to per-side result conformance.
example (context : StaticProofContext) (site : ExternalCallSiteContract)
    (original candidate : WorldExternalEnvironment)
    (refines : ExternalEnvironmentRefinesAt context site contract
      original candidate)
    (eventIndex : Nat) (originalEvent candidateEvent : WorldExternalEvent)
    (boundary : ExternalCallBoundaryRelated context site contract
      originalEvent candidateEvent) :
    let originalResult := original.result eventIndex originalEvent
    let candidateResult := candidate.result eventIndex candidateEvent
    StateRel context originalResult.world site.targetInvariant
      originalResult.state candidateResult.state := by
  have results := externalCallResultsRelated context site contract original candidate
    refines (by rfl) eventIndex originalEvent candidateEvent boundary
  exact results.2.2.2.2.1

end StageA.ExternalStatefulMemory
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir, bundle="ExternalStatefulMemory"
            )
            self.assertEqual(result["status"], "checked", result)
            self.assertNotIn("sorryAx", result["stdout"])
            self.assertNotIn("._native.", result["stdout"])


if __name__ == "__main__":
    unittest.main()
