from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES


class StageARuntimeFrameImportEnvironmentTests(unittest.TestCase):
    @unittest.skipUnless(
        shutil.which("lean"), "Lean is required for environment proofs"
    )
    def test_exact_external_call_import_preservation_is_kernel_checked(self):
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

            (stage_a / "RuntimeFrameImportEnvironment.lean").write_text(
                """import StageA.RelationalEnvironment

namespace StageA.RuntimeFrameImportEnvironment

open StageA.Formal StageA.Relational

def imported : ExternalTarget := {
  dll := [107, 101, 114, 110, 101, 108, 51, 50, 46, 100, 108, 108]
  name := .symbol [84, 101, 115, 116, 73, 109, 112, 111, 114, 116]
}

def otherImported : ExternalTarget := {
  dll := imported.dll
  name := .symbol [79, 116, 104, 101, 114, 73, 109, 112, 111, 114, 116]
}

def contract : MachineImportCallContract := {
  id := 7
  imported
  stackArgumentOffsets := []
  stackResultDelta := 0
  preservedRegisters := [.ebx, .esi, .edi, .ebp]
  clobberedRegisters := [.eax, .ecx, .edx]
  disposition := .returns
  memoryEffect := .none
  worldEffect := .none
}

def relation : ImportRegisterRelation := {
  original := .ebx
  candidate := .esi
  imported
}

def claim : ExternalImportRegisterPreservationClaim := {
  source := relation
  target := relation
}

def clobberedClaim : ExternalImportRegisterPreservationClaim := {
  source := { relation with original := .eax }
  target := { relation with original := .eax }
}

def differentImportClaim : ExternalImportRegisterPreservationClaim := {
  source := relation
  target := { relation with imported := otherImported }
}

def binding : ImportAddressPair := {
  id := 3
  imported
  originalIatRva := 8192
  candidateIatRva := 12288
  originalAddress := BitVec.ofNat 32 286331153
  candidateAddress := BitVec.ofNat 32 572662306
}

def world : RelationalWorld := {
  importAddresses := [binding]
}

def originalRegisters : Registers Word := {
  eax := BitVec.ofNat 32 0
  ebx := binding.originalAddress
  ecx := BitVec.ofNat 32 0
  edx := BitVec.ofNat 32 0
  esi := BitVec.ofNat 32 0
  edi := BitVec.ofNat 32 0
  ebp := BitVec.ofNat 32 0
  esp := BitVec.ofNat 32 4096
}

def candidateRegisters : Registers Word := {
  eax := BitVec.ofNat 32 0
  ebx := BitVec.ofNat 32 0
  ecx := BitVec.ofNat 32 0
  edx := BitVec.ofNat 32 0
  esi := binding.candidateAddress
  edi := BitVec.ofNat 32 0
  ebp := BitVec.ofNat 32 0
  esp := BitVec.ofNat 32 8192
}

example : contract.shapeValid = true := by decide
example : claim.checked contract = true := by decide
example : binding.originalAddress != binding.candidateAddress := by decide
example : relation.holds world originalRegisters candidateRegisters = true := by decide

-- A requested register classified as clobbered cannot pass the certificate checker.
example : clobberedClaim.checked contract = false := by decide

-- Exact source/target identity also rejects changing the import being named.
example : differentImportClaim.checked contract = false := by decide

example (context : StaticProofContext)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (pairConforms : ExactExternalCallPairConforms context contract
      originalEvent candidateEvent originalResult candidateResult) :
    originalEvent.imported = candidateEvent.imported ∧
      originalEvent.world = candidateEvent.world ∧
      originalResult.world = candidateResult.world ∧
      machineCallResultConforms false context contract originalEvent originalResult ∧
      machineCallResultConforms true context contract candidateEvent candidateResult := by
  exact ⟨pairConforms.originalImported.trans pairConforms.candidateImported.symm,
    pairConforms.eventWorld, pairConforms.resultWorld,
    pairConforms.originalConforms, pairConforms.candidateConforms⟩

example (context : StaticProofContext)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (sourceHolds : claim.source.holds originalEvent.world
      originalEvent.state.registers candidateEvent.state.registers = true)
    (pairConforms : ExactExternalCallPairConforms context contract
      originalEvent candidateEvent originalResult candidateResult) :
    claim.target.holds originalResult.world originalResult.state.registers
      candidateResult.state.registers = true := by
  exact externalImportRegisterPreservationHolds_of_checked context contract claim
    originalEvent candidateEvent originalResult candidateResult (by decide)
    sourceHolds pairConforms

end StageA.RuntimeFrameImportEnvironment
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir, bundle="RuntimeFrameImportEnvironment"
            )
            self.assertEqual(result["status"], "checked", result)
            self.assertNotIn("sorryAx", result["stdout"])
            self.assertNotIn("._native.", result["stdout"])


if __name__ == "__main__":
    unittest.main()
