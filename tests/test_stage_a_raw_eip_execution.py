from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES
from pe_fixtures import pe32_image


class StageARawEipExecutionTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel proofs")
    def test_checked_raw_eip_resolution_and_blockage_are_kernel_checked(self) -> None:
        image = pe32_image(b"\x90\x90\xc3", virtual_size=0x20)

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
            shutil.copyfile(
                source_root / "RelationalPEWorldExecution.lean",
                stage_a / "RelationalPEWorldExecution.lean",
            )

            (stage_a / "RawEipExecutionKernel.lean").write_text(
                f"""import StageA.RelationalPEWorldExecution

namespace StageA.RawEipExecutionKernelTests

open StageA.Formal StageA.Relational

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def fixtureBytes : Bytes := {list(image)}

def checkedMap : StaticCodeMap := {{
  entries := .leaf [{{
    id := 0
    originalRva := 0x1000
    candidateRva := 0x1000
    originalAliases := [{{ rva := 0x1002, paddingIndex := 0 }}]
    candidateAliases := [{{ rva := 0x1002, paddingIndex := 0 }}]
  }}]
  originalAddresses := .leaf [
    {{ targetId := 0, kind := .canonical }},
    {{ targetId := 0, kind := .alias 0 }}
  ]
  candidateAddresses := .leaf [
    {{ targetId := 0, kind := .canonical }},
    {{ targetId := 0, kind := .alias 0 }}
  ]
}}

def checkedExecutableButUnmapped : Bool :=
  match parsePE32 fixtureBytes with
  | none => false
  | some pe =>
      checkedMap.valid pe pe &&
        rvaInExecutableSection pe 0x1001 &&
        checkedMap.resolveRawEip false pe.imageBase
          (BitVec.ofNat 32 (pe.imageBase + 0x1000)) == some 0 &&
        checkedMap.resolveRawEip false pe.imageBase
          (BitVec.ofNat 32 (pe.imageBase + 0x1002)) == some 0 &&
        checkedMap.resolveRawEip false pe.imageBase
          (BitVec.ofNat 32 (pe.imageBase + 0x1001)) == none

example : checkedExecutableButUnmapped = true := by native_decide

def ambiguousMap : StaticCodeMap := {{
  entries := .leaf [
    {{ id := 0, originalRva := 0x1000, candidateRva := 0x1000 }},
    {{ id := 1, originalRva := 0x1000, candidateRva := 0x1000 }}
  ]
  originalAddresses := .leaf [
    {{ targetId := 0, kind := .canonical }},
    {{ targetId := 1, kind := .canonical }}
  ]
  candidateAddresses := .leaf [
    {{ targetId := 0, kind := .canonical }},
    {{ targetId := 1, kind := .canonical }}
  ]
}}

example : ambiguousMap.resolveRawEip false 0x400000
    (BitVec.ofNat 32 0x401000) = none := by native_decide

theorem executableUnmappedRunningBlocks (program : DecodedWorldProgram)
    (eip : Word) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (unmapped : program.resolveRawEip eip = none) :
    stepPE32RawEipWorldExecution program
        (.running eip state calls eventIndex world) =
      blockedRawEipWorldTransition (.unmappedEip eip) :=
  stepPE32RawEipWorldExecution_running_unmapped program eip state calls
    eventIndex world unmapped

theorem pairedRawBlockageIsUnrelatable (context : StaticProofContext)
    (originalEip candidateEip : Word) :
    Not (worldRelationalObservationsRelated context
      (some (.proofBlocked (.unmappedEip originalEip)))
      (some (.proofBlocked (.unmappedEip candidateEip)))) :=
  pairedRawEipBlocksAreUnrelated context originalEip candidateEip

#print axioms executableUnmappedRunningBlocks
#print axioms pairedRawBlockageIsUnrelatable
#print axioms worldExecutionsRelated_rawEipPairBridgeClosed
#print axioms relationalWeakBisimulation_rawEip_of_logical
#print axioms pe32ProgramsEquivalent_raw

end StageA.RawEipExecutionKernelTests
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir,
                bundle="RawEipExecutionKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
