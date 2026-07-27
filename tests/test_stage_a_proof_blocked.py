from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES


class StageAProofBlockedTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel proofs")
    def test_proof_blockage_cannot_be_related_as_a_modeled_fault(self) -> None:
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

            (stage_a / "ProofBlocked.lean").write_text(
                """import StageA.RelationalCertificates

namespace StageA.ProofBlockedTests

open StageA.Formal StageA.Relational

theorem pairedProofBlocksAreUnrelated (context : StaticProofContext)
    (reason : ExecutionBlock) :
    Not (worldRelationalObservationsRelated context
      (some (.proofBlocked reason)) (some (.proofBlocked reason))) := by
  simp [worldRelationalObservationsRelated]

theorem blockedExecutionIsNotModeledFault (reason : ExecutionBlock) :
    Not (WorldExecution.blocked reason =
      WorldExecution.fault .checkedContinue) := by
  intro impossible
  cases impossible

theorem missingRegionBehaviorBlocks (program : DecodedWorldProgram)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (missing : decodedWorldRegionBehavior program targetId state = none) :
    stepWorldExecution program (.running targetId state calls eventIndex world) =
      blockedWorldTransition (.missingRegionBehavior targetId) := by
  simp [stepWorldExecution, missing]

theorem failedCheckedContinueIsModeledFault (program : DecodedWorldProgram)
    (sourceTargetId continuationTargetId : Nat) (state : MachineState)
    (calls : List Nat) (eventIndex : Nat) (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime) :
    (transitionFromWorldOutcome program sourceTargetId state calls eventIndex world
      callbacks (.checkedContinue false continuationTargetId)).next =
        .fault .checkedContinue := by
  simp [transitionFromWorldOutcome]

theorem unknownIndirectTargetBlocks (program : DecodedWorldProgram)
    (sourceTargetId continuationTargetId : Nat) (state : MachineState)
    (calls : List Nat) (eventIndex : Nat) (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime) (target : Word)
    (codeMissing : program.context.codeMap.resolveRawEip program.candidate
      (if program.candidate then program.context.candidatePe.imageBase
       else program.context.originalPe.imageBase)
      target = none)
    (importMissing : resolveWorldImportCall program.candidate program.context
      world target state = none) :
    transitionFromWorldOutcome program sourceTargetId state calls eventIndex world
      callbacks (.indirectCall target continuationTargetId) =
        blockedWorldTransition (.unmappedIndirectControl target) := by
  simp [transitionFromWorldOutcome, codeMissing, importMissing]

#print axioms pairedProofBlocksAreUnrelated
#print axioms unknownIndirectTargetBlocks

end StageA.ProofBlockedTests
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(lean_dir, bundle="ProofBlocked")

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
