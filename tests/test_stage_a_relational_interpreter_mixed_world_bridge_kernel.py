from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


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
class StageARelationalInterpreterMixedWorldBridgeKernelTests(unittest.TestCase):
    def test_operational_trace_interface_compiles_without_unapproved_axioms(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterMixedWorldBridge"
            )
            (stage_a / "RelationalInterpreterMixedWorldBridgeKernel.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterMixedWorldBridgeKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertIn("mixedWorldProgramsEquivalent_trace", output)
        self.assertIn("MixedWorldChunkComposition.chunksRefine", output)


_KERNEL_FIXTURE = r"""import StageA.RelationalInterpreterMixedWorldBridge

namespace StageA.Relational.InterpreterMixedWorldBridgeKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

example
    {originalContext : OriginalDecodedStaticContext}
    {original : DecodedWorldProgram}
    {candidate : ExactNativeWorldProgram}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    (certificate : MixedWorldAcceptanceCertificate originalContext original
      candidate contract launch)
    (fuel : Nat)
    (originalWorld candidateWorld : RelationalWorld)
    (originalState candidateState : MachineState)
    (initial : MixedLaunchStatesRelated originalContext candidate contract
      originalWorld candidateWorld originalState candidateState) :
    ChunkedRelatedTrace original.pe32TransitionSystem candidate.transitionSystem
      certificate.composition.invariant.holds
      contract.eventObservationsRelated fuel
      (.running launch.rootTargetId originalState
        launch.continuationTargetIds 0 originalWorld)
      (.running certificate.candidateRootRva 0 candidateState
        (certificate.composition.candidateLaunchCalls candidateState) 0 []
        candidateWorld) := by
  exact mixedWorldProgramsEquivalent_trace certificate fuel originalWorld
    candidateWorld originalState candidateState initial

example (contract : MixedRelationContract) (reason : ExecutionBlock) :
    Not (contract.eventObservationsRelated
      (some (.proofBlocked reason)) none) :=
  contract.proofBlocked_left_is_unrelated reason none

#print axioms MixedWorldChunkComposition.chunksRefine
#print axioms mixedWorldProgramsEquivalent
#print axioms mixedWorldProgramsEquivalent_trace

end StageA.Relational.InterpreterMixedWorldBridgeKernel
"""


if __name__ == "__main__":
    unittest.main()
