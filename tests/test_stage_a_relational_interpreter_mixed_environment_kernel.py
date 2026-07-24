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
class StageARelationalInterpreterMixedEnvironmentKernelTests(unittest.TestCase):
    def test_exact_external_chunk_compiles_with_only_approved_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterMixedEnvironment"
            )
            (stage_a / "RelationalInterpreterMixedEnvironmentKernel.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterMixedEnvironmentKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 7, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


_KERNEL_FIXTURE = r"""import StageA.RelationalInterpreterMixedEnvironment

namespace StageA.Relational.InterpreterMixedEnvironmentKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

example
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedExternalFrameContract)
    (originalBefore : WorldExecution)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (dispatch : ExactNativeExternalDispatch candidate)
    (originalDispatch : ExactOriginalExternalDispatch original originalBefore
      suspension callbacks)
    (boundaryRelated :
      contract.externalBoundariesRelated suspension dispatch.boundary)
    (frameBoundary : MixedExternalFrameBoundaryRelated frames suspension callbacks
      dispatch.continuationRva dispatch.calls)
    (environmentsRefine : ExactOneToOneMixedExternalEnvironmentsRefine original
      candidate contract frames) :
    ExactMixedExternalInteractionChunk original candidate contract frames
      originalBefore suspension callbacks dispatch := by
  exact exactMixedExternalInteractionChunk original candidate contract frames
    originalBefore suspension callbacks dispatch originalDispatch boundaryRelated
    frameBoundary environmentsRefine

example (contract : MixedRelationContract)
    (action : WorldExternalProtocolAction) (reason : ExecutionBlock) :
    Not (MixedExternalEnvironmentActionsRelated contract action (.blocked reason)) :=
  MixedExternalEnvironmentActionsRelated.candidate_blocked_is_unrelated
    contract action reason

example (contract : MixedRelationContract)
    (entry : WorldExternalCallbackAction)
    (action : NativeWorldExternalAction) :
    Not (MixedExternalEnvironmentActionsRelated contract (.callback entry) action) :=
  MixedExternalEnvironmentActionsRelated.callback_is_unrelated contract entry action

example
    (related : MixedExternalSuccessorsRelated contract frames suspension callbacks
      dispatch (.fault originalCause) (.fault candidateCause)) :
    originalCause = candidateCause :=
  related.fault_causes_equal

example
    {reachabilityTargetIds : List Nat}
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (chunk : ExactMixedExternalInteractionChunk original candidate contract frames
      originalBefore suspension callbacks dispatch)
    (beforeRelated : invariant.holds originalBefore dispatch.before)
    (afterRelated : invariant.holds
      (originalExternalAfter original suspension callbacks) dispatch.after) :
    MixedWorldComponentChunkRefinement original candidate contract invariant
      originalBefore dispatch.before :=
  chunk.toComponent invariant beforeRelated afterRelated

#print axioms MixedExternalSuccessorsRelated.fault_causes_equal
#print axioms externalBoundaryObservationsRelated
#print axioms MixedExternalEnvironmentActionsRelated.candidate_blocked_is_unrelated
#print axioms MixedExternalEnvironmentActionsRelated.callback_is_unrelated
#print axioms ExactNativeExternalDispatch.path
#print axioms mixedExternalActions_successorsRelated
#print axioms exactMixedExternalInteractionChunk
#print axioms ExactMixedExternalInteractionChunk.toComponent

end StageA.Relational.InterpreterMixedEnvironmentKernel
"""


if __name__ == "__main__":
    unittest.main()
