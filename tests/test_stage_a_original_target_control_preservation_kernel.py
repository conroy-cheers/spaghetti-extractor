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


_KERNEL = r'''import StageA.RelationalOriginalTargetControlPreservation

namespace StageA.OriginalTargetControlPreservationKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalTargetControlPreservation
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

def checkedControlProviderBuildsExactTransition
    {program : Program} {targetId : Nat}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      context}
    {checked : CheckedOriginalTargetEffect program targetId}
    (evidence : CheckedOriginalTargetControlEvidence context inventory checked)
    (invocation : OriginalTargetInvocation targetId)
    (holds : inventory.Holds invocation.execution) :
    CheckedOriginalTargetControlPreservationCase context inventory checked
      invocation :=
  evidence.toPreservationCase invocation holds

theorem directCallControlRetainsBothTargets
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {sourceTargetId target continuation : Nat} {state : MachineState}
    (evidence : CheckedOriginalDirectCallEvidence targetIds target
      continuation) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.call target continuation) :=
  evidence.callControl

theorem importedControlRetainsExactSiteLookup
    {program : DecodedWorldProgram} {sourceTargetId continuation : Nat}
    {imported : ExternalTarget}
    (evidence : CheckedOriginalImportEvidence program sourceTargetId
      continuation imported) :
    resolveExternalCallSite program.context program.externalCallSites
      sourceTargetId continuation imported = some evidence.siteId :=
  evidence.siteResolved

theorem completeInvariantRebuildsSameStackControlPost
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    {sourceTargetId nextTargetId : Nat}
    (invocation : OriginalTargetInvocation sourceTargetId)
    (holds : inventory.Holds invocation.execution)
    (afterState : MachineState) (afterEventIndex : Nat)
    (afterWorld : RelationalWorld)
    (nextReachable : nextTargetId ∈ inventory.reachableTargets.targetIds)
    (framesPreserved : forall frame : DormantOriginalCallFrame,
      DormantOriginalCallFrame.Holds program.context invocation.world
          invocation.state frame ->
        DormantOriginalCallFrame.Holds program.context afterWorld afterState
          frame) :
    CheckedOriginalControlPost program.context
      inventory.reachableTargets.targetIds
      (originalNormalizedResume invocation.routingCallbacks nextTargetId
        afterState invocation.calls afterEventIndex afterWorld) :=
  controlPostOfPreservedFrames invocation holds nextTargetId afterState
    afterEventIndex afterWorld nextReachable framesPreserved

theorem returnedPostIsControlClosed
    (context : StaticProofContext) (targetIds : List Nat)
    (state : MachineState) (world : RelationalWorld) :
    CheckedOriginalControlPost context targetIds (.returned state world) :=
  CheckedOriginalControlPost.returned context targetIds state world

theorem terminatedPostIsControlClosed
    (context : StaticProofContext) (targetIds : List Nat)
    (world : RelationalWorld) :
    CheckedOriginalControlPost context targetIds (.terminated world) :=
  CheckedOriginalControlPost.terminated context targetIds world

theorem faultPostIsControlClosed
    (context : StaticProofContext) (targetIds : List Nat)
    (cause : ModeledFault) :
    CheckedOriginalControlPost context targetIds (.fault cause) :=
  CheckedOriginalControlPost.fault context targetIds cause

theorem unmappedReturnCallCannotAcquireControlEvidence
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {sourceTargetId target : Nat} {state : MachineState}
    (evidence : CheckedOriginalOutcomeEvidence context targetIds sourceTargetId
      state (.callUnmappedReturn target)) : False :=
  callUnmappedReturn_not_classified evidence

#print axioms checkedControlProviderBuildsExactTransition
#print axioms directCallControlRetainsBothTargets
#print axioms importedControlRetainsExactSiteLookup
#print axioms completeInvariantRebuildsSameStackControlPost
#print axioms returnedPostIsControlClosed
#print axioms terminatedPostIsControlClosed
#print axioms faultPostIsControlClosed
#print axioms unmappedReturnCallCannotAcquireControlEvidence

end StageA.OriginalTargetControlPreservationKernel
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalTargetControlPreservationKernelTests(unittest.TestCase):
    def test_generic_control_preservation_layer_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalOriginalTargetControlPreservation.lean"
        ).read_text(encoding="utf-8")

        for forbidden in (
            r"^\s*axiom\b",
            r"^\s*opaque\b",
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bGnu\b",
            r"authorizing_lean_terms",
            r"status\s*==",
        ):
            self.assertNotRegex(module_text, forbidden)

        for required in (
            "CheckedOriginalStaticTargetEvidence",
            "CheckedOriginalBranchTargetEvidence",
            "CheckedOriginalDirectCallEvidence",
            "CheckedOriginalImportEvidence",
            "CheckedOriginalReturnEvidence",
            "CheckedOriginalControlPost.running",
            "CheckedOriginalControlPost.callbackRunning",
            "CheckedOriginalControlPost.awaitingExternal",
            "CheckedOriginalControlPost.returned",
            "CheckedOriginalControlPost.terminated",
            "CheckedOriginalControlPost.fault",
            "originalNormalizedResume",
            "controlPostOfPreservedFrames",
            "CheckedOriginalRoutedOutcome",
            "CheckedOriginalTargetControlEvidence",
            "toPreservationCase",
            "returnedControl",
            "jumpControl",
            "branchControl",
            "callControl",
            "externalCallControl",
            "externalJumpControl",
            "bulkCopyControl",
            "bulkFillControl",
            "indirectCallControl",
            "indirectJumpControl",
            "checkedContinueControl",
            "atomicCompareExchangeControl",
            "callUnmappedReturn_not_classified",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalTargetControlPreservation",
            )
            (stage_a / "OriginalTargetControlPreservationKernel.lean").write_text(
                _KERNEL,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="OriginalTargetControlPreservationKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 8, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
