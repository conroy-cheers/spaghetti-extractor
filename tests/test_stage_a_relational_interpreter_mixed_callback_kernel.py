from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}


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
class StageARelationalInterpreterMixedCallbackKernelTests(unittest.TestCase):
    def test_nested_callback_paths_compile_with_only_approved_axioms(self) -> None:
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
            (stage_a / "RelationalInterpreterMixedCallbackKernel.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterMixedCallbackKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 12, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


_KERNEL_FIXTURE = r"""import StageA.RelationalInterpreterMixedEnvironment

namespace StageA.Relational.InterpreterMixedCallbackKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterNativeWorld

example (program : ExactNestedNativeWorldProgram)
    (suspension : NativeWorldExternalSuspension)
    (frames : List NativeWorldExternalCallbackRuntime)
    (entry : NativeWorldExternalCallbackAction)
    (allowed : nestedNativeCallbackTargetAllowed program entry.targetRva = true) :
    (applyNestedNativeWorldExternalAction program suspension frames
      (.callback entry)).next =
      .running entry.targetRva 0 entry.state [] suspension.eventIndex
        suspension.events entry.world ({ suspension, entry } :: frames) := by
  simp [applyNestedNativeWorldExternalAction, allowed]

example (program : ExactNestedNativeWorldProgram)
    (suspension : NativeWorldExternalSuspension)
    (frames : List NativeWorldExternalCallbackRuntime)
    (entry : NativeWorldExternalCallbackAction)
    (notAllowed : nestedNativeCallbackTargetAllowed program entry.targetRva = false) :
    (applyNestedNativeWorldExternalAction program suspension frames
      (.callback entry)).next =
      .blocked (.unmappedIndirectControl
        (BitVec.ofNat 32 (program.pe.imageBase + entry.targetRva))) := by
  simp [applyNestedNativeWorldExternalAction, notAllowed,
    blockedNestedNativeWorldTransition]

example (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (originalFrame : WorldExternalCallbackRuntime)
    (candidateFrame : NativeWorldExternalCallbackRuntime)
    (originalTail : List WorldExternalCallbackRuntime)
    (candidateTail : List NativeWorldExternalCallbackRuntime)
    (suspensionsRelated : MixedNestedExternalSuspensionCoreRelated contract frames
      originalFrame.suspension originalTail candidateFrame.suspension)
    (entriesRelated : MixedNestedExternalCallbackEntriesRelated contract frames
      originalFrame.entry candidateFrame.entry)
    (tailsRelated : MixedNestedExternalCallbackFramesRelated contract frames
      originalTail candidateTail) :
    MixedNestedExternalCallbackFramesRelated contract frames
      (originalFrame :: originalTail) (candidateFrame :: candidateTail) := by
  exact .cons originalFrame candidateFrame originalTail candidateTail
    suspensionsRelated entriesRelated tailsRelated

example (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (originalFrame : WorldExternalCallbackRuntime)
    (candidateFrame : NativeWorldExternalCallbackRuntime)
    (originalTail : List WorldExternalCallbackRuntime)
    (candidateTail : List NativeWorldExternalCallbackRuntime)
    (related : MixedNestedExternalCallbackFramesRelated contract frames
      (originalFrame :: originalTail) (candidateFrame :: candidateTail)) :
    MixedNestedExternalCallbackFramesRelated contract frames originalTail
      candidateTail :=
  related.tail

example (candidate : ExactNestedNativeWorldProgram)
    (contract : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (originalEntry : WorldExternalCallbackAction)
    (candidateEntry : NativeWorldExternalCallbackAction)
    (entriesRelated : MixedNestedExternalCallbackEntriesRelated contract frames
      originalEntry candidateEntry)
    (allowed :
      nestedNativeCallbackTargetAllowed candidate candidateEntry.targetRva = true) :
    MixedNestedExternalEnvironmentActionsRelated candidate contract frames
      (.callback originalEntry) (.callback candidateEntry) := by
  exact ⟨entriesRelated, allowed⟩

#check NativeWorldExternalAction.callback
#check NativeWorldExternalSuspension.request
#check ExactNestedNativeWorldProgram.transitionSystem
#check MixedNestedExternalSuccessorsRelated.callback
#check ExactMixedNestedExternalInteractionChunk
#check ExactMixedNestedExternalProtocolChunk
#check ExactMixedNestedExternalCallbackReturnChunk

#print axioms exactNestedNativeWorldStepIsNonempty
#print axioms nestedNativeCallbackReturnUnwinds
#print axioms MixedNestedExternalCallbackFramesRelated.tail
#print axioms ExactNestedNativeExternalDispatch.pathToSuspension
#print axioms ExactNestedNativeExternalDispatch.protocolPath
#print axioms mixedNestedExternalActions_successorsRelated
#print axioms mixedNestedExternalActionObservationsRelated
#print axioms exactMixedNestedExternalInteractionChunk
#print axioms ExactNestedNativeExternalProtocolBoundary.path
#print axioms mixedNestedExternalProtocolActions_successorsRelated
#print axioms exactMixedNestedExternalProtocolChunk
#print axioms mixedNestedExternalCallbackReturn_suspensionsRelated
#print axioms exactMixedNestedExternalCallbackReturnChunk

end StageA.Relational.InterpreterMixedCallbackKernel
"""


if __name__ == "__main__":
    unittest.main()
