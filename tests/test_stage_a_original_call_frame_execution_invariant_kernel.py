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


_KERNEL = r'''import StageA.RelationalOriginalCallFrameExecutionInvariant

namespace StageA.OriginalCallFrameExecutionInvariantKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallComposition
open StageA.Relational.InternalDirectCallMixedOriginalIntegration
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.ValueProvenance

theorem concreteCallsDetermineFrameDepth
    (context : StaticProofContext) (world : RelationalWorld)
    (state : MachineState) (frames : List DormantOriginalCallFrame)
    (calls : List Nat)
    (holds : OriginalCallFramesHold context world state frames calls) :
    frames.length = calls.length :=
  holds.length_eq context world state frames calls

theorem runningInventoryBuildsPredicate
    (context : StaticProofContext) (targetId : Nat)
    (state : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld) (frames : List DormantOriginalCallFrame)
    (holds : OriginalCallFramesHold context world state frames calls) :
    OriginalCallFrameExecutionHolds context
      (.running targetId state calls eventIndex world) := by
  exact ⟨{ active := frames }, rfl, holds⟩

theorem suspendedCallbackRequiresRegistration
    (context : StaticProofContext) (targetId : Nat)
    (state : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld)
    (callback : WorldExternalCallbackRuntime)
    (callbacks : List WorldExternalCallbackRuntime)
    (holds : OriginalCallFrameExecutionHolds context
      (.callbackRunning targetId state calls eventIndex world
        (callback :: callbacks))) :
    KnownCallbackRuntime context callback :=
  holds.callback_known context targetId state calls eventIndex world
    (callback :: callbacks) callback (by simp)

theorem blockedReturnCannotEnterInvariant
    (context : StaticProofContext) (reason : ExecutionBlock) :
    Not (OriginalCallFrameExecutionHolds context (.blocked reason)) :=
  OriginalCallFrameExecutionHolds.blocked_false context reason

def checkedComponentCombines
    {program : DecodedWorldProgram}
    (checked : CheckedOriginalCallFrameExecutionInvariant program) :
    OriginalWorldExecutionInvariant program :=
  checked.toOriginalInvariant

theorem exactCallEntryPushesConcreteContinuation
    (program : DecodedWorldProgram) (before : WorldExecution)
    (callbacks : List WorldExternalCallbackRuntime)
    (calleeTargetId continuationTargetId : Nat)
    (entryState : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld)
    (frame : DormantOriginalCallFrame)
    (frames : List DormantOriginalCallFrame)
    (suspended : List (List DormantOriginalCallFrame))
    (stepExact :
      program.pe32TransitionSystem.step before = {
        next := resumeWorldExecution callbacks calleeTargetId entryState
          (continuationTargetId :: calls) eventIndex world
        observation := none
      })
    (continuationExact :
      frame.runtime.continuationTargetId = continuationTargetId)
    (frameHolds : frame.Holds program.context world entryState)
    (tailHolds : OriginalCallFramesHold program.context world entryState
      frames calls)
    (suspendedHolds :
      SuspendedOriginalCallFramesHold program.context callbacks suspended) :
    ({ active := frame :: frames, suspended := suspended } :
      OriginalCallFrameExecutionInventory).Holds program.context
        (program.pe32TransitionSystem.step before).next :=
  OriginalCallFrameExecutionInventory.callEntry program before callbacks
    calleeTargetId continuationTargetId entryState calls eventIndex world frame
    frames suspended stepExact continuationExact frameHolds tailHolds
    suspendedHolds

theorem directCheckedFrameFactRestores
    (fact : DormantOriginalValueFact)
    (binding : CheckedDirectCallCallerFrameWordControlContract context)
    {entryBinding : ExactDirectCallEntryBinding context binding.tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution context binding.tree entryBinding
      originalProgram candidateProgram)
    (member : fact.word ∈ binding.requestedWords)
    (source : fact.HoldsAtCaller context actual.source.original.world
      actual.source.original.state) :
    fact.HoldsAtCaller context actual.originalExit.world
      actual.originalExit.state :=
  fact.restoredByCheckedDirectCall binding actual member source

theorem finiteOriginCheckedFrameFactRestores
    (fact : DormantOriginalValueFact)
    (binding : CheckedFiniteOriginCallCallerFrameWordControlContract context)
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualFiniteOriginCallReturnExecution binding.entry
      originalProgram candidateProgram)
    (member : fact.word ∈ binding.requestedWords)
    (source : fact.HoldsAtCaller context actual.sourceOriginal.world
      actual.sourceOriginal.state) :
    fact.HoldsAtCaller context actual.originalExit.world
      actual.originalExit.state :=
  fact.restoredByCheckedFiniteOriginCall binding actual member source

#print axioms concreteCallsDetermineFrameDepth
#print axioms runningInventoryBuildsPredicate
#print axioms suspendedCallbackRequiresRegistration
#print axioms blockedReturnCannotEnterInvariant
#print axioms checkedComponentCombines
#print axioms exactCallEntryPushesConcreteContinuation
#print axioms directCheckedFrameFactRestores
#print axioms finiteOriginCheckedFrameFactRestores
#print axioms OriginalCallFrameExecutionInventory.internalPreserved
#print axioms OriginalCallFrameExecutionInventory.externalSuspended
#print axioms OriginalCallFrameExecutionInventory.externalReturned
#print axioms OriginalCallFrameExecutionInventory.externalCallbackEntry
#print axioms OriginalCallFrameExecutionInventory.callbackReturnRestored
#print axioms OriginalCallFrameExecutionInventory.returnRestored
#print axioms mismatchedReturn_not_admitted
#print axioms externalUnknownCallback_not_admitted
#print axioms mismatchedCallbackReturn_not_admitted

end StageA.OriginalCallFrameExecutionInvariantKernel
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalCallFrameExecutionInvariantKernelTests(unittest.TestCase):
    def test_generic_one_sided_call_frame_foundation_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root
            / "RelationalOriginalCallFrameExecutionInvariant.lean"
        ).read_text(encoding="utf-8")
        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bGnu\b",
        ):
            self.assertNotRegex(module_text, forbidden)
        for required in (
            "OriginalCallFramesHold",
            "SuspendedOriginalCallFramesHold",
            "OriginalCallFrameExecutionHolds",
            "OriginalCallFrameExecutionInventory.callEntry",
            "OriginalCallFrameExecutionInventory.internalPreserved",
            "OriginalCallFrameExecutionInventory.externalSuspended",
            "OriginalCallFrameExecutionInventory.externalReturned",
            "OriginalCallFrameExecutionInventory.externalCallbackEntry",
            "OriginalCallFrameExecutionInventory.callbackReturnRestored",
            "OriginalCallFrameExecutionInventory.returnRestored",
            "restoredByCheckedDirectCall",
            "restoredByCheckedFiniteOriginCall",
            "mismatchedReturn_not_admitted",
            "externalUnknownCallback_not_admitted",
            "mismatchedCallbackReturn_not_admitted",
            "CheckedOriginalCallFrameExecutionInvariant.toOriginalInvariant",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalCallFrameExecutionInvariant",
            )
            (stage_a / "OriginalCallFrameExecutionInvariantKernel.lean").write_text(
                _KERNEL,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="OriginalCallFrameExecutionInvariantKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 17, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
