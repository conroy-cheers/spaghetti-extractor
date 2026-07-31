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


def _copy_module_closure(
    source_root: Path, destination: Path, module: str
) -> None:
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


@unittest.skipUnless(shutil.which("lean"), "Lean is required")
class StageARelationalInterpreterKernelOperationInstantiationKernelTests(
    unittest.TestCase
):
    def _check_module(self, module: str) -> str:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            _copy_module_closure(source_root, stage_a, module)
            result = _run_lean_relational(root, bundle=module)

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        for match in _AXIOMS.findall(output):
            axioms = {
                item.strip() for item in match.split(",") if item.strip()
            }
            self.assertLessEqual(axioms, _APPROVED_AXIOMS)
        return output

    def test_checked_operation_replay_compiles_without_bad_axioms(self) -> None:
        output = self._check_module(
            "RelationalInterpreterKernelOperationReplay"
        )
        for theorem in (
            "CheckedNativeOperationInstructionReplay.facts",
            "CheckedNativeOperationRunningInstruction.stepExact",
            "CheckedNativeOperationRunningInstruction.path",
            "CheckedNativeOperationStoppedInstruction.stepExact",
            "CheckedNativeOperationStoppedInstruction.path",
            "CheckedNativeOperationPath.trans_result",
            "CheckedNativeOperationPath.trans_after",
            "CheckedNativeOperationPath.trans_observations",
            "CheckedNativeOperationPath.ofNonempty_after",
            "CheckedNativeOperationPath.ofNonempty_observations",
            "CheckedNativeOperationFunctionReplay.entriesExact",
            "CheckedNativeOperationFunctionReplay.exactInventory",
        ):
            self.assertIn(theorem, output)

    def test_checked_operation_postcondition_compiles_without_bad_axioms(
        self,
    ) -> None:
        output = self._check_module(
            "RelationalInterpreterKernelOperationPostcondition"
        )
        for theorem in (
            "CheckedNativeOperationPostcondition.runningRegistersHold",
            "CheckedNativeOperationPostcondition.runningMemoryFrame",
            "CheckedNativeOperationPostcondition.stoppedRegistersHold",
            "CheckedNativeOperationPostcondition.stoppedMemoryFrame",
        ):
            self.assertIn(theorem, output)

    def test_checked_operation_cutpoints_compile_without_bad_axioms(
        self,
    ) -> None:
        output = self._check_module(
            "RelationalInterpreterKernelOperationCutpointChecker"
        )
        for theorem in (
            "operationInvariantEffect?_nextMachineState",
            "nativeOperationInvariantEdgeChecked_sound",
            "CheckedNativeOperationInvariantTransfer.sound",
            "CheckedNativeOperationRunningCutpoint.targetHolds",
            "CheckedNativeOperationRunningCutpoint.replayTargetHolds",
            "CheckedNativeOperationStoppedCutpoint.replayTargetHolds",
            "CheckedNativeOperationStoppedCutpoint.outcomeExact",
            "CheckedNativeOperationStoppedCutpoint.worldStepExpected",
        ):
            self.assertIn(theorem, output)

    def test_checked_operation_cutpoint_pullback_fixture(self) -> None:
        source = """import StageA.RelationalInterpreterKernelOperationCutpointChecker

namespace StageA.OperationCutpointFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationCutpointChecker

def sourceInvariant : NativeOperationInvariant := {
  predicates := [.equal (.constant 7) (.constant 7)]
}

def targetInvariant : NativeOperationInvariant := {
  predicates := [.equal (.inputReg .eax) (.constant 7)]
}

def effect : NormalizedSymbolicBehavior := {
  registers := { initialSymbolic.registers with eax := .constant 7 }
  x87 := initialSymbolic.x87
  writes := []
  flags := none
  outcome := .jump 0
}

theorem pullbackExact :
    targetInvariant.pullback? effect = some sourceInvariant := by
  decide +kernel

theorem targetHoldsForEveryState
    (state : MachineState) (holds : sourceInvariant.Holds state) :
    targetInvariant.Holds ((effect.eval state).nextMachineState state) :=
  NativeOperationInvariant.pullback?_sound targetInvariant sourceInvariant
    effect pullbackExact state holds

#print axioms targetHoldsForEveryState

end StageA.OperationCutpointFixture
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterKernelOperationCutpointChecker",
            )
            (stage_a / "OperationCutpointFixture.lean").write_text(
                source, encoding="ascii"
            )
            result = _run_lean_relational(
                root, bundle="OperationCutpointFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertIn("targetHoldsForEveryState", output)
        self.assertNotIn("sorryAx", output)

    def test_generated_style_checked_block_fixture(self) -> None:
        source = """import StageA.RelationalInterpreterKernelOperationTraceChecker

namespace StageA.OperationBlockFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationReplay
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

def pe : PE32 := {
  bytes := ByteTree.ofBytes [0x90, 0xeb, 0x00]
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 3
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{
    virtualSize := 3
    virtualAddress := 0
    rawSize := 3
    rawPointer := 0
    characteristics := 0x60000020
  }]
}

def environment : NativeWorldEnvironment := {
  action := fun _ _ _ => .blocked .missingRuntimeContinuation
}

def candidate : ExactNativeWorldProgram := {
  pe
  imports := []
  environment
}

def instruction0 : KernelInstruction := {
  rva := 0
  bytes := [0x90]
}

def replay0 : CheckedNativeOperationRunningInstruction candidate instruction0 0 :=
  .ofCanonicalChecked candidate instruction0 0
    (by decide +kernel) (by decide +kernel)

def edge0 : CheckedNativeOperationRunningEdge candidate := {
  instruction := instruction0
  undefinedSlot := 0
  replay := replay0
  cutpoint := .ofTrivial replay0
}

def instruction1 : KernelInstruction := {
  rva := 1
  bytes := [0xeb, 0x00]
}

def replay1 : CheckedNativeOperationStoppedInstruction candidate instruction1 1 :=
  .ofCanonicalChecked candidate instruction1 1
    (by decide +kernel) (by decide +kernel)

def postcondition1 : CheckedNativeOperationPostcondition replay1.behavior :=
  .ofStoppedReplay replay1

def edge1 : CheckedNativeOperationStoppedEdge candidate := {
  instruction := instruction1
  undefinedSlot := 1
  replay := replay1
  cutpoint := .ofTrivial replay1 postcondition1
}

def trace : CheckedNativeOperationRunningTrace candidate := {
  first := edge0
  tail := []
  checked := by decide +kernel
}

def block : CheckedNativeOperationBlock candidate := {
  running := some trace
  terminal := edge1
  checked := by decide +kernel
}

theorem blockPath (state : MachineState)
    (calls : List StageA.Relational.InterpreterKernel.NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running 0 0 state calls eventIndex events world)
      (block.observations state calls eventIndex events world)
      (block.after state calls eventIndex events world) :=
  block.path state calls eventIndex events world

#print axioms blockPath

end StageA.OperationBlockFixture
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterKernelOperationTraceChecker",
            )
            (stage_a / "OperationBlockFixture.lean").write_text(
                source, encoding="ascii"
            )
            result = _run_lean_relational(
                root, bundle="OperationBlockFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertIn("blockPath", output)
        self.assertNotIn("sorryAx", output)

    def test_checked_operation_traces_compile_without_bad_axioms(self) -> None:
        output = self._check_module(
            "RelationalInterpreterKernelOperationTraceChecker"
        )
        for theorem in (
            "CheckedNativeOperationRunningTrace.runExact",
            "CheckedNativeOperationRunningTrace.invariantHolds",
            "CheckedNativeOperationBlock.runExact",
            "CheckedNativeOperationBlock.path",
            "CheckedNativeOperationBlock.toCheckedPath_after",
            "CheckedNativeOperationBlock.toCheckedPath_observations",
            "CheckedNativeOperationBlock.terminalWorldStepExpected",
            "CheckedNativeOperationBlock.afterExpected",
            "CheckedNativeOperationBlock.observationsExpected",
            "CheckedNativeOperationBlock.terminalInvariantHolds",
        ):
            self.assertIn(theorem, output)

    def test_environment_indexed_operation_interface_compiles_without_bad_axioms(
        self,
    ) -> None:
        output = self._check_module(
            "RelationalInterpreterKernelOperationEnvironment"
        )
        for theorem in (
            "kernelOperationRefinesUsingAtEnvironment_iff",
            "kernelABIAtEnvironment_request",
            "CheckedKernelOperationExternalEnvironment.semanticResult",
        ):
            self.assertIn(theorem, output)

    def test_checked_operation_control_successors_compile_without_bad_axioms(
        self,
    ) -> None:
        output = self._check_module(
            "RelationalInterpreterKernelOperationControlChecker"
        )
        self.assertIn(
            "CheckedNativeOperationLocalSuccessor.afterRva", output
        )
        self.assertIn("CheckedNativeOperationLocalEdge.execute", output)
        self.assertIn(
            "CheckedNativeOperationStatePreservingLocalEdge.afterMachineState",
            output,
        )
        self.assertIn(
            "CheckedNativeOperationStatePreservingLocalEdge.afterInvariant",
            output,
        )
        self.assertIn(
            "CheckedNativeOperationLocalConnection.follow", output
        )
        self.assertIn(
            "CheckedNativeOperationLocalConnection.pathThroughTarget", output
        )

    def test_checked_operation_call_frames_compile_without_bad_axioms(
        self,
    ) -> None:
        output = self._check_module(
            "RelationalInterpreterKernelOperationFrameChecker"
        )
        self.assertIn(
            "nativeOperationSuccessorCallFrames?_context", output
        )
        self.assertIn(
            "CheckedNativeOperationStatePreservingLocalEdge.afterCallFrames",
            output,
        )
        self.assertIn(
            "CheckedNativeOperationLocalConnection.followFrames", output
        )

    def test_checked_operation_routes_compile_without_bad_axioms(self) -> None:
        output = self._check_module(
            "RelationalInterpreterKernelOperationRouteChecker"
        )
        self.assertIn(
            "CheckedNativeOperationLocalRoute.execute", output
        )

    def test_checked_operation_return_and_frame_fixture(self) -> None:
        source = """import StageA.RelationalInterpreterKernelOperationFrameChecker

namespace StageA.OperationFrameFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernelOperationControlChecker
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationFrameChecker
open StageA.Relational.InterpreterNativeWorld

def returnTarget : Expr := .read32 (.inputReg .esp)

def returnInvariant : NativeOperationInvariant := {
  predicates := [.equal returnTarget (.constant 4660)]
}

theorem stackReturnAccepted :
    checkedNativeOperationLocalSuccessor returnInvariant
      (some (.returned returnTarget)) (.returned 8192 4660) = true := by
  decide +kernel

theorem wrongStackReturnRejected :
    checkedNativeOperationLocalSuccessor returnInvariant
      (some (.returned returnTarget)) (.returned 8192 4661) = false := by
  decide +kernel

def callerFrame : StageA.Relational.InterpreterKernel.NativeCallFrame :=
  expectedNativeOperationCallFrame 8192 4660

theorem checkedPush :
    nativeOperationSuccessorCallFrames? (.call 4096 8192 4660) [] =
      some [callerFrame] := by
  decide +kernel

theorem checkedPop :
    nativeOperationSuccessorCallFrames? (.returned 8192 4660)
      [callerFrame] = some [] := by
  decide +kernel

#print axioms stackReturnAccepted
#print axioms wrongStackReturnRejected
#print axioms checkedPush
#print axioms checkedPop

end StageA.OperationFrameFixture
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterKernelOperationFrameChecker",
            )
            (stage_a / "OperationFrameFixture.lean").write_text(
                source, encoding="ascii"
            )
            result = _run_lean_relational(
                root, bundle="OperationFrameFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertIn("stackReturnAccepted", output)
        self.assertIn("wrongStackReturnRejected", output)
        self.assertNotIn("sorryAx", output)

    def test_exact_package_and_semantic_closure_compile_without_bad_axioms(
        self,
    ) -> None:
        output = self._check_module(
            "RelationalInterpreterKernelOperationInstantiation"
        )
        for theorem in (
            "checkedNativeWorldKernelOperationDispatchFamily",
            "CheckedKernelOperationInstantiation.runRefines",
            "CheckedKernelOperationInstantiation.runCutpointCluster",
            (
                "CheckedKernelOperationInstantiation."
                "programLookupRefinesUsingClosed"
            ),
            "CheckedKernelOperationInstantiation.runRefinesUsingClosed",
            "CheckedKernelOperationInstantiation.invokeRefines",
            "CheckedKernelOperationInstantiation.invokeRefinesUsingClosed",
            "CheckedKernelOperationInstantiation.stepRefines",
            "CheckedKernelOperationInstantiation.stepRefinesUsingClosed",
            "CheckedKernelOperationInstantiation.refinementFamily",
            "checkedKernelSemanticClosure",
        ):
            self.assertIn(theorem, output)


if __name__ == "__main__":
    unittest.main()
