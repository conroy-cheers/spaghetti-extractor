from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_x87_replay_bridge_runtime import (
    X87ReplayBridgeRuntimePlan,
    X87ReplayRuntimeTargetPlan,
    x87_replay_bridge_runtime_lean_sources,
)
from spaghetti_extractor.relational.lean.interpreter_x87_replay_bridge_target import (
    x87_replay_bridge_target_lean_sources,
)
from tests.test_stage_a_relational_interpreter_x87_replay_bridge_target_kernel import (
    _synthetic_candidate_data_base_source,
    _synthetic_candidate_relocations_source,
    _synthetic_generated_plan,
)


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


@unittest.skipUnless(shutil.which("lean"), "Lean is required")
class StageARelationalInterpreterKernelX87ExecutionKernelTests(
    unittest.TestCase
):
    def test_structural_binding_and_executor_boundary_are_kernel_checked(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
            )
            source_text = (
                source_root / "RelationalInterpreterKernelX87Execution.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "nativeX87ReplayEntrySavedState_returnAddress",
                source_text,
            )
            self.assertIn("nativeX87ReplayPrivateStackWordsAvoid", source_text)
            self.assertNotIn("native_decide", source_text)
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterKernelX87Execution",
            )
            result = _run_lean_relational(
                root,
                bundle="RelationalInterpreterKernelX87Execution",
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])
        approved_axioms = {"propext", "Classical.choice", "Quot.sound"}
        for axioms in re.findall(
            r"depends on axioms: \[([^\]]*)\]", result["stdout"]
        ):
            observed = {
                name.strip() for name in axioms.replace("\n", "").split(",")
            }
            self.assertLessEqual(observed, approved_axioms, result["stdout"])
        for theorem in (
            "exactNativeX87ReplayFixedTemplateCertificate?",
            "exactNativeX87ReplayFixedTemplateSchedule_isSome",
            "exactNativeX87ReplayFixedTemplateMixedReplay_isSome",
            "exactNativeX87ReplayFixedTemplateStaticExecutionOfIsSome",
            "KernelMixedReplayInstruction.semanticStep_running_slot",
            "runKernelMixedReplaySemantic_running_slot",
            "exactNativeX87ReplayOriginalSingleton_isSome",
            "exactNativeX87ReplayCandidateSingleton_isSome",
            "nativeX87ReplayEntrySavedState_returnAddress",
            "nativeX87ReplayPhysicalStatesRelatedChecked_sound",
            "executeX87Singleton_nonPhysicalPreserved",
            "exactNativeX87ReplayFixedTemplateCertificate_isSome",
            "bindExactNativeX87ReplayNestedProgram_targetInventory",
            "exactNativeX87ReplayKernelProgramBinding",
            "ExactNativeX87ReplayFixedTemplateExecutor.kernelExecution",
            "ExactNativeX87ReplayFixedTemplateExecutor.templateExecution",
        ):
            self.assertIn(theorem, result["stdout"])

    def test_schedule_decoder_accepts_reviewed_forms_and_rejects_partial_x87(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterX87ReplayBridgeRuntime",
            )
            (stage_a / "X87FixedTemplateScheduleCheck.lean").write_text(
                """import StageA.RelationalInterpreterX87ReplayBridgeRuntime

namespace StageA.Relational.InterpreterX87ReplayBridgeRuntime

example : decodeNativeX87ReplaySchedule? [0x90] = some 1 := by decide
example : decodeNativeX87ReplaySchedule? [0xd9, 0xe8] = some 1 := by decide
example :
    decodeNativeX87ReplaySchedule?
        ([0xd9, 0xe8] ++ List.replicate 18 0x90) =
      some 19 := by decide
example : decodeNativeX87ReplaySchedule? [0xd8] = none := by decide
example : decodeNativeX87ReplaySchedule? [0x9b, 0xd8] = none := by decide

end StageA.Relational.InterpreterX87ReplayBridgeRuntime
""",
                encoding="ascii",
            )
            result = _run_lean_relational(
                root,
                bundle="X87FixedTemplateScheduleCheck",
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])

    def test_generated_structural_terms_and_executor_goal_are_kernel_checked(
        self,
    ) -> None:
        image, target_plan = _synthetic_generated_plan()
        mapping = target_plan.table.frame_mappings[0]
        image_bytes = bytearray(image)
        descriptor = target_plan.table.descriptors[0]
        runtime_plan = X87ReplayBridgeRuntimePlan(
            candidate_path=Path("synthetic.exe"),
            candidate_sha256=target_plan.candidate_sha256,
            candidate_size=len(image_bytes),
            target_plan_sha256="22" * 32,
            native_engine_plan_sha256="33" * 32,
            targets=(
                X87ReplayRuntimeTargetPlan(
                    descriptor_id=descriptor.id,
                    descriptor_rva=descriptor.descriptor_rva,
                    bridge_target_rva=descriptor.bridge_target_rva,
                    instruction_rva=mapping.instruction_rva,
                    instruction_bytes=descriptor.instruction_bytes,
                    operand=None,
                ),
            ),
        )
        target_sources = x87_replay_bridge_target_lean_sources(
            target_plan,
            candidate_data_module="SyntheticX87ReplayCandidateDataBase",
            relocation_data_module="SyntheticX87ReplayCandidateRelocations",
            pack_size=1,
        )
        runtime_sources = x87_replay_bridge_runtime_lean_sources(
            runtime_plan,
            pack_size=1,
        )
        candidate_replay = """import StageA.SyntheticX87ReplayCandidateDataBase
import StageA.RelationalInterpreterX87

namespace StageA.GeneratedRelational

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterX87

def originalPe : PE32 :=
  InterpreterKernelData.generatedInterpreterKernelCandidatePe

namespace CandidateX87Replay

def checkedInterpreterX87CandidateReplayBundleHandler : CandidateReplayHandler :=
  reviewedExpectedCandidateReplay originalPe

def checkedInterpreterX87CandidateReplayBundleExactInventory : True :=
  True.intro

end CandidateX87Replay
end StageA.GeneratedRelational
"""

        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterKernelX87Execution",
            )
            (stage_a / "SyntheticX87ReplayCandidateDataBase.lean").write_text(
                _synthetic_candidate_data_base_source(bytes(image_bytes)),
                encoding="ascii",
            )
            (stage_a / "SyntheticX87ReplayCandidateRelocations.lean").write_text(
                _synthetic_candidate_relocations_source(),
                encoding="ascii",
            )
            (
                stage_a / "GeneratedInterpreterX87CandidateReplayBundle.lean"
            ).write_text(candidate_replay, encoding="ascii")
            for filename, source in target_sources.items():
                (stage_a / filename).write_text(source, encoding="utf-8")
            for filename, source in runtime_sources.items():
                (stage_a / filename).write_text(source, encoding="ascii")
            result = _run_lean_relational(
                root,
                bundle="GeneratedRelationalInterpreterX87ReplayBridgeRuntime",
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        for theorem in (
            "generatedX87ReplayBridgeNestedProgramTargetInventoryExact",
            "generatedX87ReplayBridgeKernelProgramBinding",
            "generatedX87ReplayBridgeKernelExecution",
            "generatedX87ReplayBridgeKernelExecutionClosed",
            "generatedX87ReplayBridgeTemplateExecution",
        ):
            self.assertIn(theorem, result["stdout"])


if __name__ == "__main__":
    unittest.main()
