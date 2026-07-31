from __future__ import annotations

import re
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_x87_execution import (
    interpreter_kernel_x87_execution_lean_snippet,
)


class StageAInterpreterKernelX87ExecutionTests(unittest.TestCase):
    def test_entry_replay_is_split_into_cacheable_kernel_facts(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (
            root
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelX87Execution.lean"
        ).read_text(encoding="utf-8")

        for declaration in (
            "nativeX87ReplayFixedTemplateEntryLoadedEax",
            "nativeX87ReplayFixedTemplateEntryStoredEncoded",
            "nativeX87ReplayFixedTemplateEntryFrStorAddress",
            "nativeX87ReplayFixedTemplateEntryFrStor_exact",
            "nativeX87ReplayFixedTemplateEntryRoles_afterRestore",
            "nativeX87ReplayFixedTemplateEntryRoles_afterRestore_running",
            "nativeX87ReplayFixedTemplateEntryRoles_running",
        ):
            self.assertEqual(
                len(
                    re.findall(
                        rf"\btheorem {re.escape(declaration)}\b",
                        source,
                    )
                ),
                1,
            )
        self.assertNotIn("set_option maxRecDepth", source)

        wrapper = source.split(
            "private theorem nativeX87ReplayFixedTemplateEntryRoles_running",
            maxsplit=1,
        )[1].split(
            "/-- Once the fixed bridge has restored", maxsplit=1
        )[0]
        self.assertIn(
            "nativeX87ReplayFixedTemplateEntryRoles_afterRestore runtimeTarget",
            wrapper,
        )
        self.assertIn(
            "nativeX87ReplayFixedTemplateEntryRoles_afterRestore_running",
            wrapper,
        )
        self.assertNotIn("semanticStep_", wrapper)

    def test_generic_kernel_theorem_has_fixed_template_boundary(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (
            root
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelX87Execution.lean"
        ).read_text(encoding="utf-8")
        target_source = (
            root
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterX87ReplayBridgeTarget.lean"
        ).read_text(encoding="utf-8")

        for required in (
            "ExactNativeX87ReplayKernelProgramBinding",
            "bindExactNativeX87ReplayNestedProgram",
            "nativeX87ReplayBridgeTargetInventory_exact",
            "exactNativeX87ReplayKernelProgramBinding",
            "ExactNativeX87ReplayFixedTemplateCertificate",
            "ExactNativeX87ReplayFixedTemplateExecutor",
            "ExactNativeX87ReplaySilentRunningEndpoint",
            "ExactNativeX87ReplayCheckedPostFrame",
            "exactNativeX87ReplayFixedTemplateCertificate?",
            "nativeX87ReplayFixedTemplateSchedule?",
            "executeKernelReduction",
            "nativeX87ReplayPhysicalStatesRelatedChecked_sound",
            "executeX87Singleton_nonPhysicalPreserved",
            "callRun",
            "entryRun",
            "instructionRun",
            "captureRun",
            "returnRun",
            "candidateExecuted",
            "instructionPhysicalInput",
            "instructionCommandInput",
            "faultFree",
            "nonX87Output",
            "memoryEffects",
            "physicalState",
            "mixedPost",
            "outputEncoded",
            "outputRelated",
            "kernelExecution",
            "templateExecution",
        ):
            self.assertIn(required, source)
        for required in (
            "NativeX87ReplayMixedPostStateRelated",
            "nativeX87ReplayNonX87OutputChecked",
            "nativeX87ReplayMemoryEffectsRelated",
            "nativeX87ReplayPhysicalStatesRelatedChecked",
            "nativeX87ReplayEngineLayoutCompatible",
            "faultFree :",
        ):
            self.assertIn(required, target_source)

        checker = source.split(
            "def exactNativeX87ReplayFixedTemplateCertificate?", maxsplit=1
        )[1].split("private theorem exactSilentEndpoint", maxsplit=1)[0]
        self.assertEqual(checker.count("runRelatedSteps program.transitionSystem"), 5)
        self.assertIn("RelationalWorld.empty", checker)
        self.assertIn("exactNativeX87ReplayCheckedPostFrame?", checker)
        self.assertIn("entryEndpoint.state", checker)
        self.assertIn("nativeX87ReplayPhysicalStatesRelatedChecked", source)
        self.assertIn("nativeX87ReplayMemoryEffectsRelated", source)
        candidate_execution = checker.split(
            "match exactOptionValue?\n"
            "                              (executeX87Singleton pe",
            maxsplit=1,
        )[1].split("with", maxsplit=1)[0]
        self.assertIn("entryEndpoint.state", candidate_execution)
        self.assertNotIn("source.candidateInput", candidate_execution)
        self.assertIn("| none => none", checker)
        executor = source.split(
            "structure ExactNativeX87ReplayFixedTemplateExecutor", maxsplit=1
        )[1].split("/-- Generic construction", maxsplit=1)[0]
        self.assertIn("staticInventory :", executor)
        self.assertNotIn("execute :", executor)
        self.assertNotIn(".isSome = true", executor)
        self.assertNotIn(
            "exactNativeX87ReplayFixedTemplateCertificate?", executor
        )
        self.assertNotIn("Nonempty (ExactNativeX87ReplayFixedTemplateCertificate", executor)
        for submitted in (
            "originalExecuted :",
            "candidateExecuted :",
            "callRun :",
            "entryRun :",
            "instructionRun :",
            "captureRun :",
            "returnRun :",
            "targetAfter :",
            "outputEncoded :",
        ):
            self.assertNotIn(submitted, executor)
        self.assertNotIn("programBinding :", executor)
        self.assertNotIn("handlerInventory :", executor)
        self.assertNotIn("NonemptyRelatedPath", source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_generated_interface_closes_structural_binding_once(self) -> None:
        snippet = interpreter_kernel_x87_execution_lean_snippet()

        self.assertEqual(
            snippet.count("def generatedX87ReplayBridgeNestedProgram"),
            1,
        )
        self.assertEqual(
            snippet.count("def generatedX87ReplayBridgeKernelProgramBinding"),
            1,
        )
        for theorem in (
            "generatedX87ReplayBridgeNestedProgramPeExact",
            "generatedX87ReplayBridgeNestedProgramImportsExact",
            "generatedX87ReplayBridgeNestedProgramTargetInventoryExact",
        ):
            self.assertEqual(snippet.count(f"theorem {theorem}"), 1)
        self.assertEqual(
            snippet.count(
                "def GeneratedX87ReplayBridgeFixedTemplateChecksGoal"
            ),
            1,
        )
        self.assertEqual(
            snippet.count(
                "theorem generatedX87ReplayBridgeKernelExecution\n"
            ),
            1,
        )
        self.assertEqual(
            snippet.count(
                "theorem generatedX87ReplayBridgeKernelExecutionClosed"
            ),
            1,
        )
        self.assertEqual(
            snippet.count("theorem generatedX87ReplayBridgeTemplateExecution"),
            1,
        )
        self.assertIn("bindExactNativeX87ReplayNestedProgram", snippet)
        self.assertIn("peExact :=", snippet)
        self.assertIn("importsExact :=", snippet)
        self.assertIn("targetInventory :=", snippet)
        self.assertIn("generatedInterpreterKernelCandidatePe", snippet)
        self.assertIn("generatedInterpreterKernelImports", snippet)
        self.assertIn("generatedX87ReplayBridgeTable.nativeTargetSet", snippet)
        self.assertIn(
            "generatedX87ReplayBridgeFixedTemplateExecutor carrier checked",
            snippet,
        )
        self.assertIn(").kernelExecution", snippet)
        self.assertIn(").templateExecution", snippet)
        self.assertIn(
            "generatedX87ReplayBridgeHandlerInventoryCorrespondence", snippet
        )
        self.assertNotIn("FixedTemplateAuthority", snippet)
        self.assertNotIn("RuntimeGoal", snippet)
        self.assertNotIn("sourceInvariant", snippet)
        self.assertNotIn("runRelatedSteps", snippet)
        self.assertNotIn("FixedTemplateExecutorGoal", snippet)
        self.assertNotIn("(executor :", snippet)
        self.assertNotIn('"status"', snippet)


if __name__ == "__main__":
    unittest.main()
