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


_KERNEL = r'''import StageA.RelationalOriginalCombinedAwaitingExternalPreservation

namespace StageA.OriginalCombinedAwaitingExternalPreservationKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalCombinedAwaitingExternalPreservation
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalCombinedTargetStepIndex

theorem explicitResponsesConstructTheExternalInvariant
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    (responses : CheckedOriginalCombinedMachineProtocolResponses program context
      inventory) :
    OriginalCombinedAwaitingExternalPreservation context inventory :=
  responses.toAwaitingExternalPreservation

theorem unknownCallbacksCannotUseCheckedCallbackEvidence
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {entry : WorldExternalCallbackAction}
    (response : OriginalCombinedCallbackProtocolResponse program context inventory
      suspension callbacks contract entry)
    (unknown : Not (KnownCallbackRuntime program.context
      { suspension := suspension, entry := entry })) : False :=
  response.unknownCallbackFalse unknown

theorem protocolReturnChangesOnlyDisposition
    (contract : MachineImportCallContract) :
    (protocolReturnContract contract).id = contract.id /\
      (protocolReturnContract contract).imported = contract.imported /\
      (protocolReturnContract contract).memoryEffect = contract.memoryEffect /\
      (protocolReturnContract contract).memoryFootprints =
        contract.memoryFootprints /\
      (protocolReturnContract contract).worldEffect = contract.worldEffect /\
      (protocolReturnContract contract).disposition = .returns := by
  simp [protocolReturnContract]

theorem currentProtocolEventUsesResumedState
    (suspension : WorldExternalSuspension) :
    suspension.currentEvent.state = suspension.state /\
      suspension.currentEvent.world = suspension.world /\
      suspension.currentEvent.imported = suspension.imported /\
      suspension.currentEvent.arguments = suspension.arguments := by
  exact ⟨rfl, rfl, rfl, rfl⟩

theorem returnedResponsePreservesRuntimeMemory
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {result : WorldExternalResult}
    (response : OriginalCombinedReturnedProtocolResponse program context inventory
      suspension callbacks contract result)
    (holds : inventory.Holds (.awaitingExternal suspension callbacks)) :
    OriginalRuntimeMemoryPartition.ExecutionHolds program.context
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next :=
  (response.postFamilies holds).runtimeMemory

theorem callbackResponsePreservesRuntimeMemory
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {entry : WorldExternalCallbackAction}
    (response : OriginalCombinedCallbackProtocolResponse program context inventory
      suspension callbacks contract entry)
    (holds : inventory.Holds (.awaitingExternal suspension callbacks)) :
    OriginalRuntimeMemoryPartition.ExecutionHolds program.context
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next :=
  (response.postFamilies holds).runtimeMemory

theorem terminatedResponsePreservesRuntimeMemory
    {program : DecodedWorldProgram}
    {context : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program context}
    {suspension : WorldExternalSuspension}
    {callbacks : List WorldExternalCallbackRuntime}
    {contract : MachineImportCallContract}
    {world : RelationalWorld}
    (response : OriginalCombinedTerminatedProtocolResponse program context inventory
      suspension callbacks contract world) :
    OriginalRuntimeMemoryPartition.ExecutionHolds program.context
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next :=
  response.postFamilies.runtimeMemory

#print axioms explicitResponsesConstructTheExternalInvariant
#print axioms unknownCallbacksCannotUseCheckedCallbackEvidence
#print axioms protocolReturnChangesOnlyDisposition
#print axioms currentProtocolEventUsesResumedState
#print axioms returnedResponsePreservesRuntimeMemory
#print axioms callbackResponsePreservesRuntimeMemory
#print axioms terminatedResponsePreservesRuntimeMemory

end StageA.OriginalCombinedAwaitingExternalPreservationKernel
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalCombinedAwaitingExternalPreservationKernelTests(
    unittest.TestCase
):
    def test_combined_external_responses_are_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root
            / "RelationalOriginalCombinedAwaitingExternalPreservation.lean"
        ).read_text(encoding="utf-8")

        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bGnu\b",
            r"authorizing_lean_terms",
            r"status\s*==",
            r"inventory\.Holds\s*\(program\.pe32TransitionSystem",
        ):
            self.assertNotRegex(module_text, forbidden)

        for required in (
            "CheckedOriginalMachineProtocolBoundary",
            "OriginalProtocolCallbackMachineFrame",
            "OriginalCombinedReturnedProtocolResponse",
            "OriginalCombinedCallbackProtocolResponse",
            "OriginalCombinedTerminatedProtocolResponse",
            "machineCallResultConforms false",
            "OriginalStaticWordMachineCallFrame",
            "DormantOriginalCallFrame.Holds",
            "OriginalValueFlowWorldFrame",
            "registerTargetAtContinuation",
            "stackDynamicSourceAtContinuation",
            "runtimeMemory := by",
            "entryTargetReachable",
            "worldEffect : machineCallWorldEffectHolds false",
            "OriginalCombinedMachineProtocolResponse",
            "CheckedOriginalCombinedMachineProtocolResponses",
            "toAwaitingExternalPreservation",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalCombinedAwaitingExternalPreservation",
            )
            (stage_a / "OriginalCombinedAwaitingExternalPreservationKernel.lean").write_text(
                _KERNEL,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="OriginalCombinedAwaitingExternalPreservationKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 7, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
