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


class StageARelationalInterpreterKernelCallbackTests(unittest.TestCase):
    def test_kernel_has_no_unchecked_acceptance_constructs(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        source = (source_root / "RelationalInterpreterKernelCallback.lean").read_text(
            encoding="utf-8"
        )
        kernel_source = (source_root / "RelationalInterpreterKernel.lean").read_text(
            encoding="utf-8"
        )
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
            self.assertIsNone(re.search(rf"\b{marker}\b", kernel_source), marker)
        self.assertNotRegex(
            source,
            r"\b(?:def|theorem|structure)\s+WholeProgramCertificate\b",
        )
        self.assertIn("KernelIndirectCallbackSite.decodedExact", source)
        self.assertIn("KernelCallbackInventory.coversProgram", source)
        self.assertIn("match instruction.decode? pe with", source)
        self.assertIn("targetMembership", source)
        self.assertIn("CDeclEntryHolds", source)
        self.assertIn("CDeclReturnHolds", source)
        self.assertIn("NestedFrameRelationPreserved", source)
        self.assertIn("RelocationBackedCallbackTargetInventory.checked", source)
        self.assertIn("parseRelocations pe", source)
        self.assertIn("callbackRelocationCount relocations cell.cellRva == 1", source)
        self.assertIn("NestedMixedFrameRelationPreserved", source)
        self.assertIn("RelationalMixedRuntimeStackHolds", source)
        self.assertIn("ExactCallbackTargetExecution", source)
        self.assertIn("CheckedCallbackIndirectStep", source)
        self.assertIn("CheckedExternalRetTrampolineStep", source)
        self.assertIn("CallbackAwareNativeSteps", source)
        self.assertIn("NativeDispatches.toCallbackAware", source)
        self.assertNotIn("CallbackAwareDispatchCompatible", source)
        self.assertIn("KernelOperationCallbackCertificate.refines", source)
        self.assertIn("KernelOperationCallbackRefines", source)
        self.assertIn("KernelOperationRefinesUsing", source)
        self.assertIn("KernelOperationRefinesUsing", kernel_source)
        self.assertIn("NativeDispatches pe imports nativeEnvironment", kernel_source)
        self.assertIn("unsupportedIndirect", kernel_source)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for callback checks")
    def test_generic_callback_primitives_compile(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernelCallback"
            )
            (stage_a / "RelationalInterpreterKernelCallbackFixture.lean").write_text(
                _FIXTURE, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernelCallbackFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'axiom'", result["stdout"])


_FIXTURE = r"""import StageA.RelationalInterpreterKernelCallback

namespace StageA.Relational.InterpreterKernelCallbackFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback

def fixtureABI : CDeclMachineABI := {
  argumentCount := 3
  argumentOffsets := [0, 4, 8]
  callerStackDelta := 0
  preservedRegisters := [.ebx, .esi, .edi, .ebp]
  returnKind := .wordInEax
}

example : fixtureABI.checked = true := by native_decide

example (pe : PE32) (imports : List PEImport) :
    ({ entries := [] } : CallbackTargetSet).checked pe imports = false := by
  rfl

example (pe : PE32) (targets : CallbackTargetSet) :
    ({ cells := [] } : RelocationBackedCallbackTargetInventory).checked
      pe targets = false := by
  rfl

example {context : StaticProofContext} {world : RelationalWorld}
    {inventory : KernelCallbackInventory} {program : CompiledKernelProgram}
    {pe : PE32} {imports : List PEImport} {environment : NativeEnvironment}
    {abi : KernelABIRelation}
    {trampolines : KernelExternalRetTrampolineInventory}
    {cells : KernelIndirectCallbackSite ->
      RelocationBackedCallbackTargetInventory}
    {contracts : KernelIndirectCallbackSite -> KernelCallbackTargetContract}
    {trampolineContracts : KernelExternalRetTrampolineSite ->
      KernelExternalRetTrampolineContract}
    {sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop}
    {runs : KernelIndirectCallbackSite ->
      KernelCallbackExecutionTrace -> Prop}
    {operation : KernelOperation}
    (certificate : KernelOperationCallbackCertificate context world inventory
      program pe imports environment abi trampolines cells contracts
      trampolineContracts sourceInvariant runs operation) :
    KernelOperationCallbackRefines context world inventory trampolines program
      pe imports environment abi cells contracts trampolineContracts
      sourceInvariant runs operation :=
  certificate.refines

example {context : StaticProofContext} {world : RelationalWorld}
    {inventory : KernelCallbackInventory} {program : CompiledKernelProgram}
    {pe : PE32} {imports : List PEImport} {environment : NativeEnvironment}
    {abi : KernelABIRelation}
    {trampolines : KernelExternalRetTrampolineInventory}
    {cells : KernelIndirectCallbackSite ->
      RelocationBackedCallbackTargetInventory}
    {contracts : KernelIndirectCallbackSite -> KernelCallbackTargetContract}
    {trampolineContracts : KernelExternalRetTrampolineSite ->
      KernelExternalRetTrampolineContract}
    {sourceInvariant : KernelIndirectCallbackSite -> MachineState -> Prop}
    {runs : KernelIndirectCallbackSite ->
      KernelCallbackExecutionTrace -> Prop}
    {operation : KernelOperation} :
    KernelOperationCallbackRefines context world inventory trampolines program
      pe imports environment abi cells contracts trampolineContracts
      sourceInvariant runs operation =
    KernelOperationRefinesUsing program abi
      (CallbackAwareNativeDispatches context world inventory trampolines program
        pe imports environment cells contracts trampolineContracts
        sourceInvariant runs) operation := by
  rfl

example (program : CompiledKernelProgram) (pe : PE32)
    (imports : List PEImport) (environment : NativeEnvironment)
    (abi : KernelABIRelation) (operation : KernelOperation) :
    KernelOperationRefines program pe imports environment abi operation =
      KernelOperationRefinesUsing program abi
        (NativeDispatches pe imports environment) operation := by
  rfl

#print axioms KernelIndirectCallbackExecutionRefinement.sound
#print axioms CheckedCallbackIndirectStep.refinesTarget
#print axioms NativeSteps.toCallbackAware
#print axioms NativeDispatches.toCallbackAware
#print axioms stepNativeExecution_eq_unsupportedIndirect_of_exact_indirect
#print axioms KernelOperationRefines.toCallbackAware
#print axioms KernelOperationCallbackCertificate.refines

end StageA.Relational.InterpreterKernelCallbackFixture
"""


if __name__ == "__main__":
    unittest.main()
