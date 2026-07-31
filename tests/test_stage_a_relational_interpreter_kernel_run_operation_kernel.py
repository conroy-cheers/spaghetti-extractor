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


@unittest.skipUnless(shutil.which("lean"), "Lean is required")
class StageARelationalInterpreterKernelRunOperationKernelTests(
    unittest.TestCase
):
    def _compile(self, module: str, fixture: str | None = None) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
            )
            _copy_module_closure(source_root, stage_a, module)
            bundle = module
            if fixture is not None:
                bundle = "RunFunctionAcceptanceFixture"
                (stage_a / f"{bundle}.lean").write_text(
                    fixture, encoding="ascii"
                )
            return _run_lean_relational(root, bundle=bundle)

    def test_composition_certificate_compiles_without_unapproved_axioms(
        self,
    ) -> None:
        result = self._compile("RelationalInterpreterKernelRunOperation")

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])
        self.assertIn(
            "RunFunctionNativeCheckedOperationCertificate.refines",
            result["stdout"],
        )
        self.assertIn(
            "runFunctionNativeStepOperationOfFrameParametric",
            result["stdout"],
        )
        self.assertIn(
            "kernelOperationRefinesUsing_runFunction_mono",
            result["stdout"],
        )

    def test_exact_run_refinement_embeds_in_acceptance_dispatch(self) -> None:
        fixture = """import StageA.RelationalInterpreterKernelOperationInstantiation

namespace StageA.RunFunctionAcceptanceFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelOperationInstantiation
open StageA.Relational.InterpreterKernelRunOperation
open StageA.Relational.InterpreterNativeWorld

theorem exactRunRefinesAcceptanceDispatch
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {continuationRva : Nat} {returnAddress : Word}
    (refines : KernelOperationRefinesUsing program abi
      (NativeWorldSubroutineDispatches candidate world continuationRva
        returnAddress) .runFunction) :
    KernelOperationRefinesUsing program abi
      (checkedNativeWorldKernelOperationDispatchFamily candidate world
        .runFunction) .runFunction := by
  apply kernelOperationRefinesUsing_runFunction_mono refines
  intro entryRva before after events dispatched
  exact Exists.intro continuationRva
    (Exists.intro returnAddress dispatched)

#print axioms exactRunRefinesAcceptanceDispatch

end StageA.RunFunctionAcceptanceFixture
"""
        result = self._compile(
            "RelationalInterpreterKernelOperationInstantiation", fixture
        )

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
        self.assertIn("exactRunRefinesAcceptanceDispatch", output)

    def test_checked_run_certificate_at_canonical_abi_frame_refines_acceptance(
        self,
    ) -> None:
        fixture = """import StageA.RelationalInterpreterKernelOperationInstantiation

namespace StageA.RunFunctionCanonicalAcceptanceFixture

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelOperationInstantiation
open StageA.Relational.InterpreterKernelRunOperation
open StageA.Relational.InterpreterNativeWorld

def canonicalContinuationRva (pe : PE32) : Nat :=
  pe.entrypointRva

def canonicalReturnAddress
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva records) :
    Word :=
  abi.parameters.returnAddress pe

theorem checkedRunCertificateRefinesAcceptance
    {program : CompiledKernelProgram} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {tableRva countRva : Nat} {records : List ProgramRecord}
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva records)
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    (certificate : RunFunctionNativeCheckedOperationCertificate program
      abi.relation records candidate world (canonicalContinuationRva pe)
      (canonicalReturnAddress abi)) :
    KernelOperationRefinesUsing program abi.relation
      (checkedNativeWorldKernelOperationDispatchFamily candidate world
        .runFunction) .runFunction := by
  apply kernelOperationRefinesUsing_runFunction_mono certificate.refines
  intro entryRva before after events dispatched
  exact Exists.intro (canonicalContinuationRva pe)
    (Exists.intro (canonicalReturnAddress abi) dispatched)

#print axioms checkedRunCertificateRefinesAcceptance

end StageA.RunFunctionCanonicalAcceptanceFixture
"""
        result = self._compile(
            "RelationalInterpreterKernelOperationInstantiation", fixture
        )

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
        self.assertIn("checkedRunCertificateRefinesAcceptance", output)


if __name__ == "__main__":
    unittest.main()
