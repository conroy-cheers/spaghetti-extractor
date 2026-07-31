from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)

_GENERATED_INTERFACE_SMOKE = """\
import StageA.RelationalInterpreterKernelInvokeOperation

namespace StageA.GeneratedRelational.InterpreterKernelInvokeOperationSmoke

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelInvokeOperation
open StageA.Relational.InterpreterNativeWorld

structure GeneratedInvokeCallRunFunctionRefinements
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate) where
  internal : KernelOperationRefinesUsing program abi
    (NativeWorldSubroutineDispatches candidate world
      static.internalContinuationRva static.internalReturnAddress) .runFunction
  indirect : KernelOperationRefinesUsing program abi
    (NativeWorldSubroutineDispatches candidate world
      static.indirectContinuationRva static.indirectReturnAddress) .runFunction

def GeneratedInvokeCallRunFunctionRefinements.toAuthority
    (refinements : GeneratedInvokeCallRunFunctionRefinements
      program abi candidate world static) :
    InvokeCallNativeRunFunctionRefinements program abi candidate world static := {
  internal := refinements.internal
  indirect := refinements.indirect
}

theorem generatedInvokeCallOperationRefinesUsing
    (static : InvokeCallNativeStaticBinding program candidate)
    (abiEntry : InvokeCallNativeABIEntryAuthority abi semanticRecords)
    (external : InvokeCallNativeExternalBranchAuthority program abi
      semanticRecords candidate world static)
    (internal : InvokeCallNativeInternalBranchAuthority program abi
      semanticRecords candidate world static)
    (indirect : InvokeCallNativeIndirectBranchAuthority program abi
      semanticRecords candidate world static)
    (runFunction : GeneratedInvokeCallRunFunctionRefinements
      program abi candidate world static) :
    KernelOperationRefinesUsing program abi
      (NativeWorldKernelDispatches candidate world) .invokeCall := by
  exact (InvokeCallNativeOperationCertificate.mk static abiEntry external
    internal indirect runFunction.toAuthority).refines

#print axioms generatedInvokeCallOperationRefinesUsing
#print axioms InvokeCallNativeRunFunctionRefinements.internalForAuthority
#print axioms InvokeCallNativeRunFunctionRefinements.indirectForAuthority

end StageA.GeneratedRelational.InterpreterKernelInvokeOperationSmoke
"""


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
class StageARelationalInterpreterKernelInvokeOperationKernelTests(
    unittest.TestCase
):
    def test_composition_certificate_compiles_without_unapproved_axioms(
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
                "RelationalInterpreterKernelInvokeOperation",
            )
            (
                stage_a / "GeneratedInterpreterKernelInvokeOperationSmoke.lean"
            ).write_text(_GENERATED_INTERFACE_SMOKE, encoding="ascii")
            result = _run_lean_relational(
                root,
                bundle="GeneratedInterpreterKernelInvokeOperationSmoke",
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])
        self.assertIn(
            "InvokeCallNativeRunFunctionRefinements.internalForAuthority",
            result["stdout"],
        )
        self.assertIn(
            "InvokeCallNativeRunFunctionRefinements.indirectForAuthority",
            result["stdout"],
        )
        self.assertIn(
            "generatedInvokeCallOperationRefinesUsing",
            result["stdout"],
        )
        approved_axioms = {"propext", "Classical.choice", "Quot.sound"}
        for axioms in re.findall(
            r"depends on axioms: \[([^\]]*)\]", result["stdout"]
        ):
            observed = {
                name.strip() for name in axioms.replace("\n", "").split(",")
            }
            self.assertLessEqual(observed, approved_axioms, result["stdout"])


if __name__ == "__main__":
    unittest.main()
