from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)


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
class StageARelationalInterpreterKernelStepOperationKernelTests(
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
                "RelationalInterpreterKernelStepOperation",
            )
            result = _run_lean_relational(
                root,
                bundle="RelationalInterpreterKernelStepOperation",
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
        self.assertIn(
            "InterpreterStepNativeProgramLookupCallAuthority.lookup",
            output,
        )
        self.assertIn(
            "InterpreterStepNativeActionLoopAuthority.compose",
            output,
        )
        for theorem in (
            "InterpreterStepNativeCheckedOperationCertificate.refinesDerivation",
            "InterpreterStepNativeCheckedOperationCertificate.refines",
            "InterpreterStepNativeOperationCertificate.toChecked",
        ):
            self.assertIn(theorem, output)

    def test_checked_certificate_is_request_local(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelStepOperation.lean"
        ).read_text(encoding="utf-8")

        checked = source.split(
            "structure InterpreterStepNativeCheckedOperationCertificate", 1
        )[1].split(
            "#print axioms concreteInterpreterStepRecordsExact", 1
        )[0]
        for required in (
            "InterpreterStepClosedCallTreeAuthority",
            "CheckedInterpreterStepDerivation",
            "InterpreterStepNativeFramedRequestLocalInvokeEvidence",
            "InterpreterStepNativeCheckedActionLoopAuthority",
            "certificate.closedTree.close",
            "certificate.refinesDerivation checked",
        ):
            self.assertIn(required, checked)
        self.assertNotIn(
            "InterpreterStepNativeInvokeCallAuthority program abi",
            checked,
        )
        self.assertNotIn(
            "KernelOperationRefinesUsing program abi\n"
            "      (NativeWorldSubroutineDispatches",
            checked,
        )


if __name__ == "__main__":
    unittest.main()
