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
class StageARelationalInterpreterKernelInvokeClosedCallTreeTests(
    unittest.TestCase
):
    def test_checked_invoke_adapter_compiles_without_bad_axioms(self) -> None:
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
                "RelationalInterpreterKernelInvokeOperation",
            )
            result = _run_lean_relational(
                root,
                bundle="RelationalInterpreterKernelInvokeOperation",
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
        for theorem in (
            "runFunctionSubroutine_of_checked_derivation",
            "InvokeCallNativeCheckedOperationCertificate.refinesDerivation",
            "InvokeCallNativeCheckedOperationCertificate.refines",
        ):
            self.assertIn(theorem, output)

    def test_checked_invoke_uses_only_its_retained_run_trees(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelInvokeOperation.lean"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "import StageA.RelationalInterpreterKernelRunOperation",
            source,
        )
        closure = source.split(
            "structure InvokeCallClosedCallTreeAuthority", 1
        )[1].split(
            "theorem runFunctionSubroutine_of_checked_derivation", 1
        )[0]
        self.assertIn("CheckedInvokeCallDerivation", closure)
        self.assertIn("AbstractKernelTransition", closure)
        self.assertIn("InvokeCallClosedCallTreeAuthority.ofClosure", closure)
        self.assertNotIn("KernelOperationRefinesUsing", closure)

        run_adapter = source.split(
            "theorem runFunctionSubroutine_of_checked_derivation", 1
        )[1].split(
            "structure InvokeCallNativeCheckedRunFunctionRefinements", 1
        )[0]
        self.assertIn("CheckedRunFunctionDerivation", run_adapter)
        self.assertIn("certificate.semantics.execute", run_adapter)
        self.assertNotIn(
            "runFunctionSubroutine_of_operation_refinement",
            run_adapter,
        )
        self.assertNotIn("certificate.refines", run_adapter)

        checked = source.split(
            "structure InvokeCallNativeCheckedOperationCertificate", 1
        )[1].split("#print axioms", 1)[0]
        for required in (
            "InvokeCallClosedCallTreeAuthority",
            "InvokeCallNativeCheckedRunFunctionRefinements",
            "CheckedInvokeCallDerivation",
            "runFunctionSubroutine_of_checked_derivation",
            "| external event logical kindExact",
            "certificate.external.execute environment",
            "targetExact",
            "completion.memoryFrame",
        ):
            self.assertIn(required, checked)
        self.assertNotIn(
            "InvokeCallNativeRunFunctionRefinements program abi",
            checked,
        )
        self.assertNotIn(
            "runFunctionSubroutine_of_operation_refinement",
            checked,
        )
        self.assertNotIn("statusExact", checked)

        for preserved in (
            "structure InvokeCallNativeOperationCertificate",
            "InvokeCallNativeOperationCertificate.refines",
        ):
            self.assertIn(preserved, source)
        for forbidden in ("axiom ", "native_decide", "sorry", "unsafe ", "GNU"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
