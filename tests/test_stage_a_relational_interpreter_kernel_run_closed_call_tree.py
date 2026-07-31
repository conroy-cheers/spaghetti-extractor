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
class StageARelationalInterpreterKernelRunClosedCallTreeTests(
    unittest.TestCase
):
    def test_checked_run_adapter_compiles_without_bad_axioms(self) -> None:
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
                "RelationalInterpreterKernelRunOperation",
            )
            result = _run_lean_relational(
                root,
                bundle="RelationalInterpreterKernelRunOperation",
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
            "RunFunctionNativeStepPrelude.executeChecked",
            "RunFunctionNativeCheckedLocalSemantics.execute",
            "RunFunctionNativeCheckedOperationCertificate.refines",
        ):
            self.assertIn(theorem, output)

    def test_run_tree_drives_only_its_retained_step_requests(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelRunOperation.lean"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "import StageA.RelationalInterpreterKernelClosedCallTree",
            source,
        )
        checked_semantics = source.split(
            "structure RunFunctionNativeCheckedLocalSemantics", 1
        )[1].split(
            "theorem RunFunctionNativeCheckedLocalSemantics.execute", 1
        )[0]
        for required in (
            "CheckedInterpreterStepDerivation",
            "RunFunctionNativeCheckedStepEvidence",
            "RunFunctionNativeStepPrelude",
            "RunFunctionNativeTerminalPhase",
            "RunFunctionNativeContinuationPhase",
        ):
            self.assertIn(required, checked_semantics)
        self.assertNotIn(
            "RunFunctionNativeStepOperation program abi candidate",
            checked_semantics,
        )
        self.assertNotIn("KernelOperationRefinesUsing", checked_semantics)

        execution = source.split(
            "theorem RunFunctionNativeCheckedLocalSemantics.execute", 1
        )[1].split(
            "/-! ## Producer-indexed checked Run execution -/", 1
        )[0]
        self.assertIn("match derivation with", execution)
        self.assertEqual(execution.count("executeChecked"), 3)
        self.assertIn(
            "RunFunctionNativeCheckedLocalSemantics.execute stepEntryExact",
            execution,
        )

        indexed_execution = source.split(
            "theorem RunFunctionNativeCheckedResultIndexedLocalSemantics.execute",
            1,
        )[1].split(
            "structure RunFunctionClosedCallTreeAuthority", 1
        )[0]
        for required in (
            "RunFunctionNativeCheckedEncodedTerminal",
            "RunFunctionNativeResultIndexedLoopResult",
            "resultEncoding rootSourceRva",
            "tailResult.encoding",
        ):
            self.assertIn(required, source)
        self.assertEqual(indexed_execution.count("executeChecked"), 3)
        self.assertIn("match derivation with", indexed_execution)

        certificate = source.split(
            "structure RunFunctionNativeCheckedOperationCertificate", 1
        )[1].split(
            "theorem RunFunctionNativeCheckedOperationCertificate.refines", 1
        )[0]
        self.assertIn("RunFunctionClosedCallTreeAuthority.ofClosure", source)
        for required in (
            "RunFunctionClosedCallTreeAuthority",
            "RunFunctionNativeCheckedLocalSemantics",
            "RunFunctionNativeCheckedEntryAuthority",
            "RunFunctionNativeCheckedCDeclEpilogueAuthority",
        ):
            self.assertIn(required, certificate)
        self.assertNotIn("stepFrameParametric", certificate)

        theorem = source.split(
            "theorem RunFunctionNativeCheckedOperationCertificate.refines", 1
        )[1].split("#print axioms", 1)[0]
        self.assertIn("KernelOperationRefinesUsing", theorem)
        self.assertIn("certificate.execute", theorem)
        self.assertIn("cluster.subroutineResult", theorem)
        self.assertNotIn("statusExact", theorem)
        self.assertNotIn("stepFrameParametric", theorem)

        for preserved in (
            "structure RunFunctionNativeOperationCertificate",
            "RunFunctionNativeOperationCertificate.toMachineCertificate",
            "RunFunctionNativeOperationCertificate.refines",
        ):
            self.assertIn(preserved, source)
        for forbidden in ("axiom ", "native_decide", "sorry", "unsafe ", "GNU"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
