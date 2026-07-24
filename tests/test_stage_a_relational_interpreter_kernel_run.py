from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_LINE = re.compile(r"depends on axioms: \[([^\]]*)\]", re.MULTILINE)


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


class StageARelationalInterpreterKernelRunTests(unittest.TestCase):
    def test_certificate_is_inductively_composed_without_final_simulation(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelRun.lean"
        ).read_text(encoding="utf-8")

        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        for required in (
            "RunFunctionMachineTemplate.checked",
            "spanBytes pe function.span",
            "function.checked pe imports",
            "callbacks.checked program pe imports",
            "callbackSitesContainRva",
            "template.x87FrameOffsets.isEmpty",
            "structure RunFunctionStepPhase",
            "inductive RunFunctionContinuationKind",
            "structure RunFunctionLoopPhases",
            "theorem RunFunctionLoopPhases.execute",
            "induction derivation",
            "execution.trans continuationPhase.path tailResult.path",
            "structure RunFunctionEpiloguePhase",
            "KernelOperationRefinesUsing program abi dispatches .runFunction",
        ):
            self.assertIn(required, source)
        certificate = source.split(
            "structure RunFunctionMachineCertificate", 1
        )[1].split("theorem RunFunctionMachineCertificate.refines", 1)[0]
        self.assertNotRegex(certificate, r"\bsimulate\s*:")
        self.assertNotRegex(certificate, r"\brefines\s*:")
        self.assertNotRegex(certificate, r"KernelOperationRefinesUsing")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generic_run_core_compiles_and_has_only_approved_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernelRun"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernelRun"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])
        self.assertIn("RunFunctionLoopPhases.execute", result["stdout"])
        self.assertIn("RunFunctionMachineCertificate.refines", result["stdout"])
        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


if __name__ == "__main__":
    unittest.main()
