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


class StageARelationalInterpreterKernelInvokeTests(unittest.TestCase):
    def test_certificate_is_branch_composed_without_final_refinement_field(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelInvoke.lean"
        ).read_text(encoding="utf-8")

        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        for required in (
            "reviewedInvokeCallBytes",
            "reviewedInvokeCallBlocks",
            "normalizeInvokeCallBytes",
            "decodedDirectCallTargets",
            "callbacks.checked program pe imports",
            "callbackSitesContainRva",
            "structure InvokeCallBranchExecutions",
            "external : forall",
            "internal : forall",
            "indirect : forall",
            "AbstractRunFunction",
            "KernelOperationRefinesUsing program abi dispatches .invokeCall",
            "structure ConcreteInvokeCallMachineCertificate",
            "exact related.payload.1",
            "KernelOperationRefinesUsing abi.program abi.relation dispatches .invokeCall",
        ):
            self.assertIn(required, source)
        certificate = source.split(
            "structure InvokeCallMachineCertificate", 1
        )[1].split("theorem InvokeCallMachineCertificate.refines", 1)[0]
        self.assertNotRegex(certificate, r"\bsimulate\s*:")
        self.assertNotRegex(certificate, r"\brefinement\s*:")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generic_invoke_core_compiles_and_has_only_approved_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernelInvoke"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernelInvoke"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])
        self.assertIn("InvokeCallMachineCertificate.refines", result["stdout"])
        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


if __name__ == "__main__":
    unittest.main()
