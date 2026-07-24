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


class StageARelationalInterpreterKernelStepNativeTests(unittest.TestCase):
    def test_bridge_accepts_only_checked_local_native_paths(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelStepNative.lean"
        ).read_text(encoding="utf-8")

        for required in (
            "InterpreterStepNativeTemplate.checked",
            "decodedInterpreterStepDirectCalls",
            "callbacks.checked program pe imports",
            "InterpreterStepNativeChunk",
            "runRelatedSteps candidate.transitionSystem",
            "cutpoint.instructionCount",
            "InterpreterStepNativeChunk.destinationChecked",
            "InterpreterStepNativeLocalSubroutine",
            "boundaryAllowed",
            "continuationAllowed",
            "InterpreterStepNativePath.sound",
            "InterpreterStepNativeLookupPhase",
            "InterpreterStepNativeActionPhase",
            "InterpreterStepNativeEpiloguePhase",
            "InterpreterStepNativeMachineCertificate.refines",
            "KernelOperationRefinesUsing program abi",
        ):
            self.assertIn(required, source)
        for forbidden in (
            r"\bsimulate\s*:",
            r"\bwholeOperationPath\b",
            r"\bwholeOperationFinalState\b",
        ):
            self.assertNotRegex(source, forbidden)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_bridge_compiles_with_only_approved_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernelStepNative"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernelStepNative"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])
        self.assertIn(
            "InterpreterStepNativeMachineCertificate.refines", result["stdout"]
        )
        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


if __name__ == "__main__":
    unittest.main()
