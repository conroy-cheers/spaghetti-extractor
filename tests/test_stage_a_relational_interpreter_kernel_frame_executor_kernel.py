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


@unittest.skipUnless(shutil.which("lean"), "Lean is required")
class StageARelationalInterpreterKernelFrameExecutorKernelTests(
    unittest.TestCase
):
    def test_executor_derives_frame_path_refinement_without_sorry(self) -> None:
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
                "RelationalInterpreterKernelFrameExecutor",
            )
            result = _run_lean_relational(
                root,
                bundle="RelationalInterpreterKernelFrameExecutor",
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])
        approved_axioms = {"propext", "Classical.choice", "Quot.sound"}
        for axioms in re.findall(
            r"depends on axioms: \[([^\]]*)\]", result["stdout"]
        ):
            observed = {
                name.strip() for name in axioms.replace("\n", "").split(",")
            }
            self.assertLessEqual(observed, approved_axioms, result["stdout"])
        for theorem in (
            "NativeWorldFrameCallableTailCompatibleAt.ofDisabled",
            "FrameFootprintDisjoint.empty",
            "ImportedFrameEnvironmentContract.returnedFrameAndWorld",
            "CallableFrameEnvironmentContract.resultFrameAndWorld",
            "nativeWorldFrameStepRefinesAt_of_running",
            "NativeWorldFrameExecutorPathContract.prefixesRunning",
            "NativeWorldFrameExecutorPathContract.returnCompatible",
            "NativeWorldFrameExecutorPathContract.toPathRefinement",
            "KernelOperationFrameExecutorCertificate.toFrameParametric",
        ):
            self.assertIn(theorem, result["stdout"])


if __name__ == "__main__":
    unittest.main()
