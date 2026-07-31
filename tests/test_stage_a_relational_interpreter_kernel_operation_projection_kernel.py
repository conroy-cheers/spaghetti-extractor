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
class OperationProjectionKernelTests(unittest.TestCase):
    def test_projection_kernel_checks_without_bad_axioms(self) -> None:
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
                "RelationalInterpreterKernelOperationProjection",
            )
            result = _run_lean_relational(
                root,
                bundle="RelationalInterpreterKernelOperationProjection",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        for match in _AXIOMS.findall(output):
            axioms = {
                item.strip() for item in match.split(",") if item.strip()
            }
            self.assertLessEqual(axioms, _APPROVED_AXIOMS)
        for theorem in (
            "SymbolicBehavior.eval_register",
            "SymbolicBehavior.eval_memory",
            "CompactBehaviorProjection",
            "SymbolicBehavior.compactProjection",
            "applyWrites_eq_applyConcreteWrites",
            "symbolicWritesAvoidWord_of_checked",
            "Memory.read32_applyWrites_of_checked",
            "StackWordDirectionProjection",
            "FrameWordDirectionProjection",
            "SymbolicBehavior.eval_eflags_extract_df",
            "symbolicBehaviorNextMachineState_register",
            "symbolicBehaviorNextMachineState_memory",
            "symbolicBehaviorNextMachineState_eflags_extract_df",
            "CheckedNativeOperationRunningEdge.after_register",
            "CheckedNativeOperationRunningEdge.after_read32_of_checked",
            "CheckedNativeOperationRunningEdge."
            "after_frameWordDirectionProjection",
            "CheckedNativeOperationStoppedEdge.after_read32_of_checked",
            "CheckedNativeOperationStoppedEdge."
            "after_frameWordDirectionProjection",
            "CheckedNativeOperationStoppedEdge.after_eflags_extract_df",
        ):
            self.assertIn(theorem, output)


if __name__ == "__main__":
    unittest.main()
