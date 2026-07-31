from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_relational_interpreter_kernel_operation_projection_kernel import (
    _APPROVED_AXIOMS,
    _AXIOMS,
    _copy_module_closure,
)


@unittest.skipUnless(shutil.which("lean"), "Lean is required")
class OperationFootprintProjectionKernelTests(unittest.TestCase):
    def test_footprint_projection_checks_without_bad_axioms(self) -> None:
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
                "RelationalInterpreterKernelOperationFootprintProjection",
            )
            result = _run_lean_relational(
                root,
                bundle="RelationalInterpreterKernelOperationFootprintProjection",
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
            "symbolicWriteFootprint_disjoint_of_writes_nil",
            "symbolicWriteFootprint_disjoint_wordRange_singleton",
            "CheckedNativeOperationRunningEdge."
            "footprintDisjoint_of_writes_nil",
            "CheckedNativeOperationStoppedEdge."
            "footprintDisjoint_of_writes_nil",
            "CheckedNativeOperationRunningEdge."
            "footprintDisjoint_wordRange_singleton",
            "checkedNativeOperationRunningTraceFootprintsDisjointAt_"
            "cons_projected",
            "checkedNativeOperationBlockFootprintsDisjointAt_of_exact",
        ):
            self.assertIn(theorem, output)


if __name__ == "__main__":
    unittest.main()
