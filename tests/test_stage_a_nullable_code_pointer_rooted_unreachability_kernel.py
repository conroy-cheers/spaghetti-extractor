from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_nullable_code_pointer_dispatch_kernel import (
    _copy_module_closure,
)


_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageANullableCodePointerRootedUnreachabilityKernelTests(
    unittest.TestCase
):
    def test_decoded_scanner_and_scc_induction_compile_without_escape_hatches(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalNullableCodePointerRootedUnreachability",
            )
            result = _run_lean_relational(
                root,
                bundle="RelationalNullableCodePointerRootedUnreachability",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 3, output)
        for report in reports:
            used = {
                item.strip()
                for item in report.split(",")
                if item.strip()
            }
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
