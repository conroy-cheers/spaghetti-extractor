from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_relational_interpreter_kernel_step_program_lookup_call_closure_kernel import (
    _copy_module_closure,
)


_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)


@unittest.skipUnless(shutil.which("lean"), "Lean is required")
class StageARelationalInterpreterKernelProgramTableProjectionKernelTests(
    unittest.TestCase
):
    def test_loaded_program_table_projection_compiles_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            module = "RelationalInterpreterKernelProgramTableProjection"
            source = (source_root / f"{module}.lean").read_text(
                encoding="utf-8"
            )
            for forbidden in (
                "sorry",
                "native_decide",
                "submittedMemory",
                "submittedValue",
            ):
                self.assertNotIn(forbidden, source)
            for required in (
                "loadedCandidateByte?",
                "loadedCandidateWord?",
                "immutableRangeWordChecked",
                "immutableRangeWordsChecked",
                "transferDescriptorLoadedChecked",
                "transferDescriptorRangeChecked",
                "LoadedTransferDescriptorAt",
                "rawActionLoadedChecked",
                "rawActionRangeChecked",
                "LoadedRawActionAt",
                "rawActionArrayLoadedChecked",
                "rawActionArrayRangeChecked",
                "LoadedRawActionArrayAt",
                "transferActionsLoadedChecked",
                "transferActionsRangesChecked",
                "LoadedTransferActionsAt",
            ):
                self.assertIn(required, source)
            _copy_module_closure(source_root, stage_a, module)
            result = _run_lean_relational(
                root,
                bundle=module,
                command_timeout_seconds=300,
            )

        self.assertEqual(result["status"], "checked", result)
        output = str(result["stdout"]) + str(result["stderr"])
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        for match in _AXIOMS.findall(output):
            axioms = {
                item.strip() for item in match.split(",") if item.strip()
            }
            self.assertLessEqual(axioms, _APPROVED_AXIOMS)
        for theorem in (
            "LoadedCandidateImageMemory.read32_of_checked",
            "LoadedCandidateImageMemory.read32_of_range_checked",
            "LoadedTransferDescriptorAt.of_checked",
            "LoadedTransferDescriptorAt.of_range_checked",
            "LoadedRawActionAt.of_checked",
            "LoadedRawActionAt.of_range_checked",
            "LoadedRawActionArrayAt.of_checked",
            "LoadedRawActionArrayAt.of_range_checked",
            "LoadedTransferActionsAt.of_checked",
            "LoadedTransferActionsAt.of_ranges_checked",
        ):
            self.assertIn(theorem, output)


if __name__ == "__main__":
    unittest.main()
