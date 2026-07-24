from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


class StageARelationalInterpreterNativeWorldTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_exact_native_world_transition_system_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        source = (source_root / "RelationalInterpreterNativeWorld.lean").read_text(
            encoding="utf-8"
        )
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        self.assertIn("stepKernelPE32Instruction", source)
        self.assertIn("exactNativeIndirectTargetRva?", source)
        self.assertIn("NativeIndirectTargetInventory", source)
        self.assertIn("missingNativeIndirectTargetSet", source)
        self.assertIn("callableExternal observation", source)
        self.assertIn("unmappedIndirectControl", source)
        self.assertIn("unclassifiedNativeFault", source)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in source_root.glob("*.lean"):
                shutil.copyfile(module, stage_a / module.name)
            (stage_a / "RelationalInterpreterNativeWorldKernel.lean").write_text(
                """import StageA.RelationalInterpreterNativeWorld

namespace StageA.Relational.InterpreterNativeWorldKernel

open StageA.Relational
open StageA.Relational.InterpreterNativeWorld

#check ExactNativeWorldProgram.transitionSystem
#check NativeWorldDispatches
#check exactNativeWorldStepIsNonempty
#print axioms exactNativeWorldStepIsNonempty
#print axioms NonemptyRelatedPath.trans

end StageA.Relational.InterpreterNativeWorldKernel
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterNativeWorldKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
