from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.executor import _run_lean_relational


class StageAISAConformanceKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_masked_addition_observation_is_checked_by_formal_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src"
                / "spaghetti_extractor"
                / "lean"
                / "StageA"
            )
            for module in ("Formal", "ISAConformance"):
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )

            (stage_a / "ISAConformanceKernel.lean").write_text(
                """import StageA.ISAConformance

namespace StageA.ISAConformanceKernelTests

open StageA.Formal

def addCarryCase : ISAConformanceInput := {
  bytes := [0x01, 0xd8]
  pc := 0x1000
  registers := {
    eax := 0xffffffff
    ebx := 1
    ecx := 2
    edx := 3
    esi := 4
    edi := 5
    ebp := 6
    esp := 0x70001000
  }
  eflags := 2
}

def addCarryExpected : ISAConformanceExpectation := {
  registers := {
    eax := some { value := 0, mask := 0xffffffff }
    ebx := some { value := 1, mask := 0xffffffff }
    ecx := none
    edx := none
    esi := none
    edi := none
    ebp := none
    esp := none
  }
  eflags := some { value := 0x45, mask := 0x8c5 }
  control := some (.next 0x1002)
  fault := some .none
}

example : addCarryCase.checked = true := by decide
example : addCarryExpected.checked = true := by decide
example : addCarryCase.matches addCarryExpected = true := by decide
example : (match addCarryCase.run with
    | .observed observation => observation.authorizesProof
    | _ => true) = false := by decide

end StageA.ISAConformanceKernelTests
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir,
                bundle="ISAConformanceKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
