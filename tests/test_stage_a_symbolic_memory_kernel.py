from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.executor import _run_lean_relational


class StageASymbolicMemoryKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_symbolic_word_memory_canonicalization_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src"
            / "spaghetti_extractor"
            / "lean"
            / "StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            for module in ("X87", "Formal"):
                shutil.copyfile(source_root / f"{module}.lean", stage_a / f"{module}.lean")

            (stage_a / "SymbolicMemoryKernel.lean").write_text(
                """import StageA.Formal

namespace StageA.SymbolicMemoryKernel

open StageA.Formal

def base : Expr := .inputReg .esp
def unknownAddress : Expr := .inputReg .eax

example : (base.offset 12).offset (2 ^ 32 - 12) = base := by decide
example : (Expr.sub base (.constant 4)).offset 4 = base := by decide

def exactWrites : SymbolicBehavior := {
  initialSymbolic with
  writes := [
    (base, .constant 11),
    (base, .constant 22),
    (base.offset 8, .constant 33),
  ]
}

example : symbolicRead32 exactWrites base = .constant 22 := by decide

def disjointWrites : SymbolicBehavior := {
  initialSymbolic with
  writes := [
    (base.offset 8, .constant 11),
    (base.offset 16, .constant 22),
  ]
}

example : symbolicRead32 disjointWrites base = .read32 base := by decide

def unknownTail : SymbolicBehavior := {
  initialSymbolic with
  writes := [
    (base, .constant 11),
    (unknownAddress, .constant 22),
  ]
}

example : symbolicRead32 unknownTail base != .constant 11 := by decide
example : symbolicRead32 unknownTail base != .read32 base := by decide

def overwritten : SymbolicBehavior :=
  (initialSymbolic.write32 base (.constant 11)).write32 base (.constant 22)

example : overwritten.writes = [(base, .constant 22)] := by decide

def restoredWithDisjointWrite : SymbolicBehavior :=
  ((initialSymbolic.write32 base (.constant 11)).write32
      (base.offset 8) (.constant 33)).write32 base (.read32 base)

example : restoredWithDisjointWrite.writes = [(base.offset 8, .constant 33)] := by decide
example : symbolicRead32 restoredWithDisjointWrite base = .read32 base := by decide

def restoredWithUnknownOverlap : SymbolicBehavior :=
  ((initialSymbolic.write32 base (.constant 11)).write32
      unknownAddress (.constant 33)).write32 base (.read32 base)

example : restoredWithUnknownOverlap.writes = [
    (unknownAddress, .constant 33),
    (base, .read32 base),
  ] := by decide

end StageA.SymbolicMemoryKernel
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir,
                bundle="SymbolicMemoryKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
