from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


class StageAFiniteIndexKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_balanced_finite_index_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src"
            / "spaghetti_extractor"
            / "lean"
            / "StageA"
        )
        module_source = source_root / "RelationalFiniteIndex.lean"
        source = module_source.read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            shutil.copyfile(module_source, stage_a / module_source.name)

            (stage_a / "RelationalFiniteIndexKernel.lean").write_text(
                """import StageA.RelationalFiniteIndex

namespace StageA.RelationalFiniteIndexKernel

open StageA.Relational

def leaf0 : FiniteIndex Nat := FiniteIndex.ofListLeaf [10, 11]
def leaf1 : FiniteIndex Nat := FiniteIndex.ofListLeaf [12, 13]
def leaf2 : FiniteIndex Nat := FiniteIndex.ofListLeaf [14, 15]
def leaf3 : FiniteIndex Nat := FiniteIndex.ofListLeaf [16]

def fixture : FiniteIndex Nat :=
  (leaf0.append leaf1).append (leaf2.append leaf3)

def malformedBoundary : FiniteIndex Nat :=
  .branch 4 1 (FiniteIndex.ofListLeaf [10, 11])
    (FiniteIndex.ofListLeaf [12, 13])

example : fixture.size = 7 := by decide
example : fixture.toList = [10, 11, 12, 13, 14, 15, 16] := by decide
example : fixture.get? 0 = some 10 := by decide
example : fixture.get? 3 = some 13 := by decide
example : fixture.get? 4 = some 14 := by decide
example : fixture.get? 6 = some 16 := by decide
example : fixture.get? 7 = none := by decide
example : fixture.structurallyValid 2 = true := by decide
example : fixture[4]'(by decide) = 14 := by decide
example : (([20, 21] : List Nat) : FiniteIndex Nat).toList = [20, 21] := by decide
example : ((#[30, 31] : Array Nat) : FiniteIndex Nat).get? 1 = some 31 := by decide
example : 14 ∈ fixture := by decide
example : 99 ∉ fixture := by decide
example : malformedBoundary.sizesSound = false := by decide
example : malformedBoundary.structurallyValid 2 = false := by decide

example (index : Nat) (value : Nat) (found : fixture.get? index = some value) :
    index < fixture.size :=
  FiniteIndex.get?_eq_some_implies_lt_size fixture index value found

#print axioms FiniteIndex.get?_eq_some_implies_lt_size
#print axioms FiniteIndex.get?_eq_some_implies_mem_toList
#print axioms FiniteIndex.size_append
#print axioms FiniteIndex.toList_append
#print axioms FiniteIndex.sizesSound_append
#print axioms FiniteIndex.mem_iff_mem_toList

end StageA.RelationalFiniteIndexKernel
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir,
                bundle="RelationalFiniteIndexKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
