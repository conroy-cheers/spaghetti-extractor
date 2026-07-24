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


class StageARelationalSymbolicSoundnessTests(unittest.TestCase):
    def test_bridge_has_no_unchecked_acceptance_construct(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalSymbolicSoundness.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        self.assertIn("executeInstruction_composes", source)
        self.assertIn("KernelInstruction.semanticStep", source)
        self.assertIn("ExactDecodeInventory", source)
        self.assertIn("runKernelBlockSemantic", source)
        self.assertIn("runKernelBlockConcrete_composes", source)
        self.assertIn("runKernelBlockConcrete", source)
        self.assertNotIn("instructionCompositionChecked", source)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_generic_symbolic_soundness_bridge_compiles_at_trust_zero(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(source_root, stage_a, "RelationalSymbolicSoundness")
            (stage_a / "RelationalSymbolicSoundnessFixture.lean").write_text(
                _FIXTURE, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="RelationalSymbolicSoundnessFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])


_FIXTURE = r"""import StageA.RelationalSymbolicSoundness

namespace StageA.Relational.SymbolicSoundnessFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.SymbolicSoundness

def pe : PE32 := {
  bytes := ByteTree.ofBytes [0x90, 0x90]
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 2
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{
    virtualSize := 2
    virtualAddress := 0
    rawSize := 2
    rawPointer := 0
    characteristics := 0x60000020
  }]
}

def first : KernelInstruction := { rva := 0, bytes := [0x90] }
def second : KernelInstruction := { rva := 1, bytes := [0x90] }

theorem exactInventory : ExactDecodeInventory pe [first, second] := by
  intro instruction member
  simp only [List.mem_cons, List.mem_nil_iff, or_false] at member
  rcases member with firstMember | secondMember
  · subst instruction
    exact ⟨{ instruction := .nop, size := 1, trailing := [0x90] }, by native_decide⟩
  · subst instruction
    exact ⟨{ instruction := .nop, size := 1, trailing := [] }, by native_decide⟩

example (undefinedSlot : Nat) (input : MachineState) :
    runKernelBlockConcrete pe [] undefinedSlot input [first, second] =
      runKernelBlockSemantic pe [] undefinedSlot input [first, second] :=
  runKernelBlockConcrete_composes pe [] [first, second] exactInventory
    undefinedSlot input

#print axioms executeInstruction_composes
#print axioms runKernelBlockConcrete_composes

end StageA.Relational.SymbolicSoundnessFixture
"""


if __name__ == "__main__":
    unittest.main()
