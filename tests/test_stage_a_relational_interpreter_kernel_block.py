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


class StageARelationalInterpreterKernelBlockTests(unittest.TestCase):
    def test_checker_has_no_unchecked_acceptance_construct(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelBlock.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        self.assertIn("∀ input", source)
        self.assertIn("runKernelBlockConcrete", source)
        self.assertIn("block.SymbolicExecutionSound", source)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_exact_single_instruction_certificate_compiles(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernelBlock"
            )
            (stage_a / "RelationalInterpreterKernelBlockFixture.lean").write_text(
                _FIXTURE, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernelBlockFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


_FIXTURE = r"""import StageA.RelationalInterpreterKernelBlock

namespace StageA.Relational.InterpreterKernelBlockFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelBlock

def pe : PE32 := {
  bytes := ByteTree.ofBytes [0x90]
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 1
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{
    virtualSize := 1
    virtualAddress := 0
    rawSize := 1
    rawPointer := 0
    characteristics := 0x60000020
  }]
}

def nopBlock : KernelBlock := {
  entryRva := 0
  instructions := [{ rva := 0, bytes := [0x90] }]
  successors := [1]
}

def nopReflection : ReflectedKernelBlock := {
  block := nopBlock
  instructions := [{
    submitted := { rva := 0, bytes := [0x90] }
    decoded := { instruction := .nop, size := 1, trailing := [] }
  }]
  behavior := initialSymbolic
}

def nopCertificate : ReflectiveBlockCertificate pe [] nopBlock := {
  reflection := nopReflection
  reflected := by native_decide
  blockExact := rfl
  symbolicExact := by native_decide
  agrees := by
    intro input
    have fetched : executableInstructionWindow pe 0 = some [0x90] := by
      native_decide
    have decoded : decodeInstructionExact [0x90] = some {
        instruction := .nop, size := 1, trailing := [] } := by
      native_decide
    simp [KernelBlock.symbolicConcreteAgree, runKernelBlockConcrete, nopBlock,
      nopReflection, stepPE32Instruction, fetched, decoded, executeInstruction,
      SymbolicBehavior.eval, initialSymbolic]
}

example : nopBlock.SymbolicExecutionSound pe [] := nopCertificate.sound

def movPe : PE32 := {
  pe with
  bytes := ByteTree.ofBytes [0xb8, 7, 0, 0, 0]
  sizeOfImage := 5
  sections := [{
    virtualSize := 5
    virtualAddress := 0
    rawSize := 5
    rawPointer := 0
    characteristics := 0x60000020
  }]
}

def movBlock : KernelBlock := {
  entryRva := 0
  instructions := [{ rva := 0, bytes := [0xb8, 7, 0, 0, 0] }]
  successors := [5]
}

def movBehavior : SymbolicBehavior := {
  initialSymbolic with
  registers := initialSymbolic.registers.set .eax (.constant 7)
}

def movReflection : ReflectedKernelBlock := {
  block := movBlock
  instructions := [{
    submitted := { rva := 0, bytes := [0xb8, 7, 0, 0, 0] }
    decoded := {
      instruction := .movRegImm .eax 7
      size := 5
      trailing := []
    }
  }]
  behavior := movBehavior
}

def movCertificate : ReflectiveBlockCertificate movPe [] movBlock := {
  reflection := movReflection
  reflected := by native_decide
  blockExact := rfl
  symbolicExact := by native_decide
  agrees := by
    intro input
    have fetched : executableInstructionWindow movPe 0 =
        some [0xb8, 7, 0, 0, 0] := by native_decide
    have decoded : decodeInstructionExact [0xb8, 7, 0, 0, 0] = some {
        instruction := .movRegImm .eax 7, size := 5, trailing := [] } := by
      native_decide
    simp [KernelBlock.symbolicConcreteAgree, runKernelBlockConcrete, movBlock,
      movReflection, movBehavior, stepPE32Instruction, fetched, decoded,
      executeInstruction, SymbolicBehavior.eval, initialSymbolic]
}

example : movBlock.SymbolicExecutionSound movPe [] := movCertificate.sound

def twoNopPe : PE32 := {
  pe with
  bytes := ByteTree.ofBytes [0x90, 0x90]
  sizeOfImage := 2
  sections := [{
    virtualSize := 2
    virtualAddress := 0
    rawSize := 2
    rawPointer := 0
    characteristics := 0x60000020
  }]
}

def twoNopBlock : KernelBlock := {
  entryRva := 0
  instructions := [
    { rva := 0, bytes := [0x90] },
    { rva := 1, bytes := [0x90] }
  ]
  successors := [2]
}

def twoNopReflection : ReflectedKernelBlock := {
  block := twoNopBlock
  instructions := [
    {
      submitted := { rva := 0, bytes := [0x90] }
      decoded := { instruction := .nop, size := 1, trailing := [0x90] }
    },
    {
      submitted := { rva := 1, bytes := [0x90] }
      decoded := { instruction := .nop, size := 1, trailing := [] }
    }
  ]
  behavior := initialSymbolic
}

example : reflectKernelBlock? twoNopPe [] twoNopBlock =
    some twoNopReflection := by native_decide

#print axioms ReflectiveBlockCertificate.sound
#print axioms nopCertificate
#print axioms movCertificate

end StageA.Relational.InterpreterKernelBlockFixture
"""


if __name__ == "__main__":
    unittest.main()
