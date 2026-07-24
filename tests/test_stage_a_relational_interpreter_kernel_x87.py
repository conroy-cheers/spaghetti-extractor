from __future__ import annotations

import re
import shutil
import tempfile
import types
import unittest
from pathlib import Path

import capstone

from spaghetti_extractor.relational.lean.interpreter_kernel import (
    _FunctionHint,
    _analyze_function,
    _kernel_x87_frame_plan,
    _lean_function,
)
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


def _decode(data: bytes):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    return next(decoder.disasm(data, 0x401000))


class _PE:
    def __init__(self, start: int, data: bytes) -> None:
        self.start = start
        self.data = data

    def get_data(self, rva: int, size: int) -> bytes:
        offset = rva - self.start
        return self.data[offset : offset + size]


def _binary(data: bytes, start: int = 0x1000):
    section = types.SimpleNamespace(
        executable=True,
        rva_start=start,
        raw_size=len(data),
    )
    return types.SimpleNamespace(
        image_base=0x400000,
        sections=(section,),
        pe=_PE(start, data),
    )


class StageARelationalInterpreterKernelX87Tests(unittest.TestCase):
    def test_recognizes_only_unprefixed_ia32_frame_memory_forms(self) -> None:
        cases = (
            ("dd6020", "frstor", "eax", None, 1, 32),
            ("ddb08c000000", "fnsave", "eax", None, 1, 140),
            ("dd2500000010", "frstor", None, None, 1, 0x10000000),
            ("dd642480", "frstor", "esp", None, 1, -128),
        )
        for encoded, operation, base, index, scale, displacement in cases:
            with self.subTest(encoded=encoded):
                frame = _kernel_x87_frame_plan(
                    _decode(bytes.fromhex(encoded)), 0x1000
                )
                self.assertIsNotNone(frame)
                assert frame is not None
                self.assertEqual(frame.operation, operation)
                self.assertEqual(frame.base_register, base)
                self.assertEqual(frame.index_register, index)
                self.assertEqual(frame.scale, scale)
                self.assertEqual(frame.displacement, displacement)
                self.assertEqual(frame.payload()["frame_size"], 108)

        for encoded in ("d96020", "64dd6020", "9bdd7020"):
            with self.subTest(encoded=encoded):
                self.assertIsNone(
                    _kernel_x87_frame_plan(
                        _decode(bytes.fromhex(encoded)), 0x1000
                    )
                )

    def test_frame_operations_are_separate_exact_cfg_nodes(self) -> None:
        data = bytes.fromhex(
            "55"  # push ebp
            "89e5"  # mov ebp, esp
            "dd6020"  # frstor [eax + 32]
            "90"  # nop
            "ddb08c000000"  # fnsave [eax + 140]
            "c9"  # leave
            "c3"  # ret
        )
        function, issues = _analyze_function(
            _binary(data),
            _FunctionHint(
                "generic-x87-frame", (), 0x1000, 0x1000 + len(data), True
            ),
            "helper 4096",
        )

        self.assertNotIn("unsupported_kernel_x87", {issue.code for issue in issues})
        self.assertEqual(
            [(frame.operation, frame.rva, frame.successor) for frame in function.x87_frames],
            [
                ("frstor", 0x1003, 0x1006),
                ("fnsave", 0x1007, 0x100D),
            ],
        )
        self.assertEqual(
            [(block.entry_rva, block.successors) for block in function.blocks],
            [
                (0x1000, (0x1003,)),
                (0x1006, (0x1007,)),
                (0x100D, ()),
            ],
        )
        ordinary_rvas = {
            instruction.rva
            for block in function.blocks
            for instruction in block.instructions
        }
        self.assertTrue({0x1003, 0x1007}.isdisjoint(ordinary_rvas))

        lean = _lean_function(function)
        self.assertIn("x87Frames := [", lean)
        self.assertIn("operation := .frStor", lean)
        self.assertIn("operation := .fnSave", lean)

    def test_ordinary_x87_command_is_a_separate_exact_cfg_node(self) -> None:
        data = bytes.fromhex("55" "89e5" "d94020" "c9" "c3")
        function, issues = _analyze_function(
            _binary(data),
            _FunctionHint(
                "unsupported-x87", (), 0x1000, 0x1000 + len(data), True
            ),
            "helper 4096",
        )

        self.assertFalse(function.x87_frames)
        self.assertNotIn("unsupported_kernel_x87", {issue.code for issue in issues})
        self.assertEqual(
            [(command.mnemonic, command.rva) for command in function.x87_commands],
            [("fld", 0x1003)],
        )
        ordinary_rvas = {
            instruction.rva
            for block in function.blocks
            for instruction in block.instructions
        }
        self.assertNotIn(0x1003, ordinary_rvas)
        self.assertIn("x87Commands := [", _lean_function(function))

    def test_lean_kernel_exposes_exact_frame_semantics_without_escape_hatches(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernel.lean"
        ).read_text(encoding="utf-8")

        self.assertIn("decodeKernelX87FrameExact", source)
        self.assertIn("encodeKernelX87Frame", source)
        self.assertIn("decodeKernelX87Frame", source)
        self.assertIn("kernelX87FrameAddressValid", source)
        self.assertIn("stepKernelPE32Instruction", source)
        self.assertIn("KernelX87FrameRelated (rep : EngineRep)", source)
        self.assertIn("stepKernelX87Frame?", source)
        self.assertIn("KernelX87CommandInstruction", source)
        self.assertIn("stepKernelX87Command?", source)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_exact_frstor_semantics_compile_without_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(source_root, stage_a, "RelationalInterpreterKernel")
            (stage_a / "RelationalInterpreterKernelX87Fixture.lean").write_text(
                _LEAN_FIXTURE, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernelX87Fixture"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("native_decide.ax", result["stdout"])


_LEAN_FIXTURE = r"""import StageA.RelationalInterpreterKernel

namespace StageA.Relational.InterpreterKernelX87Fixture

open StageA.Formal StageA.Relational
open StageA.Relational.Engine
open StageA.Relational.InterpreterKernel

def savedPhysical : StageA.X87.PhysicalState := {
  slots := Vector.ofFn fun index =>
    if index.val = 7 then
      .occupied .zero (BitVec.ofNat 80 0x123456789abcdef)
    else .empty
  control := BitVec.ofNat 16 0x027f
  status := BitVec.ofNat 16 0x3880
  pendingException := true
  lastOpcode := BitVec.ofNat 11 0x321
  instructionPointer := BitVec.ofNat 32 0x401234
  codeSelector := BitVec.ofNat 16 0x1b
  dataPointer := BitVec.ofNat 32 0x405678
  dataSelector := BitVec.ofNat 16 0x23
}

example : (encodeKernelX87Frame savedPhysical).length = 108 :=
  encodeKernelX87Frame_length savedPhysical

example : decodeKernelX87Frame (encodeKernelX87Frame savedPhysical) =
    some savedPhysical := by native_decide

example : (encodeKernelX87Frame savedPhysical).take 12 =
    [0x7f, 0x02, 0, 0, 0x80, 0x38, 0, 0, 0xff, 0x7f, 0, 0] := by
  native_decide

def pe : PE32 := {
  bytes := ByteTree.ofBytes [0xdd, 0x60, 0x20]
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 3
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{
    virtualSize := 3
    virtualAddress := 0
    rawSize := 3
    rawPointer := 0
    characteristics := 0x60000020
  }]
}

def frameAddress : Word := BitVec.ofNat 32 0x1020

def frameNode : KernelX87FrameInstruction := {
  rva := 0
  bytes := [0xdd, 0x60, 0x20]
  operation := .frStor
}

example : frameNode.checked pe = true := by native_decide

def frameMemory : Memory := fun address =>
  if frameAddress.toNat <= address.toNat then
    (encodeKernelX87Frame savedPhysical).getD
      (address.toNat - frameAddress.toNat) (BitVec.ofNat 8 0)
  else BitVec.ofNat 8 0

def zeroRegisters : Registers Word := {
  eax := BitVec.ofNat 32 0x1000
  ebx := BitVec.ofNat 32 0
  ecx := BitVec.ofNat 32 0
  edx := BitVec.ofNat 32 0
  esi := BitVec.ofNat 32 0
  edi := BitVec.ofNat 32 0
  ebp := BitVec.ofNat 32 0
  esp := BitVec.ofNat 32 0
}

def input : MachineState := {
  registers := zeroRegisters
  memory := frameMemory
}

def frstorRestored : Bool :=
  match stepKernelX87Frame? pe 0 7 input with
    | some (.running nextRva nextSlot state) =>
        nextRva == 3 && nextSlot == 8 &&
          state.x87Physical == savedPhysical &&
          state.x87.control == savedPhysical.control &&
          state.x87.status == savedPhysical.status &&
          state.x87.stack 0 == BitVec.ofNat 80 0x123456789abcdef
    | _ => false

example : frstorRestored = true := by native_decide

def wrappingInput : MachineState := {
  input with
  registers := { zeroRegisters with eax := BitVec.ofNat 32 0xffffff80 }
}

def wrappingAccessFaults : Bool :=
  match stepKernelPE32Instruction pe [] (.running 0 0 wrappingInput) with
  | .fault => true
  | _ => false

example : wrappingAccessFaults = true := by native_decide

def fnsavePe : PE32 := {
  pe with
  bytes := ByteTree.ofBytes [0xdd, 0xb0, 0x8c, 0, 0, 0]
  sizeOfImage := 6
  sections := [{
    virtualSize := 6
    virtualAddress := 0
    rawSize := 6
    rawPointer := 0
    characteristics := 0x60000020
  }]
}

def saveInput : MachineState := {
  input with
  x87 := kernelX87LegacyState savedPhysical input.x87.semantics
  x87Physical := savedPhysical
}

def fnsaveWritesAndResets : Bool :=
  match stepKernelX87Frame? fnsavePe 0 0 saveInput with
  | some (.running nextRva nextSlot state) =>
      nextRva == 6 && nextSlot == 1 &&
        readBytes state.memory (BitVec.ofNat 32 0x108c) 108 ==
          encodeKernelX87Frame savedPhysical &&
        state.x87Physical == StageA.X87.initialPhysicalState &&
        state.x87.control == StageA.X87.initialPhysicalState.control &&
        state.x87.status == StageA.X87.initialPhysicalState.status
  | _ => false

example : fnsaveWritesAndResets = true := by native_decide

example : decodeKernelX87FrameExact [0x64, 0xdd, 0x60, 0x20] = none := by
  native_decide

example : decodeKernelX87FrameExact [0xdd, 0xe0] = none := by native_decide

#print axioms encodeKernelX87Frame_length
#print axioms stepKernelX87Frame?_exact

end StageA.Relational.InterpreterKernelX87Fixture
"""


if __name__ == "__main__":
    unittest.main()
