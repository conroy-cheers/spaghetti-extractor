from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


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
            for module in ("X87", "Formal", "ISAConformance"):
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )

            (stage_a / "ISAConformanceKernel.lean").write_text(
                """import StageA.ISAConformance

namespace StageA.ISAConformanceKernelTests

open StageA.Formal

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

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

def leaveCase : ISAConformanceInput := {
  bytes := [0xc9]
  pc := 0x2000
  registers := {
    eax := 1
    ebx := 2
    ecx := 3
    edx := 4
    esi := 5
    edi := 6
    ebp := 0x70002000
    esp := 0x70001000
  }
  eflags := 0x202
  memory := [
    { address := 0x70002000, value := 0x78 },
    { address := 0x70002001, value := 0x56 },
    { address := 0x70002002, value := 0x34 },
    { address := 0x70002003, value := 0x12 }
  ]
}

def leaveExpected : ISAConformanceExpectation := {
  registers := {
    eax := none
    ebx := none
    ecx := none
    edx := none
    esi := none
    edi := none
    ebp := some { value := 0x12345678, mask := 0xffffffff }
    esp := some { value := 0x70002004, mask := 0xffffffff }
  }
  eflags := some { value := 0x202, mask := 0xffffffff }
  writes := some []
  control := some (.next 0x2001)
  fault := some .none
}

example : leaveCase.matches leaveExpected = true := by decide

def baseRegisters : Registers Nat := {
  eax := 0x11223344
  ebx := 0x01020304
  ecx := 0x55667788
  edx := 0x99aabbcc
  esi := 0x12345678
  edi := 0x87654321
  ebp := 0x70002000
  esp := 0x70001000
}

def noRegisterExpectations :
    Registers (Option ISAConformanceMaskedWord) := {
  eax := none
  ebx := none
  ecx := none
  edx := none
  esi := none
  edi := none
  ebp := none
  esp := none
}

def exactWord (value : Nat) : ISAConformanceMaskedWord := {
  value
  mask := 0xffffffff
}

def wordMemory (address value : Nat) : List ISAConformanceMemoryByte := [
  { address := address, value := value % 256 },
  { address := address + 1, value := (value / 256) % 256 },
  { address := address + 2, value := (value / 65536) % 256 },
  { address := address + 3, value := (value / 16777216) % 256 }
]

def maskedWordMemory (address value : Nat) :
    List ISAConformanceMaskedByte := [
  { address := address, value := value % 256, mask := 0xff },
  { address := address + 1, value := (value / 256) % 256, mask := 0xff },
  { address := address + 2, value := (value / 65536) % 256, mask := 0xff },
  { address := address + 3, value := (value / 16777216) % 256, mask := 0xff }
]

def pushFlagsCase : ISAConformanceInput := {
  bytes := [0x9c]
  pc := 0x3000
  registers := baseRegisters
  eflags := 0x00030ed7
  observeMemory := [0x70000ffc, 0x70000ffd, 0x70000ffe, 0x70000fff]
}

def pushFlagsExpected : ISAConformanceExpectation := {
  registers := {
    noRegisterExpectations with esp := some (exactWord 0x70000ffc)
  }
  eflags := some (exactWord 0x00030ed7)
  memory := maskedWordMemory 0x70000ffc 0x00000ed7
  writes := some [{ address := 0x70000ffc, value := 0x00000ed7 }]
  control := some (.next 0x3001)
  fault := some .none
}

example : pushFlagsCase.matches pushFlagsExpected = true := by native_decide

def pushAllCase : ISAConformanceInput := {
  bytes := [0x60]
  pc := 0x3100
  registers := baseRegisters
  eflags := 0x202
  observeMemory := (List.range 32).map (0x70000fe0 + ·)
}

def pushAllExpected : ISAConformanceExpectation := {
  registers := {
    noRegisterExpectations with esp := some (exactWord 0x70000fe0)
  }
  eflags := some (exactWord 0x202)
  memory :=
    maskedWordMemory 0x70000ffc 0x11223344 ++
    maskedWordMemory 0x70000ff8 0x55667788 ++
    maskedWordMemory 0x70000ff4 0x99aabbcc ++
    maskedWordMemory 0x70000ff0 0x01020304 ++
    maskedWordMemory 0x70000fec 0x70001000 ++
    maskedWordMemory 0x70000fe8 0x70002000 ++
    maskedWordMemory 0x70000fe4 0x12345678 ++
    maskedWordMemory 0x70000fe0 0x87654321
  control := some (.next 0x3101)
  fault := some .none
}

example : pushAllCase.matches pushAllExpected = true := by native_decide

def popAllCase : ISAConformanceInput := {
  bytes := [0x61]
  pc := 0x3200
  registers := { baseRegisters with esp := 0x70000fe0 }
  eflags := 0xa02
  memory :=
    wordMemory 0x70000fe0 0x88776655 ++
    wordMemory 0x70000fe4 0x77665544 ++
    wordMemory 0x70000fe8 0x66554433 ++
    wordMemory 0x70000fec 0xdeadbeef ++
    wordMemory 0x70000ff0 0x55443322 ++
    wordMemory 0x70000ff4 0x44332211 ++
    wordMemory 0x70000ff8 0x33221100 ++
    wordMemory 0x70000ffc 0x221100ff
}

def popAllExpected : ISAConformanceExpectation := {
  registers := {
    eax := some (exactWord 0x221100ff)
    ebx := some (exactWord 0x55443322)
    ecx := some (exactWord 0x33221100)
    edx := some (exactWord 0x44332211)
    esi := some (exactWord 0x77665544)
    edi := some (exactWord 0x88776655)
    ebp := some (exactWord 0x66554433)
    esp := some (exactWord 0x70001000)
  }
  eflags := some (exactWord 0xa02)
  writes := some []
  control := some (.next 0x3201)
  fault := some .none
}

example : popAllCase.matches popAllExpected = true := by native_decide

def popFlagsCase : ISAConformanceInput := {
  bytes := [0x9d]
  pc := 0x3300
  registers := { baseRegisters with esp := 0x70000ffc }
  eflags := 0x3202
  memory := wordMemory 0x70000ffc 0x00240dd5
}

def popFlagsExpected : ISAConformanceExpectation := {
  registers := {
    noRegisterExpectations with esp := some (exactWord 0x70001000)
  }
  eflags := some (exactWord 0x00243dd7)
  writes := some []
  control := some (.next 0x3301)
  fault := some .none
}

example : popFlagsCase.matches popFlagsExpected = true := by native_decide

def clearDirectionCase : ISAConformanceInput := {
  bytes := [0xfc]
  pc := 0x3400
  registers := baseRegisters
  eflags := 0x602
}

def clearDirectionExpected : ISAConformanceExpectation := {
  registers := noRegisterExpectations
  eflags := some (exactWord 0x202)
  writes := some []
  control := some (.next 0x3401)
  fault := some .none
}

example : clearDirectionCase.matches clearDirectionExpected = true := by
  native_decide

def pushImmediate8Case : ISAConformanceInput := {
  bytes := [0x6a, 0x80]
  pc := 0x3500
  registers := baseRegisters
  eflags := 0x202
  observeMemory := [0x70000ffc, 0x70000ffd, 0x70000ffe, 0x70000fff]
}

def pushImmediate8Expected : ISAConformanceExpectation := {
  registers := {
    noRegisterExpectations with esp := some (exactWord 0x70000ffc)
  }
  eflags := some (exactWord 0x202)
  memory := maskedWordMemory 0x70000ffc 0xffffff80
  writes := some [{ address := 0x70000ffc, value := 0xffffff80 }]
  control := some (.next 0x3502)
  fault := some .none
}

example : pushImmediate8Case.matches pushImmediate8Expected = true := by
  native_decide

def pushImmediate32Case : ISAConformanceInput := {
  bytes := [0x68, 0x78, 0x56, 0x34, 0x12]
  pc := 0x3600
  registers := baseRegisters
  eflags := 0x202
  observeMemory := [0x70000ffc, 0x70000ffd, 0x70000ffe, 0x70000fff]
}

def pushImmediate32Expected : ISAConformanceExpectation := {
  registers := {
    noRegisterExpectations with esp := some (exactWord 0x70000ffc)
  }
  eflags := some (exactWord 0x202)
  memory := maskedWordMemory 0x70000ffc 0x12345678
  writes := some [{ address := 0x70000ffc, value := 0x12345678 }]
  control := some (.next 0x3605)
  fault := some .none
}

example : pushImmediate32Case.matches pushImmediate32Expected = true := by
  native_decide

def fsMoffsCase : ISAConformanceInput := {
  bytes := [0x64, 0xa1, 0x30, 0, 0, 0]
  pc := 0x3700
  registers := baseRegisters
  eflags := 0x202
  fsBase := 0x7ffd0000
  memory := wordMemory 0x7ffd0030 0xcafebabe
}

def fsMoffsExpected : ISAConformanceExpectation := {
  registers := {
    noRegisterExpectations with eax := some (exactWord 0xcafebabe)
  }
  eflags := some (exactWord 0x202)
  fsBase := some 0x7ffd0000
  writes := some []
  control := some (.next 0x3706)
  fault := some .none
}

example : fsMoffsCase.matches fsMoffsExpected = true := by native_decide

def shiftWordCase : ISAConformanceInput := {
  bytes := [0x66, 0xd1, 0xe8]
  pc := 0x3800
  registers := { baseRegisters with eax := 0x11228001 }
  eflags := 0x202
}

def shiftWordExpected : ISAConformanceExpectation := {
  registers := {
    noRegisterExpectations with eax := some (exactWord 0x11224000)
  }
  eflags := some { value := 0x805, mask := 0x8c5 }
  writes := some []
  control := some (.next 0x3803)
  fault := some .none
}

example : shiftWordCase.matches shiftWordExpected = true := by native_decide

def orWordCase : ISAConformanceInput := {
  bytes := [0x66, 0x0b, 0xc1]
  pc := 0x3900
  registers := {
    baseRegisters with eax := 0x112200f0, ecx := 0x55660f00
  }
  eflags := 0xa93
}

def orWordExpected : ISAConformanceExpectation := {
  registers := {
    noRegisterExpectations with eax := some (exactWord 0x11220ff0)
  }
  eflags := some { value := 0x4, mask := 0x8c5 }
  writes := some []
  control := some (.next 0x3903)
  fault := some .none
}

example : orWordCase.matches orWordExpected = true := by native_decide

structure ShiftOracleRow where
  count : Nat
  result : Nat
  eflags : Nat
  flagMask : Nat

def shiftOracleRows : ShiftOperation -> List ShiftOracleRow
  | .left => [
      { count := 0, result := 0x81234567, eflags := 0xed7, flagMask := 0xffffffff },
      { count := 1, result := 0x02468ace, eflags := 0xe03, flagMask := 0x8c5 },
      { count := 2, result := 0x048d159c, eflags := 0x606, flagMask := 0x0c5 },
      { count := 31, result := 0x80000000, eflags := 0x687, flagMask := 0x0c5 },
      { count := 32, result := 0x81234567, eflags := 0xed7, flagMask := 0xffffffff },
      { count := 33, result := 0x02468ace, eflags := 0xe03, flagMask := 0x8c5 }
    ]
  | .right => [
      { count := 0, result := 0x81234567, eflags := 0xed7, flagMask := 0xffffffff },
      { count := 1, result := 0x4091a2b3, eflags := 0xe03, flagMask := 0x8c5 },
      { count := 2, result := 0x2048d159, eflags := 0x607, flagMask := 0x0c5 },
      { count := 31, result := 0x00000001, eflags := 0x602, flagMask := 0x0c5 },
      { count := 32, result := 0x81234567, eflags := 0xed7, flagMask := 0xffffffff },
      { count := 33, result := 0x4091a2b3, eflags := 0xe03, flagMask := 0x8c5 }
    ]
  | .arithmeticRight => [
      { count := 0, result := 0x81234567, eflags := 0xed7, flagMask := 0xffffffff },
      { count := 1, result := 0xc091a2b3, eflags := 0x683, flagMask := 0x8c5 },
      { count := 2, result := 0xe048d159, eflags := 0x687, flagMask := 0x0c5 },
      { count := 31, result := 0xffffffff, eflags := 0x686, flagMask := 0x0c5 },
      { count := 32, result := 0x81234567, eflags := 0xed7, flagMask := 0xffffffff },
      { count := 33, result := 0xc091a2b3, eflags := 0x683, flagMask := 0x8c5 }
    ]

def shiftBytes : ShiftOperation -> Bytes
  | .left => [0xd3, 0xe0]
  | .right => [0xd3, 0xe8]
  | .arithmeticRight => [0xd3, 0xf8]

def clShiftCase (operation : ShiftOperation)
    (row : ShiftOracleRow) : ISAConformanceInput := {
  bytes := shiftBytes operation
  pc := 0x3a00
  registers := {
    baseRegisters with eax := 0x81234567, ecx := row.count
  }
  eflags := 0xed7
  undefinedDefault := 0xa5a5a5a5
}

def shiftExpected (size : Nat)
    (row : ShiftOracleRow) : ISAConformanceExpectation := {
  registers := {
    noRegisterExpectations with eax := some (exactWord row.result)
  }
  eflags := some { value := row.eflags, mask := row.flagMask }
  writes := some []
  control := some (.next (0x3a00 + size))
  fault := some .none
}

example : (shiftOracleRows .left).all (fun row =>
    (clShiftCase .left row).matches (shiftExpected 2 row)) = true := by
  native_decide
example : (shiftOracleRows .right).all (fun row =>
    (clShiftCase .right row).matches (shiftExpected 2 row)) = true := by
  native_decide
example : (shiftOracleRows .arithmeticRight).all (fun row =>
    (clShiftCase .arithmeticRight row).matches (shiftExpected 2 row)) =
    true := by
  native_decide

def shlUndefinedCase (count undefinedValue : Nat) : ISAConformanceInput := {
  bytes := [0xd3, 0xe0]
  pc := 0x3a00
  registers := {
    baseRegisters with eax := 0x81234567, ecx := count
  }
  eflags := 0xed7
  undefinedDefault := undefinedValue
}

def observedEflags (input : ISAConformanceInput) : Option Nat :=
  match input.run with
  | .observed observation => some observation.eflags
  | _ => none

example : (observedEflags (shlUndefinedCase 2 0)).map
    (fun flags => flags &&& 0x800) = some 0 := by
  native_decide
example : (observedEflags (shlUndefinedCase 2 0x10)).map
    (fun flags => flags &&& 0x800) = some 0x800 := by
  native_decide
example : (observedEflags (shlUndefinedCase 1 0)).map
    (fun flags => flags &&& 0x800) = some 0x800 := by
  native_decide
example : (observedEflags (shlUndefinedCase 1 0x10)).map
    (fun flags => flags &&& 0x800) = some 0x800 := by
  native_decide

def doubleShiftOracleRows (left : Bool) : List ShiftOracleRow :=
  if left then [
    { count := 0, result := 0x81234567, eflags := 0xed7, flagMask := 0xffffffff },
    { count := 1, result := 0x02468ace, eflags := 0xe03, flagMask := 0x8c5 },
    { count := 2, result := 0x048d159d, eflags := 0x602, flagMask := 0x0c5 },
    { count := 31, result := 0xad35e3ec, eflags := 0x683, flagMask := 0x0c5 },
    { count := 32, result := 0x81234567, eflags := 0xed7, flagMask := 0xffffffff },
    { count := 33, result := 0x02468ace, eflags := 0xe03, flagMask := 0x8c5 }
  ] else [
    { count := 0, result := 0x81234567, eflags := 0xed7, flagMask := 0xffffffff },
    { count := 1, result := 0x4091a2b3, eflags := 0xe03, flagMask := 0x8c5 },
    { count := 2, result := 0x2048d159, eflags := 0x607, flagMask := 0x0c5 },
    { count := 31, result := 0xb4d78fb1, eflags := 0xe86, flagMask := 0x0c5 },
    { count := 32, result := 0x81234567, eflags := 0xed7, flagMask := 0xffffffff },
    { count := 33, result := 0x4091a2b3, eflags := 0xe03, flagMask := 0x8c5 }
  ]

def doubleShiftCase (left fromCl : Bool)
    (row : ShiftOracleRow) : ISAConformanceInput := {
  bytes :=
    if fromCl then
      [0x0f, if left then 0xa5 else 0xad, 0xd0]
    else
      [0x0f, if left then 0xa4 else 0xac, 0xd0, row.count]
  pc := 0x3b00
  registers := {
    baseRegisters with
    eax := 0x81234567
    edx := 0x5a6bc7d8
    ecx := if fromCl then row.count else 0x99
  }
  eflags := 0xed7
  undefinedDefault := 0x5a5a5a5a
}

def doubleShiftExpected (fromCl : Bool)
    (row : ShiftOracleRow) : ISAConformanceExpectation := {
  registers := {
    noRegisterExpectations with eax := some (exactWord row.result)
  }
  eflags := some { value := row.eflags, mask := row.flagMask }
  writes := some []
  control := some (.next (0x3b00 + if fromCl then 3 else 4))
  fault := some .none
}

example : (doubleShiftOracleRows true).all (fun row =>
    (doubleShiftCase true true row).matches
      (doubleShiftExpected true row)) = true := by
  native_decide
example : (doubleShiftOracleRows false).all (fun row =>
    (doubleShiftCase false true row).matches
      (doubleShiftExpected true row)) = true := by
  native_decide
example : (doubleShiftOracleRows true).all (fun row =>
    (doubleShiftCase true false row).matches
      (doubleShiftExpected false row)) = true := by
  native_decide
example : (doubleShiftOracleRows false).all (fun row =>
    (doubleShiftCase false false row).matches
      (doubleShiftExpected false row)) = true := by
  native_decide

def repStosCounts : List Nat := [0, 1, 185, 4096, 4097]
def repStosDestination : Nat := 0x00100000
def repStosValue : Nat := 0x12345678

def repStosFinalDestination (count : Nat) (direction : Bool) : Nat :=
  if direction then
    repStosDestination - count * 4
  else
    repStosDestination + count * 4

def repStosLastAddress (count : Nat) (direction : Bool) : Nat :=
  if direction then
    repStosDestination - (count - 1) * 4
  else
    repStosDestination + (count - 1) * 4

def repStosOutsideAddress (count : Nat) (direction : Bool) : Nat :=
  if direction then
    repStosDestination - count * 4
  else
    repStosDestination + count * 4

def repStosExpectedMemory (count : Nat)
    (direction : Bool) : List ISAConformanceMaskedByte :=
  if count == 0 then
    maskedWordMemory repStosDestination 0
  else
    maskedWordMemory repStosDestination repStosValue ++
      (if count == 1 then [] else
        maskedWordMemory (repStosLastAddress count direction) repStosValue) ++
      maskedWordMemory (repStosOutsideAddress count direction) 0

def repStosCase (count : Nat) (direction : Bool) : ISAConformanceInput :=
  let expectedMemory := repStosExpectedMemory count direction
  {
    bytes := [0xf3, 0xab]
    pc := 0x3c00
    registers := {
      baseRegisters with
      eax := repStosValue
      ecx := count
      edi := repStosDestination
    }
    eflags := if direction then 0x602 else 0x202
    observeMemory := expectedMemory.map (fun byte => byte.address)
  }

def repStosExpected (count : Nat)
    (direction : Bool) : ISAConformanceExpectation := {
  registers := {
    noRegisterExpectations with
    ecx := some (exactWord 0)
    edi := some (exactWord (repStosFinalDestination count direction))
  }
  eflags := some (exactWord (if direction then 0x602 else 0x202))
  memory := repStosExpectedMemory count direction
  writes := some []
  control := some (.bulkFill repStosDestination repStosValue count direction
    0x3c02)
  fault := some .none
}

example : repStosCounts.all (fun count =>
    (repStosCase count false).matches
      (repStosExpected count false)) = true := by
  native_decide
example : repStosCounts.all (fun count =>
    (repStosCase count true).matches
      (repStosExpected count true)) = true := by
  native_decide

def bitScanCase (profile : X86CPUProfile)
    (source : Nat) : ISAConformanceInput := {
  bytes := [0xf3, 0x0f, 0xbc, 0xc2]
  pc := 0x3d00
  cpuProfile := profile
  registers := {
    baseRegisters with eax := 0xdeadbeef, edx := source
  }
  eflags := 0xed7
  undefinedDefault := 0xcafebabe
}

def bitScanExpected (result flags mask : Nat) :
    ISAConformanceExpectation := {
  registers := {
    noRegisterExpectations with eax := some (exactWord result)
  }
  eflags := some { value := flags, mask }
  writes := some []
  control := some (.next 0x3d04)
  fault := some .none
}

example : (bitScanCase .i686 0).matches
    (bitScanExpected 0xcafebabe 0x40 0x40) = true := by
  native_decide
example : (bitScanCase .i686 1).matches
    (bitScanExpected 0 0 0x40) = true := by
  native_decide
example : (bitScanCase .haswell 0).matches
    (bitScanExpected 32 0x01 0x41) = true := by
  native_decide
example : (bitScanCase .haswell 1).matches
    (bitScanExpected 0 0x40 0x41) = true := by
  native_decide

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
