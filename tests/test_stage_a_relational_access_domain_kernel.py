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


class StageARelationalAccessDomainKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_access_domain_checker_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        for module in ("RelationalMachine", "RelationalInterpreterTransfer"):
            source = (source_root / f"{module}.lean").read_text(encoding="utf-8")
            for marker in ("sorry", "axiom", "unsafe"):
                self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        machine_source = (source_root / "RelationalMachine.lean").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "(dataAndStackSegmentsFlat : RelationalSide -> Prop)",
            machine_source,
        )
        self.assertIn(
            "segmentsFlat : ∀ side, dataAndStackSegmentsFlat side",
            machine_source,
        )
        self.assertNotIn(
            "dataAndStackSegmentsFlat : ∀ side : RelationalSide, Prop",
            machine_source,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterTransfer"
            )
            (stage_a / "RelationalAccessDomainKernel.lean").write_text(
                _FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalAccessDomainKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


_FIXTURE = r"""import StageA.RelationalInterpreterTransfer

namespace StageA.RelationalAccessDomainKernel

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterTransfer

def pe : PE32 := {
  bytes := ByteTree.ofBytes []
  peOffset := 0
  entrypointRva := 0x1000
  imageBase := 0x400000
  sectionAlignment := 0x1000
  fileAlignment := 0x200
  sizeOfImage := 0x3000
  sizeOfHeaders := 0x200
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [
    {
      virtualSize := 0x100
      virtualAddress := 0x1000
      rawSize := 0x100
      rawPointer := 0x200
      characteristics := 0x60000020
    },
    {
      virtualSize := 0x100
      virtualAddress := 0x2000
      rawSize := 0x100
      rawPointer := 0x400
      characteristics := 0xc0000040
    }
  ]
}

def context : StaticProofContext := {
  originalPe := pe
  candidatePe := pe
  originalImportCertificate := { descriptors := [] }
  candidateImportCertificate := { descriptors := [] }
  originalRelocations := []
  candidateRelocations := []
  codeMap := {
    entries := .leaf []
    originalAddresses := .leaf []
    candidateAddresses := .leaf []
  }
  dataMap := {
    entries := #[]
    originalOrder := []
    candidateOrder := []
  }
  roots := []
  observations := {}
}

def world : RelationalWorld := {
  stackRanges := [{
    id := 1
    originalBase := BitVec.ofNat 32 0x700000
    candidateBase := BitVec.ofNat 32 0x800000
    size := 0x100
  }]
  dynamicRanges := [{
    id := 2
    originalBase := BitVec.ofNat 32 0x900000
    candidateBase := BitVec.ofNat 32 0xa00000
    size := 0x80
  }]
}

example : wholeSpanContainedChecked 0x1000 0x100 0x1080 0x80 = true := by
  native_decide
example : wholeSpanContainedChecked 0x1000 0x100 0x1080 0x81 = false := by
  native_decide
example :
    wholeSpanContainedChecked 0xfffffffc 4 0xfffffffc 4 = true := by
  native_decide
example :
    wholeSpanContainedChecked 0xfffffffc 8 0xfffffffc 4 = false := by
  native_decide

example : pe32AccessSpanChecked pe .read 0x401000 4 = true := by native_decide
example : pe32AccessSpanChecked pe .write 0x402000 4 = true := by native_decide
example : pe32AccessSpanChecked pe .write 0x401000 4 = false := by native_decide
example : pe32AccessSpanChecked pe .write 0x400100 4 = false := by native_decide
example : pe32AccessSpanChecked pe .write 0x4020ff 2 = false := by native_decide
example : pe32AccessSpanChecked pe .read 0xfffffffe 4 = false := by native_decide

example : world.accessSpanChecked .original 0x700080 0x80 = true := by
  native_decide
example : world.accessSpanChecked .candidate 0x8000ff 2 = false := by
  native_decide
example : world.accessSpanChecked .original 0x900000 0x80 = true := by
  native_decide

example :
    repStosdSpan? (BitVec.ofNat 32 0x1000) (BitVec.ofNat 32 2) false =
      some { start := 0x1000, size := 8 } := by
  native_decide
example :
    repStosdSpan? (BitVec.ofNat 32 0x1008) (BitVec.ofNat 32 3) true =
      some { start := 0x1000, size := 12 } := by
  native_decide
example :
    repStosdSpan? (BitVec.ofNat 32 0xffffffff) (BitVec.ofNat 32 0) true =
      some { start := 0xffffffff, size := 0 } := by
  native_decide
example :
    repStosdSpan? (BitVec.ofNat 32 0xfffffffc) (BitVec.ofNat 32 2) false =
      none := by
  native_decide
example :
    repStosdSpan? (BitVec.ofNat 32 4) (BitVec.ofNat 32 3) true = none := by
  native_decide
example :
    repStosdSpan? (BitVec.ofNat 32 0xffffffff) (BitVec.ofNat 32 1) true =
      none := by
  native_decide
example :
    repMovsdSpans? (BitVec.ofNat 32 0x401000)
      (BitVec.ofNat 32 0x402000) (BitVec.ofNat 32 2) false =
      some ({ start := 0x401000, size := 8 },
        { start := 0x402000, size := 8 }) := by
  native_decide

def readText : InterpreterEvent :=
  .memoryRead (BitVec.ofNat 32 0x401000) .dword (BitVec.ofNat 32 0)

def writeData : InterpreterEvent :=
  .memoryWrite (BitVec.ofNat 32 0x402000) .dword (BitVec.ofNat 32 1)

def writeText : InterpreterEvent :=
  .memoryWrite (BitVec.ofNat 32 0x401000) .dword (BitVec.ofNat 32 1)

def fillData : InterpreterEvent :=
  .repStosd (BitVec.ofNat 32 0x402000) (BitVec.ofNat 32 0)
    (BitVec.ofNat 32 4) false

def emptyFill : InterpreterEvent :=
  .repStosd (BitVec.ofNat 32 0xffffffff) (BitVec.ofNat 32 0)
    (BitVec.ofNat 32 0) true

def checkedMove : InterpreterEvent :=
  .repMovsd (BitVec.ofNat 32 0x401000) (BitVec.ofNat 32 0x402000)
    (BitVec.ofNat 32 1) false

def nonMemoryCall : InterpreterEvent :=
  .call {
    kind := .internal
    instructionRva := 0x1000
    callIndex := 0
    targetRva := BitVec.ofNat 32 0x401010
    returnRva := 0x1005
    dll := none
    symbol := none
    ordinal := none
    arguments := []
    stackInputs := []
  }

example : interpreterEventAccessDomainChecked .original context world readText = true := by
  native_decide
example : interpreterEventAccessDomainChecked .candidate context world writeData = true := by
  native_decide
example : interpreterEventAccessDomainChecked .original context world writeText = false := by
  native_decide
example : interpreterEventAccessDomainChecked .candidate context world fillData = true := by
  native_decide
example : interpreterEventAccessDomainChecked .original context world emptyFill = true := by
  native_decide
example :
    interpreterEventAccessDomainChecked .original context world checkedMove = true := by
  native_decide
example :
    interpreterEventAccessDomainChecked .original context world nonMemoryCall = true := by
  native_decide

def Related (_world : RelationalWorld)
    (_original _candidate : InterpreterMachine) : Prop :=
  _world = world

def originalEvents (_world : RelationalWorld)
    (_original _candidate : InterpreterMachine) : List InterpreterEvent :=
  [readText, writeData, fillData]

def candidateEvents (_world : RelationalWorld)
    (_original _candidate : InterpreterMachine) : List InterpreterEvent :=
  [readText, writeData, fillData]

def SegmentsFlat (_side : RelationalSide) : Prop := True

def ArchitecturallyMapped
    (_side : RelationalSide) (_mode : ModeledAccessMode)
    (_absolute _size : Nat) : Prop := True

def certificate : CheckedAccessDomainCertificate Related context
    originalEvents candidateEvents := {
  originalChecked := by
    intro checkedWorld original candidate related
    subst checkedWorld
    change interpreterEventsAccessDomainChecked .original context world
      [readText, writeData, fillData] = true
    native_decide
  candidateChecked := by
    intro checkedWorld original candidate related
    subst checkedWorld
    change interpreterEventsAccessDomainChecked .candidate context world
      [readText, writeData, fillData] = true
    native_decide
}

def launchAssumption :
    FlatMappedAccessLaunchAssumption context world
      SegmentsFlat ArchitecturallyMapped := {
  segmentsFlat := by intro side; trivial
  modeledSpansMapped := by
    intro side mode absolute size modeled
    trivial
}

example (original candidate : InterpreterMachine) :
    ∀ event ∈ originalEvents world original candidate,
      InterpreterEventModeledAccessDomain .original context world event :=
  certificate.originalModeled world original candidate rfl

example :
    ArchitecturallyMapped .original .read 0x401000 4 :=
  launchAssumption.architecturallyMapped_of_modeled .original .read 0x401000 4
    (by
      change relationalAccessSpanChecked .original context world .read 0x401000 4 =
        true
      native_decide)

#print axioms wholeSpanContainedChecked_sound
#print axioms dynamicAddressRangeAccessSpanChecked_sound
#print axioms pe32AccessSpanChecked_read_sound
#print axioms pe32AccessSpanChecked_write_sound
#print axioms RelationalWorld.accessSpanChecked_sound
#print axioms relationalAccessSpanChecked_sound
#print axioms FlatMappedAccessLaunchAssumption.architecturallyMapped_of_modeled
#print axioms interpreterEventsAccessDomainChecked_sound
#print axioms CheckedAccessDomainCertificate.originalModeled
#print axioms CheckedAccessDomainCertificate.candidateModeled

end StageA.RelationalAccessDomainKernel
"""


if __name__ == "__main__":
    unittest.main()
