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


def _fixture_source() -> str:
    return """import StageA.RelationalInterpreterKernelABI

namespace StageA.Relational.InterpreterKernelABIFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI

def relocationPe : PE32 := {
  bytes := .leaf [0x34, 0x12, 0x40, 0x00]
  peOffset := 0
  entrypointRva := 0x1000
  imageBase := 0x400000
  sectionAlignment := 0x1000
  fileAlignment := 4
  sizeOfImage := 0x2000
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{
    virtualSize := 4
    virtualAddress := 0x1000
    rawSize := 4
    rawPointer := 0
    characteristics := 0x40000040
  }]
}

def highlow : List BaseRelocation := [{ rva := 0x1000, kind := 3 }]

example : relocationLayoutChecked relocationPe highlow = true := by
  native_decide

example : loadedImageByte? relocationPe highlow 0x500000 0x1002 = some 0x50 := by
  native_decide

example : relocationLayoutChecked relocationPe
    [{ rva := 0x1000, kind := 7 }] = false := by
  native_decide

example : (kernelCDeclLayout .programLookup).argumentOffsets = [4] := by
  rfl

example : (kernelCDeclLayout .interpreterStep).argumentOffsets = [4, 8, 12, 16] := by
  rfl

example : (kernelCDeclLayout .interpreterStep).result = .hiddenStruct 3 := by
  rfl

example : (kernelCDeclLayout .runFunction).preservedRegisters =
    [.ebx, .esi, .edi, .ebp] := by
  rfl

example : decodeEngineLayoutBytes [] = none := by
  rfl

#print axioms semanticMachine_matches
#print axioms CompiledInterpreterMixedLaunchRelation.loadedOriginalProgramTable
#print axioms CompiledInterpreterMixedLaunchRelation.loadedCandidateImage
#print axioms CompiledInterpreterMixedLaunchRelation.originalStateRepresented

end StageA.Relational.InterpreterKernelABIFixture
"""


class StageARelationalInterpreterKernelABITests(unittest.TestCase):
    def test_kernel_has_no_unchecked_acceptance_constructs(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelABI.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        self.assertIn("def ConcreteKernelABI.relation", source)
        self.assertIn("structure ABIRequestFacts", source)
        self.assertIn("structure ABIResponseFacts", source)
        self.assertIn("LoadedOriginalProgramTable", source)
        self.assertIn("countWord", source)
        self.assertIn("sourceWords", source)
        self.assertIn("sourceOffset < 2 ^ 32", source)
        self.assertIn(
            "programTableCertificate_transferCount_eq_records_length", source
        )
        self.assertIn("LoadedCandidateImageMemory", source)
        self.assertIn("decodeEngineLayoutAt", source)
        self.assertIn("parseRelocations pe == some relocations", source)
        self.assertIn("CDeclEntryFrameHolds", source)
        self.assertIn("CDeclReturnFrameHolds", source)
        self.assertIn("state.registers.eax", source)
        self.assertIn("NativeExternalEventShape", source)
        self.assertIn("CompiledInterpreterMixedLaunchRelation", source)
        self.assertIn(
            "CompiledInterpreterMixedLaunchRelation.requestRelated", source
        )
        self.assertIn("OriginalEngineStateHolds", source)

        self.assertNotIn("PE32ConsoleLaunchV2.StatesRelated", source)
        self.assertNotIn("stage_b_", source)
        self.assertNotRegex(source, r"simulation\s*:")
        self.assertNotIn("KernelABIRelation.Total", source)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_kernel_compiles_and_axiom_audit_is_clean(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernelABI"
            )
            (stage_a / "RelationalInterpreterKernelABIFixture.lean").write_text(
                _fixture_source(), encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernelABIFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
