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


class StageAKernelCallbackNativeWorldBridgeTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for bridge checks")
    def test_callback_inventory_is_the_exact_native_target_inventory(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        source = (
            source_root
            / "RelationalInterpreterKernelCallbackNativeWorldBridge.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterKernelCallbackNativeWorldBridge",
            )
            (stage_a / "KernelCallbackNativeWorldBridgeFixture.lean").write_text(
                _FIXTURE, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="KernelCallbackNativeWorldBridgeFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


_FIXTURE = r"""import StageA.RelationalInterpreterKernelCallbackNativeWorldBridge

namespace StageA.Relational.InterpreterKernelCallbackNativeWorldBridgeFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelCallbackNativeWorldBridge
open StageA.Relational.InterpreterNativeWorld

def target : CallbackTargetEntry := {
  id := 4
  entry := { rva := 23, bytes := [0xc3] }
}

def site : KernelIndirectCallbackSite := {
  id := 2
  instruction := { rva := 17, bytes := [0xff, 0xd0] }
  continuationRva := 19
  targetOperand := .register .eax
  abi := {
    argumentCount := 0
    argumentOffsets := []
    callerStackDelta := 0
    preservedRegisters := [.ebx, .esi, .edi, .ebp]
    returnKind := .wordInEax
  }
  targets := { entries := [target] }
}

def inventory : KernelCallbackInventory := { sites := [site] }

example : (kernelCallbackNativeTargetInventory inventory).targetSets = [{
    sourceRva := 17
    transfer := .call
    targets := [.internalRva 23]
  }] := by
  rfl

def pe : PE32 := {
  bytes := .empty
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 0
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := []
}

def environment : NativeWorldEnvironment := {
  action := fun _ _ _ => .blocked .missingRuntimeContinuation
}

def emptyInventory : KernelCallbackInventory := { sites := [] }

def candidate : ExactNativeWorldProgram := {
  pe
  imports := []
  environment
  indirectTargets := kernelCallbackNativeTargetInventory emptyInventory
}

def emptyProgram : CompiledKernelProgram := { functions := [] }

def binding : ExactKernelCallbackNativeWorldBinding emptyInventory emptyProgram
    candidate := {
  callbackChecked := by decide +kernel
  candidateTargets := rfl
  nativeTargetsValid := by decide +kernel
}

example : candidate.indirectTargets.valid candidate.pe = true :=
  binding.targetInventoryValid

#print axioms ExactKernelCallbackNativeWorldBinding.targetInventoryValid

end StageA.Relational.InterpreterKernelCallbackNativeWorldBridgeFixture
"""


if __name__ == "__main__":
    unittest.main()
