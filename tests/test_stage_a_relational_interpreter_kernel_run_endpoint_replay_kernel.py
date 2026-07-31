from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}


def _copy_module_closure(
    source_root: Path, destination: Path, module: str
) -> None:
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


@unittest.skipUnless(shutil.which("lean"), "Lean is required")
class StageARelationalInterpreterKernelRunEndpointReplayTests(
    unittest.TestCase
):
    def _compile_fixture(self, fixture: str) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterKernelRunIndirectTargets",
            )
            (stage_a / "RunResolverTargetFailureFixture.lean").write_text(
                fixture, encoding="ascii"
            )
            return _run_lean_relational(
                root, bundle="RunResolverTargetFailureFixture"
            )

    def test_checked_endpoint_replay_compiles_without_bad_axioms(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterKernelRunEndpointReplay",
            )
            result = _run_lean_relational(
                root,
                bundle="RelationalInterpreterKernelRunEndpointReplay",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        for match in _AXIOMS.findall(output):
            axioms = {
                item.strip() for item in match.split(",") if item.strip()
            }
            self.assertLessEqual(axioms, _APPROVED_AXIOMS)
        for theorem in (
            "RunFunctionNativeCheckedEndpointReplay.rangeExact",
            "RunFunctionNativeCheckedEndpointReplay.manifestExact",
            "RunFunctionNativeCheckedEndpointReplay.exactCandidateBytes",
            "RunFunctionNativeCheckedEndpointReplay.entryRvaExact",
            "RunFunctionNativeCheckedEndpointReplay.loopHeaderRvaExact",
            "RunFunctionNativeCheckedEndpointReplay.stepContinuationRvaExact",
            (
                "RunFunctionNativeCheckedEndpointReplay."
                "resolverContinuationRvaExact"
            ),
            "RunFunctionNativeCheckedEndpointReplay.epilogueRvaExact",
            "RunFunctionNativeCheckedEndpointReplay.fuelsExact",
            "runFunctionResolverCallEaxDecodeExact",
            (
                "runFunctionNativeResolverTargetInventoryChecked_"
                "targetSetExact"
            ),
            "RunFunctionNativeCheckedInternalSegment.entryExact",
            "RunFunctionNativeCheckedInternalSegment.slotExact",
            "RunFunctionNativeCheckedInternalSegment.fuelExact",
            "RunFunctionNativeCheckedInternalSegment.endpointPresent",
            "RunFunctionNativeCheckedInternalSegment.endpointOptionExact",
            "RunFunctionNativeCheckedInternalSegment.exitExact",
            "RunFunctionNativeCheckedInternalSegment.finalSlotExact",
            "RunFunctionNativeCheckedInternalSegment.chunkResultExact",
            "RunFunctionNativeCheckedInternalSegment.terminalPhase",
            "RunFunctionNativeCheckedInternalSegment.directContinuation",
        ):
            self.assertIn(theorem, output)

    def test_certificate_has_no_submitted_dynamic_endpoint_fields(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelRunEndpointReplay.lean"
        ).read_text(encoding="utf-8")
        certificate = source.split(
            "structure RunFunctionNativeCheckedEndpointReplay", 1
        )[1].split(
            "/-- Generated modules use this constructor", 1
        )[0]
        self.assertIn(
            "CheckedNativeOperationFunctionReplay candidate",
            certificate,
        )
        self.assertIn(
            "runFunctionNativeEndpointReplayChecked",
            certificate,
        )
        for forbidden in (
            "NonemptyRelatedPath",
            "afterState",
            "postState",
            "CallStatus",
            "AbstractRunFunction",
        ):
            self.assertNotIn(forbidden, certificate)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        segment = source.split(
            "structure RunFunctionNativeCheckedInternalSegment", 1
        )[1].split(
            "theorem RunFunctionNativeCheckedInternalSegment.entryExact", 1
        )[0]
        self.assertIn(
            "CheckedNativeOperationInternalReplay",
            segment,
        )
        self.assertIn(
            "runFunctionNativeInternalSegmentChecked",
            segment,
        )
        for forbidden in (
            "NonemptyRelatedPath",
            "afterState",
            "postState",
            "CallStatus",
        ):
            self.assertNotIn(forbidden, segment)

    def test_exact_call_eax_without_target_inventory_fails_closed(self) -> None:
        fixture = """import StageA.RelationalInterpreterKernelRunIndirectTargets

namespace StageA.RunResolverTargetFailureFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernelRunEndpointReplay
open StageA.Relational.InterpreterNativeWorld

def resolverPe : PE32 := {
  bytes := .empty
  peOffset := 0
  entrypointRva := 0
  imageBase := 0
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

def resolverEnvironment : NativeWorldEnvironment := {
  action := fun _ _ world => .terminated world
}

def resolverCandidate : ExactNativeWorldProgram := {
  pe := resolverPe
  imports := []
  environment := resolverEnvironment
}

example :
    decodeInstructionExact [0xff, 0xd0] =
      some {
        instruction := .callIndirect (.register .eax)
        size := 2
        trailing := []
      } :=
  runFunctionResolverCallEaxDecodeExact

example :
    nativeRunResolverTargetInventoryChecked resolverCandidate 288484
      [290898] = false := by
  decide +kernel

theorem requiredResolverTargetInventory :
    nativeRunResolverTargetInventoryChecked resolverCandidate 288484
      [290898] = true := by
  decide +kernel

end StageA.RunResolverTargetFailureFixture
"""
        result = self._compile_fixture(fixture)

        self.assertEqual(result["status"], "failed", result)
        output = result["stdout"] + result["stderr"]
        self.assertIn("requiredResolverTargetInventory", fixture)
        self.assertIn("Tactic `decide` proved that the proposition", output)
        self.assertIn("is false", output)

    def test_exact_call_eax_uses_checked_finite_target_inventory(self) -> None:
        fixture = """import StageA.RelationalInterpreterKernelRunIndirectTargets

namespace StageA.RunResolverTargetFailureFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernelRunEndpointReplay
open StageA.Relational.InterpreterNativeWorld

def resolverPe : PE32 := {
  bytes := .empty
  peOffset := 0
  entrypointRva := 0
  imageBase := 4194304
  sectionAlignment := 4096
  fileAlignment := 512
  sizeOfImage := 294912
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{
    virtualSize := 4096
    virtualAddress := 290816
    rawSize := 4096
    rawPointer := 0
    characteristics := 536870912
  }]
}

def resolverEnvironment : NativeWorldEnvironment := {
  action := fun _ _ world => .terminated world
}

def resolverTargets : NativeIndirectTargetInventory := {
  targetSets := [{
    sourceRva := 288484
    transfer := .call
    targets := [.internalRva 290898]
  }]
}

def resolverCandidate : ExactNativeWorldProgram := {
  pe := resolverPe
  imports := []
  environment := resolverEnvironment
  indirectTargets := resolverTargets
}

theorem requiredResolverTargetInventory :
    nativeRunResolverTargetInventoryChecked resolverCandidate 288484
      [290898] = true := by
  decide +kernel

theorem requiredResolverTargetSet :
    exists targetSet,
      resolverCandidate.indirectTargets.targetSet? 288484 .call =
          some targetSet /\\
        targetSet.shapeValid resolverCandidate.pe = true /\\
        targetSet.targets = [.internalRva 290898] := by
  decide +kernel

#print axioms requiredResolverTargetInventory

end StageA.RunResolverTargetFailureFixture
"""
        result = self._compile_fixture(fixture)

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        for match in _AXIOMS.findall(output):
            axioms = {
                item.strip() for item in match.split(",") if item.strip()
            }
            self.assertLessEqual(axioms, _APPROVED_AXIOMS)
        self.assertIn("requiredResolverTargetInventory", output)


if __name__ == "__main__":
    unittest.main()
