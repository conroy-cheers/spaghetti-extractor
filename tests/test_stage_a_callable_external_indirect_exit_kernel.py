from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_callable_external_capability_kernel import (
    _copy_module_closure,
)


_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageACallableExternalIndirectExitKernelTests(unittest.TestCase):
    def test_mixed_internal_callable_route_is_kernel_checked(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        layer = (
            source_root / "RelationalCallableExternalIndirectExit.lean"
        ).read_text(encoding="utf-8")
        for marker in ("native_decide", "sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", layer), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalCallableExternalIndirectExit"
            )
            (stage_a / "CallableExternalIndirectExitKernel.lean").write_text(
                _KERNEL_SOURCE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="CallableExternalIndirectExitKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 2, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)

    def test_memory_route_rejects_missing_origin_relation(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalCallableExternalIndirectExit"
            )
            (stage_a / "CallableExternalIndirectExitRejected.lean").write_text(
                _REJECTED_KERNEL_SOURCE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="CallableExternalIndirectExitRejected"
            )

        self.assertEqual(result["status"], "failed", result)
        output = result["stdout"] + result["stderr"]
        self.assertIn("unsolved goals", output)


_KERNEL_SOURCE = r"""import StageA.RelationalCallableExternalIndirectExit

open StageA.Relational
open StageA.Relational.CallableExternalIndirectExit

#check CallableIndirectRuntimeSelection.internal
#check CallableIndirectRuntimeSelection.callable
#check CallableIndirectRuntimeResolution.of_targetOrigin
#check CallableIndirectRuntimeResolution.of_registerOrigin
#check CallableIndirectRuntimeResolution.of_memoryOrigin
#check CallableIndirectRuntimeResolution.of_staticWordOrigin
#print axioms CallableIndirectRuntimeResolution.of_memoryOrigin
#print axioms CallableIndirectRuntimeResolution.of_registerOrigin
#print axioms CallableIndirectRuntimeResolution.of_staticWordOrigin
#print axioms CallableIndirectRuntimeResolution.targetEvaluation
#print axioms CheckedCallableIndirectExitCertificate.generic

def memoryAddress : StageA.Formal.Expr := .constant 0x1000

def memoryRoute : CallableIndirectExitRoute := {
  externalRoutes := []
  originalTarget := .read32 memoryAddress
  candidateTarget := .read32 memoryAddress
  source := .staticWord 0
  transfer := .jump
  internalTargetIds := [0]
}

def memoryInvariant : StateInvariant := {
  registerRelations := []
  memoryValueOriginRelations := [
    memoryRoute.memoryOriginRelation memoryAddress memoryAddress
  ]
}

def memoryBinding :
    CallableIndirectMemoryOriginBinding memoryRoute memoryInvariant := {
  originalAddress := memoryAddress
  candidateAddress := memoryAddress
  originalTarget := rfl
  candidateTarget := rfl
  relationMember := by simp [memoryInvariant]
}

def staticWordSlot : StaticWordRelationSlotPair := {
  id := 0
  originalAddress := 0x1000
  candidateAddress := 0x1000
  relation := .finiteOrigins 1 [.staticCodeTarget 0 0]
}

def staticWordRoute : CallableIndirectExitRoute := {
  externalRoutes := []
  originalTarget := .read32 (.constant staticWordSlot.originalAddress.toNat)
  candidateTarget := .read32 (.constant staticWordSlot.candidateAddress.toNat)
  source := .staticWord staticWordSlot.id
  transfer := .jump
  internalTargetIds := [0]
}

def staticWordProgram
    (program :
      StageA.Relational.CallableExternalExecution.OriginalCallableProgram)
    (member : staticWordSlot ∈ program.context.staticWordRelationSlots) :
    CallableIndirectStaticWordOriginBinding program staticWordRoute := {
  slot := staticWordSlot
  slotMember := member
  source := rfl
  originalTarget := rfl
  candidateTarget := rfl
  relation := rfl
}
"""


_REJECTED_KERNEL_SOURCE = r"""import StageA.RelationalCallableExternalIndirectExit

open StageA.Relational
open StageA.Relational.CallableExternalIndirectExit

def memoryAddress : StageA.Formal.Expr := .constant 0x1000

def memoryRoute : CallableIndirectExitRoute := {
  externalRoutes := []
  originalTarget := .read32 memoryAddress
  candidateTarget := .read32 memoryAddress
  source := .staticWord 0
  transfer := .jump
  internalTargetIds := [0]
}

def missingMemoryInvariant : StateInvariant := {
  registerRelations := []
}

def rejectedMemoryBinding :
    CallableIndirectMemoryOriginBinding memoryRoute missingMemoryInvariant := {
  originalAddress := memoryAddress
  candidateAddress := memoryAddress
  originalTarget := rfl
  candidateTarget := rfl
  relationMember := by simp [missingMemoryInvariant]
}
"""
