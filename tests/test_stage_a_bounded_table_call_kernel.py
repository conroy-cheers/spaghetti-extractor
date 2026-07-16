from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.executor import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES


class StageABoundedTableCallKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel proofs")
    def test_bounded_immutable_table_call_certificate_is_kernel_checked(self) -> None:
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
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )

            (stage_a / "BoundedTableCallKernel.lean").write_text(
                """import StageA.RelationalComposition

namespace StageA.BoundedTableCallKernel

open StageA.Formal StageA.Relational

def duplicateTargetRows : BoundedImmutableCodePointerTableCallClaim := {
  valueTargetId := 0
  tableOffset := 0
  originalBase := 4096
  candidateBase := 8192
  upperExclusive := 2
  originalIndexRegister := .eax
  candidateIndexRegister := .ecx
  continuationTargetId := 1
  rows := [
    { index := 0, targetId := 7 },
    { index := 1, targetId := 7 }
  ]
}

def missingRowClaim : BoundedImmutableCodePointerTableCallClaim := {
  valueTargetId := 0
  tableOffset := 0
  originalBase := 4096
  candidateBase := 8192
  upperExclusive := 2
  originalIndexRegister := .eax
  candidateIndexRegister := .ecx
  continuationTargetId := 1
  rows := [{ index := 0, targetId := 7 }]
}

example : immutableCodePointerTableRowsUnique duplicateTargetRows = false := by
  decide

example : immutableCodePointerTableRowsCover missingRowClaim = false := by
  decide

example (context : StaticProofContext)
    (claim : BoundedImmutableCodePointerTableCallClaim)
    (row : ImmutableCodePointerTableRow)
    (missing : context.codeMap.get? row.targetId = none) :
    row.checked context claim = false := by
  simp [ImmutableCodePointerTableRow.checked, missing]

example (context : StaticProofContext) (invariant : StateInvariant)
    (claim : BoundedImmutableCodePointerTableCallClaim)
    (zero : claim.upperExclusive = 0) :
    claim.shapeChecked context invariant = false := by
  unfold BoundedImmutableCodePointerTableCallClaim.shapeChecked
  rw [zero]
  cases context.dataMap.get? claim.valueTargetId <;>
    cases context.codeMap.get? claim.continuationTargetId <;> simp

example (context : StaticProofContext) (invariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableCodePointerTableCallClaim)
    (structurallyValid : context.StructurallyValid)
    (checked : claim.checked context invariant originalBehavior candidateBehavior = true) :
    BoundedImmutableCodePointerTableCallTargetsClosed context invariant
      originalBehavior candidateBehavior claim :=
  boundedImmutableCodePointerTableCallTargetsClosed_of_checked context invariant
    originalBehavior candidateBehavior claim structurallyValid checked

example (graph : RelationalProductGraph) (nodeId : Nat)
    (context : StaticProofContext) (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableCodePointerTableCallClaim)
    (structurallyValid : context.StructurallyValid)
    (originalDecoded :
      regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
        context.machineImportCallContracts region.original = some originalBehavior)
    (candidateDecoded :
      regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
        context.machineImportCallContracts region.candidate = some candidateBehavior)
    (originalNormalizedChecked :
      normalizeSymbolicBehavior false region.targets originalBehavior =
        some originalNormalized)
    (candidateNormalizedChecked :
      normalizeSymbolicBehavior true region.targets candidateBehavior =
        some candidateNormalized)
    (claimChecked : claim.checked context region.inputInvariant originalNormalized
      candidateNormalized = true)
    (edgesChecked :
      boundedImmutableCodePointerTableCallEdgesMatch graph nodeId claim = true) :
    NodeBoundedImmutableCodePointerTableCallEdgesComplete graph nodeId context region
      originalBehavior candidateBehavior originalNormalized candidateNormalized claim :=
  nodeBoundedImmutableCodePointerTableCallEdgesComplete_of_checked graph nodeId context
    region originalBehavior candidateBehavior originalNormalized candidateNormalized claim
    structurallyValid originalDecoded candidateDecoded originalNormalizedChecked
    candidateNormalizedChecked claimChecked edgesChecked

#print axioms boundedImmutableCodePointerTableCallTargetsClosed_of_checked
#print axioms nodeBoundedImmutableCodePointerTableCallEdgesComplete_of_checked

end StageA.BoundedTableCallKernel
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir, bundle="BoundedTableCallKernel"
            )
            self.assertEqual(result["status"], "checked", result)
            self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
