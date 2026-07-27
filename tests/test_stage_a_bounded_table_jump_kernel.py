from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES


class StageABoundedTableJumpKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel proofs")
    def test_bounded_relocation_table_jump_certificate_is_kernel_checked(self) -> None:
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

            (stage_a / "BoundedTableJumpKernel.lean").write_text(
                """import StageA.RelationalComposition

namespace StageA.BoundedTableJumpKernel

open StageA.Formal StageA.Relational

def registerIndexClaim : BoundedImmutableRelocationTableJumpControlClaim := {
  table := {
    valueTargetId := 0
    tableOffset := 0
    originalBase := 4096
    candidateBase := 8192
    upperExclusive := 2
    originalIndex := .bitAnd (.inputReg .eax) (.constant 255)
    candidateIndex := .bitAnd (.inputReg .ecx) (.constant 255)
    entryTargetIds := [1, 2]
    finiteTargetIds := [1, 2]
  }
  indexWitness := .binary .bitAnd (.inputReg .eax .ecx) (.constant 255)
  indexBound := {
    original := .eax
    candidate := .ecx
    originalExpression := some (.bitAnd (.inputReg .eax) (.constant 255))
    candidateExpression := some (.bitAnd (.inputReg .ecx) (.constant 255))
    upperExclusive := 2
  }
}

example : tableJumpIndexInvariant registerIndexClaim.table.originalIndex = true := by
  decide

example : registerIndexClaim.indexWitness.expression .original =
    registerIndexClaim.table.originalIndex := by
  decide

example : tableJumpIndexInvariant (.read32 (.inputReg .esp)) = false := by
  decide

example : pe32RelocationWordAt [{ rva := 16, kind := 3 }] 16 = true := by
  decide

example : pe32RelocationWordAt [] 16 = false := by
  decide

example : pe32RelocationWordAt [
    { rva := 16, kind := 3 }, { rva := 16, kind := 3 }
  ] 16 = false := by
  decide

example (context : StaticProofContext) (invariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableRelocationTableJumpControlClaim)
    (structurallyValid : context.StructurallyValid)
    (checked : claim.checked context invariant originalBehavior candidateBehavior = true) :
    BoundedImmutableRelocationTableJumpTargetsClosed context invariant
      originalBehavior candidateBehavior claim :=
  boundedImmutableRelocationTableJumpTargetsClosed_of_checked context invariant
    originalBehavior candidateBehavior claim structurallyValid checked

example (graph : RelationalProductGraph) (nodeId : Nat)
    (context : StaticProofContext) (region : RegionRelation)
    (originalBehavior candidateBehavior : SymbolicBehavior)
    (originalNormalized candidateNormalized : NormalizedSymbolicBehavior)
    (claim : BoundedImmutableRelocationTableJumpControlClaim)
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
      boundedImmutableRelocationTableJumpEdgesMatch graph nodeId context claim = true) :
    NodeBoundedImmutableRelocationTableJumpEdgesComplete graph nodeId context region
      originalBehavior candidateBehavior originalNormalized candidateNormalized claim :=
  nodeBoundedImmutableRelocationTableJumpEdgesComplete_of_checked graph nodeId context
    region originalBehavior candidateBehavior originalNormalized candidateNormalized claim
    structurallyValid originalDecoded candidateDecoded originalNormalizedChecked
    candidateNormalizedChecked claimChecked edgesChecked

#print axioms boundedImmutableRelocationTableJumpTargetsClosed_of_checked
#print axioms nodeBoundedImmutableRelocationTableJumpEdgesComplete_of_checked

end StageA.BoundedTableJumpKernel
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir, bundle="BoundedTableJumpKernel"
            )
            self.assertEqual(result["status"], "checked", result)
            self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
