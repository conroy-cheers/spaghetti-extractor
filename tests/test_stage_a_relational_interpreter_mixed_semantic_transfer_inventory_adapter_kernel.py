from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_LINE = re.compile(r"depends on axioms: \[([^\]]*)\]", re.MULTILINE)
_MODULE = "RelationalInterpreterMixedSemanticTransferInventoryAdapter"


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


class StageARelationalInterpreterMixedSemanticTransferInventoryAdapterKernelTests(
    unittest.TestCase
):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_inventory_adapter_compiles_and_retains_exact_authority(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(source_root, stage_a, _MODULE)
            (stage_a / "MixedSemanticTransferInventoryAdapterExamples.lean").write_text(
                _EXAMPLES,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="MixedSemanticTransferInventoryAdapterExamples",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn("native_decide.ax", output)
        for declaration in (
            "ExactOriginalTransferInventorySelection.inventoryRefinementAt",
            "ExactOriginalTransferInventorySelection.toSemanticTransferBinding",
            "ExactOriginalTransferInventorySelection.bindingRecordExact",
            "ExactOriginalTransferInventorySelection.bindingSourceRvaExact",
            "ExactOriginalTransferInventorySelection.bindingRegionStopExact",
            "inventoryAuthorityRetained",
            "normalizationAuthorityReused",
        ):
            self.assertIn(declaration, output)

        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip()
                for item in match.group(1).split(",")
                if item.strip()
            )
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


_EXAMPLES = r"""import StageA.RelationalInterpreterMixedSemanticTransferInventoryAdapter

namespace StageA.MixedSemanticTransferInventoryAdapterExamples

open StageA.Relational
open StageA.Relational.InterpreterAcceptance
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterMixedSemanticOperationComponent
open StageA.Relational.InterpreterMixedSemanticTransferInventoryAdapter

theorem inventoryAuthorityRetained
    (selection : ExactOriginalTransferInventorySelection acceptanceContext inventory
      context authority launch root reachability candidate candidateAuthority source) :
    ExactOriginalTransferRefinementAt acceptanceContext
      source.source.target.rva :=
  selection.inventoryRefinementAt

def exactBinding
    (selection : ExactOriginalTransferInventorySelection acceptanceContext inventory
      context authority launch root reachability candidate candidateAuthority source) :
    ExactOriginalSemanticTransferBinding context authority launch root reachability
      candidate candidateAuthority source :=
  selection.toSemanticTransferBinding

theorem normalizationAuthorityReused
    (selection : ExactOriginalTransferInventorySelection acceptanceContext inventory
      context authority launch root reachability candidate candidateAuthority source) :
    ExactProgramRecordNormalizationCertificate context.pe
      selection.toSemanticTransferBinding.path
      selection.toSemanticTransferBinding.transfer :=
  selection.toSemanticTransferBinding.normalization

theorem exactSourceRecordRetained
    (selection : ExactOriginalTransferInventorySelection acceptanceContext inventory
      context authority launch root reachability candidate candidateAuthority source) :
    selection.toSemanticTransferBinding.path.record = source.record :=
  selection.bindingRecordExact

theorem exactSourceRvaRetained
    (selection : ExactOriginalTransferInventorySelection acceptanceContext inventory
      context authority launch root reachability candidate candidateAuthority source) :
    selection.toSemanticTransferBinding.path.sourceRva =
      source.source.target.rva :=
  selection.bindingSourceRvaExact

theorem exactRegionStopRetained
    (selection : ExactOriginalTransferInventorySelection acceptanceContext inventory
      context authority launch root reachability candidate candidateAuthority source) :
    selection.toSemanticTransferBinding.path.stopRva =
      source.source.region.span.stop :=
  selection.bindingRegionStopExact

#print axioms ExactOriginalTransferInventorySelection.inventoryRefinementAt
#print axioms ExactOriginalTransferInventorySelection.toSemanticTransferBinding
#print axioms ExactOriginalTransferInventorySelection.bindingRecordExact
#print axioms ExactOriginalTransferInventorySelection.bindingSourceRvaExact
#print axioms ExactOriginalTransferInventorySelection.bindingRegionStopExact
#print axioms inventoryAuthorityRetained
#print axioms normalizationAuthorityReused
#print axioms exactSourceRecordRetained
#print axioms exactSourceRvaRetained
#print axioms exactRegionStopRetained

end StageA.MixedSemanticTransferInventoryAdapterExamples
"""


if __name__ == "__main__":
    unittest.main()
