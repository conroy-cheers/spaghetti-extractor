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


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARelationalBoundaryContractSelectionKernelTests(unittest.TestCase):
    def test_selection_is_continuation_sensitive_and_fail_closed(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(source_root, stage_a, "RelationalCertificates")
            (stage_a / "RelationalBoundaryContractSelectionKernel.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalBoundaryContractSelectionKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)


_KERNEL_FIXTURE = r"""import StageA.RelationalCertificates

namespace StageA.Relational.BoundaryContractSelectionKernel

open StageA.Formal StageA.Relational

def contractAt (base : MachineImportCallContract) (id : Nat) :
    MachineImportCallContract :=
  { base with id }

def siteAt (invariant : StateInvariant) (id source continuation contractId : Nat) :
    ExternalCallSiteContract := {
  id
  sourceTargetId := source
  continuationTargetId := continuation
  machineContractId := contractId
  boundaryInvariant := invariant
  targetInvariant := invariant
}

def programAt (base : DecodedWorldProgram)
    (contracts : List MachineImportCallContract)
    (sites : List ExternalCallSiteContract) : DecodedWorldProgram :=
  { base with
    context := { base.context with machineImportCallContracts := contracts }
    externalCallSites := sites
  }

example (base : DecodedWorldProgram) (contract : MachineImportCallContract)
    (invariant : StateInvariant) :
    DecodedWorldProgram.machineImportContractsAt
      (programAt base [contractAt contract 10] [siteAt invariant 0 7 100 10])
      7 [] = [contractAt contract 10] := by
  simp [programAt, DecodedWorldProgram.machineImportContractsAt, siteAt,
    contractAt, machineImportCallContractById?]

example (base : DecodedWorldProgram) (first second : MachineImportCallContract)
    (invariant : StateInvariant) :
    DecodedWorldProgram.machineImportContractsAt
      (programAt base [contractAt first 10, contractAt second 11]
        [siteAt invariant 0 7 100 10, siteAt invariant 1 7 200 11])
      7 [200] = [contractAt second 11] := by
  simp [programAt, DecodedWorldProgram.machineImportContractsAt, siteAt,
    contractAt, machineImportCallContractById?]

example (base : DecodedWorldProgram) (first second : MachineImportCallContract)
    (invariant : StateInvariant) :
    DecodedWorldProgram.machineImportContractsAt
      (programAt base [contractAt first 10, contractAt second 11]
        [siteAt invariant 0 7 100 10, siteAt invariant 1 7 200 11])
      7 [] = [] := by
  simp [programAt, DecodedWorldProgram.machineImportContractsAt, siteAt,
    contractAt, machineImportCallContractById?]

example (base : DecodedWorldProgram) (first second : MachineImportCallContract)
    (invariant : StateInvariant) :
    DecodedWorldProgram.machineImportContractsAt
      (programAt base [contractAt first 10, contractAt second 11]
        [siteAt invariant 0 7 100 10, siteAt invariant 1 7 100 11])
      7 [100] = [] := by
  simp [programAt, DecodedWorldProgram.machineImportContractsAt, siteAt,
    contractAt, machineImportCallContractById?]

example (base : DecodedWorldProgram) (contract : MachineImportCallContract)
    (invariant : StateInvariant) :
    DecodedWorldProgram.machineImportContractsAt
      (programAt base [contractAt contract 10] [siteAt invariant 0 7 100 99])
      7 [] = [] := by
  simp [programAt, DecodedWorldProgram.machineImportContractsAt, siteAt,
    contractAt, machineImportCallContractById?]

end StageA.Relational.BoundaryContractSelectionKernel
"""


if __name__ == "__main__":
    unittest.main()
