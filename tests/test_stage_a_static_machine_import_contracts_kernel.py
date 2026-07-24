from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.common import (
    _lean_byte_tree_definitions,
    _lean_import_certificate,
    _lean_pe,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.static_machine_import_contracts import (
    plan_static_machine_import_contracts,
    write_static_machine_import_contracts,
)
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from tests.test_stage_a_static_machine_import_contracts import _write_fixture


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound"}


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
class StageAStaticMachineImportContractsKernelTests(unittest.TestCase):
    def test_generated_register_iat_contract_rechecks_exact_pe_bytes(self) -> None:
        result = self._compile_generated(register_indirect=True)
        self._assert_approved(result)

    def test_generated_cross_region_register_iat_contract_rechecks_span(self) -> None:
        result = self._compile_generated(
            register_indirect=True, split_register_seed=True
        )
        self._assert_approved(result)

    def test_generated_restored_register_iat_contract_rechecks_all_spans(self) -> None:
        result = self._compile_generated(restored_register_call=True)
        self._assert_approved(result)

    def test_generated_caller_thunk_contract_rechecks_both_exact_spans(self) -> None:
        result = self._compile_generated(via_thunk=True)
        self._assert_approved(result)

    def test_generated_variadic_boundary_inventory_is_checked_per_site(self) -> None:
        result = self._compile_generated(via_thunk=True, variadic=True)
        self._assert_approved(result)

    def test_generated_nested_protocol_boundary_is_checked_per_site(self) -> None:
        result = self._compile_generated(nested=True)
        self._assert_approved(result)

    def test_generated_framed_external_tail_rechecks_caller_and_tail(self) -> None:
        result = self._compile_generated(framed_tail=True)
        self._assert_approved(result)

    def test_generated_framed_thunk_tail_rechecks_all_exact_spans(self) -> None:
        result = self._compile_generated(via_thunk=True, framed_tail=True)
        self._assert_approved(result)

    def test_boundary_site_projection_checks_source_and_continuation_rvas(self) -> None:
        result = self._compile_generated(site_projection=True)
        self._assert_approved(result)

    def _compile_generated(
        self,
        *,
        via_thunk: bool = False,
        register_indirect: bool = False,
        split_register_seed: bool = False,
        variadic: bool = False,
        nested: bool = False,
        site_projection: bool = False,
        framed_tail: bool = False,
        restored_register_call: bool = False,
    ) -> dict:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _write_fixture(
                root,
                via_thunk=via_thunk,
                register_indirect=register_indirect,
                split_register_seed=split_register_seed,
                variadic=variadic,
                nested=nested,
                framed_tail=framed_tail,
                restored_register_call=restored_register_call,
            )
            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)
            self.assertTrue(plan.complete, plan.to_json())

            stage_a = root / "lean" / "StageA"
            stage_a.mkdir(parents=True)
            _copy_module_closure(
                source_root, stage_a, "RelationalStaticMachineImportContracts"
            )
            pe_path = fixture.plan_arguments["original_pe"]
            pe_bytes = Path(pe_path).read_bytes()
            binary = _parse_stage_a_pe(Path(pe_path))
            try:
                original_source = _EXACT_PE_MODULE.format(
                    byte_tree=_lean_byte_tree_definitions(
                        "originalBytes", pe_bytes
                    ),
                    pe_literal=_lean_pe(binary, "originalBytes"),
                    imports_literal=_lean_import_certificate(binary),
                )
            finally:
                binary.pe.close()
            (stage_a / "GeneratedStaticMachineImportFixturePE.lean").write_text(
                original_source, encoding="utf-8"
            )
            generated_root = root / "generated"
            generated, _report = write_static_machine_import_contracts(
                generated_root, plan, fixture.bindings
            )
            shutil.copyfile(
                generated, stage_a / "GeneratedStaticMachineImportContracts.lean"
            )
            bundle = "GeneratedStaticMachineImportContracts"
            if site_projection:
                boundary = plan.boundaries[0]
                target_rows = sorted((
                    (boundary.execution_source_rva, 0),
                    (boundary.continuation_rva, 1),
                ))
                addresses = ",\n    ".join(
                    f"{{ targetId := {target_id}, kind := .canonical }}"
                    for _rva, target_id in target_rows
                )
                (stage_a / "GeneratedStaticMachineImportSiteProjection.lean").write_text(
                    _SITE_PROJECTION_MODULE.format(
                        source_rva=boundary.execution_source_rva,
                        continuation_rva=boundary.continuation_rva,
                        addresses=addresses,
                    ),
                    encoding="utf-8",
                )
                bundle = "GeneratedStaticMachineImportSiteProjection"
            result = _run_lean_relational(
                root / "lean", bundle=bundle
            )
        return result

    def _assert_approved(self, result: dict) -> None:
        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 2, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


_EXACT_PE_MODULE = r"""import StageA.Formal

namespace StageA.Generated.StaticMachineImportFixturePE

open StageA.Formal

{byte_tree}

def originalPe : PE32 := {pe_literal}

def originalImportCertificate : ImportTableCertificate := {imports_literal}

end StageA.Generated.StaticMachineImportFixturePE
"""


_SITE_PROJECTION_MODULE = r"""import StageA.GeneratedStaticMachineImportContracts

namespace StageA.Generated.StaticMachineImportSiteProjection

open StageA.Formal StageA.Relational
open StageA.Relational.StaticMachineImportContracts
open StageA.GeneratedRelational.StaticMachineImports

def siteCodeMap : StaticCodeMap := {{
  entries := .leaf [
    {{ id := 0, originalRva := {source_rva}, candidateRva := {source_rva} }},
    {{ id := 1, originalRva := {continuation_rva}, candidateRva := {continuation_rva} }}
  ]
  originalAddresses := .leaf [
    {addresses}
  ]
  candidateAddresses := .leaf [
    {addresses}
  ]
}}

def siteContext : StaticProofContext := {{
  originalPe := StageA.Generated.StaticMachineImportFixturePE.originalPe
  candidatePe := StageA.Generated.StaticMachineImportFixturePE.originalPe
  originalImportCertificate :=
    StageA.Generated.StaticMachineImportFixturePE.originalImportCertificate
  candidateImportCertificate :=
    StageA.Generated.StaticMachineImportFixturePE.originalImportCertificate
  originalRelocations := []
  candidateRelocations := []
  codeMap := siteCodeMap
  dataMap := {{ entries := #[], originalOrder := [], candidateOrder := [] }}
  roots := []
  observations := {{}}
  machineImportCallContracts := generatedMachineImportBoundaryContracts
}}

def siteRegions : List RegionRelation := [{{
  id := 0
  original := {{ start := {source_rva}, size := {continuation_rva} - {source_rva} }}
  candidate := {{ start := {source_rva}, size := {continuation_rva} - {source_rva} }}
  root := false
  inputs := []
  outputs := []
  targets := []
}}]

def siteBindings : List StaticMachineImportBoundarySiteBinding := [{{
  boundaryId := 0
  sourceTargetId := 0
  continuationTargetId := 1
  boundaryInvariant := {{ registerRelations := [] }}
  targetInvariant := {{ registerRelations := [] }}
}}]

def wrongSiteBindings : List StaticMachineImportBoundarySiteBinding := [{{
  boundaryId := 0
  sourceTargetId := 0
  continuationTargetId := 0
  boundaryInvariant := {{ registerRelations := [] }}
  targetInvariant := {{ registerRelations := [] }}
}}]

theorem siteBindingsChecked : staticMachineImportBoundarySiteBindingsValid siteContext
    siteRegions
    generatedMachineImportBoundaries generatedMachineImportBoundaryCallContracts
    siteBindings = true := by decide

theorem wrongSiteBindingsRejected : staticMachineImportBoundarySiteBindingsValid siteContext
    siteRegions
    generatedMachineImportBoundaries generatedMachineImportBoundaryCallContracts
    wrongSiteBindings = false := by decide

#print axioms siteBindingsChecked
#print axioms wrongSiteBindingsRejected

end StageA.Generated.StaticMachineImportSiteProjection
"""


if __name__ == "__main__":
    unittest.main()
