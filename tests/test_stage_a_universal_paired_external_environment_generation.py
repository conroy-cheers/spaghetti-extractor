from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.errors import StageAInputError
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
from spaghetti_extractor.relational.lean.universal_paired_external_environment import (
    UNIVERSAL_PAIRED_EXTERNAL_ENVIRONMENT_STATIC_AUTHORITY_MODULE,
    UniversalPairedExternalEnvironmentBindings,
    UniversalPairedExternalEnvironmentStaticAuthorityBindings,
    universal_paired_external_environment_source,
    write_universal_paired_external_environment_source,
)
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from tests.test_stage_a_static_machine_import_contracts import _write_fixture
from tests.test_stage_a_static_machine_import_contracts_kernel import (
    _copy_module_closure,
)


def _bindings() -> UniversalPairedExternalEnvironmentBindings:
    return UniversalPairedExternalEnvironmentBindings(
        original_module="StageA.GeneratedOriginalPE",
        candidate_module="StageA.GeneratedCandidatePE",
        static_import_module="StageA.GeneratedStaticImports",
        original_namespace="StageA.GeneratedOriginal",
        candidate_namespace="StageA.GeneratedCandidate",
        static_import_namespace="StageA.GeneratedStaticImports",
        original_bytes="originalBytes",
        candidate_bytes="candidateBytes",
        original_pe="originalPe",
        candidate_pe="candidatePe",
        original_imports="originalImports",
        candidate_imports="candidateImports",
        original_pe_parsed="originalPeParsed",
        candidate_pe_parsed="candidatePeParsed",
    )


def _static_authority(
) -> UniversalPairedExternalEnvironmentStaticAuthorityBindings:
    return UniversalPairedExternalEnvironmentStaticAuthorityBindings(
        dependency_modules=("StageA.GeneratedStaticAuthorityInputs",),
        context="StageA.GeneratedAuthority.staticProofContext",
        sites="StageA.GeneratedAuthority.externalCallSites",
        candidate_regions="StageA.GeneratedAuthority.candidateRegions",
        candidate_boundaries=(
            "StageA.GeneratedAuthority.candidateMachineImportBoundaries"
        ),
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _machine_import_report(original_sha256: str) -> dict[str, object]:
    return {
        "format": "stage-a-static-machine-import-contracts-v1",
        "status": "ready",
        "inputs": {"original_sha256": original_sha256},
        "counts": {
            "required_reachable_imports": 2,
            "lean_profile_signatures": 2,
            "checked_boundary_proposals": 2,
        },
        "blockers": [],
    }


class StageAUniversalPairedExternalEnvironmentGenerationTests(
    unittest.TestCase
):
    def test_emits_computed_static_authority_and_explicit_responses(self) -> None:
        source = universal_paired_external_environment_source(
            original_sha256="1" * 64,
            candidate_sha256="2" * 64,
            machine_import_report_sha256="3" * 64,
            bindings=_bindings(),
            static_authority=_static_authority(),
        )

        for expected in (
            "import "
            "StageA.RelationalUniversalPairedExternalEnvironmentStaticAuthority",
            "import StageA.GeneratedStaticAuthorityInputs",
            "exactCandidateMachineImportCallRoutesPinned",
            "candidateStaticMachineImportCallRoutesPinned "
            "StageA.GeneratedAuthority.staticProofContext",
            "exactPinnedStaticMachineImportPairBoundToContext",
            "exactExternalCallSiteIdsUnique",
            "exactExternalCallSitesStaticValid",
            "exactUniversalPairedExternalEnvironmentStaticAuthority",
            "exactPinnedUniversalPairedExternalEnvironmentCertificateOfResponses",
            "returningResponses : forall site contract",
            "CheckedUniversalPairedMachineResponse",
        ):
            self.assertIn(expected, source)
        self.assertIn(
            "UniversalPairedExternalEnvironmentStaticAuthority.certificate",
            source,
        )
        self.assertNotIn("WorldExternalEnvironment :=", source)
        self.assertNotIn("def returningResponses", source)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_static_authority_is_opt_in_for_existing_callers(self) -> None:
        source = universal_paired_external_environment_source(
            original_sha256="1" * 64,
            candidate_sha256="2" * 64,
            machine_import_report_sha256="3" * 64,
            bindings=_bindings(),
        )

        self.assertNotIn(
            UNIVERSAL_PAIRED_EXTERNAL_ENVIRONMENT_STATIC_AUTHORITY_MODULE,
            source,
        )
        self.assertNotIn(
            "exactUniversalPairedExternalEnvironmentStaticAuthority", source
        )

    def test_native_interpreter_routes_are_owned_by_mixed_composition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            report = root / "machine-import-report.json"
            original.write_bytes(b"exact original")
            candidate.write_bytes(b"exact candidate")
            report.write_text(
                json.dumps(_machine_import_report(_sha256(original.read_bytes()))),
                encoding="utf-8",
            )
            _, manifest_path = (
                write_universal_paired_external_environment_source(
                    original_pe=original,
                    candidate_pe=candidate,
                    machine_import_report=report,
                    out_dir=root / "out",
                    bindings=_bindings(),
                )
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(manifest["remaining_premises"], [])
        self.assertEqual(
            manifest["route_authority"], "mixed_component_composition"
        )

    def test_manifest_moves_only_computed_static_premises(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            report = root / "machine-import-report.json"
            original.write_bytes(b"exact original")
            candidate.write_bytes(b"exact candidate")
            report.write_text(
                json.dumps(_machine_import_report(_sha256(original.read_bytes()))),
                encoding="utf-8",
            )

            _, manifest_path = (
                write_universal_paired_external_environment_source(
                    original_pe=original,
                    candidate_pe=candidate,
                    machine_import_report=report,
                    out_dir=root / "out",
                    bindings=_bindings(),
                    static_authority=_static_authority(),
                )
            )
            manifest = json.loads(
                manifest_path.read_text(encoding="utf-8")
            )

        self.assertEqual(
            manifest["remaining_premises"],
            [],
        )
        self.assertEqual(
            manifest["route_authority"], "paired_static_context"
        )
        self.assertEqual(
            manifest["conditional_environment_parameters"],
            [
                (
                    "each_returning_site_has_a_universally_sound_"
                    "response_relation"
                ),
                "both_selected_environments_implement_each_response_relation",
                (
                    "protocol_and_callback_actions_have_separate_nested_"
                    "frame_refinement"
                ),
            ],
        )
        for proved in (
            "candidate_exact_call_routes_pinned_to_checked_sites_and_contracts",
            "static_proof_context_bound_to_the_exact_pe_pair",
            "external_call_site_ids_unique",
            "external_call_sites_static_valid",
            "external_call_site_contracts_resolved",
        ):
            self.assertIn(proved, manifest["proved_by_generated_terms"])
        self.assertTrue(
            manifest["authorizing_term"].endswith(
                ".exactUniversalPairedExternalEnvironmentStaticAuthority"
            )
        )
        self.assertFalse(manifest["proof_authority"])

    def test_static_authority_bindings_reject_partial_or_injected_names(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            StageAInputError, "requires dependency modules"
        ):
            UniversalPairedExternalEnvironmentStaticAuthorityBindings(
                dependency_modules=(),
                context="Authority.context",
                sites="Authority.sites",
                candidate_regions="Authority.regions",
                candidate_boundaries="Authority.boundaries",
            )
        with self.assertRaisesRegex(StageAInputError, "must be a Lean name"):
            UniversalPairedExternalEnvironmentStaticAuthorityBindings(
                dependency_modules=("StageA.Authority",),
                context="Authority.context; axiom bad : False",
                sites="Authority.sites",
                candidate_regions="Authority.regions",
                candidate_boundaries="Authority.boundaries",
            )
        with self.assertRaisesRegex(
            StageAInputError, "dependency modules must be unique"
        ):
            UniversalPairedExternalEnvironmentStaticAuthorityBindings(
                dependency_modules=("StageA.Authority", "StageA.Authority"),
                context="Authority.context",
                sites="Authority.sites",
                candidate_regions="Authority.regions",
                candidate_boundaries="Authority.boundaries",
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_static_authority_adapter_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        adapter = (
            "RelationalUniversalPairedExternalEnvironmentStaticAuthority"
        )
        support = (source_root / f"{adapter}.lean").read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", support), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            modules = (
                *RELATIONAL_KERNEL_MODULES,
                "RelationalStaticMachineImportContracts",
                "RelationalUniversalPairedExternalEnvironment",
                adapter,
            )
            for module in dict.fromkeys(modules):
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            result = _run_lean_relational(root, bundle=adapter)

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_generated_static_authority_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _write_fixture(root, via_thunk=False)
            plan = plan_static_machine_import_contracts(
                **fixture.plan_arguments
            )
            self.assertTrue(plan.complete, plan.to_json())
            boundary = plan.boundaries[0]

            lean_root = root / "lean"
            stage_a = lean_root / "StageA"
            stage_a.mkdir(parents=True)
            adapter = (
                "RelationalUniversalPairedExternalEnvironmentStaticAuthority"
            )
            _copy_module_closure(source_root, stage_a, adapter)

            pe_path = Path(fixture.plan_arguments["original_pe"])
            pe_bytes = pe_path.read_bytes()
            binary = _parse_stage_a_pe(pe_path)
            try:
                exact_pe_source = _EXACT_PE_MODULE.format(
                    byte_tree=_lean_byte_tree_definitions(
                        "originalBytes", pe_bytes
                    ),
                    pe_literal=_lean_pe(binary, "originalBytes"),
                    imports_literal=_lean_import_certificate(binary),
                )
            finally:
                binary.pe.close()
            (stage_a / "GeneratedStaticMachineImportFixturePE.lean").write_text(
                exact_pe_source, encoding="utf-8"
            )

            generated_static, _ = write_static_machine_import_contracts(
                root / "static", plan, fixture.bindings
            )
            shutil.copyfile(
                generated_static,
                stage_a / "GeneratedStaticMachineImportContracts.lean",
            )
            authority_module = "GeneratedUniversalStaticAuthorityInputs"
            (stage_a / f"{authority_module}.lean").write_text(
                _AUTHORITY_INPUTS_MODULE.format(
                    source_rva=boundary.execution_source_rva,
                    continuation_rva=boundary.continuation_rva,
                    region_stop=(
                        boundary.execution_source_rva + boundary.source_size
                    ),
                ),
                encoding="utf-8",
            )

            bindings = UniversalPairedExternalEnvironmentBindings(
                original_module=(
                    "StageA.GeneratedStaticMachineImportFixturePE"
                ),
                candidate_module=(
                    "StageA.GeneratedStaticMachineImportFixturePE"
                ),
                static_import_module=(
                    "StageA.GeneratedStaticMachineImportContracts"
                ),
                original_namespace=(
                    "StageA.Generated.StaticMachineImportFixturePE"
                ),
                candidate_namespace=(
                    "StageA.Generated.StaticMachineImportFixturePE"
                ),
                static_import_namespace=(
                    "StageA.GeneratedRelational.StaticMachineImports"
                ),
                original_bytes="originalBytes",
                candidate_bytes="originalBytes",
                original_pe="originalPe",
                candidate_pe="originalPe",
                original_imports="originalImports",
                candidate_imports="originalImports",
                original_pe_parsed="originalPeParsed",
                candidate_pe_parsed="originalPeParsed",
            )
            static_authority = (
                UniversalPairedExternalEnvironmentStaticAuthorityBindings(
                    dependency_modules=(
                        f"StageA.{authority_module}",
                    ),
                    context="StageA.Generated.Authority.staticProofContext",
                    sites="StageA.Generated.Authority.externalCallSites",
                    candidate_regions=(
                        "StageA.Generated.Authority.candidateRegions"
                    ),
                    candidate_boundaries=(
                        "StageA.Generated.Authority."
                        "candidateMachineImportBoundaries"
                    ),
                )
            )
            generated_module = "GeneratedUniversalStaticAuthority"
            (stage_a / f"{generated_module}.lean").write_text(
                universal_paired_external_environment_source(
                    original_sha256="1" * 64,
                    candidate_sha256="1" * 64,
                    machine_import_report_sha256="2" * 64,
                    bindings=bindings,
                    static_authority=static_authority,
                ),
                encoding="utf-8",
            )
            result = _run_lean_relational(
                lean_root, bundle=generated_module
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])

_EXACT_PE_MODULE = r"""import StageA.Formal

namespace StageA.Generated.StaticMachineImportFixturePE

open StageA.Formal

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{byte_tree}

def originalPe : PE32 := {pe_literal}

def originalImportCertificate : ImportTableCertificate := {imports_literal}

def originalImports : List PEImport := originalImportCertificate.imports

theorem originalPeParsed :
    parsePE32Tree originalBytes = some originalPe := by
  decide

end StageA.Generated.StaticMachineImportFixturePE
"""


_AUTHORITY_INPUTS_MODULE = r"""import StageA.GeneratedStaticMachineImportContracts
import StageA.RelationalUniversalPairedExternalEnvironmentStaticAuthority

namespace StageA.Generated.Authority

open StageA.Formal StageA.Relational
open StageA.Relational.StaticMachineImportContracts
open StageA.Relational.UniversalPairedExternalEnvironmentStaticAuthority
open StageA.GeneratedRelational.StaticMachineImports

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def codeMap : StaticCodeMap := {{
  entries := .leaf [
    {{ id := 0, regionIndex := 0, originalRva := {source_rva},
      candidateRva := {source_rva} }},
    {{ id := 1, regionIndex := 0, originalRva := {continuation_rva},
      candidateRva := {continuation_rva} }}
  ]
  originalAddresses := .leaf [
    {{ targetId := 0, kind := .canonical }},
    {{ targetId := 1, kind := .canonical }}
  ]
  candidateAddresses := .leaf [
    {{ targetId := 0, kind := .canonical }},
    {{ targetId := 1, kind := .canonical }}
  ]
}}

def staticProofContext : StaticProofContext := {{
  originalPe := StageA.Generated.StaticMachineImportFixturePE.originalPe
  candidatePe := StageA.Generated.StaticMachineImportFixturePE.originalPe
  originalImportCertificate :=
    StageA.Generated.StaticMachineImportFixturePE.originalImportCertificate
  candidateImportCertificate :=
    StageA.Generated.StaticMachineImportFixturePE.originalImportCertificate
  originalRelocations := []
  candidateRelocations := []
  codeMap := codeMap
  dataMap := {{ entries := #[], originalOrder := [], candidateOrder := [] }}
  roots := []
  observations := {{}}
  machineImportCallContracts := generatedMachineImportBoundaryContracts
}}

def candidateRegions : List RegionRelation := [{{
  id := 0
  original := {{ start := {source_rva}, size := {region_stop} - {source_rva} }}
  candidate := {{ start := {source_rva}, size := {region_stop} - {source_rva} }}
  root := false
  inputs := []
  outputs := []
  targets := []
}}]

def externalCallSites : List ExternalCallSiteContract := [{{
  id := 0
  sourceTargetId := 0
  continuationTargetId := 1
  machineContractId := 0
  boundaryInvariant := {{ registerRelations := [] }}
  targetInvariant := {{ registerRelations := [] }}
}}]

def candidateMachineImportBoundaries : List StaticMachineImportBoundary :=
  generatedMachineImportBoundaries

def wrongCandidateMachineImportBoundaries : List StaticMachineImportBoundary :=
  generatedMachineImportBoundaries.map fun boundary =>
    {{ boundary with continuationRva := boundary.continuationRva + 1 }}

theorem wrongCandidateMachineImportBoundariesRejected :
    candidateStaticMachineImportCallRoutesPinned staticProofContext
      candidateRegions generatedMachineImportSignatures
      wrongCandidateMachineImportBoundaries externalCallSites = false := by
  decide

#print axioms wrongCandidateMachineImportBoundariesRejected

end StageA.Generated.Authority
"""


if __name__ == "__main__":
    unittest.main()
