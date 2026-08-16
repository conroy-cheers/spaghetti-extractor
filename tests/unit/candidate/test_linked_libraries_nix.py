from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class LinkedLibrariesNixTests(unittest.TestCase):
    def test_catalog_pack_is_immutable_content_addressed_and_target_neutral(self) -> None:
        module = (ROOT / "nix" / "library-catalog-pack.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("__contentAddressed = true;", module)
        self.assertIn("spaghetti-extractor-library-artifact-inputs-v2", module)
        self.assertIn("bind_library_artifact_inputs", module)
        self.assertIn("index_library_artifacts", module)
        self.assertIn("abiCatalog ? null", module)
        self.assertIn("implementations ? { }", module)
        self.assertIn("LIBRARY_ABI_CATALOG_CODEC_V3.read", module)
        self.assertIn("read_library_behavior_pack_declaration_v1", module)
        self.assertIn("behavior-packs", module)
        self.assertIn("library-abi-catalog.json", module)
        self.assertNotIn("gnu-hello", module)
        self.assertNotIn("wine", module.lower())

    def test_operator_status_and_check_are_separate_from_recognition(self) -> None:
        module = (ROOT / "nix" / "library-status.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("build_library_status_v4", module)
        self.assertIn("identity_match_authorizes_replacement", module)
        self.assertIn("operator_adoption_authorizes_replacement", module)
        self.assertIn("checked_island_receipt_required", module)
        self.assertIn("handwritten_behavior_tests_required", module)

    def test_generic_dag_is_static_content_addressed_and_phase_split(self) -> None:
        module = (ROOT / "nix" / "linked-libraries.nix").read_text(encoding="utf-8")
        for phase in (
            "artifactIndex",
            "generatedCatalogLock",
            "targetSignatureGraph",
            "catalogSearchIndex",
            "releaseHypotheses",
            "checkedIslands",
            "generatedComponents",
            "checks",
        ):
            self.assertIn(phase, module)
        self.assertIn("__contentAddressed = true;", module)
        self.assertIn("index_library_artifacts", module)
        self.assertIn("build_target_signature_graph", module)
        self.assertIn("build_catalog_search_index", module)
        self.assertIn("solve_library_release_hypotheses", module)
        self.assertIn("./library-island-check.nix", module)
        self.assertIn("./library-component-generation.nix", module)
        self.assertNotIn("check_library_island_v1", module)
        self.assertNotIn("build_checked_library_component_v1", module)
        self.assertIn('mkPhaseSource "target-signature"', module)
        self.assertIn('mkPhaseSource "catalog-search"', module)
        self.assertIn('mkPhaseSource "release-hypotheses"', module)
        self.assertNotIn("linked-libraries-python-closure", module)
        generic_binding = (
            ROOT / "src" / "spaghetti_extractor" / "components" / "machine_binding.py"
        ).read_text(encoding="utf-8")
        library_binding = (
            ROOT / "src" / "spaghetti_extractor" / "libraries" / "v4_component.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("checked_library_island", generic_binding)
        self.assertIn("CHECKED_LIBRARY_ISLAND_CODEC_V1", library_binding)
        for legacy_phase in (
            "matchEvidence",
            "libraryHypotheses",
            "dynamicRequirements",
            "linkedIslands",
            "interfaceQualification",
            "replacementPlan",
            "propose_library_match_evidence",
            "infer_library_hypotheses",
            "qualify_linked_interfaces",
        ):
            self.assertNotIn(legacy_phase, module)
        self.assertNotIn("wine", module.lower())
        self.assertNotIn("executes_original_binary = true", module.lower())

    def test_authority_and_candidate_library_phases_have_explicit_roles(self) -> None:
        authority = (ROOT / "nix" / "library-island-check.nix").read_text(
            encoding="utf-8"
        )
        candidate = (
            ROOT / "nix" / "library-component-generation.nix"
        ).read_text(encoding="utf-8")
        self.assertTrue(
            authority.startswith("# spaghetti-extractor-python-role: authority")
        )
        self.assertIn("check_library_island_v1", authority)
        self.assertNotIn("build_checked_library_component_v1", authority)
        self.assertTrue(
            candidate.startswith("# spaghetti-extractor-python-role: candidate")
        )
        self.assertIn("build_checked_library_component_v1", candidate)
        self.assertNotIn("check_library_island_v1", candidate)

    def test_component_activation_requires_separate_behavioral_evidence(self) -> None:
        module = (ROOT / "nix" / "component-workflow.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("produce_component_evidence", module)
        self.assertIn("qualify_lift_unit", module)
        self.assertNotIn("produce_component_evidence_v3", module)
        self.assertNotIn("qualify_lift_unit_v3", module)
        self.assertIn("activation_requires_separate_behavioral_evidence", module)
        self.assertNotIn("linked_island_identity_authorizes_replacement", module)


if __name__ == "__main__":
    unittest.main()
