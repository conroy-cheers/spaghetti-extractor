from __future__ import annotations

import unittest
from pathlib import Path


class StageBLinkedLibrariesNixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = Path(__file__).parents[1]

    def test_generic_dag_is_static_content_addressed_and_phase_split(self) -> None:
        module = (self.repo / "nix" / "stage-b-linked-libraries.nix").read_text(
            encoding="utf-8"
        )

        for phase in (
            "artifactIndex",
            "generatedCatalogLock",
            "matchEvidence",
            "libraryHypotheses",
            "dynamicRequirements",
            "linkedIslands",
            "interfaceQualification",
            "replacementPlan",
        ):
            self.assertIn(phase, module)
        self.assertIn("__contentAddressed = true;", module)
        self.assertIn("index_library_artifacts", module)
        self.assertIn("propose_library_match_evidence", module)
        self.assertIn("infer_library_hypotheses", module)
        self.assertIn("refine_linked_islands", module)
        self.assertIn("derive_dynamic_library_requirements", module)
        self.assertIn("qualify_linked_interfaces", module)
        self.assertIn("plan_library_replacements", module)
        self.assertNotIn("wine", module.lower())
        self.assertNotIn("executes_original_binary = true", module.lower())
        self.assertIn("artifact_recognition_authorizes_replacement", module)

    def test_flake_exports_federated_benchmarks_and_vintage_fixture(self) -> None:
        flake = (self.repo / "flake.nix").read_text(encoding="utf-8")

        self.assertIn("mkStageBLinkedLibraryAnalysis", flake)
        self.assertIn("stage-b-jq-linked-islands", flake)
        self.assertIn("stage-b-gnu-hello-linked-islands", flake)
        self.assertIn("stage-b-gnu-hello-library-hypotheses", flake)
        self.assertIn("stage-b-gnu-hello-dynamic-library-requirements", flake)
        self.assertIn("stage-b-gnu-hello-library-replacement-plan", flake)
        self.assertIn("stage-b-openwatcom19-library-artifact-index", flake)
        self.assertIn("stage-b-linked-library-analysis-smoke", flake)
        self.assertIn(".counts.incomplete_dynamic_callsites > 0", flake)
        self.assertIn(".counts.exact_artifact >= 10", flake)
        self.assertIn(".bindings.dynamic_requirements_sha256", flake)
        self.assertIn("open-watcom-bin", flake)
        self.assertIn("libmingw32.a", flake)
        self.assertIn("libmingwex.a", flake)
        self.assertIn("linkedIslands =", flake)

    def test_component_dags_consume_linked_scope_without_granting_authority(
        self,
    ) -> None:
        catalog = (
            self.repo / "nix" / "stage-b-semantic-components.nix"
        ).read_text(encoding="utf-8")
        workspaces = (
            self.repo / "nix" / "stage-b-semantic-component-workspaces.nix"
        ).read_text(encoding="utf-8")

        self.assertIn("linkedIslands ? null", catalog)
        self.assertIn("linked_island_identity_authorizes_replacement", catalog)
        self.assertIn("linkedIslands ? null", workspaces)
        self.assertIn("identity_authorizes_activation == false", workspaces)
        self.assertIn("linked_islands=linked_islands", workspaces)


if __name__ == "__main__":
    unittest.main()
