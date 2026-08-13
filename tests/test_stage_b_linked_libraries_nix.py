from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class StageBLinkedLibrariesNixTests(unittest.TestCase):
    def test_generic_dag_is_static_content_addressed_and_phase_split(self) -> None:
        module = (ROOT / "nix" / "stage-b-linked-libraries.nix").read_text(encoding="utf-8")
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
        self.assertIn('effectiveCatalogLock == null then "-"', module)
        self.assertIn('None if catalog_lock == "-"', module)
        self.assertIn("infer_library_hypotheses", module)
        self.assertIn("qualify_linked_interfaces", module)
        self.assertNotIn("wine", module.lower())
        self.assertNotIn("executes_original_binary = true", module.lower())

    def test_component_dags_consume_linked_scope_without_granting_authority(self) -> None:
        catalog = (ROOT / "nix" / "stage-b-semantic-components.nix").read_text(encoding="utf-8")
        workspaces = (ROOT / "nix" / "stage-b-semantic-component-workspaces.nix").read_text(encoding="utf-8")
        self.assertIn("linkedIslands ? null", catalog)
        self.assertIn("linked_island_identity_authorizes_replacement", catalog)
        self.assertIn("linkedIslands ? null", workspaces)
        self.assertIn("identity_authorizes_activation == false", workspaces)


if __name__ == "__main__":
    unittest.main()
