from __future__ import annotations

import unittest
from pathlib import Path


class StageBSourceCallSubstitutionsNixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = Path(__file__).parents[1]

    def test_generic_pipeline_is_static_content_addressed_and_phase_split(self) -> None:
        module = (
            self.repo / "nix" / "stage-b-source-call-substitutions.nix"
        ).read_text(encoding="utf-8")

        for phase in (
            "generatedIndirectTargets",
            "callFrontier",
            "proposedSourceComponents",
            "effectiveInterfaceCatalog",
            "effectiveSubstitutionCatalog",
            "effectiveAssignments",
            "callPlan",
            "sourceInventory",
            "effectiveSourceCallBindings",
            "sourceBindingReport",
            "candidateAudit",
        ):
            self.assertIn(phase, module)
        self.assertIn("__contentAddressed = true;", module)
        self.assertIn("derive_static_indirect_call_targets", module)
        self.assertIn("propose_source_component_artifacts", module)
        self.assertIn("propose_source_component_bindings", module)
        self.assertIn("audit_candidate_dependencies", module)
        self.assertNotIn("wine", module.lower())
        self.assertNotIn("executes_original_binary = true", module.lower())
        self.assertIn('.qualification.status == "incomplete"', module)
        self.assertIn('.qualification.kind == "operator_proposal"', module)

if __name__ == "__main__":
    unittest.main()
