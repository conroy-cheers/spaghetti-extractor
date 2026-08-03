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

    def test_gnu_hello_exports_complete_frontier_and_dependency_audit(self) -> None:
        flake = (self.repo / "flake.nix").read_text(encoding="utf-8")

        for package in (
            "stage-b-gnu-hello-call-frontier",
            "stage-b-gnu-hello-proposed-source-components",
            "stage-b-gnu-hello-call-substitution-plan",
            "stage-b-gnu-hello-source-call-inventory",
            "stage-b-gnu-hello-source-call-binding-report",
            "stage-b-gnu-hello-toolchain-runtime-imports",
            "stage-b-gnu-hello-dependency-envelope",
            "stage-b-gnu-hello-candidate-dependency-audit",
            "stage-b-gnu-hello-source-call-substitution-smoke",
        ):
            self.assertIn(package, flake)
        self.assertIn("proposeSourceComponents = true;", flake)
        self.assertIn("derived_from_candidate_during_audit: false", flake)
        self.assertIn("pinned_toolchain_baseline: true", flake)
        self.assertIn("reviewed_source_runtime_closure: true", flake)


if __name__ == "__main__":
    unittest.main()
