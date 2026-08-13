from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTKIT = {"resources": ["nix/stage-b-source-project.nix"]}


class StageBSourceProjectNixTests(unittest.TestCase):
    def test_generic_binding_is_static_content_addressed_and_candidate_free(
        self,
    ) -> None:
        module = (ROOT / "nix" / "stage-b-source-project.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            'modules = [ "spaghetti_extractor.source_project" ];', module
        )
        self.assertIn("bind_source_project(", module)
        self.assertIn("machine_ir=pathlib.Path(machine_ir)", module)
        self.assertIn("specification=pathlib.Path(specification)", module)
        self.assertIn("source_root=pathlib.Path(source_root)", module)
        self.assertIn("linkedIslands ? null", module)
        self.assertIn("__contentAddressed = true;", module)
        self.assertIn("SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1", module)
        self.assertIn('equivalence_status == "not_proven"', module)
        self.assertIn("(.authority.can_authorize_machine_override | not)", module)
        self.assertNotIn("wine", module.lower())
        self.assertNotIn("candidateBinary", module)

    def test_functional_cases_are_structurally_gated_by_static_authority(
        self,
    ) -> None:
        runner = (ROOT / "nix" / "stage-b-functional-suite.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn("authorityGate ? null", runner)
        self.assertIn("test -f ${authorityGate}/authority-gate.json", runner)
        self.assertIn(
            "authorityGate == null || lib.isDerivation authorityGate", runner
        )

    def test_lift_audit_is_static_and_non_authorizing(self) -> None:
        iteration_module = (
            ROOT / "nix" / "stage-b-source-iteration-audit.nix"
        ).read_text(encoding="utf-8")
        module = (ROOT / "nix" / "stage-b-source-lift-audit.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("audit_source_iteration", iteration_module)
        self.assertNotIn("authorityDiagnostics", iteration_module)
        self.assertIn("join_source_lift_authority", module)
        self.assertIn("sourceIterationAudit", module)
        source_audit = (
            ROOT / "src" / "spaghetti_extractor" / "source_lift_audit.py"
        ).read_text(encoding="utf-8")
        self.assertIn("candidate_import_surface", source_audit)
        self.assertIn("SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1", module)
        self.assertIn(".trust.authorizes_runtime_testing | not", module)
        self.assertNotIn("wine", module.lower())
        self.assertNotIn("wine", iteration_module.lower())


if __name__ == "__main__":
    unittest.main()
