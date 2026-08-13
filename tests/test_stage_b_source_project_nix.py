from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTKIT = {
    "resources": [
        "nix/stage-b-source-project.nix",
        "targets/gnu-hello",
    ]
}


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

    def test_gnu_hello_binds_resolved_intent_to_analysis_machine_ir(self) -> None:
        target = (ROOT / "targets" / "gnu-hello" / "default.nix").read_text(
            encoding="utf-8"
        )
        workflow = (
            ROOT / "targets" / "gnu-hello" / "idiomatic.nix"
        ).read_text(encoding="utf-8")

        self.assertIn("machineIr = analysis.machineIr;", target)
        self.assertIn("intent.sourceProjects 0", target)
        self.assertIn("import ../../nix/stage-b-linked-libraries.nix", target)
        self.assertIn("linkedLibraries.linkedIslands", target)
        self.assertIn("import ../../nix/stage-b-source-project.nix", workflow)
        self.assertIn("sourceRoot = source;", workflow)
        self.assertIn("idiomaticSourceBinding = idiomatic.sourceBinding;", target)
        self.assertIn("idiomaticSourceSpecification", target)
        self.assertIn("idiomaticSourceEvidencePlan", target)
        self.assertIn("idiomaticFunctionalSuite = idiomatic.functionalSuite;", target)
        self.assertIn("authorityGate = analysisV3.finalAuthorityGate;", target)
        self.assertIn("inherit authorityGate;", workflow)

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

    def test_lift_audit_is_static_non_authorizing_and_target_wired(self) -> None:
        iteration_module = (
            ROOT / "nix" / "stage-b-source-iteration-audit.nix"
        ).read_text(encoding="utf-8")
        module = (ROOT / "nix" / "stage-b-source-lift-audit.nix").read_text(
            encoding="utf-8"
        )
        target = (ROOT / "targets" / "gnu-hello" / "default.nix").read_text(
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
        self.assertIn("sourceIterationAudit = import", target)
        self.assertIn("authorityDiagnostics = analysisV3.diagnostics;", target)
        self.assertIn("idiomaticSourceLiftAudit = sourceLiftAudit;", target)

    def test_restored_functional_suite_covers_authored_component_evidence(
        self,
    ) -> None:
        suite = (
            ROOT
            / "targets"
            / "gnu-hello"
            / "tests"
            / "functional-suite.nix"
        ).read_text(encoding="utf-8")
        evidence = json.loads(
            (
                ROOT
                / "targets"
                / "gnu-hello"
                / "intent"
                / "source"
                / "evidence.json"
            ).read_text(encoding="utf-8")
        )

        case_ids = set(re.findall(r'^\s+id = "([^"]+)";$', suite, re.MULTILINE))
        evidence_ids = {
            case_id
            for component in evidence["components"]
            for case_id in component["functional_case_ids"]
        }
        self.assertEqual(len(case_ids), 11)
        self.assertEqual(evidence_ids, case_ids)
        self.assertIn('suite_kind = "curated_expected_output";', suite)
        self.assertIn('suite_scope = "curated";', suite)
        self.assertIn("upstream_suite = false;", suite)
        self.assertIn('stdout_sink = "full_device";', suite)


if __name__ == "__main__":
    unittest.main()
