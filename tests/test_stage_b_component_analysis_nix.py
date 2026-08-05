from __future__ import annotations

import json
import unittest
from pathlib import Path

from spaghetti_extractor.target_intent import validate_authored_intent


ROOT = Path(__file__).resolve().parents[1]


class StageBComponentAnalysisNixTests(unittest.TestCase):
    def test_generic_analysis_is_static_content_addressed_and_candidate_free(self) -> None:
        analysis = (ROOT / "nix" / "stage-b-component-analysis.nix").read_text(encoding="utf-8")
        discovery = (ROOT / "nix" / "stage-b-component-discovery.nix").read_text(encoding="utf-8")

        for phase in (
            "originalInventory",
            "staticExport",
            "stateMachine",
            "machineIr",
            "reconstructionPlan",
            "componentProposals",
        ):
            self.assertIn(phase, analysis)
        self.assertIn("__contentAddressed = true;", analysis)
        self.assertIn("__contentAddressed = true;", discovery)
        self.assertNotIn("wine", analysis.lower())
        self.assertNotIn("--candidate", analysis)
        self.assertNotIn("candidateBinary", analysis)
        self.assertNotIn("sideTool", analysis)
        self.assertIn("pythonSource", analysis)
        self.assertIn("staticPythonSource ? pythonSource", analysis)
        self.assertIn('"executes_original_binary": False', analysis)
        self.assertIn(".coverage.exact.complete", discovery)
        self.assertIn(".coverage.potential.complete", discovery)

    def test_component_workspace_dag_has_granular_phase_inputs(self) -> None:
        module = (ROOT / "nix" / "stage-b-semantic-component-workspaces.nix").read_text(encoding="utf-8")
        for declaration in (
            "componentSelectionPythonSource ? pythonSource",
            "semanticComponentPythonSource ? pythonSource",
            "componentInterfacePythonSource ? pythonSource",
            "componentCatalog component",
            "componentInterfacesByName",
        ):
            self.assertIn(declaration, module)
        self.assertIn("__contentAddressed = true;", module)

    def test_interpreter_package_is_a_generic_content_addressed_phase(self) -> None:
        module = (ROOT / "nix" / "stage-b-interpreter-package.nix").read_text(encoding="utf-8")
        self.assertIn("machineIr", module)
        self.assertIn("write_stage_b_interpreter_package", module)
        self.assertIn("__contentAddressed = true;", module)
        self.assertNotIn("stage-b-jq", module.lower())
        self.assertNotIn("wine", module.lower())

    def test_jq_component_intent_is_authored_data_not_tooling(self) -> None:
        path = ROOT / "targets" / "jq" / "intent" / "components.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        validate_authored_intent(
            payload,
            expected_format="stage-b-component-intent-v1",
            context=path.relative_to(ROOT).as_posix(),
        )
        self.assertTrue(payload["components"])

    def test_dxball_consumes_the_generic_component_analysis_constructor(self) -> None:
        target = (ROOT / "targets" / "dxball" / "default.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("../../nix/stage-b-component-analysis.nix", target)
        self.assertIn("inherit archive installer original inventory analysis", target)


if __name__ == "__main__":
    unittest.main()
