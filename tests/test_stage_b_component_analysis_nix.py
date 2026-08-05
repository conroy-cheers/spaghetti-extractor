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
        self.assertIn("close_state_machine_rooted_direct_control", analysis)
        self.assertNotIn("padding-bridge", analysis)
        self.assertNotIn("padding_bridge", analysis)
        self.assertIn("executes_original_binary", analysis)
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

    def test_native_compiler_nodes_have_content_minimal_dependencies(self) -> None:
        module = (ROOT / "nix" / "stage-b-native-object-graph.nix").read_text(
            encoding="utf-8"
        )
        compile_start = module.index("mkCompiledObject =")
        compile_end = module.index("mkObjectReceipt =", compile_start)
        compiler_node = module[compile_start:compile_end]

        self.assertIn("unit.compile_key_sha256", compiler_node)
        self.assertIn("mkSourceBundle unit", compiler_node)
        self.assertNotIn("${graph}", compiler_node)
        self.assertNotIn("python", compiler_node.lower())
        self.assertIn("ownerRoots", module)
        self.assertIn('in "${root}/${file.path}"', module)
        self.assertIn("compiledObjects", module)
        self.assertIn("stage-b-interpreter-native-object-graph-v2", module)

    def test_machine_ir_preparation_is_a_distinct_reusable_phase(self) -> None:
        module = (ROOT / "nix" / "stage-b-component-analysis.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn("mkPreparedMachineIr", module)
        self.assertIn("directPreparedMachineIr", module)
        self.assertIn("preparedMachineIr = mkPreparedMachineIr", module)
        self.assertIn("preparedMachineIr = preparedMachineIr", module)
        self.assertIn("prepared_units_reused", module)

    def test_hybrid_candidate_uses_phase_specific_python_closures(self) -> None:
        module = (ROOT / "nix" / "stage-b-hybrid-candidate.nix").read_text(
            encoding="utf-8"
        )
        closure = (ROOT / "nix" / "python-module-closure.nix").read_text(
            encoding="utf-8"
        )

        for name in (
            "nativeEnginePythonSource",
            "nativeRuntimePythonSource",
            "nativeBuildPythonSource",
        ):
            self.assertIn(name, module)
        interpreter = (
            ROOT / "nix" / "stage-b-interpreter-package.nix"
        ).read_text(encoding="utf-8")
        self.assertIn("phasePythonSource", interpreter)
        self.assertIn("__contentAddressed = true;", closure)
        self.assertIn("ast.parse", closure)
        self.assertIn("python-module-closure.json", closure)

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
        self.assertIn(
            "inherit archive installer original interfaceProfile inventory analysis",
            target,
        )
        self.assertIn("externalInterfaceProfiles", target)

    def test_sdk_interface_profile_is_a_generic_content_addressed_phase(self) -> None:
        module = (
            ROOT / "nix" / "stage-a-external-interface-profile.nix"
        ).read_text(encoding="utf-8")

        self.assertIn("sdkHeaders ?", module)
        self.assertIn("extract_external_interface_profile", module)
        self.assertIn("__contentAddressed = true;", module)
        self.assertNotIn("dxball", module.lower())

    def test_analysis_source_excludes_nix_orchestration_files(self) -> None:
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        analysis_start = flake.index("analysisSource =")
        analysis_end = flake.index("pythonEnv =", analysis_start)
        analysis_source = flake[analysis_start:analysis_end]

        self.assertIn("./src", analysis_source)
        self.assertIn("./profiles", analysis_source)
        self.assertNotIn("./nix", analysis_source)
        self.assertIn("pythonSource = analysisSource", flake)


if __name__ == "__main__":
    unittest.main()
