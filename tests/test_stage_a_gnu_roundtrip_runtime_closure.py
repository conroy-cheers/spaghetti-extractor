from __future__ import annotations

import unittest
from pathlib import Path


class StageAGnuRoundtripRuntimeClosureTests(unittest.TestCase):
    def test_candidate_phases_use_only_the_explicit_runtime_closure(self) -> None:
        repo = Path(__file__).resolve().parents[1]
        lane = (
            repo / "nix" / "gnu-hello-roundtrip.nix"
        ).read_text(encoding="utf-8")
        sources = (repo / "nix" / "stage-b-python-sources.nix").read_text(
            encoding="utf-8"
        )
        runtime_start = sources.index("runtimeFiles =")
        runtime_end = sources.index("workspaceFiles =", runtime_start)
        runtime = sources[runtime_start:runtime_end]
        interpreter_start = sources.index("interpreterFiles =")
        interpreter_end = sources.index("runtimeFiles =", interpreter_start)
        interpreter = sources[interpreter_start:interpreter_end]

        for module in (
            "artifact_formats.py",
            "relational/definedness.py",
            "stage_b_c_backend.py",
            "stage_b_interpreter_backend.py",
            "stage_b_state_machine.py",
            "stage_b_typed_x87.py",
            "stage_binary.py",
        ):
            self.assertIn(module, interpreter)
        for module in (
            "component_workspace.py",
            "reconstruction_workspace.py",
            "region_replacement.py",
            "semantic_components.py",
        ):
            self.assertNotIn(module, interpreter)

        self.assertIn("artifact_formats.py", runtime)
        self.assertIn("relational/definedness.py", runtime)
        self.assertIn("spaghetti_extractor/_contract_tools", runtime)
        self.assertEqual(
            runtime.count("../src/spaghetti_extractor/relational/lean/"),
            3,
        )
        self.assertIn("relational/lean/__init__.py", runtime)
        self.assertIn("relational/lean/callable_external_capability.py", runtime)
        self.assertIn("relational/lean/callable_external_execution.py", runtime)
        self.assertNotIn("relational/lean/interpreter", runtime)
        self.assertNotIn("relational/lean/compiler.py", runtime)
        self.assertNotIn("spaghetti_extractor/lean", runtime)
        self.assertNotIn("relational/engine_segments.py", runtime)
        self.assertNotIn("cli.py", runtime)

        native_start = sources.index("nativeBuild =")
        native = sources[native_start:]
        self.assertIn("runtimeFiles", native)
        self.assertIn("stage_b_interpreter_native_build.py", native)
        self.assertIn(
            "stageBPythonSources = import ./stage-b-python-sources.nix",
            lane,
        )
        self.assertIn(
            "interpreterPythonSource = stageBPythonSources.interpreter", lane
        )
        self.assertIn("runtimePythonSource = stageBPythonSources.runtime", lane)
        self.assertIn("nativeBuildPythonSource = stageBPythonSources.nativeBuild", lane)
        self.assertIn("componentWorkspacePythonSource = stageBPythonSources.workspace", lane)

        for phase in (
            "staticExport",
            "interpreter",
            "nativeEngine",
            "nativeRuntime",
            "candidate",
        ):
            start = lane.index(f"{phase} = mkPhase")
            end = lane.index(";", start) + 1
            source = lane[start:end]
            self.assertIn("${runtimeDriver}", source)
            self.assertNotIn("${driver}", source)
            self.assertNotIn("-m spaghetti_extractor", source)

    def test_component_tooling_is_outside_the_proof_emitter_closure(self) -> None:
        repo = Path(__file__).resolve().parents[1]
        lane = (repo / "nix" / "gnu-hello-roundtrip.nix").read_text(
            encoding="utf-8"
        )
        sources = (repo / "nix" / "stage-b-python-sources.nix").read_text(
            encoding="utf-8"
        )
        proof_start = lane.index("proofPythonFiles =")
        proof_end = lane.index("proofPythonSource =", proof_start)
        proof_files = lane[proof_start:proof_end]

        for module in (
            "bounded_component_contract.py",
            "cli.py",
            "component_discovery.py",
            "component_interface.py",
            "component_selection.py",
            "component_workspace.py",
            "finite_component_contract.py",
            "semantic_components.py",
        ):
            self.assertIn(module, proof_files)

        component_start = sources.index("workspaceFiles =")
        component_end = sources.index("in\n{", component_start)
        component_files = sources[component_start:component_end]
        self.assertIn("bounded_component_contract.py", component_files)
        self.assertIn("finite_component_contract.py", component_files)
        self.assertIn("component_workspace.py", component_files)


if __name__ == "__main__":
    unittest.main()
