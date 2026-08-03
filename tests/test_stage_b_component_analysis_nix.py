from __future__ import annotations

import json
import unittest
from pathlib import Path

from spaghetti_extractor.component_selection import bind_component_selection


class StageBComponentAnalysisNixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = Path(__file__).parents[1]

    def test_generic_analysis_is_a_static_content_addressed_phase_dag(self) -> None:
        analysis = (self.repo / "nix" / "stage-b-component-analysis.nix").read_text(
            encoding="utf-8"
        )
        discovery = (
            self.repo / "nix" / "stage-b-component-discovery.nix"
        ).read_text(encoding="utf-8")

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
        self.assertNotIn("executes_candidate_binary", analysis)
        self.assertIn('"executes_original_binary": False', analysis)
        self.assertIn(".coverage.exact.complete", discovery)
        self.assertIn(".coverage.potential.complete", discovery)

    def test_flake_exports_generic_smoke_and_jq_selection_layers(self) -> None:
        flake = (self.repo / "flake.nix").read_text(encoding="utf-8")
        interfaces = (
            self.repo / "nix" / "stage-b-component-interfaces.nix"
        ).read_text(encoding="utf-8")

        self.assertIn("mkStageBComponentAnalysis", flake)
        self.assertIn("stage-b-component-analysis-smoke", flake)
        self.assertIn("stage-b-jq-selected-component-declarations", flake)
        self.assertIn("stage-b-jq-selected-component-catalog", flake)
        self.assertIn("stage-b-jq-component-interfaces", flake)
        self.assertIn("stage-b-jq-machine-ir-interpreter", flake)
        self.assertIn("stage-b-jq-option-name-match-workspace", flake)
        self.assertIn("stage-b-jq-option-name-match-qualification", flake)
        self.assertIn("stage-b-jq-option-token-classifier-workspace", flake)
        self.assertIn("stage-b-jq-option-token-classifier-qualification", flake)
        self.assertIn("stage-b-jq-stderr-value-kind-route-workspace", flake)
        self.assertIn("stage-b-jq-stderr-value-kind-route-qualification", flake)
        self.assertIn("stage-b-jq-debug-value-prefix-workspace", flake)
        self.assertIn("stage-b-jq-debug-value-prefix-qualification", flake)
        self.assertIn("stage-b-jq-usage-exit-route-workspace", flake)
        self.assertIn("stage-b-jq-usage-exit-route-qualification", flake)
        self.assertIn("stage-b-jq-usage-write-route-workspace", flake)
        self.assertIn("stage-b-jq-usage-write-route-qualification", flake)
        self.assertIn("stage-b-jq-option-value-collection-workspace", flake)
        self.assertIn("stage-b-jq-option-value-collection-qualification", flake)
        self.assertIn("stage-b-jq-output-value-release-workspace", flake)
        self.assertIn("stage-b-jq-output-value-release-qualification", flake)
        self.assertIn("stage-b-jq-output-value-dump-workspace", flake)
        self.assertIn("stage-b-jq-output-value-dump-qualification", flake)
        self.assertIn("stage-b-jq-output-value-pipeline-workspace", flake)
        self.assertIn("stage-b-jq-output-value-pipeline-qualification", flake)
        self.assertIn(
            "stage-b-jq-wide-argument-conversion-tail-workspace", flake
        )
        self.assertIn(
            "stage-b-jq-wide-argument-conversion-tail-qualification", flake
        )
        self.assertIn(
            "stage-b-jq-math-error-callback-dispatch-workspace", flake
        )
        self.assertIn(
            "stage-b-jq-math-error-callback-dispatch-qualification", flake
        )
        self.assertIn("stage-b-jq-pe32-section-count-workspace", flake)
        self.assertIn("stage-b-jq-pe32-section-count-qualification", flake)
        self.assertIn("stage-b-jq-pe32-image-base-workspace", flake)
        self.assertIn("stage-b-jq-pe32-image-base-qualification", flake)
        self.assertIn("stage-b-jq-pe32-section-for-address-workspace", flake)
        self.assertIn("stage-b-jq-pe32-section-for-address-qualification", flake)
        self.assertIn("stage-b-jq-windows-path-info-scan-workspace", flake)
        self.assertIn("stage-b-jq-windows-path-info-scan-qualification", flake)
        self.assertIn("stage-b-jq-invalid-parameter-handler-get-workspace", flake)
        self.assertIn(
            "stage-b-jq-invalid-parameter-handler-get-qualification", flake
        )
        self.assertIn(
            "stage-b-jq-invalid-parameter-handler-exchange-workspace", flake
        )
        self.assertIn(
            "stage-b-jq-invalid-parameter-handler-exchange-qualification", flake
        )
        self.assertIn("stage-b-jq-bounded-string-length-workspace", flake)
        self.assertIn("stage-b-jq-bounded-string-length-qualification", flake)
        self.assertIn("stage-b-jq-bounded-wide-string-length-workspace", flake)
        self.assertIn(
            "stage-b-jq-bounded-wide-string-length-qualification", flake
        )
        self.assertIn("stage-b-jq-component-granularity-smoke", flake)
        self.assertIn("stage-b-jq-component-registry", flake)
        self.assertIn("./fixtures/jq/components/option-name-match.c", flake)
        self.assertIn("./fixtures/jq/components/option-token-classifier.c", flake)
        self.assertIn("./fixtures/jq/components/stderr-value-kind-route.c", flake)
        self.assertIn("./fixtures/jq/components/usage-exit-route.c", flake)
        self.assertIn("./fixtures/jq/components/usage-write-route.c", flake)
        self.assertIn("./fixtures/jq/components/option-value-collection.c", flake)
        self.assertIn("./fixtures/jq/components/output-value-release.c", flake)
        self.assertIn("./fixtures/jq/components/output-value-dump.c", flake)
        self.assertIn("./fixtures/jq/components/output-value-pipeline.c", flake)
        self.assertIn("./fixtures/jq/components/debug-value-prefix.c", flake)
        self.assertIn(
            "./fixtures/jq/components/wide-argument-conversion-tail.c", flake
        )
        self.assertIn(
            "./fixtures/jq/components/math-error-callback-dispatch.c", flake
        )
        self.assertIn("./fixtures/jq/components/pe32-section-count.c", flake)
        self.assertIn("./fixtures/jq/components/pe32-image-base.c", flake)
        self.assertIn(
            "./fixtures/jq/components/pe32-section-for-address.c", flake
        )
        self.assertIn(
            "./fixtures/jq/components/windows-path-info-scan.c", flake
        )
        self.assertIn(
            "./fixtures/jq/components/invalid-parameter-handler-get.c", flake
        )
        self.assertIn(
            "./fixtures/jq/components/invalid-parameter-handler-exchange.c", flake
        )
        self.assertIn(
            "./fixtures/jq/components/bounded-string-length.c", flake
        )
        self.assertIn(
            "./fixtures/jq/components/bounded-wide-string-length.c", flake
        )
        self.assertIn("opaque_value_service_prefix_v1", flake)
        self.assertIn("status_normalize_terminal_service_v1", flake)
        self.assertIn("constant_buffer_write_v1", flake)
        self.assertIn("constant_string_collection_v1", flake)
        self.assertIn("opaque_output_pipeline_v1", flake)
        self.assertIn("opaque_value_label_prefix_v1", flake)
        self.assertIn("stdcall_wide_conversion_iteration_v1", flake)
        self.assertIn("optional_fp64_record_callback_v1", flake)
        self.assertIn("pe32_header_query_v1", flake)
        self.assertIn("windows_path_info_scan_v1", flake)
        self.assertIn("static_atomic_word_v1", flake)
        self.assertIn("bounded_wide_string_length_v1", flake)
        self.assertIn(
            "stageBInterpreterPythonSource = stageBPythonSources.interpreter",
            flake,
        )
        self.assertIn("__contentAddressed = true;", interfaces)
        self.assertNotIn("wine", interfaces.lower())
        self.assertNotIn("component_workspace", interfaces)
        interface_source_start = flake.index(
            "stageBComponentInterfacePythonSource ="
        )
        interface_source = flake[
            interface_source_start : flake.index(
                "spaghetti-extractor-roundtrip =", interface_source_start
            )
        ]
        self.assertIn("component_interface.py", interface_source)
        self.assertNotIn("component_workspace.py", interface_source)
        self.assertNotIn("reconstruction_ir.py", interface_source)
        self.assertIn('pe32-msvcrt-machine-runtime-v1.json"', flake)
        jq_contract = flake[
            flake.index('pkgs.runCommand "stage-a-jq-relation-contract"') :
        ]
        jq_contract = jq_contract[: jq_contract.index("stageAJqRelationalGraph =")]
        self.assertIn("pe32-kernel32-lockstep-v1.json", jq_contract)
        self.assertIn("pe32-msvcrt-lockstep-v1.json", jq_contract)
        self.assertNotIn("pe32-msvcrt-machine-runtime-v1.json", jq_contract)

    def test_jq_workspace_dag_has_granular_phase_inputs(self) -> None:
        module = (
            self.repo / "nix" / "stage-b-semantic-component-workspaces.nix"
        ).read_text(encoding="utf-8")
        flake = (self.repo / "flake.nix").read_text(encoding="utf-8")

        self.assertIn("componentSelectionPythonSource ? pythonSource", module)
        self.assertIn("semanticComponentPythonSource ? pythonSource", module)
        self.assertIn("componentInterfacePythonSource ? pythonSource", module)
        self.assertIn("pythonSource = componentSelectionPythonSource", module)
        self.assertIn("pythonSource = semanticComponentPythonSource", module)
        self.assertIn("pythonSource = componentInterfacePythonSource", module)
        self.assertIn("componentCatalog component", module)
        self.assertIn("componentInterfacesByName", module)
        semantic_catalog = (
            self.repo / "nix" / "stage-b-semantic-components.nix"
        ).read_text(encoding="utf-8")
        self.assertIn(".counts.declared_units > 0", semantic_catalog)
        self.assertNotIn(
            ".coverage.counts.declared_exact_reachable_units > 0",
            semantic_catalog,
        )
        self.assertNotIn(
            ".coverage.counts.unassigned_exact_reachable_units > 0",
            semantic_catalog,
        )
        self.assertIn("stageBJqOptionNameMatchIsolatedDag", flake)
        self.assertIn(
            "toString stageBJqFrontendWorkspaceDag.qualifications.option-name-match",
            flake,
        )
        self.assertIn(
            "toString stageBJqOptionNameMatchIsolatedDag.qualifications.option-name-match",
            flake,
        )

    def test_interpreter_package_is_a_generic_content_addressed_phase(self) -> None:
        module = (
            self.repo / "nix" / "stage-b-interpreter-package.nix"
        ).read_text(encoding="utf-8")

        self.assertIn("machineIr", module)
        self.assertIn("pythonSource", module)
        self.assertIn("write_stage_b_interpreter_package", module)
        self.assertIn("__contentAddressed = true;", module)
        self.assertNotIn("stage-b-jq", module.lower())
        self.assertNotIn("fixtures/jq", module.lower())
        self.assertNotIn("wine", module.lower())

    def test_jq_selection_is_frontend_scoped_and_self_bound(self) -> None:
        path = self.repo / "fixtures" / "jq" / "component-selection.json"
        payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(payload["program_id"], "jq-pe32-frontend-reference-v1")
        self.assertEqual(len(payload["components"]), 20)
        self.assertEqual(
            bind_component_selection(payload)["selection_sha256"],
            payload["selection_sha256"],
        )
        self.assertEqual(
            len({item["proposal_id"] for item in payload["components"]}), 20
        )
        self.assertTrue(
            all(
                len(item.get("proposal_binding_sha256", "")) == 64
                for item in payload["components"]
            )
        )
        self.assertIn(
            "stderr-value-kind-route",
            {item["id"] for item in payload["components"]},
        )
        self.assertIn(
            "math-error-callback-dispatch",
            {item["id"] for item in payload["components"]},
        )
        self.assertIn(
            "pe32-section-count",
            {item["id"] for item in payload["components"]},
        )
        self.assertIn(
            "pe32-image-base",
            {item["id"] for item in payload["components"]},
        )
        self.assertIn(
            "pe32-section-for-address",
            {item["id"] for item in payload["components"]},
        )
        self.assertIn(
            "windows-path-info-scan",
            {item["id"] for item in payload["components"]},
        )
        self.assertIn(
            "invalid-parameter-handler-get",
            {item["id"] for item in payload["components"]},
        )
        self.assertIn(
            "invalid-parameter-handler-exchange",
            {item["id"] for item in payload["components"]},
        )
        self.assertIn(
            "bounded-string-length",
            {item["id"] for item in payload["components"]},
        )
        self.assertIn(
            "bounded-wide-string-length",
            {item["id"] for item in payload["components"]},
        )


if __name__ == "__main__":
    unittest.main()
