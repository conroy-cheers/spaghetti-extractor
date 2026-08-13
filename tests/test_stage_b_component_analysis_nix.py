from __future__ import annotations

import json
import re
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

    def test_native_object_graph_avoids_ca_import_from_derivation(self) -> None:
        module = (ROOT / "nix" / "stage-b-native-object-graph.nix").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("builtins.readFile", module)
        self.assertNotIn("unsafeDiscardStringContext", module)
        self.assertIn("compile_stage_b_interpreter_native_object", module)
        self.assertIn("assemble_stage_b_interpreter_native_objects", module)
        self.assertIn("__contentAddressed = true;", module)
        self.assertIn("compiledObjects", module)
        self.assertIn("stage-b-interpreter-native-object-graph-v2", module)

    def test_machine_ir_preparation_is_a_distinct_reusable_phase(self) -> None:
        module = (ROOT / "nix" / "stage-b-component-analysis.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn("mkPreparedMachineIr", module)
        self.assertIn("directPreparedMachineIr", module)
        self.assertEqual(module.count("= mkPreparedMachineIr {"), 1)
        self.assertEqual(module.count("= mkMachineIr {"), 1)
        self.assertIn("preparedMachineIr = directPreparedMachineIr", module)
        self.assertIn("interprocedural_control=False", module)
        self.assertNotIn("controlManifest = provisionalMachineIr", module)
        self.assertIn("prepared_units_reused", module)
        self.assertIn("machineIrPreparationPythonSource", module)
        self.assertIn("machineIrExportPythonSource", module)
        self.assertIn('"spaghetti_extractor.finite_value_domain"', module)
        preparation = module[
            module.index("machineIrPreparationPythonSource") :
            module.index("machineIrExportPythonSource")
        ]
        self.assertNotIn("finite_value_domain", preparation)
        self.assertIn("finite_dataflow_factory=FiniteU32Dataflow", module)

    def test_component_analysis_contains_no_legacy_authority_loop(self) -> None:
        module = (ROOT / "nix" / "stage-b-component-analysis.nix").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "staticHybridAuthorityV2",
            "jointInterproceduralV2",
            "interproceduralSeed",
            "globalSlotAuthority",
            "diagnosticRootedClosure",
        ):
            self.assertNotIn(forbidden, module)

    def test_v3_registry_owns_the_complete_authority_family(self) -> None:
        registry = (
            ROOT / "src" / "spaghetti_extractor" / "analysis_v3" / "registry.py"
        ).read_text(encoding="utf-8")
        for phase in (
            "TRANSITION_SUMMARIES_PHASE_V3",
            "MEMORY_VERSIONS_PHASE_V3",
            "INDUCTIVE_AUTHORITY_PHASE_V3",
            "FINAL_AUTHORITY_PHASE_V3",
        ):
            self.assertIn(phase, registry)
        self.assertIn("require_complete_family", registry)

    def test_transition_summaries_are_native_content_addressed_units(self) -> None:
        transition = (
            ROOT / "src" / "spaghetti_extractor" / "analysis_v3"
            / "transition_summaries.py"
        ).read_text(encoding="utf-8")
        self.assertIn("map_units(", transition)
        self.assertIn('source_input="exact_units"', transition)
        self.assertNotIn("transition_summary_v2", transition)
        self.assertNotIn("authority_bindings_v2", transition)

    def test_memory_authority_is_a_dependency_scc_phase(self) -> None:
        memory = (
            ROOT / "src" / "spaghetti_extractor" / "analysis_v3"
            / "memory_versions.py"
        ).read_text(encoding="utf-8")
        self.assertIn("map_sccs(", memory)
        self.assertIn('schedule_record_inputs=("semantic_index",)', memory)
        self.assertIn('"transition_summaries": "transition-summaries-v3"', memory)

    def test_inductive_authority_consumes_native_checked_summaries(self) -> None:
        inductive = (
            ROOT / "src" / "spaghetti_extractor" / "analysis_v3" / "inductive.py"
        ).read_text(encoding="utf-8")
        self.assertIn("map_sccs(", inductive)
        self.assertIn('"memory_versions": "memory-versions-v3"', inductive)
        self.assertIn('"transition_summaries": "transition-summaries-v3"', inductive)
        self.assertNotIn("invariant_certificate_v2", inductive)

    def test_authority_graph_is_registry_derived_not_manually_plumbed(self) -> None:
        graph = (ROOT / "nix" / "authority-graph-v3.nix").read_text(
            encoding="utf-8"
        )
        manifest = (ROOT / "nix" / "analysis-v3-graph-manifest.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("graph.phases", graph)
        self.assertIn("authority_graph_manifest_v3", manifest)
        graph_module = (
            ROOT / "src" / "spaghetti_extractor" / "analysis_v3" / "graph.py"
        ).read_text(encoding="utf-8")
        self.assertIn("AUTHORITY_PHASE_REGISTRY_V3", graph_module)
        self.assertNotIn("staticHybridAuthorityV2", graph)

    def test_authority_graph_plumbing_uses_narrow_python_closures(self) -> None:
        graph = (ROOT / "nix" / "authority-graph-v3.nix").read_text(
            encoding="utf-8"
        )
        gate = (
            ROOT / "nix" / "analysis-v3-final-authority-gate.nix"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "artifactSetPythonSource = import ./python-module-closure.nix",
            graph,
        )
        self.assertIn(
            'modules = [ "spaghetti_extractor.artifact_set_v3" ];', graph
        )
        self.assertIn(
            "planningPythonSource = import ./python-module-closure.nix", graph
        )
        self.assertIn(
            'modules = [ "spaghetti_extractor.analysis_v3.planning" ];',
            graph,
        )
        self.assertIn("pythonSource = artifactSetPythonSource;", graph)
        self.assertIn("pythonSource = planningPythonSource;", graph)
        self.assertIn("pythonClosure = import ./python-module-closure.nix", gate)
        self.assertIn(
            'modules = [ "spaghetti_extractor.analysis_v3.final_authority" ];',
            gate,
        )

    def test_late_authority_families_have_independent_phase_boundaries(self) -> None:
        registry = (
            ROOT / "src" / "spaghetti_extractor" / "analysis_v3" / "registry.py"
        ).read_text(encoding="utf-8")
        for phase in (
            "CANONICAL_EXTERNAL_SITES_PHASE_V3",
            "CALLBACK_AUTHORITY_PHASE_V3",
            "LAUNCH_ROOT_CLOSURE_PHASE_V3",
            "EXCEPTIONAL_TRANSITIONS_PHASE_V3",
            "ISA_QUALIFICATION_PHASE_V3",
            "FALLBACK_COVERAGE_PHASE_V3",
        ):
            self.assertIn(phase, registry)

    def test_exact_source_plan_is_separate_from_semantic_consumers(self) -> None:
        source_plan = (ROOT / "nix" / "analysis-v3-source-plan.nix").read_text(
            encoding="utf-8"
        )
        machine_input = (
            ROOT / "nix" / "analysis-v3-machine-ir-input.nix"
        ).read_text(encoding="utf-8")
        self.assertIn("prepare_analysis_source_v3", source_plan)
        self.assertIn('"${preparation}/plan.json"', machine_input)
        self.assertIn("preplannedBoundaries", machine_input)
        self.assertIn("builtins.toFile", machine_input)

    def test_native_v3_module_closure_excludes_legacy_authority(self) -> None:
        index = json.loads(
            (ROOT / "nix" / "python-module-index.json").read_text(encoding="utf-8")
        )["modules"]
        pending = ["spaghetti_extractor.analysis_v3.registry"]
        closure: set[str] = set()
        while pending:
            module = pending.pop()
            if module in closure:
                continue
            closure.add(module)
            pending.extend(index[module]["dependencies"])
        self.assertFalse(
            [module for module in closure if module.endswith("_v2")],
            sorted(closure),
        )

    def test_final_authority_recomputes_family_completeness(self) -> None:
        final = (
            ROOT / "src" / "spaghetti_extractor" / "analysis_v3"
            / "final_authority.py"
        ).read_text(encoding="utf-8")
        self.assertIn("_check_unit_inventory", final)
        self.assertIn("_check_inductive_authority", final)
        self.assertIn("validate_authority_decision_v3", final)
        self.assertNotIn("static_hybrid_final_audit_v2", final)

    def test_candidate_builder_validates_v3_authority_twice(self) -> None:
        builder = (
            ROOT / "src" / "spaghetti_extractor"
            / "stage_b_interpreter_native_build.py"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(builder.count("_validate_candidate_authority_v3("), 3)
        self.assertNotIn("stage_b_candidate_authority_v2", builder)
        self.assertNotIn("final_static_hybrid_audit", builder)

    def test_isa_and_fallback_bindings_are_v3_native(self) -> None:
        isa = (
            ROOT / "src" / "spaghetti_extractor" / "analysis_v3"
            / "isa_qualification.py"
        ).read_text(encoding="utf-8")
        fallback = (
            ROOT / "src" / "spaghetti_extractor" / "analysis_v3"
            / "fallback_coverage.py"
        ).read_text(encoding="utf-8")
        self.assertIn("ISA_QUALIFICATION_PHASE_V3", isa)
        self.assertIn("FALLBACK_COVERAGE_PHASE_V3", fallback)
        self.assertIn('unit_aligned_inputs=("isa_qualification",)', fallback)

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
            "candidateAuthorityPythonSource",
        ):
            self.assertIn(name, module)
        interpreter = (
            ROOT / "nix" / "stage-b-interpreter-package.nix"
        ).read_text(encoding="utf-8")
        self.assertIn("phasePythonSource", interpreter)
        self.assertIn("__contentAddressed = true;", closure)
        self.assertIn("python-module-index.json", closure)
        self.assertIn("inline-checked-module-index-v1", closure)
        self.assertNotIn("python-module-validation.nix", closure)
        self.assertIn("ast.parse", closure)
        self.assertIn("python-module-closure.json", closure)
        self.assertIn('package = module.split(".", 1)[0]', closure)
        self.assertIn("run `nix run .#dev -- refresh-index`", closure)

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
        for exported in (
            "inventory",
            "analysis",
            "hybrid",
            "hybridDiagnostic",
            "diagnosticRun",
        ):
            self.assertRegex(target, rf"(?m)^\s+{exported}$")
        self.assertIn("externalInterfaceProfiles", target)
        self.assertIn("staticAuthorityV3 = analysisV3", target)
        self.assertNotIn("staticAuthorityV2", target)
        self.assertNotIn("staticCompletenessReport", target)
        self.assertNotIn("staticCompletenessGate", target)
        self.assertIn("allowDeferredPotentialTransfers = false", target)
        self.assertIn('candidateMode = "structural-diagnostic"', target)
        self.assertIn("allowDeferredPotentialTransfers = true", target)
        self.assertIn("diagnosticFailureTrap = true", target)
        self.assertNotIn("diagnosticExternalSiteProposals", target)
        self.assertNotIn("diagnosticCallableExternalRuntime", target)
        self.assertIn("nativeEnginePlan", target)
        self.assertIn("nativeRuntimePackage", target)

    def test_headless_diagnostic_run_decodes_candidate_failure_evidence(self) -> None:
        module = (
            ROOT / "nix" / "stage-b-headless-diagnostic-run.nix"
        ).read_text(encoding="utf-8")

        self.assertIn("spaghetti_extractor.stage_b_native_diagnostic", module)
        self.assertIn("decode_stage_b_native_diagnostic_file", module)
        self.assertIn("diagnostic-decoded.json", module)
        self.assertIn("original_runtime_observations: $original_runtime_observations", module)
        self.assertIn("no behavioral acceptance authority", module)

    def test_candidate_generation_has_only_v3_authority(self) -> None:
        module = (ROOT / "nix" / "stage-b-hybrid-candidate.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn("candidateAuthorityReport", module)
        self.assertIn("candidateAuthorityGate", module)
        self.assertIn("build_stage_b_candidate_authority_v3", module)
        self.assertIn("require_stage_b_candidate_authority_v3", module)
        self.assertIn("final_authority=", module)
        self.assertNotIn("final_static_hybrid_audit", module)
        self.assertNotIn("authority_bundle", module)
        self.assertIn('candidateMode ? "static-closed"', module)
        self.assertIn('"structural-diagnostic"', module)
        self.assertIn("candidate_authority=optional_path", module)
        self.assertIn("if staticClosed then", module)
        self.assertNotIn("write_static_hybrid_closure_receipt", module)
        self.assertNotIn("write_final_candidate_authorization", module)
        self.assertNotIn("stage-b-final-candidate-generation-authorization-v1", module)
        self.assertIn("externalSiteProposals ? null", module)
        self.assertIn("external_site_proposals=", module)
        self.assertIn(
            "proposal-only external-site evidence is diagnostic-only", module
        )

    def test_checked_external_sites_and_callbacks_are_native_v3_phases(self) -> None:
        external = (
            ROOT / "src" / "spaghetti_extractor" / "analysis_v3"
            / "external_sites.py"
        ).read_text(encoding="utf-8")
        callbacks = (
            ROOT / "src" / "spaghetti_extractor" / "analysis_v3"
            / "callbacks.py"
        ).read_text(encoding="utf-8")
        self.assertIn("CANONICAL_EXTERNAL_SITES_PHASE_V3 = map_units(", external)
        self.assertIn("CALLBACK_AUTHORITY_PHASE_V3 = map_units(", callbacks)
        self.assertNotIn("external_site_proposals_v2", external)
        self.assertNotIn("callback_entry_contract_v2", callbacks)

    def test_fallback_coverage_is_v3_and_has_no_v1_authority_dependency(self) -> None:
        module = (ROOT / "nix" / "stage-b-hybrid-candidate.nix").read_text(
            encoding="utf-8"
        )
        start = module.index("fallbackCoverageReceipt =")
        end = module.index("candidateAuthorityReport =", start)
        phase = module[start:end]
        receipt = (
            ROOT / "nix" / "stage-b-fallback-coverage-receipt.nix"
        ).read_text(encoding="utf-8")

        self.assertIn("stage-b-fallback-coverage-receipt.nix", phase)
        self.assertIn("stage-b-fallback-coverage-receipt-v3", receipt)
        self.assertIn("structural_units_require_lowering", receipt)
        self.assertIn("rooted_containment_authority", receipt)
        self.assertNotIn("static_completeness_report", phase)
        self.assertNotIn("staticCompletenessReport", phase)

    def test_mutable_memory_authority_uses_native_version_records(self) -> None:
        memory = (
            ROOT / "src" / "spaghetti_extractor" / "analysis_v3"
            / "memory_records.py"
        ).read_text(encoding="utf-8")
        versions = (
            ROOT / "src" / "spaghetti_extractor" / "analysis_v3"
            / "memory_versions.py"
        ).read_text(encoding="utf-8")
        self.assertIn("MemoryVersionRecordV3", memory)
        self.assertIn("check_memory_versions_completeness_v3", versions)
        self.assertNotIn("global_slot_authority_replay_v2", versions)

    def test_v3_root_isa_and_exception_phases_use_checked_records(self) -> None:
        root = ROOT / "src" / "spaghetti_extractor" / "analysis_v3"
        launch = (root / "root_closure.py").read_text(encoding="utf-8")
        isa = (root / "isa_qualification.py").read_text(encoding="utf-8")
        exceptional = (root / "exceptional_transitions.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("LAUNCH_ROOT_CLOSURE_PHASE_V3", launch)
        self.assertIn("ISA_QUALIFICATION_PHASE_V3", isa)
        self.assertIn("EXCEPTIONAL_TRANSITIONS_PHASE_V3", exceptional)
        self.assertIn("check_launch_root_closure_completeness_v3", launch)
        self.assertIn("check_isa_qualification_completeness_v3", isa)
        self.assertIn("check_exceptional_transitions_completeness_v3", exceptional)

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

    def test_flake_exposes_only_v3_static_authority(self) -> None:
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        self.assertIn("mkAnalysisAuthorityV3", flake)
        self.assertIn("dxball-final-authority-v3", flake)
        self.assertNotIn("mkStaticHybridAuthorityV2Graph", flake)
        self.assertNotIn("dxball-static-hybrid-authority-v2", flake)

    def test_v3_nix_fixture_covers_structural_and_dependency_mutations(self) -> None:
        fixture = (ROOT / "tests" / "unit" / "nix_v3" / "evaluation.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("structuralMutation", fixture)
        self.assertIn("recordMutation", fixture)
        self.assertIn("edgeMutation", fixture)
        self.assertIn("phaseSourceMutation", fixture)

    def test_legacy_nix_authority_graph_is_removed(self) -> None:
        self.assertFalse((ROOT / "nix" / "stage-b-static-hybrid-authority-v2.nix").exists())
        self.assertFalse(
            (ROOT / "nix" / "tests" / "stage-b-static-hybrid-authority-v2.nix").exists()
        )


if __name__ == "__main__":
    unittest.main()
