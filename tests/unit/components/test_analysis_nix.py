from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


class ComponentAnalysisNixTests(unittest.TestCase):
    def test_generic_analysis_is_static_content_addressed_and_candidate_free(self) -> None:
        analysis = (ROOT / "nix" / "component-analysis.nix").read_text(encoding="utf-8")
        discovery = (ROOT / "nix" / "component-discovery.nix").read_text(encoding="utf-8")

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
        self.assertNotIn("pythonSource", analysis)
        self.assertIn('phaseRole = "proposal"', analysis)
        self.assertIn("mkPythonClosure = suffix: modules:", analysis)
        self.assertIn("close_state_machine_rooted_direct_control", analysis)
        self.assertNotIn("padding-bridge", analysis)
        self.assertNotIn("padding_bridge", analysis)
        self.assertIn("executes_original_binary", analysis)
        self.assertIn('"$out/coverage.json"', discovery)
        self.assertIn(".exact.complete and .potential.complete", discovery)
        self.assertIn('"$out/proposal-index.json"', discovery)

    def test_component_dag_has_granular_phase_inputs(self) -> None:
        module = (ROOT / "nix" / "component-workflow.nix").read_text(
            encoding="utf-8"
        )
        for declaration in (
            "component-resolution-v2",
            "component-contract-v2",
            "component-source-package-v2",
            "component-evidence-v3",
            "component-qualification-v3",
            "component-activation-plan-v3",
            "component-sources-v3",
        ):
            self.assertIn(declaration, module)
        self.assertIn("__contentAddressed = true;", module)
        self.assertNotIn("component_workspace", module)
        self.assertNotIn("identity_authorizes_activation", module)
        self.assertIn("sourcePackages", module)
        self.assertIn("mkDevelopmentDeclaration", module)
        self.assertIn("developmentDeclarations", module)
        development_body = module.split(
            "mkDevelopmentDeclaration =", 1
        )[1].split("mkSourcePaths =", 1)[0]
        self.assertNotIn("proposalInput", development_body)
        self.assertNotIn("resolutionSlices", development_body)
        self.assertNotIn("machineIr", development_body)
        development_package = module.split(
            "developmentPackages =", 1
        )[1].split("mkActivationPlan =", 1)[0]
        self.assertNotIn("resolutionSlices", development_package)
        self.assertIn('name = "declaration"', development_package)
        self.assertIn("evidences", module)
        self.assertIn("exhaustive-finite-domain-v1", module)
        self.assertIn("runtimeConfigurations", module)
        self.assertIn("runtimeFor", module)
        self.assertIn("runtimePackages", module)
        self.assertIn("machineIr interpreterPackage", module)
        self.assertIn("implementation=pathlib.Path(sys.argv[2])", module)
        self.assertIn("proposalInput.selectedProposals", module)
        resolution_body = module.split(
            'resolution = pkgs.runCommand', 1
        )[1].split('mkContract =', 1)[0]
        self.assertNotIn("${componentProposals}", resolution_body)
        contract_gate = module.split(
            '.format == "spaghetti-extractor-component-contract-package-v2"', 1
        )[1].split('"$out/contract.json"', 1)[0]
        self.assertIn('.status == "violated"', contract_gate)

        proposal_input = (
            ROOT / "nix" / "component-proposal-input.nix"
        ).read_text(encoding="utf-8")
        self.assertIn("builtins.readFile", proposal_input)
        self.assertIn("builtins.toFile", proposal_input)
        self.assertIn("__contentAddressed = true;", proposal_input)

    def test_component_runtime_is_factored_out_of_candidate_construction(self) -> None:
        candidate = (
            ROOT / "nix" / "candidate-hybrid.nix"
        ).read_text(encoding="utf-8")
        sdk = (ROOT / "nix" / "target-sdk.nix").read_text(encoding="utf-8")

        self.assertIn("interpreterPackage,", candidate)
        self.assertIn("componentRuntimePackage,", candidate)
        self.assertIn("static-closed candidates require a component runtime", candidate)
        self.assertNotIn("import ./candidate-interpreter-package.nix", candidate)
        self.assertNotIn("import ./component-runtime-package.nix", candidate)
        self.assertIn(
            "componentRuntimeFor = if hasComponents then components.runtimeFor else null",
            sdk,
        )
        self.assertIn("componentRuntimePackage = components.mkRuntime", sdk)
        self.assertIn("interpreterPackage = interpreterSupport", sdk)

    def test_pe32_bundle_exports_standard_configuration_families(self) -> None:
        sdk = (ROOT / "nix" / "target-sdk.nix").read_text(encoding="utf-8")

        self.assertIn("mkPe32Bundle", sdk)
        self.assertIn('"spaghetti-extractor-target-bundle-v3"', sdk)
        self.assertIn("workflow.hasComponents", sdk)
        self.assertIn("runtimes = workflow.componentRuntimes", sdk)
        self.assertIn("static = lib.mapAttrs", sdk)
        self.assertIn("diagnostics = {", sdk)
        self.assertIn("runtime-frontiers = workflow.runtimeFrontiers", sdk)
        self.assertNotIn("diagnostic = lib.mapAttrs", sdk)
        self.assertNotIn("target = {\n    bundle =", sdk)

    def test_interpreter_package_is_a_generic_content_addressed_phase(self) -> None:
        module = (ROOT / "nix" / "machine-ir-support-package.nix").read_text(encoding="utf-8")
        gate = (ROOT / "nix" / "candidate-interpreter-package.nix").read_text(encoding="utf-8")
        self.assertIn("machineIr", module)
        self.assertIn("capabilityAnalysis", module)
        self.assertNotIn("finalAuthorityGate", module)
        self.assertIn("supportPackage", gate)
        self.assertIn("executionGate", gate)
        self.assertNotIn("finalAuthorityGate", gate)
        self.assertIn("write_spx_interpreter_package", module)
        for digest in (
            "program_source_sha256",
            "interpreter_source_sha256",
            "runtime_header_sha256",
            "interpreter_header_sha256",
            "interpreter_internal_header_sha256",
            "atomics_header_sha256",
            "atomics_backend_header_sha256",
            "atomics_source_sha256",
        ):
            self.assertIn(digest, module)
        self.assertIn("__contentAddressed = true;", module)
        self.assertNotIn("spaghetti-extractor-jq", module.lower())
        self.assertNotIn("wine", module.lower())

    def test_fallback_support_does_not_use_ifd_or_prebuild_executable_code(self) -> None:
        workflow = (ROOT / "nix" / "authority-workflow.nix").read_text(
            encoding="utf-8"
        )
        implementation = (
            ROOT / "nix" / "authority-input-implementation-capabilities.nix"
        ).read_text(encoding="utf-8")

        self.assertIn("fallbackCapabilityAnalysis", workflow)
        self.assertIn("capabilityAnalysis = fallbackCapabilityAnalysis", workflow)
        self.assertIn("fallbackSupport", workflow)
        self.assertNotIn("fallbackInterpreter", workflow)
        self.assertNotIn("preImplementationReadiness", workflow)
        self.assertNotIn("authority-preimplementation-readiness.nix", workflow)
        self.assertNotIn("builtins.readFile", workflow[workflow.index(
            "fallbackCapabilityAnalysis ="
        ):workflow.index("diagnosticsArtifacts =")])
        self.assertIn("expectedRecordIds = null", workflow)
        self.assertIn("itemIds = machineInput.expectedRecordIds", workflow)
        self.assertIn("--capability-analysis", implementation)
        self.assertNotIn("--implementation-file", implementation)

    def test_native_object_graph_normalizes_ifd_inputs_into_ca_units(self) -> None:
        module = (ROOT / "nix" / "candidate-native-object-graph.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("builtins.readFile", module)
        self.assertNotIn("builtins.path", module)
        self.assertNotIn("unsafeDiscardStringContext", module)
        self.assertIn("native-source-bundle-v1", module)
        self.assertIn(
            "compile_spx_interpreter_native_source_bundle", module
        )
        self.assertIn("assemble_spx_interpreter_native_objects", module)
        self.assertIn("__contentAddressed = true;", module)
        self.assertIn("compiledObjects", module)
        self.assertIn("spaghetti-extractor-interpreter-native-object-graph-v2", module)
        graph_declaration = module[
            module.index('graph = pkgs.runCommand') : module.index("graphPayload =")
        ]
        self.assertNotIn("__contentAddressed = true;", graph_declaration)

    def test_machine_ir_preparation_is_a_distinct_reusable_phase(self) -> None:
        module = (ROOT / "nix" / "component-analysis.nix").read_text(
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
        self.assertIn('"spaghetti_extractor.authority_inputs.finite_values"', module)
        preparation = module[
            module.index("machineIrPreparationPythonSource") :
            module.index("machineIrExportPythonSource")
        ]
        self.assertNotIn("finite_value_domain", preparation)
        self.assertIn("finite_dataflow_factory=FiniteU32Dataflow", module)

    def test_component_analysis_contains_no_legacy_authority_loop(self) -> None:
        module = (ROOT / "nix" / "component-analysis.nix").read_text(
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
            ROOT / "src" / "spaghetti_extractor" / "authority" / "registry.py"
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
            ROOT / "src" / "spaghetti_extractor" / "authority"
            / "transition_summaries.py"
        ).read_text(encoding="utf-8")
        self.assertIn("map_units(", transition)
        self.assertIn('source_input="exact_units"', transition)
        self.assertNotIn("transition_summary_v2", transition)
        self.assertNotIn("authority_bindings_v2", transition)

    def test_memory_authority_is_a_dependency_scc_phase(self) -> None:
        memory = (
            ROOT / "src" / "spaghetti_extractor" / "authority"
            / "memory_versions.py"
        ).read_text(encoding="utf-8")
        self.assertIn("map_sccs(", memory)
        self.assertIn('schedule_record_inputs=("semantic_index",)', memory)
        self.assertIn('"transition_summaries": "transition-summaries-v3"', memory)

    def test_inductive_authority_consumes_native_checked_summaries(self) -> None:
        inductive = (
            ROOT / "src" / "spaghetti_extractor" / "authority" / "inductive.py"
        ).read_text(encoding="utf-8")
        self.assertIn("map_sccs(", inductive)
        self.assertIn('"memory_versions": "memory-versions-v3"', inductive)
        self.assertIn('"transition_summaries": "transition-summaries-v3"', inductive)
        self.assertNotIn("invariant_certificate_v2", inductive)

    def test_authority_graph_is_registry_derived_not_manually_plumbed(self) -> None:
        graph = (ROOT / "nix" / "authority-graph-v3.nix").read_text(
            encoding="utf-8"
        )
        manifest = (ROOT / "nix" / "authority-graph-manifest.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("graph.phases", graph)
        self.assertIn("authority_graph_manifest_v3", manifest)
        graph_module = (
            ROOT / "src" / "spaghetti_extractor" / "authority" / "graph.py"
        ).read_text(encoding="utf-8")
        self.assertIn("AUTHORITY_PHASE_REGISTRY_V3", graph_module)
        self.assertNotIn("staticHybridAuthorityV2", graph)

    def test_authority_graph_plumbing_uses_narrow_python_closures(self) -> None:
        graph = (ROOT / "nix" / "authority-graph-v3.nix").read_text(
            encoding="utf-8"
        )
        gate = (
            ROOT / "nix" / "authority-final-gate.nix"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "artifactSetPythonSource = import ./python-module-closure.nix",
            graph,
        )
        self.assertIn('"spaghetti_extractor.artifacts.artifact_set"', graph)
        self.assertIn('"spaghetti_extractor.artifacts.io"', graph)
        self.assertIn(
            "planningPythonSource = import ./python-module-closure.nix", graph
        )
        self.assertIn(
            'modules = [ "spaghetti_extractor.authority.planning" ];',
            graph,
        )
        self.assertIn("pythonSource = artifactSetPythonSource;", graph)
        self.assertIn("pythonSource = planningPythonSource;", graph)
        self.assertIn("pythonClosure = import ./python-module-closure.nix", gate)
        self.assertIn('"spaghetti_extractor.authority.final_authority"', gate)
        self.assertIn('"spaghetti_extractor.artifacts.io"', gate)

    def test_late_authority_families_have_independent_phase_boundaries(self) -> None:
        registry = (
            ROOT / "src" / "spaghetti_extractor" / "authority" / "registry.py"
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
        source_plan = (ROOT / "nix" / "authority-source-plan.nix").read_text(
            encoding="utf-8"
        )
        machine_input = (
            ROOT / "nix" / "authority-machine-ir-input.nix"
        ).read_text(encoding="utf-8")
        self.assertIn("prepare_analysis_source_v3", source_plan)
        self.assertIn('"${preparation}/plan.json"', machine_input)
        self.assertIn("preplannedBoundaries", machine_input)
        self.assertIn("builtins.toFile", machine_input)

    def test_native_v3_module_closure_excludes_legacy_authority(self) -> None:
        index = json.loads(
            (ROOT / "nix/generated/python-module-index.json").read_text(encoding="utf-8")
        )["modules"]
        pending = ["spaghetti_extractor.authority.registry"]
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
            ROOT / "src" / "spaghetti_extractor" / "authority"
            / "final_authority.py"
        ).read_text(encoding="utf-8")
        self.assertIn("_check_unit_inventory", final)
        self.assertIn("_check_inductive_authority", final)
        self.assertIn("validate_authority_decision_v3", final)
        self.assertNotIn("static_hybrid_final_audit_v2", final)

    def test_candidate_builder_validates_v3_authority_twice(self) -> None:
        builder = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(
                (ROOT / "src" / "spaghetti_extractor" / "candidate").glob(
                    "build*.py"
                )
            )
        )
        self.assertGreaterEqual(builder.count("_validate_candidate_authority_v3("), 3)
        self.assertNotIn("spx_candidate_authority_v2", builder)
        self.assertNotIn("final_static_hybrid_audit", builder)

    def test_isa_and_fallback_bindings_are_v3_native(self) -> None:
        isa = (
            ROOT / "src" / "spaghetti_extractor" / "authority"
            / "isa_qualification.py"
        ).read_text(encoding="utf-8")
        fallback = (
            ROOT / "src" / "spaghetti_extractor" / "authority"
            / "fallback_coverage.py"
        ).read_text(encoding="utf-8")
        self.assertIn("ISA_QUALIFICATION_PHASE_V3", isa)
        self.assertIn("FALLBACK_COVERAGE_PHASE_V3", fallback)
        self.assertIn('unit_aligned_inputs=("isa_qualification",)', fallback)

    def test_hybrid_candidate_uses_phase_specific_python_closures(self) -> None:
        module = (ROOT / "nix" / "candidate-hybrid.nix").read_text(
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
            ROOT / "nix" / "machine-ir-support-package.nix"
        ).read_text(encoding="utf-8")
        self.assertIn("phasePythonSource", interpreter)
        self.assertIn("__contentAddressed = true;", closure)
        self.assertIn("python-module-index.json", closure)
        self.assertIn("role-checked-module-index-v3", closure)
        self.assertIn("role-derived-source-class-v1", closure)
        self.assertIn("unauthorizedModules", closure)
        self.assertNotIn("python-module-validation.nix", closure)
        self.assertIn("ast.parse", closure)
        self.assertIn("python-module-closure.json", closure)
        self.assertIn('package = module.split(".", 1)[0]', closure)
        self.assertIn("run `nix run .#dev -- refresh`", closure)

    def test_runtime_frontier_report_cannot_emit_or_execute_a_candidate(self) -> None:
        module = (
            ROOT / "nix" / "runtime-frontier-report.nix"
        ).read_text(encoding="utf-8")

        self.assertIn("build_runtime_frontier_report", module)
        self.assertIn(".policy.object_code_emitted", module)
        self.assertIn("runtime frontier report emitted implementation material", module)
        self.assertNotIn("wine ", module.lower())

    def test_candidate_suites_require_authority_and_headless_wine(self) -> None:
        module = (
            ROOT / "nix" / "candidate-test-suite.nix"
        ).read_text(encoding="utf-8")

        self.assertIn("spaghetti-extractor-release-acceptance-v1", module)
        self.assertIn(".status == \"complete\"", module)
        self.assertIn(".release_accepted", module)
        self.assertIn(".executable", module)
        self.assertIn("xvfb-run -a", module)
        self.assertIn("WINEDEBUG=-all", module)
        self.assertIn("candidate_only: true", module)
        self.assertIn("original_binary_executed: false", module)

    def test_candidate_generation_uses_structural_execution_gate(self) -> None:
        module = (ROOT / "nix" / "candidate-hybrid.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn("structuralExecutionGate", module)
        self.assertIn("spaghetti-extractor-structural-executable-v1", module)
        self.assertIn("structural_execution_receipt=", module)
        self.assertNotIn("final_static_hybrid_audit", module)
        self.assertNotIn("authority_bundle", module)
        self.assertNotIn("candidateMode ?", module)
        self.assertNotIn('"structural-diagnostic"', module)
        self.assertIn("candidate_authority=None", module)
        self.assertIn('execution_scope == "structural-executable-v1"', module)
        self.assertNotIn("write_static_hybrid_closure_receipt", module)
        self.assertNotIn("write_final_candidate_authorization", module)
        self.assertNotIn("spaghetti-extractor-final-candidate-generation-authorization-v1", module)
        self.assertNotIn("externalSiteProposals", module)
        self.assertNotIn("external_site_proposals=", module)
        self.assertIn("region_override_package=optional_path", module)
        self.assertNotIn("proposal-only external-site evidence", module)

    def test_candidate_policy_and_portable_gate_share_rooted_projection(self) -> None:
        projection = (
            ROOT / "nix" / "rooted-behavioral-projection.nix"
        ).read_text(encoding="utf-8")
        workflow = (ROOT / "nix" / "component-workflow.nix").read_text(
            encoding="utf-8"
        )
        sdk = (ROOT / "nix" / "target-sdk.nix").read_text(encoding="utf-8")

        self.assertIn("derive_rooted_behavioral_projection_v1", projection)
        self.assertIn("load_rooted_behavioral_projection_v1", workflow)
        self.assertIn("rooted_projection=", workflow)
        self.assertIn("rootedBehavioralProjection", sdk)
        self.assertNotIn("wine", projection.lower())

    def test_checked_external_sites_and_callbacks_are_native_v3_phases(self) -> None:
        external = (
            ROOT / "src" / "spaghetti_extractor" / "authority"
            / "external_site_checker.py"
        ).read_text(encoding="utf-8")
        callbacks = (
            ROOT / "src" / "spaghetti_extractor" / "authority"
            / "callbacks.py"
        ).read_text(encoding="utf-8")
        self.assertIn("CANONICAL_EXTERNAL_SITES_PHASE_V3 = map_units(", external)
        self.assertIn("CALLBACK_AUTHORITY_PHASE_V3 = map_units(", callbacks)
        self.assertNotIn("external_site_proposals_v2", external)
        self.assertNotIn("callback_entry_contract_v2", callbacks)

    def test_candidate_uses_reusable_machine_ir_support(self) -> None:
        module = (ROOT / "nix" / "candidate-hybrid.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("interpreterPackage", module)
        self.assertIn("structuralExecutionGate", module)
        self.assertNotIn("fallbackCoverageReceipt", module)
        self.assertNotIn("candidateAuthorityReport", module)

    def test_mutable_memory_authority_uses_native_version_records(self) -> None:
        memory = (
            ROOT / "src" / "spaghetti_extractor" / "authority"
            / "memory_records.py"
        ).read_text(encoding="utf-8")
        versions = (
            ROOT / "src" / "spaghetti_extractor" / "authority"
            / "memory_versions.py"
        ).read_text(encoding="utf-8")
        self.assertIn("MemoryVersionRecordV3", memory)
        self.assertIn("check_memory_versions_completeness_v3", versions)
        self.assertNotIn("global_slot_authority_replay_v2", versions)

    def test_v3_root_isa_and_exception_phases_use_checked_records(self) -> None:
        root = ROOT / "src" / "spaghetti_extractor" / "authority"
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
            ROOT / "nix" / "external-interface-profile.nix"
        ).read_text(encoding="utf-8")

        self.assertIn("sdkHeaders ?", module)
        self.assertIn("extract_external_interface_profile", module)
        self.assertIn("__contentAddressed = true;", module)
        self.assertNotIn("dxball", module.lower())

    def test_static_source_excludes_nix_orchestration_files(self) -> None:
        context = (ROOT / "nix" / "toolkit-context.nix").read_text(
            encoding="utf-8"
        )
        analysis_start = context.index("staticPythonFiles =")
        analysis_end = context.index("staticSource =", analysis_start)
        analysis_source = context[analysis_start:analysis_end]

        self.assertIn("../src", analysis_source)
        self.assertNotIn("../nix", analysis_source)

    def test_stable_sdk_exposes_only_generic_v3_static_authority_constructor(self) -> None:
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        sdk = (ROOT / "nix" / "target-sdk.nix").read_text(encoding="utf-8")
        self.assertIn("mkTargetSdk", flake)
        self.assertIn("authority = authorityWorkflow", sdk)
        self.assertIn("workflow.pe32", sdk)
        self.assertIn("authority-workflow.nix", sdk)
        self.assertNotIn("dxball-final-authority-v3", flake)
        self.assertNotIn("mkStaticHybridAuthorityV2Graph", flake)

    def test_v3_nix_fixture_covers_structural_and_dependency_mutations(self) -> None:
        fixture = (ROOT / "tests" / "unit" / "nix_v3" / "evaluation.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("structuralMutation", fixture)
        self.assertIn("recordMutation", fixture)
        self.assertIn("edgeMutation", fixture)
        self.assertIn("phaseSourceMutation", fixture)

    def test_legacy_nix_authority_graph_is_removed(self) -> None:
        self.assertFalse((ROOT / "nix" / "spaghetti-extractor-static-hybrid-authority-v2.nix").exists())
        self.assertFalse(
            (ROOT / "nix" / "tests" / "spaghetti-extractor-static-hybrid-authority-v2.nix").exists()
        )

    def test_static_candidate_consumes_canonical_external_site_authority(self) -> None:
        candidate = (ROOT / "nix" / "candidate-hybrid.nix").read_text(
            encoding="utf-8"
        )
        authority_workflow = (ROOT / "nix" / "authority-workflow.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'graph.phases."canonical-external-sites-v3".artifact', candidate
        )
        for phase in (
            "launch-root-closure-v3",
            "indirect-target-certificates-v3",
            "parametric-scc-summaries-v3",
        ):
            self.assertIn(f'graph.phases."{phase}".artifact', candidate)
        self.assertIn(
            'outputs ? [ "canonical-external-sites-v3" "final-authority-v3" ]',
            authority_workflow,
        )
        self.assertIn("canonical_external_sites=", candidate)
        self.assertNotIn("callableExternalRuntimeContract", candidate)
        self.assertNotIn("callable_external_contract=", candidate)
        self.assertFalse(
            (ROOT / "nix" / "callable-external-runtime-contract.py").exists()
        )

    def test_component_external_sites_are_pre_isa_and_binding_scoped(self) -> None:
        authority = (ROOT / "nix" / "authority-workflow.nix").read_text(
            encoding="utf-8"
        )
        components = (ROOT / "nix" / "component-workflow.nix").read_text(
            encoding="utf-8"
        )
        sdk = (ROOT / "nix" / "target-sdk.nix").read_text(encoding="utf-8")

        target_start = authority.index("targetEvidenceExternalArtifacts =")
        target_end = authority.index("targetEvidenceGraph =", target_start)
        target_inputs = authority[target_start:target_end]
        self.assertIn("generatedTargetEvidenceArtifact", target_inputs)
        self.assertNotIn("generatedISAEvidenceArtifact", target_inputs)
        self.assertIn(
            'externalSiteGraph.phases."canonical-external-sites-v3".artifact',
            authority,
        )
        self.assertIn(
            "&& liftUnitUsesExternalSites liftUnit",
            components,
        )
        self.assertIn(
            "canonicalExternalSites = authority.componentExternalSites;",
            sdk,
        )

if __name__ == "__main__":
    unittest.main()
