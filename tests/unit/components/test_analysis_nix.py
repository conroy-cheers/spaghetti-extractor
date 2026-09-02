from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TESTKIT = {
    "resources": (
        "nix/component-v6-work-package.nix",
        "nix/qualified-runtime-provider-v2.nix",
        "nix/native-realization-v2.nix",
    )
}


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

    def test_component_dag_is_the_direct_v6_clean_cut(self) -> None:
        module = (ROOT / "nix" / "component-workflow.nix").read_text(
            encoding="utf-8"
        )
        for phase in (
            "component-v5-interface-package.nix",
            "component-source-package-v3.nix",
            "component-semantic-slice-v2.nix",
            "component-v6-work-package.nix",
        ):
            self.assertIn(phase, module)
        self.assertIn("component-v5-index.nix", module)
        source_package = (
            ROOT / "nix" / "component-source-package-v3.nix"
        ).read_text(encoding="utf-8")
        self.assertIn("operation_symbols", source_package)
        self.assertIn("directV6ProviderIds", module)
        self.assertIn("selectedComponentIdsByConfiguration", module)
        self.assertIn("v6SemanticSlices", module)
        self.assertIn("v6WorkPackages", module)
        for retired in (
            "component-v5-contract.nix",
            "component-v5-semantic-refinement.nix",
            "component-v5-relation.nix",
            "component-v5-external-sites.nix",
            "component-v5-work-package.nix",
            "component-v4-implementation.nix",
            "component-v4-dependency-graph.nix",
            "component-v4-activation-plan.nix",
        ):
            self.assertFalse((ROOT / "nix" / retired).exists())
            self.assertNotIn(retired, module)
        self.assertNotIn("component-source-package-v2", module)
        self.assertNotIn("component-activation-plan-v3", module)
        self.assertNotIn("developmentDeclarations", module)
        self.assertNotIn("relationKernel", module)
        self.assertNotIn("interactionContractCatalog", module)

    def test_v6_work_package_projects_one_canonical_semantic_module(self) -> None:
        workflow = (ROOT / "nix" / "component-workflow.nix").read_text(
            encoding="utf-8"
        )
        module = (ROOT / "nix" / "component-v6-work-package.nix").read_text(
            encoding="utf-8"
        )
        projection = (
            ROOT / "src/spaghetti_extractor/components/work_package_v6.py"
        ).read_text(encoding="utf-8")
        self.assertIn("linkedSemanticModule", module)
        self.assertNotIn("linkedSemanticModuleV2", module)
        self.assertIn("interfacePackage", module)
        self.assertIn("bindingIntent", module)
        self.assertIn("behavioralCPackage", module)
        self.assertNotIn("transferPlan", module)
        self.assertNotIn("machineIr", module)
        self.assertNotIn("machineIrManifest", module)
        self.assertIn("LinkedSemanticModuleV2.load", projection)
        self.assertIn("build_component_semantic_slice_v2", projection)
        self.assertIn("faithful_c_slices", projection)
        self.assertNotIn("ComponentContractV4", projection)
        self.assertNotIn("ComponentMachineBindingV5", projection)
        self.assertEqual(workflow.count("interfaceIntentPath id"), 1)
        self.assertIn("interfacePackage = v5Interfaces.${id}.derivation", workflow)
        self.assertIn(
            "semanticSlice = v6SemanticSlices.${providerId}.semanticSlice",
            workflow,
        )

    def test_direct_component_provider_reuses_the_exact_runtime_abi(self) -> None:
        component = (
            ROOT / "nix" / "portable-c-work-package-provider-v2.nix"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "src/spaghetti_extractor/semantic_providers/portable_c_work_package.py"
        ).read_text(encoding="utf-8")

        self.assertIn("semanticSlice", component)
        self.assertIn("bindingIntent", component)
        self.assertIn("interfacePackage", component)
        self.assertIn("sourcePackage", component)
        self.assertIn("write_portable_c_work_package_provider_v2", component)
        self.assertNotIn("componentImplementations", component)
        self.assertNotIn("component-implementation-v4", component)
        self.assertIn(
            "from ..transfer.runtime_abi import exact_runtime_header",
            implementation,
        )
        self.assertFalse(
            (ROOT / "src/spaghetti_extractor/candidate/runtime_abi.py").exists()
        )

    def test_legacy_component_runtime_is_absent_from_candidate_construction(self) -> None:
        realization = (ROOT / "nix" / "native-realization-v2.nix").read_text(
            encoding="utf-8"
        )
        sdk = (ROOT / "nix" / "target-sdk.nix").read_text(encoding="utf-8")

        self.assertNotIn("behavioralCPackage", realization)
        self.assertIn("linkedSemanticModule", realization)
        self.assertIn("providerQualifications", realization)
        self.assertNotIn("intrinsicProviderPackage", realization)
        self.assertNotIn("componentRuntimePackage", realization)
        self.assertNotIn("component_runtime_package", realization)
        self.assertFalse((ROOT / "nix" / "candidate-deployment.nix").exists())
        self.assertFalse((ROOT / "nix" / "native-linked-skeleton.nix").exists())
        self.assertNotIn("componentRuntimeFor", sdk)
        self.assertNotIn("componentRuntimes", sdk)
        self.assertNotIn("componentRuntimePackage = components.mkRuntime", sdk)

    def test_pe32_bundle_exports_standard_configuration_families(self) -> None:
        sdk = (ROOT / "nix" / "target-sdk.nix").read_text(encoding="utf-8")

        self.assertIn("mkPe32Bundle", sdk)
        self.assertIn('"spaghetti-extractor-target-bundle-v3"', sdk)
        self.assertIn("workflow.hasComponents", sdk)
        self.assertIn("semantic-slices-v2 = lib.mapAttrs", sdk)
        self.assertIn("work-packages-v6 = lib.mapAttrs", sdk)
        self.assertNotIn("dependency-graphs-v4", sdk)
        self.assertIn("native-realizations = lib.mapAttrs", sdk)
        self.assertIn("diagnostics = {", sdk)
        self.assertNotIn("runtime-frontiers = workflow.runtimeFrontiers", sdk)
        self.assertNotIn("diagnostic = lib.mapAttrs", sdk)
        self.assertNotIn("target = {\n    bundle =", sdk)

    def test_transfer_capability_is_non_executable_and_content_addressed(self) -> None:
        module = (ROOT / "nix" / "fallback-capability-analysis.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("machineIr", module)
        self.assertIn("write_transfer_capability_analysis", module)
        self.assertIn("transfer_rows_sha256", (
            ROOT / "src/spaghetti_extractor/transfer/capability_analysis.py"
        ).read_text(encoding="utf-8"))
        self.assertNotIn("finalAuthorityGate", module)
        self.assertNotIn("compiler", module)
        self.assertNotIn("object", module)

    def test_fallback_support_does_not_use_ifd_or_prebuild_executable_code(self) -> None:
        capability = (ROOT / "nix/fallback-capability-analysis.nix").read_text(
            encoding="utf-8"
        )
        self.assertFalse((ROOT / "nix/authority-workflow.nix").exists())
        self.assertFalse(
            (ROOT / "nix/authority-input-implementation-capabilities.nix").exists()
        )
        self.assertNotIn("builtins.readFile", capability)
        self.assertNotIn("fallbackInterpreter", capability)
        self.assertNotIn("--implementation-file", capability)

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
        self.assertIn('"spaghetti_extractor.reconstruction.finite_values"', module)
        preparation = module[
            module.index("machineIrPreparationPythonSource") :
            module.index("machineIrExportPythonSource")
        ]
        self.assertIn(
            '"spaghetti_extractor.reconstruction.ir_preparation"', preparation
        )
        self.assertNotIn(
            '"spaghetti_extractor.reconstruction.ir"', preparation
        )
        export = module[
            module.index("machineIrExportPythonSource") :
            module.index("launchAssumptionProjectionPythonSource")
        ]
        self.assertIn('"spaghetti_extractor.reconstruction.ir_export"', export)
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

    def test_v3_target_wide_authority_registry_is_retired(self) -> None:
        authority = ROOT / "src/spaghetti_extractor/authority"
        self.assertFalse((authority / "registry.py").exists())
        self.assertFalse((authority / "graph.py").exists())

    def test_target_authority_manifest_and_final_gate_are_retired(self) -> None:
        self.assertFalse((ROOT / "nix/authority-graph-v3.nix").exists())
        self.assertFalse((ROOT / "nix/authority-graph-v3-boundaries.nix").exists())
        self.assertFalse((ROOT / "nix/authority-graph-v3-packs.nix").exists())
        self.assertFalse((ROOT / "nix/authority-graph-manifest.nix").exists())
        self.assertFalse((ROOT / "nix/authority-final-gate.nix").exists())
        self.assertFalse((ROOT / "nix/authority-workflow.nix").exists())
        self.assertFalse(
            (ROOT / "src/spaghetti_extractor/authority/graph.py").exists()
        )
        self.assertFalse(
            (ROOT / "src/spaghetti_extractor/authority/registry.py").exists()
        )

    def test_linked_module_has_no_separate_invalidation_projection(self) -> None:
        module = (ROOT / "nix/tests/linked-semantic-module.nix").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("linked-semantic-module-invalidation-check", module)
        self.assertNotIn('{ name = "invalidation";', module)
        self.assertNotIn("memoryLimitMiB", module)

    def test_candidate_builder_has_one_realization_build_manifest(self) -> None:
        builder = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(
                (ROOT / "src" / "spaghetti_extractor" / "candidate").glob(
                    "build*.py"
                )
            )
        )
        self.assertIn("NATIVE_REALIZATION_BUILD_MANIFEST_FORMAT", builder)
        self.assertIn("native-realization-build-manifest.json", builder)
        self.assertNotIn("native_module_build_plan", builder)
        self.assertNotIn("candidate_authority", builder)
        self.assertNotIn("spx_candidate_authority_v2", builder)
        self.assertNotIn("final_static_hybrid_audit", builder)

    def test_native_realization_uses_shared_phase_constructor(self) -> None:
        module = (ROOT / "nix" / "native-realization-v2.nix").read_text(
            encoding="utf-8"
        )
        closure = (ROOT / "nix" / "python-module-closure.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn("import ./ca-python-json-phase.nix", module)
        self.assertNotIn("module-runtime-core-package.nix", module)
        self.assertIn("lib.fileset.toSource", closure)
        self.assertIn("builtins.toFile", closure)
        self.assertIn("python-module-index.json", closure)
        self.assertIn("role-checked-module-index-v3", closure)
        self.assertIn("role-derived-source-class-v1", closure)
        self.assertIn("unauthorizedModules", closure)
        self.assertIn("staleSourceModules", closure)
        self.assertIn('builtins.hashFile "sha256"', closure)
        self.assertIn("nix run .#dev -- refresh", closure)
        self.assertNotIn("python-module-validation.nix", closure)
        self.assertNotIn("pkgs.runCommand", closure)
        self.assertNotIn("ast.parse", closure)
        self.assertIn("spaghetti-python-module-closure.json", closure)
        checks = (ROOT / "nix/flake-modules/checks.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("assert !staleSourceClosure.success", checks)
        self.assertIn("assert !(transferEvaluatorPythonClosure ? drvPath)", checks)

    def test_native_linking_consumes_the_canonical_transfer_universe(self) -> None:
        realization = (ROOT / "nix" / "native-realization-v2.nix").read_text(
            encoding="utf-8"
        )
        validation = (
            ROOT / "src/spaghetti_extractor/candidate/build_validation.py"
        ).read_text(encoding="utf-8")
        workflow = (
            ROOT / "src/spaghetti_extractor/candidate/build_workflow.py"
        ).read_text(encoding="utf-8")

        self.assertIn("linked_semantic_module", realization)
        self.assertNotIn("machineIr", realization)
        self.assertNotIn('inputs["machine_ir"]', realization)
        self.assertNotIn('inputs["machine_ir_manifest"]', realization)
        self.assertIn("load_executable_transfer_plan", validation)
        self.assertNotIn("machine_ir: Path", validation)
        self.assertNotIn("machine_ir_manifest: Path", validation)
        self.assertNotIn("machine_ir: Path", workflow)
        self.assertNotIn("machine_ir_manifest: Path", workflow)

    def test_target_sdk_owns_transfer_compilation_outside_authority(self) -> None:
        sdk = (ROOT / "nix/target-sdk.nix").read_text(encoding="utf-8")
        self.assertIn("transferPlan = executableTransferPlan", sdk)
        self.assertNotIn("transferPlan = authority.transferPlan", sdk)
        self.assertFalse((ROOT / "nix/authority-workflow.nix").exists())
        self.assertFalse((ROOT / "nix/authority-input-isa-evidence.nix").exists())
        isa_requirements = (
            ROOT / "nix/semantic-isa-requirements.nix"
        ).read_text(encoding="utf-8")
        self.assertIn("extract_lean_instruction_forms_side", isa_requirements)
        self.assertIn("isaRequirements = semanticISARequirements", sdk)

    def test_qualified_runtime_provider_owns_canonical_runtime_lowering(self) -> None:
        module = (
            ROOT / "nix" / "qualified-runtime-provider-v2.nix"
        ).read_text(encoding="utf-8")

        self.assertIn("write_qualified_runtime_provider_v2", module)
        self.assertIn("linkedSemanticModule", module)
        self.assertIn("behavioralCPackage", module)
        self.assertNotIn("intrinsicProviderPackage", module)
        self.assertNotIn("sharedModuleRuntimePackage", module)

    def test_candidate_suites_require_authority_and_headless_wine(self) -> None:
        module = (
            ROOT / "nix" / "candidate-test-suite.nix"
        ).read_text(encoding="utf-8")

        self.assertIn("spaghetti-extractor-native-realization-v2", module)
        self.assertNotIn("spaghetti-extractor-native-realization-v1", module)
        self.assertIn(".status == \"complete\"", module)
        self.assertIn(".ready_for_observation", module)
        self.assertIn("native_realization_required_before_execution", module)
        self.assertIn("xvfb-run -a", module)
        self.assertIn("WINEDEBUG=-all", module)
        self.assertIn("candidate_only: true", module)
        self.assertIn("original_binary_executed: false", module)

    def test_target_candidate_generation_uses_native_realization_only(self) -> None:
        module = (ROOT / "nix" / "target-sdk.nix").read_text(encoding="utf-8")

        self.assertIn("workflow.nativeRealizations", module)
        self.assertIn("nativeRealizationV2", module)
        self.assertNotIn("nativeRealization = callWith", module)
        self.assertNotIn("implementationSelection = callWith", module)
        self.assertNotIn("generatedBehavioralCProvider = callWith", module)
        self.assertNotIn("workflow.staticCandidates", module)
        self.assertNotIn("workflow.moduleDeployments", module)
        self.assertNotIn("spaghetti-extractor-release-acceptance-v1", module)

    def test_candidate_policy_and_provider_selection_share_exact_transfer_plan(self) -> None:
        workflow = (ROOT / "nix" / "component-workflow.nix").read_text(
            encoding="utf-8"
        )
        sdk = (ROOT / "nix" / "target-sdk.nix").read_text(encoding="utf-8")

        self.assertNotIn("v4ActivationPlans", workflow)
        self.assertNotIn("v4DependencyGraphs", workflow)
        self.assertIn("v6SemanticSlices", workflow)
        self.assertIn("v6WorkPackages", workflow)
        self.assertIn("linkedSemanticModule", workflow)
        self.assertNotIn("linkedSemanticModuleV2", workflow)
        self.assertNotIn("rootedBehavioralProjection", sdk)
        self.assertNotIn("compatibilityExecutionClosure", sdk)
        self.assertIn("linkedSemanticModule.derivation", sdk)
        self.assertNotIn("moduleExecutionClosure", sdk)
        self.assertNotIn("parityExecutionClosure", sdk)
        self.assertIn("transferPlan = transferPlan.plan", sdk)
        self.assertFalse(
            (ROOT / "nix" / "rooted-behavioral-projection.nix").exists()
        )
        self.assertFalse(
            (
                ROOT / "src" / "spaghetti_extractor" / "candidate"
                / "rooted_projection.py"
            ).exists()
        )

    def test_candidate_uses_qualified_objects_and_linked_semantics(self) -> None:
        module = (ROOT / "nix" / "native-realization-v2.nix").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("behavioralCPackage", module)
        self.assertIn("linkedSemanticModule", module)
        self.assertIn("providerQualifications", module)
        self.assertNotIn("intrinsicProviderPackage", module)
        self.assertNotIn("interpreterPackage", module)
        self.assertIn("implementationSelection", module)
        self.assertNotIn("fallbackCoverageReceipt", module)
        self.assertNotIn("candidateAuthorityReport", module)

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

    def test_lean_kernel_source_has_an_independent_cache_identity(self) -> None:
        context = (ROOT / "nix" / "toolkit-context.nix").read_text(
            encoding="utf-8"
        )
        start = context.index("leanSourceFiles =")
        end = context.index("staticPythonFiles =", start)
        lean_source = context[start:end]

        self.assertIn("pkgs.lib.fileset.toSource", lean_source)
        self.assertIn("leanSourceFiles = ../src/spaghetti_extractor/lean;", lean_source)
        self.assertIn("root = leanSourceFiles;", lean_source)
        self.assertIn("fileset = leanSourceFiles;", lean_source)

    def test_stable_sdk_does_not_expose_the_retired_authority_constructor(self) -> None:
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        sdk = (ROOT / "nix" / "target-sdk.nix").read_text(encoding="utf-8")
        self.assertIn("mkTargetSdk", flake)
        self.assertNotIn("authority = authorityWorkflow", sdk)
        self.assertNotIn("authorityWorkflow =", sdk)
        self.assertNotIn("authority-workflow.nix", sdk)
        self.assertIn("workflow.pe32", sdk)
        self.assertNotIn("dxball-final-authority-v3", flake)
        self.assertNotIn("mkStaticHybridAuthorityV2Graph", flake)

    def test_legacy_nix_authority_graph_is_removed(self) -> None:
        self.assertFalse((ROOT / "nix" / "spaghetti-extractor-static-hybrid-authority-v2.nix").exists())
        self.assertFalse(
            (ROOT / "nix" / "tests" / "spaghetti-extractor-static-hybrid-authority-v2.nix").exists()
        )

    def test_native_realization_consumes_canonical_execution_universe(self) -> None:
        candidate = (ROOT / "nix" / "native-realization-v2.nix").read_text(
            encoding="utf-8"
        )
        runtime = (ROOT / "nix" / "qualified-runtime-provider-v2.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("linkedSemanticModule", candidate)
        self.assertIn("implementationSelection", candidate)
        self.assertIn("write_qualified_runtime_provider_v2", runtime)
        for retired_runtime_input in (
            "canonicalExternalSites",
            "callbackAuthority",
            "rootClosure",
            "targetCertificates",
            "parametricSummaries",
        ):
            self.assertNotIn(retired_runtime_input, candidate)
            self.assertNotIn(retired_runtime_input, runtime)
        self.assertNotIn("callableExternalRuntimeContract", candidate)
        self.assertNotIn("callable_external_contract=", candidate)
        self.assertFalse(
            (ROOT / "nix" / "callable-external-runtime-contract.py").exists()
        )

    def test_production_runtime_graph_has_one_source_package(self) -> None:
        self.assertFalse(
            (ROOT / "nix" / "module-runtime-core-package.nix").exists()
        )
        production = "\n".join(
            (ROOT / "nix" / name).read_text(encoding="utf-8")
            for name in (
                "qualified-runtime-provider-v2.nix",
                "native-realization-v2.nix",
            )
        )
        self.assertNotIn("module-runtime-core-package.nix", production)
        self.assertNotIn("runtimeCore", production)
        self.assertNotIn("runtime_core_package", production)
        self.assertNotIn("machineIr", production)
        self.assertIn("recoveredExecutableData", production)
        shared = (
            ROOT / "nix" / "qualified-runtime-provider-v2.nix"
        ).read_text(encoding="utf-8")
        realization = (ROOT / "nix" / "native-realization-v2.nix").read_text(
            encoding="utf-8"
        )
        self.assertIn("linkedSemanticModule", shared)
        self.assertIn("behavioralCPackage", shared)
        self.assertNotIn("componentObjectPackages", shared)
        self.assertNotIn("behavioralCPackage", realization)
        self.assertNotIn("componentObjectPackages", realization)
        self.assertIn("pinnedLayoutAuthorities", shared)
        self.assertNotIn("executionClosure", shared)
        self.assertNotIn("resolvedExternalEnvironment", shared)
        self.assertNotIn("nativeIngressPlan", shared)
        self.assertNotIn("activationPlan", shared)

    def test_direct_refinement_consumes_the_v6_semantic_slice(self) -> None:
        phase = (
            ROOT / "nix" / "portable-c-work-package-provider-v2.nix"
        ).read_text(encoding="utf-8")
        workflow = (ROOT / "nix" / "component-workflow.nix").read_text(
            encoding="utf-8"
        )
        refinement = (
            ROOT / "src/spaghetti_extractor/semantic_providers/portable_c_work_package.py"
        ).read_text(encoding="utf-8")
        self.assertIn("semanticSlice", phase)
        self.assertIn("bindingIntent", phase)
        self.assertIn("interfacePackage", phase)
        self.assertIn("sourcePackage", phase)
        self.assertIn("semantic_slice=inputs", phase)
        self.assertIn("v6SemanticSlices", workflow)
        self.assertNotIn("v5ProofExecutionClosure", workflow)
        for forbidden in ("machineIr", "machineIrManifest"):
            self.assertNotIn(forbidden, phase)
        self.assertIn("SemanticSliceV2", refinement)
        self.assertIn("check_component_refinement", refinement)
        self.assertIn("_check_inductive_refinement_v5", refinement)
        self.assertNotIn("component-implementation-v4.json", refinement)

    def test_native_guest_dispatch_uses_shared_content_addressed_domains(
        self,
    ) -> None:
        canonical = (
            ROOT / "src" / "spaghetti_extractor" / "candidate" /
            "runtime_canonical.py"
        ).read_text(encoding="utf-8")
        canonical_common = (
            ROOT / "src" / "spaghetti_extractor" / "candidate" /
            "runtime_canonical_common.py"
        ).read_text(encoding="utf-8")
        canonical_build = (
            ROOT / "src" / "spaghetti_extractor" / "candidate" /
            "runtime_canonical_build.py"
        ).read_text(encoding="utf-8")
        renderer = (
            ROOT / "src" / "spaghetti_extractor" / "candidate" /
            "runtime_render_core.py"
        ).read_text(encoding="utf-8")
        model = (
            ROOT / "src" / "spaghetti_extractor" / "candidate" /
            "module_runtime_plan.py"
        ).read_text(encoding="utf-8")
        self.assertIn("_guest_dispatch_sites", canonical)
        self.assertIn("content_addressed_admitted_domains_v2", model)
        self.assertIn(
            "def guest_dispatch_from_linked_module_v2", canonical_common
        )
        self.assertIn("linked_module=linked_v2.payload", canonical_build)
        self.assertIn(
            'authority="linked_semantic_module_v2"', canonical_common
        )
        self.assertIn(
            "callable external member is disconnected", canonical_common
        )
        self.assertIn("def external_loader_targets", (
            ROOT / "src" / "spaghetti_extractor" / "candidate" /
            "runtime_model.py"
        ).read_text(encoding="utf-8"))
        self.assertIn("NativeGuestDispatchDomain", canonical_common)
        self.assertNotIn("exact_site_scoped_closure_targets_v1", model)
        resolver = renderer[
            renderer.index("static uint32_t spx_native_resolve_code_target("):
            renderer.index(
                "static uint32_t spx_native_callable_argument_value("
            )
        ]
        self.assertIn("spx_native_guest_dispatch_sites", resolver)
        self.assertNotIn("spx_native_transfer_count", resolver)

    def test_callback_ingress_has_one_cardinality_independent_realization(
        self,
    ) -> None:
        derivation = (
            ROOT / "src" / "spaghetti_extractor" / "candidate" /
            "native_ingress_derivation.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("_EAGER_CALLBACK_REALIZATION_LIMIT", derivation)
        self.assertNotIn("if len(targets) >", derivation)
        self.assertIn(
            "Preserve every callback may-domain as one runtime publication",
            derivation,
        )
        self.assertIn('callback_domains[domain_id] = domain', derivation)
        self.assertIn('callback_publications.append({', derivation)

    def test_components_consume_linked_semantics_without_external_sites(self) -> None:
        components = (ROOT / "nix" / "component-workflow.nix").read_text(
            encoding="utf-8"
        )
        sdk = (ROOT / "nix" / "target-sdk.nix").read_text(encoding="utf-8")
        self.assertFalse((ROOT / "nix/authority-workflow.nix").exists())
        self.assertNotIn("usesExternalSites", components)
        self.assertNotIn("externalSiteComponentIds", components)
        self.assertNotIn("canonicalExternalSites", components)
        self.assertNotIn("resolvedEnvironmentArtifact", components)
        self.assertNotIn("resolvedExternalEnvironment", components)
        self.assertIn("linkedSemanticModule", components)
        component_start = sdk.index(
            "      components =", sdk.index("behavioralCSource =")
        )
        component_call = sdk[component_start:sdk.index(
            "configurationIds =", component_start
        )]
        self.assertNotIn("componentExternalSites", component_call)
        self.assertNotIn("resolvedExternalEnvironment", component_call)
        self.assertIn("linkedSemanticModule", component_call)

    def test_native_realization_consumes_exact_provider_objects(self) -> None:
        realization = (ROOT / "nix" / "native-realization-v2.nix").read_text(
            encoding="utf-8"
        )
        sdk = (ROOT / "nix" / "target-sdk.nix").read_text(encoding="utf-8")
        self.assertNotIn("intrinsicProviderPackage", realization)
        self.assertIn("implementationSelection", realization)
        self.assertNotIn("sharedModuleRuntimePackage", realization)
        self.assertNotIn("nativeRealizationObjectManifest", realization)
        self.assertNotIn("behavioralCPackage", realization)
        self.assertNotIn("effectiveBehavioralCRuntimeQualifications", sdk)
        self.assertNotIn("behavioralCByConfiguration", sdk)
        self.assertNotIn("runtimeQualification", sdk)

if __name__ == "__main__":
    unittest.main()
