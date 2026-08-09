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
            "staticHybridAuthorityV2",
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

    def test_joint_phase_owns_slot_analysis_and_projections_stay_small(self) -> None:
        module = (ROOT / "nix" / "stage-b-component-analysis.nix").read_text(
            encoding="utf-8"
        )
        joint_phase = module[
            module.index("      jointInterproceduralV2 = {") :
            module.index("      interproceduralV2 = {")
        ]
        projection_phases = module[
            module.index("      interproceduralV2 = {") :
            module.index("      callbackEntryContracts = {")
        ]

        self.assertIn("spaghetti_extractor.global_slot_analysis_v2", joint_phase)
        self.assertIn("spaghetti_extractor.mutable_slot_candidates_v2", joint_phase)
        self.assertIn("spaghetti_extractor.global_slot_authority_v2", joint_phase)
        self.assertNotIn("spaghetti_extractor.entry_state_analysis_v2", joint_phase)
        self.assertEqual(
            projection_phases.count(
                'pythonModules = [ "spaghetti_extractor.artifact_projection_v2" ];'
            ),
            3,
        )
        self.assertNotIn("analyze_global_slots_v2", projection_phases)

    def test_stack_range_authority_is_replayed_inside_joint_phase(self) -> None:
        module = (ROOT / "nix" / "stage-b-component-analysis.nix").read_text(
            encoding="utf-8"
        )
        call_phase = module[
            module.index("      interproceduralSeed = {") :
            module.index("      jointInterproceduralV2 = {")
        ]
        joint_phase = module[
            module.index("      jointInterproceduralV2 = {") :
            module.index("      interproceduralV2 = {")
        ]

        self.assertIn("derive_interprocedural_result_v2", call_phase)
        self.assertNotIn("stackRangeAnalysis = {", module)
        self.assertIn("derive_joint_fixed_point_v2", joint_phase)
        self.assertIn("JointFixedPointCallbacks", joint_phase)
        self.assertIn("merge_recovery_proposals_v2", joint_phase)
        self.assertIn("derive_stack_range_analysis_v2", joint_phase)
        self.assertEqual(module.count("derive_stack_range_analysis_v2"), 2)
        self.assertIn("graph=proposal_graph", joint_phase)
        self.assertNotIn('inputs["stack_range_analysis"]', joint_phase)
        self.assertIn("range_authority_binding=stack_ranges.get(\"binding\")", joint_phase)
        self.assertIn("entry_range_facts=", joint_phase)

    def test_interprocedural_phase_does_not_import_pipeline_or_audit_layers(self) -> None:
        module = (ROOT / "nix" / "stage-b-component-analysis.nix").read_text(
            encoding="utf-8"
        )
        joint_phase = module[
            module.index("      jointInterproceduralV2 = {") :
            module.index("      interproceduralV2 = {")
        ]
        projection_phase = module[
            module.index("      interproceduralV2 = {") :
            module.index("      rootedClosure = {")
        ]

        self.assertIn("spaghetti_extractor.interprocedural_phase_v2", joint_phase)
        self.assertIn("spaghetti_extractor.joint_fixed_point_v2", joint_phase)
        self.assertIn("spaghetti_extractor.internal_function_contracts", joint_phase)
        self.assertNotIn("spaghetti_extractor.static_hybrid_pipeline_v2", joint_phase)
        self.assertIn("spaghetti_extractor.artifact_projection_v2", projection_phase)
        self.assertNotIn("derive_interprocedural_result_v2", projection_phase)
        phase_module = (
            ROOT / "src" / "spaghetti_extractor" / "interprocedural_phase_v2.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("static_hybrid_authority_v2", phase_module)
        self.assertNotIn("static_hybrid_final_audit_v2", phase_module)
        self.assertNotIn("hybrid_diagnostics_v2", phase_module)

    def test_exact_unit_phase_uses_the_stable_binding_kernel(self) -> None:
        module = (ROOT / "nix" / "stage-b-component-analysis.nix").read_text(
            encoding="utf-8"
        )
        phase = module[
            module.index("      exactUnitPrep = {") :
            module.index("      baseGraph = {")
        ]

        self.assertIn("spaghetti_extractor.machine_ir_authority_v2", phase)
        self.assertNotIn("spaghetti_extractor.hybrid_authority_builder_v2", phase)

    def test_machine_ir_closure_excludes_mutable_certificate_schemas(self) -> None:
        index = json.loads(
            (ROOT / "nix" / "python-module-index.json").read_text(
                encoding="utf-8"
            )
        )["modules"]

        pending = ["spaghetti_extractor.reconstruction_ir"]
        closure: set[str] = set()
        while pending:
            module = pending.pop()
            if module in closure:
                continue
            closure.add(module)
            pending.extend(index[module]["dependencies"])

        self.assertIn("spaghetti_extractor.authority_bindings_v2", closure)
        self.assertNotIn("spaghetti_extractor.hybrid_authority_v2", closure)
        self.assertNotIn(
            "spaghetti_extractor.external_site_proposals_v2", closure
        )
        self.assertNotIn(
            "spaghetti_extractor.static_hybrid_authority_v2", closure
        )

    def test_joint_analysis_closure_excludes_acceptance_only_schemas(self) -> None:
        index = json.loads(
            (ROOT / "nix" / "python-module-index.json").read_text(
                encoding="utf-8"
            )
        )["modules"]
        pending = [
            "spaghetti_extractor.control_analysis_v2",
            "spaghetti_extractor.global_slot_analysis_v2",
            "spaghetti_extractor.global_slot_authority_v2",
            "spaghetti_extractor.interprocedural_phase_v2",
            "spaghetti_extractor.joint_fixed_point_v2",
            "spaghetti_extractor.joint_interprocedural_analysis_v2",
            "spaghetti_extractor.launch_profile_v2",
            "spaghetti_extractor.stack_range_analysis_v2",
        ]
        closure: set[str] = set()
        while pending:
            module = pending.pop()
            if module in closure:
                continue
            closure.add(module)
            pending.extend(index[module]["dependencies"])

        self.assertIn("spaghetti_extractor.authority_record_core_v2", closure)
        self.assertIn("spaghetti_extractor.global_slot_contract_v2", closure)
        self.assertIn("spaghetti_extractor.entry_state_contract_v2", closure)
        self.assertNotIn("spaghetti_extractor.hybrid_authority_v2", closure)
        self.assertNotIn("spaghetti_extractor.external_site_proposals_v2", closure)
        self.assertNotIn("spaghetti_extractor.static_hybrid_authority_v2", closure)

    def test_entry_phases_share_complete_slot_promotion_policy(self) -> None:
        module = (ROOT / "nix" / "stage-b-component-analysis.nix").read_text(
            encoding="utf-8"
        )
        callback_phase = module[
            module.index("      callbackEntryContracts = {") :
            module.index("      finalizedLaunchProfile = {")
        ]
        entry_phase = module[
            module.index("      entryRootClosure = {") :
            module.index("      isaSelectionAuthority = {")
        ]

        for phase in (callback_phase, entry_phase):
            self.assertIn("apply_global_slot_authority_v2", phase)
            self.assertIn("authoritative_provenance", phase)

    def test_isa_requirements_are_lean_decoded_and_selection_is_rebound(self) -> None:
        module = (ROOT / "nix" / "stage-b-component-analysis.nix").read_text(
            encoding="utf-8"
        )
        requirements_phase = module[
            module.index("      isaRequirements = {") :
            module.index("      isaSelectionAuthority = {")
        ]
        selection_phase = module[
            module.index("      isaSelectionAuthority = {") :
            module.index("      exceptionCertificates = {")
        ]

        self.assertIn("extract_lean_instruction_forms_side", requirements_phase)
        self.assertIn('pythonExtraPaths = [ "spaghetti_extractor/lean/StageA" ]', requirements_phase)
        self.assertIn("extraNativeBuildInputs = [ pkgs.lean4 ]", requirements_phase)
        self.assertIn("parse_machine_ir_isa_requirements_v2", selection_phase)
        self.assertIn("compare_selection_to_machine_ir_requirements_v2", selection_phase)

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
        self.assertIn("checked-module-index-v1", closure)
        self.assertNotIn("ast.parse", closure)
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
        for exported in ("inventory", "analysis", "hybrid", "diagnosticRun"):
            self.assertRegex(target, rf"(?m)^\s+{exported}$")
        self.assertIn("externalInterfaceProfiles", target)
        self.assertIn("staticAuthorityV2", target)
        self.assertIn("staticCompletenessReport", target)
        self.assertNotIn("staticCompletenessGate", target)
        self.assertIn("allowDeferredPotentialTransfers = false", target)

    def test_candidate_generation_has_only_v2_authority(self) -> None:
        module = (ROOT / "nix" / "stage-b-hybrid-candidate.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn("candidateAuthorityReport", module)
        self.assertIn("candidateAuthorityGate", module)
        self.assertIn("build_stage_b_candidate_authority_v2", module)
        self.assertIn("require_stage_b_candidate_authority_v2", module)
        self.assertIn("final_static_hybrid_audit", module)
        self.assertIn("authority_bundle", module)
        self.assertNotIn("write_static_hybrid_closure_receipt", module)
        self.assertNotIn("write_final_candidate_authorization", module)
        self.assertNotIn("stage-b-final-candidate-generation-authorization-v1", module)

    def test_checked_external_sites_use_only_the_canonical_v2_proposal(self) -> None:
        module = (ROOT / "nix" / "stage-b-component-analysis.nix").read_text(
            encoding="utf-8"
        )
        start = module.index("checkedExternalSites = {")
        end = module.index("globalSlotAnalysis = {", start)
        phase = module[start:end]

        self.assertIn("checked_external_sites_proposal", phase)
        self.assertIn(
            "spaghetti-extractor-external-site-proposals-v2", phase
        )
        self.assertIn("derive_external_site_proposals_v2", phase)
        self.assertIn("parse_external_site_proposals_v2", phase)
        self.assertIn("external_profile_authority", phase)
        self.assertIn("rooted_closure", phase)
        self.assertNotIn("legacy_v1_diagnostic", phase)

        authority_start = module.index("staticAuthority = {")
        authority_end = module.index("authorityBundle = {", authority_start)
        authority = module[authority_start:authority_end]
        self.assertIn("parse_external_site_proposals_v2", authority)
        self.assertNotIn("checked_external_sites", authority.split("inputs = {", 1)[1].split("};", 1)[0])

    def test_fallback_coverage_is_v2_and_has_no_v1_authority_dependency(self) -> None:
        module = (ROOT / "nix" / "stage-b-hybrid-candidate.nix").read_text(
            encoding="utf-8"
        )
        start = module.index("fallbackCoverageReceipt =")
        end = module.index("candidateAuthorityReport =", start)
        phase = module[start:end]

        self.assertIn("stage-b-fallback-coverage-receipt-v2", phase)
        self.assertNotIn("static_completeness_report", phase)
        self.assertNotIn("staticCompletenessReport", phase)

    def test_v2_entry_isa_and_exception_phases_use_canonical_apis(self) -> None:
        module = (ROOT / "nix" / "stage-b-component-analysis.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn("finalize_launch_profile_v2", module)
        self.assertIn("launchProfileTemplate ? null", module)
        self.assertIn("parse_launch_assumption_template_v1", module)
        self.assertIn("original_pe = original;", module)
        self.assertIn("launch_invariants_for_entry_state", module)
        self.assertIn("derive_callback_entry_state_contracts_v2", module)
        self.assertIn("build_external_profile_authority_v2", module)
        self.assertIn('parsed.status.value != "qualified"', module)
        self.assertIn("derive_checked_exception_reports_v2", module)
        self.assertNotIn("scc_exception_certificates_missing", module)

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
