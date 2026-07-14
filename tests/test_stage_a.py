import copy
import hashlib
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wincr import cli as wincr_cli
from wincr import stage_a
from wincr import stage_binary
from wincr.stage_a import (
    STAGE_A_MODEL_ID,
    STAGE_A_MODEL_SPECS,
    STAGE_A_X86_64_MODEL_ID,
    stage_a_check_proof,
    stage_a_diff_obligations,
    stage_a_explain_obligations,
    stage_a_extract_work_items,
    stage_a_export_reference_contract,
    stage_a_generate_map,
    stage_a_semantic_coverage,
    stage_a_smoke_contract,
    stage_a_validate,
    stage_a_validate_unit,
)
from wincr.stage_a_proof import proof_model_hash, stage_a_model_description, write_proof_ir, write_solver_evidence_inventory


TEST_SOLVER_BACKEND = {
    "format": "stage-a-solver-backend-v1",
    "solver": "z3",
    "version": "test-z3",
    "engine": "stage-a-local-symbolic-x86-v1",
    "smt_fragment": "stage-a-local-symbolic-x86-observables-v1",
    "trust_boundary": "z3_unsat_local_equivalence_oracle_v1",
}


class StageAValidateTests(unittest.TestCase):
    def test_cli_exposes_v2_validation_only_under_legacy_names(self):
        parser = wincr_cli._build_parser(prog="wincr")
        subcommands = next(
            action for action in parser._actions
            if action.dest == "command"
        ).choices
        self.assertNotIn("stage-a-validate", subcommands)
        self.assertNotIn("stage-a-validate-suite", subcommands)
        self.assertIn("stage-a-legacy-validate", subcommands)
        self.assertIn("stage-a-legacy-validate-suite", subcommands)

    def test_primary_proof_replay_rejects_v2_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            (report / "verdict.json").write_text(
                json.dumps({"profile": "x86-pe32-lean-refinement-v2"}),
                encoding="utf-8",
            )
            args = mock.Mock(
                report=report,
                original=None,
                candidate=None,
                out=None,
            )
            with self.assertRaisesRegex(
                stage_a.StageAInputError,
                "stage-a-legacy-check-proof",
            ):
                wincr_cli._cmd_stage_a_check_proof(args)

    def test_structural_identity_pass_writes_required_report_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            for relative in (
                "verdict.json",
                "layout.json",
                "obligations.json",
                "failures",
                "incomplete",
                "counterexamples",
                "witnesses",
                "proof-cache",
                "lean",
            ):
                self.assertTrue((out / relative).exists(), relative)
            obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))
            self.assertEqual(obligations["counts"]["by_status"]["proved"], 2)
            block = self._obligation(out, "block:entry")
            reachability = self._obligation(out, "reachability:entry")
            self.assertEqual(block["proof_rule"], "byte_identical_x86_pe32_block")
            self.assertEqual(reachability["proof_rule"], "entry_root_reachability_v1")
            proof_index = json.loads((out / "proof-cache" / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(len(proof_index["entries"]), 1)
            proof_ir = json.loads((out / "proof-ir.json").read_text(encoding="utf-8"))
            self.assertEqual(proof_ir["model_hash"], proof_model_hash(proof_ir["model"]))
            self.assertEqual(proof_ir["proof_context"]["status"], "satisfied")
            self.assertTrue(proof_ir["proof_context"]["checks"]["model_hash_present"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["model_hash_matches_model"])
            self.assertEqual(proof_ir["proof_context"]["hashes"]["model_description_sha256"], proof_ir["model_hash"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["original_input_exists"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["candidate_input_exists"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["target_profile_satisfied"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["closure_certificate_satisfied"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["loader_frontend_profile_satisfied"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["loader_profile_satisfied"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["coverage_profile_satisfied"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["proof_cache_profile_satisfied"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["proof_rule_profile_satisfied"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["mapping_profile_satisfied"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["cfg_profile_satisfied"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["reachability_profile_satisfied"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["environment_profile_satisfied"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["solver_backend_profile_satisfied"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["trusted_boundary_profile_satisfied"])
            self.assertTrue(proof_ir["proof_context"]["checks"]["profile_manifest_satisfied"])
            self.assertEqual(proof_ir["closure_certificate"]["status"], "satisfied")
            self.assertTrue(all(proof_ir["closure_certificate"]["checks"].values()))
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["proved_block_obligations_have_solver_evidence"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["proof_artifacts_bind_same_obligations"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["coverage_profile_satisfied"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["proof_cache_profile_satisfied"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["solver_backend_profile_satisfied"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["trusted_boundary_profile_satisfied"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["profile_manifest_satisfied"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["proof_rule_profile_satisfied"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["mapping_profile_satisfied"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["cfg_profile_satisfied"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["reachability_profile_satisfied"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["environment_profile_satisfied"])
            self.assertEqual(proof_ir["target_profile"]["status"], "satisfied")
            self.assertTrue(proof_ir["target_profile"]["checks"]["loader_facts_schema_matches_model"])
            self.assertTrue(proof_ir["target_profile"]["checks"]["loader_frontend_profile_schema_matches"])
            self.assertTrue(proof_ir["target_profile"]["checks"]["loader_frontend_profile_status_satisfied"])
            self.assertTrue(proof_ir["target_profile"]["checks"]["solver_backend_profile_schema_matches"])
            self.assertTrue(proof_ir["target_profile"]["checks"]["trusted_boundary_profile_schema_matches"])
            self.assertTrue(proof_ir["target_profile"]["checks"]["profile_manifest_schema_matches"])
            self.assertTrue(proof_ir["target_profile"]["checks"]["trusted_boundary_profile_status_satisfied"])
            self.assertTrue(proof_ir["target_profile"]["checks"]["loader_profile_model_matches"])
            self.assertEqual(proof_ir["profile_manifest"]["status"], "satisfied")
            self.assertTrue(proof_ir["profile_manifest"]["checks"]["profile_manifest_gaps_closed"])
            self.assertEqual(proof_ir["profile_manifest"]["counts"]["profile_manifest_gaps"], 0)
            self.assertEqual(proof_ir["loader_frontend_profile"]["status"], "satisfied")
            self.assertTrue(proof_ir["loader_frontend_profile"]["checks"]["original_required_fields_present"])
            self.assertTrue(proof_ir["loader_frontend_profile"]["checks"]["candidate_required_fields_present"])
            self.assertTrue(proof_ir["loader_frontend_profile"]["checks"]["loader_profile_status_satisfied"])
            self.assertEqual(proof_ir["loader_profile"]["status"], "satisfied")
            loader_profile_counts = proof_ir["loader_profile"]["counts"]
            self.assertEqual(loader_profile_counts["model_bitness"], 32)
            self.assertEqual(loader_profile_counts["original_bitness"], 32)
            self.assertEqual(loader_profile_counts["candidate_bitness"], 32)
            self.assertGreater(loader_profile_counts["original_executable_sections"], 0)
            self.assertEqual(loader_profile_counts["layout_blocking_issues"], 0)
            self.assertEqual(loader_profile_counts["binary_signature_mismatches"], 0)
            self.assertTrue(proof_ir["loader_profile"]["checks"]["loader_format_matches_model"])
            self.assertTrue(proof_ir["loader_profile"]["checks"]["loader_name_matches_model"])
            self.assertTrue(proof_ir["loader_profile"]["checks"]["relocations_closed"])
            self.assertEqual(proof_ir["coverage_profile"]["status"], "satisfied")
            coverage_profile_counts = proof_ir["coverage_profile"]["counts"]
            self.assertEqual(coverage_profile_counts["coverage_obligations"], 0)
            self.assertEqual(coverage_profile_counts["block_equivalence_obligations"], 1)
            self.assertEqual(coverage_profile_counts["proved_block_equivalence_obligations"], 1)
            self.assertEqual(coverage_profile_counts["open_coverage_obligations"], 0)
            self.assertEqual(coverage_profile_counts["coverage_gaps"], 0)
            self.assertTrue(proof_ir["coverage_profile"]["checks"]["coverage_obligations_classified"])
            self.assertTrue(proof_ir["coverage_profile"]["checks"]["coverage_gaps_closed"])
            self.assertTrue(proof_ir["coverage_profile"]["checks"]["block_equivalence_present"])
            self.assertEqual(proof_ir["proof_cache_profile"]["status"], "satisfied")
            proof_cache_profile_counts = proof_ir["proof_cache_profile"]["counts"]
            self.assertEqual(proof_cache_profile_counts["proof_cache_entries"], 1)
            self.assertEqual(proof_cache_profile_counts["proof_cache_index_entries"], 1)
            self.assertEqual(proof_cache_profile_counts["proof_cache_file_missing"], 0)
            self.assertEqual(proof_cache_profile_counts["proof_cache_file_unreadable"], 0)
            self.assertEqual(proof_cache_profile_counts["proof_cache_payload_hash_mismatches"], 0)
            self.assertEqual(proof_cache_profile_counts["proof_cache_index_file_missing"], 0)
            self.assertEqual(proof_cache_profile_counts["proof_cache_index_file_hash_mismatches"], 0)
            self.assertEqual(proof_cache_profile_counts["proof_cache_index_payload_mismatches"], 0)
            self.assertEqual(proof_cache_profile_counts["proof_cache_index_entry_mismatches"], 0)
            self.assertEqual(proof_cache_profile_counts["duplicate_proof_cache_paths"], 0)
            self.assertEqual(proof_cache_profile_counts["proof_cache_gaps"], 0)
            self.assertTrue(proof_ir["proof_cache_profile"]["checks"]["proof_cache_payload_hashes_match"])
            self.assertTrue(proof_ir["proof_cache_profile"]["checks"]["proof_cache_index_file_hash_matches"])
            self.assertTrue(proof_ir["proof_cache_profile"]["checks"]["proof_cache_gaps_closed"])
            self.assertEqual(proof_ir["proof_rule_profile"]["status"], "satisfied")
            proof_rule_profile_counts = proof_ir["proof_rule_profile"]["counts"]
            self.assertGreater(proof_rule_profile_counts["model_rules"], 0)
            self.assertEqual(proof_rule_profile_counts["obligations"], 2)
            self.assertEqual(proof_rule_profile_counts["obligations_with_rules"], 2)
            self.assertEqual(proof_rule_profile_counts["unknown_obligation_rules"], 0)
            self.assertEqual(proof_rule_profile_counts["block_semantics_records"], 1)
            self.assertEqual(proof_rule_profile_counts["block_semantics_records_with_rules"], 1)
            self.assertEqual(proof_rule_profile_counts["unknown_block_semantics_rules"], 0)
            self.assertEqual(proof_rule_profile_counts["solver_evidence_entries"], 1)
            self.assertEqual(proof_rule_profile_counts["solver_evidence_entries_with_rules"], 1)
            self.assertEqual(proof_rule_profile_counts["unknown_solver_evidence_rules"], 0)
            self.assertEqual(proof_rule_profile_counts["artifact_rule_binding_gaps"], 0)
            self.assertTrue(proof_ir["proof_rule_profile"]["checks"]["obligation_rules_known"])
            self.assertTrue(proof_ir["proof_rule_profile"]["checks"]["artifact_rule_bindings_closed"])
            self.assertEqual(proof_ir["mapping_profile"]["status"], "satisfied")
            mapping_profile_counts = proof_ir["mapping_profile"]["counts"]
            self.assertEqual(mapping_profile_counts["blocks"], 1)
            self.assertEqual(mapping_profile_counts["code_blocks"], 1)
            self.assertEqual(mapping_profile_counts["non_code_blocks"], 0)
            self.assertEqual(mapping_profile_counts["reachable_blocks"], 1)
            self.assertEqual(mapping_profile_counts["unchecked_invariant_blocks"], 0)
            self.assertEqual(mapping_profile_counts["unknown_checked_root_entries"], 0)
            self.assertEqual(mapping_profile_counts["unknown_mapping_proof_rules"], 0)
            self.assertEqual(mapping_profile_counts["malformed_blocks"], 0)
            self.assertEqual(mapping_profile_counts["malformed_waivers"], 0)
            self.assertEqual(mapping_profile_counts["mapping_gaps"], 0)
            self.assertTrue(proof_ir["mapping_profile"]["checks"]["mapping_contract_present"])
            self.assertTrue(proof_ir["mapping_profile"]["checks"]["mapping_status_satisfied"])
            self.assertTrue(proof_ir["mapping_profile"]["checks"]["mapping_entries_present"])
            self.assertTrue(proof_ir["mapping_profile"]["checks"]["mapping_gaps_closed"])
            self.assertEqual(proof_ir["cfg_profile"]["status"], "satisfied")
            cfg_profile_counts = proof_ir["cfg_profile"]["counts"]
            self.assertEqual(cfg_profile_counts["block_equivalence_obligations"], 1)
            self.assertEqual(cfg_profile_counts["proved_block_equivalence_obligations"], 1)
            self.assertEqual(cfg_profile_counts["block_structure_obligations"], 0)
            self.assertEqual(cfg_profile_counts["direct_cfg_edge_obligations"], 0)
            self.assertEqual(cfg_profile_counts["indirect_cfg_target_obligations"], 0)
            self.assertEqual(cfg_profile_counts["cfg_gaps"], 0)
            self.assertTrue(proof_ir["cfg_profile"]["checks"]["cfg_gaps_closed"])
            self.assertEqual(proof_ir["reachability_profile"]["status"], "satisfied")
            reachability_profile_counts = proof_ir["reachability_profile"]["counts"]
            self.assertEqual(reachability_profile_counts["block_equivalence_obligations"], 1)
            self.assertEqual(reachability_profile_counts["proved_block_equivalence_obligations"], 1)
            self.assertEqual(reachability_profile_counts["cfg_edge_obligations"], 0)
            self.assertEqual(reachability_profile_counts["reachability_obligations"], 1)
            self.assertEqual(reachability_profile_counts["proved_reachability_obligations"], 1)
            self.assertEqual(reachability_profile_counts["entry_root_reachability"], 1)
            self.assertEqual(reachability_profile_counts["reachability_gaps"], 0)
            self.assertTrue(proof_ir["reachability_profile"]["checks"]["reachability_gaps_closed"])
            self.assertEqual(proof_ir["environment_profile"]["status"], "satisfied")
            environment_profile_counts = proof_ir["environment_profile"]["counts"]
            self.assertEqual(environment_profile_counts["original_imports"], 0)
            self.assertEqual(environment_profile_counts["candidate_imports"], 0)
            self.assertEqual(environment_profile_counts["import_thunk_block_semantics_records"], 0)
            self.assertEqual(environment_profile_counts["symbolic_observable_claims"], 0)
            self.assertEqual(environment_profile_counts["environment_gaps"], 0)
            self.assertTrue(proof_ir["environment_profile"]["checks"]["environment_model_supported"])
            self.assertTrue(proof_ir["environment_profile"]["checks"]["loader_import_signatures_match"])
            self.assertEqual(proof_ir["block_semantics"]["status"], "satisfied")
            self.assertEqual(proof_ir["block_semantics"]["counts"]["records"], 1)
            self.assertEqual(proof_ir["block_semantics"]["records"][0]["semantics_kind"], "decoded_instruction_identity")
            self.assertEqual(proof_ir["block_semantics"]["records"][0]["status"], "present")
            self.assertEqual(proof_ir["instruction_semantics"]["status"], "satisfied")
            self.assertEqual(proof_ir["instruction_semantics"]["counts"]["records"], 1)
            instruction_record = proof_ir["instruction_semantics"]["records"][0]
            self.assertEqual(instruction_record["status"], "satisfied")
            self.assertEqual(instruction_record["obligation_id"], "block:entry")
            self.assertEqual(instruction_record["semantics_kind"], "decoded_instruction_identity")
            self.assertEqual(proof_ir["instruction_profile"]["status"], "satisfied")
            instruction_profile_counts = proof_ir["instruction_profile"]["counts"]
            self.assertEqual(instruction_profile_counts["instruction_semantics_records"], 1)
            self.assertEqual(instruction_profile_counts["decoded_instruction_block_semantics"], 1)
            self.assertEqual(instruction_profile_counts["decoded_instruction_identity_records"], 1)
            self.assertEqual(instruction_profile_counts["pe_import_thunk_semantics_records"], 0)
            self.assertEqual(instruction_profile_counts["instruction_semantics_gaps"], 0)
            self.assertEqual(instruction_record["original"]["status"], "ok")
            self.assertEqual(instruction_record["candidate"]["status"], "ok")
            self.assertEqual(instruction_record["original"]["instruction_count"], 2)
            self.assertRegex(instruction_record["original"]["instruction_stream_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(instruction_record["original"]["decoded_bytes_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(proof_ir["proof_artifact_bindings"]["status"], "satisfied")
            self.assertEqual(proof_ir["proof_artifact_bindings"]["counts"]["records"], 1)
            self.assertEqual(proof_ir["proof_artifact_bindings"]["records"][0]["status"], "satisfied")
            self.assertEqual(proof_ir["proof_artifact_bindings"]["records"][0]["obligation_id"], "block:entry")
            self.assertEqual(proof_ir["semantic_observables"]["status"], "satisfied")
            self.assertEqual(proof_ir["semantic_observables"]["counts"]["records"], 1)
            self.assertEqual(proof_ir["semantic_observables"]["records"][0]["claim_kind"], "decoded_instruction_identity")
            self.assertEqual(proof_ir["semantic_observables"]["records"][0]["status"], "satisfied")
            self.assertEqual(proof_ir["semantic_profile"]["status"], "satisfied")
            semantic_profile_counts = proof_ir["semantic_profile"]["counts"]
            self.assertEqual(semantic_profile_counts["semantic_observables"], 1)
            self.assertEqual(semantic_profile_counts["decoded_instruction_identity"], 1)
            self.assertEqual(semantic_profile_counts["byte_identical_instruction_decode_boundaries"], 1)
            self.assertEqual(semantic_profile_counts["unknown_claims"], 0)
            self.assertEqual(semantic_profile_counts["unknown_trusted_boundaries"], 0)
            self.assertEqual(proof_ir["solver_claims"]["status"], "satisfied")
            self.assertEqual(proof_ir["solver_claims"]["counts"]["records"], 0)
            self.assertEqual(proof_ir["solver_evidence_profile"]["status"], "satisfied")
            solver_profile_counts = proof_ir["solver_evidence_profile"]["counts"]
            self.assertEqual(solver_profile_counts["proof_cache_entries"], 1)
            self.assertEqual(solver_profile_counts["solver_evidence_entries"], 1)
            self.assertEqual(solver_profile_counts["structural_byte_identity_entries"], 1)
            self.assertEqual(solver_profile_counts["solver_claims"], 0)
            self.assertEqual(solver_profile_counts["incomplete_entries"], 0)
            self.assertEqual(proof_ir["solver_backend_profile"]["status"], "satisfied")
            solver_backend_profile_counts = proof_ir["solver_backend_profile"]["counts"]
            self.assertEqual(solver_backend_profile_counts["solver_evidence_entries"], 1)
            self.assertEqual(solver_backend_profile_counts["solver_backed_evidence_entries"], 0)
            self.assertEqual(solver_backend_profile_counts["solver_claims"], 0)
            self.assertEqual(solver_backend_profile_counts["backend_gaps"], 0)
            self.assertEqual(proof_ir["trusted_boundaries"]["status"], "satisfied")
            self.assertEqual(proof_ir["trusted_boundaries"]["counts"]["records"], 1)
            self.assertEqual(proof_ir["trusted_boundaries"]["records"][0]["trusted_boundary"], "byte_identical_instruction_decode_v1")
            self.assertTrue(proof_ir["trusted_boundaries"]["records"][0]["allowed"])
            self.assertEqual(proof_ir["proof_composition"]["status"], "satisfied")
            self.assertEqual(proof_ir["proof_composition"]["counts"]["records"], 1)
            composition_record = proof_ir["proof_composition"]["records"][0]
            self.assertEqual(composition_record["status"], "satisfied")
            self.assertEqual(composition_record["obligation_id"], "block:entry")
            self.assertEqual(composition_record["composition_rule"], "stage-a-local-block-proof-composition-v1")
            self.assertIn(
                "instruction_semantics",
                {dependency["family"] for dependency in composition_record["dependencies"]},
            )
            self.assertNotIn(
                "solver_claim",
                {dependency["family"] for dependency in composition_record["dependencies"]},
            )
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["proved_block_obligations_have_block_semantics"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["proved_block_obligations_have_semantic_observables"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["semantic_claims_use_allowed_trusted_boundaries"])
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["proof_backing_gaps"], 0)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["proof_artifact_bindings"], 1)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["semantic_observables"], 1)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["semantic_observable_gaps"], 0)
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["solver_claims_satisfied"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["trusted_solver_claims_have_queries"])
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["solver_claims"], 0)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["solver_claim_gaps"], 0)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["trusted_boundaries"], 1)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["trusted_boundary_gaps"], 0)
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["proof_composition_satisfied"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["proved_block_obligations_have_composition_records"])
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["proof_composition_records"], 1)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["proof_composition_gaps"], 0)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["proof_cache_profile_gaps"], 0)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["evidence_binding_gaps"], 0)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["block_semantics_gaps"], 0)
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["instruction_semantics_satisfied"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["decoded_block_semantics_have_instruction_semantics"])
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["instruction_semantics_records"], 1)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["instruction_semantics_gaps"], 0)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["decoded_instruction_block_semantics"], 1)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["cfg_profile_gaps"], 0)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["mapping_profile_gaps"], 0)
            self.assertEqual(proof_ir["closure_certificate"]["counts"]["reachability_profile_gaps"], 0)
            lean_summary = json.loads((out / "lean" / "summary.json").read_text(encoding="utf-8"))
            self.assertTrue(lean_summary["global_soundness_checked"])
            self.assertTrue(lean_summary["final_pass_allowed"])
            self.assertTrue(lean_summary["proof_ir_closure_certificate_checked"])
            self.assertTrue(lean_summary["proof_ir_loader_profile_checked"])
            self.assertTrue(lean_summary["proof_ir_coverage_profile_checked"])
            self.assertTrue(lean_summary["proof_ir_proof_cache_profile_checked"])
            self.assertTrue(lean_summary["proof_ir_proof_rule_profile_checked"])
            self.assertTrue(lean_summary["proof_ir_mapping_profile_checked"])
            self.assertTrue(lean_summary["proof_ir_cfg_profile_checked"])
            self.assertTrue(lean_summary["proof_ir_reachability_profile_checked"])
            self.assertTrue(lean_summary["proof_ir_environment_profile_checked"])
            self.assertTrue(lean_summary["proof_ir_instruction_profile_checked"])
            self.assertTrue(lean_summary["proof_ir_semantic_profile_checked"])
            self.assertTrue(lean_summary["proof_ir_solver_evidence_profile_checked"])
            self.assertTrue(lean_summary["proof_ir_solver_backend_profile_checked"])
            self.assertTrue(lean_summary["proof_ir_trusted_boundary_profile_checked"])
            self.assertTrue(lean_summary["proof_ir_profile_manifest_checked"])
            self.assertTrue(lean_summary["proof_evidence_binding_checked"])
            self.assertIn("StageA/ProofIR.lean", lean_summary["generated_stubs"])
            self.assertTrue((out / "lean" / "StageA" / "ProofIR.lean").exists())
            proof_ir_lean = (out / "lean" / "StageA" / "ProofIR.lean").read_text(encoding="utf-8")
            self.assertIn("structure ProofIrCounts", proof_ir_lean)
            self.assertIn("structure TargetProfile", proof_ir_lean)
            self.assertIn("loaderFrontendProfileSchemaMatches : Bool", proof_ir_lean)
            self.assertIn("loaderFrontendProfileStatusSatisfied : Bool", proof_ir_lean)
            self.assertIn("solverBackendProfileSchemaMatches : Bool", proof_ir_lean)
            self.assertIn("trustedBoundaryProfileSchemaMatches : Bool", proof_ir_lean)
            self.assertIn("trustedBoundaryProfileStatusSatisfied : Bool", proof_ir_lean)
            self.assertIn("profileManifestSchemaMatches : Bool", proof_ir_lean)
            self.assertIn("profile.loaderFrontendProfileSchemaMatches", proof_ir_lean)
            self.assertIn("profile.loaderFrontendProfileStatusSatisfied", proof_ir_lean)
            self.assertIn("profile.solverBackendProfileSchemaMatches", proof_ir_lean)
            self.assertIn("profile.trustedBoundaryProfileSchemaMatches", proof_ir_lean)
            self.assertIn("profile.trustedBoundaryProfileStatusSatisfied", proof_ir_lean)
            self.assertIn("profile.profileManifestSchemaMatches", proof_ir_lean)
            self.assertIn("structure LoaderProfile", proof_ir_lean)
            self.assertIn("structure CoverageProfile", proof_ir_lean)
            self.assertIn("structure ProofCacheProfile", proof_ir_lean)
            self.assertIn("structure ProofRuleProfile", proof_ir_lean)
            self.assertIn("structure MappingProfile", proof_ir_lean)
            self.assertIn("def mappingProfileClosed", proof_ir_lean)
            self.assertIn("structure CfgProfile", proof_ir_lean)
            self.assertIn("structure ReachabilityProfile", proof_ir_lean)
            self.assertIn("structure EnvironmentProfile", proof_ir_lean)
            self.assertIn("structure InstructionSemanticsProfile", proof_ir_lean)
            self.assertIn("structure SemanticObservableProfile", proof_ir_lean)
            self.assertIn("structure TrustedBoundaryProfile", proof_ir_lean)
            self.assertIn("structure ProfileManifest", proof_ir_lean)
            self.assertIn("structure SolverEvidenceProfile", proof_ir_lean)
            self.assertIn("def proofIrCountsAccounted", proof_ir_lean)
            self.assertIn("def closureCertificateCountsClosed", proof_ir_lean)
            self.assertIn("def closureCertificateChecksClosed", proof_ir_lean)
            self.assertIn("def loaderProfileClosed", proof_ir_lean)
            self.assertIn("def coverageProfileClosed", proof_ir_lean)
            self.assertIn("def proofCacheProfileClosed", proof_ir_lean)
            self.assertIn("def proofRuleProfileClosed", proof_ir_lean)
            self.assertIn("def cfgProfileClosed", proof_ir_lean)
            self.assertIn("def reachabilityProfileClosed", proof_ir_lean)
            self.assertIn("def environmentProfileClosed", proof_ir_lean)
            self.assertIn("def instructionSemanticsProfileClosed", proof_ir_lean)
            self.assertIn("def semanticObservableProfileClosed", proof_ir_lean)
            self.assertIn("def trustedBoundaryProfileClosed", proof_ir_lean)
            self.assertIn("def profileManifestClosed", proof_ir_lean)
            self.assertIn("def solverEvidenceProfileClosed", proof_ir_lean)
            obligations_lean = (out / "lean" / "StageA" / "Obligations.lean").read_text(encoding="utf-8")
            self.assertIn("import StageA.ProofIR", obligations_lean)
            self.assertIn("generatedProofIrClosureCertificateClosedChecked", obligations_lean)
            self.assertIn("generatedProofIrContextBindingChecked", obligations_lean)
            self.assertIn("generatedProofIrClosureCertificateStatusChecked", obligations_lean)
            self.assertIn("generatedProofIrClosureCertificateCountsChecked", obligations_lean)
            self.assertIn("generatedProofIrClosureCertificateChecksClosedChecked", obligations_lean)
            self.assertIn("generatedProofIrCfgProfileClosedChecked", obligations_lean)
            self.assertIn("generatedCfgProfile : CfgProfile", obligations_lean)
            self.assertIn("generatedCfgProfileClosed", obligations_lean)
            self.assertIn("generatedProofIrReachabilityProfileClosedChecked", obligations_lean)
            self.assertIn("generatedReachabilityProfile : ReachabilityProfile", obligations_lean)
            self.assertIn("generatedReachabilityProfileClosed", obligations_lean)
            self.assertIn("generatedRuntimeProofCounts : RuntimeProofCounts", obligations_lean)
            self.assertIn("generatedProofIrCounts : ProofIrCounts", obligations_lean)
            self.assertIn("generatedClosureCertificateCounts : ClosureCertificateCounts", obligations_lean)
            self.assertIn("generatedClosureCertificateChecks : ClosureCertificateChecks", obligations_lean)
            self.assertIn("generatedLoaderProfile : LoaderProfile", obligations_lean)
            self.assertIn("generatedCoverageProfile : CoverageProfile", obligations_lean)
            self.assertIn("generatedProofCacheProfile : ProofCacheProfile", obligations_lean)
            self.assertIn("generatedProofRuleProfile : ProofRuleProfile", obligations_lean)
            self.assertIn("generatedCfgProfile : CfgProfile", obligations_lean)
            self.assertIn("generatedEnvironmentProfile : EnvironmentProfile", obligations_lean)
            self.assertIn("generatedInstructionSemanticsProfile : InstructionSemanticsProfile", obligations_lean)
            self.assertIn("generatedSemanticObservableProfile : SemanticObservableProfile", obligations_lean)
            self.assertIn("generatedSolverEvidenceProfile : SolverEvidenceProfile", obligations_lean)
            self.assertIn("proofIrCountsAccounted generatedRuntimeProofCounts generatedProofIrCounts", obligations_lean)
            self.assertIn(
                "closureCertificateCountsClosed generatedRuntimeProofCounts generatedProofIrCounts generatedClosureCertificateCounts",
                obligations_lean,
            )
            self.assertIn("closureCertificateChecksClosed generatedClosureCertificateChecks", obligations_lean)
            self.assertIn("loaderProfileClosed generatedLoaderProfile", obligations_lean)
            self.assertIn("coverageProfileClosed generatedProofIrCounts generatedCoverageProfile", obligations_lean)
            self.assertIn(
                "proofCacheProfileClosed generatedRuntimeProofCounts generatedProofIrCounts generatedClosureCertificateCounts generatedProofCacheProfile",
                obligations_lean,
            )
            self.assertIn("proofRuleProfileClosed generatedProofIrCounts generatedProofRuleProfile", obligations_lean)
            self.assertIn(
                "environmentProfileClosed generatedLoaderProfile generatedSemanticObservableProfile generatedClosureCertificateCounts generatedEnvironmentProfile",
                obligations_lean,
            )
            self.assertIn(
                "instructionSemanticsProfileClosed generatedProofIrCounts generatedClosureCertificateCounts generatedSemanticObservableProfile generatedInstructionSemanticsProfile",
                obligations_lean,
            )
            self.assertIn(
                "semanticObservableProfileClosed generatedProofIrCounts generatedClosureCertificateCounts generatedSemanticObservableProfile",
                obligations_lean,
            )
            self.assertIn(
                "solverEvidenceProfileClosed generatedRuntimeProofCounts generatedProofIrCounts generatedClosureCertificateCounts generatedSemanticObservableProfile generatedSolverEvidenceProfile",
                obligations_lean,
            )
            self.assertIn("generatedInstructionSemanticsProfileChecked", obligations_lean)
            self.assertIn("generatedLoaderProfileChecked", obligations_lean)
            self.assertIn("generatedProofIrLoaderProfileClosedChecked", obligations_lean)
            self.assertIn("generatedCoverageProfileChecked", obligations_lean)
            self.assertIn("generatedProofIrCoverageProfileClosedChecked", obligations_lean)
            self.assertIn("generatedProofCacheProfileChecked", obligations_lean)
            self.assertIn("generatedProofIrProofCacheProfileClosedChecked", obligations_lean)
            self.assertIn("generatedProofRuleProfileChecked", obligations_lean)
            self.assertIn("generatedProofIrProofRuleProfileClosedChecked", obligations_lean)
            self.assertIn("generatedEnvironmentProfileChecked", obligations_lean)
            self.assertIn("generatedProofIrEnvironmentProfileClosedChecked", obligations_lean)
            self.assertIn("generatedSemanticObservableProfileChecked", obligations_lean)
            self.assertIn("generatedSolverEvidenceProfileChecked", obligations_lean)
            self.assertIn("generatedClosureCheckProvedBlockObligationsHaveSolverEvidence", obligations_lean)
            self.assertIn("generatedClosureCheckProofCacheProfileSatisfied", obligations_lean)
            self.assertIn("generatedClosureCertificateProofCacheProfileGapCount", obligations_lean)
            self.assertIn("generatedProofIrProofArtifactBindingRecordCount", obligations_lean)
            self.assertIn("generatedClosureCheckProofArtifactBindingsSatisfied", obligations_lean)
            self.assertIn("generatedClosureCheckProofArtifactsBindSameObligations", obligations_lean)
            self.assertIn("generatedProofIrSemanticObservableRecordCount", obligations_lean)
            self.assertIn("generatedProofIrSolverClaimRecordCount", obligations_lean)
            self.assertIn("generatedClosureCheckSolverClaimsSatisfied", obligations_lean)
            self.assertIn("generatedClosureCheckTrustedSolverClaimsHaveQueries", obligations_lean)
            self.assertIn("generatedProofIrInstructionSemanticsRecordCount", obligations_lean)
            self.assertIn("generatedClosureCheckInstructionSemanticsSatisfied", obligations_lean)
            self.assertIn("generatedClosureCheckDecodedBlockSemanticsHaveInstructionSemantics", obligations_lean)
            self.assertIn("generatedProofIrProofCompositionRecordCount", obligations_lean)
            self.assertIn("generatedClosureCheckProofCompositionSatisfied", obligations_lean)
            self.assertIn("generatedClosureCheckProvedBlockObligationsHaveCompositionRecords", obligations_lean)
            self.assertIn("generatedClosureCheckSemanticObservablesSatisfied", obligations_lean)
            self.assertIn("generatedProofIrTrustedBoundaryRecordCount", obligations_lean)
            self.assertIn("generatedClosureCheckTrustedBoundariesSatisfied", obligations_lean)
            self.assertIn("generatedProofIrBlockSemanticsRecordCount", obligations_lean)
            self.assertIn("generatedClosureCheckProvedBlockObligationsHaveBlockSemantics", obligations_lean)
            self.assertIn("generatedProofEvidenceBindingClosedChecked", obligations_lean)

    def test_missing_lean_downgrades_otherwise_closed_pass_to_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            out = root / "report"

            with mock.patch("wincr.stage_a.shutil.which", return_value=None):
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "incomplete")
            blocker = json.loads((out / "incomplete" / "lean-global-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(blocker["category"], "lean_global_summary_unchecked")
            self.assertIn("Lean executable is not available", blocker["blocker"])
            self.assertFalse(result["proof"]["lean"]["final_pass_allowed"])

    def test_supplemental_lean_input_is_copied_imported_and_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            lean_input = root / "fixture lemma.lean"
            lean_input.write_text("namespace StageAUserFixture\n\ntheorem extraChecked : True := True.intro\n\nend StageAUserFixture\n", encoding="utf-8")
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                    lean_inputs=(lean_input,),
                )

            self.assertEqual(result["verdict"], "pass")
            summary = json.loads((out / "lean" / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["supplemental_inputs"]["errors"], [])
            self.assertEqual(summary["source_artifacts"]["status"], "satisfied")
            copied = summary["supplemental_inputs"]["copied"][0]
            self.assertEqual(copied["module"], "StageA.User.FixtureLemma")
            self.assertTrue((out / "lean" / copied["relative_path"]).exists())
            obligations_lean = (out / "lean" / "StageA" / "Obligations.lean").read_text(encoding="utf-8")
            self.assertIn("import StageA.User.FixtureLemma", obligations_lean)

    def test_incomplete_lean_source_artifact_manifest_blocks_final_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            out = root / "report"
            incomplete_manifest = {
                "format": "stage-a-lean-source-artifacts-v1",
                "generated": [],
                "supplemental": [],
                "counts": {"generated": 0, "supplemental": 0, "missing": 1},
                "status": "incomplete",
            }

            with self._mock_lean_checked(), mock.patch(
                "wincr.stage_a._lean_source_artifacts_manifest",
                return_value=incomplete_manifest,
            ):
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "incomplete")
            summary = result["proof"]["lean"]
            self.assertFalse(summary["final_pass_allowed"])
            self.assertEqual(summary["source_artifacts"]["status"], "incomplete")
            blocker = json.loads((out / "incomplete" / "lean-global-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(blocker["category"], "lean_global_summary_unchecked")
            self.assertIn("Lean source artifacts", blocker["next_action"])

    def test_supplemental_lean_input_with_unchecked_marker_blocks_final_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            lean_input = root / "unchecked.lean"
            lean_input.write_text("axiom uncheckedFact : True\n", encoding="utf-8")
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                    lean_inputs=(lean_input,),
                )

            self.assertEqual(result["verdict"], "incomplete")
            summary = json.loads((out / "lean" / "summary.json").read_text(encoding="utf-8"))
            self.assertFalse(summary["final_pass_allowed"])
            self.assertIn({"path": "StageA/User/Unchecked.lean", "line": 1, "marker": "axiom"}, summary["unchecked_markers"])

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_real_lean_summary_allows_structural_pass_when_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "pass")
            summary = json.loads((out / "lean" / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["lean_check"]["status"], "checked")
            self.assertTrue(summary["global_soundness_checked"])

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_real_lean_cache_reuses_only_generated_status_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / "lean-cache"

            def validate(label: str) -> dict:
                case = root / label
                case.mkdir()
                original = self._write_pe(case / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
                candidate = self._write_pe(case / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
                mapping = self._write_mapping(case / "block-map.json", size=6)
                return stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=case / "report",
                )

            with mock.patch.dict(os.environ, {"WINCR_STAGE_A_LEAN_CACHE": str(cache)}):
                first = validate("first")
                second = validate("second")

            self.assertEqual(first["verdict"], "pass")
            self.assertEqual(second["verdict"], "pass")
            first_cache = first["proof"]["lean"]["lean_check"]["cache"]
            second_cache = second["proof"]["lean"]["lean_check"]["cache"]
            self.assertEqual(first_cache["misses"], 2)
            self.assertEqual(second_cache["hits"], 2)
            self.assertEqual(
                {entry["module"] for entry in second_cache["entries"]},
                {"StageA/Model.lean", "StageA/ProofIR.lean"},
            )

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_real_lean_formal_profile_proves_nonidentical_mov_lea_rewrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\x90\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\x90\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=4)
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["assurance"], "lean_kernel_checked_strong_refinement")
            formal = result["proof"]["formal"]
            self.assertEqual(formal["profile"], stage_a.STAGE_A_FORMAL_PROFILE_ID)
            self.assertEqual(formal["status"], "checked")
            self.assertTrue(formal["kernel_checked"])
            self.assertEqual(formal["theorem"], "StageA.Generated.candidateRefinesOriginal")
            self.assertEqual(formal["original_sha256"], hashlib.sha256(original.read_bytes()).hexdigest())
            self.assertEqual(formal["candidate_sha256"], hashlib.sha256(candidate.read_bytes()).hexdigest())
            self.assertEqual(formal["unexpected_axioms"], [])
            self.assertEqual(set(formal["theorem_axioms"]), {"propext", "Quot.sound"})
            bundle = (out / "lean" / "StageA" / "FormalBundle.lean").read_text(encoding="utf-8")
            self.assertIn("theorem candidateRefinesOriginal", bundle)
            self.assertIn("StageA.Formal.checkProofBundle_guarantee", bundle)
            self.assertNotIn("native_decide", bundle)
            independent = stage_a_check_proof(report=out)
            self.assertEqual(independent["status"], "pass")
            self.assertTrue(all(independent["checks"].values()))
            self.assertTrue(independent["checks"]["formal_bundle_reproduced"])
            bundle_path = out / "lean" / "StageA" / "FormalBundle.lean"
            bundle_path.write_text(bundle + "\n-- local modification\n", encoding="utf-8")
            modified_check = stage_a_check_proof(report=out)
            self.assertEqual(modified_check["status"], "incomplete")
            self.assertFalse(modified_check["checks"]["formal_bundle_reproduced"])
            self.assertEqual(modified_check["lean_check"]["status"], "skipped_preflight")
            bundle_path.write_text(bundle, encoding="utf-8")
            changed_candidate = self._write_pe(root / "changed-candidate.exe", b"\xb8\x01\x00\x00\x00\xc3")
            changed_check = stage_a_check_proof(report=out, candidate=changed_candidate)
            self.assertEqual(changed_check["status"], "incomplete")
            self.assertFalse(changed_check["checks"]["candidate_artifact_matches"])
            self.assertEqual(changed_check["lean_check"]["status"], "skipped_preflight")

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_formal_profile_composes_nonzero_argument_import_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = b"\xff\x15\x40\x20\x40\x00\xc3"
            original = self._write_import_pe(root / "original.exe", code, "WriteFile@20")
            candidate = self._write_import_pe(root / "candidate.exe", code, "WriteFile@20")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "import-call",
                                "kind": "code",
                                "reachable": True,
                                "root": {"kind": "fixture_function", "checked": True},
                                "original": {"rva": 0x1000, "size": 6},
                                "candidate": {"rva": 0x1000, "size": 6},
                            },
                            {
                                "id": "continuation",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1006, "size": 1},
                                "candidate": {"rva": 0x1006, "size": 1},
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["formal"]["status"], "checked")

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_formal_profile_composes_internal_call_and_return(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xe8\x03\x00\x00\x00\xc3\x90\x90\x89\xd8\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xe8\x03\x00\x00\x00\xc3\x90\x90\x8d\x03\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "caller",
                                "kind": "code",
                                "reachable": True,
                                "root": {"kind": "fixture_function", "checked": True},
                                "original": {"rva": 0x1000, "size": 5},
                                "candidate": {"rva": 0x1000, "size": 5},
                            },
                            {
                                "id": "continuation",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1005, "size": 1},
                                "candidate": {"rva": 0x1005, "size": 1},
                            },
                            {
                                "id": "callee",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1008, "size": 3},
                                "candidate": {"rva": 0x1008, "size": 3},
                            },
                        ],
                        "waivers": [
                            {
                                "id": "call-padding",
                                "binary": "both",
                                "rva": 0x1006,
                                "size": 2,
                                "reason": "unreachable alignment padding",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "pass")
            self.assertTrue(result["proof"]["lean"]["formal_strong_refinement_checked"])
            obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"]
            edge_kinds = {
                item["edge_kind"]
                for item in obligations
                if item.get("kind") == "cfg_edge" and item.get("status") == "proved"
            }
            self.assertEqual(edge_kinds, {"call", "fallthrough"})

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_formal_profile_composes_zero_argument_import_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = b"\xff\x15\x40\x20\x40\x00\xc3"
            original = self._write_import_pe(root / "original.exe", code, "GetTickCount@0")
            candidate = self._write_import_pe(root / "candidate.exe", code, "GetTickCount@0")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "import-call",
                                "kind": "code",
                                "reachable": True,
                                "root": {"kind": "fixture_function", "checked": True},
                                "original": {"rva": 0x1000, "size": 6},
                                "candidate": {"rva": 0x1000, "size": 6},
                            },
                            {
                                "id": "continuation",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1006, "size": 1},
                                "candidate": {"rva": 0x1006, "size": 1},
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["formal"]["claim"]["external_environment"], "ordered_uninterpreted_import_environment_v2")
            independent = stage_a_check_proof(report=out)
            self.assertEqual(independent["status"], "pass")

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_formal_profile_accepts_entrypoint_inside_executable_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = bytearray(_pe32_image(b"\x90\x90\xc3"))
            struct.pack_into("<I", image, 0xA8, 0x1002)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(image)
            candidate.write_bytes(image)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "entry",
                                "kind": "code",
                                "reachable": True,
                                "root": {"kind": "fixture_function", "checked": True},
                                "original": {"rva": 0x1002, "size": 1},
                                "candidate": {"rva": 0x1002, "size": 1},
                            }
                        ],
                        "waivers": [
                            {
                                "id": "pre-entry-padding",
                                "binary": "both",
                                "rva": 0x1000,
                                "size": 2,
                                "reason": "unreachable entry alignment padding",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["formal"]["status"], "checked")

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_z3_equivalence_outside_formal_decoder_is_incomplete_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x41\x90\x90\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x83\xc1\x01\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=4)
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(result["proof"]["assurance"], "incomplete")
            diagnostics = result["proof"]["formal"]["diagnostics"]
            self.assertEqual(diagnostics["status"], "incomplete")
            self.assertEqual(
                {item["bytes"] for item in diagnostics["issues"] if item["category"] == "formal_instruction_unsupported"},
                {"41"},
            )
            self.assertEqual(result["proof"]["formal"]["status"], "not_requested")

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_formal_profile_composes_direct_branch_cfg_regions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(
                root / "original.exe",
                b"\x83\xf8\x00\x74\x03\x89\xda\xc3\x8d\x13\xc3",
            )
            candidate = self._write_pe(
                root / "candidate.exe",
                b"\x83\xf8\x00\x74\x03\x8d\x13\xc3\x89\xda\xc3",
            )
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "branch",
                                "kind": "code",
                                "reachable": True,
                                "root": {"kind": "fixture_function", "checked": True},
                                "original": {"rva": 0x1000, "size": 5},
                                "candidate": {"rva": 0x1000, "size": 5},
                            },
                            {
                                "id": "fallthrough",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1005, "size": 3},
                                "candidate": {"rva": 0x1005, "size": 3},
                            },
                            {
                                "id": "taken",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1008, "size": 3},
                                "candidate": {"rva": 0x1008, "size": 3},
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["formal"]["counts"]["regions"], 3)
            self.assertTrue(result["proof"]["lean"]["formal_strong_refinement_checked"])
            obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"]
            self.assertEqual(
                len([item for item in obligations if item.get("kind") == "cfg_edge" and item.get("status") == "proved"]),
                2,
            )

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_formal_profile_proves_sign_extended_cmp_across_encodings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(
                root / "original.exe",
                b"\x83\xf8\xff\x74\x03\x89\xda\xc3\x89\xda\xc3\x90\x90",
            )
            candidate = self._write_pe(
                root / "candidate.exe",
                b"\x3d\xff\xff\xff\xff\x74\x03\x8d\x13\xc3\x8d\x13\xc3",
            )
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "branch",
                                "kind": "code",
                                "reachable": True,
                                "root": {"kind": "fixture_function", "checked": True},
                                "original": {"rva": 0x1000, "size": 5},
                                "candidate": {"rva": 0x1000, "size": 7},
                            },
                            {
                                "id": "fallthrough",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1005, "size": 3},
                                "candidate": {"rva": 0x1007, "size": 3},
                            },
                            {
                                "id": "taken",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1008, "size": 3},
                                "candidate": {"rva": 0x100A, "size": 3},
                            },
                        ],
                        "waivers": [
                            {
                                "id": "original-tail-padding",
                                "binary": "original",
                                "rva": 0x100B,
                                "size": 2,
                                "reason": "unreachable post-return alignment padding",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["formal"]["status"], "checked")
            self.assertEqual(result["proof"]["formal"]["counts"]["regions"], 3)

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_formal_profile_proves_generic_modrm_and_unsigned_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(
                root / "original.exe",
                b"\x39\xd3\x72\x03\x31\xc9\xc3\x31\xc9\xc3",
            )
            candidate = self._write_pe(
                root / "candidate.exe",
                b"\x3b\xda\x72\x03\x33\xc9\xc3\x33\xc9\xc3",
            )
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "branch",
                                "kind": "code",
                                "reachable": True,
                                "root": {"kind": "fixture_function", "checked": True},
                                "original": {"rva": 0x1000, "size": 4},
                                "candidate": {"rva": 0x1000, "size": 4},
                            },
                            {
                                "id": "fallthrough",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1004, "size": 3},
                                "candidate": {"rva": 0x1004, "size": 3},
                            },
                            {
                                "id": "taken",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1007, "size": 3},
                                "candidate": {"rva": 0x1007, "size": 3},
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["formal"]["status"], "checked")

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_formal_profile_proves_movzx_and_long_unsigned_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(
                root / "original.exe",
                b"\x39\xd3\x0f\xb7\x03\x0f\x82\x03\x00\x00\x00\x31\xc9\xc3\x31\xc9\xc3\x90",
            )
            candidate = self._write_pe(
                root / "candidate.exe",
                b"\x3b\xda\x0f\xb7\x43\x00\x0f\x82\x03\x00\x00\x00\x33\xc9\xc3\x33\xc9\xc3",
            )
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "branch",
                                "kind": "code",
                                "reachable": True,
                                "root": {"kind": "fixture_function", "checked": True},
                                "original": {"rva": 0x1000, "size": 11},
                                "candidate": {"rva": 0x1000, "size": 12},
                            },
                            {
                                "id": "fallthrough",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x100B, "size": 3},
                                "candidate": {"rva": 0x100C, "size": 3},
                            },
                            {
                                "id": "taken",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x100E, "size": 3},
                                "candidate": {"rva": 0x100F, "size": 3},
                            },
                        ],
                        "waivers": [
                            {
                                "id": "original-tail-padding",
                                "binary": "original",
                                "rva": 0x1011,
                                "size": 1,
                                "reason": "unreachable post-return alignment padding",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "pass", result)
            self.assertEqual(result["proof"]["formal"]["status"], "checked")

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_formal_profile_normalizes_common_integer_instruction_families(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(
                root / "original.exe",
                b"\xb9\x01\x00\x00\x00\x09\xd0\xc1\xe0\x01\x39\xc8"
                b"\x0f\x83\x03\x00\x00\x00\xc2\x0c\x00\xc2\x0c\x00",
            )
            candidate = self._write_pe(
                root / "candidate.exe",
                b"\xc7\xc1\x01\x00\x00\x00\x0b\xc2\xd1\xe0\x3b\xc1"
                b"\x0f\x83\x03\x00\x00\x00\xc2\x0c\x00\xc2\x0c\x00",
            )
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "branch",
                                "kind": "code",
                                "reachable": True,
                                "root": {"kind": "fixture_function", "checked": True},
                                "original": {"rva": 0x1000, "size": 18},
                                "candidate": {"rva": 0x1000, "size": 18},
                            },
                            {
                                "id": "fallthrough",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1012, "size": 3},
                                "candidate": {"rva": 0x1012, "size": 3},
                            },
                            {
                                "id": "taken",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1015, "size": 3},
                                "candidate": {"rva": 0x1015, "size": 3},
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "pass", result)
            self.assertEqual(result["proof"]["formal"]["status"], "checked")

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_reachable_byte_mutation_fails_with_z3_counterexample_and_witness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2b\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "fail")
            failure = json.loads((out / "failures" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(failure["category"], "block_observable_mismatch")
            self.assertEqual(failure["details"]["mismatch"]["observable"], "reg:eax")
            self.assertEqual(failure["details"]["solver"], "z3")
            self.assertEqual(failure["details"]["smt_status"], "sat")
            self.assertIn("model", failure["details"])
            counterexample = json.loads((out / "counterexamples" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(counterexample["mismatch"]["mismatch"]["observable"], "reg:eax")
            self.assertTrue((out / "witnesses" / "block-entry.json").exists())

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_non_identical_flag_preserving_blocks_can_prove_equivalent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\x90\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\x90\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=4)
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"]
            self.assertEqual(obligations[0]["proof_rule"], "smt_z3_local_equivalence_v1")
            self.assertEqual(obligations[0]["symbolic"]["solver"], "z3")
            self.assertEqual(obligations[0]["symbolic"]["smt_status"], "unsat")
            symbolic_cache = [path for path in (out / "proof-cache").glob("*symbolic*.json")]
            self.assertEqual(len(symbolic_cache), 1)
            cache_payload = json.loads(symbolic_cache[0].read_text(encoding="utf-8"))
            self.assertIn("(check-sat)", cache_payload["symbolic"]["smt_query"])

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_arithmetic_equivalence_proves_registers_and_modeled_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x83\xc0\x00\xc3")  # add eax, 0; ret
            candidate = self._write_pe(root / "candidate.exe", b"\x83\xe8\x00\xc3")  # sub eax, 0; ret
            mapping = self._write_mapping(root / "block-map.json", size=4)
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            obligation = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"][0]
            self.assertEqual(obligation["proof_rule"], "smt_z3_local_equivalence_v1")
            self.assertIn("flag:zf", obligation["symbolic"]["original_observables"])
            self.assertEqual(obligation["symbolic"]["smt_status"], "unsat")

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_checked_invariant_constraints_are_used_by_smt_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xc3", virtual_size=6)  # mov eax, ebx; ret
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x07\x00\x00\x00\xc3")  # mov eax, 7; ret
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "entry",
                                "kind": "code",
                                "reachable": True,
                                "invariant": {"checked": True, "constraints": [{"reg": "ebx", "equals": 7}]},
                                "original": {"rva": 0x1000, "size": 3},
                                "candidate": {"rva": 0x1000, "size": 6},
                            }
                        ],
                        "waivers": [
                            {"id": "original-padding", "binary": "original", "rva": 0x1003, "size": 3, "reason": "alignment padding"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
            )

            self.assertEqual(result["verdict"], "pass")
            obligation = self._obligation(out, "block:entry")
            self.assertEqual(obligation["symbolic"]["smt_status"], "unsat")
            self.assertEqual(obligation["invariant"]["kind"], "checked_constraints")
            self.assertEqual(obligation["invariant"]["constraints"], [{"reg": "ebx", "equals": 7}])
            self.assertIn("pre_ebx", obligation["symbolic"]["smt_query"])

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_malformed_invariant_constraint_reports_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xc3", virtual_size=6)
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x07\x00\x00\x00\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "entry",
                                "kind": "code",
                                "reachable": True,
                                "invariant": {"checked": True, "constraints": [{"reg": "xmm0", "equals": 7}]},
                                "original": {"rva": 0x1000, "size": 3},
                                "candidate": {"rva": 0x1000, "size": 6},
                            }
                        ],
                        "waivers": [
                            {"id": "original-padding", "binary": "original", "rva": 0x1003, "size": 3, "reason": "alignment padding"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            blocker = json.loads((out / "incomplete" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(blocker["category"], "unsupported_invariant")
            self.assertIn("unsupported invariant register", blocker["blocker"])

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_branch_predicate_mutation_fails_with_successor_counterexample(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x83\xf8\x00\x74\x01\xc3")  # cmp eax, 0; je +1; ret
            candidate = self._write_pe(root / "candidate.exe", b"\x83\xf8\x00\x75\x01\xc3")  # cmp eax, 0; jne +1; ret
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            self._mapping_entry(size=5, block_id="entry"),
                            self._mapping_entry(rva=0x1005, size=1, block_id="ret"),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "fail")
            failure = json.loads((out / "failures" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(failure["category"], "block_observable_mismatch")
            self.assertEqual(failure["details"]["mismatch"]["observable"], "outcome")
            self.assertEqual(failure["details"]["smt_status"], "sat")

    def test_direct_cfg_edges_are_reported_as_proved_obligations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = b"\x83\xf8\x00\x74\x01\xc3\xc3"  # cmp eax, 0; je 0x1006; ret; ret
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            self._mapping_entry(size=5, block_id="entry"),
                            self._mapping_entry(rva=0x1005, size=1, block_id="fallthrough"),
                            self._mapping_entry(rva=0x1006, size=1, block_id="taken"),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"]
            edges = [item for item in obligations if item["kind"] == "cfg_edge"]
            self.assertEqual({edge["edge_kind"] for edge in edges}, {"taken", "fallthrough"})
            self.assertEqual({edge["target_block"] for edge in edges}, {"taken", "fallthrough"})
            self.assertTrue(all(edge["status"] == "proved" for edge in edges))
            proof_ir = json.loads((out / "proof-ir.json").read_text(encoding="utf-8"))
            cfg_profile = proof_ir["cfg_profile"]
            self.assertEqual(cfg_profile["status"], "satisfied")
            self.assertEqual(cfg_profile["counts"]["direct_cfg_edge_obligations"], 2)
            self.assertEqual(cfg_profile["counts"]["proved_direct_cfg_edge_obligations"], 2)
            self.assertEqual(cfg_profile["counts"]["open_direct_cfg_edge_obligations"], 0)
            self.assertEqual(cfg_profile["counts"]["direct_cfg_taken_edges"], 1)
            self.assertEqual(cfg_profile["counts"]["direct_cfg_fallthrough_edges"], 1)
            self.assertEqual(cfg_profile["counts"]["proved_direct_cfg_edges_with_source_block"], 2)
            self.assertEqual(cfg_profile["counts"]["proved_direct_cfg_edges_with_target_block"], 2)
            self.assertEqual(cfg_profile["counts"]["proved_direct_cfg_edges_with_original_evidence"], 2)
            self.assertEqual(cfg_profile["counts"]["proved_direct_cfg_edges_with_candidate_evidence"], 2)
            self.assertEqual(cfg_profile["counts"]["cfg_gaps"], 0)
            self.assertTrue(cfg_profile["checks"]["direct_cfg_edge_evidence_present"])
            reachability_profile = proof_ir["reachability_profile"]
            self.assertEqual(reachability_profile["status"], "satisfied")
            self.assertEqual(reachability_profile["counts"]["block_equivalence_obligations"], 3)
            self.assertEqual(reachability_profile["counts"]["cfg_edge_obligations"], 2)
            self.assertEqual(reachability_profile["counts"]["proved_cfg_edge_obligations"], 2)
            self.assertEqual(reachability_profile["counts"]["reachability_obligations"], 3)
            self.assertEqual(reachability_profile["counts"]["entry_root_reachability"], 1)
            self.assertEqual(reachability_profile["counts"]["direct_cfg_reachability"], 2)
            self.assertEqual(reachability_profile["counts"]["direct_cfg_reachability_with_proved_edge"], 2)
            self.assertEqual(reachability_profile["counts"]["reachability_gaps"], 0)
            self.assertTrue(reachability_profile["checks"]["direct_cfg_reachability_edges_proved"])

    def test_unmapped_direct_cfg_edge_reports_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = b"\xeb\x01\x90\xc3"  # jmp 0x1003; padding; ret
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [self._mapping_entry(size=2, block_id="entry")],
                        "waivers": [
                            {"id": "middle-padding", "binary": "both", "rva": 0x1002, "size": 1, "reason": "jumped-over padding"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            edge_blocker = json.loads((out / "incomplete" / "edge-entry-jump-1003.json").read_text(encoding="utf-8"))
            self.assertEqual(edge_blocker["category"], "unmapped_cfg_edge")
            self.assertEqual(edge_blocker["details"]["original_edge"]["target_rva"], 0x1003)
            proof_ir = json.loads((out / "proof-ir.json").read_text(encoding="utf-8"))
            cfg_profile = proof_ir["cfg_profile"]
            self.assertEqual(cfg_profile["status"], "incomplete")
            self.assertEqual(cfg_profile["counts"]["direct_cfg_edge_obligations"], 1)
            self.assertEqual(cfg_profile["counts"]["open_direct_cfg_edge_obligations"], 1)
            self.assertEqual(cfg_profile["counts"]["cfg_gaps"], 1)
            self.assertIn("open_direct_cfg_edge_obligation", {gap["category"] for gap in cfg_profile["gaps"]})
            self.assertFalse(cfg_profile["checks"]["direct_cfg_edges_closed"])
            self.assertFalse(proof_ir["proof_context"]["checks"]["cfg_profile_satisfied"])

    def test_checked_generated_proof_does_not_bypass_unsplit_cfg(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = b"\x83\xf8\x00\x74\x01\xc3\xc3"  # cmp eax, 0; je 0x1006; ret; ret
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "block-map.json"
            entry = self._mapping_entry(size=len(code), block_id="entry")
            entry["proof"] = {
                "rule": "reproducible_jq_same_source_optimization_pair_v1",
                "checked": True,
                "function": "entry",
            }
            mapping.write_text(json.dumps({"blocks": [entry]}), encoding="utf-8")
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            obligation = self._obligation(out, "structure:entry:original:unsplit:1003")
            self.assertEqual(obligation["kind"], "block_structure")
            self.assertEqual(obligation["incomplete"]["category"], "unsplit_basic_block")
            proof_ir = json.loads((out / "proof-ir.json").read_text(encoding="utf-8"))
            cfg_profile = proof_ir["cfg_profile"]
            self.assertEqual(cfg_profile["status"], "incomplete")
            self.assertGreaterEqual(cfg_profile["counts"]["block_structure_obligations"], 1)
            self.assertEqual(
                cfg_profile["counts"]["open_block_structure_obligations"],
                cfg_profile["counts"]["block_structure_obligations"],
            )
            self.assertIn("open_block_structure_obligation", {gap["category"] for gap in cfg_profile["gaps"]})
            self.assertFalse(cfg_profile["checks"]["block_structure_obligations_closed"])

    def test_checked_generated_proof_does_not_bypass_indirect_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xff\xe0")  # jmp eax
            candidate = self._write_pe(root / "candidate.exe", b"\xff\xe0")
            mapping = root / "block-map.json"
            entry = self._mapping_entry(size=2, block_id="entry")
            entry["proof"] = {
                "rule": "reproducible_jq_same_source_optimization_pair_v1",
                "checked": True,
                "function": "entry",
            }
            mapping.write_text(json.dumps({"blocks": [entry]}), encoding="utf-8")
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            obligation = self._obligation(out, "structure:entry:original:unknown-target:1000")
            self.assertEqual(obligation["incomplete"]["category"], "unknown_target")
            proof_ir = json.loads((out / "proof-ir.json").read_text(encoding="utf-8"))
            cfg_profile = proof_ir["cfg_profile"]
            self.assertEqual(cfg_profile["status"], "incomplete")
            self.assertEqual(cfg_profile["counts"]["block_structure_obligations"], 2)
            self.assertEqual(cfg_profile["counts"]["open_block_structure_obligations"], 2)
            self.assertIn("open_block_structure_obligation", {gap["category"] for gap in cfg_profile["gaps"]})

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_memory_read_equivalence_allows_different_block_sizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x8b\x03\xc3", virtual_size=4)  # mov eax, [ebx]; ret
            candidate = self._write_pe(root / "candidate.exe", b"\x8b\x43\x00\xc3", virtual_size=4)  # mov eax, [ebx+0]; ret
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "entry",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1000, "size": 3},
                                "candidate": {"rva": 0x1000, "size": 4},
                            }
                        ],
                        "waivers": [
                            {"id": "original-padding", "binary": "original", "rva": 0x1003, "size": 1, "reason": "alignment padding"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
            )

            self.assertEqual(result["verdict"], "pass")
            obligation = self._obligation(out, "block:entry")
            self.assertEqual(obligation["proof_rule"], "smt_z3_local_equivalence_v1")
            self.assertEqual(obligation["symbolic"]["smt_status"], "unsat")
            self.assertIn(["read", ["mem32", ["reg", "ebx"]]], obligation["symbolic"]["original_observables"]["memory_events"])

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_memory_write_offset_mutation_fails_with_memory_counterexample(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x89\x43\x04\xc3")  # mov [ebx+4], eax; ret
            candidate = self._write_pe(root / "candidate.exe", b"\x89\x43\x08\xc3")  # mov [ebx+8], eax; ret
            mapping = self._write_mapping(root / "block-map.json", size=4)
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "fail")
            failure = json.loads((out / "failures" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(failure["details"]["mismatch"]["observable"], "memory_events")
            self.assertEqual(failure["details"]["smt_status"], "sat")

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_stack_push_pop_alternate_encodings_prove_equivalent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x50\x5b\xc3", virtual_size=5)  # push eax; pop ebx; ret
            candidate = self._write_pe(root / "candidate.exe", b"\xff\xf0\x8f\xc3\xc3", virtual_size=5)  # push eax; pop ebx; ret
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "entry",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1000, "size": 3},
                                "candidate": {"rva": 0x1000, "size": 5},
                            }
                        ],
                        "waivers": [
                            {"id": "original-padding", "binary": "original", "rva": 0x1003, "size": 2, "reason": "alignment padding"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
            )

            self.assertEqual(result["verdict"], "pass")
            obligation = self._obligation(out, "block:entry")
            self.assertEqual(obligation["proof_rule"], "smt_z3_local_equivalence_v1")
            self.assertEqual(obligation["symbolic"]["smt_status"], "unsat")
            self.assertIn("memory_events", obligation["symbolic"]["original_observables"])

    def test_unproved_reachability_blocks_final_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            self._mapping_entry(size=1, block_id="entry"),
                            self._mapping_entry(rva=0x1001, size=1, block_id="orphan"),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "incomplete")
            reachability = self._obligation(out, "reachability:orphan")
            self.assertEqual(reachability["status"], "incomplete")
            self.assertEqual(reachability["incomplete"]["category"], "unproved_reachability")
            proof_ir = json.loads((out / "proof-ir.json").read_text(encoding="utf-8"))
            reachability_profile = proof_ir["reachability_profile"]
            self.assertEqual(reachability_profile["status"], "incomplete")
            self.assertEqual(reachability_profile["counts"]["reachability_obligations"], 2)
            self.assertEqual(reachability_profile["counts"]["open_reachability_obligations"], 1)
            self.assertEqual(reachability_profile["counts"]["reachability_gaps"], 1)
            self.assertIn("open_reachability_obligation", {gap["category"] for gap in reachability_profile["gaps"]})
            self.assertFalse(reachability_profile["checks"]["reachability_obligations_closed"])
            self.assertFalse(proof_ir["proof_context"]["checks"]["reachability_profile_satisfied"])

    def test_checked_root_can_prove_non_entry_block_reachable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            mapping = root / "block-map.json"
            orphan_root = self._mapping_entry(rva=0x1001, size=1, block_id="exported")
            orphan_root["root"] = {"kind": "fixture_function", "checked": True}
            mapping.write_text(
                json.dumps({"blocks": [self._mapping_entry(size=1, block_id="entry"), orphan_root]}),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            reachability = self._obligation(out, "reachability:exported")
            self.assertEqual(reachability["proof_rule"], "checked_root_reachability_v1")

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_in_block_memory_write_is_visible_to_later_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x89\x03\x8b\x0b\xc3", virtual_size=7)  # mov [ebx], eax; mov ecx, [ebx]; ret
            candidate = self._write_pe(root / "candidate.exe", b"\x89\x43\x00\x8b\x4b\x00\xc3", virtual_size=7)  # mov [ebx+0], eax; mov ecx, [ebx+0]; ret
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "entry",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1000, "size": 5},
                                "candidate": {"rva": 0x1000, "size": 7},
                            }
                        ],
                        "waivers": [
                            {"id": "padding", "binary": "original", "rva": 0x1005, "size": 2, "reason": "alignment padding"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            obligation = self._obligation(out, "block:entry")
            self.assertEqual(obligation["symbolic"]["smt_status"], "unsat")
            self.assertEqual(obligation["symbolic"]["original_observables"]["reg:ecx"], ["reg", "eax"])

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_external_import_call_equivalence_is_uninterpreted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            call_import = b"\xff\x15\x40\x20\x40\x00"
            original = self._write_import_pe(root / "original.exe", b"\x31\xc0" + call_import + b"\xc3", "GetTickCount")
            candidate = self._write_import_pe(root / "candidate.exe", b"\x29\xc0" + call_import + b"\xc3", "GetTickCount")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(size=9),
                                "external_calls": [{"dll": "kernel32.dll", "symbol": "GetTickCount", "args": []}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(result["proof"]["assurance"], "incomplete")
            obligation = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"][0]
            self.assertEqual(obligation["proof_rule"], "smt_z3_local_equivalence_v1")
            self.assertEqual(obligation["symbolic"]["smt_status"], "unsat")
            self.assertEqual(
                obligation["symbolic"]["original_observables"]["external_events"],
                [["external_call", "kernel32.dll", "GetTickCount", None, []]],
            )

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_external_import_call_argument_mutation_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            call_import = b"\xff\x15\x40\x20\x40\x00"
            original = self._write_import_pe(root / "original.exe", b"\xb8\x01\x00\x00\x00" + call_import + b"\xc3", "ExitProcess")
            candidate = self._write_import_pe(root / "candidate.exe", b"\xb8\x02\x00\x00\x00" + call_import + b"\xc3", "ExitProcess")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(size=12),
                                "external_calls": [{"dll": "kernel32.dll", "symbol": "ExitProcess", "args": ["eax"]}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "fail")
            failure = json.loads((out / "failures" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(failure["details"]["mismatch"]["observable"], "external_events")
            self.assertEqual(failure["details"]["smt_status"], "sat")

    @unittest.skipUnless(stage_a._import_z3() is not None, "requires Python Z3 bindings")
    def test_internal_direct_call_continuation_proves_with_uninterpreted_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xe8\x03\x00\x00\x00\x89\xc1\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xe8\x03\x00\x00\x00\x8d\x08\xc3\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            self._mapping_entry(size=8),
                            self._mapping_entry(rva=0x1008, size=1, block_id="callee"),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(result["proof"]["assurance"], "incomplete")
            obligation = self._obligation(out, "block:entry")
            self.assertEqual(obligation["proof_rule"], "smt_z3_local_equivalence_v1")
            self.assertEqual(obligation["symbolic"]["smt_status"], "unsat")
            self.assertEqual(obligation["symbolic"]["original_observables"]["reg:ecx"], ["call_response", 0, "eax"])
            self.assertEqual(obligation["symbolic"]["original_observables"]["external_events"][0][0], "internal_call")

    def test_import_thunk_equivalence_uses_import_signature_not_iat_rva_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_import_pe(root / "original.exe", b"\xff\x25\x40\x20\x40\x00", "GetTickCount", iat_offset=0x40)
            candidate = self._write_import_pe(root / "candidate.exe", b"\xff\x25\x44\x20\x40\x00", "GetTickCount", iat_offset=0x44)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(size=6),
                                "source": {
                                    "kind": "import_thunk",
                                    "import_signature": {"dll": "kernel32.dll", "symbol": "GetTickCount", "ordinal": None},
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["assurance"], "lean_kernel_checked_strong_refinement")
            obligation = self._obligation(out, "block:entry")
            self.assertEqual(obligation["proof_rule"], "pe_import_thunk_equivalence_v1")
            self.assertEqual(obligation["original"]["import_signature"], obligation["candidate"]["import_signature"])
            self.assertNotEqual(obligation["original"]["sha256"], obligation["candidate"]["sha256"])
            proof_ir = json.loads((out / "proof-ir.json").read_text(encoding="utf-8"))
            self.assertEqual(proof_ir["environment_profile"]["status"], "satisfied")
            environment_profile_counts = proof_ir["environment_profile"]["counts"]
            self.assertEqual(environment_profile_counts["original_imports"], 1)
            self.assertEqual(environment_profile_counts["candidate_imports"], 1)
            self.assertEqual(environment_profile_counts["import_thunk_block_semantics_records"], 1)
            self.assertEqual(environment_profile_counts["import_thunk_semantic_observable_records"], 1)
            self.assertEqual(environment_profile_counts["import_thunk_trusted_boundary_records"], 1)
            self.assertEqual(environment_profile_counts["import_thunk_solver_evidence_entries"], 1)
            self.assertEqual(environment_profile_counts["import_thunk_semantics_with_original_signature"], 1)
            self.assertEqual(environment_profile_counts["import_thunk_semantics_with_candidate_signature"], 1)
            self.assertEqual(environment_profile_counts["import_thunk_semantics_with_matching_signatures"], 1)
            self.assertEqual(environment_profile_counts["import_thunk_semantics_in_original_loader_imports"], 1)
            self.assertEqual(environment_profile_counts["import_thunk_semantics_in_candidate_loader_imports"], 1)
            self.assertEqual(environment_profile_counts["import_thunk_claims_with_original_signature_hash"], 1)
            self.assertEqual(environment_profile_counts["import_thunk_claims_with_candidate_signature_hash"], 1)
            self.assertEqual(environment_profile_counts["import_thunk_claims_with_matching_signature_hashes"], 1)
            self.assertEqual(environment_profile_counts["environment_gaps"], 0)
            self.assertTrue(proof_ir["environment_profile"]["checks"]["import_thunk_records_accounted"])
            self.assertTrue(proof_ir["environment_profile"]["checks"]["import_thunk_semantics_match_loader_imports"])
            self.assertTrue(proof_ir["closure_certificate"]["checks"]["environment_profile_satisfied"])

    @unittest.skipUnless(stage_a.shutil.which("lean") is not None, "requires Lean")
    def test_formal_profile_rejects_imports_at_different_iat_rvas(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_import_pe(root / "original.exe", b"\xff\x25\x40\x20\x40\x00", "GetTickCount", iat_offset=0x40)
            candidate = self._write_import_pe(root / "candidate.exe", b"\xff\x25\x44\x20\x40\x00", "GetTickCount", iat_offset=0x44)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(size=6),
                                "source": {
                                    "kind": "import_thunk",
                                    "import_signature": {"dll": "kernel32.dll", "symbol": "GetTickCount", "ordinal": None},
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(result["proof"]["assurance"], "incomplete")
            failed_attempt = result["proof"]["lean"]["failed_formal_pass_attempt"]
            self.assertEqual(failed_attempt["formal_proof"]["status"], "incomplete")

    def test_missing_z3_makes_non_identical_symbolic_obligation_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\x90\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\x90\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=4)
            out = root / "report"

            with mock.patch("wincr.stage_a._import_z3", return_value=None):
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "incomplete")
            blocker = json.loads((out / "incomplete" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(blocker["category"], "solver_unavailable")
            self.assertEqual(blocker["details"]["smt_status"], "unavailable")

    def test_unsupported_instruction_reports_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x0f\x0b\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x0f\x0b\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=3)
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            blocker = json.loads((out / "incomplete" / "block-entry.json").read_text(encoding="utf-8"))
            self.assertEqual(blocker["category"], "unsupported_semantics")
            self.assertIn("unsupported instruction ud2", blocker["blocker"])

    def test_unmapped_executable_bytes_report_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=5)
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"]
            unmapped = [item for item in obligations if item["status"] == "unmapped"]
            self.assertEqual(len(unmapped), 2)
            self.assertEqual({item["binary"] for item in unmapped}, {"original", "candidate"})
            proof_ir = json.loads((out / "proof-ir.json").read_text(encoding="utf-8"))
            self.assertEqual(proof_ir["coverage_profile"]["status"], "incomplete")
            self.assertEqual(proof_ir["coverage_profile"]["counts"]["coverage_obligations"], 2)
            self.assertEqual(proof_ir["coverage_profile"]["counts"]["unmapped_coverage_obligations"], 2)
            self.assertEqual(proof_ir["coverage_profile"]["counts"]["open_coverage_obligations"], 2)
            self.assertEqual(proof_ir["coverage_profile"]["counts"]["coverage_gaps"], 2)
            self.assertFalse(proof_ir["coverage_profile"]["checks"]["coverage_status_satisfied"])
            self.assertFalse(proof_ir["coverage_profile"]["checks"]["coverage_gaps_closed"])
            self.assertFalse(proof_ir["proof_context"]["checks"]["coverage_profile_satisfied"])

    def test_hand_authored_non_padding_waiver_is_incomplete_and_unmapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [self._mapping_entry(size=1, block_id="entry")],
                        "waivers": [
                            {"id": "ret-is-not-padding", "binary": "both", "rva": 0x1001, "size": 1, "reason": "bad waiver"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            waiver = self._obligation(out, "waiver:ret-is-not-padding:both:1001-1002")
            self.assertEqual(waiver["status"], "incomplete")
            self.assertEqual(waiver["incomplete"]["category"], "unverified_noncode_waiver")
            obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"]
            unmapped = [item for item in obligations if item["status"] == "unmapped"]
            self.assertEqual({(item["binary"], item["rva_start"], item["rva_end"]) for item in unmapped}, {("original", 0x1001, 0x1002), ("candidate", 0x1001, 0x1002)})

    def test_duplicate_mapping_id_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x50\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x50\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            self._mapping_entry(size=1, block_id="dup"),
                            self._mapping_entry(rva=0x1001, size=1, block_id="dup"),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "fail")
            failure = json.loads((out / "failures" / "mapping-block-dup.json").read_text(encoding="utf-8"))
            self.assertEqual(failure["category"], "invalid_mapping")

    def test_cli_stage_a_legacy_validate_uses_explicit_command_surface(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(root / "block-map.json", size=6)
            out = root / "report"

            with self._mock_lean_checked():
                code = wincr_cli.main(
                    [
                        "stage-a-legacy-validate",
                        "--original",
                        str(original),
                        "--candidate",
                        str(candidate),
                        "--mapping",
                        str(mapping),
                        "--model",
                        STAGE_A_MODEL_ID,
                        "--out",
                        str(out),
                    ],
                    prog="wincr",
                )

            self.assertEqual(code, 0)
            self.assertEqual(json.loads((out / "verdict.json").read_text(encoding="utf-8"))["verdict"], "pass")

    def test_cli_stage_a_legacy_validate_suite_runs_relative_case_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = root / "cases"
            cases.mkdir()
            original = self._write_pe(cases / "original.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            candidate = self._write_pe(cases / "candidate.exe", b"\xb8\x2a\x00\x00\x00\xc3")
            mapping = self._write_mapping(cases / "block-map.json", size=6)
            suite = root / "suite.json"
            suite.write_text(
                json.dumps(
                    {
                        "model": STAGE_A_MODEL_ID,
                        "cases": [
                            {
                                "id": "identity",
                                "original": str(original.relative_to(root)),
                                "candidate": str(candidate.relative_to(root)),
                                "mapping": str(mapping.relative_to(root)),
                                "expect": "pass",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "suite-report"

            with self._mock_lean_checked():
                code = wincr_cli.main(
                    [
                        "stage-a-legacy-validate-suite",
                        "--suite",
                        str(suite),
                        "--out",
                        str(out),
                    ],
                    prog="wincr",
                )

            self.assertEqual(code, 0)
            summary = json.loads((out / "suite.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["status"], "pass")
            self.assertEqual(summary["counts"], {"cases": 1, "passed": 1, "failed": 0, "incomplete": 0})
            self.assertEqual(summary["cases"][0]["actual_verdict"], "pass")
            self.assertTrue((out / "cases" / "identity" / "verdict.json").exists())

    def test_stage_a_generate_map_classifies_paired_executable_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x50\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x50\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401001                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401001                tiny\n", encoding="utf-8")
            mapping = root / "jq-block-map.json"
            layout = root / "jq-layout-contract.json"

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=mapping,
                layout_contract_out=layout,
                original_flags="-O2 test",
                candidate_flags="-O2 -falign-functions=32 test",
            )

            self.assertEqual(result["status"], "pass")
            payload = json.loads(mapping.read_text(encoding="utf-8"))
            self.assertEqual(payload["counts"]["issues"], 0)
            self.assertEqual(payload["counts"]["blocks"], 2)
            self.assertIn("section-gap--text-0000", {block["id"] for block in payload["blocks"]})
            self.assertEqual(payload["blocks"][0]["proof"]["original_flags"], "-O2 test")
            self.assertEqual(payload["blocks"][0]["proof"]["candidate_flags"], "-O2 -falign-functions=32 test")
            contract = json.loads(layout.read_text(encoding="utf-8"))
            self.assertTrue(contract["facts"]["all_executable_bytes_classified"])
            self.assertTrue(contract["facts"]["matching_section_rvas"])
            self.assertTrue(contract["facts"]["matching_normalized_executable_section_spans"])

    def test_linker_map_parser_uses_split_text_fragment_as_weak_function_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary_path = self._write_pe(root / "candidate.exe", b"\xc3" * 0x90)
            linker_map = root / "candidate.map"
            linker_map.write_text(
                "\n".join(
                    [
                        " .text$dirname  0x00401000       0x20 object.o",
                        "                0x00401000                dirname",
                        " .text$dtoa_lock",
                        "                0x00401020        0xc object.o",
                        "                0x00401020                .weak._dtoa_lock.___crt_atexit",
                        " .text$isoptish",
                        "                0x0040102c        0xc object.o",
                        "                0x0040102c                .weak._isoptish.___crt_atexit",
                        " .text$process  0x00401038        0xc object.o",
                        "                0x00401038                process",
                        " .text$umain     0x00401044       0x30 object.o",
                        "                0x00401044                umain",
                        "                0x0040104c                _fu2___setmode",
                        "                0x00401058                stage_b_contract_rva_00001058",
                        " .text$after_umain",
                        "                0x00401074       0x10 object.o",
                        "                0x00401074                after_umain",
                    ]
                ),
                encoding="utf-8",
            )

            stage_a_functions = stage_a._parse_linker_map_functions(linker_map, stage_a._parse_stage_a_pe(binary_path))
            stage_binary_functions = stage_binary._parse_linker_map_functions(linker_map, stage_binary._parse_stage_a_pe(binary_path))

        self.assertIs(stage_a._parse_stage_a_pe, stage_binary._parse_stage_a_pe)
        self.assertIs(stage_a._parse_linker_map_functions, stage_binary._parse_linker_map_functions)
        for functions in (stage_a_functions, stage_binary_functions):
            by_name = {item["name"]: item for item in functions}
            self.assertEqual(by_name["dirname"]["rva_start"], 0x1000)
            self.assertEqual(by_name["dirname"]["rva_end"], 0x1020)
            self.assertEqual(by_name["dtoa_lock"]["rva_start"], 0x1020)
            self.assertEqual(by_name["dtoa_lock"]["rva_end"], 0x102C)
            self.assertEqual(by_name["isoptish"]["rva_start"], 0x102C)
            self.assertEqual(by_name["isoptish"]["rva_end"], 0x1038)
            self.assertEqual(by_name["process"]["rva_start"], 0x1038)
            self.assertEqual(by_name["process"]["rva_end"], 0x1044)
            self.assertEqual(by_name["umain"]["rva_start"], 0x1044)
            self.assertEqual(by_name["umain"]["rva_end"], 0x1074)
            self.assertEqual(by_name["after_umain"]["rva_start"], 0x1074)
            self.assertNotIn("fu2___setmode", by_name)
            self.assertNotIn("_fu2___setmode", by_name)
            self.assertNotIn("stage_b_contract_rva_00001058", by_name)

    def test_stage_a_generate_map_splits_basic_blocks_and_uses_cfg_reachability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = b"\x83\xf8\x00\x74\x01\xc3\xc3"  # cmp eax, 0; je 0x1006; ret; ret
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                branchy\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                branchy\n", encoding="utf-8")
            mapping = root / "jq-block-map.json"

            generated = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=mapping,
            )

            self.assertEqual(generated["status"], "pass")
            payload = json.loads(mapping.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["blocks"]), 3)
            self.assertIn("root", payload["blocks"][0])
            self.assertNotIn("root", payload["blocks"][1])
            self.assertNotIn("root", payload["blocks"][2])

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                )

            self.assertEqual(result["verdict"], "pass")
            reachability = self._obligation(root / "report", "reachability:branchy-0001")
            self.assertEqual(reachability["proof_rule"], "direct_cfg_reachability_v1")

    def test_stage_a_generate_map_reports_block_shapes_for_ambiguous_function_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x74\x01\xc3\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                branchy\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                branchy\n", encoding="utf-8")

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "jq-block-map.json",
            )

            self.assertEqual(result["status"], "incomplete")
            issue = next(issue for issue in result["issues"] if issue["category"] == "ambiguous_block_match")
            details = issue["details"]
            self.assertEqual(details["function"], "branchy")
            self.assertEqual(details["original_blocks"], 1)
            self.assertEqual(details["candidate_blocks"], 3)
            self.assertEqual(details["block_count_delta"], 2)
            self.assertEqual(details["original_block_shapes"]["items"][0]["terminal_instruction"]["mnemonic"], "ret")
            self.assertEqual(details["candidate_block_shapes"]["items"][0]["terminal_instruction"]["mnemonic"], "je")
            self.assertEqual(details["candidate_block_shapes"]["items"][0]["direct_edge_counts"], {"taken": 1, "fallthrough": 1})
            self.assertEqual(details["candidate_block_shapes"]["items"][0]["direct_edges"][0]["target_rva"], 0x1003)

    def test_stage_a_generate_map_rejects_duplicate_linker_map_function_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text(
                "                0x00401000                duplicate\n"
                "                0x00401001                duplicate\n",
                encoding="utf-8",
            )
            candidate_map.write_text(
                "                0x00401000                duplicate\n"
                "                0x00401001                duplicate\n",
                encoding="utf-8",
            )

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "jq-block-map.json",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("ambiguous_linker_map", {issue["category"] for issue in result["issues"]})

    def test_stage_a_generate_map_matches_unique_decorated_function_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                __mingw_printf\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                ___mingw_printf@0\n", encoding="utf-8")

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "jq-block-map.json",
            )

            self.assertEqual(result["status"], "pass")
            block = result["blocks"][0]
            self.assertEqual(block["source"]["function"], "__mingw_printf")
            self.assertEqual(block["source"]["candidate_function"], "___mingw_printf@0")
            self.assertEqual(block["source"]["function_match_key"], "mingw_printf")

    def test_stage_a_generate_map_rejects_duplicate_canonical_function_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text(
                "                0x00401000                __same\n"
                "                0x00401001                ___same@0\n",
                encoding="utf-8",
            )
            candidate_map.write_text("                0x00401000                ____same\n", encoding="utf-8")

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "jq-block-map.json",
            )

            self.assertEqual(result["status"], "incomplete")
            duplicate_key_issues = [
                issue
                for issue in result["issues"]
                if issue.get("obligation_id") == "map:alias:same"
            ]
            self.assertEqual(len(duplicate_key_issues), 1)

    def test_stage_a_generate_map_matches_unique_import_thunks_by_import_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_import_pe(root / "original.exe", b"\xff\x25\x40\x20\x40\x00", "GetTickCount", iat_offset=0x40)
            candidate = self._write_import_pe(root / "candidate.exe", b"\xff\x25\x44\x20\x40\x00", "GetTickCount", iat_offset=0x44)
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                _GetTickCount@0\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                imported_GetTickCount\n", encoding="utf-8")
            mapping = root / "jq-block-map.json"

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=mapping,
            )

            self.assertEqual(result["status"], "pass")
            self.assertEqual(len(result["blocks"]), 1)
            block = result["blocks"][0]
            self.assertEqual(block["source"]["kind"], "import_thunk")
            self.assertEqual(block["source"]["function"], "_GetTickCount@0")
            self.assertEqual(block["source"]["candidate_function"], "imported_GetTickCount")
            self.assertEqual(block["source"]["import_signature"]["symbol"], "GetTickCount")

            with self._mock_lean_checked():
                validation = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                )

            self.assertEqual(validation["verdict"], "pass")
            self.assertEqual(validation["proof"]["assurance"], "lean_kernel_checked_strong_refinement")
            self.assertEqual(self._obligation(root / "report", f"block:{block['id']}")["proof_rule"], "pe_import_thunk_equivalence_v1")

    def test_stage_a_generate_map_rejects_ambiguous_import_thunk_signature_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            thunk = b"\xff\x25\x40\x20\x40\x00"
            original = self._write_import_pe(root / "original.exe", thunk + b"\x90" * 6, "GetTickCount")
            candidate = self._write_import_pe(root / "candidate.exe", thunk + thunk, "GetTickCount")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                original_import\n", encoding="utf-8")
            candidate_map.write_text(
                "                0x00401000                candidate_import_a\n"
                "                0x00401006                candidate_import_b\n",
                encoding="utf-8",
            )

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "jq-block-map.json",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("ambiguous_import_thunk_match", {issue["category"] for issue in result["issues"]})

    def test_stage_a_generate_map_writes_reproducible_layout_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x50\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x50\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401001                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401001                tiny\n", encoding="utf-8")
            layout_a = root / "layout-a.json"
            layout_b = root / "layout-b.json"

            for out, layout in ((root / "map-a.json", layout_a), (root / "map-b.json", layout_b)):
                result = stage_a_generate_map(
                    original=original,
                    candidate=candidate,
                    linker_map_original=original_map,
                    linker_map_candidate=candidate_map,
                    out=out,
                    layout_contract_out=layout,
                )
                self.assertEqual(result["status"], "pass")

            self.assertEqual(layout_a.read_bytes(), layout_b.read_bytes())

    def test_stage_a_generate_map_normalizes_deprecated_proof_rule_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                proof_rule="reproducible_jq_same_source_optimization_pair_v1",
            )

            self.assertEqual(result["status"], "pass")
            generated_map = json.loads(block_map.read_text(encoding="utf-8"))
            proof = generated_map["blocks"][0]["proof"]
            self.assertEqual(proof["rule"], "same_source_layout_preserving_build_v1")
            self.assertEqual(proof["deprecated_rule_alias"], "reproducible_jq_same_source_optimization_pair_v1")

    def test_stage_a_generate_map_requires_stage_b_metadata_for_generic_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "block-map.json",
                proof_rule="stage_b_skeleton_reimplementation_contract_v1",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("missing_stage_b_proof_metadata", {issue["category"] for issue in result["issues"]})

    def test_stage_a_export_reference_contract_records_binary_faithfulness_constraints(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            generated_map = json.loads(block_map.read_text(encoding="utf-8"))
            self.assertEqual(generated_map["blocks"][0]["proof"]["rule"], "same_source_layout_preserving_build_v1")
            with self._mock_lean_checked():
                validation = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )
            self.assertEqual(validation["proof"]["proof_ir"]["format"], "stage-a-proof-ir-v1")
            self.assertEqual(validation["proof"]["solver_evidence"]["format"], "stage-a-solver-evidence-v1")
            self.assertEqual(validation["proof"]["solver_evidence"]["status"], "satisfied")
            self.assertTrue(validation["proof"]["lean"]["proof_ir_checked"])
            self.assertTrue(validation["proof"]["lean"]["proof_ir_model_hash_bound_checked"])
            self.assertTrue(validation["proof"]["lean"]["proof_ir_target_profile_checked"])
            self.assertTrue(validation["proof"]["lean"]["proof_ir_loader_frontend_profile_checked"])
            self.assertTrue(validation["proof"]["lean"]["proof_ir_closure_certificate_checked"])
            self.assertTrue(validation["proof"]["lean"]["solver_evidence_checked"])
            self.assertTrue(validation["proof"]["lean"]["proof_evidence_binding_checked"])
            self.assertTrue((root / "report" / "proof-ir.json").exists())
            self.assertTrue((root / "report" / "solver-evidence.jsonl").exists())

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "report",
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            self.assertEqual(result["format"], "stage-a-reference-contract-v1")
            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["constraints"]["proof_obligation_inventory"]["status"], "satisfied")
            self.assertEqual(result["constraints"]["executable_byte_coverage"]["status"], "satisfied")
            self.assertEqual(result["constraints"]["layout_normalization_assumptions"]["status"], "satisfied")
            self.assertEqual(result["constraints"]["validation_report_artifact_binding"]["status"], "satisfied")
            binding_facts = result["constraints"]["validation_report_artifact_binding"]["facts"]
            self.assertTrue(binding_facts["verdict_model_hash_matches_payload"])
            self.assertTrue(binding_facts["proof_ir_model_hash_matches_payload"])
            self.assertTrue(binding_facts["proof_ir_context_model_hash_bound"])
            self.assertEqual(binding_facts["proof_ir_loader_frontend_profile_status"], "satisfied")
            self.assertEqual(binding_facts["proof_ir_solver_backend_profile_status"], "satisfied")
            self.assertEqual(binding_facts["proof_ir_profile_manifest_status"], "satisfied")
            self.assertTrue(binding_facts["matching_mapping_payload"])
            self.assertTrue(binding_facts["layout_artifact_matches_proof_ir"])
            self.assertTrue(binding_facts["obligations_artifact_matches_verdict"])
            self.assertTrue(binding_facts["obligations_artifact_matches_proof_ir"])
            self.assertTrue(binding_facts["proof_ir_artifact_matches_verdict"])
            self.assertTrue(binding_facts["proof_cache_artifacts_match_proof_ir"])
            self.assertTrue(binding_facts["solver_evidence_artifacts_match_verdict"])
            self.assertEqual(binding_facts["proof_ir_target_profile_status"], "satisfied")
            self.assertTrue(binding_facts["lean_summary_matches_verdict"])
            self.assertTrue(binding_facts["lean_summary_final_pass_allowed"])
            self.assertTrue(binding_facts["lean_inputs_matches_summary"])
            self.assertTrue(binding_facts["lean_source_artifacts_match_summary"])
            self.assertEqual(result["constraints"]["function_ranges"]["functions"][0]["name"], "tiny")
            self.assertIn("relocations", result["original"])
            self.assertTrue((root / "reference-contract.json").exists())
            for family in result["families"]:
                self.assertIn(family["status"], {"satisfied", "incomplete", "not_applicable", "violated"})
                self.assertNotEqual(family["status"], "represented")
            self.assertEqual(
                {item["family"]: item["status"] for item in result["families"]}["proof_inventory"],
                "satisfied",
            )

            coverage_gaps = json.loads((root / "coverage_gaps.json").read_text(encoding="utf-8"))
            obligation_index = json.loads((root / "obligation_index.json").read_text(encoding="utf-8"))
            contract_summary = json.loads((root / "contract_summary.json").read_text(encoding="utf-8"))
            self.assertEqual(coverage_gaps["format"], "stage-a-coverage-gaps-v1")
            self.assertEqual(coverage_gaps["status"], "pass")
            self.assertEqual(coverage_gaps["counts"]["gaps"], 0)
            self.assertEqual(obligation_index["format"], "stage-a-obligation-index-v1")
            self.assertGreater(obligation_index["counts"]["obligations"], 0)
            self.assertEqual(contract_summary["format"], "stage-a-contract-summary-v1")
            by_status = contract_summary["counts"]["by_status"]
            self.assertEqual(by_status.get("incomplete", 0), 0)
            self.assertEqual(by_status.get("violated", 0), 0)
            self.assertEqual(by_status["satisfied"] + by_status["not_applicable"], len(result["families"]))

            smoke = stage_a_smoke_contract(reference_contract=root / "reference-contract.json")
            self.assertEqual(smoke["status"], "pass")

    def test_stage_a_reference_contract_records_coff_symbol_aliases_on_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe_with_coff_symbol(root / "original.exe", b"\xc3", "_tinyh")
            candidate = self._write_pe_with_coff_symbol(root / "candidate.exe", b"\xc3", "_tinyh")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
            )

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            block = result["constraints"]["basic_blocks_and_cfg"]["basic_blocks"][0]
            self.assertEqual(block["id"], "tiny-0000")
            self.assertIn("_tinyh", block["symbol_aliases"]["original"])
            self.assertIn("tinyh", block["symbol_aliases"]["original"])
            self.assertIn("_tinyh", block["symbol_aliases"]["candidate"])
            self.assertIn("tinyh", block["symbol_aliases"]["candidate"])

    def test_stage_a_export_reference_contract_writes_unit_contract_sidecars(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                ___dyn_tls_init@12\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                ___dyn_tls_init@12\n", encoding="utf-8")
            block_map = root / "block-map.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
            )
            units = root / "units"

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            self.assertIn("unit_contracts", result["sidecars"])
            for name in (
                "block-contracts.jsonl",
                "function-contracts.jsonl",
                "cluster-contracts.jsonl",
                "repair-units.json",
                "source-obligations.json",
                "semantic-transfer-contracts.jsonl",
                "memory-frame-contracts.json",
                "call-summary-contracts.json",
                "cluster-semantic-contracts.jsonl",
            ):
                self.assertTrue((units / name).exists(), name)
            block_contract = json.loads((units / "block-contracts.jsonl").read_text(encoding="utf-8").splitlines()[0])
            function_contract = json.loads((units / "function-contracts.jsonl").read_text(encoding="utf-8").splitlines()[0])
            cluster_contracts = [
                json.loads(line)
                for line in (units / "cluster-contracts.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            self.assertEqual(block_contract["format"], "stage-a-block-contract-v1")
            self.assertEqual(block_contract["function"], "___dyn_tls_init@12")
            self.assertEqual(function_contract["format"], "stage-a-function-contract-v1")
            self.assertEqual(function_contract["function"], "___dyn_tls_init@12")
            self.assertIn("tls_callback_abi", {item["repair_class"] for item in cluster_contracts})

            work = stage_a_extract_work_items(
                reference_contract=root / "reference-contract.json",
                unit_contract_dir=units,
                out=root / "work-items.json",
            )
            self.assertEqual(work["format"], "stage-a-work-items-v1")
            self.assertGreater(work["counts"]["work_items"], 0)
            self.assertIn("tls_callback_abi", {item["repair_class"] for item in work["work_items"]})

    def test_reference_contract_semantic_transfer_sidecar_exports_block_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex("83c404")  # add esp, 4
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = self._write_mapping(root / "block-map.json", size=len(code), block_id="stack-adjust")
            units = root / "units"

            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            transfer = json.loads((units / "semantic-transfer-contracts.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(transfer["format"], "stage-a-semantic-transfer-contract-v1")
            self.assertEqual(transfer["status"], "reimplementable")
            self.assertEqual(transfer["stack_delta"]["net_bytes"], 4)
            self.assertIn("esp", {item["register"] for item in transfer["register_writes"]})
            self.assertEqual(transfer["outcome"]["kind"], "fallthrough")

            coverage = stage_a_semantic_coverage(
                reference_contract=root / "reference-contract.json",
                unit_contract_dir=units,
                out=root / "semantic-coverage.json",
            )
            self.assertEqual(coverage["status"], "pass")
            self.assertEqual(coverage["counts"]["analysis_blocked"], 0)
            self.assertTrue(coverage["acceptance"]["full_reimplementation_ready"])

    def test_reference_contract_semantic_transfer_exports_internal_call_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = b"\xe8\x03\x00\x00\x00\x89\xc1\xc3"
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = self._write_mapping(root / "block-map.json", size=len(code), block_id="internal-call")
            units = root / "units"

            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            transfer = json.loads((units / "semantic-transfer-contracts.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(transfer["status"], "reimplementable")
            self.assertEqual(transfer["external_events"][0]["kind"], "internal_call")
            self.assertEqual(transfer["external_events"][0]["target_rva"], 0x1008)
            self.assertEqual(transfer["external_events"][0]["effect_model"], "uninterpreted_internal_call_response_v1")
            register_writes = {item["register"]: item["value"] for item in transfer["register_writes"]}
            self.assertEqual(register_writes["ecx"], {"op": "call_response", "width": 32, "call_index": 0, "register": "eax"})

    def test_reference_contract_emits_checked_verified_decompiler_region_for_selected_jq_cluster(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = b"\xc3"
            caller = bytes.fromhex("8d431cba0100000089d9e802000000ebee")
            callee = b"\xc3"
            original = self._write_pe(root / "original.exe", target + caller + callee)
            candidate = self._write_pe(root / "candidate.exe", target + caller + callee)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(rva=0x1000, size=len(target), block_id="section-gap--text-0494"),
                                "source": {"kind": "linker_map_function", "function": "section-gap--text-0494"},
                            },
                            {
                                **self._mapping_entry(rva=0x1000 + len(target), size=len(caller), block_id="section-gap--text-0498"),
                                "source": {"kind": "linker_map_function", "function": "section-gap--text-0498"},
                            },
                            {
                                **self._mapping_entry(
                                    rva=0x1000 + len(target) + len(caller),
                                    size=len(callee),
                                    block_id="section-gap--text-0202",
                                ),
                                "source": {"kind": "linker_map_function", "function": "section-gap--text-0202"},
                            },
                        ],
                        "status": "pass",
                    }
                ),
                encoding="utf-8",
            )
            units = root / "units"

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            semantic = result["constraints"]["semantic_region_contracts"]
            self.assertEqual(semantic["status"], "satisfied")
            region = semantic["regions"][0]
            self.assertEqual(region["status"], "checked")
            self.assertEqual(region["function"], "section-gap--text-0498")
            self.assertEqual(region["callee"]["block_id"], "section-gap--text-0202")
            direct_jump = region["ir"]["operations"][-1]
            direct_call = region["ir"]["operations"][-2]
            self.assertEqual(direct_call["op"], "direct_call")
            self.assertEqual([item["register"] for item in direct_call["register_arguments"]], ["eax", "edx", "ecx"])
            self.assertEqual(direct_jump["op"], "direct_jump")
            self.assertEqual(direct_jump["target_block_id"], "section-gap--text-0494")
            self.assertEqual(region["c_contract"]["status"], "checked")
            self.assertEqual(region["x86_to_ir_validation"]["status"], "proved")
            self.assertEqual(region["c_contract_equivalence"]["status"], "proved")
            proof_ids = {item["id"] for item in result["constraints"]["proof_obligation_inventory"]["obligations"]}
            self.assertIn("semantic-region:section-gap-0498-to-0202:x86-to-ir", proof_ids)
            sidecar_rows = [
                json.loads(line)
                for line in (units / "semantic-region-contracts.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            self.assertEqual(sidecar_rows[0]["status"], "checked")

    def test_reference_contract_semantic_region_fails_closed_on_register_setup_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = b"\xc3"
            caller = bytes.fromhex("8d4320ba0100000089d9e802000000ebee")
            callee = b"\xc3"
            original = self._write_pe(root / "original.exe", target + caller + callee)
            candidate = self._write_pe(root / "candidate.exe", target + caller + callee)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(rva=0x1000, size=len(target), block_id="section-gap--text-0494"),
                                "source": {"kind": "linker_map_function", "function": "section-gap--text-0494"},
                            },
                            {
                                **self._mapping_entry(rva=0x1000 + len(target), size=len(caller), block_id="section-gap--text-0498"),
                                "source": {"kind": "linker_map_function", "function": "section-gap--text-0498"},
                            },
                            {
                                **self._mapping_entry(
                                    rva=0x1000 + len(target) + len(caller),
                                    size=len(callee),
                                    block_id="section-gap--text-0202",
                                ),
                                "source": {"kind": "linker_map_function", "function": "section-gap--text-0202"},
                            },
                        ],
                        "status": "pass",
                    }
                ),
                encoding="utf-8",
            )

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=root / "units",
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            semantic = result["constraints"]["semantic_region_contracts"]
            self.assertEqual(semantic["status"], "incomplete")
            region = semantic["regions"][0]
            self.assertEqual(region["status"], "incomplete")
            self.assertEqual(region["blocker_category"], "x86_to_ir_register_input_mismatch")
            self.assertEqual(region["proof_obligations"][0]["status"], "incomplete")

    def test_semantic_region_abi_inventory_accepts_provenance_rich_matching_sources(self):
        callsite = {
            "argument_inventory": {
                "register_args": [
                    {
                        "register": "eax",
                        "source": {
                            "kind": "address",
                            "address_class": "computed_address",
                            "addressing": {"base": "ebx", "index": None, "scale": 1, "disp": 0x1C},
                            "instruction": {"mnemonic": "lea", "op_str": "eax, [ebx + 0x1c]"},
                        },
                    },
                    {
                        "register": "edx",
                        "source": {
                            "kind": "immediate",
                            "value": 1,
                            "instruction": {"mnemonic": "mov", "op_str": "edx, 1"},
                        },
                    },
                    {
                        "register": "ecx",
                        "source": {
                            "kind": "register",
                            "register": "ebx",
                            "instruction": {"mnemonic": "mov", "op_str": "ecx, ebx"},
                        },
                    },
                ]
            }
        }

        self.assertEqual(
            stage_a._semantic_region_abi_inventory_mismatches(
                callsite,
                (
                    ("eax", ("add", ("reg", "ebx"), ("const", 0x1C))),
                    ("edx", ("const", 1)),
                    ("ecx", ("reg", "ebx")),
                ),
            ),
            [],
        )
        bad_callsite = copy.deepcopy(callsite)
        bad_callsite["argument_inventory"]["register_args"][0]["source"]["addressing"]["disp"] = 0x20
        self.assertEqual(
            stage_a._semantic_region_abi_inventory_mismatches(
                bad_callsite,
                (
                    ("eax", ("add", ("reg", "ebx"), ("const", 0x1C))),
                    ("edx", ("const", 1)),
                    ("ecx", ("reg", "ebx")),
                ),
            )[0]["register"],
            "eax",
        )

    def test_reference_contract_semantic_transfer_fail_closed_for_unsupported_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex("0f0b")  # ud2 remains outside the executable transfer model
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = self._write_mapping(root / "block-map.json", size=len(code), block_id="unsupported-ud2")
            units = root / "units"

            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            transfer = json.loads((units / "semantic-transfer-contracts.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(transfer["status"], "incomplete")
            self.assertEqual(transfer["blocker_category"], "unsupported_semantics")
            work = json.loads((units / "repair-units.json").read_text(encoding="utf-8"))["work_items"]
            self.assertIn("semantic_transfer", {item["family"] for item in work})

            coverage = stage_a_semantic_coverage(
                reference_contract=root / "reference-contract.json",
                unit_contract_dir=units,
                out=root / "semantic-coverage.json",
            )
            self.assertEqual(coverage["status"], "incomplete")
            self.assertEqual(coverage["counts"]["analysis_blocked"], 1)
            self.assertEqual(coverage["counts"]["unsupported_instruction_shapes"], 1)
            self.assertEqual(coverage["blockers"][0]["function"], "unsupported-ud2")

    def test_stage_a_validate_unit_filters_contract_focus_without_original_tracing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )
                stage_a_export_reference_contract(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    validation_report=root / "report",
                    layout_contract=layout_contract,
                    model=STAGE_A_MODEL_ID,
                    out=root / "reference-contract.json",
                )
            skeleton_manifest = self._write_skeleton_manifest(
                root / "manifest.json",
                [{"function": "tiny", "file": "src/jq_stage_b_skeleton.c", "line_start": 10, "line_end": 12}],
            )

            result = stage_a_validate_unit(
                reference_contract=root / "reference-contract.json",
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_manifest,
                focus="tiny",
                model=STAGE_A_MODEL_ID,
                out=root / "unit",
            )

            self.assertEqual(result["status"], "pass")
            self.assertGreater(result["counts"]["unit_contracts"], 0)
            self.assertTrue((root / "unit" / "unit-validation.json").exists())

    def test_stage_a_validate_unit_reuses_supplied_contract_candidate_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference_contract = root / "reference-contract.json"
            candidate = root / "candidate.exe"
            candidate_map = root / "candidate.map"
            skeleton_manifest = root / "manifest.json"
            reference_contract.write_text(
                json.dumps({"format": "stage-a-reference-contract-v1", "model": STAGE_A_MODEL_ID, "families": []}),
                encoding="utf-8",
            )
            candidate.write_bytes(b"not parsed when validation is supplied")
            candidate_map.write_text("not parsed\n", encoding="utf-8")
            skeleton_manifest.write_text(json.dumps({"format": "stage-b-skeleton-v1"}), encoding="utf-8")
            validation = {
                "format": "stage-a-contract-candidate-validation-v1",
                "status": "incomplete",
                "verdict": "incomplete",
                "families": [{"family": "cfg", "status": "incomplete", "function": "selected"}],
                "issues": [],
                "counts": {"families": 1, "issues": 0},
            }

            with mock.patch("wincr.stage_a.stage_a_validate_contract_candidate") as validate_candidate:
                result = stage_a_validate_unit(
                    reference_contract=reference_contract,
                    candidate=candidate,
                    linker_map_candidate=candidate_map,
                    skeleton_manifest=skeleton_manifest,
                    focus="selected",
                    model=STAGE_A_MODEL_ID,
                    contract_candidate_validation=validation,
                    out=root / "unit",
                )

            validate_candidate.assert_not_called()
            self.assertEqual(result["contract_candidate_validation_source"], "provided")
            self.assertEqual(result["candidate_contract_status"], "incomplete")
            self.assertEqual(result["focused_status"], "incomplete")
            self.assertEqual(result["counts"]["families"], 1)
            self.assertTrue((root / "unit" / "unit-validation.json").exists())

    def test_reference_contract_abi_callsites_ignore_prologue_pushes_and_capture_stack_slots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex(
                "55"  # push ebp
                "89e5"  # mov ebp, esp
                "83ec10"  # sub esp, 0x10
                "b878563412"  # mov eax, 0x12345678
                "89442404"  # mov [esp + 4], eax
                "c7042400204000"  # mov dword ptr [esp], 0x402000
                "e800000000"  # call next instruction
                "c9"  # leave
                "c3"  # ret
            )
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = self._write_mapping(root / "block-map.json", size=len(code), block_id="stack-args")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            abi = result["constraints"]["abi_callsites"]
            self.assertEqual(abi["counts"]["callsites"], 1)
            self.assertEqual(abi["original"]["functions"][0]["stack_delta"]["net_bytes"], 0)
            callsite = abi["original"]["functions"][0]["callsites"][0]
            sources = callsite["argument_sources"]
            self.assertEqual([source["stack_offset"] for source in sources], [4, 0])
            self.assertEqual(sources[0]["kind"], "register")
            self.assertEqual(sources[0]["register"], "eax")
            self.assertEqual(sources[1]["kind"], "immediate")
            self.assertEqual(sources[1]["value"], 0x402000)
            source_rvas = {
                source["instruction"]["rva"]
                for source in sources
                if isinstance(source.get("instruction"), dict)
            }
            self.assertNotIn(0x1000, source_rvas)
            self.assertNotIn("source", callsite["hidden_sret_or_out_param_evidence"])
            self.assertEqual(
                callsite["hidden_sret_or_out_param_evidence"]["reason"],
                "first_stack_argument_not_address_like",
            )

    def test_reference_contract_abi_stack_delta_tracks_explicit_cdecl_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex(
                "6a01"  # push 1
                "e800000000"  # call next instruction
                "83c404"  # add esp, 4
                "c3"  # ret
            )
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = self._write_mapping(root / "block-map.json", size=len(code), block_id="cdecl-cleanup")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            function = result["constraints"]["abi_callsites"]["original"]["functions"][0]
            self.assertEqual(function["stack_delta"]["net_bytes"], 0)
            self.assertEqual(function["blocks"][0]["abi"]["stack_delta"]["net_bytes"], 0)

    def test_reference_contract_abi_stack_delta_marks_multiblock_functions_block_local(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex(
                "55"  # push ebp
                "c3"  # ret
            )
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(rva=0x1000, size=1, block_id="split-0000"),
                                "source": {"function": "split"},
                            },
                            {
                                **self._mapping_entry(rva=0x1001, size=1, block_id="split-0001"),
                                "source": {"function": "split"},
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            function = result["constraints"]["abi_callsites"]["original"]["functions"][0]
            self.assertEqual(function["name"], "split")
            self.assertEqual(function["stack_delta"]["status"], "block_local")
            self.assertEqual(function["stack_delta"]["blocks"], 2)
            self.assertEqual(function["blocks"][0]["abi"]["stack_delta"]["status"], "derived")

    def test_reference_contract_abi_carries_predecessor_stack_arguments_to_split_call_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            setup = bytes.fromhex(
                "c744240800000000"  # mov dword ptr [esp + 8], 0
                "c74424040a000000"  # mov dword ptr [esp + 4], 0xa
                "890424"  # mov dword ptr [esp], eax
                "7406"  # je branch-call, skipping the fallthrough call and return
            )
            fallthrough_call = bytes.fromhex("e800000000")
            branch_call = bytes.fromhex("e800000000")
            code = setup + fallthrough_call + b"\xc3" + branch_call + b"\xc3"
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(rva=0x1000, size=len(setup), block_id="split-call-setup"),
                                "source": {"function": "split_call"},
                            },
                            {
                                **self._mapping_entry(rva=0x1000 + len(setup), size=len(fallthrough_call), block_id="split-call-fallthrough"),
                                "source": {"function": "split_call"},
                            },
                            {
                                **self._mapping_entry(
                                    rva=0x1000 + len(setup) + len(fallthrough_call) + 1,
                                    size=len(branch_call),
                                    block_id="split-call-branch",
                                ),
                                "source": {"function": "split_call"},
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            function = result["constraints"]["abi_callsites"]["original"]["functions"][0]
            self.assertEqual(function["name"], "split_call")
            self.assertEqual(len(function["callsites"]), 2)
            for callsite in function["callsites"]:
                self.assertEqual([source["stack_offset"] for source in callsite["argument_sources"]], [8, 4, 0])
                self.assertEqual(
                    [arg["source"]["stack_offset"] for arg in callsite["argument_inventory"]["stack_args"]],
                    [0, 4, 8],
                )
                self.assertEqual(callsite["argument_inventory"]["argument_count"], 3)
                self.assertEqual(callsite["predecessor_argument_sources"]["source"], "direct_cfg_predecessor_exit")
                self.assertEqual(callsite["predecessor_argument_sources"]["predecessor_block_ids"], ["split-call-setup"])

    def test_reference_contract_abi_callsites_mark_explicit_stack_address_first_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex(
                "55"  # push ebp
                "89e5"  # mov ebp, esp
                "83ec10"  # sub esp, 0x10
                "8d45fc"  # lea eax, [ebp - 4]
                "890424"  # mov [esp], eax
                "e800000000"  # call next instruction
                "c9"  # leave
                "c3"  # ret
            )
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = self._write_mapping(root / "block-map.json", size=len(code), block_id="stack-address")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            callsite = result["constraints"]["abi_callsites"]["original"]["functions"][0]["callsites"][0]
            source = callsite["argument_sources"][0]
            self.assertEqual(source["kind"], "register")
            self.assertEqual(source["register"], "eax")
            self.assertEqual(source["register_definition"]["kind"], "address")
            self.assertEqual(source["register_definition"]["address_class"], "stack_address")
            self.assertEqual(callsite["hidden_sret_or_out_param_evidence"]["status"], "candidate")
            self.assertEqual(
                callsite["hidden_sret_or_out_param_evidence"]["address_role"],
                "stack_out_param_or_scratch_buffer",
            )
            self.assertEqual(
                callsite["hidden_sret_or_out_param_evidence"]["reason"],
                "first_stack_argument_has_address_provenance",
            )

    def test_reference_contract_unit_sidecars_include_register_out_param_memory_and_clusters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex(
                "c70000000000"  # mov dword ptr [eax], 0
                "c3"  # ret
            )
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = self._write_mapping(root / "block-map.json", size=len(code), block_id="write-through-eax")
            units = root / "units"

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            function = result["constraints"]["abi_callsites"]["original"]["functions"][0]
            self.assertEqual(function["register_out_param_candidates"][0]["register"], "eax")
            self.assertEqual(function["memory_effect_summary"]["writes"], 1)
            block_contract = json.loads((units / "block-contracts.jsonl").read_text(encoding="utf-8").splitlines()[0])
            state = block_contract["state_contract"]
            self.assertEqual(state["register_out_param_candidates"][0]["kind"], "register_carried_out_param")
            self.assertEqual(state["memory_writes"][0]["memory_role"], "computed_memory")
            memory_frames = json.loads((units / "memory-frame-contracts.json").read_text(encoding="utf-8"))
            self.assertEqual(memory_frames["counts"]["accesses"], 1)
            self.assertEqual(memory_frames["accesses"][0]["frame_kind"], "object.pointer_candidate")
            clusters = [
                json.loads(line)
                for line in (units / "cluster-contracts.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            self.assertIn("abi_register_carried_out_param", {item["cluster_kind"] for item in clusters})
            self.assertIn("hidden_sret_or_out_param", {item["repair_class"] for item in clusters})

    def test_reference_contract_unit_sidecars_include_switch_and_loop_contract_clusters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            switch_code = bytes.fromhex("ff248500504000")  # jmp dword ptr [eax * 4 + 0x405000]
            loop_code = bytes.fromhex("ebfe")  # jmp self
            code = switch_code + loop_code
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            self._mapping_entry(rva=0x1000, size=len(switch_code), block_id="switch-dispatch"),
                            self._mapping_entry(rva=0x1000 + len(switch_code), size=len(loop_code), block_id="loop-backedge"),
                        ]
                    }
                ),
                encoding="utf-8",
            )
            units = root / "units"

            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            clusters = [
                json.loads(line)
                for line in (units / "cluster-contracts.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            kinds = {item["cluster_kind"] for item in clusters}
            repair_classes = {item["repair_class"] for item in clusters}
            self.assertIn("abi_switch_or_jump_table_candidate", kinds)
            self.assertIn("abi_loop_backedge_candidate", kinds)
            self.assertIn("switch_or_jump_table_dispatch", repair_classes)
            self.assertIn("loop_or_state_machine", repair_classes)
            semantic_clusters = [
                json.loads(line)
                for line in (units / "cluster-semantic-contracts.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            complete_kinds = {item["cluster_kind"] for item in semantic_clusters if item["status"] == "complete"}
            self.assertIn("abi_switch_or_jump_table_candidate", complete_kinds)
            self.assertIn("abi_loop_backedge_candidate", complete_kinds)
            switch_cluster = next(item for item in semantic_clusters if item["cluster_kind"] == "abi_switch_or_jump_table_candidate")
            loop_cluster = next(item for item in semantic_clusters if item["cluster_kind"] == "abi_loop_backedge_candidate")
            self.assertIn("indirect-jump contract", switch_cluster["next_action"])
            self.assertIn("low-level CFG backedges", loop_cluster["next_action"])

    def test_reference_contract_does_not_report_nonlocal_tail_jump_as_loop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = b"\xc3" + (b"\x90" * 15) + bytes.fromhex("e9ebffffff")  # jmp from 0x1010 to 0x1000
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            target = self._mapping_entry(rva=0x1000, size=1, block_id="target")
            target["source"] = {"function": "target"}
            tail = self._mapping_entry(rva=0x1010, size=5, block_id="entry-tail")
            tail["source"] = {"function": "entry_tail"}
            mapping = root / "block-map.json"
            mapping.write_text(json.dumps({"blocks": [target, tail]}), encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            functions = {
                function["name"]: function
                for function in result["constraints"]["abi_callsites"]["original"]["functions"]
            }
            tail_function = functions["entry_tail"]
            self.assertEqual(tail_function["loop_hints"], [])
            self.assertEqual(tail_function["blocks"][0]["abi"]["loop_hints"], [])
            self.assertEqual(tail_function["direct_control_transfers"][0]["target_rva"], 0x1000)

    def test_reference_contract_resolves_bounded_pe32_jump_table_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            table_rva = 0x1010
            table_va = 0x400000 + table_rva
            dispatch = bytes.fromhex("83e101") + b"\xff\x24\x8d" + struct.pack("<I", table_va)
            body = (
                dispatch
                + b"\xc3"  # case 0 target at 0x100a
                + b"\xc3"  # case 1 target at 0x100b
                + (b"\0" * (table_rva - 0x1000 - len(dispatch) - 2))
                + struct.pack("<II", 0x40100A, 0x40100B)
            )
            original = self._write_pe(root / "original.exe", body)
            candidate = self._write_pe(root / "candidate.exe", body)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(rva=0x1000, size=len(dispatch), block_id="dispatch-0000"),
                                "source": {"kind": "linker_map_function", "function": "dispatch"},
                            },
                            {
                                **self._mapping_entry(rva=0x100A, size=1, block_id="dispatch-0001"),
                                "source": {"kind": "linker_map_function", "function": "dispatch"},
                            },
                            {
                                **self._mapping_entry(rva=0x100B, size=1, block_id="dispatch-0002"),
                                "source": {"kind": "linker_map_function", "function": "dispatch"},
                            },
                        ],
                        "status": "pass",
                    }
                ),
                encoding="utf-8",
            )
            units = root / "units"

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            functions = result["constraints"]["abi_callsites"]["original"]["functions"]
            switch = next(item for item in functions if item["name"] == "dispatch")["switch_contracts"][0]
            self.assertEqual(switch["evidence_status"], "derived")
            self.assertEqual(switch["table_bounds"], {"lower": 0, "upper": 1, "entries": 2, "source": "and_immediate_mask"})
            self.assertEqual([item["target_rva"] for item in switch["case_targets"]], [0x100A, 0x100B])
            self.assertEqual(switch["unique_target_rvas"], [0x100A, 0x100B])
            jump_targets = result["constraints"]["roots_and_jump_tables"]["jump_table_targets"]
            self.assertEqual({item["target_rva"] for item in jump_targets}, {0x100A, 0x100B})
            transfer_rows = [
                json.loads(line)
                for line in (units / "semantic-transfer-contracts.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            dispatch_transfer = next(item for item in transfer_rows if item["block_id"] == "dispatch-0000")
            self.assertEqual(dispatch_transfer["outcome"]["kind"], "indirect_jump_table")
            self.assertEqual(dispatch_transfer["outcome"]["target_rvas"], [0x100A, 0x100B])

    def test_reference_contract_refines_jump_table_bounds_from_predecessor_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            table_rva = 0x1020
            table_va = 0x400000 + table_rva
            predecessor = bytes.fromhex("80f901770a")  # cmp cl, 1; ja 0x40100f
            dispatch = bytes.fromhex("0fb6c9") + b"\xff\x24\x8d" + struct.pack("<I", table_va)
            body = (
                predecessor
                + dispatch
                + b"\xc3"  # default target at 0x100f
                + b"\xc3"  # case 0 target at 0x1010
                + b"\xc3"  # case 1 target at 0x1011
                + (b"\0" * (table_rva - 0x1000 - len(predecessor) - len(dispatch) - 3))
                + struct.pack("<II", 0x401010, 0x401011)
            )
            original = self._write_pe(root / "original.exe", body)
            candidate = self._write_pe(root / "candidate.exe", body)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(rva=0x1000, size=len(predecessor), block_id="dispatch-guard"),
                                "source": {"kind": "linker_map_function", "function": "dispatch"},
                            },
                            {
                                **self._mapping_entry(rva=0x1005, size=len(dispatch), block_id="dispatch-table"),
                                "source": {"kind": "linker_map_function", "function": "dispatch"},
                            },
                            {
                                **self._mapping_entry(rva=0x100F, size=1, block_id="dispatch-default"),
                                "source": {"kind": "linker_map_function", "function": "dispatch"},
                            },
                            {
                                **self._mapping_entry(rva=0x1010, size=1, block_id="dispatch-case-0"),
                                "source": {"kind": "linker_map_function", "function": "dispatch"},
                            },
                            {
                                **self._mapping_entry(rva=0x1011, size=1, block_id="dispatch-case-1"),
                                "source": {"kind": "linker_map_function", "function": "dispatch"},
                            },
                        ],
                        "status": "pass",
                    }
                ),
                encoding="utf-8",
            )

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=root / "units",
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            functions = result["constraints"]["abi_callsites"]["original"]["functions"]
            switch = next(item for item in functions if item["name"] == "dispatch")["switch_contracts"][0]
            self.assertEqual(switch["evidence_status"], "derived")
            self.assertEqual(switch["table_bounds"]["upper"], 1)
            self.assertEqual(switch["table_bounds"]["source"], "intersected_static_index_bounds")
            self.assertEqual([item["target_rva"] for item in switch["case_targets"]], [0x1010, 0x1011])

    def test_reference_contract_rejects_jump_table_entry_outside_executable_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            table_rva = 0x1010
            table_va = 0x400000 + table_rva
            dispatch = bytes.fromhex("83e101") + b"\xff\x24\x8d" + struct.pack("<I", table_va)
            body = (
                dispatch
                + b"\xc3"
                + b"\xc3"
                + (b"\0" * (table_rva - 0x1000 - len(dispatch) - 2))
                + struct.pack("<II", 0x40100A, 0)
            )
            original = self._write_pe(root / "original.exe", body)
            candidate = self._write_pe(root / "candidate.exe", body)
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                **self._mapping_entry(rva=0x1000, size=len(dispatch), block_id="dispatch-0000"),
                                "source": {"kind": "linker_map_function", "function": "dispatch"},
                            }
                        ],
                        "status": "pass",
                    }
                ),
                encoding="utf-8",
            )

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=root / "units",
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            functions = result["constraints"]["abi_callsites"]["original"]["functions"]
            switch = next(item for item in functions if item["name"] == "dispatch")["switch_contracts"][0]
            self.assertEqual(switch["evidence_status"], "incomplete")
            self.assertIn("does not resolve to executable code", switch["blocker"])
            self.assertFalse(result["constraints"]["roots_and_jump_tables"]["jump_table_targets"])

    def test_reference_contract_call_summary_records_import_varargs_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            call_import = b"\xff\x15\x40\x20\x40\x00"
            original = self._write_import_pe(root / "original.exe", call_import, "___mingw_fprintf")
            candidate = self._write_import_pe(root / "candidate.exe", call_import, "___mingw_fprintf")
            mapping = self._write_mapping(root / "block-map.json", size=len(call_import), block_id="fprintf-call")
            units = root / "units"

            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                unit_contract_dir=units,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            summaries = json.loads((units / "call-summary-contracts.json").read_text(encoding="utf-8"))
            self.assertEqual(summaries["counts"]["calls"], 1)
            call = summaries["calls"][0]
            self.assertEqual(call["target"]["symbol"], "___mingw_fprintf")
            self.assertEqual(call["varargs_evidence"]["status"], "candidate")
            self.assertIn("variadic", call["next_action"])

    def test_abi_callsites_resolve_import_loaded_through_register(self):
        class FakePE:
            def __init__(self, data: bytes):
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if rva < 0x1000:
                    return b""
                offset = rva - 0x1000
                return self.data[offset : offset + size]

        code = bytes.fromhex(
            "a164234100"  # mov eax, dword ptr [0x412364]
            "ffd0"  # call eax
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(),
            imports=(
                stage_a.StageAImport(
                    dll="kernel32.dll",
                    symbol="LeaveCriticalSection",
                    ordinal=None,
                    thunk_rva=0x12364,
                ),
            ),
            pe=FakePE(code),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=0x1000 + len(code)),
            "iat-register-call",
        )

        self.assertEqual(evidence["memory_reads"][0]["memory_role"], "import_address_table")
        self.assertEqual(evidence["memory_reads"][0]["import"]["symbol"], "LeaveCriticalSection")
        self.assertEqual(len(evidence["callsites"]), 1)
        callsite = evidence["callsites"][0]
        self.assertEqual(callsite["target"]["kind"], "import")
        self.assertEqual(callsite["target"]["symbol"], "LeaveCriticalSection")
        self.assertEqual(callsite["target"]["dll"], "kernel32.dll")
        self.assertEqual(callsite["target"]["thunk_rva"], 0x12364)
        self.assertEqual(callsite["target"]["via_register"], "eax")
        self.assertEqual(callsite["target"]["source"]["memory_rva"], 0x12364)
        self.assertEqual(callsite["target"]["source"]["import"]["symbol"], "LeaveCriticalSection")
        self.assertEqual(callsite["target"]["source"]["memory_role"], "import_address_table")
        self.assertEqual(callsite["function_pointer_targets"], [])

    def test_candidate_abi_constraint_splits_function_ranges_into_basic_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex(
                "c744240402000000"  # stale write to stack arg 1 in predecessor block
                "eb08"  # jump over the dead write block
                "c744240403000000"  # skipped block; must not leak into target block
                "c7042401000000"  # live stack arg 0
                "e802000000"  # call 0x401020
                "c3"  # ret
                "90"  # padding
                "c3"  # callee
            )
            binary = stage_a._parse_stage_a_pe(self._write_pe(root / "candidate.exe", code))

            result = stage_a._candidate_abi_constraint_from_functions(
                binary,
                [{"name": "caller", "rva_start": 0x1000, "rva_end": 0x101F}],
            )

            caller = next(item for item in result["candidate"]["functions"] if item["name"] == "caller")
            self.assertGreaterEqual(len(caller["blocks"]), 2)
            self.assertEqual(len(caller["callsites"]), 1)
            inventory = caller["callsites"][0]["argument_inventory"]
            self.assertEqual(inventory["argument_count"], 1)
            self.assertEqual([item["index"] for item in inventory["stack_args"]], [0])
            self.assertEqual(inventory["stack_args"][0]["source"]["value"], 1)

    def test_candidate_abi_section_gap_probe_uses_contract_rva_anchor_inside_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytearray(b"\x90" * 0x50)
            code[0x38:0x3E] = bytes.fromhex("e803000000c3")  # call 0x401040; ret
            code[0x40] = 0xC3
            binary = stage_a._parse_stage_a_pe(self._write_pe(root / "candidate.exe", bytes(code)))
            reference_abi = {
                "original": {
                    "functions": [
                        {
                            "name": "owner",
                            "blocks": [{"block_id": "owner-0000", "rva_start": 0x1010, "rva_end": 0x1030}],
                            "callsites": [],
                        },
                        {
                            "name": "section-gap--text-0001",
                            "blocks": [
                                {
                                    "block_id": "section-gap--text-0001",
                                    "rva_start": 0x1018,
                                    "rva_end": 0x101E,
                                }
                            ],
                            "callsites": [
                                {
                                    "id": "callsite:section-gap--text-0001:1018",
                                    "block_id": "section-gap--text-0001",
                                    "instruction": {"rva": 0x1018, "mnemonic": "call", "op_str": "0x401040"},
                                    "target": {"kind": "direct", "target_rva": 0x1040},
                                }
                            ],
                        },
                        {
                            "name": "target",
                            "blocks": [{"block_id": "target-0000", "rva_start": 0x1040, "rva_end": 0x1041}],
                            "callsites": [],
                        },
                    ]
                }
            }
            alias_evidence = {
                "matches_by_reference": {
                    "owner": {
                        "reference_name": "owner",
                        "source_function": "owner",
                        "source_kind": "generated_contract_guided_flow",
                        "candidate": {"name": "owner", "rva_start": 0x1000, "rva_end": 0x1050},
                    }
                }
            }

            result = stage_a._candidate_abi_constraint_from_functions(
                binary,
                [{"name": "owner", "rva_start": 0x1000, "rva_end": 0x1050}],
                reference_abi=reference_abi,
                alias_evidence=alias_evidence,
                candidate_rva_anchors={0x1010: 0x1030},
            )

            gap = next(item for item in result["candidate"]["functions"] if item["name"] == "section-gap--text-0001")
            self.assertEqual(gap["blocks"][0]["rva_start"], 0x1038)
            self.assertEqual(gap["blocks"][0]["rva_end"], 0x103E)
            self.assertEqual(len(gap["callsites"]), 1)
            self.assertEqual(gap["callsites"][0]["instruction"]["rva"], 0x1038)
            self.assertEqual(gap["callsites"][0]["target"]["target_rva"], 0x1040)

    def test_candidate_abi_predecessor_arguments_follow_skipped_direct_jump_stub(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex(
                "c744240800000000"  # mov dword ptr [esp + 8], 0
                "c74424040a000000"  # mov dword ptr [esp + 4], 10
                "891c24"  # mov dword ptr [esp], ebx
                "39c0"  # cmp eax, eax
                "7407"  # je 0x40101e
                "eb00"  # padding-style jump stub to 0x401019
                "e802000000"  # call 0x401020
                "c3"  # ret
                "90"  # align target at 0x1020
                "c3"  # callee
            )
            binary = stage_a._parse_stage_a_pe(self._write_pe(root / "candidate.exe", code))

            result = stage_a._candidate_abi_constraint_from_functions(
                binary,
                [{"name": "caller", "rva_start": 0x1000, "rva_end": 0x1021}],
            )

            caller = next(item for item in result["candidate"]["functions"] if item["name"] == "caller")
            callsite = next(item for item in caller["callsites"] if item["instruction"]["rva"] == 0x1019)
            inventory = callsite["argument_inventory"]
            self.assertEqual(inventory["argument_count"], 3)
            self.assertEqual([item["role"] for item in inventory["stack_args"]], ["register", "immediate", "immediate"])
            self.assertEqual(callsite["predecessor_argument_sources"]["source"], "direct_cfg_predecessor_exit")
            self.assertEqual(callsite["predecessor_argument_sources"]["predecessor_edges"][0]["resolved_target_rva"], 0x1019)

    def test_candidate_abi_composes_direct_callee_import_memory_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytearray(b"\x90" * 0x30)
            code[0x00:0x06] = bytes.fromhex("e80b000000c3")  # call helper; ret
            code[0x10:0x16] = bytes.fromhex("e80b000000c3")  # call import thunk; ret
            code[0x20:0x26] = bytes.fromhex("ff2540204000")  # jmp dword ptr [0x402040]
            binary = stage_a._parse_stage_a_pe(
                self._write_import_pe(root / "candidate.exe", bytes(code), "ImportedTarget", iat_offset=0x40)
            )

            result = stage_a._candidate_abi_constraint_from_functions(
                binary,
                [
                    {"name": "caller", "rva_start": 0x1000, "rva_end": 0x1006},
                    {"name": "helper", "rva_start": 0x1010, "rva_end": 0x1016},
                    {"name": "import_thunk", "rva_start": 0x1020, "rva_end": 0x1026},
                ],
            )

            caller = next(item for item in result["candidate"]["functions"] if item["name"] == "caller")
            self.assertEqual(caller["memory_effect_summary"]["read_roles"].get("import_address_table"), 1)
            effects = caller["direct_callee_import_memory_effects"]
            self.assertEqual(len(effects["reads"]), 1)
            self.assertEqual(effects["reads"][0]["import"]["symbol"], "ImportedTarget")
            self.assertEqual(effects["reads"][0]["composition_kind"], "direct_callee_import_memory")

    def test_abi_refptr_direct_jump_is_not_reported_as_switch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytearray(b"\x90" * 0x30)
            code[0x00:0x06] = bytes.fromhex("ff2510104000")  # jmp dword ptr [0x401010]
            code[0x10:0x14] = struct.pack("<I", 0x401020)
            code[0x20] = 0xC3
            binary = stage_a._parse_stage_a_pe(self._write_pe(root / "candidate.exe", bytes(code)))

            evidence = stage_a._abi_block_evidence(
                binary,
                stage_a.BlockSide(rva_start=0x1000, rva_end=0x1006),
                "refptr-jump",
            )

            self.assertEqual(evidence["switch_contracts"], [])
            self.assertEqual(evidence["direct_refptr_transfers"][0]["pointer_rva"], 0x1010)
            self.assertEqual(evidence["direct_refptr_transfers"][0]["target_rva"], 0x1020)
            self.assertEqual(evidence["memory_effect_summary"]["reads"], 1)

    def test_abi_identity_lea_alignment_does_not_create_preserved_register(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = stage_a._parse_stage_a_pe(
                self._write_pe(root / "candidate.exe", bytes.fromhex("8db600000000c3"))
            )

            evidence = stage_a._abi_block_evidence(
                binary,
                stage_a.BlockSide(rva_start=0x1000, rva_end=0x1007),
                "alignment-lea",
            )

            self.assertNotIn("esi", evidence["preserved_candidates"])
            self.assertNotIn("esi", evidence["register_reads"])
            self.assertNotIn("esi", evidence["register_writes"])

    def test_candidate_abi_reports_direct_compare_dispatch_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex(
                "83f9007410"  # cmp ecx, 0; je case0
                "83f901740c"  # cmp ecx, 1; je case1
                "83f9027408"  # cmp ecx, 2; je case2
                "83f9037404"  # cmp ecx, 3; je case3
                "c3"  # default
                "c3"  # case0
                "c3"  # case1
                "c3"  # case2
                "c3"  # case3
            )
            binary = stage_a._parse_stage_a_pe(self._write_pe(root / "candidate.exe", code))

            result = stage_a._candidate_abi_constraint_from_functions(
                binary,
                [{"name": "dispatch", "rva_start": 0x1000, "rva_end": 0x1000 + len(code)}],
            )

            function = next(item for item in result["candidate"]["functions"] if item["name"] == "dispatch")
            dispatch = function["decision_tree_contracts"][0]
            self.assertEqual(dispatch["kind"], "direct_compare_dispatch_candidate")
            self.assertEqual(dispatch["selector_register"], "ecx")
            self.assertEqual(dispatch["case_count"], 4)

    def test_contract_candidate_abi_refptr_direct_jump_covers_legacy_switch_and_memory_read(self):
        reference_function = {
            "name": "refptr_alias",
            "memory_effect_summary": {
                "evidence_status": "derived",
                "reads": 1,
                "writes": 0,
                "read_roles": {"global_writable_pointer_slot": 1},
                "write_roles": {},
            },
            "switch_contracts": [
                {
                    "kind": "indirect_jump_table_candidate",
                    "resolved_target_rva": 0x2000,
                    "index_expression": {"base": None, "index": None, "disp": 0xD034, "scale": 1},
                }
            ],
        }
        candidate_function = {
            "name": "refptr_alias",
            "memory_effect_summary": {
                "evidence_status": "derived",
                "reads": 0,
                "writes": 0,
                "read_roles": {},
                "write_roles": {},
            },
            "switch_contracts": [],
            "direct_control_transfers": [{"kind": "direct_control_transfer", "target_rva": 0x3000}],
        }

        self.assertIsNone(
            stage_a._contract_candidate_abi_function_mismatch(
                "refptr_alias",
                "refptr_alias",
                reference_function,
                candidate_function,
                None,
            )
        )

    def test_contract_candidate_abi_direct_compare_dispatch_covers_switch_contract(self):
        reference_function = {
            "name": "dispatch",
            "switch_contracts": [{"kind": "indirect_jump_table_candidate"}],
        }
        candidate_function = {
            "name": "dispatch",
            "switch_contracts": [],
            "decision_tree_contracts": [{"kind": "direct_compare_dispatch_candidate", "case_count": 4}],
        }

        self.assertIsNone(
            stage_a._contract_candidate_abi_function_mismatch(
                "dispatch",
                "dispatch",
                reference_function,
                candidate_function,
                None,
            )
        )

        candidate_function["decision_tree_contracts"] = []
        mismatch = stage_a._contract_candidate_abi_function_mismatch(
            "dispatch",
            "dispatch",
            reference_function,
            candidate_function,
            None,
        )
        self.assertEqual(mismatch["issues"][0]["category"], "switch_or_jump_table_contract_missing")

    def test_contract_candidate_abi_loop_mismatch_ignores_nonlocal_tail_jump_hints(self):
        reference_function = {
            "name": "entry_stub",
            "blocks": [{"rva_start": 0x1010, "rva_end": 0x1015}],
            "loop_hints": [
                {
                    "instruction": {"rva": 0x1010},
                    "target_rva": 0x1000,
                    "kind": "backedge_candidate",
                }
            ],
        }
        candidate_function = {
            "name": "entry_stub",
            "blocks": [{"rva_start": 0x2010, "rva_end": 0x2015}],
            "loop_hints": [],
            "direct_control_transfers": [{"target_rva": 0x2000}],
        }

        self.assertIsNone(
            stage_a._contract_candidate_abi_function_mismatch(
                "entry_stub",
                "entry_stub",
                reference_function,
                candidate_function,
                None,
            )
        )

        reference_function["loop_hints"][0]["target_rva"] = 0x1010
        mismatch = stage_a._contract_candidate_abi_function_mismatch(
            "entry_stub",
            "entry_stub",
            reference_function,
            candidate_function,
            None,
        )
        self.assertEqual(mismatch["issues"][0]["category"], "loop_backedge_contract_missing")

    def test_contract_candidate_abi_preserved_register_ignores_legacy_identity_lea(self):
        reference_function = {
            "name": "alignment_sensitive",
            "registers": {"preserved_candidates": ["esi"]},
            "register_value_provenance": [
                {
                    "register": "esi",
                    "definition": {
                        "kind": "address",
                        "address_class": "computed_address",
                        "addressing": {"base": "esi", "index": None, "disp": 0, "scale": 1},
                        "instruction": {"mnemonic": "lea", "op_str": "esi, [esi]"},
                    },
                }
            ],
        }
        candidate_function = {
            "name": "alignment_sensitive",
            "registers": {"preserved_candidates": []},
        }

        self.assertIsNone(
            stage_a._contract_candidate_abi_function_mismatch(
                "alignment_sensitive",
                "alignment_sensitive",
                reference_function,
                candidate_function,
                None,
            )
        )

        reference_function["register_value_provenance"][0]["definition"]["addressing"]["disp"] = 4
        mismatch = stage_a._contract_candidate_abi_function_mismatch(
            "alignment_sensitive",
            "alignment_sensitive",
            reference_function,
            candidate_function,
            None,
        )
        self.assertEqual(mismatch["issues"][0]["category"], "preserved_register_mismatch")

    def test_abi_callsites_bound_known_stdcall_import_arguments(self):
        class FakePE:
            def __init__(self, data: bytes):
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if rva < 0x1000:
                    return b""
                offset = rva - 0x1000
                return self.data[offset : offset + size]

        code = bytes.fromhex(
            "8944241c"  # mov dword ptr [esp + 0x1c], eax
            "c7042400104000"  # mov dword ptr [esp], 0x401000
            "ff1564234100"  # call dword ptr [0x412364]
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(),
            imports=(
                stage_a.StageAImport(
                    dll="kernel32.dll",
                    symbol="LeaveCriticalSection",
                    ordinal=None,
                    thunk_rva=0x12364,
                ),
            ),
            pe=FakePE(code),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=0x1000 + len(code)),
            "stdcall-spill",
        )

        callsite = evidence["callsites"][0]
        self.assertEqual([source["stack_offset"] for source in callsite["argument_sources"]], [0])
        inventory = callsite["argument_inventory"]
        self.assertEqual(inventory["argument_count"], 1)
        self.assertEqual(len(inventory["stack_args"]), 1)
        self.assertEqual(inventory["stack_args"][0]["source"]["stack_offset"], 0)
        self.assertEqual(inventory["stack_args"][0]["role"], "immediate")

    def test_abi_string_literals_ignore_executable_section_bytes(self):
        class FakePE:
            def get_data(self, rva: int, size: int) -> bytes:
                if rva == 0x6000:
                    return b"hello\0"
                if rva == 0xE000:
                    return b"hello\0"
                return b""

        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=0,
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(
                stage_a.StageASection(".text", 0x1000, 0xC500, 0, 0xB500, 0, True, True, False, True),
                stage_a.StageASection(".rdata", 0xE000, 0xE100, 0, 0x100, 0, False, True, False, False),
            ),
            imports=(),
            pe=FakePE(),
        )

        self.assertIsNone(stage_a._abi_string_literal_at_rva(binary, 0x6000))
        literal = stage_a._abi_string_literal_at_rva(binary, 0xE000)
        self.assertIsNotNone(literal)
        self.assertEqual(literal["text"], "hello")

    def test_abi_callsites_recover_x86_internal_register_arguments_from_direct_target_entry(self):
        class FakePE:
            def __init__(self, data: bytes):
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if rva < 0x1000:
                    return b""
                offset = rva - 0x1000
                return self.data[offset : offset + size]

        target_rva = 0x1020
        caller = bytes.fromhex(
            "8d4c2408"  # lea ecx, [esp + 8]
            "89c2"  # mov edx, eax
            "89f8"  # mov eax, edi
        )
        call_rva = 0x1000 + len(caller)
        code = caller + b"\xe8" + struct.pack("<i", target_rva - (call_rva + 5))
        code += b"\x90" * (target_rva - (0x1000 + len(code)))
        code += bytes.fromhex(
            "55"  # push ebp
            "89d5"  # mov ebp, edx
            "89cb"  # mov ebx, ecx
            "89442404"  # mov dword ptr [esp + 4], eax
            "c3"  # ret
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(
                stage_a.StageASection(
                    name=".text",
                    rva_start=0x1000,
                    rva_end=0x1000 + len(code),
                    raw_pointer=0,
                    raw_size=len(code),
                    characteristics=0,
                    executable=True,
                    readable=True,
                    writable=False,
                    contains_code=True,
                ),
            ),
            imports=(),
            pe=FakePE(code),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=call_rva + 5),
            "x86-register-call",
        )

        callsite = evidence["callsites"][0]
        inventory = callsite["argument_inventory"]
        self.assertEqual(inventory["calling_convention"], "x86_register_carried_internal")
        self.assertEqual(inventory["argument_count"], 3)
        self.assertEqual([arg["register"] for arg in inventory["register_args"]], ["eax", "edx", "ecx"])
        self.assertEqual([arg["role"] for arg in inventory["register_args"]], ["register", "register", "stack_out_param_or_scratch_buffer"])
        self.assertEqual(inventory["register_argument_evidence"]["source"], "direct_target_entry_read_before_write")
        self.assertEqual(inventory["register_argument_evidence"]["target_rva"], target_rva)

    def test_abi_callsites_ignore_noncontiguous_stack_spills_before_call(self):
        class FakePE:
            def __init__(self, data: bytes):
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if rva < 0x1000:
                    return b""
                offset = rva - 0x1000
                return self.data[offset : offset + size]

        code = bytes.fromhex(
            "8954241c"  # mov dword ptr [esp + 0x1c], edx
            "e800000000"  # call next instruction
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(),
            imports=(),
            pe=FakePE(code),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=0x1000 + len(code)),
            "local-spill-before-call",
        )

        callsite = evidence["callsites"][0]
        self.assertEqual(callsite["argument_sources"], [])
        self.assertEqual(callsite["argument_inventory"]["argument_count"], 0)
        self.assertEqual(callsite["hidden_sret_or_out_param_evidence"]["reason"], "no_static_arguments")

    def test_abi_callsites_classify_global_function_pointer_slot(self):
        class FakePE:
            def __init__(self, code: bytes, data: bytes):
                self.code = code
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if 0x1000 <= rva < 0x2000:
                    offset = rva - 0x1000
                    return self.code[offset : offset + size]
                if 0xD000 <= rva < 0xD100:
                    offset = rva - 0xD000
                    return self.data[offset : offset + size]
                return b""

        data = bytearray(0x100)
        struct.pack_into("<I", data, 0, 0x401234)
        code = bytes.fromhex(
            "a100d04000"  # mov eax, dword ptr [0x40d000]
            "ffd0"  # call eax
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(
                stage_a.StageASection(".text", 0x1000, 0x2000, 0, 0x1000, 0, True, True, False, True),
                stage_a.StageASection(".data", 0xD000, 0xD100, 0, 0x100, 0, False, True, True, False),
            ),
            imports=(),
            pe=FakePE(code, bytes(data)),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=0x1000 + len(code)),
            "global-slot-call",
        )

        callsite = evidence["callsites"][0]
        self.assertEqual(callsite["target"]["kind"], "function_pointer")
        self.assertEqual(callsite["target"]["status"], "resolved_static_pointer_slot")
        self.assertEqual(callsite["target"]["memory_rva"], 0xD000)
        self.assertEqual(callsite["target"]["memory_role"], "global_writable_pointer_slot")
        self.assertEqual(callsite["target"]["source"]["memory_section"]["name"], ".data")
        self.assertEqual(callsite["target"]["recoverable_targets"][0]["target_rva"], 0x1234)
        self.assertEqual(callsite["function_pointer_targets"][0]["status"], "resolved_static_pointer_slot")
        self.assertEqual(callsite["function_pointer_targets"][0]["memory_role"], "global_writable_pointer_slot")
        self.assertEqual(callsite["function_pointer_targets"][0]["recoverable_targets"][0]["target_rva"], 0x1234)

    def test_abi_callsites_keeps_non_executable_global_function_pointer_slot_unresolved(self):
        class FakePE:
            def __init__(self, code: bytes, data: bytes):
                self.code = code
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if 0x1000 <= rva < 0x2000:
                    offset = rva - 0x1000
                    return self.code[offset : offset + size]
                if 0xD000 <= rva < 0xD100:
                    offset = rva - 0xD000
                    return self.data[offset : offset + size]
                return b""

        data = bytearray(0x100)
        struct.pack_into("<I", data, 0, 0x40D080)
        code = bytes.fromhex(
            "a100d04000"  # mov eax, dword ptr [0x40d000]
            "ffd0"  # call eax
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(
                stage_a.StageASection(".text", 0x1000, 0x2000, 0, 0x1000, 0, True, True, False, True),
                stage_a.StageASection(".data", 0xD000, 0xD100, 0, 0x100, 0, False, True, True, False),
            ),
            imports=(),
            pe=FakePE(code, bytes(data)),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=0x1000 + len(code)),
            "global-slot-call",
        )

        callsite = evidence["callsites"][0]
        self.assertEqual(callsite["target"]["kind"], "function_pointer")
        self.assertEqual(callsite["target"]["status"], "unresolved")
        self.assertEqual(callsite["target"]["memory_rva"], 0xD000)
        self.assertEqual(callsite["target"]["memory_role"], "global_writable_pointer_slot")
        self.assertEqual(callsite["target"]["recoverable_targets"], [])
        self.assertEqual(callsite["function_pointer_targets"][0]["memory_role"], "global_writable_pointer_slot")

    def test_abi_callsites_classify_direct_stack_slot_function_pointer_call(self):
        class FakePE:
            def __init__(self, data: bytes):
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if rva < 0x1000:
                    return b""
                offset = rva - 0x1000
                return self.data[offset : offset + size]

        code = bytes.fromhex(
            "ff542464"  # call dword ptr [esp + 0x64]
            "c3"  # ret
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(),
            imports=(),
            pe=FakePE(code),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=0x1000 + len(code)),
            "stack-slot-call",
        )

        callsite = evidence["callsites"][0]
        self.assertEqual(callsite["target"]["kind"], "function_pointer")
        self.assertEqual(callsite["target"]["operand"], "dword ptr [esp + 0x64]")
        self.assertEqual(callsite["target"]["memory_role"], "stack_pointer_slot")
        self.assertEqual(callsite["target"]["source"]["addressing"]["disp"], 0x64)
        self.assertEqual(callsite["function_pointer_targets"][0]["memory_role"], "stack_pointer_slot")

    def test_abi_callsites_classify_argument_callback_table_deref(self):
        class FakePE:
            def __init__(self, data: bytes):
                self.data = data

            def get_data(self, rva: int, size: int) -> bytes:
                if rva < 0x1000:
                    return b""
                offset = rva - 0x1000
                return self.data[offset : offset + size]

        code = bytes.fromhex(
            "8b4508"  # mov eax, dword ptr [ebp + 8]
            "8b00"  # mov eax, dword ptr [eax]
            "ffd0"  # call eax
        )
        binary = stage_a.StageABinary(
            path=Path("candidate.exe"),
            sha256="",
            size=len(code),
            machine="i386",
            bitness=32,
            image_base=0x400000,
            entrypoint_rva=0x1000,
            size_of_image=0x20000,
            subsystem="console",
            sections=(),
            imports=(),
            pe=FakePE(code),
        )

        evidence = stage_a._abi_block_evidence(
            binary,
            stage_a.BlockSide(rva_start=0x1000, rva_end=0x1000 + len(code)),
            "argument-table-call",
        )

        callsite = evidence["callsites"][0]
        self.assertEqual(callsite["target"]["kind"], "function_pointer")
        self.assertEqual(callsite["target"]["memory_role"], "argument_pointer_deref")
        self.assertEqual(callsite["target"]["source"]["base_register_definition"]["memory_role"], "stack_argument_slot")
        self.assertEqual(callsite["function_pointer_targets"][0]["memory_role"], "argument_pointer_deref")

    def test_contract_candidate_abi_coverage_gaps_name_missing_functions_and_callsites(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_missing",
                        "blocks": [{"block_id": "missing", "rva_start": 0x1000, "rva_end": 0x1010, "size": 0x10}],
                        "callsites": [
                            {
                                "id": "callsite:missing:1004",
                                "block_id": "missing",
                                "instruction": {"rva": 0x1004, "mnemonic": "call", "op_str": "0x402000"},
                                "target": {"kind": "direct", "target_rva": 0x2000},
                            }
                        ],
                    },
                    {
                        "name": "_partial",
                        "blocks": [{"block_id": "partial", "rva_start": 0x1100, "rva_end": 0x1120, "size": 0x20}],
                        "callsites": [
                            {"id": "callsite:partial:1104", "block_id": "partial", "instruction": {"rva": 0x1104}},
                            {"id": "callsite:partial:1110", "block_id": "partial", "instruction": {"rva": 0x1110}},
                        ],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "partial",
                        "callsites": [
                            {"id": "callsite:partial:1104", "block_id": "partial", "instruction": {"rva": 0x1104}},
                        ],
                    }
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["missing_functions"], 1)
        self.assertEqual(gaps["counts"]["incomplete_callsite_functions"], 1)
        self.assertEqual(gaps["counts"]["missing_callsites"], 1)
        self.assertEqual(gaps["missing_functions"][0]["name"], "_missing")
        self.assertEqual(gaps["missing_functions"][0]["match_key"], "missing")
        self.assertEqual(gaps["missing_functions"][0]["callsites"], 1)
        self.assertEqual(gaps["missing_functions"][0]["callsite_samples"][0]["instruction"]["op_str"], "0x402000")
        self.assertEqual(gaps["incomplete_callsites"][0]["name"], "_partial")
        self.assertEqual(gaps["incomplete_callsites"][0]["candidate_callsites"], 1)
        self.assertEqual(gaps["incomplete_callsites"][0]["reference_callsites"], 2)

    def test_contract_candidate_abi_coverage_gaps_report_missing_callsite_signatures(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_partial",
                        "callsites": [
                            {
                                "id": "callsite:partial:1104",
                                "block_id": "partial:0",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "malloc"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register"}],
                                    "register_args": [],
                                },
                            },
                            {
                                "id": "callsite:partial:1110",
                                "block_id": "partial:1",
                                "target": {"kind": "import", "dll": "kernel32.dll", "symbol": "LeaveCriticalSection"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [
                                        {
                                            "index": 0,
                                            "role": "immediate",
                                            "source": {"kind": "immediate", "stack_offset": 0, "value": 2},
                                        }
                                    ],
                                    "register_args": [],
                                },
                            },
                        ],
                    }
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "partial",
                        "callsites": [
                            {
                                "id": "callsite:partial:2104",
                                "block_id": "partial:0",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "malloc"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register"}],
                                    "register_args": [],
                                },
                            },
                        ],
                    }
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        gap = gaps["incomplete_callsites"][0]
        self.assertEqual(gap["matched_callsite_pairs"], 1)
        self.assertEqual(gap["unmatched_reference_callsites"], 1)
        self.assertEqual(gap["unmatched_candidate_callsites"], 0)
        missing = gap["missing_callsite_signatures"][0]
        self.assertRegex(missing["signature_id"], r"^callsite-signature:[0-9a-f]{16}$")
        self.assertEqual(missing["missing"], 1)
        self.assertEqual(missing["reference_count"], 1)
        self.assertEqual(missing["candidate_count"], 0)
        self.assertEqual(
            missing["signature"]["target"],
            {"kind": "import", "dll": "kernel32.dll", "symbol": "LeaveCriticalSection", "ordinal": ""},
        )
        self.assertEqual(missing["signature"]["argument_inventory"]["argument_count"], 1)
        self.assertEqual(missing["signature"]["argument_inventory"]["stack_roles"], ["immediate"])
        self.assertEqual(missing["signature"]["argument_inventory"]["stack_args"][0]["source"]["value"], 2)
        self.assertEqual(missing["reference_examples"][0]["callsite"]["id"], "callsite:partial:1110")
        self.assertEqual(gap["callsite_signature_delta"]["counts"]["reference_only_signatures"], 1)

    def test_contract_candidate_abi_signature_delta_matches_stack_slot_function_pointer_roles(self):
        reference_callsite = {
            "id": "callsite:umain:bcb3",
            "target": {
                "kind": "function_pointer",
                "operand": "dword ptr [esp + 0x64]",
                "memory_role": "stack_pointer_slot",
                "status": "unresolved",
                "source": {
                    "kind": "memory",
                    "addressing": {"base": "esp", "index": None, "scale": 1, "disp": 0x64},
                    "memory_role": "stack_pointer_slot",
                },
            },
            "argument_inventory": {
                "calling_convention": "cdecl_or_stdcall_stack",
                "argument_count": 1,
                "stack_args": [
                    {
                        "index": 0,
                        "role": "immediate",
                        "source": {"kind": "immediate", "stack_offset": 0, "value": 2},
                    }
                ],
                "register_args": [],
            },
        }
        candidate_callsite = copy.deepcopy(reference_callsite)
        candidate_callsite["id"] = "callsite:umain:bcb3-candidate"
        candidate_callsite["target"]["operand"] = "dword ptr [esp + 0x88]"
        candidate_callsite["target"]["source"]["addressing"]["disp"] = 0x88

        delta = stage_a._contract_candidate_abi_callsite_signature_delta(
            [reference_callsite],
            [candidate_callsite],
            [],
            reference_function_index=[],
            candidate_function_index=[],
        )

        self.assertEqual(delta["counts"]["reference_only_signatures"], 0)
        self.assertEqual(delta["counts"]["candidate_only_signatures"], 0)
        signature = stage_a._abi_callsite_contract_signature(reference_callsite, [])
        self.assertEqual(
            signature["target"],
            {
                "kind": "function_pointer",
                "memory_role": "stack_pointer_slot",
                "status": "unresolved",
                "source": {"kind": "memory", "memory_role": "stack_pointer_slot"},
            },
        )

    def test_contract_candidate_abi_signature_delta_canonicalizes_implicit_stack_offsets(self):
        reference_callsite = {
            "id": "callsite:foo:1000",
            "target": {"kind": "direct", "target_rva": 0x2000},
            "argument_inventory": {
                "calling_convention": "cdecl_or_stdcall_stack",
                "argument_count": 2,
                "stack_args": [
                    {
                        "index": 0,
                        "role": "register",
                        "source": {"kind": "register", "stack_offset": 0},
                    },
                    {
                        "index": 1,
                        "role": "immediate",
                        "source": {"kind": "immediate", "stack_offset": 4, "value": 7},
                    },
                ],
                "register_args": [],
            },
        }
        candidate_callsite = copy.deepcopy(reference_callsite)
        candidate_callsite["id"] = "callsite:foo:push-candidate"
        for argument in candidate_callsite["argument_inventory"]["stack_args"]:
            argument["source"].pop("stack_offset", None)

        delta = stage_a._contract_candidate_abi_callsite_signature_delta(
            [reference_callsite],
            [candidate_callsite],
            [(0, 0, reference_callsite, candidate_callsite)],
            reference_function_index=[],
            candidate_function_index=[],
        )

        self.assertEqual(delta["counts"]["reference_only_signatures"], 0)
        self.assertEqual(delta["counts"]["candidate_only_signatures"], 0)
        signature = stage_a._abi_callsite_contract_signature(candidate_callsite, [])
        stack_args = signature["argument_inventory"]["stack_args"]
        self.assertEqual(stack_args[0]["source"]["stack_offset"], 0)
        self.assertEqual(stack_args[1]["source"]["stack_offset"], 4)

    def test_contract_candidate_abi_signature_delta_keeps_nonstandard_stack_offsets_distinct(self):
        reference_callsite = {
            "id": "callsite:foo:1000",
            "target": {"kind": "direct", "target_rva": 0x2000},
            "argument_inventory": {
                "calling_convention": "cdecl_or_stdcall_stack",
                "argument_count": 1,
                "stack_args": [
                    {
                        "index": 0,
                        "role": "immediate",
                        "source": {"kind": "immediate", "stack_offset": 0, "value": 2},
                    }
                ],
                "register_args": [],
            },
        }
        candidate_callsite = copy.deepcopy(reference_callsite)
        candidate_callsite["id"] = "callsite:foo:offset-candidate"
        candidate_callsite["argument_inventory"]["stack_args"][0]["source"]["stack_offset"] = 4

        delta = stage_a._contract_candidate_abi_callsite_signature_delta(
            [reference_callsite],
            [candidate_callsite],
            [(0, 0, reference_callsite, candidate_callsite)],
            reference_function_index=[],
            candidate_function_index=[],
        )

        self.assertEqual(delta["counts"]["reference_only_signatures"], 1)
        self.assertEqual(delta["counts"]["candidate_only_signatures"], 1)

    def test_contract_candidate_abi_coverage_gaps_report_global_signature_shortages_first(self):
        def stack_slot_callsite(callsite_id: str, value: int) -> dict[str, object]:
            return {
                "id": callsite_id,
                "target": {
                    "kind": "function_pointer",
                    "operand": "dword ptr [esp + 0x64]",
                    "memory_role": "stack_pointer_slot",
                    "status": "unresolved",
                    "source": {"kind": "memory", "memory_role": "stack_pointer_slot"},
                },
                "argument_inventory": {
                    "calling_convention": "cdecl_or_stdcall_stack",
                    "argument_count": 1,
                    "stack_args": [
                        {
                            "index": 0,
                            "role": "immediate",
                            "source": {"kind": "immediate", "stack_offset": 0, "value": value},
                        }
                    ],
                    "register_args": [],
                },
            }

        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "umain",
                        "callsites": [
                            stack_slot_callsite("callsite:umain:arg1", 1),
                            stack_slot_callsite("callsite:umain:arg2", 2),
                        ],
                    }
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "umain",
                        "callsites": [stack_slot_callsite("callsite:umain:candidate-arg2", 2)],
                    }
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        gap = gaps["incomplete_callsites"][0]
        missing = gap["missing_callsite_signatures"][0]
        self.assertEqual(missing["signature"]["argument_inventory"]["stack_args"][0]["source"]["value"], 1)
        unmatched = gap["unmatched_reference_callsite_signatures"][0]
        self.assertEqual(unmatched["signature"]["argument_inventory"]["stack_args"][0]["source"]["value"], 2)
        self.assertEqual(gap["callsite_signature_delta"]["counts"]["reference_only_signatures"], 1)

    def test_contract_candidate_abi_signature_delta_keeps_global_function_pointer_identity(self):
        reference_callsite = {
            "id": "callsite:global:d000",
            "target": {
                "kind": "function_pointer",
                "operand": "eax",
                "memory_role": "global_writable_pointer_slot",
                "memory_rva": 0xD000,
                "status": "unresolved",
                "source": {
                    "kind": "memory",
                    "memory_role": "global_writable_pointer_slot",
                    "memory_rva": 0xD000,
                },
            },
        }
        candidate_callsite = copy.deepcopy(reference_callsite)
        candidate_callsite["id"] = "callsite:global:e000"
        candidate_callsite["target"]["memory_rva"] = 0xE000
        candidate_callsite["target"]["source"]["memory_rva"] = 0xE000

        delta = stage_a._contract_candidate_abi_callsite_signature_delta(
            [reference_callsite],
            [candidate_callsite],
            [],
            reference_function_index=[],
            candidate_function_index=[],
        )

        self.assertEqual(delta["counts"]["reference_only_signatures"], 1)
        self.assertEqual(delta["counts"]["candidate_only_signatures"], 1)
        self.assertEqual(delta["reference_only"][0]["signature"]["target"]["memory_rva"], 0xD000)
        self.assertEqual(delta["candidate_only"][0]["signature"]["target"]["memory_rva"], 0xE000)

    def test_contract_candidate_abi_coverage_gaps_report_function_and_callsite_mismatches(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_jq_init",
                        "memory_effect_summary": {
                            "reads": 0,
                            "writes": 1,
                            "read_roles": {},
                            "write_roles": {"computed_memory": 1},
                        },
                        "register_out_param_candidates": [{"register": "eax"}],
                        "callsites": [
                            {
                                "id": "callsite:jq_init:1004",
                                "block_id": "jq_init:0",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "___mingw_fprintf"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 2,
                                    "stack_args": [
                                        {"index": 0, "role": "memory"},
                                        {"index": 1, "role": "string_literal"},
                                    ],
                                    "register_args": [],
                                },
                                "varargs_evidence": {
                                    "status": "candidate",
                                    "format_string": {
                                        "status": "derived",
                                        "required_varargs": 1,
                                        "observed_varargs": 0,
                                        "missing_varargs": 1,
                                    },
                                },
                            }
                        ],
                    }
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "jq_init",
                        "memory_effect_summary": {
                            "reads": 0,
                            "writes": 0,
                            "read_roles": {},
                            "write_roles": {},
                        },
                        "register_out_param_candidates": [],
                        "callsites": [
                            {
                                "id": "callsite:jq_init:1004",
                                "block_id": "jq_init:0",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "___mingw_fprintf"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "memory"}],
                                    "register_args": [],
                                },
                                "varargs_evidence": {"status": "not_observed"},
                            }
                        ],
                    }
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["function_mismatches"], 1)
        self.assertEqual(gaps["counts"]["callsite_mismatches"], 1)
        self.assertEqual(gaps["function_mismatches"][0]["repair_class"], "hidden_sret_or_out_param")
        self.assertEqual(gaps["callsite_mismatches"][0]["repair_class"], "varargs_or_stdio_bridge")
        self.assertIn("varargs", gaps["callsite_mismatches"][0]["next_action"])

    def test_contract_candidate_abi_memory_summary_accepts_stack_frame_slot_normalization(self):
        reference_function = {
            "memory_effect_summary": {
                "evidence_status": "derived",
                "reads": 1,
                "writes": 0,
                "read_roles": {"stack_pointer_slot": 1},
                "write_roles": {},
            }
        }
        candidate_function = {
            "memory_effect_summary": {
                "evidence_status": "derived",
                "reads": 1,
                "writes": 0,
                "read_roles": {"stack_argument_slot": 1},
                "write_roles": {},
            }
        }

        self.assertIsNone(stage_a._contract_candidate_abi_memory_summary_issue(reference_function, candidate_function))

    def test_contract_candidate_abi_memory_summary_accepts_argument_pointer_refinement(self):
        reference_function = {
            "memory_effect_summary": {
                "reads": 1,
                "writes": 2,
                "read_roles": {"computed_pointer_deref": 1},
                "write_roles": {"computed_memory": 2},
            }
        }
        candidate_function = {
            "memory_effect_summary": {
                "reads": 1,
                "writes": 2,
                "read_roles": {"argument_pointer_deref": 1},
                "write_roles": {"argument_pointer_deref": 1, "computed_pointer_deref": 1},
            }
        }

        self.assertIsNone(stage_a._contract_candidate_abi_memory_summary_issue(reference_function, candidate_function))

    def test_contract_candidate_abi_register_out_param_accepts_argument_pointer_writes(self):
        reference_function = {
            "register_out_param_candidates": [{"register": "eax"}, {"register": "eax"}],
            "memory_effect_summary": {
                "reads": 0,
                "writes": 2,
                "read_roles": {},
                "write_roles": {"computed_memory": 2},
            },
        }
        candidate_function = {
            "register_out_param_candidates": [],
            "memory_writes": [
                {"memory_role": "argument_pointer_deref"},
                {"memory_role": "computed_pointer_deref"},
            ],
            "memory_effect_summary": {
                "reads": 0,
                "writes": 2,
                "read_roles": {},
                "write_roles": {"argument_pointer_deref": 1, "computed_pointer_deref": 1},
            },
        }

        self.assertIsNone(
            stage_a._contract_candidate_abi_function_mismatch(
                "arg_pointer_out",
                "arg_pointer_out",
                reference_function,
                candidate_function,
                None,
            )
        )

        candidate_function["memory_writes"] = [{"memory_role": "computed_pointer_deref"}]
        mismatch = stage_a._contract_candidate_abi_function_mismatch(
            "arg_pointer_out",
            "arg_pointer_out",
            reference_function,
            candidate_function,
            None,
        )
        self.assertEqual(mismatch["issues"][0]["category"], "register_carried_out_param_missing")

    def test_contract_candidate_abi_memory_summary_keeps_global_roles_strict(self):
        reference_function = {
            "memory_effect_summary": {
                "evidence_status": "derived",
                "reads": 2,
                "writes": 0,
                "read_roles": {"stack_pointer_slot": 1, "global_writable_pointer_slot": 1},
                "write_roles": {},
            }
        }
        candidate_function = {
            "memory_effect_summary": {
                "evidence_status": "derived",
                "reads": 2,
                "writes": 0,
                "read_roles": {"stack_argument_slot": 2},
                "write_roles": {},
            }
        }

        issue = stage_a._contract_candidate_abi_memory_summary_issue(reference_function, candidate_function)

        self.assertIsNotNone(issue)
        self.assertEqual(issue["missing_read_roles"], {"global_writable_pointer_slot": 1})

    def test_contract_candidate_binary_signature_delta_names_header_sections_and_imports(self):
        expected = {
            "machine": "i386",
            "bitness": 32,
            "subsystem": "windows_cui",
            "image_base": 0x400000,
            "entrypoint_rva": 0x1420,
            "sections": [
                {"name": ".text", "rva_start": 0x1000, "rva_end": 0x2000, "executable": True, "readable": True, "writable": False},
                {"name": ".idata", "rva_start": 0x3000, "rva_end": 0x3400, "executable": False, "readable": True, "writable": False},
            ],
            "imports": [{"dll": "kernel32.dll", "symbol": "Sleep", "ordinal": None}],
        }
        candidate = {
            **expected,
            "image_base": 0x410000,
            "entrypoint_rva": 0x1500,
            "sections": [
                {"name": ".text", "rva_start": 0x1000, "rva_end": 0x2100, "executable": True, "readable": True, "writable": False},
                {"name": ".reloc", "rva_start": 0x4000, "rva_end": 0x4200, "executable": False, "readable": True, "writable": False},
            ],
            "imports": [{"dll": "user32.dll", "symbol": "MessageBoxA", "ordinal": None}],
        }

        delta = stage_a._contract_binary_signature_delta(expected, candidate)

        self.assertEqual(delta["header"]["image_base"], {"expected": 0x400000, "observed": 0x410000})
        self.assertEqual(delta["header"]["entrypoint_rva"], {"expected": 0x1420, "observed": 0x1500})
        text_delta = next(item for item in delta["sections"] if item["name"] == ".text")
        self.assertEqual(text_delta["delta"]["size"]["delta"], 0x100)
        self.assertEqual({item["status"] for item in delta["sections"] if item["name"] in {".idata", ".reloc"}}, {"missing", "extra"})
        self.assertEqual(delta["imports"]["missing"][0]["symbol"], "Sleep")
        self.assertEqual(delta["imports"]["extra"][0]["symbol"], "MessageBoxA")

    def test_contract_candidate_abi_coverage_gaps_match_callsites_by_signature_before_index(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_allocator",
                        "callsites": [
                            {
                                "id": "callsite:allocator:1004",
                                "block_id": "allocator:0",
                                "target": {"kind": "import", "dll": "kernel32.dll", "symbol": "LeaveCriticalSection"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "immediate"}],
                                    "register_args": [],
                                },
                            },
                            {
                                "id": "callsite:allocator:1020",
                                "block_id": "allocator:1",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "malloc"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register"}],
                                    "register_args": [],
                                },
                            },
                        ],
                    }
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "allocator",
                        "callsites": [
                            {
                                "id": "callsite:allocator:2020",
                                "block_id": "allocator:1",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "malloc"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register"}],
                                    "register_args": [],
                                },
                            },
                            {
                                "id": "callsite:allocator:2004",
                                "block_id": "allocator:0",
                                "target": {"kind": "import", "dll": "kernel32.dll", "symbol": "LeaveCriticalSection"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "immediate"}],
                                    "register_args": [],
                                },
                            },
                        ],
                    }
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 0)

    def test_contract_candidate_abi_coverage_gaps_match_direct_import_thunks_before_index(self):
        def import_thunk_function(name, rva):
            return {
                "name": name,
                "blocks": [
                    {
                        "block_id": f"{name}:0",
                        "rva_start": rva,
                        "rva_end": rva + 8,
                        "abi": {
                            "callsites": [],
                            "memory_reads": [
                                {
                                    "memory_role": "global_readonly_pointer_slot",
                                    "memory_section": {"name": ".idata"},
                                    "instruction": {"mnemonic": "jmp"},
                                }
                            ],
                        },
                    }
                ],
                "callsites": [],
            }

        reference_abi = {
            "original": {
                "import_prototypes": [
                    {"dll": "msvcrt.dll", "symbol": "_fileno"},
                    {"dll": "msvcrt.dll", "symbol": "_get_osfhandle"},
                    {"dll": "kernel32.dll", "symbol": "WriteFile"},
                ],
                "functions": [
                    {
                        "name": "section-gap--text-0068",
                        "callsites": [
                            {
                                "id": "callsite:section-gap--text-0068:15ee",
                                "block_id": "section-gap--text-0068",
                                "target": {"kind": "direct", "target_rva": 0x2000},
                            },
                            {
                                "id": "callsite:section-gap--text-0068:15fa",
                                "block_id": "section-gap--text-0068",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "_get_osfhandle"},
                            },
                            {
                                "id": "callsite:section-gap--text-0068:1624",
                                "block_id": "section-gap--text-0068",
                                "target": {"kind": "import", "dll": "kernel32.dll", "symbol": "WriteFile"},
                            },
                        ],
                    },
                    import_thunk_function("_fileno", 0x2000),
                ],
            }
        }
        candidate_abi = {
            "candidate": {
                "import_prototypes": [
                    {"dll": "msvcrt.dll", "symbol": "_get_osfhandle"},
                    {"dll": "kernel32.dll", "symbol": "WriteFile"},
                ],
                "functions": [
                    {
                        "name": "section-gap--text-0068",
                        "callsites": [
                            {
                                "id": "callsite:section-gap--text-0068:15fa",
                                "block_id": "section-gap--text-0068",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                            },
                            {
                                "id": "callsite:section-gap--text-0068:1624",
                                "block_id": "section-gap--text-0068",
                                "target": {"kind": "direct", "target_rva": 0x6000},
                            },
                        ],
                    },
                    import_thunk_function("_get_osfhandle", 0x5000),
                    import_thunk_function("_WriteFile@20", 0x6000),
                ],
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["incomplete_callsite_functions"], 1)
        self.assertEqual(gaps["counts"]["missing_callsites"], 1)
        self.assertEqual(gaps["counts"]["callsite_mismatches"], 0)
        self.assertEqual(gaps["incomplete_callsites"][0]["name"], "section-gap--text-0068")

    def test_contract_candidate_abi_coverage_gaps_normalize_direct_targets_by_resolved_alias(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_caller",
                        "blocks": [{"block_id": "caller", "rva_start": 0x1000, "rva_end": 0x1010}],
                        "callsites": [
                            {
                                "id": "callsite:caller:1004",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x2000},
                            }
                        ],
                    },
                    {
                        "name": "_target",
                        "blocks": [{"block_id": "target", "rva_start": 0x2000, "rva_end": 0x2010}],
                        "callsites": [],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "caller",
                        "blocks": [{"block_id": "caller", "rva_start": 0x3000, "rva_end": 0x3010}],
                        "callsites": [
                            {
                                "id": "callsite:caller:3004",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x4000},
                            }
                        ],
                    },
                    {
                        "name": "target",
                        "blocks": [{"block_id": "target", "rva_start": 0x4000, "rva_end": 0x4010}],
                        "callsites": [],
                    },
                ]
            }
        }
        alias_evidence = {
            "matches_by_reference": {
                "_target": {
                    "reference_name": "_target",
                    "source_function": "target",
                    "candidate": {"name": "target", "rva_start": 0x4000, "rva_end": 0x4010},
                }
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi, alias_evidence=alias_evidence)

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 0)

    def test_contract_candidate_abi_coverage_gaps_keep_different_resolved_direct_targets_incomplete(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_caller",
                        "blocks": [{"block_id": "caller", "rva_start": 0x1000, "rva_end": 0x1010}],
                        "callsites": [
                            {
                                "id": "callsite:caller:1004",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x2000},
                            }
                        ],
                    },
                    {
                        "name": "_target",
                        "blocks": [{"block_id": "target", "rva_start": 0x2000, "rva_end": 0x2010}],
                        "callsites": [],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "caller",
                        "blocks": [{"block_id": "caller", "rva_start": 0x3000, "rva_end": 0x3010}],
                        "callsites": [
                            {
                                "id": "callsite:caller:3004",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                            }
                        ],
                    },
                    {
                        "name": "other",
                        "blocks": [{"block_id": "other", "rva_start": 0x5000, "rva_end": 0x5010}],
                        "callsites": [],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)
        mismatch = gaps["callsite_mismatches"][0]

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 1)
        self.assertEqual(mismatch["issues"][0]["category"], "call_target_mismatch")
        self.assertEqual(mismatch["repair_class"], "call_target_mismatch")
        self.assertEqual(mismatch["issues"][0]["expected"]["resolved_functions"][0]["name"], "_target")
        self.assertEqual(mismatch["issues"][0]["observed"]["resolved_functions"][0]["name"], "other")

    def test_contract_candidate_abi_coverage_gaps_classify_call_target_before_argument_roles(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_caller",
                        "blocks": [{"block_id": "caller", "rva_start": 0x1000, "rva_end": 0x1010}],
                        "callsites": [
                            {
                                "id": "callsite:caller:1004",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x2000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 2,
                                    "stack_args": [
                                        {"index": 0, "role": "register"},
                                        {"index": 1, "role": "memory"},
                                    ],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "_target",
                        "blocks": [{"block_id": "target", "rva_start": 0x2000, "rva_end": 0x2010}],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "caller",
                        "blocks": [{"block_id": "caller", "rva_start": 0x3000, "rva_end": 0x3010}],
                        "callsites": [
                            {
                                "id": "callsite:caller:3004",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register"}],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "other",
                        "blocks": [{"block_id": "other", "rva_start": 0x5000, "rva_end": 0x5010}],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)
        mismatch = gaps["callsite_mismatches"][0]

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 1)
        self.assertEqual(mismatch["repair_class"], "call_target_mismatch")
        self.assertIn("call target", mismatch["next_action"])
        self.assertNotIn("save/restore", mismatch["next_action"])

    def test_contract_candidate_abi_coverage_gaps_classify_argument_inventory_before_register_text(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_caller",
                        "callsites": [
                            {
                                "id": "callsite:caller:1004",
                                "block_id": "caller",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "memcmp"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "memory"}],
                                    "register_args": [],
                                },
                            }
                        ],
                    }
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "caller",
                        "callsites": [
                            {
                                "id": "callsite:caller:3004",
                                "block_id": "caller",
                                "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "memcmp"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register"}],
                                    "register_args": [],
                                },
                            }
                        ],
                    }
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)
        mismatch = gaps["callsite_mismatches"][0]

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 1)
        self.assertEqual(mismatch["issues"][0]["category"], "callsite_argument_inventory_mismatch")
        self.assertEqual(mismatch["repair_class"], "callsite_argument_inventory_mismatch")
        self.assertIn("argument order/count/roles", mismatch["next_action"])
        self.assertNotIn("save/restore", mismatch["next_action"])

    def test_contract_candidate_abi_coverage_gaps_accept_candidate_specific_stack_out_param_role(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "_FindPESectionByName",
                        "callsites": [
                            {
                                "id": "callsite:reference",
                                "block_id": "_FindPESectionByName-0008",
                                "target": {"kind": "direct", "target_rva": 0x3000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 3,
                                    "stack_args": [
                                        {"index": 0, "role": "register"},
                                        {"index": 1, "role": "register"},
                                        {"index": 2, "role": "immediate"},
                                    ],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "_target",
                        "blocks": [{"block_id": "target", "rva_start": 0x3000, "rva_end": 0x3010}],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "_FindPESectionByName",
                        "callsites": [
                            {
                                "id": "callsite:candidate",
                                "block_id": "_FindPESectionByName",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 3,
                                    "stack_args": [
                                        {"index": 0, "role": "stack_out_param_or_scratch_buffer"},
                                        {"index": 1, "role": "register"},
                                        {"index": 2, "role": "immediate"},
                                    ],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "_target",
                        "blocks": [{"block_id": "target", "rva_start": 0x5000, "rva_end": 0x5010}],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 0)

    def test_contract_candidate_abi_coverage_gaps_accept_by_value_argument_role_shape_changes(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "__gdtoa",
                        "callsites": [
                            {
                                "id": "callsite:reference",
                                "block_id": "__gdtoa-0005",
                                "target": {"kind": "direct", "target_rva": 0x3000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 3,
                                    "stack_args": [
                                        {"index": 0, "role": "register"},
                                        {"index": 1, "role": "stack_pointer_slot"},
                                        {"index": 2, "role": "computed_memory"},
                                    ],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "__dtoa_target",
                        "blocks": [{"block_id": "target", "rva_start": 0x3000, "rva_end": 0x3010}],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "__gdtoa",
                        "callsites": [
                            {
                                "id": "callsite:candidate",
                                "block_id": "___gdtoa",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 3,
                                    "stack_args": [
                                        {"index": 0, "role": "stack_local_slot"},
                                        {"index": 1, "role": "stack_argument_slot"},
                                        {"index": 2, "role": "computed_pointer_deref"},
                                    ],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "__dtoa_target",
                        "blocks": [{"block_id": "target", "rva_start": 0x5000, "rva_end": 0x5010}],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 0)

    def test_contract_candidate_abi_coverage_gaps_accept_candidate_string_literal_refinement(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "caller",
                        "callsites": [
                            {
                                "id": "callsite:reference",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x3000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "immediate"}],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "target",
                        "blocks": [{"block_id": "target", "rva_start": 0x3000, "rva_end": 0x3010}],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "caller",
                        "callsites": [
                            {
                                "id": "callsite:candidate",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "string_literal"}],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "target",
                        "blocks": [{"block_id": "target", "rva_start": 0x5000, "rva_end": 0x5010}],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 0)

    def test_contract_candidate_abi_coverage_gaps_accept_candidate_global_pointer_refinement(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "caller",
                        "callsites": [
                            {
                                "id": "callsite:reference",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x3000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register", "source": {"kind": "register"}}],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "target",
                        "blocks": [{"block_id": "target", "rva_start": 0x3000, "rva_end": 0x3010}],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "caller",
                        "callsites": [
                            {
                                "id": "callsite:candidate",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [
                                        {
                                            "index": 0,
                                            "role": "global_writable_pointer_slot",
                                            "source": {"kind": "register"},
                                        }
                                    ],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "target",
                        "blocks": [{"block_id": "target", "rva_start": 0x5000, "rva_end": 0x5010}],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 0)

    def test_contract_candidate_abi_coverage_gaps_reports_underconstrained_reference_arguments(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "__gdtoa",
                        "callsites": [
                            {
                                "id": "callsite:reference",
                                "block_id": "__gdtoa-0155",
                                "target": {"kind": "direct", "target_rva": 0x3000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 0,
                                    "stack_args": [],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "__multadd_D2A",
                        "blocks": [{"block_id": "target", "rva_start": 0x3000, "rva_end": 0x3010}],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "___gdtoa",
                        "callsites": [
                            {
                                "id": "callsite:candidate",
                                "block_id": "___gdtoa",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 3,
                                    "stack_args": [
                                        {"index": 0, "role": "stack_pointer_slot"},
                                        {"index": 1, "role": "immediate"},
                                        {"index": 2, "role": "immediate"},
                                    ],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "___multadd_D2A",
                        "aliases": ["__multadd_D2A", "___multadd_D2A"],
                        "blocks": [{"block_id": "target", "rva_start": 0x5000, "rva_end": 0x5010}],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)
        mismatch = gaps["callsite_mismatches"][0]

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 1)
        self.assertEqual(mismatch["issues"][0]["category"], "reference_argument_inventory_underconstrained")
        self.assertEqual(mismatch["repair_class"], "stage_a_argument_inventory_underconstrained")
        self.assertIn("improve Stage A argument recovery", mismatch["next_action"])

    def test_contract_candidate_abi_coverage_gaps_reject_literal_and_address_role_loss(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "caller",
                        "callsites": [
                            {
                                "id": "callsite:reference",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x3000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 2,
                                    "stack_args": [
                                        {"index": 0, "role": "string_literal"},
                                        {"index": 1, "role": "computed_out_param_or_hidden_sret"},
                                    ],
                                    "register_args": [],
                                },
                                "hidden_sret_or_out_param_evidence": {"status": "candidate"},
                            }
                        ],
                    },
                    {
                        "name": "target",
                        "blocks": [{"block_id": "target", "rva_start": 0x3000, "rva_end": 0x3010}],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "caller",
                        "callsites": [
                            {
                                "id": "callsite:candidate",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 2,
                                    "stack_args": [
                                        {"index": 0, "role": "immediate"},
                                        {"index": 1, "role": "register"},
                                    ],
                                    "register_args": [],
                                },
                                "hidden_sret_or_out_param_evidence": {"status": "unknown"},
                            }
                        ],
                    },
                    {
                        "name": "target",
                        "blocks": [{"block_id": "target", "rva_start": 0x5000, "rva_end": 0x5010}],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 1)
        self.assertEqual(gaps["callsite_mismatches"][0]["issues"][0]["category"], "hidden_sret_or_out_param_missing")
        self.assertEqual(gaps["callsite_mismatches"][0]["issues"][1]["category"], "callsite_argument_inventory_mismatch")

    def test_contract_candidate_abi_coverage_gaps_reject_lost_stack_out_param_role(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "caller",
                        "callsites": [
                            {
                                "id": "callsite:reference",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x3000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "stack_out_param_or_scratch_buffer"}],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "target",
                        "blocks": [{"block_id": "target", "rva_start": 0x3000, "rva_end": 0x3010}],
                    },
                ]
            }
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "caller",
                        "callsites": [
                            {
                                "id": "callsite:candidate",
                                "block_id": "caller",
                                "target": {"kind": "direct", "target_rva": 0x5000},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 1,
                                    "stack_args": [{"index": 0, "role": "register"}],
                                    "register_args": [],
                                },
                            }
                        ],
                    },
                    {
                        "name": "target",
                        "blocks": [{"block_id": "target", "rva_start": 0x5000, "rva_end": 0x5010}],
                    },
                ]
            }
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        self.assertEqual(gaps["counts"]["callsite_mismatches"], 1)
        self.assertEqual(gaps["callsite_mismatches"][0]["issues"][0]["category"], "callsite_argument_inventory_mismatch")

    def test_contract_candidate_abi_coverage_gaps_use_explicit_skeleton_aliases(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "__dyn_tls_dtor@12",
                        "blocks": [{"block_id": "dyn", "rva_start": 0x1000, "rva_end": 0x1001, "size": 1}],
                        "callsites": [],
                    }
                ]
            },
            "counts": {"functions": 1, "callsites": 0},
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "___dyn_tls_dtor_12",
                        "callsites": [],
                    }
                ]
            },
            "counts": {"functions": 1, "callsites": 0},
        }
        alias_evidence = stage_a._contract_candidate_skeleton_alias_evidence(
            {
                "format": "stage-b-skeleton-v1",
                "source_map": {
                    "functions": [
                        {
                            "function": "___dyn_tls_dtor_12",
                            "aliases": ["__dyn_tls_dtor@12"],
                            "source_kind": "decompiled_function",
                        }
                    ]
                },
            },
            [{"name": "___dyn_tls_dtor_12", "rva_start": 0x1000, "rva_end": 0x1001, "section": ".text"}],
        )

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi, alias_evidence=alias_evidence)

        self.assertEqual(gaps["counts"]["missing_functions"], 0)
        self.assertEqual(gaps["counts"]["ambiguous_functions"], 0)
        self.assertEqual(alias_evidence["matches_by_reference"]["__dyn_tls_dtor@12"]["source_function"], "___dyn_tls_dtor_12")

    def test_contract_candidate_abi_coverage_gaps_prefer_explicit_alias_over_same_rva_probe(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "section-gap--text-0130",
                        "blocks": [{"block_id": "section-gap--text-0130", "rva_start": 0x4EF8, "rva_end": 0x4F38}],
                        "callsites": [
                            {
                                "id": "callsite:section-gap--text-0130:4f2b",
                                "block_id": "section-gap--text-0130",
                                "instruction": {"rva": 0x4F2B},
                                "target": {"kind": "import", "dll": "kernel32.dll", "symbol": "VirtualProtect"},
                                "argument_inventory": {
                                    "calling_convention": "cdecl_or_stdcall_stack",
                                    "argument_count": 4,
                                    "stack_args": [{"index": index, "role": "register"} for index in range(4)],
                                    "register_args": [],
                                },
                            }
                        ],
                    }
                ]
            }
        }
        matching_callsite = {
            "id": "callsite:stage_b_contract_section_gap__text_0130:4e9a",
            "block_id": "stage_b_contract_section_gap__text_0130",
            "instruction": {"rva": 0x4E9A},
            "target": {"kind": "import", "dll": "kernel32.dll", "symbol": "VirtualProtect"},
            "argument_inventory": {
                "calling_convention": "cdecl_or_stdcall_stack",
                "argument_count": 4,
                "stack_args": [{"index": index, "role": "register"} for index in range(4)],
                "register_args": [],
            },
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {
                        "name": "section-gap--text-0130",
                        "callsites": [
                            {
                                "target": {"kind": "direct", "target_rva": 0x58E9},
                                "argument_inventory": {"calling_convention": "cdecl_or_stdcall_stack", "argument_count": 0, "stack_args": []},
                            },
                            {
                                "target": {"kind": "direct", "target_rva": 0x5B59},
                                "argument_inventory": {"calling_convention": "cdecl_or_stdcall_stack", "argument_count": 0, "stack_args": []},
                            },
                        ],
                    },
                    {
                        "name": "stage_b_contract_section_gap__text_0130",
                        "callsites": [matching_callsite],
                    },
                ]
            }
        }
        alias_evidence = {
            "matches_by_reference": {
                "section-gap--text-0130": {
                    "source_function": "stage_b_contract_section_gap__text_0130",
                    "source_kind": "generated_contract_guided_flow",
                    "candidate": {"name": "stage_b_contract_section_gap__text_0130"},
                }
            },
            "ambiguities_by_reference": {},
        }

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi, alias_evidence=alias_evidence)

        self.assertEqual(gaps["counts"]["missing_functions"], 0)
        self.assertEqual(gaps["counts"]["callsite_mismatches"], 0)
        self.assertEqual(gaps["counts"]["incomplete_callsite_functions"], 0)

    def test_candidate_abi_probes_reference_section_gap_units_at_same_rva(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            candidate_bin = stage_a._parse_stage_a_pe(candidate)
            reference_abi = {
                "original": {
                    "functions": [
                        {
                            "name": "section-gap--text-0000",
                            "blocks": [
                                {
                                    "block_id": "section-gap--text-0000",
                                    "rva_start": 0x1000,
                                    "rva_end": 0x1001,
                                    "size": 1,
                                }
                            ],
                            "callsites": [],
                        },
                        {
                            "name": "ordinary_missing",
                            "blocks": [
                                {
                                    "block_id": "ordinary_missing-0000",
                                    "rva_start": 0x1000,
                                    "rva_end": 0x1001,
                                    "size": 1,
                                }
                            ],
                            "callsites": [],
                        },
                    ]
                },
                "counts": {"functions": 2, "callsites": 0},
            }

            candidate_abi = stage_a._candidate_abi_constraint_from_functions(candidate_bin, [], reference_abi=reference_abi)
            gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi)

        by_name = {item["name"]: item for item in candidate_abi["candidate"]["functions"]}
        self.assertIn("section-gap--text-0000", by_name)
        self.assertEqual(by_name["section-gap--text-0000"]["blocks"][0]["block_id"], "section-gap--text-0000")
        self.assertEqual(by_name["section-gap--text-0000"]["stack_delta"]["status"], "block_local")
        self.assertNotIn("ordinary_missing", by_name)
        self.assertEqual(gaps["counts"]["missing_functions"], 1)
        self.assertEqual(gaps["missing_functions"][0]["name"], "ordinary_missing")

    def test_contract_candidate_alias_evidence_matches_generated_c_identifier_alias(self):
        alias_evidence = stage_a._contract_candidate_skeleton_alias_evidence(
            {
                "format": "stage-b-skeleton-v1",
                "source_map": {
                    "functions": [
                        {
                            "function": "_gnu_exception_handler@4",
                            "aliases": ["_gnu_exception_handler@4", "_gnu_exception_handler_4"],
                            "source_kind": "generated_contract_placeholder",
                        }
                    ]
                },
            },
            [{"name": "_gnu_exception_handler_4", "rva_start": 0x3414, "rva_end": 0x3420, "section": ".text"}],
        )

        match = alias_evidence["matches_by_reference"]["_gnu_exception_handler@4"]

        self.assertEqual(alias_evidence["status"], "satisfied")
        self.assertEqual(match["source_function"], "_gnu_exception_handler@4")
        self.assertEqual(match["candidate"]["name"], "_gnu_exception_handler_4")

    def test_contract_candidate_alias_evidence_prefers_unique_exact_source_function(self):
        alias_evidence = stage_a._contract_candidate_skeleton_alias_evidence(
            {
                "format": "stage-b-skeleton-v1",
                "source_map": {
                    "functions": [
                        {
                            "function": "__crt_atexit",
                            "aliases": ["_crt_atexit", "__crt_atexit"],
                            "source_kind": "omitted_import_thunk",
                        }
                    ]
                },
            },
            [
                {"name": "__crt_atexit", "rva_start": 0x86A8, "rva_end": 0x86B0, "section": ".text"},
                {"name": "_crt_atexit", "rva_start": 0x27E8, "rva_end": 0x27F0, "section": ".text"},
            ],
        )

        match = alias_evidence["matches_by_reference"]["__crt_atexit"]

        self.assertEqual(alias_evidence["status"], "satisfied")
        self.assertEqual(alias_evidence["counts"]["ambiguities"], 0)
        self.assertEqual(match["candidate"]["name"], "__crt_atexit")
        self.assertEqual(match["resolution"], "unique_exact_source_function")
        self.assertEqual(alias_evidence["matches_by_reference"]["_crt_atexit"]["candidate"]["name"], "__crt_atexit")

    def test_contract_candidate_alias_evidence_ignores_section_symbol_aliases(self):
        alias_evidence = stage_a._contract_candidate_skeleton_alias_evidence(
            {
                "format": "stage-b-skeleton-v1",
                "source_map": {
                    "functions": [
                        {
                            "function": "___mbrtowc_cp",
                            "aliases": ["section-gap--text-0747", "mbrtowc_cp", ".text"],
                            "source_kind": "generated_contract_placeholder_from_section_gap_alias",
                        },
                        {
                            "function": "___wcrtomb_cp",
                            "aliases": ["section-gap--text-0740", "wcrtomb_cp", ".text"],
                            "source_kind": "generated_contract_placeholder_from_section_gap_alias",
                        },
                    ]
                },
            },
            [
                {"name": "___mbrtowc_cp", "rva_start": 0x464C, "rva_end": 0x4650, "section": ".text"},
                {"name": "___wcrtomb_cp", "rva_start": 0x5650, "rva_end": 0x5654, "section": ".text"},
            ],
        )

        self.assertEqual(alias_evidence["status"], "satisfied")
        self.assertEqual(alias_evidence["counts"]["ambiguities"], 0)
        self.assertNotIn(".text", alias_evidence["matches_by_reference"])
        self.assertNotIn(".text", alias_evidence["ambiguities_by_reference"])
        self.assertEqual(alias_evidence["matches_by_reference"]["section-gap--text-0747"]["candidate"]["name"], "___mbrtowc_cp")
        self.assertEqual(alias_evidence["matches_by_reference"]["section-gap--text-0740"]["candidate"]["name"], "___wcrtomb_cp")

    def test_contract_candidate_alias_evidence_keeps_duplicate_exact_source_function_incomplete(self):
        alias_evidence = stage_a._contract_candidate_skeleton_alias_evidence(
            {
                "format": "stage-b-skeleton-v1",
                "source_map": {
                    "functions": [
                        {
                            "function": "__crt_atexit",
                            "aliases": ["_crt_atexit", "__crt_atexit"],
                            "source_kind": "omitted_import_thunk",
                        }
                    ]
                },
            },
            [
                {"name": "__crt_atexit", "rva_start": 0x86A8, "rva_end": 0x86B0, "section": ".text"},
                {"name": "__crt_atexit", "rva_start": 0x96A8, "rva_end": 0x96B0, "section": ".text"},
                {"name": "_crt_atexit", "rva_start": 0x27E8, "rva_end": 0x27F0, "section": ".text"},
            ],
        )

        self.assertEqual(alias_evidence["status"], "incomplete")
        self.assertEqual(alias_evidence["counts"]["ambiguities"], 2)
        self.assertIn("__crt_atexit", alias_evidence["ambiguities_by_reference"])

    def test_contract_candidate_alias_evidence_records_unmatched_source_aliases(self):
        alias_evidence = stage_a._contract_candidate_skeleton_alias_evidence(
            {
                "format": "stage-b-skeleton-v1",
                "source_map": {
                    "functions": [
                        {
                            "function": "___iob_func",
                            "aliases": ["__iob_func"],
                            "source_kind": "omitted_import_thunk",
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 2305,
                            "line_end": 2308,
                        }
                    ]
                },
            },
            [],
        )

        unmatched = alias_evidence["unmatched_by_reference"]["__iob_func"][0]

        self.assertEqual(alias_evidence["status"], "satisfied")
        self.assertEqual(alias_evidence["counts"]["unmatched_aliases"], 2)
        self.assertEqual(unmatched["source_function"], "___iob_func")
        self.assertEqual(unmatched["source_kind"], "omitted_import_thunk")
        self.assertEqual(unmatched["file"], "src/jq_stage_b_skeleton.c")

    def test_contract_candidate_missing_function_details_classify_import_thunk_and_runtime_entry(self):
        alias_evidence = {
            "unmatched_by_reference": {
                "__iob_func": [
                    {
                        "reference_name": "__iob_func",
                        "source_function": "___iob_func",
                        "source_kind": "omitted_import_thunk",
                        "source_aliases": ["__iob_func"],
                    }
                ],
                "wmain": [
                    {
                        "reference_name": "wmain",
                        "source_function": "_wmain",
                        "source_kind": "omitted_runtime_entry",
                        "source_aliases": ["wmain"],
                    }
                ],
            }
        }
        constraints = {
            "import_thunks": {
                "mapped_import_thunks": [
                    {
                        "id": "__iob_func-import-thunk",
                        "source": {
                            "function": "__iob_func",
                            "kind": "import_thunk",
                            "import_signature": {"dll": "msvcrt.dll", "symbol": "__p__iob", "ordinal": None},
                        },
                        "original": {"rva_start": 0x2000, "rva_end": 0x2006},
                    }
                ]
            }
        }

        details = stage_a._contract_candidate_missing_function_details(
            ["__iob_func", "wmain"],
            constraints=constraints,
            candidate_imports=[{"dll": "MSVCRT.dll", "symbol": "__p__iob", "ordinal": None}],
            alias_evidence=alias_evidence,
        )

        by_function = {item["function"]: item for item in details}
        self.assertEqual(by_function["__iob_func"]["category"], "import_thunk_symbol_missing_with_matching_import")
        self.assertEqual(by_function["__iob_func"]["candidate_import_match"]["symbol"], "__p__iob")
        self.assertEqual(by_function["__iob_func"]["source_evidence"]["source_kind"], "omitted_import_thunk")
        self.assertIn("import thunk symbol", by_function["__iob_func"]["next_action"])
        self.assertEqual(by_function["wmain"]["category"], "runtime_entry_replaced_by_generated_bridge")
        self.assertIn("runtime/CRT", by_function["wmain"]["next_action"])

    def test_contract_candidate_abi_coverage_gaps_fail_closed_on_ambiguous_skeleton_aliases(self):
        reference_abi = {
            "original": {
                "functions": [
                    {
                        "name": "__dup@4",
                        "blocks": [{"block_id": "dup", "rva_start": 0x1000, "rva_end": 0x1001, "size": 1}],
                        "callsites": [],
                    }
                ]
            },
            "counts": {"functions": 1, "callsites": 0},
        }
        candidate_abi = {
            "candidate": {
                "functions": [
                    {"name": "___first_4", "callsites": []},
                    {"name": "___second_4", "callsites": []},
                ]
            },
            "counts": {"functions": 2, "callsites": 0},
        }
        alias_evidence = stage_a._contract_candidate_skeleton_alias_evidence(
            {
                "format": "stage-b-skeleton-v1",
                "source_map": {
                    "functions": [
                        {"function": "___first_4", "aliases": ["__dup@4"]},
                        {"function": "___second_4", "aliases": ["__dup@4"]},
                    ]
                },
            },
            [
                {"name": "___first_4", "rva_start": 0x1000, "rva_end": 0x1001, "section": ".text"},
                {"name": "___second_4", "rva_start": 0x1001, "rva_end": 0x1002, "section": ".text"},
            ],
        )

        gaps = stage_a._contract_candidate_abi_coverage_gaps(reference_abi, candidate_abi, alias_evidence=alias_evidence)

        self.assertEqual(alias_evidence["status"], "incomplete")
        self.assertEqual(gaps["counts"]["missing_functions"], 0)
        self.assertEqual(gaps["counts"]["ambiguous_functions"], 1)
        self.assertEqual(gaps["ambiguous_functions"][0]["name"], "__dup@4")

    def test_validate_contract_candidate_satisfies_function_ranges_with_explicit_skeleton_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            candidate_bin = stage_a._parse_stage_a_pe(candidate)
            contract = self._write_reference_contract(
                root / "reference-contract.json",
                candidate_bin,
                functions=["__dyn_tls_init@12"],
            )
            linker_map = root / "candidate.map"
            linker_map.write_text("0x401000 @___dyn_tls_init_12@16\n", encoding="utf-8")
            skeleton_manifest = self._write_skeleton_manifest(
                root / "manifest.json",
                [
                    {
                        "function": "___dyn_tls_init_12",
                        "aliases": ["__dyn_tls_init@12"],
                        "source_kind": "decompiled_function",
                    }
                ],
            )

            result = stage_a.stage_a_validate_contract_candidate(
                reference_contract=contract,
                candidate=candidate,
                linker_map_candidate=linker_map,
                skeleton_manifest=skeleton_manifest,
                out=root / "out",
            )

        families = {item["family"]: item for item in result["families"]}
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(families["function_ranges"]["status"], "satisfied")
        self.assertEqual(families["abi_callsites"]["status"], "satisfied")
        self.assertEqual(families["function_ranges"]["evidence"]["alias_matches"][0]["reference_name"], "__dyn_tls_init@12")
        self.assertEqual(result["counts"]["alias_matches"], 2)

    def test_validate_contract_candidate_keeps_duplicate_skeleton_alias_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            candidate_bin = stage_a._parse_stage_a_pe(candidate)
            contract = self._write_reference_contract(root / "reference-contract.json", candidate_bin, functions=["__dup@4"])
            linker_map = root / "candidate.map"
            linker_map.write_text("0x401000 ___first_4\n0x401001 ___second_4\n", encoding="utf-8")
            skeleton_manifest = self._write_skeleton_manifest(
                root / "manifest.json",
                [
                    {"function": "___first_4", "aliases": ["__dup@4"]},
                    {"function": "___second_4", "aliases": ["__dup@4"]},
                ],
            )

            result = stage_a.stage_a_validate_contract_candidate(
                reference_contract=contract,
                candidate=candidate,
                linker_map_candidate=linker_map,
                skeleton_manifest=skeleton_manifest,
                out=root / "out",
            )

        families = {item["family"]: item for item in result["families"]}
        self.assertEqual(result["verdict"], "incomplete")
        self.assertEqual(families["function_ranges"]["status"], "incomplete")
        self.assertEqual(families["abi_callsites"]["status"], "incomplete")
        self.assertEqual(families["function_ranges"]["evidence"]["missing_functions"], [])
        self.assertEqual(families["function_ranges"]["evidence"]["ambiguous_aliases"][0]["matches_total"], 2)

    def test_audit_contract_shortfalls_reports_generated_candidate_acceptance_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = self._write_import_pe(root / "jq-candidate.exe", b"\xff\xd0\xc3", "jq_init", dll="libjq-1.dll")
            candidate_bin = stage_a._parse_stage_a_pe(candidate)
            contract = self._write_reference_contract(root / "jq-original-reference-contract.json", candidate_bin, functions=["stage_b_contract_section_gap__text_0001"])
            linker_map = root / "candidate.map"
            linker_map.write_text("0x401000 stage_b_contract_section_gap__text_0001\n", encoding="utf-8")
            skeleton_manifest = self._write_skeleton_manifest(
                root / "manifest.json",
                [
                    {
                        "function": "stage_b_contract_section_gap__text_0001",
                        "aliases": ["section-gap--text-0001", "missing_reference_alias"],
                        "source_kind": "generated_contract_guided_raw_flow",
                        "file": "src/jq_stage_b_skeleton.c",
                        "line_start": 42,
                        "line_end": 44,
                        "rva_start": 0x1000,
                        "rva_end": 0x1003,
                    }
                ],
            )
            repair_units = {
                "format": "stage-a-repair-units-v1",
                "work_items": [
                    {
                        "id": "work:hidden-sret",
                        "family": "abi_callsites",
                        "repair_class": "hidden_sret_or_out_param",
                        "severity": "incomplete",
                        "next_action": "recover hidden sret",
                    }
                ],
                "counts": {"work_items": 1},
            }
            (root / "repair-units.json").write_text(json.dumps(repair_units), encoding="utf-8")
            (root / "source-obligations.json").write_text(json.dumps({"obligations": []}), encoding="utf-8")
            crash = root / "crash.json"
            crash.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-crash-v1",
                        "status": "detected",
                        "crash_kind": "wine_unhandled_page_fault",
                        "instruction_address": "0x00401001",
                    }
                ),
                encoding="utf-8",
            )

            result = stage_a.stage_a_audit_contract_shortfalls(
                reference_contract=contract,
                candidate=candidate,
                linker_map_candidate=linker_map,
                skeleton_manifest=skeleton_manifest,
                candidate_crash_report=crash,
                out=root / "audit",
                target_name="jq",
            )
            audit_written = (root / "audit" / "stage-a-shortfalls.json").exists()

        families = {item["family"]: item for item in result["families"]}
        categories = {item["category"] for item in result["findings"]}
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("candidate_runtime_witness", families)
        self.assertIn("raw_section_gap_accepted", families)
        self.assertIn("target_owned_import_borrowed", families)
        self.assertIn("abi_underconstrained", families)
        self.assertIn("coverage_gap_masked", families)
        self.assertIn("candidate_only_crash_static_location", categories)
        self.assertEqual(result["findings"][0]["category"], "candidate_only_crash_static_location")
        self.assertEqual(result["findings"][0]["location"]["source_function"], "stage_b_contract_section_gap__text_0001")
        self.assertTrue(audit_written)

    def test_validate_contract_candidate_fails_closed_on_raw_section_gap_shortfall(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = self._write_pe(root / "candidate.exe", b"\xff\xd0\xc3")
            candidate_bin = stage_a._parse_stage_a_pe(candidate)
            contract = self._write_reference_contract(root / "reference-contract.json", candidate_bin, functions=["stage_b_contract_section_gap__text_0001"])
            linker_map = root / "candidate.map"
            linker_map.write_text("0x401000 stage_b_contract_section_gap__text_0001\n", encoding="utf-8")
            skeleton_manifest = self._write_skeleton_manifest(
                root / "manifest.json",
                [
                    {
                        "function": "stage_b_contract_section_gap__text_0001",
                        "aliases": ["stage_b_contract_section_gap__text_0001"],
                        "source_kind": "generated_contract_guided_raw_flow",
                        "rva_start": 0x1000,
                        "rva_end": 0x1003,
                    }
                ],
            )

            result = stage_a.stage_a_validate_contract_candidate(
                reference_contract=contract,
                candidate=candidate,
                linker_map_candidate=linker_map,
                skeleton_manifest=skeleton_manifest,
                out=root / "out",
            )

        families = {item["family"]: item for item in result["families"]}
        self.assertEqual(result["verdict"], "incomplete")
        self.assertEqual(families["contract_shortfalls"]["status"], "incomplete")
        self.assertIn("raw_section_gap_accepted", result["shortfall_audit"]["counts"]["by_family"])

    def test_stage_a_export_reference_contract_rejects_stale_validation_report_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )

            self._write_pe(candidate, b"\x90")
            mutated_map = json.loads(block_map.read_text(encoding="utf-8"))
            mutated_map["blocks"][0]["id"] = "tiny-stale-map"
            block_map.write_text(json.dumps(mutated_map, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "report",
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            self.assertEqual(result["status"], "incomplete")
            binding = result["constraints"]["validation_report_artifact_binding"]
            self.assertEqual(binding["status"], "incomplete")
            self.assertFalse(binding["facts"]["matching_candidate_sha256"])
            self.assertFalse(binding["facts"]["matching_mapping_payload"])
            self.assertIn(
                "validation_report_binary_mismatch",
                {issue["category"] for issue in binding["issues"]},
            )
            self.assertIn(
                "validation_report_mapping_mismatch",
                {issue["category"] for issue in binding["issues"]},
            )

            gaps = json.loads((root / "coverage_gaps.json").read_text(encoding="utf-8"))
            self.assertEqual(gaps["status"], "incomplete")
            self.assertIn(
                "validation_report_artifact_binding",
                {gap["family"] for gap in gaps["gaps"]},
            )
            self.assertEqual(gaps["next_work"][0]["family"], "validation_report_artifact_binding")

            explanation = stage_a_explain_obligations(
                reference_contract=root / "reference-contract.json",
                focus="validation_report_binary_mismatch",
            )
            self.assertEqual(explanation["status"], "pass")
            self.assertTrue(explanation["gaps"])

            self._write_pe(candidate, b"\xc3")
            smoke = stage_a_smoke_contract(reference_contract=root / "reference-contract.json")
            self.assertEqual(smoke["status"], "incomplete")
            self.assertIn("stale_bound_artifact", {issue["category"] for issue in smoke["issues"]})

    def test_stage_a_export_reference_contract_requires_proof_ir_and_solver_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )
            (root / "report" / "proof-ir.json").unlink()
            (root / "report" / "solver-evidence-index.json").unlink()

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "report",
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

            binding = result["constraints"]["validation_report_artifact_binding"]
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(binding["status"], "incomplete")
            self.assertIn("validation_report_proof_ir_missing", {issue["category"] for issue in binding["issues"]})
            self.assertIn("validation_report_solver_evidence_missing", {issue["category"] for issue in binding["issues"]})
            smoke = stage_a_smoke_contract(reference_contract=root / "reference-contract.json")
            self.assertEqual(smoke["status"], "incomplete")
            self.assertIn("missing_bound_artifact", {issue["category"] for issue in smoke["issues"]})

    def test_stage_a_export_reference_contract_rejects_stale_proof_ir_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, candidate, block_map, layout_contract, report = self._validated_identity_report(root)
            proof_ir_path = report / "proof-ir.json"
            proof_ir = json.loads(proof_ir_path.read_text(encoding="utf-8"))
            proof_ir["loader_profile"]["counts"]["layout_blocking_issues"] = 999
            proof_ir_path.write_text(json.dumps(proof_ir, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=report,
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertFalse(binding["facts"]["proof_ir_artifact_matches_verdict"])
        self.assertIn(
            "validation_report_proof_ir_artifact_mismatch",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_stale_verdict_model_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, candidate, block_map, layout_contract, report = self._validated_identity_report(root)
            verdict_path = report / "verdict.json"
            verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
            verdict["model_hash"] = "0" * 64
            verdict_path.write_text(json.dumps(verdict, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=report,
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertFalse(binding["facts"]["verdict_model_hash_matches_payload"])
        self.assertIn(
            "validation_report_model_hash_mismatch",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_stale_proof_ir_model_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, candidate, block_map, layout_contract, report = self._validated_identity_report(root)
            proof_ir_path = report / "proof-ir.json"
            proof_ir = json.loads(proof_ir_path.read_text(encoding="utf-8"))
            proof_ir["model_hash"] = "0" * 64
            proof_ir_path.write_text(json.dumps(proof_ir, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=report,
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertFalse(binding["facts"]["proof_ir_model_hash_matches_payload"])
        self.assertFalse(binding["facts"]["proof_ir_context_model_hash_bound"])
        categories = {issue["category"] for issue in binding["issues"]}
        self.assertIn("validation_report_proof_ir_model_hash_mismatch", categories)
        self.assertIn("validation_report_proof_ir_context_model_hash_mismatch", categories)

    def test_stage_a_export_reference_contract_rejects_stale_layout_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, candidate, block_map, layout_contract, report = self._validated_identity_report(root)
            layout_path = report / "layout.json"
            layout = json.loads(layout_path.read_text(encoding="utf-8"))
            layout["issues"] = [{"category": "stale-layout-marker"}]
            layout_path.write_text(json.dumps(layout, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=report,
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertFalse(binding["facts"]["layout_artifact_matches_proof_ir"])
        self.assertIn(
            "validation_report_layout_artifact_mismatch",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_stale_obligations_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, candidate, block_map, layout_contract, report = self._validated_identity_report(root)
            obligations_path = report / "obligations.json"
            obligations = json.loads(obligations_path.read_text(encoding="utf-8"))
            obligations["obligations"][0]["status"] = "failed"
            obligations["counts"]["by_status"] = {"failed": 1}
            obligations_path.write_text(json.dumps(obligations, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=report,
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertFalse(binding["facts"]["obligations_artifact_matches_verdict"])
        self.assertFalse(binding["facts"]["obligations_artifact_matches_proof_ir"])
        categories = {issue["category"] for issue in binding["issues"]}
        self.assertIn("validation_report_obligations_count_mismatch", categories)
        self.assertIn("validation_report_obligations_artifact_mismatch", categories)

    def test_stage_a_export_reference_contract_rejects_stale_proof_cache_index_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, candidate, block_map, layout_contract, report = self._validated_identity_report(root)
            proof_cache_index_path = report / "proof-cache" / "index.json"
            proof_cache_index = json.loads(proof_cache_index_path.read_text(encoding="utf-8"))
            proof_cache_index["entries"] = []
            proof_cache_index_path.write_text(
                json.dumps(proof_cache_index, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=report,
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertFalse(binding["facts"]["proof_cache_artifacts_match_proof_ir"])
        self.assertFalse(binding["facts"]["proof_cache_index_payload_matches_proof_ir"])
        self.assertIn(
            "validation_report_proof_cache_index_mismatch",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_stale_proof_cache_payload_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, candidate, block_map, layout_contract, report = self._validated_identity_report(root)
            proof_cache_index = json.loads((report / "proof-cache" / "index.json").read_text(encoding="utf-8"))
            proof_cache_entry = proof_cache_index["entries"][0]
            proof_cache_path = report / proof_cache_entry["path"]
            proof_cache_payload = json.loads(proof_cache_path.read_text(encoding="utf-8"))
            proof_cache_payload["stale_marker"] = True
            proof_cache_path.write_text(
                json.dumps(proof_cache_payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=report,
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertFalse(binding["facts"]["proof_cache_artifacts_match_proof_ir"])
        self.assertFalse(binding["facts"]["proof_cache_payload_hashes_match_index"])
        self.assertEqual(binding["facts"]["proof_cache_payload_hash_mismatches"], 1)
        self.assertIn(
            "validation_report_proof_cache_payload_mismatch",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_stale_solver_evidence_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, candidate, block_map, layout_contract, report = self._validated_identity_report(root)
            solver_index_path = report / "solver-evidence-index.json"
            solver_index = json.loads(solver_index_path.read_text(encoding="utf-8"))
            solver_index["counts"]["entries"] = 999
            solver_index_path.write_text(json.dumps(solver_index, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=report,
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertFalse(binding["facts"]["solver_evidence_artifacts_match_verdict"])
        self.assertIn(
            "validation_report_solver_evidence_artifact_mismatch",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_stale_lean_inputs_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, candidate, block_map, layout_contract, report = self._validated_identity_report(root)
            lean_inputs_path = report / "lean" / "inputs.json"
            lean_inputs = json.loads(lean_inputs_path.read_text(encoding="utf-8"))
            lean_inputs["lean_inputs"]["errors"].append({"source": "stale-input.lean", "error": "edited"})
            lean_inputs_path.write_text(json.dumps(lean_inputs, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=report,
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertTrue(binding["facts"]["lean_summary_matches_verdict"])
        self.assertFalse(binding["facts"]["lean_inputs_matches_summary"])
        self.assertIn(
            "validation_report_lean_inputs_artifact_mismatch",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_stale_generated_lean_source_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, candidate, block_map, layout_contract, report = self._validated_identity_report(root)
            generated_source = report / "lean" / "StageA" / "Obligations.lean"
            generated_source.write_text(
                generated_source.read_text(encoding="utf-8") + "\n-- edited after validation\n",
                encoding="utf-8",
            )

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=report,
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertFalse(binding["facts"]["lean_generated_sources_match_summary"])
        self.assertFalse(binding["facts"]["lean_source_artifacts_match_summary"])
        self.assertEqual(binding["facts"]["lean_source_artifact_mismatches"], 1)
        self.assertIn(
            "validation_report_lean_source_artifact_mismatch",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_stale_supplemental_lean_source_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lean_input = root / "fixture lemma.lean"
            lean_input.write_text(
                "namespace StageAUserFixture\n\ntheorem extraChecked : True := True.intro\n\nend StageAUserFixture\n",
                encoding="utf-8",
            )
            original, candidate, block_map, layout_contract, report = self._validated_identity_report(
                root,
                lean_inputs=(lean_input,),
            )
            summary = json.loads((report / "lean" / "summary.json").read_text(encoding="utf-8"))
            copied_path = report / "lean" / summary["supplemental_inputs"]["copied"][0]["relative_path"]
            copied_path.write_text(
                copied_path.read_text(encoding="utf-8") + "\n-- edited after validation\n",
                encoding="utf-8",
            )

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=report,
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertTrue(binding["facts"]["lean_generated_sources_match_summary"])
        self.assertFalse(binding["facts"]["lean_supplemental_sources_match_summary"])
        self.assertFalse(binding["facts"]["lean_source_artifacts_match_summary"])
        self.assertEqual(binding["facts"]["lean_source_artifact_mismatches"], 1)
        self.assertIn(
            "validation_report_lean_source_artifact_mismatch",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_stale_lean_summary_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, candidate, block_map, layout_contract, report = self._validated_identity_report(root)
            lean_summary_path = report / "lean" / "summary.json"
            lean_summary = json.loads(lean_summary_path.read_text(encoding="utf-8"))
            lean_summary["final_pass_allowed"] = False
            lean_summary["proof_ir_checked"] = False
            lean_summary_path.write_text(json.dumps(lean_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=report,
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertFalse(binding["facts"]["lean_summary_matches_verdict"])
        self.assertFalse(binding["facts"]["lean_summary_final_pass_allowed"])
        self.assertIn(
            "validation_report_lean_summary_artifact_mismatch",
            {issue["category"] for issue in binding["issues"]},
        )
        self.assertIn(
            "validation_report_lean_summary_incomplete",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_incomplete_proof_ir_closure_certificate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )
            proof_ir_path = root / "report" / "proof-ir.json"
            proof_ir = json.loads(proof_ir_path.read_text(encoding="utf-8"))
            proof_ir["closure_certificate"]["status"] = "incomplete"
            proof_ir["closure_certificate"]["checks"]["obligations_closed"] = False
            proof_ir_path.write_text(json.dumps(proof_ir, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "report",
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertIn(
            "validation_report_proof_ir_closure_certificate_incomplete",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_incomplete_proof_ir_proof_rule_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )
            proof_ir_path = root / "report" / "proof-ir.json"
            proof_ir = json.loads(proof_ir_path.read_text(encoding="utf-8"))
            proof_ir["proof_rule_profile"]["status"] = "incomplete"
            proof_ir["proof_rule_profile"]["checks"]["obligation_rules_known"] = False
            proof_ir_path.write_text(json.dumps(proof_ir, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "report",
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertIn(
            "validation_report_proof_ir_proof_rule_profile_incomplete",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_incomplete_proof_ir_mapping_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )
            proof_ir_path = root / "report" / "proof-ir.json"
            proof_ir = json.loads(proof_ir_path.read_text(encoding="utf-8"))
            proof_ir["mapping_profile"]["status"] = "incomplete"
            proof_ir["mapping_profile"]["checks"]["mapping_gaps_closed"] = False
            proof_ir_path.write_text(json.dumps(proof_ir, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "report",
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertEqual(binding["facts"]["proof_ir_mapping_profile_status"], "incomplete")
        self.assertIn(
            "validation_report_proof_ir_mapping_profile_incomplete",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_incomplete_required_proof_ir_profiles(self):
        cases = [
            (
                "proof_context",
                "loader_profile_satisfied",
                "validation_report_proof_ir_context_incomplete",
                "proof_ir_context_status",
            ),
            (
                "target_profile",
                "loader_profile_model_matches",
                "validation_report_proof_ir_target_profile_incomplete",
                "proof_ir_target_profile_status",
            ),
            (
                "loader_frontend_profile",
                "original_required_fields_present",
                "validation_report_proof_ir_loader_frontend_profile_incomplete",
                "proof_ir_loader_frontend_profile_status",
            ),
            (
                "loader_profile",
                "layout_compatible",
                "validation_report_proof_ir_loader_profile_incomplete",
                "proof_ir_loader_profile_status",
            ),
            (
                "proof_cache_profile",
                "proof_cache_gaps_closed",
                "validation_report_proof_ir_proof_cache_profile_incomplete",
                "proof_ir_proof_cache_profile_status",
            ),
            (
                "instruction_profile",
                "records_satisfied",
                "validation_report_proof_ir_instruction_profile_incomplete",
                "proof_ir_instruction_profile_status",
            ),
            (
                "semantic_profile",
                "semantic_observable_gaps_closed",
                "validation_report_proof_ir_semantic_profile_incomplete",
                "proof_ir_semantic_profile_status",
            ),
            (
                "solver_evidence_profile",
                "solver_evidence_entries_satisfied",
                "validation_report_proof_ir_solver_evidence_profile_incomplete",
                "proof_ir_solver_evidence_profile_status",
            ),
            (
                "solver_backend_profile",
                "backend_gaps_closed",
                "validation_report_proof_ir_solver_backend_profile_incomplete",
                "proof_ir_solver_backend_profile_status",
            ),
            (
                "trusted_boundary_profile",
                "records_gap_free",
                "validation_report_proof_ir_trusted_boundary_profile_incomplete",
                "proof_ir_trusted_boundary_profile_status",
            ),
            (
                "profile_manifest",
                "profile_manifest_gaps_closed",
                "validation_report_proof_ir_profile_manifest_incomplete",
                "proof_ir_profile_manifest_status",
            ),
        ]
        for profile_key, check_key, category, fact_key in cases:
            with self.subTest(profile_key=profile_key), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                original, candidate, block_map, layout_contract, report = self._validated_identity_report(root)
                proof_ir_path = report / "proof-ir.json"
                proof_ir = json.loads(proof_ir_path.read_text(encoding="utf-8"))
                proof_ir[profile_key]["status"] = "incomplete"
                proof_ir[profile_key]["checks"][check_key] = False
                proof_ir_path.write_text(json.dumps(proof_ir, indent=2, sort_keys=True) + "\n", encoding="utf-8")

                result = stage_a_export_reference_contract(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    validation_report=report,
                    layout_contract=layout_contract,
                    model=STAGE_A_MODEL_ID,
                    out=root / "reference-contract.json",
                )

                binding = result["constraints"]["validation_report_artifact_binding"]
                self.assertEqual(result["status"], "incomplete")
                self.assertEqual(binding["status"], "incomplete")
                self.assertEqual(binding["facts"][fact_key], "incomplete")
                self.assertIn(category, {issue["category"] for issue in binding["issues"]})

    def test_stage_a_export_reference_contract_rejects_incomplete_proof_ir_cfg_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )
            proof_ir_path = root / "report" / "proof-ir.json"
            proof_ir = json.loads(proof_ir_path.read_text(encoding="utf-8"))
            proof_ir["cfg_profile"]["status"] = "incomplete"
            proof_ir["cfg_profile"]["checks"]["cfg_gaps_closed"] = False
            proof_ir_path.write_text(json.dumps(proof_ir, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "report",
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertIn(
            "validation_report_proof_ir_cfg_profile_incomplete",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_incomplete_proof_ir_reachability_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )
            proof_ir_path = root / "report" / "proof-ir.json"
            proof_ir = json.loads(proof_ir_path.read_text(encoding="utf-8"))
            proof_ir["reachability_profile"]["status"] = "incomplete"
            proof_ir["reachability_profile"]["checks"]["reachability_gaps_closed"] = False
            proof_ir_path.write_text(json.dumps(proof_ir, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "report",
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertIn(
            "validation_report_proof_ir_reachability_profile_incomplete",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_incomplete_proof_ir_environment_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )
            proof_ir_path = root / "report" / "proof-ir.json"
            proof_ir = json.loads(proof_ir_path.read_text(encoding="utf-8"))
            proof_ir["environment_profile"]["status"] = "incomplete"
            proof_ir["environment_profile"]["checks"]["environment_gaps_closed"] = False
            proof_ir_path.write_text(json.dumps(proof_ir, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "report",
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertIn(
            "validation_report_proof_ir_environment_profile_incomplete",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_stage_a_export_reference_contract_rejects_incomplete_proof_ir_abi_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )
            proof_ir_path = root / "report" / "proof-ir.json"
            proof_ir = json.loads(proof_ir_path.read_text(encoding="utf-8"))
            proof_ir["abi_profile"]["status"] = "incomplete"
            proof_ir["abi_profile"]["checks"]["abi_gaps_closed"] = False
            proof_ir_path.write_text(json.dumps(proof_ir, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "report",
                layout_contract=layout_contract,
                model=STAGE_A_MODEL_ID,
                out=root / "reference-contract.json",
            )

        binding = result["constraints"]["validation_report_artifact_binding"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(binding["status"], "incomplete")
        self.assertIn(
            "validation_report_proof_ir_abi_profile_incomplete",
            {issue["category"] for issue in binding["issues"]},
        )

    def test_proof_ir_schema_tracks_loader_and_isa_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            model = stage_a_model_description(
                STAGE_A_X86_64_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32plus-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[],
                failures=[],
                incomplete=[],
                proof_cache=[],
                proof_cache_index={"entries": []},
                solver_evidence={"format": "stage-a-solver-evidence-v1", "counts": {"entries": 0}},
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))

        self.assertEqual(proof_ir["schema"]["target_profile"], "stage-a-target-profile-v1")
        self.assertEqual(proof_ir["schema"]["loader_facts"], "stage-a-loader-pe32plus-facts-v1")
        self.assertEqual(proof_ir["schema"]["loader_frontend_profile"], "stage-a-loader-frontend-profile-v1")
        self.assertEqual(proof_ir["schema"]["loader_profile"], "stage-a-loader-profile-v1")
        self.assertEqual(proof_ir["schema"]["coverage_profile"], "stage-a-executable-coverage-profile-v1")
        self.assertEqual(proof_ir["schema"]["proof_cache_profile"], "stage-a-proof-cache-profile-v1")
        self.assertEqual(proof_ir["schema"]["proof_rule_profile"], "stage-a-proof-rule-profile-v1")
        self.assertEqual(proof_ir["schema"]["mapping_profile"], "stage-a-mapping-profile-v1")
        self.assertEqual(proof_ir["schema"]["environment_profile"], "stage-a-environment-profile-v1")
        self.assertEqual(proof_ir["schema"]["abi_profile"], "stage-a-abi-callsite-profile-v1")
        self.assertEqual(proof_ir["schema"]["block_semantics"], "stage-a-x86_64-block-semantics-v1")
        self.assertEqual(proof_ir["schema"]["instruction_semantics"], "stage-a-x86_64-instruction-semantics-v1")
        self.assertEqual(proof_ir["schema"]["instruction_profile"], "stage-a-instruction-semantics-profile-v1")
        self.assertEqual(proof_ir["schema"]["semantic_observables"], "stage-a-x86_64-semantic-observables-v1")
        self.assertEqual(proof_ir["schema"]["semantic_profile"], "stage-a-semantic-observable-profile-v1")
        self.assertEqual(proof_ir["schema"]["proof_composition"], "stage-a-proof-composition-v1")
        self.assertEqual(proof_ir["schema"]["solver_evidence_profile"], "stage-a-solver-evidence-profile-v1")
        self.assertEqual(proof_ir["schema"]["solver_backend_profile"], "stage-a-solver-backend-profile-v1")
        self.assertEqual(proof_ir["schema"]["trusted_boundary_profile"], "stage-a-trusted-boundary-profile-v1")
        self.assertEqual(proof_ir["schema"]["profile_manifest"], "stage-a-proof-profile-manifest-v1")
        self.assertEqual(proof_ir["target_profile"]["format"], "stage-a-target-profile-v1")
        self.assertEqual(proof_ir["target_profile"]["model"]["isa"], "x86_64")
        self.assertTrue(proof_ir["target_profile"]["checks"]["loader_frontend_profile_schema_matches"])
        self.assertTrue(proof_ir["target_profile"]["checks"]["solver_backend_profile_schema_matches"])
        self.assertTrue(proof_ir["target_profile"]["checks"]["trusted_boundary_profile_schema_matches"])
        self.assertTrue(proof_ir["target_profile"]["checks"]["profile_manifest_schema_matches"])
        self.assertFalse(proof_ir["target_profile"]["checks"]["loader_facts_loader_matches_model"])
        self.assertEqual(proof_ir["loader_frontend_profile"]["format"], "stage-a-loader-frontend-profile-v1")
        self.assertEqual(proof_ir["loader_frontend_profile"]["status"], "incomplete")
        self.assertFalse(proof_ir["loader_frontend_profile"]["checks"]["original_side_present"])

    def test_proof_ir_abi_profile_accepts_matching_callsite_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )
            abi_contract = {
                "status": "derived",
                "evidence_kind": "capstone-static-abi-callsites",
                "scope": "original-candidate-pair",
                "original": {
                    "functions": [
                        {
                            "name": "_caller",
                            "blocks": [{"block_id": "caller", "rva_start": 0x1000, "rva_end": 0x1010}],
                            "stack_delta": {"status": "derived", "net_bytes": 0},
                            "registers": {"preserved_candidates": ["esi"], "clobbered_candidates": ["eax"]},
                            "callsites": [
                                {
                                    "id": "callsite:caller:1004",
                                    "block_id": "caller",
                                    "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "fprintf"},
                                    "hidden_sret_or_out_param_evidence": {"status": "none"},
                                    "varargs_evidence": {"status": "candidate"},
                                    "function_pointer_targets": [],
                                }
                            ],
                        }
                    ],
                    "import_prototypes": [{"dll": "msvcrt.dll", "symbol": "fprintf"}],
                },
                "candidate": {
                    "functions": [
                        {
                            "name": "_caller",
                            "blocks": [{"block_id": "caller", "rva_start": 0x1000, "rva_end": 0x1010}],
                            "stack_delta": {"status": "derived", "net_bytes": 0},
                            "registers": {"preserved_candidates": ["esi"], "clobbered_candidates": ["eax"]},
                            "callsites": [
                                {
                                    "id": "callsite:caller:1004",
                                    "block_id": "caller",
                                    "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "fprintf"},
                                    "hidden_sret_or_out_param_evidence": {"status": "none"},
                                    "varargs_evidence": {"status": "candidate"},
                                    "function_pointer_targets": [],
                                }
                            ],
                        }
                    ],
                    "import_prototypes": [{"dll": "msvcrt.dll", "symbol": "fprintf"}],
                },
                "comparison_gaps": {
                    "counts": {
                        "missing_functions": 0,
                        "ambiguous_functions": 0,
                        "incomplete_callsite_functions": 0,
                        "missing_callsites": 0,
                        "function_mismatches": 0,
                        "callsite_mismatches": 0,
                    }
                },
            }

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[],
                failures=[],
                incomplete=[],
                proof_cache=[],
                proof_cache_index={"format": "stage-a-proof-cache-index-v1", "entries": []},
                solver_evidence={"format": "stage-a-solver-evidence-v1", "counts": {"entries": 0}},
                mapping_payload={},
                invariant_payload={},
                abi_contract=abi_contract,
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))

        profile = proof_ir["abi_profile"]
        self.assertEqual(profile["status"], "satisfied")
        self.assertTrue(profile["checks"]["abi_contract_present"])
        self.assertTrue(profile["checks"]["callsite_counts_match"])
        self.assertEqual(profile["counts"]["original_callsites"], 1)
        self.assertEqual(profile["counts"]["candidate_callsites"], 1)
        self.assertEqual(profile["counts"]["original_varargs_candidates"], 1)
        self.assertEqual(profile["counts"]["abi_gaps"], 0)

    def test_proof_ir_abi_profile_rejects_callsite_contract_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )
            abi_contract = {
                "status": "incomplete",
                "evidence_kind": "capstone-static-abi-callsites",
                "scope": "original-candidate-pair",
                "original": {
                    "functions": [
                        {
                            "name": "_caller",
                            "callsites": [
                                {"id": "callsite:caller:1004", "target": {"kind": "direct", "target_rva": 0x2000}},
                                {"id": "callsite:caller:1008", "target": {"kind": "import", "symbol": "fprintf"}},
                            ],
                        }
                    ],
                    "import_prototypes": [],
                },
                "candidate": {
                    "functions": [
                        {
                            "name": "_caller",
                            "callsites": [
                                {"id": "callsite:caller:1004", "target": {"kind": "direct", "target_rva": 0x2000}},
                            ],
                        }
                    ],
                    "import_prototypes": [],
                },
                "comparison_gaps": {
                    "incomplete_callsites": [{"name": "_caller", "missing_callsites": 1}],
                    "counts": {
                        "missing_functions": 0,
                        "ambiguous_functions": 0,
                        "incomplete_callsite_functions": 1,
                        "missing_callsites": 1,
                        "function_mismatches": 0,
                        "callsite_mismatches": 0,
                    },
                },
            }

            summary = write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[],
                failures=[],
                incomplete=[],
                proof_cache=[],
                proof_cache_index={"format": "stage-a-proof-cache-index-v1", "entries": []},
                solver_evidence={"format": "stage-a-solver-evidence-v1", "counts": {"entries": 0}},
                mapping_payload={},
                invariant_payload={},
                abi_contract=abi_contract,
            )
            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))

        profile = proof_ir["abi_profile"]
        self.assertEqual(profile["status"], "incomplete")
        self.assertFalse(profile["checks"]["abi_contract_status_satisfied"])
        self.assertFalse(profile["checks"]["callsite_counts_match"])
        self.assertFalse(profile["checks"]["callsites_complete"])
        self.assertEqual(profile["counts"]["abi_gaps"], 2)
        self.assertFalse(proof_ir["proof_context"]["checks"]["abi_profile_satisfied"])
        self.assertFalse(proof_ir["closure_certificate"]["checks"]["abi_profile_satisfied"])
        self.assertEqual(summary["abi_profile"]["status"], "incomplete")

    def test_proof_ir_loader_profile_rejects_model_and_loader_mismatch(self):
        def loader_side(machine: str, bitness: int) -> dict[str, object]:
            return {
                "sha256": "0" * 64,
                "size": 1,
                "machine": machine,
                "bitness": bitness,
                "image_base": 0x400000,
                "entrypoint_rva": 0x1000,
                "size_of_image": 0x2000,
                "subsystem": "windows_cui",
                "sections": [
                    {
                        "name": ".text",
                        "rva_start": 0x1000,
                        "rva_end": 0x1100,
                        "permissions": {"execute": True, "read": True, "write": False, "code": True},
                    }
                ],
                "executable_sections": [{"name": ".text", "rva_start": 0x1000, "rva_end": 0x1100, "size": 0x100}],
                "imports": [],
                "relocations": {
                    "status": "empty_directory",
                    "directory": {"rva": 0, "size": 0},
                    "blocks": [],
                    "counts": {"blocks": 0, "entries": 0},
                },
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={
                    "format": "stage-a-loader-pe32plus-facts-v1",
                    "loader": "pe32plus",
                    "original": loader_side("x86_64", 64),
                    "candidate": loader_side("i386", 32),
                },
                layout={
                    "compatible": False,
                    "issues": [{"category": "layout_mismatch", "severity": "incomplete"}],
                },
                obligations=[],
                failures=[],
                incomplete=[],
                proof_cache=[],
                proof_cache_index={"format": "stage-a-proof-cache-index-v1", "entries": []},
                solver_evidence={
                    "format": "stage-a-solver-evidence-v1",
                    "status": "satisfied",
                    "sha256": "0" * 64,
                    "index_sha256": "1" * 64,
                    "counts": {"entries": 0},
                    "entries": [],
                },
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))

        profile = proof_ir["loader_profile"]
        self.assertEqual(profile["status"], "incomplete")
        self.assertFalse(profile["checks"]["loader_format_matches_model"])
        self.assertFalse(profile["checks"]["loader_name_matches_model"])
        self.assertFalse(profile["checks"]["original_model_matches"])
        self.assertFalse(profile["checks"]["layout_compatible"])
        self.assertEqual(profile["counts"]["layout_blocking_issues"], 1)
        self.assertGreaterEqual(profile["counts"]["binary_signature_mismatches"], 1)
        self.assertEqual(proof_ir["target_profile"]["status"], "incomplete")
        self.assertEqual(proof_ir["loader_frontend_profile"]["status"], "incomplete")
        self.assertTrue(proof_ir["loader_frontend_profile"]["checks"]["original_required_fields_present"])
        self.assertFalse(proof_ir["loader_frontend_profile"]["checks"]["loader_facts_loader_matches_model"])
        self.assertTrue(proof_ir["target_profile"]["checks"]["loader_facts_schema_matches_model"])
        self.assertFalse(proof_ir["target_profile"]["checks"]["loader_facts_loader_matches_model"])
        self.assertFalse(proof_ir["target_profile"]["checks"]["loader_profile_status_satisfied"])
        self.assertFalse(proof_ir["proof_context"]["checks"]["target_profile_satisfied"])
        self.assertFalse(proof_ir["proof_context"]["checks"]["loader_profile_satisfied"])
        self.assertEqual(proof_ir["proof_context"]["status"], "incomplete")

    def test_proof_ir_proof_rule_profile_rejects_unknown_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )
            loader_side = {
                "sha256": "0" * 64,
                "size": 8,
                "machine": "i386",
                "subsystem": "console",
                "bitness": 32,
                "image_base": 0x400000,
                "entrypoint_rva": 0x1000,
                "size_of_image": 0x2000,
                "sections": [
                    {
                        "name": ".text",
                        "virtual_address": 0x1000,
                        "virtual_size": 0x10,
                        "raw_size": 0x10,
                        "permissions": {"execute": True, "read": True, "write": False},
                    }
                ],
                "executable_sections": [{"name": ".text", "start_rva": 0x1000, "end_rva": 0x1010}],
                "imports": [],
                "relocations": {"status": "empty_directory", "directory": {}, "counts": {"blocks": 0, "entries": 0}},
            }

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={
                    "format": "stage-a-loader-pe32-facts-v1",
                    "loader": "pe32",
                    "original": dict(loader_side),
                    "candidate": dict(loader_side),
                },
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:unknown-rule",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "target_specific_unapproved_rule_v1",
                    }
                ],
                failures=[],
                incomplete=[],
                proof_cache=[],
                proof_cache_index={"format": "stage-a-proof-cache-index-v1", "entries": []},
                solver_evidence={
                    "format": "stage-a-solver-evidence-v1",
                    "status": "satisfied",
                    "sha256": "0" * 64,
                    "index_sha256": "1" * 64,
                    "counts": {"entries": 0},
                    "entries": [],
                },
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))

        profile = proof_ir["proof_rule_profile"]
        self.assertEqual(profile["status"], "incomplete")
        self.assertEqual(profile["counts"]["unknown_obligation_rules"], 1)
        self.assertFalse(profile["checks"]["obligation_rules_known"])
        self.assertFalse(proof_ir["proof_context"]["checks"]["proof_rule_profile_satisfied"])
        self.assertEqual(proof_ir["proof_context"]["status"], "incomplete")

    def test_proof_ir_mapping_profile_rejects_mapping_contract_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[],
                failures=[],
                incomplete=[],
                proof_cache=[],
                proof_cache_index={"format": "stage-a-proof-cache-index-v1", "entries": []},
                solver_evidence={
                    "format": "stage-a-solver-evidence-v1",
                    "status": "satisfied",
                    "sha256": "0" * 64,
                    "index_sha256": "1" * 64,
                    "counts": {"entries": 0},
                    "entries": [],
                },
                mapping_payload={},
                invariant_payload={},
                mapping_contract={
                    "format": "stage-a-mapping-contract-v1",
                    "status": "incomplete",
                    "blocks": [
                        {
                            "id": "bad-entry",
                            "kind": "code",
                            "reachable": True,
                            "invariant_checked": False,
                            "original": {"rva_start": 0x1000, "rva_end": 0x1000},
                            "candidate": {"rva_start": 0x1000, "rva_end": 0x1001},
                            "root_present": True,
                            "root_checked": True,
                            "checked_root_kind": None,
                            "unknown_checked_root": True,
                            "proof_rule": "target_specific_map_rule_v1",
                            "proof_checked": True,
                        }
                    ],
                    "waivers": [
                        {
                            "id": "bad-padding",
                            "binary": "original",
                            "rva_start": 0x2000,
                            "rva_end": 0x2000,
                            "reason": "padding",
                        }
                    ],
                    "issues": [
                        {
                            "category": "invalid_mapping",
                            "status": "incomplete",
                            "severity": "incomplete",
                            "obligation_id": "mapping:bad-entry",
                        }
                    ],
                    "counts": {
                        "code_blocks": 1,
                        "non_code_blocks": 0,
                        "reachable_blocks": 1,
                        "unchecked_invariant_blocks": 1,
                        "root_entries": 1,
                        "checked_root_entries": 0,
                        "unknown_checked_root_entries": 1,
                        "mapping_proofs": 1,
                        "checked_mapping_proofs": 1,
                        "unchecked_mapping_proofs": 0,
                        "failed_issues": 0,
                        "incomplete_issues": 1,
                    },
                },
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))

        profile = proof_ir["mapping_profile"]
        self.assertEqual(profile["status"], "incomplete")
        self.assertEqual(profile["counts"]["blocks"], 1)
        self.assertEqual(profile["counts"]["malformed_blocks"], 1)
        self.assertEqual(profile["counts"]["malformed_waivers"], 1)
        self.assertEqual(profile["counts"]["unknown_checked_root_entries"], 1)
        self.assertEqual(profile["counts"]["unknown_mapping_proof_rules"], 1)
        self.assertEqual(profile["counts"]["mapping_gaps"], 6)
        self.assertFalse(profile["checks"]["mapping_status_satisfied"])
        self.assertFalse(profile["checks"]["mapping_issues_closed"])
        self.assertFalse(profile["checks"]["mapping_ranges_well_formed"])
        self.assertFalse(profile["checks"]["mapping_invariants_checked"])
        self.assertFalse(profile["checks"]["checked_roots_known"])
        self.assertFalse(profile["checks"]["mapping_proof_rules_known"])
        self.assertFalse(profile["checks"]["waiver_ranges_well_formed"])
        self.assertFalse(profile["checks"]["mapping_gaps_closed"])
        self.assertFalse(proof_ir["proof_context"]["checks"]["mapping_profile_satisfied"])
        self.assertFalse(proof_ir["closure_certificate"]["checks"]["mapping_profile_satisfied"])
        self.assertEqual(proof_ir["closure_certificate"]["counts"]["mapping_profile_gaps"], 6)
        self.assertEqual(proof_ir["proof_context"]["status"], "incomplete")

    def test_proof_ir_reachability_profile_rejects_direct_reachability_without_edge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:entry",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "byte_identical_x86_pe32_block",
                    },
                    {
                        "id": "block:target",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "byte_identical_x86_pe32_block",
                    },
                    {
                        "id": "reachability:entry",
                        "kind": "reachability",
                        "status": "proved",
                        "block": "entry",
                        "proof_rule": "entry_root_reachability_v1",
                        "proof": {"kind": "entry_root", "root_kind": "pe_entrypoint"},
                    },
                    {
                        "id": "reachability:target",
                        "kind": "reachability",
                        "status": "proved",
                        "block": "target",
                        "proof_rule": "direct_cfg_reachability_v1",
                        "proof": {
                            "kind": "direct_cfg_edge",
                            "edge_obligation": "edge:entry:fallthrough:target",
                            "source_block": "entry",
                            "edge_kind": "fallthrough",
                        },
                    },
                ],
                failures=[],
                incomplete=[],
                proof_cache=[],
                proof_cache_index={"format": "stage-a-proof-cache-index-v1", "entries": []},
                solver_evidence={
                    "format": "stage-a-solver-evidence-v1",
                    "status": "satisfied",
                    "sha256": "0" * 64,
                    "index_sha256": "1" * 64,
                    "counts": {"entries": 0},
                    "entries": [],
                },
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))

        profile = proof_ir["reachability_profile"]
        self.assertEqual(profile["status"], "incomplete")
        self.assertEqual(profile["counts"]["direct_cfg_reachability"], 1)
        self.assertEqual(profile["counts"]["direct_cfg_reachability_with_edge_obligation"], 1)
        self.assertEqual(profile["counts"]["direct_cfg_reachability_with_proved_edge"], 0)
        self.assertEqual(profile["counts"]["reachability_gaps"], 1)
        self.assertIn("direct_cfg_reachability_missing_edge_obligation", {gap["category"] for gap in profile["gaps"]})
        self.assertFalse(profile["checks"]["direct_cfg_reachability_edges_proved"])
        self.assertFalse(proof_ir["proof_context"]["checks"]["reachability_profile_satisfied"])
        self.assertEqual(proof_ir["proof_context"]["status"], "incomplete")

    def test_proof_ir_cfg_profile_rejects_indirect_target_without_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:entry",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "byte_identical_x86_pe32_block",
                    },
                    {
                        "id": "indirect-edge:entry:0000:0",
                        "kind": "indirect_cfg_target",
                        "status": "proved",
                        "proof_rule": "same_source_layout_preserving_build_v1",
                        "source_block": "entry",
                        "original": {"instruction": {"mnemonic": "jmp"}},
                        "candidate": {"instruction": {"mnemonic": "jmp"}},
                    },
                ],
                failures=[],
                incomplete=[],
                proof_cache=[],
                proof_cache_index={"format": "stage-a-proof-cache-index-v1", "entries": []},
                solver_evidence={
                    "format": "stage-a-solver-evidence-v1",
                    "status": "satisfied",
                    "sha256": "0" * 64,
                    "index_sha256": "1" * 64,
                    "counts": {"entries": 0},
                    "entries": [],
                },
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))

        profile = proof_ir["cfg_profile"]
        self.assertEqual(profile["status"], "incomplete")
        self.assertEqual(profile["counts"]["indirect_cfg_target_obligations"], 1)
        self.assertEqual(profile["counts"]["proved_indirect_cfg_target_obligations"], 1)
        self.assertEqual(profile["counts"]["proved_indirect_cfg_targets_with_signature"], 0)
        self.assertEqual(profile["counts"]["cfg_gaps"], 1)
        self.assertIn("indirect_cfg_target_missing_signature", {gap["category"] for gap in profile["gaps"]})
        self.assertFalse(profile["checks"]["indirect_cfg_target_metadata_present"])
        self.assertFalse(proof_ir["proof_context"]["checks"]["cfg_profile_satisfied"])
        self.assertEqual(proof_ir["proof_context"]["status"], "incomplete")

    def test_proof_ir_environment_profile_rejects_import_thunk_without_signature_evidence(self):
        def loader_side() -> dict[str, object]:
            return {
                "machine": "i386",
                "subsystem": "console",
                "bitness": 32,
                "image_base": 0x400000,
                "entrypoint_rva": 0x1000,
                "size_of_image": 0x3000,
                "sections": [
                    {
                        "name": ".text",
                        "permissions": {"execute": True, "read": True, "write": False, "code": True},
                    }
                ],
                "executable_sections": [{"name": ".text", "rva_start": 0x1000, "rva_end": 0x1006}],
                "imports": [{"dll": "kernel32.dll", "symbol": "GetTickCount", "ordinal": None}],
                "relocations": {"status": "empty_directory", "directory": {}, "counts": {"blocks": 0, "entries": 0}},
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            import_signature = {"dll": "kernel32.dll", "symbol": "GetTickCount", "ordinal": None}
            base_analysis = {
                "status": "ok",
                "machine": "i386",
                "bitness": 32,
                "instructions": [{"rva": 0x1000, "size": 6, "mnemonic": "jmp", "op_str": "dword ptr [0x402040]", "bytes": "ff2540204000"}],
            }
            original_analysis = {**base_analysis, "import_signature": import_signature}
            candidate_analysis = dict(base_analysis)
            payload = {
                "format": "stage-a-import-thunk-proof-cache-v1",
                "obligation_id": "block:import-thunk",
                "proof_rule": "pe_import_thunk_equivalence_v1",
                "query": {
                    "kind": "pe_import_thunk_equivalence",
                    "original_sha256": "0" * 64,
                    "candidate_sha256": "1" * 64,
                    "original_import": import_signature,
                    "candidate_import": import_signature,
                    "same_import_signature": True,
                },
                "original_analysis": original_analysis,
                "candidate_analysis": candidate_analysis,
            }
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            proof_cache = [{"path": "proof-cache/import-thunk.json", "status": "proved", "sha256": digest}]
            (root / "proof-cache").mkdir()
            (root / "proof-cache" / "import-thunk.json").write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            proof_cache_index = {"format": "stage-a-proof-cache-index-v1", "entries": proof_cache}
            (root / "proof-cache" / "index.json").write_text(json.dumps(proof_cache_index, sort_keys=True), encoding="utf-8")
            solver_evidence = write_solver_evidence_inventory(root, proof_cache)
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={
                    "format": "stage-a-loader-pe32-facts-v1",
                    "loader": "pe32",
                    "original": loader_side(),
                    "candidate": loader_side(),
                },
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:import-thunk",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "pe_import_thunk_equivalence_v1",
                        "proof_cache": "proof-cache/import-thunk.json",
                    }
                ],
                failures=[],
                incomplete=[],
                proof_cache=proof_cache,
                proof_cache_index=proof_cache_index,
                solver_evidence=solver_evidence,
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))
            certificate = proof_ir["closure_certificate"]

        self.assertEqual(proof_ir["environment_profile"]["status"], "incomplete")
        self.assertEqual(proof_ir["environment_profile"]["counts"]["import_thunk_block_semantics_records"], 1)
        self.assertEqual(proof_ir["environment_profile"]["counts"]["import_thunk_semantics_with_original_signature"], 1)
        self.assertEqual(proof_ir["environment_profile"]["counts"]["import_thunk_semantics_with_candidate_signature"], 0)
        self.assertFalse(proof_ir["environment_profile"]["checks"]["import_thunk_semantics_have_signatures"])
        self.assertFalse(proof_ir["environment_profile"]["checks"]["import_thunk_claims_have_signature_hashes"])
        self.assertIn(
            "candidate_import_thunk_semantics_missing_import_signature",
            {gap["category"] for gap in proof_ir["environment_profile"]["gaps"]},
        )
        self.assertIn(
            "candidate_import_thunk_claim_missing_import_signature_hash",
            {gap["category"] for gap in proof_ir["environment_profile"]["gaps"]},
        )
        self.assertFalse(proof_ir["proof_context"]["checks"]["environment_profile_satisfied"])
        self.assertEqual(certificate["status"], "incomplete")
        self.assertFalse(certificate["checks"]["environment_profile_satisfied"])
        self.assertEqual(certificate["counts"]["environment_profile_gaps"], 2)

    def test_proof_ir_context_binding_requires_input_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=root / "missing-original.exe",
                candidate=root / "missing-candidate.exe",
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[],
                failures=[],
                incomplete=[],
                proof_cache=[],
                proof_cache_index={"format": "stage-a-proof-cache-index-v1", "entries": []},
                solver_evidence={
                    "format": "stage-a-solver-evidence-v1",
                    "status": "satisfied",
                    "sha256": "0" * 64,
                    "index_sha256": "1" * 64,
                    "counts": {"entries": 0},
                    "entries": [],
                },
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))
            context = proof_ir["proof_context"]

        self.assertEqual(context["status"], "incomplete")
        self.assertFalse(context["checks"]["model_hash_present"])
        self.assertFalse(context["checks"]["model_hash_matches_model"])
        self.assertFalse(context["checks"]["original_input_exists"])
        self.assertFalse(context["checks"]["candidate_input_exists"])
        self.assertFalse(context["checks"]["input_hashes_present"])

    def test_proof_ir_closure_certificate_requires_proved_block_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:no-evidence",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "byte_identical_x86_pe32_block",
                    }
                ],
                failures=[],
                incomplete=[],
                proof_cache=[],
                proof_cache_index={"format": "stage-a-proof-cache-index-v1", "entries": []},
                solver_evidence={
                    "format": "stage-a-solver-evidence-v1",
                    "status": "satisfied",
                    "sha256": "0" * 64,
                    "index_sha256": "1" * 64,
                    "counts": {"entries": 0},
                    "entries": [],
                },
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))
            certificate = proof_ir["closure_certificate"]

        self.assertEqual(certificate["status"], "incomplete")
        self.assertFalse(certificate["checks"]["proved_block_obligations_have_proof_cache"])
        self.assertFalse(certificate["checks"]["proved_block_obligations_have_solver_evidence"])
        self.assertFalse(certificate["checks"]["proved_block_obligations_have_block_semantics"])
        self.assertEqual(certificate["proof_backing_gaps"][0]["category"], "missing_proof_cache_reference")
        self.assertEqual(certificate["block_semantics_gaps"][0]["category"], "missing_block_semantics_record")

    def test_proof_ir_closure_certificate_requires_block_semantics_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            proof_cache = [
                {
                    "path": "proof-cache/missing.json",
                    "status": "proved",
                    "sha256": "f" * 64,
                }
            ]
            (root / "proof-cache").mkdir()
            (root / "proof-cache" / "index.json").write_text(
                json.dumps({"format": "stage-a-proof-cache-index-v1", "entries": proof_cache}, sort_keys=True),
                encoding="utf-8",
            )
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:missing-semantics",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "byte_identical_x86_pe32_block",
                        "proof_cache": "proof-cache/missing.json",
                    }
                ],
                failures=[],
                incomplete=[],
                proof_cache=proof_cache,
                proof_cache_index={"format": "stage-a-proof-cache-index-v1", "entries": proof_cache},
                solver_evidence={
                    "format": "stage-a-solver-evidence-v1",
                    "status": "satisfied",
                    "sha256": "0" * 64,
                    "index_sha256": "1" * 64,
                    "counts": {"entries": 1},
                    "entries": [
                        {
                            "status": "satisfied",
                            "proof_cache": "proof-cache/missing.json",
                            "obligation_id": "block:missing-semantics",
                        }
                    ],
                },
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))
            certificate = proof_ir["closure_certificate"]

        self.assertEqual(proof_ir["block_semantics"]["status"], "incomplete")
        self.assertEqual(proof_ir["block_semantics"]["records"][0]["semantics_kind"], "missing_proof_cache")
        self.assertEqual(certificate["status"], "incomplete")
        self.assertFalse(certificate["checks"]["block_semantics_satisfied"])
        self.assertFalse(certificate["checks"]["proved_block_obligations_have_block_semantics"])
        self.assertEqual(certificate["block_semantics_gaps"][0]["category"], "missing_block_semantics_record")

    def test_proof_ir_instruction_semantics_rejects_decoded_byte_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            analysis = {
                "status": "ok",
                "machine": "i386",
                "bitness": 32,
                "instructions": [{"rva": 0x1000, "size": 1, "mnemonic": "ret", "op_str": "", "bytes": "c3"}],
            }
            payload = {
                "format": "stage-a-proof-cache-v1",
                "obligation_id": "block:decoded-byte-mismatch",
                "proof_rule": "byte_identical_x86_pe32_block",
                "smt_status": "not_required_for_structural_identity",
                "query": {
                    "kind": "byte_identity_implication",
                    "original_sha256": "0" * 64,
                    "candidate_sha256": hashlib.sha256(bytes.fromhex("c3")).hexdigest(),
                    "equal": True,
                },
                "original_analysis": analysis,
                "candidate_analysis": analysis,
            }
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            proof_cache = [
                {
                    "path": "proof-cache/decoded-byte-mismatch.json",
                    "status": "not_required_for_structural_identity",
                    "sha256": digest,
                }
            ]
            (root / "proof-cache").mkdir()
            (root / "proof-cache" / "decoded-byte-mismatch.json").write_text(
                json.dumps(payload, sort_keys=True),
                encoding="utf-8",
            )
            proof_cache_index = {"format": "stage-a-proof-cache-index-v1", "entries": proof_cache}
            (root / "proof-cache" / "index.json").write_text(json.dumps(proof_cache_index, sort_keys=True), encoding="utf-8")
            solver_evidence = write_solver_evidence_inventory(root, proof_cache)
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )
            loader_side = {
                "sha256": "0" * 64,
                "size": 8,
                "machine": "i386",
                "subsystem": "console",
                "bitness": 32,
                "image_base": 0x400000,
                "entrypoint_rva": 0x1000,
                "size_of_image": 0x2000,
                "sections": [
                    {
                        "name": ".text",
                        "virtual_address": 0x1000,
                        "virtual_size": 0x10,
                        "raw_size": 0x10,
                        "permissions": {"execute": True, "read": True, "write": False},
                    }
                ],
                "executable_sections": [{"name": ".text", "start_rva": 0x1000, "end_rva": 0x1010}],
                "imports": [],
                "relocations": {"status": "empty_directory", "directory": {}, "counts": {"blocks": 0, "entries": 0}},
            }

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={
                    "format": "stage-a-loader-pe32-facts-v1",
                    "loader": "pe32",
                    "original": dict(loader_side),
                    "candidate": dict(loader_side),
                },
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:decoded-byte-mismatch",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "byte_identical_x86_pe32_block",
                        "proof_cache": "proof-cache/decoded-byte-mismatch.json",
                    }
                ],
                failures=[],
                incomplete=[],
                proof_cache=proof_cache,
                proof_cache_index=proof_cache_index,
                solver_evidence=solver_evidence,
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))
            certificate = proof_ir["closure_certificate"]

        self.assertEqual(proof_ir["instruction_semantics"]["status"], "incomplete")
        self.assertEqual(proof_ir["instruction_semantics"]["counts"]["records"], 1)
        self.assertEqual(
            proof_ir["instruction_semantics"]["records"][0]["gaps"][0]["category"],
            "original_decoded_bytes_sha256_mismatch",
        )
        self.assertEqual(proof_ir["instruction_profile"]["status"], "incomplete")
        self.assertEqual(proof_ir["instruction_profile"]["counts"]["instruction_semantics_records"], 1)
        self.assertEqual(proof_ir["instruction_profile"]["counts"]["incomplete_records"], 1)
        self.assertEqual(proof_ir["instruction_profile"]["counts"]["instruction_semantics_gaps"], 1)
        self.assertEqual(proof_ir["instruction_profile"]["counts"]["decoded_byte_hash_mismatches"], 1)
        self.assertFalse(proof_ir["instruction_profile"]["checks"]["instruction_semantics_gaps_closed"])
        self.assertFalse(proof_ir["instruction_profile"]["checks"]["decoded_byte_hash_mismatches_closed"])
        self.assertEqual(certificate["status"], "incomplete")
        self.assertFalse(certificate["checks"]["instruction_semantics_satisfied"])
        self.assertFalse(certificate["checks"]["decoded_block_semantics_have_instruction_semantics"])
        self.assertEqual(certificate["counts"]["instruction_semantics_records"], 1)
        self.assertEqual(certificate["counts"]["instruction_semantics_gaps"], 2)
        self.assertEqual(certificate["instruction_semantics_gaps"][0]["category"], "original_decoded_bytes_sha256_mismatch")
        self.assertEqual(proof_ir["proof_composition"]["status"], "incomplete")
        self.assertEqual(proof_ir["proof_composition"]["counts"]["records"], 1)
        self.assertIn(
            "instruction_semantics",
            {gap["family"] for gap in proof_ir["proof_composition"]["records"][0]["gaps"]},
        )
        self.assertFalse(certificate["checks"]["proof_composition_satisfied"])
        self.assertFalse(certificate["checks"]["proved_block_obligations_have_composition_records"])
        self.assertEqual(certificate["counts"]["proof_composition_records"], 1)
        self.assertGreaterEqual(certificate["counts"]["proof_composition_gaps"], 1)

    def test_proof_ir_closure_certificate_rejects_solver_evidence_obligation_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            payload = {
                "format": "stage-a-proof-cache-v1",
                "obligation_id": "block:real",
                "proof_rule": "byte_identical_x86_pe32_block",
                "smt_status": "not_required_for_structural_identity",
                "query": {
                    "kind": "byte_identity_implication",
                    "original_sha256": "0" * 64,
                    "candidate_sha256": "0" * 64,
                    "equal": True,
                },
                "original_analysis": {"status": "supported", "machine": "i386", "bitness": 32, "instructions": []},
                "candidate_analysis": {"status": "supported", "machine": "i386", "bitness": 32, "instructions": []},
            }
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            proof_cache = [
                {
                    "path": "proof-cache/real.json",
                    "status": "not_required_for_structural_identity",
                    "sha256": digest,
                }
            ]
            (root / "proof-cache").mkdir()
            (root / "proof-cache" / "real.json").write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            (root / "proof-cache" / "index.json").write_text(
                json.dumps({"format": "stage-a-proof-cache-index-v1", "entries": proof_cache}, sort_keys=True),
                encoding="utf-8",
            )
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:real",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "byte_identical_x86_pe32_block",
                        "proof_cache": "proof-cache/real.json",
                    },
                    {
                        "id": "block:other",
                        "kind": "reachability",
                        "status": "proved",
                        "proof_rule": "checked_root_reachability_v1",
                    },
                ],
                failures=[],
                incomplete=[],
                proof_cache=proof_cache,
                proof_cache_index={"format": "stage-a-proof-cache-index-v1", "entries": proof_cache},
                solver_evidence={
                    "format": "stage-a-solver-evidence-v1",
                    "status": "satisfied",
                    "sha256": "0" * 64,
                    "index_sha256": "1" * 64,
                    "counts": {"entries": 1},
                    "entries": [
                        {
                            "id": "evidence:0000:block:other",
                            "status": "satisfied",
                            "evidence_kind": "structural_byte_identity",
                            "proof_cache": "proof-cache/real.json",
                            "obligation_id": "block:other",
                            "proof_rule": "byte_identical_x86_pe32_block",
                            "generic_proof_rule": "byte_identical_x86_pe32_block",
                        }
                    ],
                },
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))
            certificate = proof_ir["closure_certificate"]

        self.assertEqual(certificate["status"], "incomplete")
        self.assertEqual(proof_ir["proof_artifact_bindings"]["status"], "incomplete")
        self.assertEqual(proof_ir["proof_artifact_bindings"]["records"][0]["status"], "incomplete")
        self.assertEqual(
            proof_ir["proof_artifact_bindings"]["records"][0]["gaps"][0]["category"],
            "solver_evidence_obligation_id_mismatch",
        )
        self.assertTrue(certificate["checks"]["solver_evidence_entries_bind_known_obligations"])
        self.assertFalse(certificate["checks"]["proof_artifact_bindings_satisfied"])
        self.assertFalse(certificate["checks"]["proof_artifacts_bind_same_obligations"])
        self.assertEqual(certificate["counts"]["evidence_binding_gaps"], 1)
        self.assertEqual(certificate["evidence_binding_gaps"][0]["category"], "solver_evidence_obligation_id_mismatch")

    def test_proof_ir_closure_certificate_rejects_unknown_semantic_observables(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            payload = {
                "format": "stage-a-unknown-proof-cache-v1",
                "obligation_id": "block:unknown-semantics",
                "proof_rule": "byte_identical_x86_pe32_block",
                "query": {
                    "kind": "unknown_semantics_for_test",
                    "original_sha256": "0" * 64,
                    "candidate_sha256": "0" * 64,
                    "equal": True,
                },
            }
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            proof_cache = [
                {
                    "path": "proof-cache/unknown.json",
                    "status": "proved",
                    "sha256": digest,
                }
            ]
            (root / "proof-cache").mkdir()
            (root / "proof-cache" / "unknown.json").write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            (root / "proof-cache" / "index.json").write_text(
                json.dumps({"format": "stage-a-proof-cache-index-v1", "entries": proof_cache}, sort_keys=True),
                encoding="utf-8",
            )
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:unknown-semantics",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "byte_identical_x86_pe32_block",
                        "proof_cache": "proof-cache/unknown.json",
                    }
                ],
                failures=[],
                incomplete=[],
                proof_cache=proof_cache,
                proof_cache_index={"format": "stage-a-proof-cache-index-v1", "entries": proof_cache},
                solver_evidence={
                    "format": "stage-a-solver-evidence-v1",
                    "status": "satisfied",
                    "sha256": "0" * 64,
                    "index_sha256": "1" * 64,
                    "counts": {"entries": 1},
                    "entries": [
                        {
                            "id": "evidence:0000:block:unknown-semantics",
                            "status": "satisfied",
                            "evidence_kind": "unknown_proof_cache",
                            "proof_cache": "proof-cache/unknown.json",
                            "obligation_id": "block:unknown-semantics",
                            "proof_rule": "byte_identical_x86_pe32_block",
                            "generic_proof_rule": "byte_identical_x86_pe32_block",
                        }
                    ],
                },
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))
            certificate = proof_ir["closure_certificate"]

        self.assertEqual(proof_ir["semantic_observables"]["status"], "incomplete")
        self.assertEqual(proof_ir["semantic_observables"]["records"][0]["claim_kind"], "unknown")
        self.assertEqual(proof_ir["semantic_profile"]["status"], "incomplete")
        self.assertEqual(proof_ir["semantic_profile"]["counts"]["semantic_observables"], 1)
        self.assertEqual(proof_ir["semantic_profile"]["counts"]["unknown_claims"], 1)
        self.assertEqual(proof_ir["semantic_profile"]["counts"]["missing_trusted_boundaries"], 2)
        self.assertFalse(proof_ir["semantic_profile"]["checks"]["claim_kinds_known"])
        self.assertFalse(proof_ir["semantic_profile"]["checks"]["trusted_boundaries_known"])
        self.assertEqual(proof_ir["solver_evidence_profile"]["status"], "incomplete")
        self.assertEqual(proof_ir["solver_evidence_profile"]["counts"]["unknown_proof_cache_entries"], 1)
        self.assertFalse(proof_ir["solver_evidence_profile"]["checks"]["no_unknown_proof_cache_entries"])
        self.assertEqual(
            proof_ir["semantic_observables"]["records"][0]["gaps"][0]["category"],
            "unknown_semantics_kind",
        )
        self.assertEqual(proof_ir["trusted_boundaries"]["status"], "incomplete")
        self.assertFalse(proof_ir["trusted_boundaries"]["records"][0]["allowed"])
        self.assertIn(
            "missing_trusted_boundary",
            {gap["category"] for gap in proof_ir["trusted_boundaries"]["records"][0]["gaps"]},
        )
        self.assertEqual(certificate["status"], "incomplete")
        self.assertFalse(certificate["checks"]["semantic_observables_satisfied"])
        self.assertFalse(certificate["checks"]["proved_block_obligations_have_semantic_observables"])
        self.assertFalse(certificate["checks"]["trusted_boundaries_satisfied"])
        self.assertFalse(certificate["checks"]["semantic_claims_use_allowed_trusted_boundaries"])
        self.assertEqual(certificate["counts"]["semantic_observable_gaps"], 1)
        self.assertEqual(certificate["counts"]["trusted_boundary_gaps"], 2)
        self.assertEqual(certificate["semantic_observable_gaps"][0]["category"], "unknown_semantics_kind")

    def test_proof_ir_solver_claims_inventory_accepts_symbolic_z3_unsat_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            payload = {
                "format": "stage-a-symbolic-proof-cache-v1",
                "obligation_id": "block:symbolic",
                "proof_rule": "smt_z3_local_equivalence_v1",
                "symbolic": {
                    "status": "proved",
                    "solver": "z3",
                    "smt_status": "unsat",
                    "proof_rule": "smt_z3_local_equivalence_v1",
                    "solver_backend": dict(TEST_SOLVER_BACKEND),
                    "smt_query": "(check-sat)",
                    "invariant": {"entry": "true"},
                    "original_observables": {"reg:eax": ["const", 1]},
                    "candidate_observables": {"reg:eax": ["const", 1]},
                },
            }
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            proof_cache = [{"path": "proof-cache/symbolic.json", "status": "proved", "sha256": digest}]
            (root / "proof-cache").mkdir()
            (root / "proof-cache" / "symbolic.json").write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            proof_cache_index = {"format": "stage-a-proof-cache-index-v1", "entries": proof_cache}
            (root / "proof-cache" / "index.json").write_text(json.dumps(proof_cache_index, sort_keys=True), encoding="utf-8")
            solver_evidence = write_solver_evidence_inventory(root, proof_cache)
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )
            loader_side = {
                "sha256": "0" * 64,
                "size": 8,
                "machine": "i386",
                "subsystem": "console",
                "bitness": 32,
                "image_base": 0x400000,
                "entrypoint_rva": 0x1000,
                "size_of_image": 0x2000,
                "sections": [
                    {
                        "name": ".text",
                        "virtual_address": 0x1000,
                        "virtual_size": 0x10,
                        "raw_size": 0x10,
                        "permissions": {"execute": True, "read": True, "write": False},
                    }
                ],
                "executable_sections": [{"name": ".text", "start_rva": 0x1000, "end_rva": 0x1010}],
                "imports": [],
                "relocations": {"status": "empty_directory", "directory": {}, "counts": {"blocks": 0, "entries": 0}},
            }

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={
                    "format": "stage-a-loader-pe32-facts-v1",
                    "loader": "pe32",
                    "original": dict(loader_side),
                    "candidate": dict(loader_side),
                },
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:symbolic",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "smt_z3_local_equivalence_v1",
                        "proof_cache": "proof-cache/symbolic.json",
                    }
                ],
                failures=[],
                incomplete=[],
                proof_cache=proof_cache,
                proof_cache_index=proof_cache_index,
                solver_evidence=solver_evidence,
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))
            certificate = proof_ir["closure_certificate"]

        self.assertEqual(proof_ir["solver_claims"]["status"], "satisfied")
        self.assertEqual(proof_ir["solver_claims"]["counts"]["records"], 1)
        self.assertEqual(proof_ir["semantic_profile"]["status"], "satisfied")
        self.assertEqual(proof_ir["semantic_profile"]["counts"]["symbolic_observable_equivalence"], 1)
        self.assertEqual(proof_ir["semantic_profile"]["counts"]["z3_unsat_local_equivalence_boundaries"], 1)
        self.assertEqual(proof_ir["semantic_profile"]["counts"]["solver_claims"], 1)
        self.assertTrue(proof_ir["semantic_profile"]["checks"]["symbolic_claims_match_solver_claims"])
        self.assertEqual(proof_ir["solver_evidence_profile"]["status"], "satisfied")
        self.assertEqual(proof_ir["solver_evidence_profile"]["counts"]["trusted_z3_unsat_entries"], 1)
        self.assertEqual(proof_ir["solver_evidence_profile"]["counts"]["trusted_z3_unsat_claims"], 1)
        self.assertEqual(proof_ir["solver_evidence_profile"]["counts"]["solver_claims_with_query_hash"], 1)
        self.assertEqual(proof_ir["solver_evidence_profile"]["counts"]["solver_evidence_query_hash_mismatches"], 0)
        self.assertEqual(proof_ir["solver_evidence_profile"]["counts"]["solver_evidence_file_hash_mismatches"], 0)
        self.assertEqual(proof_ir["solver_evidence_profile"]["counts"]["solver_evidence_index_hash_mismatches"], 0)
        self.assertEqual(proof_ir["solver_evidence_profile"]["counts"]["solver_evidence_entry_hash_mismatches"], 0)
        self.assertEqual(proof_ir["solver_evidence_profile"]["counts"]["solver_evidence_index_entry_hash_mismatches"], 0)
        self.assertTrue(proof_ir["solver_evidence_profile"]["checks"]["trusted_z3_evidence_matches_claims"])
        self.assertTrue(proof_ir["solver_evidence_profile"]["checks"]["solver_evidence_file_hashes_match"])
        self.assertTrue(proof_ir["solver_evidence_profile"]["checks"]["solver_evidence_entry_hashes_match"])
        self.assertEqual(proof_ir["solver_backend_profile"]["status"], "satisfied")
        solver_backend_profile_counts = proof_ir["solver_backend_profile"]["counts"]
        self.assertEqual(solver_backend_profile_counts["solver_backed_evidence_entries"], 1)
        self.assertEqual(solver_backend_profile_counts["solver_evidence_with_backend"], 1)
        self.assertEqual(solver_backend_profile_counts["solver_claims_with_backend"], 1)
        self.assertEqual(solver_backend_profile_counts["backend_hash_mismatches"], 0)
        self.assertEqual(solver_backend_profile_counts["backend_gaps"], 0)
        claim = proof_ir["solver_claims"]["records"][0]
        self.assertEqual(claim["status"], "satisfied")
        self.assertEqual(claim["trusted_boundary"], "z3_unsat_local_equivalence_oracle_v1")
        self.assertEqual(claim["solver"], "z3")
        self.assertEqual(claim["smt_status"], "unsat")
        self.assertRegex(claim["smt_query_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(claim["solver_backend"], TEST_SOLVER_BACKEND)
        self.assertRegex(claim["solver_backend_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(claim["semantic_observable_record_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(claim["solver_evidence"]["smt_query_sha256"], claim["smt_query_sha256"])
        self.assertEqual(claim["solver_evidence"]["solver_backend_sha256"], claim["solver_backend_sha256"])
        self.assertEqual(certificate["status"], "satisfied")
        self.assertTrue(certificate["checks"]["solver_claims_satisfied"])
        self.assertTrue(certificate["checks"]["trusted_solver_claims_have_queries"])
        self.assertEqual(certificate["counts"]["solver_claims"], 1)
        self.assertEqual(certificate["counts"]["solver_claim_gaps"], 0)
        self.assertEqual(proof_ir["proof_composition"]["status"], "satisfied")
        self.assertIn(
            "solver_claim",
            {dependency["family"] for dependency in proof_ir["proof_composition"]["records"][0]["dependencies"]},
        )

    def test_proof_ir_solver_backend_profile_rejects_z3_unsat_without_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            payload = {
                "format": "stage-a-symbolic-proof-cache-v1",
                "obligation_id": "block:symbolic-missing-backend",
                "proof_rule": "smt_z3_local_equivalence_v1",
                "symbolic": {
                    "status": "proved",
                    "solver": "z3",
                    "smt_status": "unsat",
                    "proof_rule": "smt_z3_local_equivalence_v1",
                    "smt_query": "(check-sat)",
                    "invariant": {"entry": "true"},
                    "original_observables": {"reg:eax": ["const", 1]},
                    "candidate_observables": {"reg:eax": ["const", 1]},
                },
            }
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            proof_cache = [{"path": "proof-cache/symbolic-missing-backend.json", "status": "proved", "sha256": digest}]
            (root / "proof-cache").mkdir()
            (root / "proof-cache" / "symbolic-missing-backend.json").write_text(
                json.dumps(payload, sort_keys=True),
                encoding="utf-8",
            )
            proof_cache_index = {"format": "stage-a-proof-cache-index-v1", "entries": proof_cache}
            (root / "proof-cache" / "index.json").write_text(json.dumps(proof_cache_index, sort_keys=True), encoding="utf-8")
            solver_evidence = write_solver_evidence_inventory(root, proof_cache)
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:symbolic-missing-backend",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "smt_z3_local_equivalence_v1",
                        "proof_cache": "proof-cache/symbolic-missing-backend.json",
                    }
                ],
                failures=[],
                incomplete=[],
                proof_cache=proof_cache,
                proof_cache_index=proof_cache_index,
                solver_evidence=solver_evidence,
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))
            certificate = proof_ir["closure_certificate"]

        self.assertEqual(proof_ir["solver_claims"]["status"], "incomplete")
        self.assertEqual(proof_ir["solver_claims"]["records"][0]["gaps"][0]["category"], "missing_solver_backend")
        self.assertEqual(proof_ir["solver_backend_profile"]["status"], "incomplete")
        self.assertEqual(proof_ir["solver_backend_profile"]["counts"]["missing_backend_entries"], 1)
        self.assertEqual(proof_ir["solver_backend_profile"]["counts"]["missing_backend_claims"], 1)
        self.assertGreaterEqual(proof_ir["solver_backend_profile"]["counts"]["backend_gaps"], 2)
        self.assertFalse(proof_ir["solver_backend_profile"]["checks"]["solver_backed_evidence_has_backend"])
        self.assertFalse(proof_ir["solver_backend_profile"]["checks"]["solver_claims_have_backend"])
        self.assertFalse(proof_ir["solver_backend_profile"]["checks"]["trusted_z3_uses_z3_backend"])
        self.assertFalse(proof_ir["proof_context"]["checks"]["solver_backend_profile_satisfied"])
        self.assertEqual(certificate["status"], "incomplete")
        self.assertFalse(certificate["checks"]["solver_backend_profile_satisfied"])
        self.assertEqual(
            certificate["counts"]["solver_backend_profile_gaps"],
            proof_ir["solver_backend_profile"]["counts"]["backend_gaps"],
        )

    def test_proof_ir_solver_claims_reject_z3_unsat_without_query_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            payload = {
                "format": "stage-a-symbolic-proof-cache-v1",
                "obligation_id": "block:symbolic-missing-query",
                "proof_rule": "smt_z3_local_equivalence_v1",
                "symbolic": {
                    "status": "proved",
                    "solver": "z3",
                    "smt_status": "unsat",
                    "proof_rule": "smt_z3_local_equivalence_v1",
                    "solver_backend": dict(TEST_SOLVER_BACKEND),
                    "invariant": {"entry": "true"},
                    "original_observables": {"reg:eax": ["const", 1]},
                    "candidate_observables": {"reg:eax": ["const", 1]},
                },
            }
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            proof_cache = [{"path": "proof-cache/symbolic-missing-query.json", "status": "proved", "sha256": digest}]
            (root / "proof-cache").mkdir()
            (root / "proof-cache" / "symbolic-missing-query.json").write_text(
                json.dumps(payload, sort_keys=True),
                encoding="utf-8",
            )
            proof_cache_index = {"format": "stage-a-proof-cache-index-v1", "entries": proof_cache}
            (root / "proof-cache" / "index.json").write_text(json.dumps(proof_cache_index, sort_keys=True), encoding="utf-8")
            solver_evidence = write_solver_evidence_inventory(root, proof_cache)
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:symbolic-missing-query",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "smt_z3_local_equivalence_v1",
                        "proof_cache": "proof-cache/symbolic-missing-query.json",
                    }
                ],
                failures=[],
                incomplete=[],
                proof_cache=proof_cache,
                proof_cache_index=proof_cache_index,
                solver_evidence=solver_evidence,
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))
            certificate = proof_ir["closure_certificate"]

        self.assertEqual(proof_ir["solver_claims"]["status"], "incomplete")
        self.assertEqual(proof_ir["solver_claims"]["counts"]["records"], 1)
        self.assertEqual(proof_ir["solver_claims"]["counts"]["gaps"], 1)
        self.assertEqual(proof_ir["solver_claims"]["records"][0]["gaps"][0]["category"], "missing_smt_query_sha256")
        self.assertEqual(proof_ir["solver_evidence_profile"]["status"], "incomplete")
        self.assertEqual(proof_ir["solver_evidence_profile"]["counts"]["trusted_z3_unsat_entries"], 1)
        self.assertEqual(proof_ir["solver_evidence_profile"]["counts"]["solver_claims_with_query_hash"], 0)
        self.assertEqual(proof_ir["solver_evidence_profile"]["counts"]["solver_evidence_query_hash_gaps"], 1)
        self.assertFalse(proof_ir["solver_evidence_profile"]["checks"]["solver_claims_have_query_hashes"])
        self.assertFalse(proof_ir["solver_evidence_profile"]["checks"]["solver_evidence_query_hashes_present"])
        self.assertEqual(certificate["status"], "incomplete")
        self.assertFalse(certificate["checks"]["solver_claims_satisfied"])
        self.assertFalse(certificate["checks"]["trusted_solver_claims_have_queries"])
        self.assertEqual(certificate["counts"]["solver_claims"], 1)
        self.assertEqual(certificate["counts"]["solver_claim_gaps"], 1)
        self.assertEqual(certificate["solver_claim_gaps"][0]["category"], "missing_smt_query_sha256")

    def test_proof_ir_solver_claims_reject_solver_evidence_query_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            payload = {
                "format": "stage-a-symbolic-proof-cache-v1",
                "obligation_id": "block:symbolic-tampered-evidence",
                "proof_rule": "smt_z3_local_equivalence_v1",
                "symbolic": {
                    "status": "proved",
                    "solver": "z3",
                    "smt_status": "unsat",
                    "proof_rule": "smt_z3_local_equivalence_v1",
                    "solver_backend": dict(TEST_SOLVER_BACKEND),
                    "smt_query": "(check-sat)",
                    "invariant": {"entry": "true"},
                    "original_observables": {"reg:eax": ["const", 1]},
                    "candidate_observables": {"reg:eax": ["const", 1]},
                },
            }
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            proof_cache = [{"path": "proof-cache/symbolic-tampered-evidence.json", "status": "proved", "sha256": digest}]
            (root / "proof-cache").mkdir()
            (root / "proof-cache" / "symbolic-tampered-evidence.json").write_text(
                json.dumps(payload, sort_keys=True),
                encoding="utf-8",
            )
            proof_cache_index = {"format": "stage-a-proof-cache-index-v1", "entries": proof_cache}
            (root / "proof-cache" / "index.json").write_text(json.dumps(proof_cache_index, sort_keys=True), encoding="utf-8")
            solver_evidence = write_solver_evidence_inventory(root, proof_cache)
            solver_evidence["entries"][0]["smt_query_sha256"] = "f" * 64
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:symbolic-tampered-evidence",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "smt_z3_local_equivalence_v1",
                        "proof_cache": "proof-cache/symbolic-tampered-evidence.json",
                    }
                ],
                failures=[],
                incomplete=[],
                proof_cache=proof_cache,
                proof_cache_index=proof_cache_index,
                solver_evidence=solver_evidence,
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))
            certificate = proof_ir["closure_certificate"]

        self.assertEqual(proof_ir["solver_claims"]["status"], "incomplete")
        self.assertEqual(
            proof_ir["solver_claims"]["records"][0]["gaps"][0]["category"],
            "solver_evidence_smt_query_sha256_mismatch",
        )
        self.assertEqual(proof_ir["solver_evidence_profile"]["status"], "incomplete")
        self.assertEqual(proof_ir["solver_evidence_profile"]["counts"]["solver_claim_gaps"], 1)
        self.assertEqual(proof_ir["solver_evidence_profile"]["counts"]["solver_evidence_query_hash_mismatches"], 1)
        self.assertFalse(proof_ir["solver_evidence_profile"]["checks"]["solver_evidence_query_hashes_match"])
        self.assertFalse(proof_ir["solver_evidence_profile"]["checks"]["solver_claim_gaps_closed"])
        self.assertFalse(certificate["checks"]["trusted_solver_claims_have_queries"])

    def test_proof_ir_solver_evidence_profile_rejects_tampered_solver_evidence_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            payload = {
                "format": "stage-a-symbolic-proof-cache-v1",
                "obligation_id": "block:symbolic-stale-evidence-hash",
                "proof_rule": "smt_z3_local_equivalence_v1",
                "symbolic": {
                    "status": "proved",
                    "solver": "z3",
                    "smt_status": "unsat",
                    "proof_rule": "smt_z3_local_equivalence_v1",
                    "solver_backend": dict(TEST_SOLVER_BACKEND),
                    "smt_query": "(check-sat)",
                    "invariant": {"entry": "true"},
                    "original_observables": {"reg:eax": ["const", 1]},
                    "candidate_observables": {"reg:eax": ["const", 1]},
                },
            }
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            proof_cache = [{"path": "proof-cache/symbolic-stale-evidence-hash.json", "status": "proved", "sha256": digest}]
            (root / "proof-cache").mkdir()
            (root / "proof-cache" / "symbolic-stale-evidence-hash.json").write_text(
                json.dumps(payload, sort_keys=True),
                encoding="utf-8",
            )
            proof_cache_index = {"format": "stage-a-proof-cache-index-v1", "entries": proof_cache}
            (root / "proof-cache" / "index.json").write_text(json.dumps(proof_cache_index, sort_keys=True), encoding="utf-8")
            solver_evidence = write_solver_evidence_inventory(root, proof_cache)
            solver_evidence["sha256"] = "f" * 64
            solver_evidence["index_sha256"] = "e" * 64
            solver_evidence["entries"][0]["entry_sha256"] = "d" * 64
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:symbolic-stale-evidence-hash",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "smt_z3_local_equivalence_v1",
                        "proof_cache": "proof-cache/symbolic-stale-evidence-hash.json",
                    }
                ],
                failures=[],
                incomplete=[],
                proof_cache=proof_cache,
                proof_cache_index=proof_cache_index,
                solver_evidence=solver_evidence,
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))

        profile = proof_ir["solver_evidence_profile"]
        self.assertEqual(profile["status"], "incomplete")
        self.assertEqual(profile["counts"]["solver_evidence_file_hash_mismatches"], 1)
        self.assertEqual(profile["counts"]["solver_evidence_index_hash_mismatches"], 1)
        self.assertEqual(profile["counts"]["solver_evidence_entry_hash_mismatches"], 0)
        self.assertEqual(profile["counts"]["solver_evidence_index_entry_hash_mismatches"], 1)
        self.assertFalse(profile["checks"]["solver_evidence_file_hashes_match"])
        self.assertFalse(profile["checks"]["solver_evidence_entry_hashes_match"])

    def test_proof_ir_proof_cache_profile_rejects_tampered_proof_cache_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")
            payload = {
                "format": "stage-a-symbolic-proof-cache-v1",
                "obligation_id": "block:symbolic-stale-proof-cache-hash",
                "proof_rule": "smt_z3_local_equivalence_v1",
                "symbolic": {
                    "status": "proved",
                    "solver": "z3",
                    "smt_status": "unsat",
                    "proof_rule": "smt_z3_local_equivalence_v1",
                    "solver_backend": dict(TEST_SOLVER_BACKEND),
                    "smt_query": "(check-sat)",
                    "invariant": {"entry": "true"},
                    "original_observables": {"reg:eax": ["const", 1]},
                    "candidate_observables": {"reg:eax": ["const", 1]},
                },
            }
            proof_cache = [
                {
                    "path": "proof-cache/symbolic-stale-proof-cache-hash.json",
                    "status": "proved",
                    "sha256": "f" * 64,
                }
            ]
            (root / "proof-cache").mkdir()
            (root / "proof-cache" / "symbolic-stale-proof-cache-hash.json").write_text(
                json.dumps(payload, sort_keys=True),
                encoding="utf-8",
            )
            proof_cache_index = {"format": "stage-a-proof-cache-index-v1", "entries": proof_cache}
            (root / "proof-cache" / "index.json").write_text(json.dumps(proof_cache_index, sort_keys=True), encoding="utf-8")
            solver_evidence = write_solver_evidence_inventory(root, proof_cache)
            model = stage_a_model_description(
                STAGE_A_MODEL_ID,
                model_specs=STAGE_A_MODEL_SPECS,
                default_model=STAGE_A_MODEL_ID,
            )

            write_proof_ir(
                out=root,
                original=original,
                candidate=candidate,
                model_description=model,
                model_hash="model-hash",
                loader_facts={"format": "stage-a-loader-pe32-facts-v1"},
                layout={"compatible": True, "issues": []},
                obligations=[
                    {
                        "id": "block:symbolic-stale-proof-cache-hash",
                        "kind": "block_equivalence",
                        "status": "proved",
                        "proof_rule": "smt_z3_local_equivalence_v1",
                        "proof_cache": "proof-cache/symbolic-stale-proof-cache-hash.json",
                    }
                ],
                failures=[],
                incomplete=[],
                proof_cache=proof_cache,
                proof_cache_index=proof_cache_index,
                solver_evidence=solver_evidence,
                mapping_payload={},
                invariant_payload={},
            )

            proof_ir = json.loads((root / "proof-ir.json").read_text(encoding="utf-8"))

        profile = proof_ir["proof_cache_profile"]
        self.assertEqual(profile["status"], "incomplete")
        self.assertEqual(profile["counts"]["proof_cache_payload_hash_mismatches"], 1)
        self.assertEqual(profile["counts"]["proof_cache_gaps"], 1)
        self.assertFalse(profile["checks"]["proof_cache_payload_hashes_match"])
        self.assertFalse(profile["checks"]["proof_cache_gaps_closed"])
        self.assertFalse(proof_ir["proof_context"]["checks"]["proof_cache_profile_satisfied"])
        self.assertFalse(proof_ir["closure_certificate"]["checks"]["proof_cache_profile_satisfied"])
        self.assertEqual(proof_ir["closure_certificate"]["counts"]["proof_cache_profile_gaps"], 1)

    def test_stage_a_diff_obligations_reports_resolved_contract_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            before = root / "before" / "reference-contract.json"
            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                layout_contract=layout_contract,
                out=before,
            )
            with self._mock_lean_checked():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=block_map,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                    layout_contract=layout_contract,
                )
            after = root / "after" / "reference-contract.json"
            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "report",
                layout_contract=layout_contract,
                out=after,
            )

            diff = stage_a_diff_obligations(before=before, after=after)
            self.assertEqual(diff["status"], "pass")
            self.assertGreater(diff["counts"]["resolved"], 0)
            self.assertEqual(diff["counts"]["new"], 0)
            self.assertIn(
                "validation_report_artifact_binding",
                {gap["family"] for gap in diff["resolved"]},
            )

    def test_stage_a_generate_map_rejects_import_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            call_import = b"\xff\x15\x40\x20\x40\x00\xc3"
            original = self._write_import_pe(root / "original.exe", call_import, "GetTickCount")
            candidate = self._write_import_pe(root / "candidate.exe", call_import, "ExitProcess")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "jq-block-map.json",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("layout_mismatch", {issue["category"] for issue in result["issues"]})

    def test_checked_generated_jq_mapping_rule_cannot_close_unsupported_formal_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x0f\x0b\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x0f\x0b\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "format": "stage-a-block-map-v1",
                        "generator": "stage-a-generate-map",
                        "status": "pass",
                        "blocks": [
                            {
                                "id": "jq-function",
                                "kind": "code",
                                "reachable": True,
                                "root": {"kind": "linker_map_function", "checked": True, "symbol": "tiny"},
                                "original": {"rva": 0x1000, "size": 3},
                                "candidate": {"rva": 0x1000, "size": 3},
                                "source": {"kind": "linker_map_capstone_block_match_v1", "function": "tiny"},
                                "proof": {
                                    "rule": "reproducible_jq_same_source_optimization_pair_v1",
                                    "checked": True,
                                    "function": "tiny",
                                    "original_flags": "-O2",
                                    "candidate_flags": "-O2 -falign-functions=32",
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=out,
                )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(result["proof"]["assurance"], "incomplete")
            formal_attempt = result["proof"]["lean"]["failed_formal_pass_attempt"]["formal_proof"]
            self.assertEqual(formal_attempt["diagnostics"]["status"], "incomplete")
            self.assertIn("0f0b", {item.get("bytes") for item in formal_attempt["diagnostics"]["issues"]})
            obligation = self._obligation(out, "block:jq-function")
            self.assertEqual(obligation["proof_rule"], "same_source_layout_preserving_build_v1")
            self.assertEqual(obligation["proof"]["deprecated_rule_alias"], "reproducible_jq_same_source_optimization_pair_v1")
            proof_ir = json.loads((out / "proof-ir.json").read_text(encoding="utf-8"))
            block_ir = next(item for item in proof_ir["obligations"]["items"] if item["id"] == "block:jq-function")
            self.assertEqual(block_ir["generic_proof_rule"], "same_source_layout_preserving_build_v1")
            self.assertEqual(proof_ir["proof_rule_profile"]["status"], "satisfied")
            self.assertEqual(proof_ir["proof_rule_profile"]["counts"]["deprecated_alias_uses"], 0)
            self.assertEqual(proof_ir["proof_rule_profile"]["counts"]["unnormalized_deprecated_alias_uses"], 0)
            self.assertEqual(proof_ir["proof_rule_profile"]["counts"]["unknown_obligation_rules"], 0)
            self.assertTrue(proof_ir["proof_rule_profile"]["checks"]["deprecated_aliases_normalized"])
            evidence = json.loads((out / "solver-evidence.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(evidence["proof_rule"], "same_source_layout_preserving_build_v1")
            self.assertEqual(evidence["generic_proof_rule"], "same_source_layout_preserving_build_v1")
            proof_cache = json.loads((out / evidence["proof_cache"]).read_text(encoding="utf-8"))
            self.assertEqual(
                proof_cache["query"]["proof"]["deprecated_rule_alias"],
                "reproducible_jq_same_source_optimization_pair_v1",
            )

    def test_recovered_cfg_block_root_marker_does_not_prove_reachability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            orphan = self._mapping_entry(rva=0x1001, size=1, block_id="orphan")
            orphan["root"] = {"kind": "recovered_cfg_block", "checked": True}
            mapping = root / "block-map.json"
            mapping.write_text(json.dumps({"blocks": [self._mapping_entry(size=1, block_id="entry"), orphan]}), encoding="utf-8")

            with self._mock_lean_checked():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_MODEL_ID,
                    out=root / "report",
                )

            self.assertEqual(result["verdict"], "incomplete")
            reachability = self._obligation(root / "report", "reachability:orphan")
            self.assertEqual(reachability["status"], "incomplete")
            self.assertEqual(reachability["incomplete"]["category"], "unproved_reachability")

    def test_generated_map_issues_block_final_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "format": "stage-a-block-map-v1",
                        "generator": "stage-a-generate-map",
                        "status": "incomplete",
                        "issues": [{"category": "layout_mismatch", "blocker": "test"}],
                        "blocks": [
                            {
                                "id": "entry",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1000, "size": 0x200},
                                "candidate": {"rva": 0x1000, "size": 0x200},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = root / "report"

            result = stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=mapping,
                model=STAGE_A_MODEL_ID,
                out=out,
            )

            self.assertEqual(result["verdict"], "incomplete")
            blocker = json.loads((out / "incomplete" / "mapping-generated-map.json").read_text(encoding="utf-8"))
            self.assertEqual(blocker["category"], "generated_map_incomplete")

    def _validated_identity_report(
        self,
        root: Path,
        *,
        lean_inputs: tuple[Path, ...] = (),
    ) -> tuple[Path, Path, Path, Path, Path]:
        original = self._write_pe(root / "original.exe", b"\xc3")
        candidate = self._write_pe(root / "candidate.exe", b"\xc3")
        original_map = root / "original.map"
        candidate_map = root / "candidate.map"
        original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
        candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
        block_map = root / "block-map.json"
        layout_contract = root / "layout-contract.json"
        stage_a_generate_map(
            original=original,
            candidate=candidate,
            linker_map_original=original_map,
            linker_map_candidate=candidate_map,
            out=block_map,
            layout_contract_out=layout_contract,
        )
        report = root / "report"
        with self._mock_lean_checked():
            stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=block_map,
                model=STAGE_A_MODEL_ID,
                out=report,
                layout_contract=layout_contract,
                lean_inputs=lean_inputs,
            )
        return original, candidate, block_map, layout_contract, report

    def _mock_lean_checked(self):
        return _LeanCheckedMock()

    def _write_mapping(self, path: Path, *, rva: int = 0x1000, size: int, block_id: str = "entry") -> Path:
        path.write_text(json.dumps({"blocks": [self._mapping_entry(rva=rva, size=size, block_id=block_id)]}), encoding="utf-8")
        return path

    def _obligation(self, out: Path, obligation_id: str) -> dict:
        obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"]
        for obligation in obligations:
            if obligation["id"] == obligation_id:
                return obligation
        self.fail(f"missing obligation {obligation_id}")

    def _mapping_entry(self, *, rva: int = 0x1000, size: int, block_id: str = "entry") -> dict:
        return {
            "id": block_id,
            "kind": "code",
            "reachable": rva == 0x1000,
            "original": {"rva": rva, "size": size},
            "candidate": {"rva": rva, "size": size},
        }

    def _write_pe(self, path: Path, code: bytes, *, virtual_size: int | None = None) -> Path:
        path.write_bytes(_pe32_image(code, virtual_size=virtual_size))
        return path

    def _write_pe_with_coff_symbol(self, path: Path, code: bytes, symbol: str) -> Path:
        image = bytearray(_pe32_image(code))
        pointer_to_symbol_table = len(image)
        name = symbol.encode("ascii")
        if len(name) > 8:
            raise AssertionError("test COFF symbol helper only supports short names")
        symbol_entry = name.ljust(8, b"\0") + struct.pack("<IhHBB", 0, 1, 0x20, 3, 0)
        image.extend(symbol_entry)
        image.extend(struct.pack("<I", 4))
        struct.pack_into("<I", image, 0x8C, pointer_to_symbol_table)
        struct.pack_into("<I", image, 0x90, 1)
        path.write_bytes(bytes(image))
        return path

    def _write_reference_contract(self, path: Path, binary: stage_a.StageABinary, *, functions: list[str]) -> Path:
        layout = stage_a._binary_reference_layout(binary)
        function_rows = [
            {
                "name": name,
                "rva_start": 0x1000 + index,
                "rva_end": 0x1000 + index + 1,
                "section": ".text",
                "bytes_sha256": "",
            }
            for index, name in enumerate(functions)
        ]
        abi_functions = [
            {
                "name": name,
                "blocks": [
                    {
                        "block_id": f"block-{index}",
                        "rva_start": 0x1000 + index,
                        "rva_end": 0x1000 + index + 1,
                        "size": 1,
                    }
                ],
                "callsites": [],
            }
            for index, name in enumerate(functions)
        ]
        sidecars = {
            "coverage_gaps": {"path": "coverage_gaps.json"},
            "obligation_index": {"path": "obligation_index.json"},
            "contract_summary": {"path": "contract_summary.json"},
            "abi_callsites": {"path": "abi_callsites.json"},
        }
        payload = {
            "format": "stage-a-reference-contract-v1",
            "model": STAGE_A_MODEL_ID,
            "status": "pass",
            "original": layout,
            "constraints": {
                "function_ranges": {"status": "satisfied", "functions": function_rows},
                "abi_callsites": {
                    "status": "satisfied",
                    "original": {"functions": abi_functions, "import_prototypes": []},
                    "counts": {"functions": len(functions), "callsites": 0, "import_prototypes": 0},
                },
            },
            "families": [
                {"family": "binary_faithfulness", "status": "satisfied"},
                {"family": "function_ranges", "status": "satisfied"},
                {"family": "abi_callsites", "status": "satisfied"},
                {"family": "import_thunks", "status": "satisfied"},
                {"family": "proof_inventory", "status": "satisfied"},
            ],
            "inputs": {},
            "sidecars": sidecars,
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        contract_ref = {"path": str(path), "sha256": stage_a.sha256_file(path), "exists": True}
        for sidecar in sidecars.values():
            sidecar_path = path.parent / str(sidecar["path"])
            sidecar_path.write_text(json.dumps({"reference_contract": contract_ref}), encoding="utf-8")
        return path

    def _write_skeleton_manifest(self, path: Path, functions: list[dict]) -> Path:
        payload = {
            "format": "stage-b-skeleton-v1",
            "source_map": {
                "format": "stage-b-source-map-v1",
                "functions": functions,
            },
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _write_import_pe(self, path: Path, code: bytes, symbol: str, *, dll: str = "KERNEL32.dll", iat_offset: int = 0x40) -> Path:
        path.write_bytes(_pe32_import_image(code, symbol=symbol, dll=dll, iat_offset=iat_offset))
        return path


def _pe32_image(code: bytes, *, virtual_size: int | None = None) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    text_raw = 0x200
    text_raw_size = _align(len(code), file_alignment)
    text_virtual_size = virtual_size if virtual_size is not None else len(code)
    size_of_image = _align(text_rva + text_virtual_size, section_alignment)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,
        1,
        0,
        0,
        0,
        224,
        0x010F,
    )
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B,
        0,
        0,
        text_raw_size,
        0,
        0,
        text_rva,
        text_rva,
        0,
        0x400000,
        section_alignment,
        file_alignment,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        size_of_image,
        headers_size,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional = optional_prefix + (b"\0" * (16 * 8))
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        text_virtual_size,
        text_rva,
        text_raw_size,
        text_raw,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    headers = bytes(dos) + b"PE\0\0" + coff + optional + section
    headers = headers.ljust(headers_size, b"\0")
    return headers + code.ljust(text_raw_size, b"\0")


def _pe32_import_image(code: bytes, *, symbol: str, dll: str = "KERNEL32.dll", iat_offset: int = 0x40) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    image_base = 0x400000
    text_rva = 0x1000
    idata_rva = 0x2000
    text_raw = 0x200
    text_raw_size = _align(len(code), file_alignment)
    idata_raw = text_raw + text_raw_size
    idata_raw_size = 0x200
    size_of_image = _align(idata_rva + idata_raw_size, section_alignment)

    int_rva = idata_rva + 0x30
    iat_rva = idata_rva + iat_offset
    dll_name_rva = idata_rva + 0x50
    import_name_rva = idata_rva + 0x80
    idata = bytearray(idata_raw_size)
    struct.pack_into("<IIIII", idata, 0x00, int_rva, 0, 0, dll_name_rva, iat_rva)
    struct.pack_into("<II", idata, 0x30, import_name_rva, 0)
    struct.pack_into("<II", idata, iat_offset, import_name_rva, 0)
    idata[0x50 : 0x50 + len(dll) + 1] = dll.encode("ascii") + b"\0"
    name = symbol.encode("ascii")
    struct.pack_into("<H", idata, 0x80, 0)
    idata[0x82 : 0x82 + len(name) + 1] = name + b"\0"

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,
        2,
        0,
        0,
        0,
        224,
        0x010F,
    )
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B,
        0,
        0,
        text_raw_size,
        idata_raw_size,
        0,
        text_rva,
        text_rva,
        idata_rva,
        image_base,
        section_alignment,
        file_alignment,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        size_of_image,
        headers_size,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional = bytearray(optional_prefix + (b"\0" * (16 * 8)))
    struct.pack_into("<II", optional, len(optional_prefix) + 8, idata_rva, 40)
    text_section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        len(code),
        text_rva,
        text_raw_size,
        text_raw,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    idata_section = struct.pack(
        "<8sIIIIIIHHI",
        b".idata\0\0",
        idata_raw_size,
        idata_rva,
        idata_raw_size,
        idata_raw,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    headers = bytes(dos) + b"PE\0\0" + coff + bytes(optional) + text_section + idata_section
    headers = headers.ljust(headers_size, b"\0")
    return headers + code.ljust(text_raw_size, b"\0") + bytes(idata)


class _LeanCheckedMock:
    def __enter__(self):
        self._which = mock.patch("wincr.stage_a.shutil.which", return_value="/nix/store/lean/bin/lean")
        self._check = mock.patch(
            "wincr.stage_a._run_lean_check",
            return_value={
                "status": "checked",
                "command": ["/nix/store/lean/bin/lean", "StageA/Obligations.lean"],
                "returncode": 0,
                "stdout": "'StageA.Generated.candidateRefinesOriginal' depends on axioms: [propext, Quot.sound]\n",
                "stderr": "",
            },
        )
        self._which.start()
        self._check.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._check.stop()
        self._which.stop()
        return False


def _align(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment
