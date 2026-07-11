import json
import os
import shutil
import struct
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event, Timer
from unittest.mock import patch

from wincr.stage_a_relational import (
    RELATIONAL_ENVIRONMENT_ID,
    RELATIONAL_OBSERVATIONS,
    _normalize_contract,
    _normalized_behavior_fast_path,
    _partition_proof_shards,
    _run_lean_relational,
    _validate_prepared_relational,
    stage_a_build_relational,
    stage_a_check_relational_proof,
    stage_a_generate_relation_contract,
    stage_a_prepare_relational,
    stage_a_prove_relational,
)
from wincr.stage_binary import StageAInputError, _parse_stage_a_pe


class StageARelationalTests(unittest.TestCase):
    def test_normalized_fast_path_accepts_only_mapped_control_flow_differences(self):
        pairs = [
            {"original": register, "candidate": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        ]
        region = {
            "inputs": pairs,
            "outputs": pairs,
            "bounds": [],
            "values": [],
            "code_targets": [
                {"id": 1, "original_rva": 0x1000, "candidate_rva": 0x2000},
                {"id": 2, "original_rva": 0x1010, "candidate_rva": 0x2020},
            ],
        }
        core = "{ registers := shared"
        behaviors = {
            "original": core + ", outcome := some (StageA.Formal.OutcomeExpr.branch condition 4096 4112) }",
            "candidate": core + ", outcome := some (StageA.Formal.OutcomeExpr.branch condition 8192 8224) }",
        }
        self.assertTrue(_normalized_behavior_fast_path(region, behaviors))

        behaviors["candidate"] = core + ", outcome := some (StageA.Formal.OutcomeExpr.branch condition 8192 8225) }"
        self.assertFalse(_normalized_behavior_fast_path(region, behaviors))

    def test_proof_shards_are_bounded_by_region_count_and_estimated_source_size(self):
        self.assertEqual(
            _partition_proof_shards(
                [100, 100, 450, 100, 100, 100],
                max_regions=3,
                target_bytes=500,
            ),
            [[0, 1], [2], [3, 4, 5]],
        )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for sharded relational proofs")
    def test_sharded_local_proof_does_not_import_raw_pe_attestations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            contract = self._write_contract(root / "relation.json")
            report = root / "report"

            with patch.dict(os.environ, {"WINCR_STAGE_A_RELATIONAL_SHARD_THRESHOLD": "1"}):
                result = stage_a_prove_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=report,
                )

            self.assertEqual(result["verdict"], "pass", result)
            self.assertEqual(result["proof"]["lean"]["status"], "checked")
            shard = (report / "lean" / "StageA" / "RelationalProofShard0.lean").read_text(
                encoding="utf-8"
            )
            definitions = (
                report / "lean" / "StageA" / "RelationalDefinitionsShard0.lean"
            ).read_text(encoding="utf-8")
            bundle = (report / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            original_decode = (
                report / "lean" / "StageA" / "RelationalProofOriginalDecodeChunk0.lean"
            ).read_text(encoding="utf-8")
            candidate_decode = (
                report / "lean" / "StageA" / "RelationalProofCandidateDecodeChunk0.lean"
            ).read_text(encoding="utf-8")
            direct = (
                report / "lean" / "StageA" / "RelationalProofDirectChunk0.lean"
            ).read_text(encoding="utf-8")
            closure = (
                report / "lean" / "StageA" / "RelationalProofClosureBase.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("import StageA.RelationalDefinitionsShard0\n", shard)
            self.assertIn("import StageA.Relational\n", definitions)
            self.assertNotIn("RelationalProofBase", shard)
            self.assertNotIn("originalPe", shard)
            self.assertNotIn("originalPe", definitions)
            self.assertIn("import StageA.RelationalProofOriginal", original_decode)
            self.assertIn("originalBehavior0CheckedDecoded", original_decode)
            self.assertNotIn("candidatePe", original_decode)
            self.assertIn("import StageA.RelationalProofCandidate", candidate_decode)
            self.assertIn("candidateBehavior0CheckedDecoded", candidate_decode)
            self.assertNotIn("originalPe", candidate_decode)
            self.assertIn("regionEquivalentWithImports_of_decoded", direct)
            self.assertIn("region0CheckedDirect", direct)
            self.assertIn("directRegionChunk0Checked", direct)
            self.assertIn("structuralChecked", closure)
            self.assertIn("allDirectRegionsChecked", bundle)
            self.assertIn("allRegionsChecked", bundle)
            self.assertFalse(
                (report / "lean" / "StageA" / "RelationalProofGoalChunk0.lean").exists()
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for relational preparation")
    def test_prepare_emits_valid_source_only_derivation_graph_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            contract = self._write_contract(root / "relation.json")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["status"], "prepared")
            self.assertEqual(list(prepared.rglob("*.olean")), [])
            graph = _validate_prepared_relational(prepared)
            self.assertEqual(graph["lean"]["trust"], 0)
            self.assertEqual(graph["root_module"], "RelationalBundle")
            self.assertGreater(graph["counts"]["derivations"], 1)
            self.assertTrue(any(node["id"].startswith("definitions-pack-") for node in graph["nodes"]))
            proof_pack = next(node for node in graph["nodes"] if node["id"].startswith("local-proof-pack-"))
            self.assertEqual(proof_pack["resource_class"], "medium")

            second = root / "prepared-second"
            stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=second,
            )
            self.assertEqual(
                (prepared / "module-graph.json").read_bytes(),
                (second / "module-graph.json").read_bytes(),
            )
            self.assertEqual(
                (prepared / "prepared-proof.json").read_bytes(),
                (second / "prepared-proof.json").read_bytes(),
            )

            source = prepared / "lean" / "StageA" / "RelationalBundle.lean"
            source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "source hash does not match"):
                _validate_prepared_relational(prepared)

    @unittest.skipUnless(
        shutil.which("lean") and shutil.which("nix") and os.environ.get("WINCR_RUN_NIX_INTEGRATION") == "1",
        "set WINCR_RUN_NIX_INTEGRATION=1 to run the Nix derivation graph",
    )
    def test_nix_executor_builds_and_trust_zero_audits_prepared_graph(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            contract = self._write_contract(root / "relation.json")
            prepared = root / "prepared"
            stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            result = stage_a_build_relational(
                prepared=prepared,
                out=root / "report",
                flake=Path(__file__).parents[1],
            )

            self.assertEqual(result["status"], "pass", result)
            self.assertTrue(result["checks"]["lean_trust_zero"])
            self.assertEqual(result["lean_audit"]["unexpected_axioms"], [])
            self.assertGreater(result["provenance"]["node_derivations"], 1)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for process cancellation")
    def test_relational_lean_process_is_terminated_on_cancellation(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = Path(__file__).parents[1] / "src" / "wincr" / "lean" / "StageA"
            for name in ("Formal.lean", "Relational.lean"):
                shutil.copyfile(source_root / name, stage_a / name)
            (stage_a / "Slow.lean").write_text(
                "import StageA.Relational\n\n#eval IO.sleep 10000\n",
                encoding="utf-8",
            )
            cancellation = Event()
            timer = Timer(0.2, cancellation.set)
            started = time.monotonic()
            timer.start()
            try:
                result = _run_lean_relational(
                    lean_dir,
                    bundle="Slow",
                    cancel_event=cancellation,
                )
            finally:
                timer.cancel()

            self.assertEqual(result["status"], "cancelled", result)
            self.assertLess(time.monotonic() - started, 3)

    def test_relation_contract_generator_projects_complete_block_map(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "entry-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 4},
                "candidate": {"rva": 0x1000, "size": 4},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            result = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                out=contract,
            )

            self.assertEqual(result["status"], "generated")
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertTrue(payload["regions"][0]["root"])
            self.assertEqual(payload["environment"]["id"], RELATIONAL_ENVIRONMENT_ID)
            self.assertEqual(payload["memory_relation"]["mode"], "identity")

            original_bin = _parse_stage_a_pe(original)
            candidate_bin = _parse_stage_a_pe(candidate)
            renormalized, issues = _normalize_contract(payload, original_bin, candidate_bin)
            self.assertEqual(issues, [])
            self.assertEqual(
                [region["target_ids"] for region in renormalized["regions"]],
                [region["target_ids"] for region in payload["regions"]],
            )
            self.assertEqual(
                [region["code_targets"] for region in renormalized["regions"]],
                [region["code_targets"] for region in payload["regions"]],
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for string-copy relational proofs")
    def test_relation_generator_splits_and_checks_symbolic_rep_movsd(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("b904000000f3a5ebf7")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "copy-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": len(code)},
                "candidate": {"rva": 0x1000, "size": len(code)},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                out=contract,
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(generated["status"], "generated")
            self.assertEqual(len(payload["regions"]), 2)
            self.assertEqual(
                (payload["regions"][0]["original"]["rva_start"], payload["regions"][0]["original"]["size"]),
                (0x1000, 7),
            )
            self.assertEqual(
                (payload["regions"][1]["original"]["rva_start"], payload["regions"][1]["original"]["size"]),
                (0x1007, 2),
            )

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")

    def test_contract_rejects_executable_coverage_gap_before_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            contract = self._write_contract(root / "relation.json", region_size=2)

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertIn("executable_coverage_gap", {issue["category"] for issue in result["issues"]})

    def test_contract_rejects_unresolved_logical_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            contract = self._write_contract(root / "relation.json", target_rva=0x1002)

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertIn("unresolved_code_target", {issue["category"] for issue in result["issues"]})

    def test_contract_requires_explicit_adversarial_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            contract = self._write_contract(root / "relation.json")
            payload = json.loads(contract.read_text(encoding="utf-8"))
            del payload["environment"]
            contract.write_text(json.dumps(payload), encoding="utf-8")

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertIn("environment_contract_missing", {issue["category"] for issue in result["issues"]})

    def test_unsupported_instruction_emits_actionable_semantic_gap_before_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("0f57c0ebfb")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(root / "relation.json", region_size=5)
            report = root / "report"

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=report,
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(result["diagnostic"]["category"], "semantic_preflight_incomplete")
            gaps = json.loads((report / "semantic-gaps.json").read_text(encoding="utf-8"))
            self.assertEqual(gaps["issues"][0]["category"], "formal_instruction_unsupported")
            self.assertIn("Lean decoder", gaps["issues"][0]["next_action"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for exact-byte relational replay")
    def test_exact_byte_region_proof_passes_and_tampering_fails_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", bytes.fromhex("8b03894304ebf9"))
            candidate = self._write_pe(root / "candidate.exe", bytes.fromhex("8b4300894304ebf8"))
            contract = self._write_contract(root / "relation.json", region_size=7, candidate_region_size=8)
            report = root / "report"

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=report,
            )

            self.assertEqual(result["verdict"], "pass")
            self.assertFalse(result["claim_scope"]["acceptance_eligible"])
            replay = stage_a_check_relational_proof(report=report)
            self.assertEqual(replay["status"], "pass")
            proof_ir = json.loads((report / "relational-proof-ir.json").read_text(encoding="utf-8"))
            self.assertEqual(proof_ir["obligations"][0]["status"], "proved")
            self.assertEqual(proof_ir["obligations"][0]["evidence"]["kind"], "lean_normalization")

            normalized = json.loads((report / "relation-contract.json").read_text(encoding="utf-8"))
            normalized["regions"][0]["outputs"] = normalized["regions"][0]["outputs"][:-1]
            (report / "relation-contract.json").write_text(json.dumps(normalized), encoding="utf-8")
            tampered = stage_a_check_relational_proof(report=report)
            self.assertEqual(tampered["status"], "incomplete")
            self.assertFalse(tampered["checks"]["contract_hash_matches"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for checked counterexamples")
    def test_semantic_mutation_produces_lean_checked_counterexample(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x89\xc8\xeb\xfc")
            contract = self._write_contract(root / "relation.json")

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "fail")
            self.assertEqual(result["proof"]["theorem"], "StageA.GeneratedRelationalCounterexample.exactCounterexample")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")
            self.assertEqual(result["diagnostic"]["category"], "checked_relational_counterexample")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for width-aware relational proofs")
    def test_word_test_and_compare_zero_are_exactly_equivalent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", bytes.fromhex("84c074006685f67400ebf5"))
            candidate = self._write_pe(root / "candidate.exe", bytes.fromhex("3c0074006683fe007400ebf4"))
            contract = self._write_contract(root / "relation.json", region_size=11, candidate_region_size=12)
            payload = json.loads(contract.read_text(encoding="utf-8"))
            pairs = payload["regions"][0]["inputs"]
            payload["code_targets"] = [
                {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                {"id": 1, "original_rva": 0x1004, "candidate_rva": 0x1004},
                {"id": 2, "original_rva": 0x1009, "candidate_rva": 0x100A},
            ]
            payload["regions"] = [
                {
                    "id": "byte-condition",
                    "root": True,
                    "original": {"rva": 0x1000, "size": 4},
                    "candidate": {"rva": 0x1000, "size": 4},
                    "inputs": pairs,
                    "outputs": pairs,
                },
                {
                    "id": "word-condition",
                    "root": False,
                    "original": {"rva": 0x1004, "size": 5},
                    "candidate": {"rva": 0x1004, "size": 6},
                    "inputs": pairs,
                    "outputs": pairs,
                },
                {
                    "id": "loop-back",
                    "root": False,
                    "original": {"rva": 0x1009, "size": 2},
                    "candidate": {"rva": 0x100A, "size": 2},
                    "inputs": pairs,
                    "outputs": pairs,
                },
            ]
            contract.write_text(json.dumps(payload), encoding="utf-8")

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for condition-code relational proofs")
    def test_setcc_and_cmovcc_compose_across_equivalent_flag_producers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", bytes.fromhex("83f9000f94c00f44c3ebf5"))
            candidate = self._write_pe(root / "candidate.exe", bytes.fromhex("85c90f94c00f44c3ebf6"))
            contract = self._write_contract(
                root / "relation.json",
                region_size=11,
                candidate_region_size=10,
            )

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for bit-scan relational proofs")
    def test_bsr_and_tzcnt_have_checked_partial_flag_and_undefined_value_semantics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("0fbdc3ebfbf30fbcc3ebfa")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            pairs = [{"original": register, "candidate": register} for register in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
            )]
            payload = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                ],
                "regions": [
                    {
                        "id": "bsr-loop", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "tzcnt-loop", "root": True,
                        "original": {"rva": 0x1005, "size": 6},
                        "candidate": {"rva": 0x1005, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(payload), encoding="utf-8")

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")
            bundle = (root / "report" / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            self.assertIn("highestSetBit", bundle)
            self.assertIn("lowestSetBit", bundle)
            self.assertNotIn("highestSetBitExpression", bundle)
            self.assertNotIn("lowestSetBitExpression", bundle)
            self.assertLess(len(bundle), 500_000)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for read-after-write relational proofs")
    def test_ambiguous_read_after_write_uses_compact_checked_expression(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("8b44242cc7442460000000008b400483c001ebec")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(root / "relation.json", region_size=len(code))

            result = stage_a_prove_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=root / "report",
            )
            self.assertEqual(result["verdict"], "pass", result)
            self.assertEqual(result["proof"]["lean"]["status"], "checked")
            bundle = (root / "report" / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            self.assertIn("read8AfterWrite", bundle)
            self.assertLess(len(bundle), 300_000)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for x87 relational proofs")
    def test_x87_stack_and_arithmetic_state_is_part_of_the_checked_relation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("d9e8d9eed9c9dec1ddd8ebf4")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(root / "relation.json", region_size=len(code))

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for x87 memory proofs")
    def test_x87_memory_conversion_and_writes_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("dd0424dd5c2408ebf7")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(root / "relation.json", region_size=len(code))

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for mapped static-data proofs")
    def test_relocated_x87_static_data_uses_checked_memory_mapping(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_relocated_data(0x2000))
            candidate.write_bytes(_pe32_image_with_relocated_data(0x3000))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "x87-static-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 8},
                "candidate": {"rva": 0x1000, "size": 8},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                out=contract,
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))

            self.assertEqual(generated["status"], "generated")
            self.assertEqual(len(payload["value_targets"]), 1)
            self.assertEqual(payload["value_targets"][0]["mapped_size"], 8)
            self.assertEqual(payload["value_targets"][0]["original_value"], 0x402000)
            self.assertEqual(payload["value_targets"][0]["candidate_value"], 0x403000)

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for immutable image-data proofs")
    def test_relocated_readonly_x87_data_is_decoded_from_exact_pe_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_relocated_data(0x2000, writable=False))
            candidate.write_bytes(_pe32_image_with_relocated_data(0x3000, writable=False))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "x87-immutable-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 8},
                "candidate": {"rva": 0x1000, "size": 8},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(generated["status"], "generated")
            self.assertEqual(payload["value_targets"], [])

            result = stage_a_prove_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=root / "report",
            )
            self.assertEqual(result["verdict"], "pass")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for indexed mapped-memory proofs")
    def test_relocation_pointer_table_emits_and_checks_bounded_index_mapping(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_relocation_pointer_table(0x2000, mask_index=True))
            candidate.write_bytes(_pe32_image_with_relocation_pointer_table(0x3000, mask_index=True))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "pointer-table-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 12},
                "candidate": {"rva": 0x1000, "size": 12},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(generated["status"], "generated")
            self.assertEqual(payload["regions"][0]["bounds"], [{
                "original": "edx", "candidate": "edx", "unsigned_lt": 2,
            }])
            mapped = [target for target in payload["value_targets"] if target["mapped_size"] > 0]
            self.assertEqual(len(mapped), 1)
            self.assertEqual(mapped[0]["mapped_size"], 8)

            result = stage_a_prove_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=root / "report",
            )
            self.assertEqual(result["verdict"], "pass", result)
            self.assertEqual(result["proof"]["lean"]["status"], "checked")
            proof_ir = json.loads(
                (root / "report" / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            assumption_kinds = {
                obligation["kind"]: obligation["status"]
                for obligation in proof_ir["obligations"]
                if obligation["kind"] != "relational_region_equivalence"
            }
            self.assertEqual(assumption_kinds, {
                "cfg_bound_invariant": "incomplete",
                "relocation_aware_memory_relation": "incomplete",
            })
            self.assertEqual(proof_ir["status"], "incomplete")
            self.assertEqual(result["counts"]["incomplete_assumptions"], 2)
            bundle = (root / "report" / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            self.assertIn("MappedIndexedAddress", bundle)
            self.assertIn("IndexMaskFact", bundle)
            self.assertIn("boundsSatisfied", bundle)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for address-separation proofs")
    def test_relocated_read_after_stack_write_requires_cfg_address_separation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_stack_write_and_relocated_read(0x2000))
            candidate.write_bytes(_pe32_image_with_stack_write_and_relocated_read(0x3000))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "stack-write-relocated-read-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 15},
                "candidate": {"rva": 0x1000, "size": 15},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )
            self.assertEqual(generated["status"], "generated")
            payload = json.loads(contract.read_text(encoding="utf-8"))
            original_bin = _parse_stage_a_pe(original)
            candidate_bin = _parse_stage_a_pe(candidate)
            normalized, issues = _normalize_contract(payload, original_bin, candidate_bin)
            self.assertEqual(issues, [])
            self.assertEqual(len(normalized["regions"][0]["address_separations"]), 16)

            report = root / "report"
            result = stage_a_prove_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=report,
            )
            self.assertEqual(result["verdict"], "pass", result)
            self.assertEqual(result["proof"]["lean"]["status"], "checked")
            proof_ir = json.loads((report / "relational-proof-ir.json").read_text(encoding="utf-8"))
            assumption_kinds = {
                obligation["kind"]
                for obligation in proof_ir["obligations"]
                if obligation["kind"] != "relational_region_equivalence"
            }
            self.assertEqual(assumption_kinds, {"cfg_address_separation_invariant"})
            self.assertEqual(proof_ir["status"], "incomplete")

            replay = stage_a_check_relational_proof(report=report)
            self.assertEqual(replay["status"], "incomplete")
            self.assertFalse(replay["checks"]["proof_ir_satisfied"])
            self.assertFalse(replay["checks"]["no_incomplete_assumptions"])
            self.assertFalse(replay["checks"]["contract_families_closed"])

    def _write_contract(
        self,
        path: Path,
        *,
        region_size: int = 4,
        candidate_region_size: int | None = None,
        target_rva: int = 0x1000,
    ) -> Path:
        candidate_region_size = candidate_region_size or region_size
        pairs = [{"original": register, "candidate": register} for register in (
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
        )]
        payload = {
            "format": "stage-a-relation-contract-v1",
            "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
            "observations": RELATIONAL_OBSERVATIONS,
            "code_targets": [{"id": 0, "original_rva": target_rva, "candidate_rva": target_rva}],
            "regions": [{
                "id": "entry-loop",
                "root": True,
                "original": {"rva": 0x1000, "size": region_size},
                "candidate": {"rva": 0x1000, "size": candidate_region_size},
                "inputs": pairs,
                "outputs": pairs,
            }],
            "padding": [],
            "memory_relation": {"mode": "identity"},
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    @staticmethod
    def _write_pe(path: Path, code: bytes) -> Path:
        path.write_bytes(_pe32_image(code))
        return path


def _pe32_image(code: bytes) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    text_raw_size = _align(len(code), file_alignment)
    size_of_image = _align(text_rva + len(code), section_alignment)
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, text_raw_size, 0, 0, text_rva, text_rva, 0, 0x400000,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0, size_of_image,
        headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    optional = optional_prefix + (b"\0" * (16 * 8))
    section = struct.pack(
        "<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, text_raw_size,
        headers_size, 0, 0, 0, 0, 0x60000020,
    )
    headers = (bytes(dos) + b"PE\0\0" + coff + optional + section).ljust(headers_size, b"\0")
    return headers + code.ljust(text_raw_size, b"\0")


def _pe32_image_with_relocated_data(data_rva: int, *, writable: bool = True) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    reloc_rva = 0x4000
    text_raw = 0x200
    data_raw = 0x400
    reloc_raw = 0x600
    image_base = 0x400000
    code = b"\xdd\x05" + struct.pack("<I", image_base + data_rva) + b"\xeb\xf8"
    data = struct.pack("<d", 1.5)
    relocations = struct.pack("<IIHH", text_rva, 12, 0x3002, 0)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, 0x200, 0x400, 0, text_rva, text_rva, data_rva, image_base,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0, 0x5000,
        headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 5 * 8, reloc_rva, len(relocations))
    sections = b"".join((
        struct.pack("<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, 0x200, text_raw, 0, 0, 0, 0, 0x60000020),
        struct.pack(
            "<8sIIIIIIHHI", b".data\0\0\0", len(data), data_rva, 0x200, data_raw,
            0, 0, 0, 0, 0xC0000040 if writable else 0x40000040,
        ),
        struct.pack("<8sIIIIIIHHI", b".reloc\0\0", len(relocations), reloc_rva, 0x200, reloc_raw, 0, 0, 0, 0, 0x42000040),
    ))
    headers = (bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories) + sections).ljust(headers_size, b"\0")
    return headers + code.ljust(0x200, b"\0") + data.ljust(0x200, b"\0") + relocations.ljust(0x200, b"\0")


def _pe32_image_with_relocation_pointer_table(data_rva: int, *, mask_index: bool = False) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    reloc_rva = 0x5000
    text_raw = 0x200
    data_raw = 0x400
    reloc_raw = 0x600
    image_base = 0x400000
    if mask_index:
        code = b"\x83\xe2\xff\x8b\x1c\x95" + struct.pack("<I", image_base + data_rva) + b"\xeb\xf4"
        relocation_offset = 6
    else:
        code = b"\x8b\x1c\x95" + struct.pack("<I", image_base + data_rva) + b"\xeb\xf7"
        relocation_offset = 3
    data = bytearray(0x40)
    struct.pack_into("<II", data, 0, image_base + data_rva + 0x20, image_base + data_rva + 0x30)
    data[0x20:0x26] = b"first\0"
    data[0x30:0x37] = b"second\0"

    def relocation_block(page_rva: int, offsets: list[int]) -> bytes:
        entries = [0x3000 | offset for offset in offsets]
        if len(entries) % 2:
            entries.append(0)
        size = 8 + 2 * len(entries)
        return struct.pack("<II", page_rva, size) + struct.pack("<" + "H" * len(entries), *entries)

    relocations = relocation_block(text_rva, [relocation_offset]) + relocation_block(data_rva, [0, 4])
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, 0x200, 0x400, 0, text_rva, text_rva, data_rva, image_base,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0, 0x6000,
        headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 5 * 8, reloc_rva, len(relocations))
    sections = b"".join((
        struct.pack("<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, 0x200, text_raw, 0, 0, 0, 0, 0x60000020),
        struct.pack("<8sIIIIIIHHI", b".data\0\0\0", len(data), data_rva, 0x200, data_raw, 0, 0, 0, 0, 0xC0000040),
        struct.pack("<8sIIIIIIHHI", b".reloc\0\0", len(relocations), reloc_rva, 0x200, reloc_raw, 0, 0, 0, 0, 0x42000040),
    ))
    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories) + sections
    ).ljust(headers_size, b"\0")
    return (
        headers + code.ljust(0x200, b"\0") + bytes(data).ljust(0x200, b"\0")
        + relocations.ljust(0x200, b"\0")
    )


def _pe32_image_with_stack_write_and_relocated_read(data_rva: int) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    reloc_rva = 0x4000
    text_raw = 0x200
    data_raw = 0x400
    reloc_raw = 0x600
    image_base = 0x400000
    code = b"\xc7\x44\x24\x08\x00\x00\x00\x00\xa1" + struct.pack(
        "<I", image_base + data_rva
    ) + b"\xeb\xf1"
    data = struct.pack("<I", 0x12345678)
    relocations = struct.pack("<IIHH", text_rva, 12, 0x3009, 0)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, 0x200, 0x200, 0, text_rva, text_rva, data_rva, image_base,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0, 0x5000,
        headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 5 * 8, reloc_rva, len(relocations))
    sections = b"".join((
        struct.pack(
            "<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, 0x200,
            text_raw, 0, 0, 0, 0, 0x60000020,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".data\0\0\0", len(data), data_rva, 0x200,
            data_raw, 0, 0, 0, 0, 0xC0000040,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".reloc\0\0", len(relocations), reloc_rva, 0x200,
            reloc_raw, 0, 0, 0, 0, 0x42000040,
        ),
    ))
    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories) + sections
    ).ljust(headers_size, b"\0")
    return (
        headers + code.ljust(0x200, b"\0") + data.ljust(0x200, b"\0")
        + relocations.ljust(0x200, b"\0")
    )


def _align(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


if __name__ == "__main__":
    unittest.main()
