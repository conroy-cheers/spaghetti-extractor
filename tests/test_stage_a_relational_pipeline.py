from tests.stage_a_relational_support import *


class StageARelationalPipelineTests(StageARelationalTestBase):
    def test_proof_shards_are_bounded_by_region_count_and_estimated_source_size(self):
        self.assertEqual(
            _partition_proof_shards(
                [100, 100, 450, 100, 100, 100],
                max_regions=3,
                target_bytes=500,
            ),
            [[0, 1], [2], [3, 4, 5]],
        )

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
                "source": {
                    "kind": "linker_map_capstone_block_match_v1",
                    "function": "entry_loop",
                    "function_block_index": 0,
                },
                "root": {
                    "checked": True,
                    "kind": "linker_map_function",
                    "symbol": "entry_loop",
                },
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
            self.assertEqual(payload["regions"][0]["function_id"], "entry_loop")
            self.assertEqual(payload["regions"][0]["function_block_index"], 0)
            self.assertEqual(payload["regions"][0]["function_cut_index"], 0)
            self.assertTrue(payload["regions"][0]["function_entry"])
            self.assertEqual(
                payload["regions"][0]["function_root_kind"],
                "linker_map_function",
            )
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

    def test_relation_contract_generator_selects_shared_external_profile_imports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("ff1540204000c3")
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            candidate.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "entry",
                "kind": "code",
                "original": {"rva": 0x1000, "size": len(code)},
                "candidate": {"rva": 0x1000, "size": len(code)},
            }]}), encoding="utf-8")
            profile = root / "external-profile.json"
            profile.write_text(json.dumps({
                "format": "stage-a-external-environment-profile-v1",
                "id": "generic-kernel32-test-v1",
                "machine_import_call_contracts": [{
                    "id": 10,
                    "import": {"dll": "kernel32.dll", "symbol": "Sleep"},
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 1,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }, {
                    "id": 11,
                    "import": {"dll": "kernel32.dll", "symbol": "GetLastError"},
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 0,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
            }), encoding="utf-8")
            contract = root / "relation.json"

            result = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                external_profile=profile,
                out=contract,
            )

            self.assertEqual(result["status"], "generated", result["issues"])
            self.assertEqual(result["counts"]["machine_import_call_contracts"], 1)
            self.assertEqual(result["external_profile"]["declared_contracts"], 2)
            self.assertEqual(result["external_profile"]["selected_contracts"], 1)
            self.assertEqual(result["external_profile"]["ignored_contracts"], 1)
            self.assertEqual(result["external_profile"]["covered_common_imports"], 1)
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["machine_import_call_contracts"][0]["import"],
                {"dll": "kernel32.dll", "symbol": "Sleep"},
            )

    def test_relation_contract_generator_rejects_invalid_external_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("ff1540204000c3")
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            candidate.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "entry",
                "kind": "code",
                "original": {"rva": 0x1000, "size": len(code)},
                "candidate": {"rva": 0x1000, "size": len(code)},
            }]}), encoding="utf-8")
            profile = root / "external-profile.json"
            duplicate = {
                "id": 4,
                "import": {"dll": "kernel32.dll", "symbol": "Sleep"},
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 1,
                "memory_effect": "none",
                "memory_footprints": [],
                "world_effect": "none",
            }
            profile.write_text(json.dumps({
                "format": "stage-a-external-environment-profile-v1",
                "id": "duplicate-v1",
                "machine_import_call_contracts": [duplicate, duplicate],
            }), encoding="utf-8")

            result = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                external_profile=profile,
                out=root / "relation.json",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn(
                "machine_import_call_contract_invalid",
                {issue["category"] for issue in result["issues"]},
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
            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(
                result["proof"]["lean"]["status"], "checked",
                result["proof"]["lean"],
            )

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

            self.assertEqual(result["verdict"], "incomplete")
            self.assertFalse(result["claim_scope"]["acceptance_eligible"])
            replay = stage_a_check_relational_proof(report=report)
            self.assertEqual(replay["status"], "incomplete")
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
            self.assertEqual(
                result["proof"]["lean"]["status"], "checked",
                result["proof"]["lean"],
            )
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

            self.assertEqual(result["verdict"], "incomplete")
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

            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")

    def test_normalized_register_reflexivity_bridge_is_emitted_for_cmov_expression(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("eb0039fa89d00f4cc783c01b7cf4c3")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(
                root / "relation.json",
                region_size=len(code),
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))
            pairs = payload["regions"][0]["inputs"]
            payload["code_targets"] = [
                {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                {"id": 1, "original_rva": 0x1002, "candidate_rva": 0x1002},
                {"id": 2, "original_rva": 0x100E, "candidate_rva": 0x100E},
            ]
            payload["regions"] = [
                {
                    "id": "entry",
                    "root": True,
                    "original": {"rva": 0x1000, "size": 2},
                    "candidate": {"rva": 0x1000, "size": 2},
                    "inputs": pairs,
                    "outputs": pairs,
                },
                {
                    "id": "cmov-loop",
                    "root": False,
                    "original": {"rva": 0x1002, "size": len(code) - 3},
                    "candidate": {"rva": 0x1002, "size": len(code) - 3},
                    "inputs": pairs,
                    "outputs": pairs,
                },
                {
                    "id": "fallthrough",
                    "root": False,
                    "original": {"rva": 0x100E, "size": 1},
                    "candidate": {"rva": 0x100E, "size": 1},
                    "inputs": pairs,
                    "outputs": pairs,
                },
            ]
            contract.write_text(json.dumps(payload), encoding="utf-8")

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["status"], "prepared", result)
            proof = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((root / "report" / "lean" / "StageA").glob(
                    "RelationalProofShard*.lean"
                ))
            )
            self.assertIn("registersRelatedValues_self_of_identity", proof)
            self.assertIn("OriginalWritesEmpty", proof)
            self.assertIn("writes = [] := by rfl", proof)
            self.assertIn("OutcomeConditionWithin", proof)
            self.assertIn("outcomesRelated_normalized_branch_of_agreement", proof)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for cross-region flag execution")
    def test_logical_execution_carries_computed_flags_into_the_next_region(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = Path(__file__).parents[1] / "src" / "spaghetti_extractor" / "lean" / "StageA"
            for name in ("Formal.lean",):
                shutil.copyfile(source_root / name, stage_a / name)
            (stage_a / "FlagsCompose.lean").write_text(
                """import StageA.Formal

namespace StageA.FlagsCompose

open StageA.Formal

def inputRegisters : Registers Expr := {
  eax := .inputReg .eax
  ebx := .inputReg .ebx
  ecx := .inputReg .ecx
  edx := .inputReg .edx
  esi := .inputReg .esi
  edi := .inputReg .edi
  ebp := .inputReg .ebp
  esp := .inputReg .esp
}

def concreteRegisters (ecx : Nat) : Registers Word := {
  eax := BitVec.ofNat 32 0
  ebx := BitVec.ofNat 32 0
  ecx := BitVec.ofNat 32 ecx
  edx := BitVec.ofNat 32 0
  esi := BitVec.ofNat 32 0
  edi := BitVec.ofNat 32 0
  ebp := BitVec.ofNat 32 0
  esp := BitVec.ofNat 32 0
}

def compare : LogicalBehavior := {
  registers := inputRegisters
  x87 := initialSymbolicX87
  writes := []
  flags := some (subtractionFlags (.inputReg .ecx) (.constant 0) (.inputReg .ecx))
  outcome := .jump 1
}

def branch : LogicalBehavior := {
  registers := inputRegisters
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .branch (.inputFlag 6) 2 3
}

def environment : Environment := { result := fun _ event => event.state }

def initial (ecx : Nat) : MachineState := {
  registers := concreteRegisters ecx
  memory := fun _ => BitVec.ofNat 8 0
  eflags := BitVec.ofNat 32 0
}

def selectedRegion (ecx : Nat) : Nat :=
  let behaviors := [some compare, some branch, none, none]
  let first := stepExecution environment behaviors (.running 0 (initial ecx) [] 0 [])
  match stepExecution environment behaviors first with
  | .running region _ _ _ _ => region
  | _ => 99

example : selectedRegion 0 = 2 := by decide
example : selectedRegion 1 = 3 := by decide

end StageA.FlagsCompose
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(lean_dir, bundle="FlagsCompose")
            self.assertEqual(result["status"], "checked", result)

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

            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(
                result["proof"]["lean"]["status"], "checked",
                result["proof"]["lean"],
            )
            bundle = (root / "report" / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            generated_proofs = "\n".join(
                path.read_text(encoding="utf-8")
                for pattern in ("RelationalDefinitionsShard*.lean", "RelationalProofShard*.lean")
                for path in sorted((root / "report" / "lean" / "StageA").glob(pattern))
            )
            self.assertIn("highestSetBit", generated_proofs)
            self.assertIn("lowestSetBit", generated_proofs)
            self.assertNotIn("highestSetBitExpression", generated_proofs)
            self.assertNotIn("lowestSetBitExpression", generated_proofs)
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
            self.assertEqual(result["verdict"], "incomplete", result)
            self.assertEqual(result["proof"]["lean"]["status"], "checked")
            bundle = (root / "report" / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            generated_proofs = "\n".join(
                path.read_text(encoding="utf-8")
                for pattern in ("RelationalDefinitionsShard*.lean", "RelationalProofShard*.lean")
                for path in sorted((root / "report" / "lean" / "StageA").glob(pattern))
            )
            self.assertIn("read8AfterWrite", generated_proofs)
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
            self.assertTrue(
                result["claim_scope"]["whole_program_observational_equivalence"]
            )

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

            self.assertEqual(result["verdict"], "incomplete")
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
            self.assertEqual(result["verdict"], "incomplete")
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
            self.assertTrue(
                result["claim_scope"]["whole_program_observational_equivalence"]
            )

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

            original_bin = _parse_stage_a_pe(original)
            candidate_bin = _parse_stage_a_pe(candidate)
            normalized, issues = _normalize_contract(payload, original_bin, candidate_bin)
            self.assertEqual(issues, [])
            normalized_mapped = [
                target for target in normalized["value_targets"] if target["mapped_size"] > 0
            ]
            self.assertEqual(normalized_mapped[0]["relocation_offsets"], [0, 4])

            result = stage_a_prove_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=root / "report",
            )
            self.assertEqual(result["verdict"], "incomplete", result)
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
                "cfg_register_relation_preservation": "incomplete",
                "mapped_relocation_image_relation": "proved",
                "relational_product_graph_decoded_exit_completeness": "candidate_requires_lean_replay",
                "relational_product_graph_declared_edge_refinement": "incomplete",
                "relational_product_graph_reachable_local_refinement": "incomplete",
                "relational_product_graph_structure": "candidate_requires_lean_replay",
                "relational_segment_refinement": "incomplete",
                "static_proof_context": "proved",
                "product_graph_composition": "incomplete",
                "whole_program_observational_equivalence": "incomplete",
            })
            self.assertEqual(proof_ir["status"], "incomplete")
            self.assertEqual(result["counts"]["incomplete_assumptions"], 9)
            relocation = next(
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "mapped_relocation_image_relation"
            )
            self.assertEqual(
                relocation["evidence"]["kind"],
                "lean_checked_mapped_relocation_image_relation",
            )
            bundle = (root / "report" / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            generated_sources = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (root / "report" / "lean" / "StageA").glob("*.lean")
            )
            self.assertIn("GeneratedMappedRelocationImageCertificate", bundle)
            self.assertIn("MappedIndexedAddress", generated_sources)
            self.assertIn("originalExpression := some", generated_sources)
            self.assertIn("Expr.bitAnd", generated_sources)
            self.assertIn("boundsSatisfied", generated_sources)

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
            self.assertEqual(result["verdict"], "incomplete", result)
            self.assertEqual(
                result["proof"]["lean"]["status"], "checked",
                result["proof"]["lean"],
            )
            proof_ir = json.loads((report / "relational-proof-ir.json").read_text(encoding="utf-8"))
            assumption_kinds = {
                obligation["kind"]
                for obligation in proof_ir["obligations"]
                if obligation["kind"] != "relational_region_equivalence"
            }
            self.assertEqual(assumption_kinds, {
                "cfg_address_separation_invariant",
                "cfg_register_relation_preservation",
                "memory_transition_preservation",
                "paired_stack_range_world",
                "relational_product_graph_decoded_exit_completeness",
                "relational_product_graph_declared_edge_refinement",
                "relational_product_graph_reachable_local_refinement",
                "relational_product_graph_structure",
                "relational_segment_refinement",
                "stack_address_separation_inventory",
                "static_proof_context",
                "product_graph_composition",
                "whole_program_observational_equivalence",
            })
            transition = next(
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "memory_transition_preservation"
            )
            self.assertEqual(
                transition["id"],
                "memory-transition:stack-write-relocated-read-loop",
            )
            self.assertEqual(
                transition["repair_class"], "identical_symbolic_write_pullback"
            )
            self.assertEqual(
                proof_ir["memory_transition_summary"]["transition_obligations"], 1
            )
            self.assertEqual(proof_ir["status"], "incomplete")

            replay = stage_a_check_relational_proof(report=report)
            self.assertEqual(replay["status"], "incomplete")
            self.assertFalse(replay["checks"]["proof_ir_satisfied"])
            self.assertFalse(replay["checks"]["no_incomplete_assumptions"])
            self.assertFalse(replay["checks"]["contract_families_closed"])
