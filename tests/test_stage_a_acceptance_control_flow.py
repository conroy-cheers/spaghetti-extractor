from tests.stage_a_relational_support import *
from spaghetti_extractor.relational.schema import (
    PROTOCOL_CALLBACK_CONTROL_FORMAT,
    RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
)
from spaghetti_extractor.relational.lean.acceptance import (
    _acceptance_segment_imports,
    _frame_relations_requiring_internal_preservation,
    _lean_frame_exact_word_register_output_claim,
    _lean_acceptance_linked_shallow_lift,
    _lean_acceptance_linked_shallow_node,
    _lean_return_slot_frame_transfer_claim,
    _lean_runtime_call_import_transfer_claim,
    _launch_check_ranges,
    _launch_state_predicates_structurally_true,
    _launch_structural_image_ranges,
    _runtime_frame_protected_bytes,
    _segment_module_ownership,
    _semantic_bool_is_structural_tautology,
)
from spaghetti_extractor.relational.lean.expressions import (
    _lean_direct_call_prepared_exact_word_seed_claim,
)
from typing import Any


class StageAAcceptanceControlFlowTests(StageARelationalTestBase):
    def test_acceptance_chunks_import_only_their_owned_segment_modules(self):
        ownership = _segment_module_ownership([
            {"module": "RelationalSegmentRefinementChunk0", "edge_ids": [0, 1]},
            {"module": "RelationalSegmentRefinementChunk1", "edge_ids": [2]},
        ])

        imports = _acceptance_segment_imports(
            [
                {"kind": "jump", "edges": [{"edge_id": 2}]},
                {"kind": "branch", "edges": [{"edge_id": 0}]},
                {"kind": "external_call", "edges": [{"edge_id": 99}]},
            ],
            ownership,
        )

        self.assertEqual(
            imports,
            "import StageA.RelationalSegmentRefinementChunk0\n"
            "import StageA.RelationalSegmentRefinementChunk1\n",
        )

    def test_acceptance_segment_imports_fail_closed_on_missing_or_duplicate_owner(self):
        with self.assertRaisesRegex(StageAInputError, "without generated Lean owners"):
            _acceptance_segment_imports(
                [{"kind": "jump", "edges": [{"edge_id": 3}]}],
                {0: "Chunk0"},
            )
        with self.assertRaisesRegex(StageAInputError, "owned by both"):
            _segment_module_ownership([
                {"module": "Chunk0", "edge_ids": [3]},
                {"module": "Chunk1", "edge_ids": [3]},
            ])

    def test_control_frontier_does_not_hide_independent_reachable_branch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = _pe32_image(
                b"\x85\xc0\x74\x02"  # test eax, eax; jz indirect-call
                b"\xeb\xfe"            # independent direct loop
                b"\xff\xd0"            # unresolved call eax
                b"\xc3"                 # indirect-call continuation
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(image)
            candidate.write_bytes(image)
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1004, "candidate_rva": 0x1004},
                    {"id": 2, "original_rva": 0x1006, "candidate_rva": 0x1006},
                    {"id": 3, "original_rva": 0x1008, "candidate_rva": 0x1008},
                ],
                "regions": [
                    {
                        "id": "fork", "root": True,
                        "original": {"rva": 0x1000, "size": 4},
                        "candidate": {"rva": 0x1000, "size": 4},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "independent-loop", "root": False,
                        "original": {"rva": 0x1004, "size": 2},
                        "candidate": {"rva": 0x1004, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "unresolved-indirect-call", "root": False,
                        "original": {"rva": 0x1006, "size": 2},
                        "candidate": {"rva": 0x1006, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "indirect-continuation", "root": False,
                        "original": {"rva": 0x1008, "size": 1},
                        "candidate": {"rva": 0x1008, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "prepared",
            )

            self.assertEqual(result["status"], "prepared", result)
            self.assertEqual(result["acceptance"]["status"], "incomplete", result)
            self.assertIn(
                "bounded_indirect_control_profile_unmet",
                {
                    blocker["code"]
                    for blocker in result["acceptance"]["blockers"]
                },
            )
            self.assertEqual(
                [
                    state["node_id"]
                    for state in result["acceptance"]["control_states"]
                ],
                [0, 2, 1],
            )

            module_graph = json.loads(
                (root / "prepared" / "module-graph.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertIn(
                "RelationalInstructionAdequacyCertificate",
                module_graph["modules"],
            )
            self.assertEqual(
                module_graph["counts"]["instruction_adequacy_modules"], 5
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_direct_loop_emits_and_checks_closed_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\xeb\xfe")
            candidate = self._write_pe(root / "candidate.exe", b"\xeb\xfe")
            contract = self._write_contract(root / "relation.json", region_size=2)
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["status"], "prepared")
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["expected_final_theorem"],
                RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
            )
            graph = _validate_prepared_relational(prepared)
            self.assertEqual(graph["root_module"], "RelationalAcceptance")
            self.assertEqual(graph["acceptance"]["profile"], "direct-no-write-jump-v1")
            self.assertIn("RelationalAcceptance", graph["modules"])
            self.assertIn("RelationalAcceptanceChunk0", graph["modules"])
            self.assertIn(
                "RelationalLaunchRealizabilityCertificate", graph["modules"]
            )
            launch_node = next(
                node for node in graph["nodes"]
                if node["modules"] == ["RelationalLaunchRealizabilityCertificate"]
            )
            self.assertEqual(launch_node["resource_class"], "high-memory")
            self.assertGreaterEqual(launch_node["estimated_memory_mb"], 10240)
            launch_leaf_nodes = [
                node for node in graph["nodes"]
                if len(node["modules"]) == 1
                and node["modules"][0].startswith("RelationalLaunch")
                and "Leaf" in node["modules"][0]
            ]
            self.assertGreater(len(launch_leaf_nodes), 4)
            self.assertTrue(all(
                node["resource_class"] == "high-memory"
                and node["estimated_memory_mb"] >= 4096
                for node in launch_leaf_nodes
            ))
            self.assertIn("RelationalLaunchContext", graph["modules"])
            self.assertIn("RelationalLaunchCheckCertificate", graph["modules"])
            self.assertIn("RelationalLinkedControlProfile", graph["modules"])
            self.assertIn(
                "RelationalInstructionAdequacyCertificate", graph["modules"]
            )
            self.assertEqual(graph["counts"]["instruction_adequacy_modules"], 3)
            adequacy_source = (
                prepared / "lean" / "StageA" /
                "RelationalInstructionAdequacyCertificate.lean"
            ).read_text(encoding="utf-8")
            original_adequacy_chunk = (
                prepared / "lean" / "StageA" /
                "RelationalProofOriginalInstructionAdequacyChunk0.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "theorem allOriginalRegionsInstructionAdequate", adequacy_source
            )
            self.assertIn(
                "theorem allCandidateRegionsInstructionAdequate", adequacy_source
            )
            self.assertIn(
                "regionInstructionAdequateWithX87_of_checked",
                original_adequacy_chunk,
            )
            linked_control_source = (
                prepared / "lean" / "StageA" /
                "RelationalLinkedControlProfile.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "def linkedProductControlProfile", linked_control_source
            )
            self.assertIn(
                "theorem linkedRuntimeCallFrameLinkCandidatesChecked",
                linked_control_source,
            )
            acceptance_source = (
                prepared / "lean" / "StageA" / "RelationalAcceptance.lean"
            ).read_text(encoding="utf-8")
            self.assertNotIn(
                "theorem candidatePE32ProgramsEquivalent :", acceptance_source
            )
            self.assertIn(
                "theorem candidatePE32ProgramsEquivalentLinked", acceptance_source
            )
            self.assertIn(
                "def linkedWholeProgramCertificate : LinkedWholeProgramCertificate",
                acceptance_source,
            )
            self.assertIn(
                "pe32ProgramsEquivalentLinked_raw", acceptance_source
            )
            self.assertIn("originalInstructionSemanticsAdequate", acceptance_source)
            self.assertIn("candidateInstructionSemanticsAdequate", acceptance_source)
            self.assertIn(
                "launchRealizable := consoleLaunchLinkedRealizable",
                acceptance_source,
            )
            self.assertIn(
                "import StageA.RelationalLaunchRealizabilityCertificate",
                acceptance_source,
            )
            self.assertIn(
                "instructionSemanticsAdequate_of_regions", acceptance_source
            )
            self.assertNotIn(
                "instructionSemanticsAdequate_of_checked", acceptance_source
            )
            self.assertNotIn("sorry", acceptance_source)
            launch_source = (
                prepared / "lean" / "StageA" /
                "RelationalLaunchRealizabilityCertificate.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("theorem consoleLaunchRealizable", launch_source)
            self.assertIn("theorem consoleLaunchLinkedRealizable", launch_source)
            self.assertIn(
                "import StageA.RelationalLaunchCheckCertificate", launch_source
            )
            self.assertNotIn("preferredBaseImageMemory_of_checked", launch_source)
            launch_checks = (
                prepared / "lean" / "StageA" /
                "RelationalLaunchCheckCertificate.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "preferredBaseImageMemory_projection_of_compatible_ranges",
                launch_checks,
            )
            self.assertIn(
                "preferredBaseImageMemory_implies_immutable", launch_checks
            )
            self.assertIn(
                "loaderPopulatedPreferredBaseMemory_maps_image", launch_checks
            )
            self.assertIn(
                "preferredBaseImageMemory_after_stack_range_writes",
                launch_checks,
            )
            self.assertIn(
                "theorem consoleLaunchCandidateExcludedImageMapped",
                launch_checks,
            )
            self.assertFalse(
                (prepared / "lean" / "StageA" /
                 "RelationalLaunchOriginalImmutableImageLeaf0.lean").exists()
            )
            self.assertFalse(
                (prepared / "lean" / "StageA" /
                 "RelationalLaunchOriginalImageMappedLeaf0.lean").exists()
            )
            self.assertIn("mappedImageSpans staticProofContext.candidatePe", launch_checks)
            self.assertNotIn(
                "staticProofContext.originalPe.sizeOfImage", launch_checks
            )
            self.assertIn(
                "stackRangesMemoryHold_of_single_range_indexed_holds",
                launch_checks,
            )
            self.assertIn("IndexedBoolCertificate.holds_of_ranges", launch_checks)
            candidate_leaf = (
                prepared / "lean" / "StageA" /
                "RelationalLaunchCandidateImageMappedLeaf0.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "candidateProjectionImageCompatibleAt_of_immutable_span",
                candidate_leaf,
            )
            self.assertIn(
                "consoleLaunchCandidateLoaderImageChecked", candidate_leaf
            )
            self.assertIn(
                "consoleLaunchCandidateImageCompatibilityAt", candidate_leaf
            )
            self.assertIn("{ start := 0, size := 512 }", candidate_leaf)
            self.assertNotIn("axiom", launch_source)
            self.assertNotIn("sorry", launch_source)
            self.assertNotIn("native_decide", launch_source)

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalentLinked' depends on axioms",
                lean["stdout"],
            )
            self.assertNotIn("._native.", lean["stdout"])
            self.assertNotIn("sorryAx", lean["stdout"])

            for compiled in (prepared / "lean").rglob("*.olean"):
                compiled.unlink()

            candidate_leaf_path = (
                prepared / "lean" / "StageA" /
                "RelationalLaunchCandidateImageMappedLeaf0.lean"
            )
            candidate_leaf_path.write_text(
                candidate_leaf_path.read_text(encoding="utf-8").replace(
                    "{ start := 0, size := 512 }",
                    "{ start := 1, size := 512 }",
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(StageAInputError, "source hash"):
                _validate_prepared_relational(prepared)

            proof_ir = json.loads(
                (prepared / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            finalized = _finalize_nix_proof_ir(
                proof_ir,
                theorem_checked=True,
                theorem=RELATIONAL_ACCEPTANCE_THEOREM,
                result_path=Path("/nix/store/test-whole-program-proof"),
            )
            self.assertEqual(finalized["status"], "satisfied")
            self.assertTrue(all(
                obligation["status"] == "proved"
                for obligation in finalized["obligations"]
            ))
            self.assertTrue(all(
                family["status"] in {"satisfied", "not_applicable"}
                for family in finalized["families"]
            ))

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_top_level_return_checks_terminal_invariant_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            contract = self._write_contract(root / "relation.json", region_size=1)
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["node_steps"][0]["kind"], "terminate"
            )
            self.assertEqual(
                result["acceptance"]["terminal_invariant"]["stack_windows"], []
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_guarded_branch_emits_and_checks_closed_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = b"\x85\xc0\x74\x02\xeb\xfa\xeb\xf8"
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            ]
            relation = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, rva in enumerate((0x1000, 0x1004, 0x1006))
                ],
                "regions": [
                    {
                        "id": name,
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                    }
                    for index, (name, rva, size) in enumerate((
                        ("condition", 0x1000, 4),
                        ("fallthrough", 0x1004, 2),
                        ("taken", 0x1006, 2),
                    ))
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(relation), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready")
            graph = _validate_prepared_relational(prepared)
            self.assertEqual(
                graph["acceptance"]["profile"], "guarded-no-write-control-v1"
            )
            condition_step = graph["acceptance"]["node_steps"][0]
            self.assertEqual(condition_step["kind"], "branch")
            self.assertEqual(
                [edge["edge_id"] for edge in condition_step["edges"]], [0, 1]
            )

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for bound proofs")
    def test_branch_guard_establishes_successor_bound_in_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # cmp eax, 4; jb taken; fallthrough: jmp fallthrough; taken: ret
            code = b"\x83\xf8\x04\x72\x02\xeb\xfe\xc3"
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            expression = {"op": "input_reg", "reg": "eax"}
            regions = [
                {
                    "id": "condition",
                    "root": True,
                    "original": {"rva": 0x1000, "size": 5},
                    "candidate": {"rva": 0x1000, "size": 5},
                    "inputs": pairs,
                    "outputs": pairs,
                },
                {
                    "id": "fallthrough",
                    "root": False,
                    "original": {"rva": 0x1005, "size": 2},
                    "candidate": {"rva": 0x1005, "size": 2},
                    "inputs": pairs,
                    "outputs": pairs,
                },
                {
                    "id": "taken",
                    "root": False,
                    "original": {"rva": 0x1007, "size": 1},
                    "candidate": {"rva": 0x1007, "size": 1},
                    "inputs": pairs,
                    "outputs": pairs,
                    "bounds": [{
                        "original": "eax",
                        "candidate": "eax",
                        "original_expression": expression,
                        "candidate_expression": expression,
                        "unsigned_lt": 4,
                    }],
                },
            ]
            relation = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, rva in enumerate((0x1000, 0x1005, 0x1007))
                ],
                "regions": regions,
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(relation), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            normalized = json.loads(
                (prepared / "relation-contract.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                normalized["regions"][0]["state_predicates"][0]["source"],
                "no_write_state_predicate_edge_pullback",
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for input-flag proofs")
    def test_input_flag_guard_closes_only_for_the_same_checked_flag(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(
                root / "original.exe", b"\x72\x02\xeb\xfc\xeb\xfa"
            )
            candidate = self._write_pe(
                root / "candidate.exe", b"\x70\x02\xeb\xfc\xeb\xfa"
            )
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            relation = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, rva in enumerate((0x1000, 0x1002, 0x1004))
                ],
                "regions": [
                    {
                        "id": name,
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                    }
                    for index, (name, rva, size) in enumerate((
                        ("condition", 0x1000, 2),
                        ("fallthrough", 0x1002, 2),
                        ("taken", 0x1004, 2),
                    ))
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(relation), encoding="utf-8")

            mismatched = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "mismatched",
            )

            self.assertEqual(mismatched["acceptance"]["status"], "incomplete")
            diagnostics = json.loads(
                (root / "mismatched" / "relational-segment-diagnostics.json")
                .read_text(encoding="utf-8")
            )
            self.assertTrue(any(
                "branch_guard_relation_unsupported" in edge["failed_checks"]
                for edge in diagnostics["edges"]
                if edge["edge_kind"].startswith("branch_")
            ))

            candidate.write_bytes(original.read_bytes())
            prepared = root / "prepared"
            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["profile"], "guarded-no-write-control-v1"
            )
            self.assertEqual(
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["branch", "jump", "jump"],
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for exact guards")
    def test_exact_pure_guard_uses_derived_register_exactness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = b"\xb8\x07\x00\x00\x00\xeb\x00\x83\xf8\x07\x74\x02\xeb\xfe\xeb\xfe"
            original = self._write_pe(root / "original.exe", code)
            candidate_code = bytearray(code)
            candidate_code[9] = 8
            candidate = self._write_pe(root / "candidate.exe", bytes(candidate_code))
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            relation = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, rva in enumerate((0x1000, 0x1007, 0x100C, 0x100E))
                ],
                "regions": [
                    {
                        "id": name,
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                    }
                    for index, (name, rva, size) in enumerate((
                        ("exact-producer", 0x1000, 7),
                        ("condition", 0x1007, 5),
                        ("fallthrough", 0x100C, 2),
                        ("taken", 0x100E, 2),
                    ))
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(relation), encoding="utf-8")

            mismatched = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "mismatched",
            )
            self.assertEqual(mismatched["acceptance"]["status"], "incomplete")
            diagnostics = json.loads(
                (root / "mismatched" / "relational-segment-diagnostics.json")
                .read_text(encoding="utf-8")
            )
            self.assertTrue(any(
                "branch_guard_relation_unsupported" in edge["failed_checks"]
                for edge in diagnostics["edges"]
                if edge["edge_kind"].startswith("branch_")
            ))

            candidate.write_bytes(original.read_bytes())
            prepared = root / "prepared"
            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )
            register_relations = json.loads(
                (prepared / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            condition_inputs = register_relations["regions"][1]["inputs"]
            self.assertIn({
                "original": "eax",
                "candidate": "eax",
                "relation": "fixed_word",
                "value": 7,
            }, condition_inputs)
            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalSegmentRefinementChunk*.lean"
                    )
                )
            )
            self.assertIn("ExactPureGuardClaim", segment_source)
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for relation weakening")
    def test_exact_register_output_weakens_to_related_successor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # The two branch arms join with EDX exact on one arm and related on
            # the other. The exact arm must satisfy the weaker join invariant.
            root_code = b"\x66\x81\x3d\x88\x00\x40\x00\x00\x00\x74\x07"
            original_code = (
                root_code
                + b"\xba\x19\x10\x40\x00\xeb\x07"
                + b"\xba\x07\x00\x00\x00\xeb\x00"
                + b"\xeb\xfe"
            )
            candidate_good = (
                root_code
                + b"\xba\x1a\x10\x40\x00\xeb\x08"
                + b"\xba\x07\x00\x00\x00\x90\xeb\x00"
                + b"\xeb\xfe"
            )
            original = self._write_pe(root / "original.exe", original_code)
            candidate_mismatch = bytearray(candidate_good)
            candidate_mismatch[19] = 8
            candidate = self._write_pe(
                root / "candidate.exe", bytes(candidate_mismatch)
            )
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            relation = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {
                        "id": index,
                        "original_rva": original_rva,
                        "candidate_rva": candidate_rva,
                    }
                    for index, (original_rva, candidate_rva) in enumerate((
                        (0x1000, 0x1000),
                        (0x100B, 0x100B),
                        (0x1012, 0x1012),
                        (0x1019, 0x101A),
                    ))
                ],
                "regions": [
                    {
                        "id": name,
                        "root": index == 0,
                        "original": {"rva": original_rva, "size": original_size},
                        "candidate": {
                            "rva": candidate_rva, "size": candidate_size,
                        },
                        "inputs": pairs,
                        "outputs": pairs,
                    }
                    for index, (
                        name, original_rva, candidate_rva,
                        original_size, candidate_size,
                    ) in enumerate((
                        ("branch", 0x1000, 0x1000, 11, 11),
                        ("related-arm", 0x100B, 0x100B, 7, 7),
                        ("exact-arm", 0x1012, 0x1012, 7, 8),
                        ("join", 0x1019, 0x101A, 2, 2),
                    ))
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(relation), encoding="utf-8")

            mismatched = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "mismatched",
            )
            self.assertEqual(mismatched["acceptance"]["status"], "incomplete")

            candidate.write_bytes(_pe32_image(candidate_good))
            prepared = root / "prepared"
            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )
            register_relations = json.loads(
                (prepared / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertIn({
                "original": "edx",
                "candidate": "edx",
                "relation": "fixed_word",
                "value": 7,
            }, register_relations["regions"][2]["outputs"])
            self.assertIn({
                "original": "edx", "candidate": "edx", "relation": "related_word",
            }, register_relations["regions"][3]["inputs"])
            diagnostics = json.loads(
                (prepared / "relational-segment-diagnostics.json").read_text(
                    encoding="utf-8"
                )
            )
            exact_join_edge = next(
                edge for edge in diagnostics["edges"]
                if edge["source_region_index"] == 2
                and edge["target_region_index"] == 3
            )
            self.assertTrue(exact_join_edge["eligible"], exact_join_edge)
            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalSegmentRefinementChunk*.lean"
                    )
                )
            )
            self.assertIn("TargetRegisterOutputClaims", segment_source)
            self.assertIn("relation := .relatedWord", segment_source)
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for immutable headers")
    def test_immutable_mapped_pe_header_read8_closes_exact_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # cmp word ptr [0x400088], 0; je taken; fallthrough/taken self-loop.
            code = (
                b"\x66\x81\x3d\x88\x00\x40\x00\x00\x00"
                b"\x74\x02\xeb\xfe\xeb\xfe"
            )
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            relation = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, rva in enumerate((0x1000, 0x100B, 0x100D))
                ],
                "regions": [
                    {
                        "id": name,
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                    }
                    for index, (name, rva, size) in enumerate((
                        ("header-condition", 0x1000, 11),
                        ("fallthrough", 0x100B, 2),
                        ("taken", 0x100D, 2),
                    ))
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(relation), encoding="utf-8")

            mismatched_image = bytearray(candidate.read_bytes())
            mismatched_image[0x88] = 1
            candidate.write_bytes(bytes(mismatched_image))
            mismatched = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "mismatched",
            )
            self.assertEqual(mismatched["acceptance"]["status"], "incomplete")
            diagnostics = json.loads(
                (root / "mismatched" / "relational-segment-diagnostics.json")
                .read_text(encoding="utf-8")
            )
            self.assertTrue(any(
                "branch_guard_relation_unsupported" in edge["failed_checks"]
                for edge in diagnostics["edges"]
                if edge["edge_kind"].startswith("branch_")
            ))

            candidate.write_bytes(original.read_bytes())
            prepared = root / "prepared"
            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(_parse_stage_a_pe(original).size_of_headers, 0x200)
            original_attestation = (
                prepared / "lean" / "StageA" / "RelationalProofOriginal.lean"
            ).read_text(encoding="utf-8")
            candidate_attestation = (
                prepared / "lean" / "StageA" / "RelationalProofCandidate.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("sizeOfHeaders := 512", original_attestation)
            self.assertIn("sizeOfHeaders := 512", candidate_attestation)
            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalSegmentRefinementChunk*.lean"
                    )
                )
            )
            self.assertIn("ExactPureGuardClaim", segment_source)
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for immutable words")
    def test_immutable_image_word_load_closes_register_transfer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_immutable_word_branch(7))
            candidate.write_bytes(_pe32_image_with_immutable_word_branch(8))
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            relation = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, rva in enumerate((0x1000, 0x1007, 0x100C, 0x100E))
                ],
                "regions": [
                    {
                        "id": name,
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                    }
                    for index, (name, rva, size) in enumerate((
                        ("immutable-load", 0x1000, 7),
                        ("condition", 0x1007, 5),
                        ("fallthrough", 0x100C, 2),
                        ("taken", 0x100E, 2),
                    ))
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(relation), encoding="utf-8")

            mismatched = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "mismatched",
            )
            self.assertEqual(mismatched["acceptance"]["status"], "incomplete")
            mismatched_relations = json.loads(
                (root / "mismatched" / "relational-register-relations.json")
                .read_text(encoding="utf-8")
            )
            self.assertNotIn(
                "immutable_image_word",
                {
                    claim["kind"]
                    for claim in mismatched_relations["regions"][0]["output_claims"]
                },
            )

            candidate.write_bytes(original.read_bytes())
            prepared = root / "prepared"
            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            register_relations = json.loads(
                (prepared / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            immutable_claims = [
                claim
                for claim in register_relations["regions"][0]["output_claims"]
                if claim["kind"] == "immutable_image_word"
            ]
            self.assertEqual(len(immutable_claims), 1)
            self.assertEqual(immutable_claims[0]["original_value"], 7)
            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalRegisterRelationsChunk*.lean"
                    )
                )
            )
            self.assertIn("RegisterOutputClaim.immutableImageWord", segment_source)
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for immutable expressions")
    def test_fixed_immutable_expression_chain_closes_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # Load e_lfanew, use it to read the COFF timestamp, then branch on
            # that value in a third block.  This forces fixed scalar evidence
            # to cross two CFG edges before it closes a guard.
            code = (
                bytes.fromhex("8b153c004000eb00")
                + bytes.fromhex("8b8208004000eb00")
                + bytes.fromhex("83f8007402")
                + bytes.fromhex("ebfeebfe")
            )
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            relation = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, rva in enumerate(
                        (0x1000, 0x1008, 0x1010, 0x1015, 0x1017)
                    )
                ],
                "regions": [
                    {
                        "id": name,
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                    }
                    for index, (name, rva, size) in enumerate((
                        ("load-pe-offset", 0x1000, 8),
                        ("dependent-header-load", 0x1008, 8),
                        ("header-value-branch", 0x1010, 5),
                        ("fallthrough-loop", 0x1015, 2),
                        ("taken-loop", 0x1017, 2),
                    ))
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(relation), encoding="utf-8")

            changed = bytearray(candidate.read_bytes())
            changed[0x88:0x8C] = struct.pack("<I", 1)
            candidate.write_bytes(bytes(changed))
            mismatched = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "mismatched",
            )
            self.assertEqual(mismatched["acceptance"]["status"], "incomplete")
            mismatched_relations = json.loads(
                (root / "mismatched" / "relational-register-relations.json")
                .read_text(encoding="utf-8")
            )
            self.assertNotIn(
                "fixed_immutable_expression",
                {
                    claim["kind"]
                    for claim in mismatched_relations["regions"][1]["output_claims"]
                },
            )

            candidate.write_bytes(original.read_bytes())
            prepared = root / "prepared"
            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            register_relations = json.loads(
                (prepared / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            first_output = next(
                row for row in register_relations["regions"][0]["outputs"]
                if row["original"] == "edx"
            )
            self.assertEqual(first_output["relation"], "fixed_word")
            self.assertEqual(first_output["value"], 0x80)
            dependent_claims = [
                claim
                for claim in register_relations["regions"][1]["output_claims"]
                if claim["kind"] == "fixed_immutable_expression"
            ]
            self.assertEqual(len(dependent_claims), 1)
            self.assertEqual(dependent_claims[0]["original_value"], 0)
            generated = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalRegisterRelationsChunk*.lean"
                    )
                )
            )
            self.assertIn(
                "RegisterOutputClaim.fixedImmutableExpression", generated,
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for static word slots")
    def test_static_word_slot_load_closes_register_transfer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            image = _pe32_image_with_writable_data(
                bytes.fromhex("a100204000ebf9"), relocation_offsets=[],
            )
            original.write_bytes(image)
            candidate.write_bytes(image)
            contract = self._write_contract(root / "relation.json", region_size=7)
            relation = json.loads(contract.read_text(encoding="utf-8"))
            relation["static_word_relation_slots"] = [{
                "id": 0,
                "original_address": 0x402000,
                "candidate_address": 0x402000,
                "relation": "related_word",
            }]
            contract.write_text(json.dumps(relation), encoding="utf-8")

            related_result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "related",
            )
            self.assertEqual(related_result["acceptance"]["status"], "ready")
            related_relations = json.loads(
                (root / "related" / "relational-register-relations.json")
                .read_text(encoding="utf-8")
            )
            related_claims = [
                claim
                for region in related_relations["regions"]
                for claim in region["output_claims"]
                if claim["kind"] == "static_word_slot"
            ]
            self.assertEqual(len(related_claims), 1)
            self.assertEqual(
                related_claims[0]["output"]["relation"], "related_word"
            )

            relation["static_word_relation_slots"][0]["relation"] = "exact"
            contract.write_text(json.dumps(relation), encoding="utf-8")
            prepared = root / "prepared"
            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )
            register_relations = json.loads(
                (prepared / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            static_claims = [
                claim
                for region in register_relations["regions"]
                for claim in region["output_claims"]
                if claim["kind"] == "static_word_slot"
            ]
            self.assertEqual(len(static_claims), 1)
            self.assertEqual(static_claims[0]["original_address"], 0x402000)
            self.assertEqual(result["acceptance"]["status"], "ready", {
                "result": result,
                "register_relations": register_relations,
                "segment_diagnostics": json.loads(
                    (prepared / "relational-segment-diagnostics.json").read_text(
                        encoding="utf-8"
                    )
                ),
            })
            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalSegmentRefinementChunk*.lean"
                    )
                )
            )
            self.assertIn("RegisterOutputClaim.staticWordSlot", segment_source)
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for paired guards")
    def test_paired_static_word_guard_closes_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_writable_data(
                bytes.fromhex("a10020400085c07402ebf5ebf3"),
                relocation_offsets=[], data_size=8,
            ))
            candidate.write_bytes(_pe32_image_with_writable_data(
                bytes.fromhex("a10020400085c07402ebf5ebf3"),
                relocation_offsets=[], data_size=8,
            ))
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            relation = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, rva in enumerate((0x1000, 0x1009, 0x100B))
                ],
                "regions": [
                    {
                        "id": name,
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                    }
                    for index, (name, rva, size) in enumerate((
                        ("paired-load-branch", 0x1000, 9),
                        ("fallthrough-loop", 0x1009, 2),
                        ("taken-loop", 0x100B, 2),
                    ))
                ],
                "static_word_relation_slots": [{
                    "id": 0,
                    "original_address": 0x402000,
                    "candidate_address": 0x402004,
                    "relation": "exact",
                }],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(relation), encoding="utf-8")

            mismatched = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "mismatched",
            )
            # The mismatched explicit slot must neither authorize a
            # static-word guard nor be silently supplemented with an
            # overlapping inferred slot.
            self.assertEqual(mismatched["acceptance"]["status"], "incomplete")
            mismatch_diagnostics = json.loads(
                (root / "mismatched" / "relational-segment-diagnostics.json")
                .read_text(encoding="utf-8")
            )
            mismatch_edges = [
                edge
                for edge in mismatch_diagnostics["edges"]
                if edge["source_region_index"] == 0
            ]
            self.assertTrue(mismatch_edges)
            self.assertTrue(any(
                "exact_memory_output_claim_present" in edge["failed_checks"]
                for edge in mismatch_edges
            ), mismatch_edges)
            mismatch_segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (root / "mismatched" / "lean" / "StageA").glob(
                        "RelationalSegmentRefinementChunk*.lean"
                    )
                )
            )
            self.assertNotIn("StaticWordZeroGuardClaim", mismatch_segment_source)
            mismatch_contract = json.loads(
                (root / "mismatched" / "relation-contract.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                mismatch_contract["static_word_relation_slots"],
                relation["static_word_relation_slots"],
            )
            mismatch_static_analysis = json.loads(
                (root / "mismatched" / "relational-static-word-relations.json")
                .read_text(encoding="utf-8")
            )
            self.assertIn(
                "static_word_address_mapping_ambiguous",
                {
                    item["category"]
                    for item in mismatch_static_analysis["rejected"]
                },
            )

            relation["static_word_relation_slots"][0][
                "candidate_address"
            ] = 0x402000
            contract.write_text(json.dumps(relation), encoding="utf-8")
            prepared = root / "prepared"
            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalSegmentRefinementChunk*.lean"
                    )
                )
            )
            self.assertEqual(
                segment_source.count(": StaticWordZeroGuardClaim"), 2
            )
            self.assertIn("relation := .exact", segment_source)
            self.assertIn("staticWordZeroGuard_eval_equal_of_checked", segment_source)
            module_graph = json.loads(
                (prepared / "module-graph.json").read_text(encoding="utf-8")
            )
            dependency_path = []
            pending = [(module_graph["root_module"], [])]
            while pending:
                module, prior = pending.pop(0)
                path = [*prior, module]
                if module.startswith("RelationalProofShard"):
                    dependency_path = path
                    break
                pending.extend(
                    (dependency, path)
                    for dependency in module_graph["modules"][module]["imports"]
                )
            self.assertFalse(
                any(name.startswith("RelationalProofShard")
                    for name in module_graph["modules"]),
                dependency_path,
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(
        shutil.which("lean"), "Lean is required for immutable pointer-chain guards"
    )
    def test_immutable_pe_pointer_chain_guard_closes_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"

            def pointer_chain_code(image_base: int) -> bytes:
                return (
                    bytes.fromhex("8b153c004000")
                    + b"\x81\xc2" + struct.pack("<I", image_base)
                    + bytes.fromhex("813a504500007402ebfeebfe")
                )

            original.write_bytes(_pe32_image(pointer_chain_code(0x400000)))
            candidate.write_bytes(_pe32_image(pointer_chain_code(0x400004)))
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "esi", "edi", "ebp", "esp"
                )
            ]
            relation = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, rva in enumerate((0x1000, 0x1014, 0x1016))
                ],
                "regions": [
                    {
                        "id": name,
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                    }
                    for index, (name, rva, size) in enumerate((
                        ("pe-pointer-chain-branch", 0x1000, 20),
                        ("fallthrough-loop", 0x1014, 2),
                        ("taken-loop", 0x1016, 2),
                    ))
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(relation), encoding="utf-8")

            mismatched = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "mismatched",
            )
            self.assertEqual(mismatched["acceptance"]["status"], "incomplete")
            self.assertIn(
                "launch_realizability_certificate_unsupported",
                {
                    blocker["code"]
                    for blocker in mismatched["acceptance"]["blockers"]
                },
            )

            candidate.write_bytes(_pe32_image(pointer_chain_code(0x400000)))
            prepared = root / "prepared"
            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalSegmentRefinementChunk*.lean"
                    )
                )
            )
            self.assertEqual(
                segment_source.count(": PairedExactGuardClaim"), 2
            )
            self.assertIn("PairedExactExprWitness.read32At", segment_source)
            self.assertIn("PairedStaticExprWitness.read32", segment_source)
            self.assertIn("PairedStaticExprWitness.binary .add", segment_source)
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_representative_control_slice_closes_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_representative_control_image(0x3000))
            candidate.write_bytes(
                _pe32_representative_control_image(0x3000, terminal_rva=0x1030)
            )
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [
                {
                    "id": name,
                    "kind": "code",
                    "original": {"rva": rva, "size": size},
                    "candidate": {"rva": rva, "size": size},
                }
                for name, rva, size in (
                    ("internal-call", 0x1000, 5),
                    ("import-call", 0x1005, 6),
                    ("conditional-loop", 0x100B, 4),
                    ("indirect-jump", 0x100F, 6),
                    ("internal-return", 0x1015, 1),
                )
            ] + [{
                "id": "terminal-return",
                "kind": "code",
                "original": {"rva": 0x1020, "size": 1},
                "candidate": {"rva": 0x1030, "size": 1},
            }, {
                "id": "alignment-padding",
                "kind": "padding",
                "original": {"rva": 0x1016, "size": 10},
                "candidate": {"rva": 0x1016, "size": 26},
            }]}), encoding="utf-8")
            contract = root / "relation.json"
            stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))
            payload["machine_import_call_contracts"] = [{
                "id": 0,
                "import": {"dll": "kernel32.dll", "symbol": "GetTickCount"},
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 0,
                "memory_effect": "none",
                "memory_footprints": [],
                "world_effect": "none",
            }]
            contract.write_text(json.dumps(payload), encoding="utf-8")
            unconstrained = root / "unconstrained"

            incomplete = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=unconstrained,
            )

            self.assertEqual(incomplete["acceptance"]["status"], "incomplete")
            self.assertIn(
                "terminal_result_relation_unmet",
                {
                    blocker["code"]
                    for blocker in incomplete["acceptance"]["blockers"]
                },
            )

            payload["machine_import_call_contracts"][0][
                "result_register_relations"
            ] = [{"register": "eax", "relation": "exact"}]
            contract.write_text(json.dumps(payload), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["profile"],
                "representative-compositional-control-v1",
            )
            self.assertEqual(
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["call", "external_call", "branch", "indirect_jump", "return", "terminate"],
            )
            progress = result["composition_progress"]
            self.assertEqual(progress["counts"]["rooted_reachable_nodes"], 6)
            self.assertEqual(progress["counts"]["rooted_reachable_feasible_edges"], 5)
            self.assertEqual(progress["counts"]["rooted_decoded_control_frontier_nodes"], 0)
            self.assertEqual(progress["counts"]["rooted_segment_refinement_frontier_edges"], 0)
            self.assertEqual(progress["frontiers"]["acceptance_blockers"], [])

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalent' depends on axioms", lean["stdout"]
            )
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for relational proofs")
    def test_exact_register_transfer_and_cfg_edge_are_checked_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(
                root / "original.exe", bytes.fromhex("89442404ebfa")
            )
            candidate = self._write_pe(
                root / "candidate.exe", bytes.fromhex("89442404ebfa")
            )
            contract = self._write_contract(root / "relation.json", region_size=6)
            report = root / "report"

            with patch.dict(
                os.environ, {"SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_SHARD_THRESHOLD": "1"}
            ):
                result = stage_a_prepare_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=report,
                )

            self.assertEqual(result["status"], "prepared", result)
            relations = json.loads(
                (report / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            # The ordinary registers are exact, but ESP is related by its
            # checked paired-stack offset rather than literal address equality.
            self.assertEqual(relations["counts"]["fully_exact_output_regions"], 0)
            self.assertEqual(relations["counts"]["fully_exact_edge_proposals"], 0)
            self.assertEqual(relations["counts"]["exact_pair_edge_claims"], 7)
            self.assertEqual(relations["counts"]["register_output_claims"], 7)
            self.assertEqual(relations["counts"]["fully_supported_output_regions"], 1)
            source = (
                report
                / "lean"
                / "StageA"
                / "RelationalRegisterRelationsChunk0.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("ExactRegisterTransferClosed", source)
            self.assertIn("ExactRegisterRelationPairEdgeClosed", source)
            self.assertIn("exactRegisterRelationPairEdgeClosed_of_checked", source)
            self.assertIn("RegisterOutputClaim.identity", source)
            self.assertIn("RegisterTransferClosed", source)
            self.assertIn("registerTransferClosed_of_checked", source)
            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (report / "lean" / "StageA").glob(
                        "RelationalSegmentRefinementChunk*.lean"
                    )
                )
            )
            self.assertIn(
                "stackWindowsRelated_after_affine_of_checked", segment_source
            )
            proof_ir = json.loads(
                (report / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            transition = next(
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "memory_transition_preservation"
            )
            self.assertEqual(
                transition["status"],
                "candidate_requires_lean_replay",
            )
            memory_contracts = json.loads(
                (report / "relational-memory-contracts.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                memory_contracts["counts"]["exact_memory_transition_edges"], 1
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for segment proofs")
    def test_dynamic_base_spill_with_field_write_is_checked_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex(
                "894424048910eb008b442404eb00a300204000eb00"
                "a10020400085c07501c38b08eb00c3"
            )
            image = _pe32_image_with_writable_data(
                code, relocation_offsets=[0x0f, 0x16],
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(image)
            candidate.write_bytes(image)
            registers = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            dynamic_relation = {
                "original": "eax", "candidate": "eax",
                "original_offset": 0, "candidate_offset": 0,
                "required_words": [{"offset": 0, "kind": "relatedWord"}],
            }
            stack_window = {
                "range_id": 0,
                "original_register": "esp", "candidate_register": "esp",
                "bytes_below": 0, "bytes_above": 8,
            }
            dynamic_stack_relation = {
                "window": stack_window, "stack_offset": 4,
                "original_offset": 0, "candidate_offset": 0,
                "required_words": [{"offset": 0, "kind": "relatedWord"}],
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1008, "candidate_rva": 0x1008},
                    {"id": 2, "original_rva": 0x100e, "candidate_rva": 0x100e},
                    {"id": 3, "original_rva": 0x1015, "candidate_rva": 0x1015},
                    {"id": 4, "original_rva": 0x101e, "candidate_rva": 0x101e},
                    {"id": 5, "original_rva": 0x101f, "candidate_rva": 0x101f},
                    {"id": 6, "original_rva": 0x1023, "candidate_rva": 0x1023},
                ],
                "regions": [
                    {
                        "id": "spill-and-write", "root": True,
                        "original": {"rva": 0x1000, "size": 8},
                        "candidate": {"rva": 0x1000, "size": 8},
                        "inputs": registers, "outputs": registers,
                        "input_dynamic_range_relations": [dynamic_relation],
                        "output_dynamic_range_relations": [dynamic_relation],
                    },
                    {
                        "id": "reload", "root": False,
                        "original": {"rva": 0x1008, "size": 6},
                        "candidate": {"rva": 0x1008, "size": 6},
                        "inputs": registers, "outputs": registers,
                        "input_dynamic_stack_range_relations": [
                            dynamic_stack_relation
                        ],
                        "output_dynamic_range_relations": [dynamic_relation],
                    },
                    {
                        "id": "publish", "root": False,
                        "original": {"rva": 0x100e, "size": 7},
                        "candidate": {"rva": 0x100e, "size": 7},
                        "inputs": registers, "outputs": registers,
                        "input_dynamic_range_relations": [dynamic_relation],
                    },
                    {
                        "id": "reload-static", "root": False,
                        "original": {"rva": 0x1015, "size": 9},
                        "candidate": {"rva": 0x1015, "size": 9},
                        "inputs": registers, "outputs": registers,
                    },
                    {
                        "id": "empty-return", "root": False,
                        "original": {"rva": 0x101e, "size": 1},
                        "candidate": {"rva": 0x101e, "size": 1},
                        "inputs": registers, "outputs": registers,
                    },
                    {
                        "id": "dereference", "root": False,
                        "original": {"rva": 0x101f, "size": 4},
                        "candidate": {"rva": 0x101f, "size": 4},
                        "inputs": registers, "outputs": registers,
                    },
                    {
                        "id": "return", "root": False,
                        "original": {"rva": 0x1023, "size": 1},
                        "candidate": {"rva": 0x1023, "size": 1},
                        "inputs": registers, "outputs": registers,
                    },
                ],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            proof_ir = json.loads(
                (prepared / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            spill_certificates = [
                obligation["analysis"]["certificate"]
                for obligation in proof_ir["obligations"]
                if (
                    obligation.get("analysis", {}).get("certificate") or {}
                ).get("prepared_dynamic_stack_spill_claim")
            ]
            diagnostics = json.loads(
                (prepared / "relational-segment-diagnostics.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(len(spill_certificates), 1, diagnostics)
            certificate = spill_certificates[0]
            self.assertEqual(
                certificate["prepared_dynamic_stack_spill_claim"]["amount"], 4,
            )
            publication_writes = [
                obligation["analysis"]["certificate"][
                    "paired_prepared_writes_claim"
                ]["writes"]
                for obligation in proof_ir["obligations"]
                if (
                    obligation.get("analysis", {}).get("certificate") or {}
                ).get("paired_prepared_writes_claim")
                and any(
                    write.get("kind") == "static_dynamic_pointer"
                    and (write.get("value") or {}).get("profile")
                        == "dynamic_range_v1"
                    for write in obligation["analysis"]["certificate"][
                        "paired_prepared_writes_claim"
                    ]["writes"]
                )
            ]
            self.assertEqual(len(publication_writes), 1, diagnostics)
            static_seed_modules = [
                path for path in (prepared / "lean" / "StageA").glob("*.lean")
                if "StaticDynamicPointerSeedClaim" in path.read_text(
                    encoding="utf-8"
                )
            ]
            self.assertEqual(len(static_seed_modules), 1, diagnostics)
            spill_modules = [
                path for path in (prepared / "lean" / "StageA").glob("*.lean")
                if "DynamicStackSpillClaim" in path.read_text(encoding="utf-8")
            ]
            self.assertEqual(len(spill_modules), 1, result)
            reload_modules = [
                path for path in (prepared / "lean" / "StageA").glob(
                    "RelationalSegmentRefinementChunk*.lean"
                )
                if "DynamicStackRangeReloadClaim" in path.read_text(
                    encoding="utf-8"
                )
            ]
            self.assertEqual(len(reload_modules), 1, diagnostics)
            for module in {
                spill_modules[0], reload_modules[0], static_seed_modules[0],
            }:
                lean = _run_lean_relational(
                    prepared / "lean", bundle=module.stem,
                )
                self.assertEqual(lean["status"], "checked", lean)
                self.assertNotIn("sorryAx", lean["stdout"])
