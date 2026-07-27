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


class StageAAcceptanceCallsFramesTests(StageARelationalTestBase):
    def test_prepared_exact_word_seed_is_total_lean_syntax(self):
        stack_item = {
            "kind": "stack",
            "window": {
                "range_id": 0,
                "original_register": "esp",
                "candidate_register": "esp",
                "bytes_below": 12,
                "bytes_above": 1,
            },
            "amount": 4,
            "value": {
                "original": {"op": "constant", "value": 7},
                "candidate": {"op": "constant", "value": 7},
                "profile": "exact_inputs_v1",
            },
        }
        witness = {"kind": "input"}
        rendered = _lean_direct_call_prepared_exact_word_seed_claim({
            "before": [],
            "selected": stack_item,
            "after": [stack_item],
            "original_selected_address": witness,
            "candidate_selected_address": witness,
            "original_after_addresses": [witness],
            "candidate_after_addresses": [witness],
            "exact_word": {"original_offset": 4, "candidate_offset": 4},
        })

        self.assertIsInstance(rendered, str)
        self.assertNotIn("None", rendered)
        self.assertIn("originalAfterAddresses := [RegisterOffsetWitness.input]", rendered)

    def test_runtime_frame_protected_span_covers_all_exact_words(self):
        self.assertEqual(_runtime_frame_protected_bytes({}), 4)
        self.assertEqual(
            _runtime_frame_protected_bytes({
                "exact_words": [
                    {"original": 4, "candidate": 12},
                    {"original": 28, "candidate": 20},
                ],
            }),
            32,
        )

    def test_protected_frame_memory_claim_serializes_checked_witnesses(self):
        claim = {
            "transfer": {
                "source": {
                    "original_register": "esp", "original": 0,
                    "candidate_register": "esp", "candidate": 0,
                },
                "target": {
                    "original_register": "ebp", "original": 4,
                    "candidate_register": "ebp", "candidate": 4,
                },
                "original_output_witness": {
                    "kind": "sub_right", "prior": {"kind": "input"},
                    "value": 4,
                },
                "candidate_output_witness": {
                    "kind": "sub_right", "prior": {"kind": "input"},
                    "value": 4,
                },
            },
            "memory": {
                "profile": "protected_frame_span_v1",
                "offsets": {
                    "original_register": "esp", "original": 0,
                    "candidate_register": "esp", "candidate": 0,
                },
                "writes": [
                    {
                        "kind": "static_word",
                        "slot_id": 7,
                    },
                ],
            },
        }

        source = _lean_return_slot_frame_transfer_claim(claim)

        self.assertIn("memory := .protectedSpan", source)
        self.assertIn("writes := [.staticWord 7]", source)

    def test_return_pop_does_not_require_the_removed_frame_relations(self):
        frame_relations = (("active-eax",), ("outer-ebx",), ("tail-esi",))

        self.assertEqual(
            _frame_relations_requiring_internal_preservation(
                frame_relations, "return_pop"
            ),
            (("outer-ebx",), ("tail-esi",)),
        )
        self.assertEqual(
            _frame_relations_requiring_internal_preservation(
                frame_relations, "transfer"
            ),
            frame_relations,
        )

    def test_frame_fact_claim_serializes_explicit_carried_relations(self):
        inventory = {
            "locations": [{
                "original_register": "esp",
                "original": 0,
                "candidate_register": "esp",
                "candidate": 0,
            }],
            "preserved_relations": [{
                "original": "eax", "candidate": "eax", "relation": "exact",
            }],
        }
        carried = [{
            "original": "ebx", "candidate": "ebx", "relation": "exact",
        }]

        legacy = _lean_runtime_call_import_transfer_claim(inventory, inventory)
        refreshed = _lean_runtime_call_import_transfer_claim(
            inventory, inventory, carried
        )

        self.assertNotIn("carriedRelations", legacy)
        self.assertIn("carriedRelations := some", refreshed)
        self.assertIn("original := .ebx", refreshed)

    def test_frame_word_claim_serializes_input_byte_assembly_profile(self):
        claim = {
            "profile": "active_frame_exact_word_register_output_v1",
            "source_location": {
                "original_register": "esp", "original": 28,
                "candidate_register": "esp", "candidate": 28,
            },
            "word": {"original": 4, "candidate": 4},
            "output": {
                "original": "eax", "candidate": "eax", "relation": "exact",
            },
            "original_address_witness": {
                "kind": "add_right",
                "prior": {"kind": "input"},
                "value": 32,
            },
            "candidate_address_witness": {
                "kind": "add_right",
                "prior": {"kind": "input"},
                "value": 32,
            },
            "original_input_assembled_read": True,
            "candidate_input_assembled_read": True,
            "original_write_witnesses": [],
            "candidate_write_witnesses": [],
        }

        source = _lean_frame_exact_word_register_output_claim(claim)

        self.assertIn("originalInputAssembledRead := true", source)
        self.assertIn("candidateInputAssembledRead := true", source)
        self.assertIn("originalAssembledRead := false", source)
        self.assertIn("candidateAssembledRead := false", source)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for memory-write proofs")
    def test_paired_stack_word_write_loop_closes_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("c744240800000000ebf6")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(
                root / "relation.json", region_size=len(code)
            )
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
                "paired-stack-write-control-v1",
            )
            self.assertEqual(
                result["composition_progress"]["counts"][
                    "rooted_segment_refinement_frontier_edges"
                ],
                0,
            )
            segment_source = (
                prepared
                / "lean"
                / "StageA"
                / "RelationalSegmentRefinementChunk0.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("PairedStackWordWriteClaim", segment_source)
            self.assertIn(
                "segmentTransitionClosed_of_paired_stack_word_write",
                segment_source,
            )

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalentLinked' depends on axioms",
                lean["stdout"],
            )
            self.assertNotIn("sorryAx", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for memory-write proofs")
    def test_paired_stack_word_writes_loop_closes_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("89042489542404ebf7")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(
                root / "relation.json", region_size=len(code)
            )
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
                "paired-stack-write-control-v1",
            )
            self.assertEqual(
                result["composition_progress"]["counts"][
                    "rooted_segment_refinement_frontier_edges"
                ],
                0,
            )
            segment_source = (
                prepared
                / "lean"
                / "StageA"
                / "RelationalSegmentRefinementChunk0.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("PairedStackWordWritesClaim", segment_source)
            self.assertIn(
                "segmentTransitionClosed_of_paired_stack_word_writes",
                segment_source,
            )
            proof_ir = json.loads(
                (prepared / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            segment_obligations = [
                obligation for obligation in proof_ir["obligations"]
                if obligation.get("kind") == "relational_segment_refinement"
                and obligation.get("status") == "proved"
            ]
            self.assertEqual(len(segment_obligations), 1)
            certificate = segment_obligations[0]["analysis"]["certificate"]
            self.assertEqual(
                certificate["format"], RELATIONAL_SEGMENT_CERTIFICATE_FORMAT
            )
            self.assertEqual(
                certificate["certificate_profile"],
                "composable_paired_stack_word_writes_v1",
            )
            self.assertEqual(
                len(certificate["paired_stack_writes_claim"]["writes"]), 2
            )

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalentLinked' depends on axioms",
                lean["stdout"],
            )
            self.assertNotIn("sorryAx", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for stack-read proofs")
    def test_direct_paired_stack_read_loop_closes_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_code = bytes.fromhex("8b442404ebfa")
            candidate_code = bytes.fromhex("8b4c2404ebfa")
            original = self._write_pe(root / "original.exe", original_code)
            candidate = self._write_pe(root / "candidate.exe", candidate_code)
            contract = self._write_contract(
                root / "relation.json", region_size=len(original_code),
                candidate_region_size=len(candidate_code),
            )
            contract_payload = json.loads(contract.read_text(encoding="utf-8"))
            input_pairs = contract_payload["regions"][0]["inputs"]
            contract_payload["regions"][0]["inputs"] = [
                pair for pair in input_pairs
                if pair["original"] not in {"eax", "ecx"}
            ]
            output_pairs = contract_payload["regions"][0]["outputs"]
            contract_payload["regions"][0]["outputs"] = [
                ({**pair, "candidate": "ecx"}
                 if pair["original"] == "eax" else pair)
                for pair in output_pairs
                if pair["original"] != "ecx"
            ]
            contract.write_text(json.dumps(contract_payload), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            diagnostic_context = {
                "result": result,
                "segments": json.loads(
                    (prepared / "relational-segment-diagnostics.json").read_text(
                        encoding="utf-8"
                    )
                ),
                "registers": json.loads(
                    (prepared / "relational-register-relations.json").read_text(
                        encoding="utf-8"
                    )
                ),
                "stack": json.loads(
                    (prepared / "relational-stack-windows.json").read_text(
                        encoding="utf-8"
                    )
                ),
            }
            self.assertEqual(
                result["acceptance"]["status"], "ready", diagnostic_context
            )
            self.assertEqual(
                result["composition_progress"]["counts"][
                    "rooted_segment_refinement_frontier_edges"
                ],
                0,
            )
            proof_ir = json.loads(
                (prepared / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            segment = next(
                obligation for obligation in proof_ir["obligations"]
                if obligation.get("kind") == "relational_segment_refinement"
            )
            register_relations = json.loads(
                (prepared / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            output_claim = next(
                claim for claim in register_relations["regions"][
                    segment["source_region_index"]
                ]["output_claims"]
                if claim["kind"] == "stack_read32_sub"
            )
            self.assertEqual(output_claim["offset"], 4)
            self.assertEqual(output_claim["subtract"], 0)
            self.assertTrue(output_claim["original_direct_read"])
            self.assertTrue(output_claim["candidate_direct_read"])
            self.assertFalse(output_claim["original_direct_address"])
            self.assertFalse(output_claim["candidate_direct_address"])
            segment_diagnostics = json.loads(
                (prepared / "relational-segment-diagnostics.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(segment_diagnostics["counts"]["eligible"], 1)
            self.assertEqual(
                segment_diagnostics["edges"][0]["failed_checks"], []
            )

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalentLinked' depends on axioms",
                lean["stdout"],
            )
            self.assertNotIn("sorryAx", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for stack-read proofs")
    def test_below_frame_stack_read_closes_only_for_same_checked_location(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_code = bytes.fromhex("89e5eb008b45f4ebfb")
            candidate_code = bytes.fromhex("89e5eb008b45f4ebfb")
            original = self._write_pe(root / "original.exe", original_code)
            candidate = self._write_pe(root / "candidate.exe", candidate_code)
            contract = self._write_contract(
                root / "relation.json", region_size=4,
            )
            contract_payload = json.loads(contract.read_text(encoding="utf-8"))
            contract_payload["code_targets"].append({
                "id": 1, "original_rva": 0x1004, "candidate_rva": 0x1004,
            })
            second_region = json.loads(json.dumps(contract_payload["regions"][0]))
            second_region.update({
                "id": "below-frame-loop",
                "root": False,
                "original": {"rva": 0x1004, "size": 5},
                "candidate": {"rva": 0x1004, "size": 5},
            })
            contract_payload["regions"].append(second_region)
            contract.write_text(json.dumps(contract_payload), encoding="utf-8")

            mismatched_code = bytes.fromhex("89e5eb008b45f8ebfb")
            candidate.write_bytes(_pe32_image(mismatched_code))
            mismatched = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "mismatched",
            )
            self.assertEqual(mismatched["acceptance"]["status"], "incomplete")

            candidate.write_bytes(_pe32_image(candidate_code))
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
            diagnostics = json.loads(
                (prepared / "relational-segment-diagnostics.json").read_text(
                    encoding="utf-8"
                )
            )
            context = {
                "result": result,
                "register_relations": register_relations,
                "diagnostics": diagnostics,
            }
            self.assertEqual(result["acceptance"]["status"], "ready", context)
            claim = next(
                claim for claim in register_relations["regions"][1]["output_claims"]
                if claim["output"]["original"] == "eax"
            )
            self.assertEqual(claim["kind"], "stack_read32_relative")
            self.assertEqual(claim["adjustment"], {"kind": "subtract", "amount": 12})
            self.assertTrue(all(
                not edge["failed_checks"] for edge in diagnostics["edges"]
            ), diagnostics)

            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalSegmentRefinementChunk*.lean"
                    )
                )
            )
            self.assertIn("RegisterOutputClaim.stackRead32Relative", segment_source)
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalentLinked' depends on axioms",
                lean["stdout"],
            )
            self.assertNotIn("sorryAx", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for stack-guard proofs")
    def test_below_frame_zero_guard_closes_only_for_same_checked_location(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_code = bytes.fromhex("89e5eb00837df4007402ebfeebfe")
            candidate_code = bytes.fromhex("89e5eb00837df4007402ebfeebfe")
            original = self._write_pe(root / "original.exe", original_code)
            candidate = self._write_pe(root / "candidate.exe", candidate_code)
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
                    for index, rva in enumerate((0x1000, 0x1004, 0x100A, 0x100C))
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
                        ("frame-seed", 0x1000, 4),
                        ("below-frame-condition", 0x1004, 6),
                        ("fallthrough-loop", 0x100A, 2),
                        ("taken-loop", 0x100C, 2),
                    ))
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(relation), encoding="utf-8")

            candidate.write_bytes(_pe32_image(
                bytes.fromhex("89e5eb00837df8007402ebfeebfe")
            ))
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
            mismatch_segments = json.loads(
                (root / "mismatched" / "relational-segment-candidates.json")
                .read_text(encoding="utf-8")
            )
            mismatch_guards = [
                edge["guard_relation_claim"]
                for edge in mismatch_segments["candidates"]
                if edge["source_region_index"] == 1
            ]
            self.assertEqual(len(mismatch_guards), 2)
            self.assertTrue(all(
                guard["profile"] == "paired_exact_guard_v1"
                for guard in mismatch_guards
            ))
            exact_reads = [
                guard["witness"]["left"]["read"]
                if guard["witness"]["left"]["kind"]
                    == "state_predicate_read32"
                else guard["witness"]["left"]["left"]["read"]
                for guard in mismatch_guards
            ]
            self.assertTrue(all(
                read["original_address"] != read["candidate_address"]
                for read in exact_reads
            ))

            candidate.write_bytes(_pe32_image(candidate_code))
            prepared = root / "prepared"
            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )
            diagnostics = json.loads(
                (prepared / "relational-segment-diagnostics.json").read_text(
                    encoding="utf-8"
                )
            )
            context = {"result": result, "diagnostics": diagnostics}
            self.assertEqual(result["acceptance"]["status"], "ready", context)
            branch_edges = [
                edge for edge in diagnostics["edges"]
                if edge["source_region_index"] == 1
            ]
            self.assertEqual(len(branch_edges), 2)
            self.assertTrue(all(not edge["failed_checks"] for edge in branch_edges))
            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalSegmentRefinementChunk*.lean"
                    )
                )
            )
            self.assertEqual(
                segment_source.count(": StackWordZeroRelativeGuardClaim"), 2
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_direct_call_return_loop_checks_runtime_frames_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = (
                b"\x83\xec\x0c"              # sub esp, 12
                b"\xe8\x05\x00\x00\x00"  # call callee-return
                b"\x83\xc4\x0c"              # add esp, 12
                b"\xeb\xf3"                    # loop to caller
                b"\xc3"                          # callee-return: ret
            )
            original = self._write_pe(root / "original.exe", code)
            candidate_image = bytearray(_pe32_image(b"\x90" + code))
            struct.pack_into("<I", candidate_image, 0xA8, 0x1001)
            candidate = root / "candidate.exe"
            candidate.write_bytes(candidate_image)
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1001},
                    {"id": 1, "original_rva": 0x1008, "candidate_rva": 0x1009},
                    {"id": 2, "original_rva": 0x100D, "candidate_rva": 0x100E},
                ],
                "regions": [
                    {
                        "id": "caller", "root": True,
                        "original": {"rva": 0x1000, "size": 8},
                        "candidate": {"rva": 0x1001, "size": 8},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "continuation", "root": False,
                        "original": {"rva": 0x1008, "size": 5},
                        "candidate": {"rva": 0x1009, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "callee-return", "root": False,
                        "original": {"rva": 0x100D, "size": 1},
                        "candidate": {"rva": 0x100E, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "padding": [{
                    "id": "candidate-entry-padding",
                    "side": "candidate",
                    "rva": 0x1000,
                    "size": 1,
                }],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["status"], "prepared")
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(result["acceptance"]["profile"], "finite-call-return-v1")
            self.assertEqual(
                result["acceptance"]["linked_acceptance"],
                {
                    "status": "ready",
                    "profile": "lean-checked-shallow-profile-compatibility-v1",
                    "theorem": (
                        "StageA.GeneratedRelational."
                        "candidatePE32ProgramsEquivalentLinked"
                    ),
                    "blockers": [],
                },
            )
            progress = json.loads(
                (prepared / "composition-progress.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result["composition_progress"], progress)
            self.assertEqual(progress["status"], "ready_for_lean")
            self.assertEqual(progress["counts"]["rooted_reachable_nodes"], 3)
            self.assertEqual(
                progress["counts"]["rooted_reachable_feasible_edges"], 2
            )
            self.assertEqual(progress["counts"]["rooted_refined_segments"], 2)
            self.assertEqual(
                progress["counts"]["rooted_stack_invariant_frontier_nodes"], 0
            )
            self.assertEqual(progress["next_work"], [])
            self.assertEqual(
                result["acceptance"]["control_states"],
                [
                    {"node_id": 0, "calls": [], "frame_offsets": []},
                    {
                        "node_id": 2,
                        "calls": [1],
                        "frame_offsets": [{"locations": [{
                            "original_register": "esp", "original": 0,
                            "candidate_register": "esp", "candidate": 0,
                        }]}],
                    },
                    {"node_id": 1, "calls": [], "frame_offsets": []},
                ],
            )
            normalized = json.loads(
                (prepared / "relation-contract.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                normalized["regions"][0]["stack_windows"][0]["bytes_below"], 16
            )
            self.assertEqual(
                normalized["regions"][1]["stack_windows"][0],
                {
                    "range_id": 0,
                    "original_register": "esp",
                    "candidate_register": "esp",
                    "bytes_below": 4,
                    "bytes_above": 13,
                    "source": "related_word_affine_output_seed",
                },
            )
            self.assertEqual(
                normalized["regions"][2]["stack_windows"][0]["bytes_above"], 17
            )
            direct_call = next(
                obligation["analysis"]["certificate"]
                for obligation in json.loads(
                    (prepared / "relational-proof-ir.json").read_text(
                        encoding="utf-8"
                    )
                )["obligations"]
                if obligation["kind"] == "relational_segment_refinement"
                and obligation["analysis"].get("certificate", {}).get(
                    "certificate_profile"
                ) == "composable_direct_call_v1"
            )
            self.assertEqual(direct_call["original_return_address"], 0x401008)
            self.assertEqual(direct_call["candidate_return_address"], 0x401009)
            self.assertEqual(direct_call["stack_amount"], 16)
            segment_source = (
                prepared / "lean" / "StageA" /
                "RelationalSegmentRefinementChunk0.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "segmentRefinementEdge0OriginalNormalizedBehavior",
                segment_source,
            )
            self.assertIn(
                "segmentRefinementEdge0CandidateNormalizedBehavior",
                segment_source,
            )

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

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_internal_callee_jump_uses_linked_active_frame_transfer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = (
                b"\xe8\x01\x00\x00\x00"  # call callee-entry
                b"\xc3"                  # top-level continuation: ret
                b"\xeb\x00"              # callee-entry: jump to return
                b"\xc3"                  # callee-return: ret
            )
            original = self._write_pe(root / "original.exe", code)
            candidate_image = bytearray(_pe32_image(b"\x90" + code))
            struct.pack_into("<I", candidate_image, 0xA8, 0x1001)
            candidate = root / "candidate.exe"
            candidate.write_bytes(candidate_image)
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
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1001},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1006},
                    {"id": 2, "original_rva": 0x1006, "candidate_rva": 0x1007},
                    {"id": 3, "original_rva": 0x1008, "candidate_rva": 0x1009},
                ],
                "regions": [
                    {
                        "id": "caller", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1001, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                        "stack_windows": [{
                            "range_id": 0,
                            "original_register": "esp",
                            "candidate_register": "esp",
                            "bytes_below": 4, "bytes_above": 4,
                        }],
                    },
                    {
                        "id": "continuation", "root": False,
                        "original": {"rva": 0x1005, "size": 1},
                        "candidate": {"rva": 0x1006, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                        "stack_windows": [{
                            "range_id": 0,
                            "original_register": "esp",
                            "candidate_register": "esp",
                            "bytes_below": 0, "bytes_above": 4,
                        }],
                    },
                    {
                        "id": "callee-entry", "root": False,
                        "original": {"rva": 0x1006, "size": 2},
                        "candidate": {"rva": 0x1007, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                        "stack_windows": [{
                            "range_id": 0,
                            "original_register": "esp",
                            "candidate_register": "esp",
                            "bytes_below": 0, "bytes_above": 8,
                        }],
                    },
                    {
                        "id": "callee-return", "root": False,
                        "original": {"rva": 0x1008, "size": 1},
                        "candidate": {"rva": 0x1009, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                        "stack_windows": [{
                            "range_id": 0,
                            "original_register": "esp",
                            "candidate_register": "esp",
                            "bytes_below": 0, "bytes_above": 8,
                        }],
                    },
                ],
                "padding": [{
                    "id": "candidate-entry-padding",
                    "side": "candidate", "rva": 0x1000, "size": 1,
                }],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["linked_acceptance"]["status"], "ready"
            )
            node_sources = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalAcceptanceChunk*.lean"
                    )
                )
            )
            self.assertIn(
                "RelationalLinkedRuntimeCallStackHolds.afterActiveTransfer",
                node_sources,
            )
            self.assertIn(
                "RelationalLinkedRuntimeCallFactsHold.afterInternal", node_sources
            )

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

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_nested_direct_calls_require_native_linked_frame_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = (
                b"\xe8\x01\x00\x00\x00"  # call first callee
                b"\xc3"                  # top-level continuation
                b"\xe8\x01\x00\x00\x00"  # first callee calls second
                b"\xc3"                  # first-callee continuation
                b"\xc3"                  # second callee
            )
            original = self._write_pe(root / "original.exe", code)
            candidate_image = bytearray(_pe32_image(b"\x90" + code))
            struct.pack_into("<I", candidate_image, 0xA8, 0x1001)
            candidate = root / "candidate.exe"
            candidate.write_bytes(candidate_image)
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
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1001},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1006},
                    {"id": 2, "original_rva": 0x1006, "candidate_rva": 0x1007},
                    {"id": 3, "original_rva": 0x100B, "candidate_rva": 0x100C},
                    {"id": 4, "original_rva": 0x100C, "candidate_rva": 0x100D},
                ],
                "regions": [
                    {
                        "id": "caller", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1001, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "top-continuation", "root": False,
                        "original": {"rva": 0x1005, "size": 1},
                        "candidate": {"rva": 0x1006, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "first-callee", "root": False,
                        "original": {"rva": 0x1006, "size": 5},
                        "candidate": {"rva": 0x1007, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "first-callee-continuation", "root": False,
                        "original": {"rva": 0x100B, "size": 1},
                        "candidate": {"rva": 0x100C, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "second-callee", "root": False,
                        "original": {"rva": 0x100C, "size": 1},
                        "candidate": {"rva": 0x100D, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "padding": [{
                    "id": "candidate-entry-padding",
                    "side": "candidate", "rva": 0x1000, "size": 1,
                }],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            linked = result["acceptance"]["linked_acceptance"]
            self.assertEqual(linked["status"], "ready", result)
            self.assertEqual(
                linked["profile"], "native-linked-call-return-v1", result
            )
            linked_control = result["acceptance"]["linked_control"]
            self.assertEqual(linked_control["counts"]["link_candidates"], 1)
            self.assertEqual(linked_control["counts"]["link_gaps"], 0)
            self.assertTrue(any(
                2 in state["representative_depths"]
                for state in linked_control["states"]
            ))
            node_sources = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalAcceptanceChunk*.lean"
                    )
                )
            )
            self.assertIn("pushNestedAfterSingletonWrite", node_sources)
            self.assertIn("popNestedAfterNoWriteTransfer", node_sources)
            self.assertIn("popLastAfter", node_sources)
            self.assertIn("theorem acceptanceRunningNode1Refined", node_sources)
            self.assertIn("have oldResult := acceptanceRunningNode1Refined", node_sources)

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

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_known_indirect_call_checks_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_immutable_indirect_call(
                0x2000, writable=True, argument_writes=False,
            ))
            candidate_image = bytearray(_pe32_image_with_immutable_indirect_call(
                0x3000, writable=True, argument_writes=False,
            ))
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ecx", "edx", "ebx", "ebp")
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1006, "candidate_rva": 0x1006},
                    {"id": 2, "original_rva": 0x1030, "candidate_rva": 0x1030},
                ],
                "regions": [
                    {
                        "id": "indirect-call", "root": True,
                        "original": {"rva": 0x1000, "size": 6},
                        "candidate": {"rva": 0x1000, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "continuation-loop", "root": False,
                        "original": {"rva": 0x1006, "size": 2},
                        "candidate": {"rva": 0x1006, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "callee-return", "root": False,
                        "original": {"rva": 0x1030, "size": 1},
                        "candidate": {"rva": 0x1030, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "padding": [{
                    "id": "call-to-callee-padding", "side": "both",
                    "rva": 0x1008, "size": 0x28,
                }],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")

            struct.pack_into("<I", candidate_image, 0x400, 0x401031)
            candidate.write_bytes(candidate_image)
            rejected = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "rejected",
            )
            self.assertEqual(rejected["acceptance"]["status"], "incomplete")
            self.assertEqual(
                rejected["composition_progress"]["counts"][
                    "unresolved_indirect_control_nodes"
                ],
                1,
            )

            candidate.write_bytes(_pe32_image_with_immutable_indirect_call(
                0x3000, writable=True, argument_writes=False,
            ))
            prepared = root / "prepared"
            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["status"], "prepared", result)
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            progress = result["composition_progress"]
            self.assertEqual(progress["status"], "ready_for_lean")
            self.assertEqual(progress["counts"]["rooted_reachable_nodes"], 3)
            self.assertEqual(
                progress["counts"]["rooted_reachable_feasible_edges"], 2
            )
            self.assertEqual(progress["counts"]["rooted_refined_segments"], 2)
            self.assertEqual(
                progress["counts"]["rooted_decoded_control_frontier_nodes"], 0
            )
            self.assertEqual(
                progress["counts"]["rooted_segment_refinement_frontier_edges"], 0
            )
            self.assertEqual(
                progress["counts"]["rooted_stack_invariant_frontier_nodes"], 0
            )
            self.assertEqual(
                progress["counts"]["unresolved_indirect_control_nodes"], 0
            )
            self.assertEqual(progress["frontiers"]["unresolved_indirect_control"], [])
            self.assertEqual(progress["next_work"], [])

            proof_ir = json.loads(
                (prepared / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            segment_certificates = [
                obligation["analysis"]["certificate"]
                for obligation in proof_ir["obligations"]
                if obligation.get("kind") == "relational_segment_refinement"
                and obligation.get("status") == "proved"
            ]
            self.assertIn(
                "composable_known_indirect_call_v1",
                {
                    certificate["certificate_profile"]
                    for certificate in segment_certificates
                },
            )
            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((prepared / "lean" / "StageA").glob(
                    "RelationalSegmentRefinementChunk*.lean"
                ))
            )
            self.assertIn("productNode0ImmutableIndirectCallClosed", segment_source)
            self.assertIn("DirectCallSegmentShapeClosed", segment_source)
            decoded_control_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((prepared / "lean" / "StageA").glob(
                    "RelationalProductDecodedControlChunk*.lean"
                ))
            )
            self.assertIn("StaticWordSlotIndirectCallTargetClaim", decoded_control_source)
            self.assertIn(
                "immutableIndirectCallTargetsClosed_of_staticWordSlot",
                decoded_control_source,
            )

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_nested_known_indirect_call_replays_its_return_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(
                _pe32_image_with_nested_immutable_indirect_call(0x2000)
            )
            candidate.write_bytes(
                _pe32_image_with_nested_immutable_indirect_call(0x3000)
            )
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ecx", "edx", "ebx", "ebp")
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                    {"id": 2, "original_rva": 0x1030, "candidate_rva": 0x1030},
                    {"id": 3, "original_rva": 0x1036, "candidate_rva": 0x1036},
                    {"id": 4, "original_rva": 0x1050, "candidate_rva": 0x1050},
                ],
                "regions": [
                    {
                        "id": "outer-call", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "outer-continuation", "root": False,
                        "original": {"rva": 0x1005, "size": 2},
                        "candidate": {"rva": 0x1005, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "indirect-call", "root": False,
                        "original": {"rva": 0x1030, "size": 6},
                        "candidate": {"rva": 0x1030, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "indirect-continuation", "root": False,
                        "original": {"rva": 0x1036, "size": 1},
                        "candidate": {"rva": 0x1036, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "indirect-callee", "root": False,
                        "original": {"rva": 0x1050, "size": 1},
                        "candidate": {"rva": 0x1050, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "padding": [
                    {"id": "outer-padding", "side": "both",
                     "rva": 0x1007, "size": 0x29},
                    {"id": "inner-padding", "side": "both",
                     "rva": 0x1037, "size": 0x19},
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

            self.assertEqual(result.get("status"), "prepared", result)
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["composition_progress"]["status"], "ready_for_lean", result
            )
            self.assertEqual(
                result["acceptance"]["control_states"],
                [
                    {"node_id": 0, "calls": [], "frame_offsets": []},
                    {
                        "node_id": 2,
                        "calls": [1],
                        "frame_offsets": [{"locations": [{
                            "original_register": "esp", "original": 0,
                            "candidate_register": "esp", "candidate": 0,
                        }]}],
                    },
                    {
                        "node_id": 4,
                        "calls": [3, 1],
                        "frame_offsets": [
                            {"locations": [{
                                "original_register": "esp", "original": 0,
                                "candidate_register": "esp", "candidate": 0,
                            }]},
                            {"locations": [{
                                "original_register": "esp", "original": 4,
                                "candidate_register": "esp", "candidate": 4,
                            }]},
                        ],
                    },
                    {
                        "node_id": 3,
                        "calls": [1],
                        "frame_offsets": [{"locations": [{
                            "original_register": "esp", "original": 0,
                            "candidate_register": "esp", "candidate": 0,
                        }]}],
                    },
                    {"node_id": 1, "calls": [], "frame_offsets": []},
                ],
            )
            register_relations = json.loads(
                (prepared / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            indirect_edges = [
                edge
                for edge in register_relations["edges"]
                if edge.get("indirect_call_push_claim") is not None
            ]
            self.assertEqual(len(indirect_edges), 1)
            self.assertEqual(
                len(indirect_edges[0]["return_slot_call_summary_claims"]), 1
            )
            register_modules = [
                (path, path.read_text(encoding="utf-8"))
                for path in sorted((prepared / "lean" / "StageA").glob(
                    "RelationalRegisterRelationsChunk*.lean"
                ))
            ]
            register_source = "\n".join(source for _, source in register_modules)
            self.assertIn("IndirectReturnSlotCallSummaryClosed", register_source)
            self.assertIn(
                "indirectReturnSlotCallSummaryClosed_of_checked", register_source
            )
            summary_modules = [
                path for path, source in register_modules
                if "IndirectReturnSlotCallSummaryClosed" in source
            ]
            self.assertEqual(len(summary_modules), 1)

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_import_register_survives_checked_internal_call_and_return(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\x8b\x35" + struct.pack("<I", iat_address)
                + b"\xe8\x15\x00\x00\x00"
                + b"\xeb\xfe"
                + b"\x90" * 0x13
                + b"\xc3"
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="GetTickCount"))
            candidate.write_bytes(_pe32_import_image(code, symbol="GetTickCount"))
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ebx", "ecx", "edx", "ebp")
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, rva in enumerate(
                        (0x1000, 0x1006, 0x100B, 0x1020)
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
                        ("iat-seed", 0x1000, 6),
                        ("internal-call", 0x1006, 5),
                        ("continuation-loop", 0x100B, 2),
                        ("internal-return", 0x1020, 1),
                    ))
                ],
                "padding": [{
                    "id": "internal-alignment",
                    "side": "both",
                    "rva": 0x100D,
                    "size": 0x13,
                }],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result.get("status"), "prepared", result)
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["composition_progress"]["status"], "ready_for_lean", result
            )
            import_analysis = json.loads(
                (prepared / "relational-import-register-invariants.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(import_analysis["counts"]["indirect_import_calls"], 0)
            self.assertGreaterEqual(
                import_analysis["counts"]["internal_return_predecessors"], 1
            )
            return_step = next(
                step for step in result["acceptance"]["node_steps"]
                if step["kind"] == "return"
            )
            self.assertEqual(
                [claim["kind"] for claim in return_step["import_transfer_claims"]],
                ["preserve"],
            )

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_direct_call_with_prepared_stack_word_checks_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def image(*, candidate: bool, mapped_pointer: int) -> bytes:
                source_rva = 0x1001 if candidate else 0x1000
                callee_rva = source_rva + 0xF
                code = (
                    b"\xc7\x44\x24\x04" + struct.pack("<I", mapped_pointer)
                    + b"\xe8\x02\x00\x00\x00"  # call callee-return
                    + b"\xeb\xf1"                  # continuation loops to source
                    + b"\xc3"                        # callee-return: ret
                )
                result = bytearray(_pe32_image((b"\x90" if candidate else b"") + code))
                if candidate:
                    struct.pack_into("<I", result, 0xA8, source_rva)
                return bytes(result)

            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(image(candidate=False, mapped_pointer=0x40100F))
            candidate.write_bytes(image(candidate=True, mapped_pointer=0x401010))
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
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1001},
                    {"id": 1, "original_rva": 0x100D, "candidate_rva": 0x100E},
                    {"id": 2, "original_rva": 0x100F, "candidate_rva": 0x1010},
                ],
                "regions": [
                    {
                        "id": "caller", "root": True,
                        "original": {"rva": 0x1000, "size": 13},
                        "candidate": {"rva": 0x1001, "size": 13},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "continuation", "root": False,
                        "original": {"rva": 0x100D, "size": 2},
                        "candidate": {"rva": 0x100E, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "callee-return", "root": False,
                        "original": {"rva": 0x100F, "size": 1},
                        "candidate": {"rva": 0x1010, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "padding": [{
                    "id": "candidate-entry-padding",
                    "side": "candidate", "rva": 0x1000, "size": 1,
                }],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["status"], "prepared", result)
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["composition_progress"]["counts"][
                    "rooted_segment_refinement_frontier_edges"
                ],
                0,
            )
            proof_ir = json.loads(
                (prepared / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            direct_call = next(
                obligation["analysis"]["certificate"]
                for obligation in proof_ir["obligations"]
                if obligation.get("kind") == "relational_segment_refinement"
                and obligation.get("analysis", {}).get("certificate", {}).get(
                    "certificate_profile"
                ) == "composable_direct_call_stack_writes_v1"
            )
            prepared_value = direct_call["direct_call_stack_writes_claim"][
                "stack_writes"
            ]["writes"][0]["value"]
            self.assertEqual(prepared_value["profile"], "mapped_code_target_v1")
            self.assertEqual(prepared_value["target_id"], 2)
            self.assertEqual(
                direct_call["direct_call_stack_writes_claim"]["exact_word_seeds"],
                [],
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalent' depends on axioms",
                lean["stdout"],
            )
            self.assertNotIn("sorryAx", lean["stdout"])

            candidate.write_bytes(image(candidate=True, mapped_pointer=0x401011))
            mutated = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "mutated",
            )
            self.assertEqual(mutated["acceptance"]["status"], "incomplete")
            self.assertGreater(
                mutated["composition_progress"]["counts"][
                    "rooted_segment_refinement_frontier_edges"
                ],
                0,
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_direct_call_seeds_checked_exact_scalar_word_in_callee_frame(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = (
                b"\xc7\x44\x24\x04\x2a\x00\x00\x00"
                b"\xc7\x44\x24\x08\x2b\x00\x00\x00"
                b"\xe8\x02\x00\x00\x00"
                b"\xeb\xe9"
                b"\xc3"
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image(code))
            candidate.write_bytes(_pe32_image(code))
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
                    {"id": 1, "original_rva": 0x1015, "candidate_rva": 0x1015},
                    {"id": 2, "original_rva": 0x1017, "candidate_rva": 0x1017},
                ],
                "regions": [
                    {
                        "id": "caller", "root": True,
                        "original": {"rva": 0x1000, "size": 21},
                        "candidate": {"rva": 0x1000, "size": 21},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "continuation", "root": False,
                        "original": {"rva": 0x1015, "size": 2},
                        "candidate": {"rva": 0x1015, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "callee-return", "root": False,
                        "original": {"rva": 0x1017, "size": 1},
                        "candidate": {"rva": 0x1017, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["status"], "prepared", result)
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            proof_ir = json.loads(
                (prepared / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            direct_call = next(
                obligation["analysis"]["certificate"]
                for obligation in proof_ir["obligations"]
                if obligation.get("kind") == "relational_segment_refinement"
                and obligation.get("analysis", {}).get("certificate", {}).get(
                    "certificate_profile"
                ) == "composable_direct_call_stack_writes_v1"
            )
            exact_seeds = direct_call["direct_call_stack_writes_claim"][
                "exact_word_seeds"
            ]
            self.assertEqual(len(exact_seeds), 2)
            self.assertEqual(
                [seed["exact_word"] for seed in exact_seeds],
                [
                    {"original_offset": 8, "candidate_offset": 8},
                    {"original_offset": 12, "candidate_offset": 12},
                ],
            )
            callee_states = [
                state for state in result["acceptance"]["control_states"]
                if state["node_id"] == 2 and state["calls"] == [1]
            ]
            self.assertEqual(len(callee_states), 1)
            self.assertEqual(
                callee_states[0]["frame_offsets"][0]["exact_words"],
                [
                    {"original": 8, "candidate": 8},
                    {"original": 12, "candidate": 12},
                ],
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])

            mismatched_code = bytearray(code)
            mismatched_code[4] = 0x2B
            candidate.write_bytes(_pe32_image(bytes(mismatched_code)))
            mismatched = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "mismatched",
            )
            self.assertEqual(mismatched["acceptance"]["status"], "incomplete")
            self.assertGreater(
                mismatched["composition_progress"]["counts"][
                    "rooted_segment_refinement_frontier_edges"
                ],
                0,
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_direct_call_with_prepared_static_word_checks_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_writable_static_call())
            candidate.write_bytes(_pe32_image_with_writable_static_call())
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
                    {"id": 1, "original_rva": 0x100F, "candidate_rva": 0x100F},
                    {"id": 2, "original_rva": 0x1011, "candidate_rva": 0x1011},
                ],
                "regions": [
                    {
                        "id": "caller", "root": True,
                        "original": {"rva": 0x1000, "size": 15},
                        "candidate": {"rva": 0x1000, "size": 15},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "continuation", "root": False,
                        "original": {"rva": 0x100F, "size": 2},
                        "candidate": {"rva": 0x100F, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "callee-return", "root": False,
                        "original": {"rva": 0x1011, "size": 1},
                        "candidate": {"rva": 0x1011, "size": 1},
                        "inputs": pairs, "outputs": pairs,
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

            self.assertEqual(result["status"], "prepared", result)
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["composition_progress"]["counts"][
                    "rooted_segment_refinement_frontier_edges"
                ],
                0,
            )
            proof_ir = json.loads(
                (prepared / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            direct_call = next(
                obligation["analysis"]["certificate"]
                for obligation in proof_ir["obligations"]
                if obligation.get("kind") == "relational_segment_refinement"
                and obligation.get("analysis", {}).get("certificate", {}).get(
                    "certificate_profile"
                ) == "composable_direct_call_prepared_writes_v1"
            )
            prepared_write = direct_call["direct_call_prepared_writes_claim"][
                "prepared_writes"
            ]["writes"][0]
            self.assertEqual(prepared_write["kind"], "static_word")
            self.assertEqual(prepared_write["original_address"], 0x402000)
            self.assertEqual(prepared_write["value"]["profile"], "exact_inputs_v1")
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalent' depends on axioms",
                lean["stdout"],
            )
            self.assertNotIn("sorryAx", lean["stdout"])

            candidate.write_bytes(
                _pe32_image_with_writable_static_call(stored_value=9)
            )
            mutated = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "mutated",
            )
            self.assertEqual(mutated["acceptance"]["status"], "incomplete")
            self.assertGreater(
                mutated["composition_progress"]["counts"][
                    "rooted_segment_refinement_frontier_edges"
                ],
                0,
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for stack-base proofs")
    def test_preserved_stack_base_becomes_related_word_at_successor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # The middle block reads through EBX, so its input relation is a
            # stack window. Its successor no longer needs a window but still
            # carries EBX as a related word.
            code = bytes.fromhex("89e3eb008b03eb00ebfe")
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
                    for index, rva in enumerate((0x1000, 0x1004, 0x1008))
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
                        ("stack-base-seed", 0x1000, 4),
                        ("stack-read", 0x1004, 4),
                        ("ordinary-successor", 0x1008, 2),
                    ))
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(relation), encoding="utf-8")

            bad_code = bytearray(code)
            bad_code[1] = 0xC3  # mov ebx, eax instead of mov ebx, esp
            candidate.write_bytes(_pe32_image(bytes(bad_code)))
            mismatched = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "mismatched",
            )
            self.assertEqual(mismatched["acceptance"]["status"], "incomplete")

            candidate.write_bytes(_pe32_image(code))
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
            diagnostics = json.loads(
                (prepared / "relational-segment-diagnostics.json").read_text(
                    encoding="utf-8"
                )
            )
            context = {
                "result": result,
                "register_relations": register_relations,
                "diagnostics": diagnostics,
            }
            self.assertEqual(result["acceptance"]["status"], "ready", context)
            self.assertIn(
                "ebx",
                {
                    str(window["original_register"])
                    for window in json.loads(
                        (prepared / "relation-contract.json").read_text(
                            encoding="utf-8"
                        )
                    )["regions"][1]["stack_windows"]
                },
            )
            self.assertNotIn(
                "ebx",
                {
                    str(window["original_register"])
                    for window in json.loads(
                        (prepared / "relation-contract.json").read_text(
                            encoding="utf-8"
                        )
                    )["regions"][2]["stack_windows"]
                },
            )
            claim = next(
                claim
                for claim in register_relations["regions"][1]["output_claims"]
                if claim["output"]["original"] == "ebx"
            )
            self.assertEqual(claim["kind"], "stack_window_identity")
            successor_edge = next(
                edge for edge in diagnostics["edges"]
                if edge["source_region_index"] == 1
                and edge["target_region_index"] == 2
            )
            self.assertTrue(successor_edge["eligible"], successor_edge)
            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalSegmentRefinementChunk*.lean"
                    )
                )
            )
            self.assertIn("RegisterOutputClaim.stackWindowIdentity", segment_source)
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for call-return proofs")
    def test_call_return_shape_is_reconstructed_from_pe_bytes_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("e802000000ebfec3")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            blocks = [
                ("caller-call", 0x1000, 5, "caller", 0, True),
                ("caller-continuation", 0x1005, 2, "caller", 1, False),
                ("callee-return", 0x1007, 1, "callee", 0, True),
            ]
            mapping = root / "mapping.json"
            mapping.write_text(
                json.dumps({
                    "blocks": [
                        {
                            "id": block_id,
                            "kind": "code",
                            "original": {"rva": rva, "size": size},
                            "candidate": {"rva": rva, "size": size},
                            "source": {
                                "kind": "linker_map_capstone_block_match_v1",
                                "function": function,
                                "function_block_index": block_index,
                            },
                            **({
                                "root": {
                                    "checked": True,
                                    "kind": "linker_map_function",
                                    "symbol": function,
                                },
                            } if function_entry else {}),
                        }
                        for block_id, rva, size, function, block_index, function_entry
                        in blocks
                    ],
                }),
                encoding="utf-8",
            )
            contract = root / "relation.json"
            generated = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                out=contract,
            )
            self.assertEqual(generated["status"], "generated", generated)

            with patch.dict(
                os.environ, {"SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_SHARD_THRESHOLD": "1"}
            ):
                result = stage_a_prepare_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=root / "report",
                )

            self.assertEqual(result["status"], "prepared", result)
            relations = json.loads(
                (root / "report" / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(relations["counts"]["call_return_edges"], 0)
            proof_ir = json.loads(
                (root / "report" / "relational-proof-ir.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(any(
                obligation["kind"] == "call_return_stack_composition"
                for obligation in proof_ir["obligations"]
            ))
            product_graph = json.loads(
                (root / "report" / "relational-product-graph.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                product_graph["evidence"]["runtime_call_continuations"],
                [{"source_node_id": 0, "continuation_node_ids": [1]}],
            )
            segment_obligations = [
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "relational_segment_refinement"
            ]
            self.assertGreaterEqual(len(segment_obligations), 1)
            self.assertIn(
                "successor_state_composition",
                {obligation["repair_class"] for obligation in segment_obligations},
            )
            self.assertGreaterEqual(
                proof_ir["segment_refinement_summary"]["proved"], 1
            )
            proved_segments = [
                obligation for obligation in segment_obligations
                if obligation["status"] == "proved"
            ]
            self.assertTrue(any(
                obligation["analysis"]["certificate_profile"]
                    == "composable_local_no_write_v1"
                for obligation in proved_segments
            ))
            register_sources = [
                path.read_text(encoding="utf-8")
                for path in (root / "report" / "lean" / "StageA").glob(
                    "RelationalRegisterRelationsChunk*.lean"
                )
            ]
            self.assertFalse(any(
                "CallReturnEdgeShapeClosed" in source
                for source in register_sources
            ))
